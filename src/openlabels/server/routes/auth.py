"""
OAuth 2.0 authentication routes for OpenLabels.

Supports multiple authentication providers:
- Azure AD (via MSAL): Authorization Code Flow with PKCE
- Generic OIDC: Standard Authorization Code Flow with any OIDC provider
- Dev mode: No-auth bypass for development (requires debug=True)

Flow (both providers):
1. User visits /auth/login
2. Redirected to IdP login page (Microsoft, Okta, Google, Keycloak, etc.)
3. After login, redirected to /auth/callback with authorization code
4. Server exchanges code for tokens
5. User redirected to app with session established

Sessions are stored in PostgreSQL for production reliability.

Security features:
- Open redirect prevention via URL validation
- Rate limiting on auth endpoints
- Secure session cookies with HttpOnly and SameSite
- CSRF state parameter validation
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from slowapi import Limiter
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.config import get_settings
from openlabels.server.db import get_session
from openlabels.server.routes import audit_log
from openlabels.server.security import log_security_event
from openlabels.server.session import PendingAuthStore, SessionStore
from openlabels.server.utils import get_client_ip

logger = logging.getLogger(__name__)


def _get_request_context(request: Request) -> dict:
    """Extract request context for security logging."""
    return {
        "ip": get_client_ip(request),
        "user_agent": request.headers.get("user-agent", "unknown"),
        "path": str(request.url.path),
    }


def validate_redirect_uri(redirect_uri: str | None, request: Request) -> str:
    """
    Validate redirect URI to prevent open redirect attacks.

    Security: Only allows:
    1. Relative paths starting with /
    2. URLs matching the request's host (same-origin)
    3. URLs in the configured CORS allowed_origins
    """
    if not redirect_uri:
        return "/"

    # Handle relative paths - must start with single /
    if redirect_uri.startswith("/"):
        if redirect_uri.startswith("//"):
            logger.warning(f"Blocked protocol-relative redirect: {redirect_uri}")
            return "/"
        if ".." in redirect_uri or any(c in redirect_uri for c in "\x00\r\n"):
            logger.warning(f"Blocked unsafe redirect path: {redirect_uri}")
            return "/"
        return redirect_uri

    try:
        parsed = urlparse(redirect_uri)
    except (ValueError, TypeError) as e:
        logger.warning(
            f"Failed to parse redirect URI '{redirect_uri}': {type(e).__name__}: {e}"
        )
        return "/"

    if parsed.scheme not in ("http", "https"):
        logger.warning(f"Blocked redirect with invalid scheme: {redirect_uri}")
        return "/"

    request_host = request.url.netloc
    if parsed.netloc == request_host:
        return redirect_uri

    settings = get_settings()
    redirect_origin = f"{parsed.scheme}://{parsed.netloc}"
    if redirect_origin in settings.cors.allowed_origins:
        return redirect_uri

    logger.warning(
        f"Blocked open redirect attempt: {redirect_uri} "
        f"(not in allowed origins: {settings.cors.allowed_origins})"
    )
    return "/"

router = APIRouter()
limiter = Limiter(key_func=get_client_ip)

# Token cookie settings
SESSION_COOKIE_NAME = "openlabels_session"
SESSION_COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 days
SESSION_TTL_SECONDS = SESSION_COOKIE_MAX_AGE

# Per-session lock to prevent concurrent token refresh races
_refresh_locks: dict[str, asyncio.Lock] = {}


class DevLoginRequest(BaseModel):
    """Request body for dev-mode username/password login."""
    username: str
    password: str


class DevLoginResponse(BaseModel):
    """Response after successful dev login."""
    authenticated: bool
    user: dict


class UserInfoResponse(BaseModel):
    """Current user information."""
    id: str
    email: str
    name: str | None
    tenant_id: str
    roles: list[str]


class TokenResponse(BaseModel):
    """Token response for API clients."""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str


class AuthConfigResponse(BaseModel):
    """Auth configuration for frontend to know which provider to show."""
    provider: str
    display_name: str
    button_style: str
    login_url: str


def _get_msal_app():
    """Get MSAL confidential client application (Azure AD only)."""
    from msal import ConfidentialClientApplication

    settings = get_settings()

    if settings.auth.provider not in ("azure_ad",):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="MSAL is only available with AUTH_PROVIDER=azure_ad",
        )

    return ConfidentialClientApplication(
        client_id=settings.auth.client_id,
        client_credential=settings.auth.client_secret,
        authority=f"https://login.microsoftonline.com/{settings.auth.tenant_id}",
    )


def _generate_session_id() -> str:
    """Generate secure session ID."""
    return secrets.token_urlsafe(32)


def _set_session_cookie(
    response: RedirectResponse | JSONResponse,
    session_id: str,
    request: Request,
) -> None:
    """Set the session cookie on a response."""
    is_secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=is_secure,
    )


# ---------- Auth Config Endpoint (for frontend) ----------

@router.get("/config", response_model=AuthConfigResponse)
async def get_auth_config(request: Request) -> AuthConfigResponse:
    """Return auth provider configuration for the frontend.

    The frontend calls this to know which login button(s) to show
    and what text/style to use.
    """
    settings = get_settings()
    provider = settings.auth.provider

    if provider == "oidc":
        oidc = settings.auth.oidc
        return AuthConfigResponse(
            provider="oidc",
            display_name=oidc.display_name,
            button_style=oidc.button_style,
            login_url="/api/v1/auth/login",
        )
    elif provider == "azure_ad":
        return AuthConfigResponse(
            provider="azure_ad",
            display_name="Microsoft",
            button_style="microsoft",
            login_url="/api/v1/auth/login",
        )
    else:
        return AuthConfigResponse(
            provider="none",
            display_name="Development",
            button_style="generic",
            login_url="/api/v1/auth/login",
        )


# ---------- Login ----------

@router.get("/login")
@limiter.limit(lambda: get_settings().rate_limit.auth_limit)
async def login(
    request: Request,
    redirect_uri: str | None = None,
    db: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """
    Initiate OAuth login flow.

    Routes to the appropriate provider (Azure AD, OIDC, or dev mode).
    """
    settings = get_settings()
    session_store = SessionStore(db)
    pending_store = PendingAuthStore(db)

    # Cleanup expired entries periodically
    await session_store.cleanup_expired()
    await pending_store.cleanup_expired()

    if settings.auth.provider == "none":
        return await _login_dev_mode(request, redirect_uri, db, session_store)

    if settings.auth.provider == "oidc":
        return await _login_oidc(request, redirect_uri, db, pending_store)

    # Default: Azure AD via MSAL
    return await _login_azure_ad(request, redirect_uri, db, pending_store)


async def _login_dev_mode(
    request: Request,
    redirect_uri: str | None,
    db: AsyncSession,
    session_store: SessionStore,
) -> RedirectResponse:
    """Handle dev mode login (no auth)."""
    settings = get_settings()

    if settings.server.environment == "production":
        logger.error("SECURITY: Dev mode auth (AUTH_PROVIDER=none) is disabled in production!")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication not configured. Set AUTH_PROVIDER=azure_ad or AUTH_PROVIDER=oidc for production.",
        )

    if not settings.server.debug:
        logger.error("SECURITY: AUTH_PROVIDER=none requires DEBUG=true.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication not configured for production. Contact administrator.",
        )

    # Session fixation prevention
    existing_session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if existing_session_id:
        await session_store.delete(existing_session_id)

    logger.warning("DEV MODE: Creating fake admin session - DO NOT USE IN PRODUCTION")
    session_id = _generate_session_id()
    session_data = {
        "access_token": "dev-token",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        "provider": "none",
        "claims": {
            "oid": "dev-user-oid",
            "sub": "dev-user-oid",
            "preferred_username": "dev@localhost",
            "email": "dev@localhost",
            "name": "Development User",
            "tid": "dev-tenant",
            "roles": ["admin"],
        },
    }
    await session_store.set(session_id, session_data, SESSION_TTL_SECONDS, tenant_id=None, user_id=None)
    await db.commit()

    safe_redirect = validate_redirect_uri(redirect_uri, request)
    response = RedirectResponse(url=safe_redirect, status_code=302)
    _set_session_cookie(response, session_id, request)
    return response


async def _login_azure_ad(
    request: Request,
    redirect_uri: str | None,
    db: AsyncSession,
    pending_store: PendingAuthStore,
) -> RedirectResponse:
    """Initiate Azure AD login via MSAL."""
    msal_app = _get_msal_app()

    state = secrets.token_urlsafe(32)
    callback_url = str(request.url_for("auth_callback"))
    safe_redirect = validate_redirect_uri(redirect_uri, request)

    await pending_store.set(state, safe_redirect, callback_url)

    auth_url = msal_app.get_authorization_request_url(
        scopes=["User.Read", "openid", "profile", "email"],
        state=state,
        redirect_uri=callback_url,
    )

    return RedirectResponse(url=auth_url, status_code=302)


async def _login_oidc(
    request: Request,
    redirect_uri: str | None,
    db: AsyncSession,
    pending_store: PendingAuthStore,
) -> RedirectResponse:
    """Initiate generic OIDC login."""
    from openlabels.auth.oidc_provider import get_authorization_url, get_discovery

    settings = get_settings()
    oidc_config = settings.auth.oidc

    if not oidc_config.discovery_url:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC discovery URL not configured",
        )

    discovery = await get_discovery(oidc_config.discovery_url)

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    callback_url = str(request.url_for("auth_callback"))
    safe_redirect = validate_redirect_uri(redirect_uri, request)

    # Store state, redirect, and nonce for callback validation
    await pending_store.set(state, safe_redirect, callback_url, nonce=nonce)

    auth_url = get_authorization_url(
        discovery=discovery,
        config=oidc_config,
        state=state,
        redirect_uri=callback_url,
        nonce=nonce,
    )

    return RedirectResponse(url=auth_url, status_code=302)


# ---------- Callback ----------

@router.get("/callback")
@limiter.limit(lambda: get_settings().rate_limit.auth_limit)
async def auth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """
    OAuth callback endpoint.

    The IdP (Microsoft, Okta, Google, etc.) redirects here after user login.
    Routes to the appropriate handler based on the configured provider.
    """
    settings = get_settings()

    if settings.auth.provider == "none":
        return RedirectResponse(url="/", status_code=302)

    # Handle errors from IdP
    if error:
        logger.error(f"OAuth error: {error} - {error_description}")
        log_security_event(
            event_type="oauth_error",
            details={
                **_get_request_context(request),
                "error": error,
                "error_code": error_description[:100] if error_description else None,
            },
            level="warning",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication failed. Please try again or contact support.",
        )

    if not code or not state:
        log_security_event(
            event_type="oauth_invalid_request",
            details={
                **_get_request_context(request),
                "missing_code": not code,
                "missing_state": not state,
            },
            level="warning",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing authorization code or state",
        )

    # Validate state
    pending_store = PendingAuthStore(db)
    pending = await pending_store.get(state)

    if not pending:
        log_security_event(
            event_type="oauth_invalid_state",
            details={
                **_get_request_context(request),
                "state_hash": hash(state) % 10000,
            },
            level="warning",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state",
        )

    await pending_store.delete(state)

    callback_url = pending["callback_url"]
    final_redirect = pending["redirect_uri"]
    nonce = pending.get("nonce")

    if settings.auth.provider == "oidc":
        return await _callback_oidc(request, code, callback_url, final_redirect, db, nonce=nonce)

    # Default: Azure AD
    return await _callback_azure_ad(request, code, callback_url, final_redirect, db)


async def _callback_azure_ad(
    request: Request,
    code: str,
    callback_url: str,
    final_redirect: str,
    db: AsyncSession,
) -> RedirectResponse:
    """Handle Azure AD OAuth callback."""
    msal_app = _get_msal_app()

    try:
        result = msal_app.acquire_token_by_authorization_code(
            code=code,
            scopes=["User.Read", "openid", "profile", "email"],
            redirect_uri=callback_url,
        )
    except (ConnectionError, OSError, RuntimeError, ValueError) as e:
        logger.error(f"Token acquisition failed: {e}")
        log_security_event(
            event_type="token_acquisition_failed",
            details={**_get_request_context(request), "error_type": type(e).__name__},
            level="error",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to acquire token",
        ) from e

    if "error" in result:
        logger.error(f"Token error: {result.get('error_description', result.get('error'))}")
        log_security_event(
            event_type="token_exchange_failed",
            details={**_get_request_context(request), "error": result.get("error")},
            level="warning",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to complete authentication. Please try again.",
        )

    # Create session
    session_store = SessionStore(db)

    # Session fixation prevention
    existing_session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if existing_session_id:
        await session_store.delete(existing_session_id)

    session_id = _generate_session_id()
    expires_in = result.get("expires_in", 3600)

    id_token_claims = result.get("id_token_claims", {})
    session_data = {
        "access_token": result["access_token"],
        "refresh_token": result.get("refresh_token"),
        "id_token": result.get("id_token"),
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(),
        "provider": "azure_ad",
        "claims": id_token_claims,
    }

    user_id = id_token_claims.get("oid")
    tenant_id = id_token_claims.get("tid")
    await session_store.set(session_id, session_data, SESSION_TTL_SECONDS, tenant_id=tenant_id, user_id=user_id)

    audit_log(
        db, tenant_id=None, user_id=None,
        action="login_success", resource_type="session",
        details={
            "provider": "azure_ad",
            "email": id_token_claims.get("preferred_username"),
            "ip": get_client_ip(request),
        },
    )

    response = RedirectResponse(url=final_redirect, status_code=302)
    _set_session_cookie(response, session_id, request)
    return response


async def _callback_oidc(
    request: Request,
    code: str,
    callback_url: str,
    final_redirect: str,
    db: AsyncSession,
    nonce: str | None = None,
) -> RedirectResponse:
    """Handle generic OIDC callback."""
    from openlabels.auth.oidc_provider import (
        exchange_code,
        extract_claims,
        get_discovery,
        validate_id_token,
    )

    settings = get_settings()
    oidc_config = settings.auth.oidc

    discovery = await get_discovery(oidc_config.discovery_url)

    # Exchange code for tokens
    token_result = await exchange_code(discovery, oidc_config, code, callback_url)

    if "error" in token_result:
        logger.error(f"OIDC token error: {token_result.get('error_description', token_result.get('error'))}")
        log_security_event(
            event_type="oidc_token_exchange_failed",
            details={**_get_request_context(request), "error": token_result.get("error")},
            level="warning",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to complete authentication. Please try again.",
        )

    # Validate id_token if present
    id_token = token_result.get("id_token")
    if id_token:
        raw_claims = await validate_id_token(id_token, discovery, oidc_config)
        # Validate nonce to prevent replay attacks
        if nonce and raw_claims.get("nonce") != nonce:
            log_security_event(
                event_type="oidc_nonce_mismatch",
                details=_get_request_context(request),
                level="warning",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Authentication failed: nonce mismatch (possible replay attack).",
            )
    else:
        # Some providers don't return id_token in the code exchange —
        # fall back to userinfo endpoint
        raw_claims = await _fetch_userinfo(discovery, token_result["access_token"])

    normalized = extract_claims(raw_claims, oidc_config)

    # Create session
    session_store = SessionStore(db)

    # Session fixation prevention
    existing_session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if existing_session_id:
        await session_store.delete(existing_session_id)

    session_id = _generate_session_id()
    expires_in = token_result.get("expires_in", 3600)

    # Store claims in a consistent format for the /me endpoint
    session_data = {
        "access_token": token_result["access_token"],
        "refresh_token": token_result.get("refresh_token"),
        "id_token": id_token,
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(),
        "provider": "oidc",
        "claims": {
            # Normalized fields that /me and other endpoints expect
            "oid": normalized.sub,
            "sub": normalized.sub,
            "preferred_username": normalized.email,
            "email": normalized.email,
            "name": normalized.name,
            "tid": normalized.tenant_id,
            "roles": normalized.roles,
        },
    }

    await session_store.set(
        session_id, session_data, SESSION_TTL_SECONDS,
        tenant_id=normalized.tenant_id, user_id=normalized.sub,
    )

    audit_log(
        db, tenant_id=None, user_id=None,
        action="login_success", resource_type="session",
        details={
            "provider": "oidc",
            "email": normalized.email,
            "ip": get_client_ip(request),
        },
    )

    response = RedirectResponse(url=final_redirect, status_code=302)
    _set_session_cookie(response, session_id, request)
    return response


async def _fetch_userinfo(discovery: dict, access_token: str) -> dict:
    """Fetch user info from the OIDC userinfo endpoint.

    Used when id_token is not available in the token response.
    """
    import httpx

    userinfo_endpoint = discovery.get("userinfo_endpoint")
    if not userinfo_endpoint:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Provider did not return id_token and has no userinfo_endpoint",
        )

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()


# ---------- Dev Login ----------

@router.post("/dev-login", response_model=DevLoginResponse)
@limiter.limit(lambda: get_settings().rate_limit.auth_limit)
async def dev_login(
    request: Request,
    body: DevLoginRequest,
    db: AsyncSession = Depends(get_session),
) -> DevLoginResponse:
    """Simple username/password login for development only."""
    settings = get_settings()

    if settings.server.environment == "production":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Dev login is disabled in production")
    if settings.auth.provider != "none":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Dev login requires AUTH_PROVIDER=none")
    if not settings.server.debug:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Dev login requires DEBUG=true")

    if body.username != "admin" or body.password != "admin":
        log_security_event(
            event_type="dev_login_failed",
            details={**_get_request_context(request), "username": body.username},
            level="warning",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    session_store = SessionStore(db)
    existing_session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if existing_session_id:
        await session_store.delete(existing_session_id)

    logger.warning("DEV MODE: admin/admin login used — DO NOT USE IN PRODUCTION")
    session_id = _generate_session_id()
    session_data = {
        "access_token": "dev-token",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        "provider": "none",
        "claims": {
            "oid": "dev-user-oid",
            "sub": "dev-user-oid",
            "preferred_username": "admin@localhost",
            "email": "admin@localhost",
            "name": "Admin (Dev)",
            "tid": "dev-tenant",
            "roles": ["admin"],
        },
    }
    await session_store.set(session_id, session_data, SESSION_TTL_SECONDS, tenant_id=None, user_id=None)

    user_info = {"id": "dev-user-oid", "email": "admin@localhost", "name": "Admin (Dev)", "roles": ["admin"]}

    response = JSONResponse(content={"authenticated": True, "user": user_info})
    _set_session_cookie(response, session_id, request)
    return response


# ---------- Logout ----------

@router.post("/logout")
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """Log out the current user. Supports provider-specific logout."""
    settings = get_settings()

    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    id_token = None
    if session_id:
        session_store = SessionStore(db)
        # Get session data before deleting (for id_token_hint)
        session_data = await session_store.get(session_id)
        if session_data:
            id_token = session_data.get("id_token")
            claims = session_data.get("claims", {})
            audit_log(
                db, tenant_id=None, user_id=None,
                action="logout", resource_type="session",
                details={
                    "provider": session_data.get("provider"),
                    "email": claims.get("preferred_username", claims.get("email")),
                    "ip": get_client_ip(request),
                },
            )
        await session_store.delete(session_id)

    is_secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"

    # Check for provider-specific logout
    if settings.auth.provider == "oidc":
        from openlabels.auth.oidc_provider import get_discovery, get_end_session_url

        try:
            discovery = await get_discovery(settings.auth.oidc.discovery_url)
            logout_url = get_end_session_url(
                discovery, settings.auth.oidc,
                post_logout_redirect_uri=str(request.base_url),
                id_token_hint=id_token,
            )
            if logout_url:
                response = RedirectResponse(url=logout_url, status_code=302)
                response.delete_cookie(SESSION_COOKIE_NAME, samesite="lax", secure=is_secure)
                return response
        except Exception:
            logger.debug("Failed to get OIDC end_session_endpoint, falling back to local logout")

    elif settings.auth.provider == "azure_ad" and settings.auth.tenant_id:
        encoded_redirect = quote(str(request.base_url), safe="")
        logout_url = (
            f"https://login.microsoftonline.com/{settings.auth.tenant_id}"
            f"/oauth2/v2.0/logout?post_logout_redirect_uri={encoded_redirect}"
        )
        response = RedirectResponse(url=logout_url, status_code=302)
        response.delete_cookie(SESSION_COOKIE_NAME, samesite="lax", secure=is_secure)
        return response

    # Local-only logout
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(SESSION_COOKIE_NAME, samesite="lax", secure=is_secure)
    return response


# ---------- User Info ----------

@router.get("/me", response_model=UserInfoResponse)
@limiter.limit(lambda: get_settings().rate_limit.api_limit)
async def get_current_user_info(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> UserInfoResponse:
    """Get current user information from session."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    session_store = SessionStore(db)
    session_data = await session_store.get(session_id)

    if not session_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")

    # Check token expiration
    expires_at_str = session_data.get("expires_at")
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str)
        if expires_at < datetime.now(timezone.utc):
            await session_store.delete(session_id)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")

    claims = session_data.get("claims", {})

    return UserInfoResponse(
        id=claims.get("oid", claims.get("sub", "unknown")),
        email=claims.get("preferred_username", claims.get("email", "unknown")),
        name=claims.get("name"),
        tenant_id=claims.get("tid", "unknown"),
        roles=claims.get("roles", []),
    )


# ---------- Token ----------

@router.post("/token", response_model=TokenResponse)
@limiter.limit(lambda: get_settings().rate_limit.auth_limit)
async def get_token(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """Get access token for API calls."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    session_store = SessionStore(db)
    session_data = await session_store.get(session_id)

    if not session_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")

    expires_at_str = session_data.get("expires_at")
    expires_at = datetime.fromisoformat(expires_at_str) if expires_at_str else datetime.min.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        # Try to refresh
        lock = _refresh_locks.setdefault(session_id, asyncio.Lock())
        try:
            async with lock:
                session_data = await session_store.get(session_id)
                if session_data is None:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired, please login again")

                expires_at_str = session_data.get("expires_at")
                expires_at = datetime.fromisoformat(expires_at_str) if expires_at_str else datetime.min.replace(tzinfo=timezone.utc)

                if expires_at < datetime.now(timezone.utc):
                    refresh_token_value = session_data.get("refresh_token")
                    if refresh_token_value:
                        provider = session_data.get("provider", "azure_ad")
                        try:
                            result = await _refresh_token(provider, refresh_token_value)

                            if "access_token" in result:
                                new_expires_in = result.get("expires_in", 3600)
                                session_data["access_token"] = result["access_token"]
                                session_data["expires_at"] = (
                                    datetime.now(timezone.utc) + timedelta(seconds=new_expires_in)
                                ).isoformat()
                                if "refresh_token" in result:
                                    session_data["refresh_token"] = result["refresh_token"]
                                await session_store.set(session_id, session_data, SESSION_TTL_SECONDS)
                                expires_at = datetime.fromisoformat(session_data["expires_at"])
                            else:
                                await session_store.delete(session_id)
                                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired, please login again")
                        except HTTPException:
                            raise
                        except (ConnectionError, OSError, RuntimeError, ValueError) as e:
                            logger.warning(f"Token refresh failed: {type(e).__name__}: {e}")
                            await session_store.delete(session_id)
                            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired, please login again") from e
                    else:
                        await session_store.delete(session_id)
                        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired, please login again")
        finally:
            _refresh_locks.pop(session_id, None)

    expires_in = int((expires_at - datetime.now(timezone.utc)).total_seconds())

    return TokenResponse(
        access_token=session_data["access_token"],
        expires_in=max(expires_in, 0),
        scope="openid profile email",
    )


async def _refresh_token(provider: str, refresh_token_value: str) -> dict:
    """Refresh an access token using the appropriate provider."""
    if provider == "oidc":
        from openlabels.auth.oidc_provider import get_discovery
        from openlabels.auth.oidc_provider import refresh_token as oidc_refresh

        settings = get_settings()
        discovery = await get_discovery(settings.auth.oidc.discovery_url)
        return await oidc_refresh(discovery, settings.auth.oidc, refresh_token_value)
    else:
        # Azure AD via MSAL
        msal_app = _get_msal_app()
        return msal_app.acquire_token_by_refresh_token(
            refresh_token_value,
            scopes=["User.Read", "openid", "profile", "email"],
        )


# ---------- Status ----------

@router.get("/status")
@limiter.limit(lambda: get_settings().rate_limit.api_limit)
async def auth_status(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> dict:
    """Check authentication status."""
    settings = get_settings()
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    authenticated = False
    user_info = None

    if session_id:
        session_store = SessionStore(db)
        session_data = await session_store.get(session_id)

        if session_data:
            expires_at_str = session_data.get("expires_at")
            if expires_at_str:
                expires_at = datetime.fromisoformat(expires_at_str)
                if expires_at > datetime.now(timezone.utc):
                    authenticated = True
                    claims = session_data.get("claims", {})
                    user_info = {
                        "id": claims.get("oid", claims.get("sub")),
                        "email": claims.get("preferred_username", claims.get("email")),
                        "name": claims.get("name"),
                    }

    return {
        "authenticated": authenticated,
        "provider": settings.auth.provider,
        "user": user_info,
        "login_url": str(request.url.path).rsplit("/status", 1)[0] + "/login" if not authenticated else None,
    }


# ---------- Revoke ----------

@router.post("/revoke")
@limiter.limit(lambda: get_settings().rate_limit.auth_limit)
async def revoke_token(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> dict:
    """Revoke the current session token."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    session_store = SessionStore(db)
    deleted = await session_store.delete(session_id)

    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found or already revoked")

    audit_log(
        db, tenant_id=None, user_id=None,
        action="session_revoked", resource_type="session",
        details={"ip": get_client_ip(request)},
    )

    return {"status": "revoked", "message": "Session has been revoked"}


# ---------- Logout All ----------

@router.post("/logout-all")
@limiter.limit(lambda: get_settings().rate_limit.auth_limit)
async def logout_all_sessions(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> dict:
    """Log out all sessions for the current user."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    session_store = SessionStore(db)
    session_data = await session_store.get(session_id)

    if not session_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")

    claims = session_data.get("claims", {})
    user_id = claims.get("oid", claims.get("sub"))

    if not user_id:
        await session_store.delete(session_id)
        return {"status": "success", "sessions_revoked": 1}

    count = await session_store.delete_all_for_user(user_id)
    logger.info(f"User {user_id} logged out of {count} sessions")

    return {
        "status": "success",
        "sessions_revoked": count,
        "message": f"Logged out of {count} session(s) across all devices",
    }
