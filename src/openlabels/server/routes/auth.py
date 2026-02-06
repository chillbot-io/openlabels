"""
OAuth 2.0 authentication routes for OpenLabels.

Implements the Authorization Code Flow with PKCE for secure authentication
with Microsoft Entra ID (Azure AD).

Flow:
1. User visits /auth/login
2. Redirected to Microsoft login
3. After login, redirected to /auth/callback with authorization code
4. Server exchanges code for tokens
5. User redirected to app with session established

Sessions are stored in PostgreSQL for production reliability.

Security features:
- Open redirect prevention via URL validation
- Rate limiting on auth endpoints
- Secure session cookies with HttpOnly and SameSite
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse
import secrets
import logging

from fastapi import APIRouter, HTTPException, Request, Depends, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from msal import ConfidentialClientApplication
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter

from openlabels.server.config import get_settings
from openlabels.server.utils import get_client_ip
from openlabels.server.db import get_session
from openlabels.server.session import SessionStore, PendingAuthStore
from openlabels.server.security import log_security_event

logger = logging.getLogger(__name__)


def _get_request_context(request: Request) -> dict:
    """Extract request context for security logging."""
    return {
        "ip": get_client_ip(request),
        "user_agent": request.headers.get("user-agent", "unknown"),
        "path": str(request.url.path),
    }


def validate_redirect_uri(redirect_uri: Optional[str], request: Request) -> str:
    """
    Validate redirect URI to prevent open redirect attacks.

    Security: Only allows:
    1. Relative paths starting with /
    2. URLs matching the request's host (same-origin)
    3. URLs in the configured CORS allowed_origins

    Args:
        redirect_uri: The redirect URI to validate
        request: The current request (for host validation)

    Returns:
        Safe redirect URI (defaults to "/" if invalid)
    """
    if not redirect_uri:
        return "/"

    # Handle relative paths - must start with single /
    if redirect_uri.startswith("/"):
        # Block protocol-relative URLs (//evil.com)
        if redirect_uri.startswith("//"):
            logger.warning(f"Blocked protocol-relative redirect: {redirect_uri}")
            return "/"
        # Ensure no path traversal or weird characters
        # Only allow safe relative paths
        return redirect_uri

    # Parse the URL for validation
    try:
        parsed = urlparse(redirect_uri)
    except Exception as e:
        # Log the exception type and message for debugging URL parsing failures
        logger.warning(
            f"Failed to parse redirect URI '{redirect_uri}': {type(e).__name__}: {e}"
        )
        return "/"

    # Must have a valid scheme
    if parsed.scheme not in ("http", "https"):
        logger.warning(f"Blocked redirect with invalid scheme: {redirect_uri}")
        return "/"

    # Get the request's origin
    request_host = request.url.netloc

    # Check if redirect is to same host (same-origin)
    if parsed.netloc == request_host:
        return redirect_uri

    # Check against CORS allowed origins
    settings = get_settings()
    redirect_origin = f"{parsed.scheme}://{parsed.netloc}"

    if redirect_origin in settings.cors.allowed_origins:
        return redirect_uri

    # Log attempted open redirect attack
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


class UserInfoResponse(BaseModel):
    """Current user information."""
    id: str
    email: str
    name: Optional[str]
    tenant_id: str
    roles: list[str]


class TokenResponse(BaseModel):
    """Token response for API clients."""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str


def _get_msal_app() -> ConfidentialClientApplication:
    """Get MSAL confidential client application."""
    settings = get_settings()

    if settings.auth.provider == "none":
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Authentication not configured. Set AUTH_PROVIDER=azure_ad",
        )

    return ConfidentialClientApplication(
        client_id=settings.auth.client_id,
        client_credential=settings.auth.client_secret,
        authority=f"https://login.microsoftonline.com/{settings.auth.tenant_id}",
    )


def _generate_session_id() -> str:
    """Generate secure session ID."""
    return secrets.token_urlsafe(32)


@router.get("/login")
@limiter.limit(lambda: get_settings().rate_limit.auth_limit)
async def login(
    request: Request,
    redirect_uri: Optional[str] = None,
    db: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """
    Initiate OAuth login flow.

    Redirects user to Microsoft login page.

    Query params:
        redirect_uri: Where to redirect after login (default: /)
    """
    settings = get_settings()
    session_store = SessionStore(db)
    pending_store = PendingAuthStore(db)

    # Cleanup expired entries periodically
    await session_store.cleanup_expired()
    await pending_store.cleanup_expired()

    if settings.auth.provider == "none":
        # SECURITY: Block dev mode auth in production environment
        if settings.server.environment == "production":
            logger.error("SECURITY: Dev mode auth (AUTH_PROVIDER=none) is disabled in production!")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication not configured. Set AUTH_PROVIDER=azure_ad for production.",
            )

        # Dev mode - create fake session and redirect
        # SECURITY: Only allow in debug mode to prevent accidental production use
        if not settings.server.debug:
            logger.error(
                "SECURITY: AUTH_PROVIDER=none requires DEBUG=true. "
                "Set AUTH_PROVIDER=azure_ad for production."
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication not configured for production. Contact administrator.",
            )

        # SECURITY: Session fixation prevention - invalidate any existing session
        # before creating a new one to prevent session accumulation
        existing_session_id = request.cookies.get(SESSION_COOKIE_NAME)
        if existing_session_id:
            await session_store.delete(existing_session_id)
            logger.debug("DEV MODE: Invalidated existing session before creating new one")

        logger.warning("DEV MODE: Creating fake admin session - DO NOT USE IN PRODUCTION")
        session_id = _generate_session_id()
        session_data = {
            "access_token": "dev-token",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
            "claims": {
                "oid": "dev-user-oid",
                "preferred_username": "dev@localhost",
                "name": "Development User",
                "tid": "dev-tenant",
                "roles": ["admin"],
            },
        }
        await session_store.set(
            session_id,
            session_data,
            SESSION_TTL_SECONDS,
            tenant_id=None,
            user_id=None,
        )

        # Validate redirect URI to prevent open redirect attacks
        safe_redirect = validate_redirect_uri(redirect_uri, request)

        response = RedirectResponse(url=safe_redirect, status_code=302)
        response.set_cookie(
            SESSION_COOKIE_NAME,
            session_id,
            max_age=SESSION_COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax",
            secure=request.url.scheme == "https",
        )
        return response

    msal_app = _get_msal_app()

    # Generate state
    state = secrets.token_urlsafe(32)

    # Build callback URL
    callback_url = str(request.url_for("auth_callback"))

    # Validate redirect URI before storing - prevents open redirect after OAuth flow
    safe_redirect = validate_redirect_uri(redirect_uri, request)

    # Store pending auth state
    await pending_store.set(state, safe_redirect, callback_url)

    # Get authorization URL
    auth_url = msal_app.get_authorization_request_url(
        scopes=["User.Read", "openid", "profile", "email"],
        state=state,
        redirect_uri=callback_url,
    )

    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/callback")
@limiter.limit(lambda: get_settings().rate_limit.auth_limit)
async def auth_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    db: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """
    OAuth callback endpoint.

    Microsoft redirects here after user login.
    """
    settings = get_settings()

    if settings.auth.provider == "none":
        return RedirectResponse(url="/", status_code=302)

    # Handle errors from Microsoft
    if error:
        # Log detailed error server-side for debugging
        logger.error(f"OAuth error: {error} - {error_description}")
        # Security: Log failed authentication attempt
        log_security_event(
            event_type="oauth_error",
            details={
                **_get_request_context(request),
                "error": error,
                "error_code": error_description[:100] if error_description else None,
            },
            level="warning",
        )
        # Return generic message to client to prevent information leakage
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
                "state_hash": hash(state) % 10000,  # Log hash, not actual state
            },
            level="warning",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state",
        )

    # Remove pending state
    await pending_store.delete(state)

    callback_url = pending["callback_url"]
    final_redirect = pending["redirect_uri"]

    # Exchange code for tokens
    msal_app = _get_msal_app()

    try:
        result = msal_app.acquire_token_by_authorization_code(
            code=code,
            scopes=["User.Read", "openid", "profile", "email"],
            redirect_uri=callback_url,
        )
    except Exception as e:
        logger.error(f"Token acquisition failed: {e}")
        log_security_event(
            event_type="token_acquisition_failed",
            details={
                **_get_request_context(request),
                "error_type": type(e).__name__,
            },
            level="error",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to acquire token",
        )

    if "error" in result:
        # Log detailed error server-side for debugging
        logger.error(f"Token error: {result.get('error_description', result.get('error'))}")
        log_security_event(
            event_type="token_exchange_failed",
            details={
                **_get_request_context(request),
                "error": result.get("error"),
            },
            level="warning",
        )
        # Return generic message to client to prevent information leakage
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to complete authentication. Please try again.",
        )

    # Create session
    session_store = SessionStore(db)

    # SECURITY: Session fixation prevention - invalidate any existing session
    # before creating a new one after successful authentication
    existing_session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if existing_session_id:
        await session_store.delete(existing_session_id)
        logger.debug("Invalidated existing session during OAuth callback")

    session_id = _generate_session_id()
    expires_in = result.get("expires_in", 3600)

    id_token_claims = result.get("id_token_claims", {})
    session_data = {
        "access_token": result["access_token"],
        "refresh_token": result.get("refresh_token"),
        "id_token": result.get("id_token"),
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(),
        "claims": id_token_claims,
    }
    # Store with user_id for logout-all functionality
    user_id = id_token_claims.get("oid")
    tenant_id = id_token_claims.get("tid")
    await session_store.set(
        session_id,
        session_data,
        SESSION_TTL_SECONDS,
        tenant_id=tenant_id,
        user_id=user_id,
    )

    # Redirect with session cookie
    response = RedirectResponse(url=final_redirect, status_code=302)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )

    return response


@router.get("/logout")
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """
    Log out the current user.

    Clears session and redirects to Microsoft logout if configured.
    """
    settings = get_settings()

    # Get and clear session
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        session_store = SessionStore(db)
        await session_store.delete(session_id)

    # Create response that clears cookie
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(SESSION_COOKIE_NAME)

    # Optionally redirect to Microsoft logout
    if settings.auth.provider == "azure_ad" and settings.auth.tenant_id:
        logout_url = (
            f"https://login.microsoftonline.com/{settings.auth.tenant_id}"
            f"/oauth2/v2.0/logout?post_logout_redirect_uri={request.base_url}"
        )
        return RedirectResponse(url=logout_url, status_code=302)

    return response


@router.get("/me", response_model=UserInfoResponse)
async def get_current_user_info(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> UserInfoResponse:
    """
    Get current user information.

    Returns user info from the session token claims.
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    session_store = SessionStore(db)
    session_data = await session_store.get(session_id)

    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
        )

    # Check token expiration
    expires_at_str = session_data.get("expires_at")
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str)
        if expires_at < datetime.now(timezone.utc):
            await session_store.delete(session_id)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired",
            )

    claims = session_data.get("claims", {})

    return UserInfoResponse(
        id=claims.get("oid", "unknown"),
        email=claims.get("preferred_username", claims.get("email", "unknown")),
        name=claims.get("name"),
        tenant_id=claims.get("tid", "unknown"),
        roles=claims.get("roles", []),
    )


@router.post("/token", response_model=TokenResponse)
async def get_token(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """
    Get access token for API calls.

    For SPAs or API clients that need to make authenticated requests.
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    session_store = SessionStore(db)
    session_data = await session_store.get(session_id)

    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
        )

    expires_at_str = session_data.get("expires_at")
    expires_at = datetime.fromisoformat(expires_at_str) if expires_at_str else datetime.min

    if expires_at < datetime.now(timezone.utc):
        # Try to refresh
        refresh_token = session_data.get("refresh_token")
        if refresh_token:
            try:
                msal_app = _get_msal_app()
                result = msal_app.acquire_token_by_refresh_token(
                    refresh_token,
                    scopes=["User.Read", "openid", "profile", "email"],
                )

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
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session expired, please login again",
                    )
            except HTTPException:
                raise
            except Exception as e:
                # SECURITY: Log token refresh failures for security monitoring
                # This could indicate token theft, expired credentials, or service issues
                logger.warning(f"Token refresh failed during session validation: {type(e).__name__}: {e}")
                await session_store.delete(session_id)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session expired, please login again",
                )
        else:
            await session_store.delete(session_id)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired, please login again",
            )

    expires_in = int((expires_at - datetime.now(timezone.utc)).total_seconds())

    return TokenResponse(
        access_token=session_data["access_token"],
        expires_in=max(expires_in, 0),
        scope="User.Read openid profile email",
    )


@router.get("/status")
async def auth_status(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> dict:
    """
    Check authentication status.

    Useful for frontend to determine if user is logged in.
    """
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
                        "id": claims.get("oid"),
                        "email": claims.get("preferred_username"),
                        "name": claims.get("name"),
                    }

    return {
        "authenticated": authenticated,
        "provider": settings.auth.provider,
        "user": user_info,
        "login_url": str(request.url.path).rsplit("/status", 1)[0] + "/login" if not authenticated else None,
    }


@router.post("/revoke")
async def revoke_token(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> dict:
    """
    Revoke the current session token.

    This invalidates the current session immediately.
    For API clients that want to explicitly revoke their token.
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    session_store = SessionStore(db)
    deleted = await session_store.delete(session_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or already revoked",
        )

    return {"status": "revoked", "message": "Session has been revoked"}


@router.post("/logout-all")
async def logout_all_sessions(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> dict:
    """
    Log out all sessions for the current user.

    Useful when user suspects account compromise or wants to
    force re-authentication on all devices.
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    session_store = SessionStore(db)
    session_data = await session_store.get(session_id)

    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
        )

    # Get user ID from claims
    claims = session_data.get("claims", {})
    user_id = claims.get("oid")

    if not user_id:
        # If no user_id in claims, just delete current session
        await session_store.delete(session_id)
        return {"status": "success", "sessions_revoked": 1}

    # Delete all sessions for this user
    count = await session_store.delete_all_for_user(user_id)

    logger.info(f"User {user_id} logged out of {count} sessions")

    return {
        "status": "success",
        "sessions_revoked": count,
        "message": f"Logged out of {count} session(s) across all devices",
    }
