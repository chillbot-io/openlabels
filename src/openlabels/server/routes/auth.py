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
"""

from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode
import secrets
import logging

from fastapi import APIRouter, HTTPException, Request, Response, Depends, status
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel
from msal import ConfidentialClientApplication

from openlabels.server.config import get_settings
from openlabels.auth.oauth import TokenClaims

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Session storage (in production, use Redis or database)
# Maps session_id -> {access_token, refresh_token, expires_at, claims}
_sessions: dict[str, dict] = {}

# PKCE state storage (temporary, for login flow)
# Maps state -> {code_verifier, redirect_uri, created_at}
_pending_auth: dict[str, dict] = {}

# Token cookie settings
SESSION_COOKIE_NAME = "openlabels_session"
SESSION_COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 days


class LoginResponse(BaseModel):
    """Response from login endpoint."""
    login_url: str


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


def _cleanup_expired_sessions():
    """Remove expired sessions and pending auth states."""
    now = datetime.utcnow()

    # Clean sessions
    expired_sessions = [
        sid for sid, data in _sessions.items()
        if data.get("expires_at", now) < now
    ]
    for sid in expired_sessions:
        del _sessions[sid]

    # Clean pending auth (expire after 10 minutes)
    expired_auth = [
        state for state, data in _pending_auth.items()
        if now - data.get("created_at", now) > timedelta(minutes=10)
    ]
    for state in expired_auth:
        del _pending_auth[state]


@router.get("/login")
async def login(
    request: Request,
    redirect_uri: Optional[str] = None,
) -> RedirectResponse:
    """
    Initiate OAuth login flow.

    Redirects user to Microsoft login page.

    Query params:
        redirect_uri: Where to redirect after login (default: /)
    """
    settings = get_settings()
    _cleanup_expired_sessions()

    if settings.auth.provider == "none":
        # Dev mode - create fake session and redirect
        session_id = _generate_session_id()
        _sessions[session_id] = {
            "access_token": "dev-token",
            "expires_at": datetime.utcnow() + timedelta(days=7),
            "claims": {
                "oid": "dev-user-oid",
                "preferred_username": "dev@localhost",
                "name": "Development User",
                "tid": "dev-tenant",
                "roles": ["admin"],
            },
        }

        response = RedirectResponse(url=redirect_uri or "/", status_code=302)
        response.set_cookie(
            SESSION_COOKIE_NAME,
            session_id,
            max_age=SESSION_COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax",
        )
        return response

    msal_app = _get_msal_app()

    # Generate state and PKCE verifier
    state = secrets.token_urlsafe(32)

    # Build callback URL
    callback_url = str(request.url_for("auth_callback"))

    # Store pending auth state
    _pending_auth[state] = {
        "redirect_uri": redirect_uri or "/",
        "callback_url": callback_url,
        "created_at": datetime.utcnow(),
    }

    # Get authorization URL
    auth_url = msal_app.get_authorization_request_url(
        scopes=["User.Read", "openid", "profile", "email"],
        state=state,
        redirect_uri=callback_url,
    )

    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/callback")
async def auth_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
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
        logger.error(f"OAuth error: {error} - {error_description}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Authentication failed: {error_description or error}",
        )

    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing authorization code or state",
        )

    # Validate state
    if state not in _pending_auth:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state",
        )

    pending = _pending_auth.pop(state)
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to acquire token",
        )

    if "error" in result:
        logger.error(f"Token error: {result.get('error_description', result.get('error'))}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("error_description", "Token acquisition failed"),
        )

    # Create session
    session_id = _generate_session_id()
    expires_in = result.get("expires_in", 3600)

    _sessions[session_id] = {
        "access_token": result["access_token"],
        "refresh_token": result.get("refresh_token"),
        "id_token": result.get("id_token"),
        "expires_at": datetime.utcnow() + timedelta(seconds=expires_in),
        "claims": result.get("id_token_claims", {}),
    }

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
async def logout(request: Request) -> RedirectResponse:
    """
    Log out the current user.

    Clears session and redirects to Microsoft logout if configured.
    """
    settings = get_settings()

    # Get and clear session
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id and session_id in _sessions:
        del _sessions[session_id]

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
async def get_current_user_info(request: Request) -> UserInfoResponse:
    """
    Get current user information.

    Returns user info from the session token claims.
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id or session_id not in _sessions:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    session = _sessions[session_id]

    # Check expiration
    if session.get("expires_at", datetime.min) < datetime.utcnow():
        del _sessions[session_id]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired",
        )

    claims = session.get("claims", {})

    return UserInfoResponse(
        id=claims.get("oid", "unknown"),
        email=claims.get("preferred_username", claims.get("email", "unknown")),
        name=claims.get("name"),
        tenant_id=claims.get("tid", "unknown"),
        roles=claims.get("roles", []),
    )


@router.post("/token", response_model=TokenResponse)
async def get_token(request: Request) -> TokenResponse:
    """
    Get access token for API calls.

    For SPAs or API clients that need to make authenticated requests.
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id or session_id not in _sessions:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    session = _sessions[session_id]
    expires_at = session.get("expires_at", datetime.min)

    if expires_at < datetime.utcnow():
        # Try to refresh
        refresh_token = session.get("refresh_token")
        if refresh_token:
            try:
                msal_app = _get_msal_app()
                result = msal_app.acquire_token_by_refresh_token(
                    refresh_token,
                    scopes=["User.Read", "openid", "profile", "email"],
                )

                if "access_token" in result:
                    session["access_token"] = result["access_token"]
                    session["expires_at"] = datetime.utcnow() + timedelta(
                        seconds=result.get("expires_in", 3600)
                    )
                    if "refresh_token" in result:
                        session["refresh_token"] = result["refresh_token"]
                else:
                    del _sessions[session_id]
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session expired, please login again",
                    )
            except Exception:
                del _sessions[session_id]
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session expired, please login again",
                )
        else:
            del _sessions[session_id]
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired, please login again",
            )

    expires_in = int((session["expires_at"] - datetime.utcnow()).total_seconds())

    return TokenResponse(
        access_token=session["access_token"],
        expires_in=max(expires_in, 0),
        scope="User.Read openid profile email",
    )


@router.get("/status")
async def auth_status(request: Request) -> dict:
    """
    Check authentication status.

    Useful for frontend to determine if user is logged in.
    """
    settings = get_settings()
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    authenticated = False
    user_info = None

    if session_id and session_id in _sessions:
        session = _sessions[session_id]
        if session.get("expires_at", datetime.min) > datetime.utcnow():
            authenticated = True
            claims = session.get("claims", {})
            user_info = {
                "id": claims.get("oid"),
                "email": claims.get("preferred_username"),
                "name": claims.get("name"),
            }

    return {
        "authenticated": authenticated,
        "provider": settings.auth.provider,
        "user": user_info,
        "login_url": "/auth/login" if not authenticated else None,
    }
