"""
CSRF protection middleware for OpenLabels.

Implements double-submit cookie pattern and origin validation to protect
against Cross-Site Request Forgery attacks.

Protection mechanisms:
1. Origin/Referer header validation for state-changing requests
2. Double-submit CSRF token (cookie + header must match)
3. SameSite cookie attribute (already set in auth.py)
"""

import hashlib
import hmac
import logging
import posixpath
import secrets
from collections.abc import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from openlabels.server.config import get_settings

logger = logging.getLogger(__name__)

# CSRF token cookie name
CSRF_COOKIE_NAME = "openlabels_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_TOKEN_LENGTH = 32
SESSION_COOKIE_NAME = "openlabels_session"

# Methods that require CSRF protection
PROTECTED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# Paths exempt from CSRF (e.g., auth callbacks, webhooks).
# Includes both bare and /api/v1/-prefixed variants so that the
# versioned API routes are matched correctly.
EXEMPT_PATHS = {
    "/auth/callback",  # OAuth callback (legacy)
    "/api/v1/auth/callback",  # OAuth callback (versioned)
    "/health",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/api/v1/webhooks/m365",  # M365 audit webhook (external POST)
    "/api/v1/webhooks/graph",  # Graph change notification webhook (external POST)
}


def _normalize_path(path: str) -> str:
    """Normalize a URL path: collapse double slashes, resolve dots, strip trailing slash."""
    # posixpath.normpath collapses // and resolves . / ..
    normalized = posixpath.normpath(path)
    # POSIX preserves exactly two leading slashes (//foo); collapse to single slash
    # since URL paths should always start with a single slash.
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    # Strip trailing slash for consistent matching (but keep "/" as-is)
    if normalized != "/" and normalized.endswith("/"):
        normalized = normalized.rstrip("/")
    return normalized


def _session_binding(session_id: str) -> str:
    """Derive a short binding hash from a session ID."""
    return hashlib.sha256(session_id.encode()).hexdigest()[:16]


def generate_csrf_token(session_id: str | None = None) -> str:
    """Generate a secure CSRF token, optionally bound to a session ID."""
    raw = secrets.token_urlsafe(CSRF_TOKEN_LENGTH)
    if session_id:
        return f"{raw}.{_session_binding(session_id)}"
    return raw


def is_same_origin(request: Request) -> bool:
    """
    Check if request originates from the same origin.

    Validates Origin header (preferred) or Referer header.
    """
    settings = get_settings()
    allowed_origins = set(settings.cors.allowed_origins)

    # Get origin from headers
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")

    if origin:
        # Check against allowed origins
        if origin in allowed_origins:
            return True
        # Also allow same host
        request_origin = f"{request.url.scheme}://{request.url.netloc}"
        if origin == request_origin:
            return True
        logger.warning(f"CSRF: Origin mismatch - got {origin}, expected {allowed_origins}")
        return False

    if referer:
        # Parse referer to get origin
        from urllib.parse import urlparse
        parsed = urlparse(referer)
        referer_origin = f"{parsed.scheme}://{parsed.netloc}"
        if referer_origin in allowed_origins:
            return True
        request_origin = f"{request.url.scheme}://{request.url.netloc}"
        if referer_origin == request_origin:
            return True
        logger.warning(f"CSRF: Referer mismatch - got {referer_origin}")
        return False

    # No origin or referer — reject for state-changing requests.
    # Legitimate browser requests always include at least one of these headers.
    logger.warning("CSRF: No Origin or Referer header present")
    return False


def validate_csrf_token(request: Request) -> bool:
    """
    Validate CSRF token using double-submit cookie pattern.

    The token in the X-CSRF-Token header must match the token in the cookie.
    If a session cookie is present, the CSRF token must be bound to that session.
    """
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    header_token = request.headers.get(CSRF_HEADER_NAME)

    if not cookie_token or not header_token:
        return False

    # Constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(cookie_token, header_token):
        return False

    # If user has a session, verify the CSRF token is bound to it
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        expected_suffix = f".{_session_binding(session_id)}"
        if not cookie_token.endswith(expected_suffix):
            logger.warning("CSRF: token not bound to current session")
            return False

    return True


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF protection middleware.

    Validates state-changing requests have proper CSRF protection via:
    1. Origin/Referer header validation
    2. Double-submit CSRF token validation

    Sets CSRF token cookie on responses if not present.
    """

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        settings = get_settings()

        # Skip CSRF validation for dev/test mode only, but still set the cookie
        # so the frontend can read it (apiFetch requires it for POST/PUT/DELETE).
        # SECURITY: Only bypass CSRF when BOTH conditions are true:
        # 1. Auth is explicitly disabled (provider="none")
        # 2. Environment is explicitly development or testing (never staging/production)
        if settings.auth.provider == "none":
            if settings.server.environment not in ("development", "testing"):
                logger.error(
                    "CSRF: auth.provider='none' in '%s' environment. "
                    "CSRF protection remains ENABLED. Fix auth configuration.",
                    settings.server.environment,
                )
            else:
                response = await call_next(request)
                if request.method == "GET" and CSRF_COOKIE_NAME not in request.cookies:
                    self._set_csrf_cookie(request, response)
                return response

        # Skip for safe methods
        if request.method not in PROTECTED_METHODS:
            response = await call_next(request)
            # Set CSRF cookie on GET requests if not present
            if request.method == "GET" and CSRF_COOKIE_NAME not in request.cookies:
                self._set_csrf_cookie(request, response)
            return response

        # Skip exempt paths (normalize to prevent bypass via double slashes, etc.)
        if _normalize_path(request.url.path) in EXEMPT_PATHS:
            return await call_next(request)

        # WebSocket upgrade requests: skip token check but validate origin
        if request.headers.get("upgrade", "").lower() == "websocket":
            if not is_same_origin(request):
                logger.warning(
                    "CSRF: WebSocket upgrade rejected - origin check failed for %s",
                    request.url.path,
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "csrf_validation_failed",
                        "message": "CSRF validation failed: invalid origin for WebSocket upgrade",
                    },
                )
            return await call_next(request)

        # Validate CSRF protection
        # Option 1: Origin validation (sufficient for most cases)
        if not is_same_origin(request):
            logger.warning(f"CSRF validation failed: origin check failed for {request.url.path}")
            return JSONResponse(
                status_code=403,
                content={
                    "error": "csrf_validation_failed",
                    "message": "CSRF validation failed: invalid origin",
                },
            )

        # Option 2: Double-submit token validation (required for all protected requests)
        if not validate_csrf_token(request):
            logger.warning(f"CSRF validation failed: token mismatch for {request.url.path}")
            return JSONResponse(
                status_code=403,
                content={
                    "error": "csrf_validation_failed",
                    "message": "CSRF validation failed: missing or invalid token",
                },
            )

        response = await call_next(request)
        return response

    def _set_csrf_cookie(self, request: Request, response: Response) -> None:
        """Set CSRF token cookie, bound to session if available."""
        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        token = generate_csrf_token(session_id)
        # SECURITY: Detect HTTPS via X-Forwarded-Proto for TLS-terminating reverse proxies
        is_secure = (
            request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto") == "https"
        )
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=token,
            max_age=60 * 60 * 24 * 7,  # 7 days (match session)
            httponly=False,  # Must be readable by JavaScript
            samesite="lax",
            secure=is_secure,
            path="/",
        )
