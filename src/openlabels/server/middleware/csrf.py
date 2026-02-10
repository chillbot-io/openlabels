"""
CSRF protection middleware for OpenLabels.

Implements double-submit cookie pattern and origin validation to protect
against Cross-Site Request Forgery attacks.

Protection mechanisms:
1. Origin/Referer header validation for state-changing requests
2. Double-submit CSRF token (cookie + header must match)
3. SameSite cookie attribute (already set in auth.py)
"""

import logging
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

# Methods that require CSRF protection
PROTECTED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# Paths exempt from CSRF (e.g., auth callbacks, webhooks)
EXEMPT_PATHS = {
    "/auth/callback",  # OAuth callback from Microsoft
    "/health",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
}


def generate_csrf_token() -> str:
    """Generate a secure CSRF token."""
    return secrets.token_urlsafe(CSRF_TOKEN_LENGTH)


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
    """
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    header_token = request.headers.get(CSRF_HEADER_NAME)

    if not cookie_token or not header_token:
        return False

    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(cookie_token, header_token)


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

        # Skip CSRF for dev mode
        if settings.auth.provider == "none":
            response = await call_next(request)
            return response

        # Skip for safe methods
        if request.method not in PROTECTED_METHODS:
            response = await call_next(request)
            # Set CSRF cookie on GET requests if not present
            if request.method == "GET" and CSRF_COOKIE_NAME not in request.cookies:
                self._set_csrf_cookie(request, response)
            return response

        # Skip exempt paths
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        # Skip WebSocket upgrade requests
        if request.headers.get("upgrade", "").lower() == "websocket":
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
            # Allow API requests that use Bearer auth (they don't need CSRF tokens)
            auth_header = request.headers.get("authorization", "")
            if not auth_header.startswith("Bearer "):
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
        """Set CSRF token cookie."""
        token = generate_csrf_token()
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=token,
            max_age=60 * 60 * 24 * 7,  # 7 days (match session)
            httponly=False,  # Must be readable by JavaScript
            samesite="lax",
            secure=request.url.scheme == "https",
            path="/",
        )
