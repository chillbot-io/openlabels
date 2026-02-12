"""Middleware registration for the FastAPI application.

All middleware functions and configuration live here so that ``app.py``
stays a thin application factory.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, Response
from slowapi.middleware import SlowAPIMiddleware

from openlabels.server.config import get_settings
from openlabels.server.logging import get_request_id, set_request_id
from openlabels.server.metrics import http_active_connections, record_http_request
from openlabels.server.middleware.csrf import CSRFMiddleware

logger = logging.getLogger(__name__)

# Type alias for the ``call_next`` parameter of HTTP middleware.
_CallNext = Callable[[Request], Coroutine[Any, Any, Response]]


# ---------------------------------------------------------------------------
# Standalone middleware functions (importable for unit testing)
# ---------------------------------------------------------------------------


async def add_request_id(request: Request, call_next: _CallNext) -> Response:
    """Attach a correlation ID to every request/response."""
    raw_id = request.headers.get("X-Request-ID")
    if raw_id:
        # Sanitize: alphanumeric, hyphens, underscores only; max 64 chars
        import re as _re
        request_id = _re.sub(r"[^a-zA-Z0-9_-]", "", raw_id)[:64] or str(uuid.uuid4())[:8]
    else:
        request_id = str(uuid.uuid4())[:8]
    set_request_id(request_id)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


async def track_metrics(request: Request, call_next: _CallNext) -> Response:
    """Track HTTP request metrics for Prometheus."""
    if request.url.path == "/metrics":
        return await call_next(request)

    http_active_connections.inc()
    start_time = time.perf_counter()
    try:
        response = await call_next(request)
        duration = time.perf_counter() - start_time
        record_http_request(
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration=duration,
        )
        return response
    except Exception:
        duration = time.perf_counter() - start_time
        record_http_request(
            method=request.method,
            path=request.url.path,
            status=500,
            duration=duration,
        )
        raise
    finally:
        http_active_connections.dec()


async def limit_request_size(request: Request, call_next: _CallNext) -> Response:
    """Reject request bodies that exceed the configured size limit."""
    settings = get_settings()
    max_size = settings.security.max_request_size_mb * 1024 * 1024
    content_length = request.headers.get("content-length")
    try:
        parsed_length = int(content_length) if content_length else 0
    except (ValueError, TypeError):
        parsed_length = 0
    if parsed_length > max_size:
        request_id = get_request_id()
        body: dict[str, Any] = {
            "error": "REQUEST_TOO_LARGE",
            "message": f"Request body exceeds {settings.security.max_request_size_mb}MB limit",
            "details": {"max_size_mb": settings.security.max_request_size_mb},
        }
        if request_id:
            body["request_id"] = request_id
        return JSONResponse(status_code=413, content=body)
    return await call_next(request)


async def add_security_headers(request: Request, call_next: _CallNext) -> Response:
    """Add security headers (HSTS, CSP, X-Frame-Options, etc.)."""
    response = await call_next(request)
    settings = get_settings()

    if settings.server.environment in ("production", "staging"):
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # NOTE: 'unsafe-inline' for styles is required by HTMX/Tailwind inline styles.
    # Migrate to nonce-based CSP when feasible to eliminate this exception.
    csp_directives = [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self'",
        "connect-src 'self' wss: ws:",
        "frame-ancestors 'self'",
        "form-action 'self'",
        "base-uri 'self'",
    ]
    response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

    permissions = [
        "accelerometer=()",
        "camera=()",
        "geolocation=()",
        "gyroscope=()",
        "magnetometer=()",
        "microphone=()",
        "payment=()",
        "usb=()",
    ]
    response.headers["Permissions-Policy"] = ", ".join(permissions)
    return response


async def add_deprecation_warning(request: Request, call_next: _CallNext) -> Response:
    """Add deprecation headers for legacy /api/* (non-versioned) routes."""
    response = await call_next(request)
    path = request.url.path

    if (
        path.startswith("/api/")
        and not path.startswith("/api/v1")
        and not path.startswith("/api/docs")
        and not path.startswith("/api/redoc")
        and not path.startswith("/api/openapi")
    ):
        response.headers["X-API-Deprecation"] = "true"
        response.headers["X-API-Deprecation-Date"] = "2026-12-01"
        response.headers["X-API-Deprecation-Info"] = (
            "This API endpoint is deprecated. Please migrate to /api/v1/. "
            "See /api for version information."
        )
        response.headers["Deprecation"] = "true"
        response.headers["Sunset"] = "2026-12-01T00:00:00Z"
        response.headers["Link"] = f'</api/v1{path[4:]}>; rel="successor-version"'
        logger.debug(
            f"Deprecated API call: {request.method} {path} — "
            f"Client should migrate to /api/v1{path[4:]}"
        )
    return response


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_middleware(app: FastAPI) -> None:
    """Register all middleware on *app* in the correct order.

    FastAPI/Starlette processes middleware in **reverse** registration order,
    so the *last* registered middleware is the *outermost* layer.
    """
    settings = get_settings()

    # --- class-based middleware ---

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors.allowed_origins,
        allow_credentials=settings.cors.allow_credentials,
        allow_methods=settings.cors.allow_methods,
        allow_headers=settings.cors.allow_headers,
    )

    # Rate limiting (if enabled)
    if settings.rate_limit.enabled:
        app.add_middleware(SlowAPIMiddleware)

    # CSRF protection
    app.add_middleware(CSRFMiddleware)

    # Trusted host validation (prevents Host header injection)
    # Derive allowed hosts from server host + CORS allowed origins
    from urllib.parse import urlparse as _urlparse
    allowed_hosts = {"localhost", "127.0.0.1", settings.server.host}
    for origin in settings.cors.allowed_origins:
        try:
            parsed = _urlparse(origin)
            if parsed.hostname:
                allowed_hosts.add(parsed.hostname)
        except (ValueError, TypeError):
            pass
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(allowed_hosts))

    # --- function-based middleware ---
    # Registered via app.middleware() which wraps them in BaseHTTPMiddleware.
    _register = app.middleware("http")
    _register(add_request_id)
    _register(track_metrics)
    _register(limit_request_size)
    _register(add_security_headers)
    _register(add_deprecation_warning)
