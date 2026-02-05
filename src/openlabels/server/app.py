"""
FastAPI application for OpenLabels Server.

Security features:
- CORS configured from settings (not wildcard)
- Rate limiting on sensitive endpoints
- Request size limits
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- CSRF protection via double-submit cookie pattern
- Sentry error tracking (optional, when SENTRY_DSN is configured)
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded  # noqa: F401 - used in register_exception_handlers
from slowapi.middleware import SlowAPIMiddleware

from openlabels import __version__
from openlabels.server.config import get_settings, SentrySettings
from openlabels.server.utils import get_client_ip  # noqa: F401 - re-exported for backwards compatibility
from openlabels.server.db import init_db, close_db
from openlabels.server.middleware.csrf import CSRFMiddleware
from openlabels.server.logging import setup_logging, set_request_id, get_request_id
from openlabels.server.errors import register_exception_handlers, create_error_response
from openlabels.server.metrics import (
    PrometheusMiddleware,
    metrics_router,
    setup_metrics,
)
from openlabels.server.routes import v1
from openlabels.web import router as web_router

logger = logging.getLogger(__name__)


def init_sentry(sentry_settings: SentrySettings, server_environment: str) -> bool:
    """
    Initialize Sentry SDK for error tracking and performance monitoring.

    Returns True if Sentry was initialized, False otherwise.
    """
    if not sentry_settings.is_enabled:
        logger.info("Sentry not configured (SENTRY_DSN not set) - skipping initialization")
        return False

    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.starlette import StarletteIntegration
        from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
        from sentry_sdk.integrations.logging import LoggingIntegration

        # Use configured environment or fall back to server environment
        environment = sentry_settings.environment or server_environment

        # Use configured release or fall back to app version
        release = sentry_settings.release or f"openlabels@{__version__}"

        sentry_sdk.init(
            dsn=sentry_settings.dsn,
            environment=environment,
            release=release,
            traces_sample_rate=sentry_settings.traces_sample_rate,
            profiles_sample_rate=sentry_settings.profiles_sample_rate,
            send_default_pii=sentry_settings.send_default_pii,
            debug=sentry_settings.debug,
            integrations=[
                # FastAPI/Starlette integration for automatic request/response tracking
                FastApiIntegration(transaction_style="endpoint"),
                StarletteIntegration(transaction_style="endpoint"),
                # SQLAlchemy integration for database query tracking
                SqlalchemyIntegration(),
                # Logging integration - capture errors and warnings as breadcrumbs
                LoggingIntegration(
                    level=logging.INFO,  # Capture INFO+ as breadcrumbs
                    event_level=logging.ERROR,  # Create events for ERROR+
                ),
            ],
            # Filter out health check endpoints from performance monitoring
            traces_sampler=_traces_sampler,
            # Add tags for better filtering in Sentry dashboard
            _experiments={
                "continuous_profiling_auto_start": True,
            },
        )

        logger.info(
            f"Sentry initialized successfully",
            extra={
                "sentry_environment": environment,
                "sentry_release": release,
                "traces_sample_rate": sentry_settings.traces_sample_rate,
            }
        )
        return True

    except ImportError as e:
        logger.warning(f"Sentry SDK not available: {e}")
        return False
    except Exception as e:
        logger.error(f"Failed to initialize Sentry: {e}")
        return False


def _traces_sampler(sampling_context: dict) -> float:
    """
    Custom traces sampler to filter out noisy endpoints.

    Returns a sample rate between 0.0 and 1.0.
    """
    settings = get_settings()
    default_rate = settings.sentry.traces_sample_rate

    # Get transaction name from context
    transaction_context = sampling_context.get("transaction_context", {})
    name = transaction_context.get("name", "")

    # Don't trace health check and metrics endpoints
    if name in ("/health", "/api/health", "/api/v1/health", "/api/v1/health/live", "/api/v1/health/ready", "/metrics"):
        return 0.0

    # Lower sample rate for high-frequency endpoints
    if name.startswith("/api/v1/ws") or name.startswith("/api/ws"):
        return default_rate * 0.1  # 10% of normal rate for WebSocket

    return default_rate


# Initialize rate limiter with proxy-aware IP detection
limiter = Limiter(key_func=get_client_ip)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan - startup and shutdown handlers."""
    # Startup
    settings = get_settings()

    # Configure structured logging
    setup_logging(
        level=settings.logging.level,
        json_format=not settings.server.debug,  # JSON in production, readable in debug
        log_file=settings.logging.file,
    )

    # Initialize Sentry for error tracking (optional - only if SENTRY_DSN is configured)
    sentry_enabled = init_sentry(settings.sentry, settings.server.environment)

    # Initialize Prometheus metrics
    setup_metrics()

    await init_db(
        settings.database.url,
        pool_size=settings.database.pool_size,
        max_overflow=settings.database.max_overflow,
    )
    logger.info(
        f"OpenLabels v{__version__} starting up",
        extra={"sentry_enabled": sentry_enabled}
    )
    yield
    # Shutdown
    await close_db()
    logger.info("OpenLabels shutting down")


app = FastAPI(
    title="OpenLabels",
    description="Open Source Data Classification & Auto-Labeling Platform",
    version=__version__,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Add rate limiter to app state
app.state.limiter = limiter


def configure_middleware():
    """Configure all middleware based on settings."""
    settings = get_settings()

    # CORS middleware - configured from settings, not wildcards
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors.allowed_origins,
        allow_credentials=settings.cors.allow_credentials,
        allow_methods=settings.cors.allow_methods,
        allow_headers=settings.cors.allow_headers,
    )

    # Rate limiting middleware
    # Note: RateLimitExceeded is handled by register_exception_handlers for standardized format
    if settings.rate_limit.enabled:
        app.add_middleware(SlowAPIMiddleware)

    # CSRF protection middleware
    app.add_middleware(CSRFMiddleware)

    # Prometheus metrics middleware - tracks request count, latency, and active connections
    # This should be added after other middleware to capture accurate timing
    app.add_middleware(PrometheusMiddleware)


# Configure middleware
configure_middleware()


# Request correlation ID middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add request correlation ID for tracing."""
    # Use provided X-Request-ID or generate new one
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())[:8]
    set_request_id(request_id)

    response = await call_next(request)

    # Include request ID in response headers
    response.headers["X-Request-ID"] = request_id
    return response


# Request size limit middleware
@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """Limit request body size to prevent DoS."""
    settings = get_settings()
    max_size = settings.security.max_request_size_mb * 1024 * 1024

    # Check content-length header
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > max_size:
        return create_error_response(
            status_code=413,
            code="request_too_large",
            message=f"Request body exceeds {settings.security.max_request_size_mb}MB limit",
            details={"max_size_mb": settings.security.max_request_size_mb},
        )

    return await call_next(request)


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Add security headers to all responses.

    Headers added:
    - Strict-Transport-Security: Enforce HTTPS
    - X-Content-Type-Options: Prevent MIME sniffing
    - X-Frame-Options: Prevent clickjacking
    - X-XSS-Protection: XSS filter (legacy browsers)
    - Referrer-Policy: Control referrer information
    - Content-Security-Policy: Restrict resource loading
    - Permissions-Policy: Restrict browser features
    """
    response = await call_next(request)
    settings = get_settings()

    # Only add HSTS in production with HTTPS
    if settings.server.environment == "production":
        # HSTS: Force HTTPS for 1 year, include subdomains
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent clickjacking - allow framing from same origin only
    response.headers["X-Frame-Options"] = "SAMEORIGIN"

    # XSS filter for legacy browsers
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Control referrer information
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Content Security Policy - restrictive but functional
    # Allows inline styles (needed for some UI frameworks) but blocks inline scripts
    csp_directives = [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",  # Allow inline styles for UI
        "img-src 'self' data: https:",
        "font-src 'self'",
        "connect-src 'self' wss: ws:",  # Allow WebSocket connections
        "frame-ancestors 'self'",
        "form-action 'self'",
        "base-uri 'self'",
    ]
    response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

    # Restrict browser features (Permissions-Policy)
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


# Register standardized exception handlers
# This replaces the default FastAPI exception handling with our standardized format
# Format: {"error": {"code": "...", "message": "...", "details": {...}}, "request_id": "..."}
register_exception_handlers(app)


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": __version__}


# API info
@app.get("/api")
async def api_info():
    """API information and available versions."""
    return {
        "name": "OpenLabels API",
        "version": __version__,
        "docs": "/api/docs",
        "current_version": "v1",
        "available_versions": ["v1"],
        "v1_base_url": "/api/v1",
    }


@app.get("/api/v1")
async def api_v1_info():
    """API v1 information."""
    return {
        "name": "OpenLabels API",
        "version": "v1",
        "app_version": __version__,
        "docs": "/api/docs",
    }


# Include versioned API router
# All API endpoints are now under /api/v1/*
app.include_router(v1.router, prefix="/api/v1")

# Prometheus metrics endpoint (/metrics)
# Note: This endpoint is excluded from authentication to allow Prometheus scraping
app.include_router(metrics_router, tags=["Metrics"])

# Web UI
app.include_router(web_router, prefix="/ui", tags=["Web UI"])


# =============================================================================
# Backward Compatibility - Redirect old /api/* paths to /api/v1/*
# =============================================================================
# These redirects ensure existing clients continue to work while they migrate
# to the new versioned endpoints. The redirects use HTTP 307 (Temporary Redirect)
# to preserve the request method (GET, POST, etc.) and body.

# List of API path prefixes that need backward compatibility redirects
_LEGACY_API_PREFIXES = [
    "audit", "jobs", "scans", "results", "targets", "schedules",
    "labels", "users", "dashboard", "remediation", "monitoring",
    "health", "settings",
]


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
async def legacy_api_redirect(request: Request, path: str):
    """
    Redirect legacy /api/* requests to /api/v1/*.

    This ensures backward compatibility for clients using the old API paths.
    Uses HTTP 307 to preserve the request method and body.
    """
    # Check if this is a legacy API path that should be redirected
    path_prefix = path.split("/")[0] if path else ""

    if path_prefix in _LEGACY_API_PREFIXES:
        # Build the new URL with /api/v1 prefix
        new_path = f"/api/v1/{path}"
        query_string = request.url.query
        if query_string:
            new_path = f"{new_path}?{query_string}"

        return RedirectResponse(
            url=new_path,
            status_code=307,  # Temporary Redirect - preserves method and body
            headers={"X-API-Deprecation-Warning": "This endpoint is deprecated. Please use /api/v1/* endpoints."},
        )

    # For paths that don't match legacy patterns, return 404
    return JSONResponse(
        status_code=404,
        content={"error": "not_found", "message": f"Endpoint /api/{path} not found. Try /api/v1/{path}"},
    )


# Legacy /auth/* redirect to /api/v1/auth/*
@app.api_route("/auth/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
async def legacy_auth_redirect(request: Request, path: str):
    """
    Redirect legacy /auth/* requests to /api/v1/auth/*.

    Uses HTTP 307 to preserve the request method and body.
    """
    new_path = f"/api/v1/auth/{path}"
    query_string = request.url.query
    if query_string:
        new_path = f"{new_path}?{query_string}"

    return RedirectResponse(
        url=new_path,
        status_code=307,
        headers={"X-API-Deprecation-Warning": "This endpoint is deprecated. Please use /api/v1/auth/* endpoints."},
    )


# Legacy /ws/* redirect to /api/v1/ws/*
@app.api_route("/ws/{path:path}", methods=["GET"], include_in_schema=False)
async def legacy_ws_redirect(request: Request, path: str):
    """
    Redirect legacy /ws/* WebSocket requests to /api/v1/ws/*.

    Note: WebSocket upgrade requests may not follow redirects automatically.
    Clients should update to use /api/v1/ws/* directly.
    """
    new_path = f"/api/v1/ws/{path}"
    query_string = request.url.query
    if query_string:
        new_path = f"{new_path}?{query_string}"

    return RedirectResponse(
        url=new_path,
        status_code=307,
        headers={"X-API-Deprecation-Warning": "This endpoint is deprecated. Please use /api/v1/ws/* endpoints."},
    )
