"""
FastAPI application for OpenLabels Server.

Security features:
- CORS configured from settings (not wildcard)
- Rate limiting on sensitive endpoints
- Request size limits
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- CSRF protection via double-submit cookie pattern

API Versioning:
- All API routes are available under /api/v1/ (recommended)
- Legacy routes under /api/ are deprecated but still functional
- Deprecation warnings are sent via X-API-Deprecation header
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
import logging
import uuid
import warnings

from fastapi import APIRouter, FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from slowapi import Limiter, _rate_limit_exceeded_handler as rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from pydantic import ValidationError as PydanticValidationError

from openlabels import __version__
from openlabels.server.config import get_settings
from openlabels.server.utils import get_client_ip  # noqa: F401 - re-exported for backwards compatibility
from openlabels.server.db import init_db, close_db
from openlabels.server.cache import get_cache_manager, close_cache
from openlabels.server.middleware.csrf import CSRFMiddleware
from openlabels.server.logging import setup_logging, set_request_id, get_request_id
from openlabels.server.exceptions import APIError, RateLimitError
from openlabels.server.schemas import ErrorResponse
from openlabels.server.routes import (
    auth,
    audit,
    jobs,
    scans,
    results,
    targets,
    schedules,
    labels,
    dashboard,
    ws,
    users,
    remediation,
    monitoring,
    health,
    settings,
)
from openlabels.web import router as web_router

logger = logging.getLogger(__name__)

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

    await init_db(settings.database.url)

    # Initialize cache (Redis with in-memory fallback)
    try:
        cache_manager = await get_cache_manager()
        if cache_manager.is_redis_connected:
            logger.info("Redis cache initialized")
        else:
            logger.info("Using in-memory cache (Redis not available)")
    except Exception as e:
        # Cache is optional - log the failure type for debugging
        logger.warning(f"Cache initialization failed: {type(e).__name__}: {e} - caching disabled")

    logger.info(f"OpenLabels v{__version__} starting up")
    yield
    # Shutdown
    await close_cache()
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
    if settings.rate_limit.enabled:
        app.add_middleware(SlowAPIMiddleware)
        app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

    # CSRF protection middleware
    app.add_middleware(CSRFMiddleware)


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
        request_id = get_request_id()
        error_response = {
            "error": "REQUEST_TOO_LARGE",
            "message": f"Request body exceeds {settings.security.max_request_size_mb}MB limit",
            "details": {"max_size_mb": settings.security.max_request_size_mb},
        }
        if request_id:
            error_response["request_id"] = request_id
        return JSONResponse(
            status_code=413,
            content=error_response,
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


# Deprecation warning middleware for non-versioned API calls
@app.middleware("http")
async def add_deprecation_warning(request: Request, call_next):
    """
    Add deprecation warning header for legacy API routes.

    Routes matching /api/* but not /api/v1/* are considered deprecated.
    This helps clients migrate to the versioned API endpoints.
    """
    response = await call_next(request)

    path = request.url.path

    # Check if this is a legacy API call (not versioned)
    # Legacy routes: /api/scans, /api/results, etc.
    # Versioned routes: /api/v1/scans, /api/v1/results, etc.
    # Excluded: /api (info), /api/docs, /api/redoc, /api/openapi.json
    if (
        path.startswith("/api/")
        and not path.startswith("/api/v1")
        and not path.startswith("/api/docs")
        and not path.startswith("/api/redoc")
        and not path.startswith("/api/openapi")
    ):
        # Add deprecation warning headers
        response.headers["X-API-Deprecation"] = "true"
        response.headers["X-API-Deprecation-Date"] = "2025-06-01"
        response.headers["X-API-Deprecation-Info"] = (
            "This API endpoint is deprecated. Please migrate to /api/v1/. "
            "See /api for version information."
        )
        # Standard Deprecation header (RFC 8594)
        response.headers["Deprecation"] = "true"
        response.headers["Sunset"] = "2025-06-01T00:00:00Z"
        response.headers["Link"] = f'</api/v1{path[4:]}>; rel="successor-version"'

        # Log deprecation warning (at debug level to avoid log spam)
        logger.debug(
            f"Deprecated API call: {request.method} {path} - "
            f"Client should migrate to /api/v1{path[4:]}"
        )

    return response


# =============================================================================
# EXCEPTION HANDLERS
# =============================================================================


async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """
    Handle rate limit exceeded errors with standardized format.

    Converts slowapi's RateLimitExceeded to our ErrorResponse format.
    """
    request_id = get_request_id()
    error_response = {
        "error": "RATE_LIMIT_EXCEEDED",
        "message": "Rate limit exceeded. Please try again later.",
        "details": {"limit": str(exc.detail) if hasattr(exc, "detail") else None},
    }
    if request_id:
        error_response["request_id"] = request_id

    response = JSONResponse(status_code=429, content=error_response)

    # Add Retry-After header if available
    if hasattr(exc, "headers") and exc.headers:
        for key, value in exc.headers.items():
            response.headers[key] = value

    return response


@app.exception_handler(APIError)
async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
    """
    Handle custom API exceptions with standardized format.

    All custom exceptions (NotFoundError, ValidationError, etc.) inherit
    from APIError and are automatically converted to ErrorResponse format.
    """
    request_id = get_request_id()
    error_response = exc.to_dict(request_id=request_id)

    # Log the error (debug level for client errors, warning for server errors)
    if exc.status_code >= 500:
        logger.warning(
            f"API error: {exc.error_code} - {exc.message}",
            extra={
                "path": request.url.path,
                "method": request.method,
                "status_code": exc.status_code,
                "error_code": exc.error_code,
            }
        )
    else:
        logger.debug(
            f"API error: {exc.error_code} - {exc.message}",
            extra={
                "path": request.url.path,
                "method": request.method,
                "status_code": exc.status_code,
                "error_code": exc.error_code,
            }
        )

    response = JSONResponse(status_code=exc.status_code, content=error_response)

    # Add Retry-After header for rate limit errors
    if isinstance(exc, RateLimitError) and exc.retry_after:
        response.headers["Retry-After"] = str(exc.retry_after)

    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """
    Handle FastAPI's HTTPException with standardized format.

    This ensures that any HTTPException raised (including those from
    dependencies and middleware) are converted to our standardized format.
    """
    request_id = get_request_id()

    # Map HTTP status codes to error codes
    error_code_map = {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        409: "CONFLICT",
        413: "REQUEST_TOO_LARGE",
        422: "VALIDATION_ERROR",
        429: "RATE_LIMIT_EXCEEDED",
        500: "INTERNAL_ERROR",
        502: "BAD_GATEWAY",
        503: "SERVICE_UNAVAILABLE",
        504: "GATEWAY_TIMEOUT",
    }

    error_code = error_code_map.get(exc.status_code, "ERROR")

    error_response = {
        "error": error_code,
        "message": exc.detail if isinstance(exc.detail, str) else str(exc.detail),
    }
    if request_id:
        error_response["request_id"] = request_id

    # Log server errors
    if exc.status_code >= 500:
        logger.warning(
            f"HTTP exception: {exc.status_code} - {exc.detail}",
            extra={
                "path": request.url.path,
                "method": request.method,
                "status_code": exc.status_code,
            }
        )

    return JSONResponse(status_code=exc.status_code, content=error_response)


@app.exception_handler(RequestValidationError)
async def request_validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """
    Handle Pydantic request validation errors with standardized format.

    Converts FastAPI's RequestValidationError (from request body/query validation)
    to our standardized format with detailed field-level error information.
    """
    request_id = get_request_id()

    # Extract validation error details
    validation_errors = []
    for error in exc.errors():
        error_detail = {
            "field": ".".join(str(loc) for loc in error.get("loc", [])),
            "message": error.get("msg", "Validation error"),
            "type": error.get("type", "value_error"),
        }
        # Include the invalid value if it's safe to expose
        if "input" in error and error["input"] is not None:
            # Don't expose potentially sensitive values
            input_val = error["input"]
            if isinstance(input_val, (str, int, float, bool)):
                # Truncate long strings
                if isinstance(input_val, str) and len(input_val) > 100:
                    input_val = input_val[:100] + "..."
                error_detail["input"] = input_val
        validation_errors.append(error_detail)

    error_response = {
        "error": "VALIDATION_ERROR",
        "message": "Request validation failed",
        "details": {"validation_errors": validation_errors},
    }
    if request_id:
        error_response["request_id"] = request_id

    logger.debug(
        f"Validation error: {len(validation_errors)} field(s) failed validation",
        extra={
            "path": request.url.path,
            "method": request.method,
            "error_count": len(validation_errors),
        }
    )

    return JSONResponse(status_code=422, content=error_response)


@app.exception_handler(PydanticValidationError)
async def pydantic_validation_error_handler(
    request: Request, exc: PydanticValidationError
) -> JSONResponse:
    """
    Handle Pydantic validation errors (not from request parsing).

    This catches validation errors that occur during manual model validation
    or data processing, converting them to our standardized format.
    """
    request_id = get_request_id()

    # Extract validation error details
    validation_errors = []
    for error in exc.errors():
        error_detail = {
            "field": ".".join(str(loc) for loc in error.get("loc", [])),
            "message": error.get("msg", "Validation error"),
            "type": error.get("type", "value_error"),
        }
        validation_errors.append(error_detail)

    error_response = {
        "error": "VALIDATION_ERROR",
        "message": "Data validation failed",
        "details": {"validation_errors": validation_errors},
    }
    if request_id:
        error_response["request_id"] = request_id

    return JSONResponse(status_code=422, content=error_response)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle unexpected exceptions with standardized format.

    This is the fallback handler for any exception not caught by more
    specific handlers. It logs the full exception for debugging while
    returning a safe error message to the client.
    """
    request_id = get_request_id()
    settings = get_settings()

    logger.exception(
        f"Unhandled exception: {exc}",
        extra={
            "path": request.url.path,
            "method": request.method,
            "exception_type": type(exc).__name__,
        }
    )

    # Only expose exception details in debug mode
    if settings.server.debug:
        error_response = {
            "error": "INTERNAL_ERROR",
            "message": str(exc),
            "details": {"exception_type": type(exc).__name__},
        }
    else:
        error_response = {
            "error": "INTERNAL_ERROR",
            "message": "An unexpected error occurred",
        }

    if request_id:
        error_response["request_id"] = request_id

    return JSONResponse(status_code=500, content=error_response)


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": __version__}


# API info
@app.get("/api")
async def api_info():
    """API information."""
    return {
        "name": "OpenLabels API",
        "version": __version__,
        "docs": "/api/docs",
        "current_version": "v1",
        "versions": {
            "v1": "/api/v1",
        },
        "deprecation_notice": "Direct /api/* routes are deprecated. Please use /api/v1/* instead.",
    }


@app.get("/api/v1")
async def api_v1_info():
    """API v1 information."""
    return {
        "name": "OpenLabels API",
        "version": __version__,
        "api_version": "v1",
        "docs": "/api/docs",
        "endpoints": {
            "auth": "/api/v1/auth",
            "scans": "/api/v1/scans",
            "results": "/api/v1/results",
            "targets": "/api/v1/targets",
            "labels": "/api/v1/labels",
            "jobs": "/api/v1/jobs",
            "schedules": "/api/v1/schedules",
            "users": "/api/v1/users",
            "dashboard": "/api/v1/dashboard",
            "remediation": "/api/v1/remediation",
            "monitoring": "/api/v1/monitoring",
            "health": "/api/v1/health",
            "settings": "/api/v1/settings",
            "audit": "/api/v1/audit",
        },
    }


# Create versioned API router (v1)
api_v1_router = APIRouter(prefix="/api/v1")

# Include all API routes under v1
api_v1_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_v1_router.include_router(audit.router, prefix="/audit", tags=["Audit"])
api_v1_router.include_router(jobs.router, prefix="/jobs", tags=["Jobs"])
api_v1_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
api_v1_router.include_router(results.router, prefix="/results", tags=["Results"])
api_v1_router.include_router(targets.router, prefix="/targets", tags=["Targets"])
api_v1_router.include_router(schedules.router, prefix="/schedules", tags=["Schedules"])
api_v1_router.include_router(labels.router, prefix="/labels", tags=["Labels"])
api_v1_router.include_router(users.router, prefix="/users", tags=["Users"])
api_v1_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
api_v1_router.include_router(remediation.router, prefix="/remediation", tags=["Remediation"])
api_v1_router.include_router(monitoring.router, prefix="/monitoring", tags=["Monitoring"])
api_v1_router.include_router(health.router, prefix="/health", tags=["Health"])
api_v1_router.include_router(settings.router, prefix="/settings", tags=["Settings"])

# Mount versioned API router
app.include_router(api_v1_router)

# Create deprecated legacy API router (maintains backward compatibility)
# These routes will be marked as deprecated and include warning headers
api_legacy_router = APIRouter(prefix="/api", deprecated=True)

# Include all API routes under legacy /api prefix (deprecated)
api_legacy_router.include_router(auth.router, prefix="/auth", tags=["Authentication (Deprecated)"])
api_legacy_router.include_router(audit.router, prefix="/audit", tags=["Audit (Deprecated)"])
api_legacy_router.include_router(jobs.router, prefix="/jobs", tags=["Jobs (Deprecated)"])
api_legacy_router.include_router(scans.router, prefix="/scans", tags=["Scans (Deprecated)"])
api_legacy_router.include_router(results.router, prefix="/results", tags=["Results (Deprecated)"])
api_legacy_router.include_router(targets.router, prefix="/targets", tags=["Targets (Deprecated)"])
api_legacy_router.include_router(schedules.router, prefix="/schedules", tags=["Schedules (Deprecated)"])
api_legacy_router.include_router(labels.router, prefix="/labels", tags=["Labels (Deprecated)"])
api_legacy_router.include_router(users.router, prefix="/users", tags=["Users (Deprecated)"])
api_legacy_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard (Deprecated)"])
api_legacy_router.include_router(remediation.router, prefix="/remediation", tags=["Remediation (Deprecated)"])
api_legacy_router.include_router(monitoring.router, prefix="/monitoring", tags=["Monitoring (Deprecated)"])
api_legacy_router.include_router(health.router, prefix="/health", tags=["Health (Deprecated)"])
api_legacy_router.include_router(settings.router, prefix="/settings", tags=["Settings (Deprecated)"])

# Mount legacy API router (for backward compatibility)
app.include_router(api_legacy_router)

# WebSocket routes (not versioned - real-time communication)
app.include_router(ws.router, tags=["WebSocket"])

# Web UI
app.include_router(web_router, prefix="/ui", tags=["Web UI"])
