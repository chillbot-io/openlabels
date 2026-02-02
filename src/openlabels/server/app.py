"""
FastAPI application for OpenLabels Server.

Security features:
- CORS configured from settings (not wildcard)
- Rate limiting on sensitive endpoints
- Request size limits
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from openlabels import __version__
from openlabels.server.config import get_settings


def get_client_ip(request: Request) -> str:
    """
    Get real client IP address, handling proxies.

    Checks X-Forwarded-For header first (set by reverse proxies),
    then falls back to the direct client IP.

    Security note: X-Forwarded-For can be spoofed by clients.
    In production, configure your reverse proxy to overwrite
    (not append) this header with the actual client IP.
    """
    # Check X-Forwarded-For (standard proxy header)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP (original client), stripping whitespace
        # Format: "client, proxy1, proxy2"
        return forwarded_for.split(",")[0].strip()

    # Check X-Real-IP (nginx default)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Fall back to direct client IP
    if request.client:
        return request.client.host

    return "127.0.0.1"
from openlabels.server.db import init_db, close_db
from openlabels.server.middleware.csrf import CSRFMiddleware
from openlabels.server.logging import setup_logging, set_request_id, get_request_id
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
)

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
    logger.info(f"OpenLabels v{__version__} starting up")
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
    if settings.rate_limit.enabled:
        app.add_middleware(SlowAPIMiddleware)
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
        return JSONResponse(
            status_code=413,
            content={
                "error": "request_too_large",
                "message": f"Request body exceeds {settings.security.max_request_size_mb}MB limit",
            },
        )

    return await call_next(request)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions."""
    request_id = get_request_id()
    logger.exception(
        f"Unhandled exception: {exc}",
        extra={
            "path": request.url.path,
            "method": request.method,
        }
    )
    error_response = {
        "error": "internal_server_error",
        "message": str(exc) if get_settings().server.debug else "An unexpected error occurred",
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
    }


# Include routers
app.include_router(auth.router, tags=["Authentication"])  # /auth/* endpoints
app.include_router(audit.router, prefix="/api/audit", tags=["Audit"])
app.include_router(jobs.router, prefix="/api/jobs", tags=["Jobs"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(results.router, prefix="/api/results", tags=["Results"])
app.include_router(targets.router, prefix="/api/targets", tags=["Targets"])
app.include_router(schedules.router, prefix="/api/schedules", tags=["Schedules"])
app.include_router(labels.router, prefix="/api/labels", tags=["Labels"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(remediation.router, prefix="/api/remediation", tags=["Remediation"])
app.include_router(monitoring.router, prefix="/api/monitoring", tags=["Monitoring"])
app.include_router(health.router, prefix="/api/health", tags=["Health"])
app.include_router(ws.router, tags=["WebSocket"])
