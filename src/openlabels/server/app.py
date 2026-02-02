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

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from openlabels import __version__
from openlabels.server.config import get_settings
from openlabels.server.db import init_db, close_db
from openlabels.server.middleware.csrf import CSRFMiddleware
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
)

logger = logging.getLogger(__name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan - startup and shutdown handlers."""
    # Startup
    settings = get_settings()
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
    logger.exception(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": str(exc) if get_settings().server.debug else "An unexpected error occurred",
        },
    )


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
app.include_router(ws.router, tags=["WebSocket"])
