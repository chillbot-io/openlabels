"""
FastAPI application for OpenLabels Server.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from openlabels import __version__
from openlabels.server.config import get_settings
from openlabels.server.db import init_db, close_db
from openlabels.server.routes import (
    scans,
    results,
    targets,
    schedules,
    labels,
    dashboard,
    ws,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan - startup and shutdown handlers."""
    # Startup
    settings = get_settings()
    await init_db(settings.database.url)
    yield
    # Shutdown
    await close_db()


app = FastAPI(
    title="OpenLabels",
    description="Open Source Data Classification & Auto-Labeling Platform",
    version=__version__,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions."""
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
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(results.router, prefix="/api/results", tags=["Results"])
app.include_router(targets.router, prefix="/api/targets", tags=["Targets"])
app.include_router(schedules.router, prefix="/api/schedules", tags=["Schedules"])
app.include_router(labels.router, prefix="/api/labels", tags=["Labels"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(ws.router, tags=["WebSocket"])
