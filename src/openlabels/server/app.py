"""FastAPI application factory for OpenLabels Server.

The application is assembled from focused modules:

* **lifespan.py** — startup / shutdown lifecycle
* **error_handlers.py** — global exception handlers
* **middleware/stack.py** — middleware registration
* **sentry.py** — Sentry error-tracking init
* **tracing.py** — optional OpenTelemetry tracing

API Versioning:
  All API routes live under ``/api/v1/``.
  Legacy ``/api/*`` routes redirect to ``/api/v1/*`` with deprecation headers.
"""

from __future__ import annotations

import logging
import types

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from slowapi import Limiter

from openlabels import __version__
from openlabels.server.error_handlers import register_error_handlers
from openlabels.server.lifespan import lifespan
from openlabels.server.middleware import register_middleware
from openlabels.server.utils import get_client_ip
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
    policies,
    export,
    reporting,
)
from openlabels.web import router as web_router

# API version constants
API_V1_PREFIX = "/api/v1"
CURRENT_API_VERSION = "v1"
SUPPORTED_API_VERSIONS = ["v1"]

logger = logging.getLogger(__name__)

# Default in-memory limiter — replaced during lifespan with Redis-backed if available.
# Kept at module level because SlowAPIMiddleware reads ``app.state.limiter`` and several
# route modules reference this for @limiter.limit() decorators.
limiter = Limiter(key_func=get_client_ip)

# Legacy API prefixes eligible for automatic redirect.
_LEGACY_API_PREFIXES = [
    "audit", "jobs", "scans", "results", "targets", "schedules",
    "labels", "users", "dashboard", "remediation", "monitoring",
    "health", "settings", "policies", "export", "reporting",
]


# ---------------------------------------------------------------------------
# Router wiring
# ---------------------------------------------------------------------------

_ROUTE_MODULES: list[tuple[str, str, types.ModuleType]] = [
    ("/auth", "Authentication", auth),
    ("/audit", "Audit", audit),
    ("/jobs", "Jobs", jobs),
    ("/scans", "Scans", scans),
    ("/results", "Results", results),
    ("/targets", "Targets", targets),
    ("/schedules", "Schedules", schedules),
    ("/labels", "Labels", labels),
    ("/users", "Users", users),
    ("/dashboard", "Dashboard", dashboard),
    ("/remediation", "Remediation", remediation),
    ("/monitoring", "Monitoring", monitoring),
    ("/health", "Health", health),
    ("/settings", "Settings", settings),
    ("/policies", "Policies", policies),
    ("/export", "Export", export),
    ("/reporting", "Reporting", reporting),
]


def _include_routes(app: FastAPI) -> None:
    """Wire up versioned (v1) and legacy API routers, plus WebSocket & Web UI."""

    # --- Versioned API ---
    api_v1_router = APIRouter(prefix=API_V1_PREFIX)
    for prefix, tag, module in _ROUTE_MODULES:
        api_v1_router.include_router(module.router, prefix=prefix, tags=[tag])
    app.include_router(api_v1_router)

    # --- Legacy API (deprecated, emits warning headers via middleware) ---
    api_legacy_router = APIRouter(prefix="/api", deprecated=True)
    for prefix, tag, module in _ROUTE_MODULES:
        api_legacy_router.include_router(
            module.router, prefix=prefix, tags=[f"{tag} (Deprecated)"],
        )
    app.include_router(api_legacy_router)

    # --- WebSocket (not versioned) ---
    app.include_router(ws.router, tags=["WebSocket"])

    # --- Web UI ---
    app.include_router(web_router, prefix="/ui", tags=["Web UI"])


def _register_root_endpoints(app: FastAPI) -> None:
    """Register endpoints that live outside the versioned API prefix."""

    @app.get("/health")
    async def health_check() -> dict[str, str]:
        return {"status": "healthy", "version": __version__}

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/api")
    async def api_info() -> dict[str, object]:
        return {
            "name": "OpenLabels API",
            "version": __version__,
            "current_api_version": CURRENT_API_VERSION,
            "supported_versions": SUPPORTED_API_VERSIONS,
            "docs": "/api/docs",
            "current_version": "v1",
            "versions": {"v1": "/api/v1"},
            "deprecation_notice": (
                "Direct /api/* routes are deprecated. Please use /api/v1/* instead."
            ),
        }

    @app.get("/api/v1")
    async def api_v1_info() -> dict[str, object]:
        return {
            "name": "OpenLabels API",
            "version": __version__,
            "api_version": "v1",
            "docs": "/api/docs",
            "endpoints": {
                prefix.lstrip("/"): f"/api/v1{prefix}"
                for prefix, _, _ in _ROUTE_MODULES
            },
        }


def _register_legacy_redirects(app: FastAPI) -> None:
    """Redirect ``/api/<resource>`` → ``/api/v1/<resource>`` (HTTP 307)."""

    @app.api_route(
        "/api/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        include_in_schema=False,
    )
    async def legacy_api_redirect(request: Request, path: str) -> JSONResponse | RedirectResponse:
        path_prefix = path.split("/")[0] if path else ""
        if path_prefix in _LEGACY_API_PREFIXES:
            new_path = f"/api/v1/{path}"
            qs = request.url.query
            if qs:
                new_path = f"{new_path}?{qs}"
            return RedirectResponse(
                url=new_path,
                status_code=307,
                headers={
                    "X-API-Deprecation-Warning": (
                        "This endpoint is deprecated. Please use /api/v1/* endpoints."
                    )
                },
            )
        return JSONResponse(
            status_code=404,
            content={
                "error": "not_found",
                "message": f"Endpoint /api/{path} not found. Try /api/v1/{path}",
            },
        )

    @app.api_route(
        "/auth/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        include_in_schema=False,
    )
    async def legacy_auth_redirect(request: Request, path: str) -> RedirectResponse:
        new_path = f"/api/v1/auth/{path}"
        qs = request.url.query
        if qs:
            new_path = f"{new_path}?{qs}"
        return RedirectResponse(
            url=new_path,
            status_code=307,
            headers={
                "X-API-Deprecation-Warning": (
                    "This endpoint is deprecated. Please use /api/v1/auth/* endpoints."
                )
            },
        )


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """Build and return the fully-configured FastAPI application."""
    application = FastAPI(
        title="OpenLabels API",
        description=(
            "Open Source Data Classification & Auto-Labeling Platform\n\n"
            f"**Current API Version:** {CURRENT_API_VERSION}\n\n"
            f"**Supported Versions:** {', '.join(SUPPORTED_API_VERSIONS)}\n\n"
            "All API endpoints are versioned under `/api/v1/*`. "
            "For backward compatibility, requests to `/api/*` (non-versioned) "
            "will be redirected to `/api/v1/*`."
        ),
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    application.state.limiter = limiter

    register_middleware(application)
    register_error_handlers(application)
    _include_routes(application)
    _register_root_endpoints(application)
    _register_legacy_redirects(application)

    return application


app = create_app()
