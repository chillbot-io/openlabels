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
from pathlib import Path

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from slowapi import Limiter

from openlabels import __version__
from openlabels.server.error_handlers import register_error_handlers
from openlabels.server.lifespan import lifespan
from openlabels.server.middleware import register_middleware
from openlabels.server.routes import (
    audit,
    auth,
    browse,
    credentials,
    dashboard,
    enumerate,
    export,
    health,
    jobs,
    labels,
    monitoring,
    permissions,
    policies,
    query,
    remediation,
    reporting,
    results,
    scans,
    schedules,
    settings,
    targets,
    users,
    webhooks,
    ws,
    ws_events,
)
from openlabels.server.utils import get_client_ip
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
    "audit", "browse", "credentials", "enumerate", "jobs", "scans",
    "results", "targets", "schedules",
    "labels", "users", "dashboard", "remediation", "monitoring",
    "health", "settings", "policies", "export", "reporting", "webhooks",
    "permissions", "query",
]


# Router wiring
_ROUTE_MODULES: list[tuple[str, str, types.ModuleType]] = [
    ("/auth", "Authentication", auth),
    ("/audit", "Audit", audit),
    ("/browse", "Browse", browse),
    ("/credentials", "Credentials", credentials),
    ("/enumerate", "Enumerate", enumerate),
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
    ("/webhooks", "Webhooks", webhooks),
    ("/permissions", "Permissions", permissions),
    ("/query", "Query", query),
]


def _include_routes(app: FastAPI) -> None:
    """Wire up versioned (v1) and legacy API routers, plus WebSocket & Web UI."""

    # Versioned API
    api_v1_router = APIRouter(prefix=API_V1_PREFIX)
    for prefix, tag, module in _ROUTE_MODULES:
        api_v1_router.include_router(module.router, prefix=prefix, tags=[tag])
    app.include_router(api_v1_router)

    # Legacy /api/* routes are handled by _register_legacy_redirects() which
    # issues 307 redirects to /api/v1/*. We no longer double-register every
    # route handler under /api/ — that duplicated memory, OpenAPI schema
    # entries, and middleware invocations.

    # WebSocket (not versioned)
    app.include_router(ws.router, tags=["WebSocket"])
    app.include_router(ws_events.router, tags=["WebSocket"])

    # Web UI
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
    async def legacy_api_redirect(request: Request, path: str) -> Response:
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


def _register_spa_serving(app: FastAPI) -> None:
    """Serve the React SPA frontend from ``frontend/dist``.

    If the frontend build directory exists, mounts it as static files
    under ``/assets`` and adds a catch-all that serves ``index.html``
    for client-side routing.

    If the directory does not exist (e.g. backend-only dev), this is
    a no-op and no static routes are added.
    """
    # Look for the frontend dist directory relative to the project root.
    # The project root is four levels up from this file:
    #   src/openlabels/server/app.py -> ../../.. -> project root
    project_root = Path(__file__).resolve().parent.parent.parent.parent
    dist_dir = project_root / "frontend" / "dist"

    if not dist_dir.is_dir():
        logger.info(
            "SPA frontend not found at %s — skipping static file serving. "
            "Run 'npm run build' in frontend/ to enable.",
            dist_dir,
        )
        return

    index_html = dist_dir / "index.html"
    if not index_html.is_file():
        logger.warning("frontend/dist exists but index.html is missing — skipping SPA serving")
        return

    # Mount static assets (JS, CSS, images) under /assets
    assets_dir = dist_dir / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="spa_assets")
        logger.info("Mounted SPA assets from %s", assets_dir)

    # Catch-all: serve index.html for any path not matched by API or static files.
    # This enables client-side routing (React Router, etc.)
    @app.get("/{path:path}", include_in_schema=False)
    async def spa_fallback(request: Request, path: str) -> Response:
        # Don't intercept API, WebSocket, metrics, health, or HTMX UI routes
        if path.startswith(("api/", "ws/", "ws_events/", "metrics", "health", "ui/")):
            return JSONResponse(status_code=404, content={"error": "not_found"})
        return FileResponse(str(index_html), media_type="text/html")


# Application factory
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
    # SPA serving must be registered LAST so the catch-all doesn't shadow API routes
    _register_spa_serving(application)

    return application


app = create_app()
