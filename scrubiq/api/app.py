"""FastAPI application factory."""

import os
import re
import uuid
import secrets
import threading
from contextlib import asynccontextmanager
from pathlib import Path
import logging
from typing import Optional

# Configure logging to show app logs in console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

from fastapi import FastAPI, HTTPException, Request


# BACKGROUND MODULE PRELOADING
# Start loading heavy modules immediately when this file is imported.
# This runs in parallel with uvicorn startup, so modules are often
# ready before the first request arrives.

_preload_lock = threading.Lock()
_preload_thread = None
_preload_complete = threading.Event()


def _preload_heavy_modules():
    """Preload heavy modules in background during app startup.
    
    This significantly reduces the perceived startup time because:
    1. ONNX runtime import is ~1-2s
    2. tokenizers import is ~0.5s  
    3. Anthropic SDK import is ~1-2s
    
    By preloading while uvicorn is starting, these are ready sooner.
    """
    import time
    start = time.time()
    _logger = logging.getLogger(__name__)
    
    try:
        # Import ONNX runtime (heaviest dependency)
        _logger.debug("Preloading onnxruntime...")
        try:
            import onnxruntime
            _logger.debug(f"  onnxruntime loaded in {time.time()-start:.2f}s")
        except ImportError:
            pass
        
        # Import tokenizers library
        t0 = time.time()
        _logger.debug("Preloading tokenizers...")
        try:
            import tokenizers
            _logger.debug(f"  tokenizers loaded in {time.time()-t0:.2f}s")
        except ImportError:
            pass
        
        # Import numpy (used everywhere)
        t0 = time.time()
        try:
            import numpy
            _logger.debug(f"  numpy loaded in {time.time()-t0:.2f}s")
        except ImportError:
            pass
        
        # Import Anthropic SDK
        t0 = time.time()
        _logger.debug("Preloading anthropic SDK...")
        try:
            import anthropic
            _logger.debug(f"  anthropic loaded in {time.time()-t0:.2f}s")
        except ImportError:
            pass
        
        # Import OpenAI SDK
        t0 = time.time()
        try:
            import openai
            _logger.debug(f"  openai loaded in {time.time()-t0:.2f}s")
        except ImportError:
            pass
        
        _logger.info(f"Module preloading complete in {time.time()-start:.2f}s")
    except Exception as e:
        _logger.warning(f"Module preload error: {e}")
    finally:
        _preload_complete.set()


def _start_preloading():
    """Start the preloading thread if not already started.

    Thread-safe: uses lock to prevent multiple preload threads.
    """
    global _preload_thread
    with _preload_lock:
        if _preload_thread is None:
            _preload_thread = threading.Thread(
                target=_preload_heavy_modules,
                daemon=True,
                name="module-preloader"
            )
            _preload_thread.start()


# Start preloading immediately on module import
_start_preloading()
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ..config import Config
from ..core import ScrubIQ
from ..services import APIKeyService
from ..storage import Database
from ..instance_pool import init_pool, close_pool, get_pool
from .dependencies import set_api_key_service
from .errors import APIError, api_error_handler

logger = logging.getLogger(__name__)


# ENVIRONMENT CONFIGURATION

def load_dotenv():
    """Load .env file from project directory or home directory."""
    # Try multiple locations
    search_paths = [
        Path.cwd() / ".env",  # Current directory
        Path.home() / ".scrubiq" / ".env",  # Home config dir
        Path(__file__).parent.parent.parent / ".env",  # Project root
    ]
    
    for env_path in search_paths:
        if env_path.exists():
            logger.info(f"Loading environment from {env_path}")
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, _, value = line.partition('=')
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        if key and key not in os.environ:
                            os.environ[key] = value
            return True
    return False


# Load .env on module import
load_dotenv()

# Check if production mode
IS_PRODUCTION = os.environ.get("PROD", "").lower() in ("1", "true", "yes")


# RATE LIMITING
from .limiter import limiter as _limiter, SLOWAPI_AVAILABLE as _SLOWAPI_AVAILABLE
if _SLOWAPI_AVAILABLE:
    from .limiter import RateLimitExceeded, SlowAPIMiddleware, _rate_limit_exceeded_handler


# SECURITY MIDDLEWARE

# Maximum request body size for non-file endpoints (10MB default)
# File uploads bypass this limit and use MAX_FILE_SIZE_BYTES from constants.py (50MB)
MAX_REQUEST_BODY_SIZE = int(os.environ.get("MAX_REQUEST_SIZE_MB", "10")) * 1024 * 1024


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Limit request body size to prevent DoS attacks."""
    
    async def dispatch(self, request: Request, call_next):
        # Skip size check for file uploads (they have their own limits)
        if request.url.path.endswith("/upload"):
            return await call_next(request)
        
        # Check Content-Length header
        content_length = request.headers.get("content-length")
        if content_length:
            if int(content_length) > MAX_REQUEST_BODY_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={
                        "detail": f"Request body too large. Maximum size is {MAX_REQUEST_BODY_SIZE // (1024*1024)}MB"
                    }
                )
        
        return await call_next(request)


# NOTE: CSRF middleware removed - not needed for Bearer token authentication
# API key auth via Authorization header is not vulnerable to CSRF since:
# 1. Browsers don't auto-send Authorization headers (unlike cookies)
# 2. Attackers cannot forge Authorization headers via cross-site requests
# 3. The bearer token must be explicitly included by legitimate clients


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # SECURITY: HSTS - force HTTPS in production
        # Prevents downgrade attacks and cookie hijacking
        if IS_PRODUCTION:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # CSP - restrict to self and inline for Vite dev
        # In production, allow external LLM API endpoints
        if IS_PRODUCTION:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                # Allow connections to Anthropic, OpenAI, and Ollama APIs
                "connect-src 'self' https://api.anthropic.com https://api.openai.com http://localhost:11434"
            )

        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add unique request ID to all requests for tracing."""
    
    # Valid request ID pattern: 8 hex characters
    REQUEST_ID_PATTERN = re.compile(r'^[a-f0-9]{8}$')
    
    async def dispatch(self, request: Request, call_next):
        # Check for client-provided request ID (for request tracing)
        request_id = request.headers.get("X-Request-ID")
        
        # Validate format if provided, otherwise generate new
        if request_id and self.REQUEST_ID_PATTERN.match(request_id):
            # Use client-provided ID (validated)
            pass
        else:
            # Generate new ID (16 hex chars = 64 bits for better uniqueness)
            request_id = uuid.uuid4().hex[:16]
        
        request.state.request_id = request_id
        
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        
        return response


# APPLICATION FACTORY

# Track database for API key service (shared across pool)
_shared_db: Optional[Database] = None


def get_cors_origins() -> list[str]:
    """Get CORS origins from environment or use secure defaults.

    SECURITY NOTE: When using env-configured origins with allow_credentials=True,
    ensure only trusted origins are specified. Malicious origins could steal
    session cookies if incorrectly configured.

    SECURITY: Wildcard (*) origins are NEVER allowed when credentials are enabled.
    This is a CORS spec requirement - browsers won't send credentials to wildcards.
    """
    env_origins = os.environ.get("CORS_ORIGINS", "")

    if env_origins:
        # Parse comma-separated origins from env
        custom_origins = [origin.strip() for origin in env_origins.split(",") if origin.strip()]

        # SECURITY: Reject wildcard origins - incompatible with credentials
        if "*" in custom_origins:
            logger.error(
                "SECURITY: Wildcard (*) CORS origin rejected. "
                "Cannot use credentials with wildcard origins per CORS spec. "
                "Falling back to localhost-only defaults."
            )
            custom_origins = []  # Fall through to defaults

        # SECURITY: Reject origins without explicit protocol
        invalid_origins = [o for o in custom_origins if not o.startswith(("http://", "https://", "tauri://"))]
        if invalid_origins:
            logger.error(
                f"SECURITY: Invalid CORS origins (missing protocol): {invalid_origins}. "
                "Origins must start with http://, https://, or tauri://. Ignoring these."
            )
            custom_origins = [o for o in custom_origins if o.startswith(("http://", "https://", "tauri://"))]

        # SECURITY: Warn if non-localhost origins are configured (credential leak risk)
        if custom_origins:
            non_local = [o for o in custom_origins if "localhost" not in o and "127.0.0.1" not in o and "tauri://" not in o]
            if non_local:
                logger.warning(
                    f"SECURITY: Non-localhost CORS origins configured with credentials enabled: {non_local}. "
                    "Ensure these origins are trusted to prevent credential theft."
                )
            return custom_origins

    # Default: localhost only (secure for local-first deployment)
    return [
        "tauri://localhost",
        "http://localhost",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://localhost:8741",
        "http://127.0.0.1:8741",
    ]


def create_app(config: "Config | None" = None, enable_spa: bool = True) -> FastAPI:
    """
    Create FastAPI application with security hardening.

    Args:
        config: Optional config override
        enable_spa: Enable SPA static file serving (disable for tests)

    Returns:
        FastAPI app ready to run
    """
    global _shared_db
    from .routes import router
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse

    # Use provided config or create default
    app_config = config or Config()
    logger.info(f"Using data directory: {app_config.data_dir}")
    logger.info(f"Using models directory: {app_config.models_dir}")
    logger.info(f"Using dictionaries directory: {app_config.dictionaries_dir}")

    # Define lifespan as closure to capture config
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Application lifespan - init/cleanup.

        Multi-tenant Architecture:
        - Instance pool manages per-API-key ScrubIQ instances
        - ML models are preloaded and shared across all instances
        - Each API key gets isolated tokens, conversations, audit logs
        - Shared database for API key validation and rate limiting
        """
        global _shared_db

        # Initialize ConfigProvider
        from .routes.config import init_config_provider
        init_config_provider(app_config)
        logger.info("ConfigProvider initialized")

        # Create shared database connection for API key service
        app_config.ensure_directories()
        _shared_db = Database(app_config.db_path)
        _shared_db.connect()
        logger.info("Shared database connected")

        # Initialize API key service (uses shared database)
        api_key_service = APIKeyService(_shared_db)
        set_api_key_service(api_key_service)
        logger.info("API key service initialized")

        # Initialize instance pool with model preloading
        # Models are loaded once and shared across all instances
        pool = init_pool(
            config=app_config,
            max_instances=int(os.environ.get("MAX_INSTANCES", "100")),
            idle_timeout_seconds=int(os.environ.get("INSTANCE_IDLE_TIMEOUT", "3600")),
        )
        logger.info(f"Instance pool initialized (max={pool._max_instances}, idle_timeout={pool._idle_timeout}s)")

        # Initialize rate limiter with shared database
        from ..rate_limiter import init_rate_limiter
        init_rate_limiter(_shared_db)
        logger.info("Rate limiter initialized")

        yield

        # Cleanup
        close_pool()
        logger.info("Instance pool closed")

        if _shared_db:
            _shared_db.close()
            _shared_db = None
            logger.info("Shared database closed")
    
    # Disable docs in production for security
    docs_url = None if IS_PRODUCTION else "/docs"
    redoc_url = None if IS_PRODUCTION else "/redoc"
    openapi_url = None if IS_PRODUCTION else "/openapi.json"
    
    app = FastAPI(
        title="ScrubIQ",
        description="PHI/PII Detection & Redaction API",
        version="2.6.0",
        lifespan=lifespan,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
    )
    # MIDDLEWARE (order matters - first added = outermost)
    # Request ID tracking (outermost - runs first)
    app.add_middleware(RequestIDMiddleware)

    # Request size limit (before processing)
    app.add_middleware(RequestSizeLimitMiddleware)

    # NOTE: CSRF middleware removed - Bearer token auth doesn't need CSRF protection

    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)
    
    # CORS
    cors_origins = get_cors_origins()
    logger.info(f"CORS origins: {cors_origins}")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "PUT"],
        # Whitelist specific headers instead of allowing all
        allow_headers=[
            "Accept",
            "Accept-Language",
            "Content-Language",
            "Content-Type",
            "Authorization",  # Bearer token authentication
            "X-Request-ID",
            "X-Requested-With",
        ],
        # Expose these headers to JavaScript (Access-Control-Expose-Headers)
        expose_headers=[
            "X-Request-ID",
            "Retry-After",
        ],
        # Cache preflight responses for 1 hour (reduces OPTIONS requests)
        max_age=3600,
    )
    # RATE LIMITING
    if _SLOWAPI_AVAILABLE and _limiter:
        app.state.limiter = _limiter
        app.add_middleware(SlowAPIMiddleware)
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # EXCEPTION HANDLERS
    # Register custom APIError handler for standardized error responses
    app.add_exception_handler(APIError, api_error_handler)

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Catch-all exception handler that returns proper JSON."""
        request_id = getattr(request.state, 'request_id', 'unknown')
        # Log full details internally for debugging
        logger.error(f"[{request_id}] Unhandled exception: {type(exc).__name__}: {exc}")
        # Return generic error to client - don't expose exception details
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": request_id},
            headers={"X-Request-ID": request_id},
        )
    # ROUTES
    from .settings import router as settings_router
    
    # Mount at /api/* for production and new Vite config
    app.include_router(router, prefix="/api")
    app.include_router(settings_router, prefix="/api")
    # Also mount at root for backward compatibility
    app.include_router(router)
    app.include_router(settings_router)

    # Ensure health endpoints are exempt from rate limiting
    # This is done explicitly here after routes are included to guarantee
    # the exemption is registered regardless of import order
    if _SLOWAPI_AVAILABLE and _limiter:
        from .routes.admin import health
        exempt_name = f"{health.__module__}.{health.__name__}"
        _limiter._exempt_routes.add(exempt_name)
        logger.debug(f"Exempt routes: {_limiter._exempt_routes}")

    # STATIC FILE SERVING (production only, can be disabled for tests)
    ui_dist = Path(__file__).parent.parent.parent / "ui" / "dist"

    if enable_spa and ui_dist.exists():
        logger.info(f"Serving static files from {ui_dist}")
        
        # Serve assets directory
        assets_dir = ui_dist / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")
        
        # SPA fallback - serve index.html for non-API routes
        @app.get("/{path:path}")
        async def serve_spa(path: str):
            """Serve SPA - return index.html for all non-API, non-asset routes."""
            if path.startswith("api/"):
                raise HTTPException(404, "Not found")

            # SECURITY FIX: Prevent path traversal attacks
            # Resolve the path and verify it stays within ui_dist
            try:
                file_path = (ui_dist / path).resolve()
                ui_dist_resolved = ui_dist.resolve()

                # Check that resolved path is within ui_dist (prevent ../ traversal)
                if not file_path.is_relative_to(ui_dist_resolved):
                    logger.warning(f"Path traversal attempt blocked: {path}")
                    raise HTTPException(403, "Access denied")

            except (ValueError, OSError):
                # Invalid path (e.g., null bytes, invalid characters)
                raise HTTPException(400, "Invalid path")

            if file_path.exists() and file_path.is_file():
                return FileResponse(file_path)

            index_path = ui_dist / "index.html"
            if index_path.exists():
                return FileResponse(index_path)

            raise HTTPException(404, "Not found")

        # Re-register health endpoint AFTER SPA catch-all
        # This ensures slowapi finds the health handler (not SPA) since it returns LAST match
        from .routes.admin import health as health_handler
        app.add_api_route("/health", health_handler, methods=["GET"])
        logger.debug("Re-registered /health after SPA catch-all for rate limit exemption")
    else:
        logger.info(f"No ui/dist found at {ui_dist} - static serving disabled")
        logger.info("Run 'cd ui && npm run build' to enable production mode")

    return app


# For running directly: uvicorn scrubiq.api.app:app
app = create_app()
