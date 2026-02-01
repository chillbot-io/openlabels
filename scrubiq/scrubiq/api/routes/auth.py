"""Authentication status routes.

With API key authentication, sessions are auto-unlocked on each request.
These routes provide status information and provider listing.
"""

import logging
from fastapi import APIRouter, Depends, Request

from ...core import ScrubIQ
from ...instance_pool import get_pool
from ...constants import API_RATE_WINDOW_SECONDS
from ...rate_limiter import check_rate_limit
from ..dependencies import require_api_key, get_api_key_service
from .schemas import StatusResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["auth"])

# Rate limits for auth endpoints
AUTH_READ_RATE_LIMIT = 60  # Max reads per window


@router.get("/status", response_model=StatusResponse)
def status(request: Request):
    """
    Get system status.

    This is a public endpoint that shows basic status information.
    Use for health checks and initial setup detection.
    """
    # Check if any API keys exist (for initial setup flow)
    service = get_api_key_service()
    has_keys = service.has_any_keys()

    # Get pool stats
    try:
        pool = get_pool()
        pool_stats = pool.get_stats()
        active_instances = pool_stats["current_size"]
    except RuntimeError:
        active_instances = 0

    return StatusResponse(
        initialized=has_keys,  # True if API keys exist
        unlocked=active_instances > 0,  # True if any active instances
        timeout_remaining=None,  # No longer relevant with API keys
        tokens_count=0,  # Per-instance, not global
        review_pending=0,  # Per-instance, not global
        models_ready=ScrubIQ.is_preload_complete(),
        models_loading=not ScrubIQ.is_preload_complete(),
        preload_complete=ScrubIQ.is_preload_complete(),
        is_new_vault=not has_keys,  # New vault if no API keys
        vault_needs_upgrade=False,  # No longer relevant
    )


@router.get("/providers")
def list_providers(request: Request, cr: ScrubIQ = Depends(require_api_key)):
    """
    List available LLM providers and their models.

    Requires API key authentication.
    """
    check_rate_limit(request, action="auth_read", limit=AUTH_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    return {
        "available": cr.list_llm_providers(),
        "models": cr.list_llm_models(),
    }
