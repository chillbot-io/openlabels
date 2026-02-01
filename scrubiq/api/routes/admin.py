"""Admin routes: health checks, greeting."""

import os
import sys
import platform
import random
import logging
from datetime import date

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse

from ...core import ScrubIQ
from ...constants import API_RATE_WINDOW_SECONDS, DEFAULT_ANTHROPIC_FAST_MODEL
from ...rate_limiter import check_rate_limit
from ..dependencies import require_api_key
from ..limiter import limiter, SLOWAPI_AVAILABLE
from .schemas import GreetingResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin"])

# Check if production mode (don't expose version info)
_IS_PRODUCTION = os.environ.get("PROD", "").lower() in ("1", "true", "yes")

# Rate limits for admin endpoints
ADMIN_READ_RATE_LIMIT = 60  # Max reads per window
GREETING_RATE_LIMIT = 10  # Greeting uses LLM, so limit more strictly

# Cache for daily greeting
_greeting_cache: dict = {"date": None, "greeting": None}


# Conditional exempt decorator for health endpoints
_exempt = limiter.exempt if SLOWAPI_AVAILABLE and limiter else lambda f: f


@router.get("/health")
@_exempt
def health():
    """Basic health check endpoint for load balancers.

    Exempt from rate limiting to allow monitoring/load balancer health checks.

    SECURITY: Never exposes version info to reduce attack surface.
    Use /health/detailed (requires auth) for version and component status.
    """
    # SECURITY: Always return minimal response - no version info
    # Version info helps attackers identify known vulnerabilities
    return {"status": "ok"}


@router.get("/.well-known/security.txt", response_class=PlainTextResponse)
def security_txt():
    """
    Security.txt for responsible disclosure per RFC 9116.

    See: https://securitytxt.org/
    """
    return """# ScrubIQ Security Policy
# Per RFC 9116 (https://www.rfc-editor.org/rfc/rfc9116)

Contact: https://github.com/chillbot-io/scrubiq/security/advisories/new
Preferred-Languages: en
Canonical: /.well-known/security.txt
Policy: https://github.com/chillbot-io/scrubiq/security/policy

# For security issues, please report via GitHub Security Advisories.
# We aim to respond within 48 hours and provide updates within 7 days.
"""


@router.get("/health/detailed")
def health_detailed(cr: ScrubIQ = Depends(require_api_key)):
    """Detailed health check with component status."""
    from ... import __version__
    
    db_ok = cr._db is not None and cr._db.conn is not None
    encryption_status = "ok" if cr.is_unlocked else "locked"
    
    # Detector status
    if not cr.is_unlocked:
        detector_status = "not_loaded"
    elif cr._models_loading:
        detector_status = "loading"
    elif cr._detectors is not None:
        detector_status = "ok"
    else:
        detector_status = "failed"
    
    # LLM status
    if not cr.is_unlocked:
        llm_status = "not_loaded"
    elif cr._llm_loading:
        llm_status = "loading"
    elif cr._llm_client is not None and cr._llm_client.is_available():
        llm_status = "ok"
    else:
        llm_status = "unavailable"
    
    # OCR status
    if not cr.is_unlocked:
        ocr_status = "not_loaded"
    elif cr._ocr_engine is not None and cr._ocr_engine.is_available:
        ocr_status = "ok"
    else:
        ocr_status = "unavailable"
    
    return {
        "status": "ok",
        "version": __version__,
        "python_version": sys.version.split()[0],
        "platform": platform.system(),
        "components": {
            "database": "ok" if db_ok else "error",
            "encryption": encryption_status,
            "detectors": detector_status,
            "llm": llm_status,
            "ocr": ocr_status,
        },
        "ready": (
            cr.is_unlocked and 
            not cr._models_loading and 
            cr._detectors is not None
        ),
    }


@router.get("/greeting", response_model=GreetingResponse)
def get_greeting(request: Request, cr: ScrubIQ = Depends(require_api_key)):
    """Get a friendly greeting for the empty state."""
    check_rate_limit(request, action="greeting", limit=GREETING_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    today = date.today().isoformat()
    
    # Check cache
    if _greeting_cache["date"] == today and _greeting_cache["greeting"]:
        return GreetingResponse(greeting=_greeting_cache["greeting"], cached=True)
    
    default_greetings = [
        "Welcome! How can I help you today?",
        "Ready to assist. What's on your mind?",
        "Let's work on something together.",
        "How can I help you today?",
        "Ready when you are. Your data stays protected.",
    ]

    # Try to generate with LLM
    if cr.is_unlocked and cr.has_llm:
        try:
            prompt = """Generate a single warm, professional greeting for an AI assistant.
The greeting should:
- Be friendly but professional
- Be 5-15 words
- Not include a name (user hasn't set one yet)
- Not include "I'm an AI" or similar
- Transition naturally to getting work done

Examples of good greetings:
- "Good to see you! What are we working on today?"
- "Ready to help. What's on your mind?"
- "Let's tackle something together. What do you need?"

Respond with ONLY the greeting, no quotes or explanation."""

            response = cr._llm_client.chat(
                messages=[{"role": "user", "content": prompt}],
                model=DEFAULT_ANTHROPIC_FAST_MODEL,
            )
            
            if response.success and response.text:
                greeting = response.text.strip().strip('"').strip("'")
                if 5 <= len(greeting) <= 100:
                    _greeting_cache["date"] = today
                    _greeting_cache["greeting"] = greeting
                    return GreetingResponse(greeting=greeting, cached=False)
        except Exception as e:
            logger.warning(f"Failed to generate greeting: {e}")
    
    # Fallback to random default
    greeting = random.choice(default_greetings)
    _greeting_cache["date"] = today
    _greeting_cache["greeting"] = greeting

    return GreetingResponse(greeting=greeting, cached=False)


@router.get("/audit/status")
def audit_status(request: Request, cr: ScrubIQ = Depends(require_api_key)):
    """
    Get audit log status for monitoring and retention planning.

    Returns information about audit log size, entry count, and retention status.
    Use this to monitor growth and plan archival/rotation.

    HIPAA requires 6 years (2190 days) retention by default.
    """
    check_rate_limit(request, action="admin_read", limit=ADMIN_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    if not cr._audit:
        return {
            "status": "not_initialized",
            "message": "Audit log not available",
        }

    retention_info = cr._audit.get_retention_status()
    chain_valid, chain_error = cr._audit.verify_chain()

    return {
        "status": "ok",
        "total_entries": retention_info["total_entries"],
        "oldest_entry": retention_info["oldest_entry"],
        "entries_past_retention": retention_info["entries_past_retention"],
        "retention_days": retention_info["retention_days"],
        "estimated_size_mb": retention_info["estimated_size_mb"],
        "chain_integrity": "valid" if chain_valid else "broken",
        "chain_error": chain_error,
    }
