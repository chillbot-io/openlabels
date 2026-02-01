"""Review and audit routes."""

import logging
from typing import List
from fastapi import APIRouter, Depends, Path, Query, Request

from ...core import ScrubIQ
from ...constants import API_RATE_WINDOW_SECONDS, MAX_PAGINATION_LIMIT
from ...rate_limiter import check_rate_limit
from ..dependencies import require_unlocked
from ..errors import not_found, ErrorCode
from .schemas import ReviewItem, AuditEntry, AuditVerifyResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["reviews"])

# Rate limits for review/audit endpoints
AUDIT_RATE_LIMIT = 30  # Max audit requests per window
REVIEW_RATE_LIMIT = 60  # Max review actions per window


@router.get("/reviews", response_model=List[ReviewItem])
def list_reviews(request: Request, cr: ScrubIQ = Depends(require_unlocked)):
    """List pending human review items."""
    check_rate_limit(request, action="review", limit=REVIEW_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    return [ReviewItem(**r) for r in cr.get_pending_reviews()]


@router.post("/reviews/{item_id}/approve")
def approve_review(
    request: Request,
    item_id: str = Path(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$"),
    cr: ScrubIQ = Depends(require_unlocked)
):
    """Approve a detection (keep as PHI)."""
    check_rate_limit(request, action="review", limit=REVIEW_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    success = cr.approve_review(item_id)
    if not success:
        raise not_found("Review item not found", error_code=ErrorCode.NOT_FOUND)
    return {"success": True}


@router.post("/reviews/{item_id}/reject")
def reject_review(
    request: Request,
    item_id: str = Path(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$"),
    cr: ScrubIQ = Depends(require_unlocked)
):
    """Reject a detection (false positive)."""
    check_rate_limit(request, action="review", limit=REVIEW_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    success = cr.reject_review(item_id)
    if not success:
        raise not_found("Review item not found", error_code=ErrorCode.NOT_FOUND)
    return {"success": True}


@router.get("/audits", response_model=List[AuditEntry])
def list_audits(
    request: Request,
    limit: int = Query(default=100, ge=1, le=MAX_PAGINATION_LIMIT),
    cr: ScrubIQ = Depends(require_unlocked),
):
    """List recent audit entries."""
    check_rate_limit(request, action="audit", limit=AUDIT_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    return [AuditEntry(**e) for e in cr.get_audit_entries(limit=limit)]


@router.get("/audits/verify", response_model=AuditVerifyResponse)
def verify_audits(request: Request, cr: ScrubIQ = Depends(require_unlocked)):
    """Verify audit log integrity."""
    check_rate_limit(request, action="audit", limit=AUDIT_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    valid, error = cr.verify_audit_chain()
    return AuditVerifyResponse(valid=valid, error=error)
