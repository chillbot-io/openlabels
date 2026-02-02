"""
Sensitivity label management API endpoints.

Provides:
- List sensitivity labels from database
- Sync labels from Microsoft 365 (immediate or background job)
- Label rules for auto-labeling
- Apply/remove labels from files
- Label cache management
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import SensitivityLabel, LabelRule, ScanResult
from openlabels.auth.dependencies import get_current_user, require_admin, CurrentUser
from openlabels.jobs import JobQueue

logger = logging.getLogger(__name__)

# Check for httpx
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

router = APIRouter()


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================


class LabelResponse(BaseModel):
    """Sensitivity label response."""

    id: str
    name: str
    description: Optional[str]
    priority: Optional[int]
    color: Optional[str]
    parent_id: Optional[str]

    class Config:
        from_attributes = True


class LabelRuleCreate(BaseModel):
    """Request to create a label rule."""

    rule_type: str  # 'risk_tier' | 'entity_type'
    match_value: str  # 'CRITICAL' | 'SSN'
    label_id: str
    priority: int = 0


class LabelRuleResponse(BaseModel):
    """Label rule response."""

    id: UUID
    rule_type: str
    match_value: str
    label_id: str
    label_name: Optional[str] = None
    priority: int

    class Config:
        from_attributes = True


class ApplyLabelRequest(BaseModel):
    """Request to apply a label to a file."""

    result_id: UUID
    label_id: str


@router.get("", response_model=list[LabelResponse])
async def list_labels(
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> list[LabelResponse]:
    """List available sensitivity labels."""
    query = select(SensitivityLabel).where(
        SensitivityLabel.tenant_id == user.tenant_id
    ).order_by(SensitivityLabel.priority)
    result = await session.execute(query)
    labels = result.scalars().all()
    return [LabelResponse.model_validate(l) for l in labels]


class LabelSyncRequest(BaseModel):
    """Request body for label sync options."""

    background: bool = False  # Run as background job
    remove_stale: bool = False  # Remove labels not in M365


@router.post("/sync", status_code=202)
async def sync_labels(
    request: Optional[LabelSyncRequest] = None,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> dict:
    """
    Sync sensitivity labels from Microsoft 365.

    Options:
    - background: If true, runs sync as a background job (returns immediately)
    - remove_stale: If true, removes labels from DB that no longer exist in M365
    """
    if not HTTPX_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="httpx not installed - cannot sync labels"
        )

    request = request or LabelSyncRequest()

    try:
        from openlabels.server.config import get_settings
        settings = get_settings()
        auth = settings.auth

        # Check Azure AD configuration
        if auth.provider != "azure_ad" or not all([auth.tenant_id, auth.client_id, auth.client_secret]):
            raise HTTPException(
                status_code=503,
                detail="Azure AD not configured - cannot sync labels from M365"
            )

        # If background mode, enqueue as job
        if request.background:
            queue = JobQueue(session, user.tenant_id)
            job_id = await queue.enqueue(
                task_type="label_sync",
                payload={
                    "tenant_id": str(user.tenant_id),
                    "azure_tenant_id": auth.tenant_id,
                    "client_id": auth.client_id,
                    "client_secret": auth.client_secret,
                    "remove_stale": request.remove_stale,
                },
                priority=70,  # High priority
            )
            return {
                "message": "Label sync job queued",
                "job_id": str(job_id),
                "background": True,
            }

        # Immediate sync
        from openlabels.jobs.tasks.label_sync import sync_labels_from_graph

        result = await sync_labels_from_graph(
            session=session,
            tenant_id=user.tenant_id,
            azure_tenant_id=auth.tenant_id,
            client_id=auth.client_id,
            client_secret=auth.client_secret,
            remove_stale=request.remove_stale,
        )

        await session.commit()

        # Invalidate label cache after sync
        try:
            from openlabels.labeling.engine import get_label_cache
            get_label_cache().invalidate()
        except Exception:
            pass

        return {
            "message": "Label sync completed",
            **result.to_dict(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Label sync failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Label sync failed: {str(e)}"
        )


@router.get("/sync/status")
async def get_sync_status(
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Get label sync status including last sync time and counts."""
    # Get label count and last sync time
    query = select(
        func.count(SensitivityLabel.id),
        func.max(SensitivityLabel.synced_at),
    ).where(SensitivityLabel.tenant_id == user.tenant_id)

    result = await session.execute(query)
    row = result.one()
    label_count, last_synced = row

    # Get cache status
    try:
        from openlabels.labeling.engine import get_label_cache
        cache_stats = get_label_cache().stats
    except Exception:
        cache_stats = None

    return {
        "label_count": label_count or 0,
        "last_synced_at": last_synced.isoformat() if last_synced else None,
        "cache": cache_stats,
    }


@router.post("/cache/invalidate", status_code=200)
async def invalidate_label_cache(
    user: CurrentUser = Depends(require_admin),
) -> dict:
    """Invalidate the label cache, forcing a refresh on next access."""
    try:
        from openlabels.labeling.engine import get_label_cache
        get_label_cache().invalidate()
        return {"message": "Label cache invalidated"}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to invalidate cache: {e}"
        )


@router.get("/rules", response_model=list[LabelRuleResponse])
async def list_label_rules(
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> list[LabelRuleResponse]:
    """List label mapping rules."""
    query = select(LabelRule).where(
        LabelRule.tenant_id == user.tenant_id
    ).order_by(LabelRule.priority.desc())
    result = await session.execute(query)
    rules = result.scalars().all()

    # Enrich with label names
    responses = []
    for rule in rules:
        label = await session.get(SensitivityLabel, rule.label_id)
        response = LabelRuleResponse.model_validate(rule)
        if label:
            response.label_name = label.name
        responses.append(response)

    return responses


@router.post("/rules", response_model=LabelRuleResponse, status_code=201)
async def create_label_rule(
    request: LabelRuleCreate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> LabelRuleResponse:
    """Create a label mapping rule."""
    if request.rule_type not in ("risk_tier", "entity_type"):
        raise HTTPException(status_code=400, detail="Invalid rule type")

    # Verify label exists
    label = await session.get(SensitivityLabel, request.label_id)
    if not label or label.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Label not found")

    rule = LabelRule(
        tenant_id=user.tenant_id,
        rule_type=request.rule_type,
        match_value=request.match_value,
        label_id=request.label_id,
        priority=request.priority,
        created_by=user.id,
    )
    session.add(rule)
    await session.flush()

    response = LabelRuleResponse.model_validate(rule)
    response.label_name = label.name
    return response


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_label_rule(
    rule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> None:
    """Delete a label rule."""
    rule = await session.get(LabelRule, rule_id)
    if not rule or rule.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule not found")

    await session.delete(rule)


@router.post("/apply", status_code=202)
async def apply_label(
    request: ApplyLabelRequest,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> dict:
    """Apply a sensitivity label to a file."""
    result = await session.get(ScanResult, request.result_id)
    if not result or result.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Result not found")

    label = await session.get(SensitivityLabel, request.label_id)
    if not label or label.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Label not found")

    # Enqueue labeling job
    queue = JobQueue(session, user.tenant_id)
    job_id = await queue.enqueue(
        task_type="label",
        payload={
            "result_id": str(request.result_id),
            "label_id": request.label_id,
            "file_path": result.file_path,
        },
        priority=60,  # Higher priority than scans
    )

    return {
        "message": "Label application queued",
        "job_id": str(job_id),
        "result_id": str(request.result_id),
        "label_id": request.label_id,
    }
