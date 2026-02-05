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
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.config import get_settings
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
    settings = get_settings()
    try:
        query = select(SensitivityLabel).where(
            SensitivityLabel.tenant_id == user.tenant_id
        ).order_by(SensitivityLabel.priority)
        result = await session.execute(query)
        labels = result.scalars().all()
        return [LabelResponse.model_validate(l) for l in labels]
    except SQLAlchemyError as e:
        logger.error(f"Database error in list_labels: {e}")
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in list_labels: {e}")
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


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
        except Exception as e:
            logger.debug(f"Failed to invalidate label cache: {e}")

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
    settings = get_settings()
    try:
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
        except Exception as e:
            logger.debug(f"Failed to get cache stats: {e}")
            cache_stats = None

        return {
            "label_count": label_count or 0,
            "last_synced_at": last_synced.isoformat() if last_synced else None,
            "cache": cache_stats,
        }
    except SQLAlchemyError as e:
        logger.error(f"Database error in get_sync_status: {e}")
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in get_sync_status: {e}")
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


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
    settings = get_settings()
    try:
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
    except SQLAlchemyError as e:
        logger.error(f"Database error in list_label_rules: {e}")
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in list_label_rules: {e}")
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


@router.post("/rules", response_model=LabelRuleResponse, status_code=201)
async def create_label_rule(
    request: LabelRuleCreate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> LabelRuleResponse:
    """Create a label mapping rule."""
    if request.rule_type not in ("risk_tier", "entity_type"):
        raise HTTPException(status_code=400, detail="Invalid rule type")

    settings = get_settings()
    try:
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

        # Refresh to load server-generated defaults and ensure proper types
        await session.refresh(rule)

        response = LabelRuleResponse.model_validate(rule)
        return response.model_copy(update={"label_name": label.name})
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error in create_label_rule: {e}")
        await session.rollback()
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in create_label_rule: {e}")
        await session.rollback()
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_label_rule(
    rule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> None:
    """Delete a label rule."""
    settings = get_settings()
    try:
        rule = await session.get(LabelRule, rule_id)
        if not rule or rule.tenant_id != user.tenant_id:
            raise HTTPException(status_code=404, detail="Rule not found")

        await session.delete(rule)
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error in delete_label_rule: {e}")
        await session.rollback()
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in delete_label_rule: {e}")
        await session.rollback()
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


@router.post("/apply", status_code=202)
async def apply_label(
    request: ApplyLabelRequest,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> dict:
    """Apply a sensitivity label to a file."""
    settings = get_settings()
    try:
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
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error in apply_label: {e}")
        await session.rollback()
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in apply_label: {e}")
        await session.rollback()
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


# =============================================================================
# LABEL MAPPINGS (simplified interface for web UI)
# =============================================================================


class LabelMappingsResponse(BaseModel):
    """Label mappings for each risk tier."""

    CRITICAL: Optional[str] = None
    HIGH: Optional[str] = None
    MEDIUM: Optional[str] = None
    LOW: Optional[str] = None
    labels: list[LabelResponse] = []


class LabelMappingsUpdate(BaseModel):
    """Request to update label mappings."""

    CRITICAL: Optional[str] = None
    HIGH: Optional[str] = None
    MEDIUM: Optional[str] = None
    LOW: Optional[str] = None


@router.get("/mappings", response_model=LabelMappingsResponse)
async def get_label_mappings(
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> LabelMappingsResponse:
    """Get label mappings for each risk tier."""
    settings = get_settings()
    try:
        # Get all rules for risk_tier type
        query = select(LabelRule).where(
            LabelRule.tenant_id == user.tenant_id,
            LabelRule.rule_type == "risk_tier",
        )
        result = await session.execute(query)
        rules = result.scalars().all()

        # Build mappings dict
        mappings = {}
        for rule in rules:
            mappings[rule.match_value] = rule.label_id

        # Get available labels
        label_query = select(SensitivityLabel).where(
            SensitivityLabel.tenant_id == user.tenant_id
        ).order_by(SensitivityLabel.priority)
        label_result = await session.execute(label_query)
        labels = [LabelResponse.model_validate(l) for l in label_result.scalars().all()]

        return LabelMappingsResponse(
            CRITICAL=mappings.get("CRITICAL"),
            HIGH=mappings.get("HIGH"),
            MEDIUM=mappings.get("MEDIUM"),
            LOW=mappings.get("LOW"),
            labels=labels,
        )
    except SQLAlchemyError as e:
        logger.error(f"Database error in get_label_mappings: {e}")
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in get_label_mappings: {e}")
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


from fastapi import Request
from fastapi.responses import HTMLResponse


@router.post("/mappings")
async def update_label_mappings(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Update label mappings for risk tiers."""
    settings = get_settings()
    try:
        # Try to get JSON body, fallback to form data
        content_type = request.headers.get("content-type", "")

        if "application/json" in content_type:
            data = await request.json()
        else:
            form = await request.form()
            data = {
                "CRITICAL": form.get("CRITICAL") or None,
                "HIGH": form.get("HIGH") or None,
                "MEDIUM": form.get("MEDIUM") or None,
                "LOW": form.get("LOW") or None,
            }

        # Delete existing risk_tier rules
        existing_query = select(LabelRule).where(
            LabelRule.tenant_id == user.tenant_id,
            LabelRule.rule_type == "risk_tier",
        )
        existing_result = await session.execute(existing_query)
        for rule in existing_result.scalars().all():
            await session.delete(rule)

        # Create new rules for non-empty mappings
        # Flush after deletes to avoid sentinel matching issues with asyncpg
        await session.flush()

        priority = 100
        for risk_tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            label_id = data.get(risk_tier)
            if label_id:
                # Verify label exists
                label = await session.get(SensitivityLabel, label_id)
                if label and label.tenant_id == user.tenant_id:
                    rule = LabelRule(
                        tenant_id=user.tenant_id,
                        rule_type="risk_tier",
                        match_value=risk_tier,
                        label_id=label_id,
                        priority=priority,
                        created_by=user.id,
                    )
                    session.add(rule)
                    # Flush each insert individually to avoid asyncpg sentinel matching issues
                    await session.flush()
            priority -= 10

        # Check if HTMX request
        if request.headers.get("HX-Request"):
            return HTMLResponse(
                content="",
                status_code=200,
                headers={
                    "HX-Trigger": '{"notify": {"message": "Label mappings saved", "type": "success"}}',
                },
            )

        return {"message": "Label mappings updated"}
    except SQLAlchemyError as e:
        logger.error(f"Database error in update_label_mappings: {e}")
        await session.rollback()
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in update_label_mappings: {e}")
        await session.rollback()
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)
