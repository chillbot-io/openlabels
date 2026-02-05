"""
Sensitivity label management API endpoints.

Provides:
- List sensitivity labels from database
- Sync labels from Microsoft 365 (immediate or background job)
- Label rules for auto-labeling
- Apply/remove labels from files
- Label cache management

Performance:
- Labels and mappings are cached with Redis (fallback to in-memory)
- Cache is automatically invalidated when labels are synced or mappings updated
"""

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)
from openlabels.server.dependencies import (
    LabelServiceDep,
    TenantContextDep,
    AdminContextDep,
    DbSessionDep,
)
from openlabels.server.exceptions import NotFoundError, BadRequestError

logger = logging.getLogger(__name__)

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


class LabelSyncRequest(BaseModel):
    """Request body for label sync options."""

    background: bool = False  # Run as background job
    remove_stale: bool = False  # Remove labels not in M365


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


# =============================================================================
# LABEL ENDPOINTS
# =============================================================================


@router.get("", response_model=PaginatedResponse[LabelResponse])
async def list_labels(
    pagination: PaginationParams = Depends(),
    label_service: LabelServiceDep = Depends(),
    _tenant: TenantContextDep = Depends(),
) -> PaginatedResponse[LabelResponse]:
    """
    List available sensitivity labels with pagination.

    Results are cached per tenant for improved performance.
    Cache is invalidated when labels are synced.
    """
    labels, total = await label_service.list_labels(
        limit=pagination.limit,
        offset=pagination.offset,
    )

    return PaginatedResponse[LabelResponse](
        **create_paginated_response(
            items=[LabelResponse.model_validate(l) for l in labels],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.post("/sync", status_code=202)
async def sync_labels(
    request: Optional[LabelSyncRequest] = None,
    label_service: LabelServiceDep = Depends(),
    _admin: AdminContextDep = Depends(),
) -> dict:
    """
    Sync sensitivity labels from Microsoft 365.

    Options:
    - background: If true, runs sync as a background job (returns immediately)
    - remove_stale: If true, removes labels from DB that no longer exist in M365
    """
    request = request or LabelSyncRequest()
    return await label_service.sync_labels(
        background=request.background,
    )


@router.get("/sync/status")
async def get_sync_status(
    label_service: LabelServiceDep = Depends(),
    _tenant: TenantContextDep = Depends(),
) -> dict:
    """Get label sync status including last sync time and counts."""
    from sqlalchemy import select, func
    from openlabels.server.models import SensitivityLabel

    db = label_service.session

    # Get label count and last sync time
    query = select(
        func.count(SensitivityLabel.id),
        func.max(SensitivityLabel.synced_at),
    ).where(SensitivityLabel.tenant_id == label_service.tenant_id)

    result = await db.execute(query)
    row = result.one()
    label_count, last_synced = row

    # Get cache status
    try:
        from openlabels.labeling.engine import get_label_cache
        cache_stats = get_label_cache().stats
    except Exception as e:
        logger.debug(f"Failed to get label cache stats: {type(e).__name__}: {e}")
        cache_stats = None

    return {
        "label_count": label_count or 0,
        "last_synced_at": last_synced.isoformat() if last_synced else None,
        "cache": cache_stats,
    }


@router.post("/cache/invalidate", status_code=200)
async def invalidate_label_cache(
    label_service: LabelServiceDep = Depends(),
    _admin: AdminContextDep = Depends(),
) -> dict:
    """Invalidate the label cache, forcing a refresh on next access."""
    errors = []

    # Invalidate internal label cache
    try:
        from openlabels.labeling.engine import get_label_cache
        get_label_cache().invalidate()
    except Exception as e:
        errors.append(f"Label engine cache: {e}")

    # Invalidate Redis/memory cache for this tenant
    from openlabels.server.cache import invalidate_cache
    try:
        await invalidate_cache(f"labels:tenant:{label_service.tenant_id}")
        await invalidate_cache(f"label_mappings:tenant:{label_service.tenant_id}")
    except Exception as e:
        errors.append(f"Redis cache: {e}")

    if errors and len(errors) == 2:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to invalidate caches: {'; '.join(errors)}"
        )

    return {
        "message": "Label cache invalidated",
        "warnings": errors if errors else None,
    }


# =============================================================================
# LABEL RULES ENDPOINTS
# =============================================================================


@router.get("/rules", response_model=PaginatedResponse[LabelRuleResponse])
async def list_label_rules(
    pagination: PaginationParams = Depends(),
    label_service: LabelServiceDep = Depends(),
    _tenant: TenantContextDep = Depends(),
) -> PaginatedResponse[LabelRuleResponse]:
    """List label mapping rules with label names using a single JOIN query."""
    rules, total = await label_service.get_label_rules(
        limit=pagination.limit,
        offset=pagination.offset,
    )

    # Build responses - rules come back as LabelRule objects
    items = [LabelRuleResponse.model_validate(rule) for rule in rules]

    return PaginatedResponse[LabelRuleResponse](
        **create_paginated_response(
            items=items,
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.post("/rules", response_model=LabelRuleResponse, status_code=201)
async def create_label_rule(
    request: LabelRuleCreate,
    label_service: LabelServiceDep = Depends(),
    _admin: AdminContextDep = Depends(),
) -> LabelRuleResponse:
    """Create a label mapping rule."""
    rule = await label_service.create_label_rule({
        "rule_type": request.rule_type,
        "match_value": request.match_value,
        "label_id": request.label_id,
        "priority": request.priority,
    })

    return LabelRuleResponse.model_validate(rule)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_label_rule(
    rule_id: UUID,
    label_service: LabelServiceDep = Depends(),
    _admin: AdminContextDep = Depends(),
) -> None:
    """Delete a label rule."""
    await label_service.delete_label_rule(rule_id)


# =============================================================================
# LABEL APPLICATION ENDPOINTS
# =============================================================================


@router.post("/apply", status_code=202)
async def apply_label(
    request: ApplyLabelRequest,
    db: DbSessionDep = Depends(),
    label_service: LabelServiceDep = Depends(),
    admin: AdminContextDep = Depends(),
) -> dict:
    """Apply a sensitivity label to a file."""
    from openlabels.server.models import ScanResult, SensitivityLabel
    from openlabels.jobs import JobQueue

    result = await db.get(ScanResult, request.result_id)
    if not result or result.tenant_id != admin.tenant_id:
        raise NotFoundError(
            message="Result not found",
            resource_type="ScanResult",
            resource_id=str(request.result_id),
        )

    label = await db.get(SensitivityLabel, request.label_id)
    if not label or label.tenant_id != admin.tenant_id:
        raise NotFoundError(
            message="Label not found",
            resource_type="SensitivityLabel",
            resource_id=request.label_id,
        )

    # Enqueue labeling job
    queue = JobQueue(db, admin.tenant_id)
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


# =============================================================================
# LABEL MAPPINGS (simplified interface for web UI)
# =============================================================================


@router.get("/mappings", response_model=LabelMappingsResponse)
async def get_label_mappings(
    db: DbSessionDep = Depends(),
    label_service: LabelServiceDep = Depends(),
    _tenant: TenantContextDep = Depends(),
) -> LabelMappingsResponse:
    """
    Get label mappings for each risk tier.

    Results are cached per tenant for improved performance.
    Cache is invalidated when mappings are updated.
    """
    from openlabels.server.cache import get_cache_manager
    from openlabels.server.models import LabelRule, SensitivityLabel
    from sqlalchemy import select

    tenant_id = label_service.tenant_id
    cache_key = f"label_mappings:tenant:{tenant_id}"

    # Try to get from cache first
    try:
        cache = await get_cache_manager()
        cached = await cache.get(cache_key)
        if cached is not None:
            logger.debug(f"Cache hit for label mappings (tenant: {tenant_id})")
            return LabelMappingsResponse(
                CRITICAL=cached.get("CRITICAL"),
                HIGH=cached.get("HIGH"),
                MEDIUM=cached.get("MEDIUM"),
                LOW=cached.get("LOW"),
                labels=[LabelResponse(**l) for l in cached.get("labels", [])],
            )
    except Exception as e:
        logger.debug(f"Cache read failed: {e}")

    # Get all rules for risk_tier type
    query = select(LabelRule).where(
        LabelRule.tenant_id == tenant_id,
        LabelRule.rule_type == "risk_tier",
    )
    result = await db.execute(query)
    rules = result.scalars().all()

    # Build mappings dict
    mappings = {}
    for rule in rules:
        mappings[rule.match_value] = rule.label_id

    # Get available labels
    label_query = select(SensitivityLabel).where(
        SensitivityLabel.tenant_id == tenant_id
    ).order_by(SensitivityLabel.priority)
    label_result = await db.execute(label_query)
    labels = [LabelResponse.model_validate(l) for l in label_result.scalars().all()]

    response = LabelMappingsResponse(
        CRITICAL=mappings.get("CRITICAL"),
        HIGH=mappings.get("HIGH"),
        MEDIUM=mappings.get("MEDIUM"),
        LOW=mappings.get("LOW"),
        labels=labels,
    )

    # Cache the result
    try:
        cache = await get_cache_manager()
        cache_data = {
            "CRITICAL": response.CRITICAL,
            "HIGH": response.HIGH,
            "MEDIUM": response.MEDIUM,
            "LOW": response.LOW,
            "labels": [l.model_dump() for l in response.labels],
        }
        await cache.set(cache_key, cache_data)
        logger.debug(f"Cached label mappings for tenant: {tenant_id}")
    except Exception as e:
        logger.debug(f"Cache write failed: {e}")

    return response


@router.post("/mappings")
async def update_label_mappings(
    request: Request,
    db: DbSessionDep = Depends(),
    label_service: LabelServiceDep = Depends(),
    admin: AdminContextDep = Depends(),
):
    """Update label mappings for risk tiers."""
    from openlabels.server.cache import invalidate_cache
    from openlabels.server.models import LabelRule, SensitivityLabel
    from sqlalchemy import select

    tenant_id = label_service.tenant_id

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
        LabelRule.tenant_id == tenant_id,
        LabelRule.rule_type == "risk_tier",
    )
    existing_result = await db.execute(existing_query)
    for rule in existing_result.scalars().all():
        await db.delete(rule)

    # Flush after deletes to avoid sentinel matching issues with asyncpg
    await db.flush()

    # Batch fetch all requested labels in a single query (avoids N+1)
    requested_label_ids = [lid for lid in data.values() if lid]
    valid_labels = {}
    if requested_label_ids:
        labels_query = select(SensitivityLabel).where(
            SensitivityLabel.id.in_(requested_label_ids),
            SensitivityLabel.tenant_id == tenant_id,
        )
        labels_result = await db.execute(labels_query)
        valid_labels = {label.id: label for label in labels_result.scalars().all()}

    # Create new rules for non-empty mappings using pre-fetched labels
    priority = 100
    for risk_tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        label_id = data.get(risk_tier)
        if label_id and label_id in valid_labels:
            rule = LabelRule(
                tenant_id=tenant_id,
                rule_type="risk_tier",
                match_value=risk_tier,
                label_id=label_id,
                priority=priority,
                created_by=admin.user_id,
            )
            db.add(rule)
            # Flush each insert individually to avoid asyncpg sentinel matching issues
            await db.flush()
        priority -= 10

    # Invalidate cache for label mappings
    try:
        await invalidate_cache(f"label_mappings:tenant:{tenant_id}")
        logger.debug(f"Invalidated label mappings cache for tenant: {tenant_id}")
    except Exception as e:
        logger.debug(f"Failed to invalidate label mappings cache: {e}")

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
