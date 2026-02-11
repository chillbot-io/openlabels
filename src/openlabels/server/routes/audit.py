"""
Audit log API endpoints.

Provides read-only access to audit trail for compliance and security monitoring.

Supports both cursor-based and offset-based pagination:
- Cursor-based (recommended for large audit logs): Use `cursor` parameter
- Offset-based (backward compatible): Use `page` and `page_size` parameters
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import require_admin
from openlabels.server.db import get_session
from openlabels.server.models import AuditLog
from openlabels.server.routes import get_or_404
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
    paginate_query,
)

router = APIRouter()


class AuditLogResponse(BaseModel):
    """Audit log entry response."""

    id: UUID
    user_id: UUID | None
    action: str
    resource_type: str | None
    resource_id: UUID | None
    details: dict | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogFilters(BaseModel):
    """Available filter options for audit logs."""

    actions: list[str]
    resource_types: list[str]


@router.get("", response_model=PaginatedResponse[AuditLogResponse])
async def list_audit_logs(
    action: str | None = Query(None, description="Filter by action type"),
    resource_type: str | None = Query(None, description="Filter by resource type"),
    resource_id: UUID | None = Query(None, description="Filter by resource ID"),
    user_id: UUID | None = Query(None, description="Filter by user ID"),
    start_date: datetime | None = Query(None, description="Start of date range"),
    end_date: datetime | None = Query(None, description="End of date range"),
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
) -> PaginatedResponse[AuditLogResponse]:
    """
    List audit log entries with filtering and pagination.

    Admin access required. Returns audit trail for the current tenant.
    """
    # Build base query with tenant filter
    conditions = [AuditLog.tenant_id == user.tenant_id]

    if action:
        # Validate action against known enum values to prevent DB-level errors
        VALID_AUDIT_ACTIONS = {
            'scan_started', 'scan_completed', 'scan_failed', 'scan_cancelled',
            'label_applied', 'label_removed', 'label_sync',
            'target_created', 'target_updated', 'target_deleted',
            'user_created', 'user_updated', 'user_deleted',
            'schedule_created', 'schedule_updated', 'schedule_deleted',
            'quarantine_executed', 'lockdown_executed', 'rollback_executed',
            'monitoring_enabled', 'monitoring_disabled',
        }
        if action not in VALID_AUDIT_ACTIONS:
            return PaginatedResponse[AuditLogResponse](
                **create_paginated_response(
                    items=[], total=0, page=pagination.page, page_size=pagination.page_size,
                )
            )
        conditions.append(AuditLog.action == action)
    if resource_type:
        conditions.append(AuditLog.resource_type == resource_type)
    if resource_id:
        conditions.append(AuditLog.resource_id == resource_id)
    if user_id:
        conditions.append(AuditLog.user_id == user_id)
    if start_date:
        conditions.append(AuditLog.created_at >= start_date)
    if end_date:
        conditions.append(AuditLog.created_at <= end_date)

    query = (
        select(AuditLog)
        .where(and_(*conditions))
        .order_by(AuditLog.created_at.desc())
    )
    result = await paginate_query(
        session, query, pagination,
        transformer=lambda log: AuditLogResponse.model_validate(log),
    )
    return PaginatedResponse[AuditLogResponse](**result)


@router.get("/filters", response_model=AuditLogFilters)
async def get_audit_filters(
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    Get available filter options for audit logs.

    Returns distinct actions and resource types for the current tenant.
    """
    # Get distinct actions
    actions_query = (
        select(AuditLog.action)
        .where(AuditLog.tenant_id == user.tenant_id)
        .distinct()
        .limit(500)
    )
    actions_result = await session.execute(actions_query)
    actions = [row[0] for row in actions_result.all()]

    # Get distinct resource types
    types_query = (
        select(AuditLog.resource_type)
        .where(
            AuditLog.tenant_id == user.tenant_id,
            AuditLog.resource_type.isnot(None),
        )
        .distinct()
        .limit(500)
    )
    types_result = await session.execute(types_query)
    resource_types = [row[0] for row in types_result.all()]

    return AuditLogFilters(
        actions=sorted(actions),
        resource_types=sorted(resource_types),
    )


@router.get("/{log_id}", response_model=AuditLogResponse)
async def get_audit_log(
    log_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Get a specific audit log entry."""
    log = await get_or_404(session, AuditLog, log_id, tenant_id=user.tenant_id)
    return AuditLogResponse.model_validate(log)


@router.get("/resource/{resource_type}/{resource_id}", response_model=PaginatedResponse[AuditLogResponse])
async def get_resource_history(
    resource_type: str,
    resource_id: UUID,
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
) -> PaginatedResponse[AuditLogResponse]:
    """
    Get audit history for a specific resource with pagination.

    Useful for tracking all actions performed on a particular target, schedule, etc.
    """
    base_query = select(AuditLog).where(
        AuditLog.tenant_id == user.tenant_id,
        AuditLog.resource_type == resource_type,
        AuditLog.resource_id == resource_id,
    )

    # Get total count
    count_query = select(func.count()).select_from(base_query.subquery())
    count_result = await session.execute(count_query)
    total = count_result.scalar() or 0

    # Get paginated results
    query = (
        base_query
        .order_by(AuditLog.created_at.desc())
        .offset(pagination.offset)
        .limit(pagination.limit)
    )
    result = await session.execute(query)
    logs = result.scalars().all()

    return PaginatedResponse[AuditLogResponse](
        **create_paginated_response(
            items=[AuditLogResponse.model_validate(log) for log in logs],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )
