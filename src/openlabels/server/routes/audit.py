"""
Audit log API endpoints.

Provides read-only access to audit trail for compliance and security monitoring.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import AuditLog
from openlabels.auth.dependencies import get_current_user, require_admin

router = APIRouter()


class AuditLogResponse(BaseModel):
    """Audit log entry response."""

    id: UUID
    user_id: Optional[UUID]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[UUID]
    details: Optional[dict]
    created_at: datetime

    class Config:
        from_attributes = True


class PaginatedAuditResponse(BaseModel):
    """Paginated list of audit log entries."""

    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class AuditLogFilters(BaseModel):
    """Available filter options for audit logs."""

    actions: list[str]
    resource_types: list[str]


@router.get("", response_model=PaginatedAuditResponse)
async def list_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action type"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    resource_id: Optional[UUID] = Query(None, description="Filter by resource ID"),
    user_id: Optional[UUID] = Query(None, description="Filter by user ID"),
    start_date: Optional[datetime] = Query(None, description="Start of date range"),
    end_date: Optional[datetime] = Query(None, description="End of date range"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    List audit log entries with filtering and pagination.

    Admin access required. Returns audit trail for the current tenant.
    """
    # Build base query with tenant filter
    conditions = [AuditLog.tenant_id == user.tenant_id]

    if action:
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

    base_query = select(AuditLog).where(and_(*conditions))

    # Get total count
    count_query = select(func.count()).select_from(base_query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Calculate pagination
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    offset = (page - 1) * page_size

    # Get paginated results (newest first)
    paginated_query = (
        base_query
        .order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(paginated_query)
    logs = result.scalars().all()

    return PaginatedAuditResponse(
        items=[AuditLogResponse.model_validate(log) for log in logs],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


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
    log = await session.get(AuditLog, log_id)
    if not log or log.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Audit log entry not found")
    return AuditLogResponse.model_validate(log)


@router.get("/resource/{resource_type}/{resource_id}", response_model=list[AuditLogResponse])
async def get_resource_history(
    resource_type: str,
    resource_id: UUID,
    limit: int = Query(50, ge=1, le=200, description="Max entries to return"),
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    Get audit history for a specific resource.

    Useful for tracking all actions performed on a particular target, schedule, etc.
    """
    query = (
        select(AuditLog)
        .where(
            AuditLog.tenant_id == user.tenant_id,
            AuditLog.resource_type == resource_type,
            AuditLog.resource_id == resource_id,
        )
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    )
    result = await session.execute(query)
    logs = result.scalars().all()

    return [AuditLogResponse.model_validate(log) for log in logs]
