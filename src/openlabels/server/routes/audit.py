"""
Audit log API endpoints.

Provides read-only access to audit trail for compliance and security monitoring.

Supports both cursor-based and offset-based pagination:
- Cursor-based (recommended for large audit logs): Use `cursor` parameter
- Offset-based (backward compatible): Use `page` and `page_size` parameters
"""

from datetime import datetime
from typing import Optional, Union
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import AuditLog
from openlabels.server.pagination import (
    CursorPaginationParams,
    PaginationMeta,
    CursorPaginationMeta,
    apply_cursor_pagination,
    build_cursor_response,
)
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


# Legacy response format for backward compatibility
class PaginatedAuditResponse(BaseModel):
    """
    Paginated list of audit log entries (legacy format).

    DEPRECATED: New clients should use the standardized format.
    """

    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
    # New fields for forward compatibility
    has_more: Optional[bool] = None


# New standardized response format
class AuditPaginatedResponse(BaseModel):
    """Standardized paginated response for audit logs."""

    data: list[AuditLogResponse] = Field(description="List of audit log entries")
    pagination: Union[CursorPaginationMeta, PaginationMeta] = Field(
        description="Pagination metadata"
    )


class AuditLogFilters(BaseModel):
    """Available filter options for audit logs."""

    actions: list[str]
    resource_types: list[str]


@router.get("")
async def list_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action type"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    resource_id: Optional[UUID] = Query(None, description="Filter by resource ID"),
    user_id: Optional[UUID] = Query(None, description="Filter by user ID"),
    start_date: Optional[datetime] = Query(None, description="Start of date range"),
    end_date: Optional[datetime] = Query(None, description="End of date range"),
    # Cursor-based pagination (recommended for large audit logs)
    cursor: Optional[str] = Query(
        None,
        description="Cursor for next page (recommended for large datasets)",
    ),
    # Offset-based pagination (for backward compatibility)
    page: int = Query(1, ge=1, description="Page number (ignored if cursor provided)"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    # Optional total count
    include_total: bool = Query(
        True,
        description="Include total count (set to false for faster queries)",
    ),
    # Response format
    format: str = Query(
        "legacy",
        description="Response format: 'legacy' or 'standard' (data/pagination)",
    ),
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
) -> Union[PaginatedAuditResponse, AuditPaginatedResponse]:
    """
    List audit log entries with filtering and pagination.

    Admin access required. Returns audit trail for the current tenant.

    Supports two pagination modes:
    - **Cursor-based** (recommended): Pass `cursor` from previous response
    - **Offset-based** (backward compatible): Use `page` and `page_size` parameters

    Supports two response formats:
    - **legacy** (default): `{items, total, page, page_size, total_pages}`
    - **standard**: `{data, pagination}` with cursor support
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

    # Count total if requested
    total = None
    if include_total:
        base_query = select(AuditLog).where(and_(*conditions))
        count_query = select(func.count()).select_from(base_query.subquery())
        total_result = await session.execute(count_query)
        total = total_result.scalar() or 0

    # Use cursor-based pagination if cursor is provided or standard format requested
    if cursor is not None or format == "standard":
        # Build base query with filters
        query = select(AuditLog).where(and_(*conditions))

        # Apply cursor-based pagination
        pagination_params = CursorPaginationParams(
            cursor=cursor,
            limit=page_size,
            include_total=include_total,
        )
        query, cursor_info = apply_cursor_pagination(
            query,
            AuditLog,
            pagination_params,
            sort_column=AuditLog.created_at,
            sort_desc=True,
        )

        result = await session.execute(query)
        logs = list(result.scalars().all())

        # Build pagination metadata
        pagination_meta = build_cursor_response(logs, cursor_info, total)

        # Trim extra result used for has_more check
        actual_logs = logs[: pagination_params.limit]

        if format == "standard":
            return AuditPaginatedResponse(
                data=[AuditLogResponse.model_validate(log) for log in actual_logs],
                pagination=pagination_meta,
            )
        else:
            # Legacy format with cursor info added
            total_pages = (total + page_size - 1) // page_size if total and total > 0 else 1
            return PaginatedAuditResponse(
                items=[AuditLogResponse.model_validate(log) for log in actual_logs],
                total=total or 0,
                page=page,
                page_size=page_size,
                total_pages=total_pages,
                has_more=pagination_meta.has_more,
            )

    # Offset-based pagination (legacy mode)
    # Count total if not yet done
    if total is None:
        base_query = select(AuditLog).where(and_(*conditions))
        count_query = select(func.count()).select_from(base_query.subquery())
        total_result = await session.execute(count_query)
        total = total_result.scalar() or 0

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    offset = (page - 1) * page_size

    # Get paginated results (newest first)
    paginated_query = (
        select(AuditLog)
        .where(and_(*conditions))
        .order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(paginated_query)
    logs = result.scalars().all()

    if format == "standard":
        return AuditPaginatedResponse(
            data=[AuditLogResponse.model_validate(log) for log in logs],
            pagination=PaginationMeta.from_offset(total, page, page_size),
        )

    return PaginatedAuditResponse(
        items=[AuditLogResponse.model_validate(log) for log in logs],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        has_more=page < total_pages,
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
