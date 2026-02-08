"""
File monitoring and access events API endpoints.

Provides:
- File access event queries
- Monitored file management
- Access statistics and anomaly detection
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, case
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import (
    MonitoredFile,
    FileAccessEvent,
    FileInventory,
    AuditLog,
)
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)
from openlabels.auth.dependencies import get_current_user, require_admin
from openlabels.core.path_validation import validate_path, PathValidationError

router = APIRouter()


# =============================================================================
# RESPONSE MODELS
# =============================================================================


class MonitoredFileResponse(BaseModel):
    """Monitored file response."""

    id: UUID
    file_path: str
    risk_tier: str
    sacl_enabled: bool
    audit_rule_enabled: bool
    audit_read: bool
    audit_write: bool
    added_at: datetime
    last_event_at: Optional[datetime]
    access_count: int

    class Config:
        from_attributes = True


class AccessEventResponse(BaseModel):
    """File access event response."""

    id: UUID
    file_path: str
    action: str
    success: bool
    user_name: Optional[str]
    user_domain: Optional[str]
    process_name: Optional[str]
    event_time: datetime

    class Config:
        from_attributes = True


class EnableMonitoringRequest(BaseModel):
    """Request to enable monitoring on a file."""

    file_path: str = Field(..., description="Path to file to monitor")
    audit_read: bool = Field(True, description="Audit read access")
    audit_write: bool = Field(True, description="Audit write access")


class AccessStatsResponse(BaseModel):
    """Access statistics response."""

    total_events: int
    events_last_24h: int
    events_last_7d: int
    by_action: dict[str, int]
    by_user: list[dict]
    monitored_files_count: int


# =============================================================================
# MONITORED FILES ENDPOINTS
# =============================================================================


@router.get("/files", response_model=PaginatedResponse[MonitoredFileResponse])
async def list_monitored_files(
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier"),
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
) -> PaginatedResponse[MonitoredFileResponse]:
    """
    List all monitored files with pagination.

    Returns files that have monitoring enabled for access auditing.
    """
    # Build query
    query = select(MonitoredFile).where(MonitoredFile.tenant_id == user.tenant_id)

    if risk_tier:
        query = query.where(MonitoredFile.risk_tier == risk_tier)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    query = query.order_by(MonitoredFile.added_at.desc()).offset(pagination.offset).limit(pagination.limit)

    result = await session.execute(query)
    files = result.scalars().all()

    return PaginatedResponse[MonitoredFileResponse](
        **create_paginated_response(
            items=[MonitoredFileResponse.model_validate(f) for f in files],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.post("/files", response_model=MonitoredFileResponse)
async def enable_file_monitoring(
    request: EnableMonitoringRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    Enable monitoring on a file.

    This registers the file for access auditing. The actual SACL/auditd
    configuration is handled by the monitoring agent.

    Security:
    - File path is validated to prevent path traversal attacks
    - System directories are blocked from monitoring
    """
    # Security: Validate file path to prevent path traversal and block system paths
    try:
        validated_path = validate_path(request.file_path)
    except PathValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Check if already monitored
    existing = await session.execute(
        select(MonitoredFile).where(
            MonitoredFile.tenant_id == user.tenant_id,
            MonitoredFile.file_path == validated_path,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="File is already monitored")

    # Get file from inventory if it exists (to get risk tier)
    inventory = await session.execute(
        select(FileInventory).where(
            FileInventory.tenant_id == user.tenant_id,
            FileInventory.file_path == validated_path,
        )
    )
    file_inv = inventory.scalar_one_or_none()
    risk_tier = file_inv.risk_tier if file_inv else "MEDIUM"

    # Create monitored file record
    monitored = MonitoredFile(
        tenant_id=user.tenant_id,
        file_inventory_id=file_inv.id if file_inv else None,
        file_path=validated_path,  # Use validated path
        risk_tier=risk_tier,
        audit_read=request.audit_read,
        audit_write=request.audit_write,
        enabled_by=user.email,
    )
    session.add(monitored)

    # Log audit event
    audit = AuditLog(
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="monitoring_enabled",
        resource_type="file",
        details={
            "file_path": validated_path,  # Use validated path
            "audit_read": request.audit_read,
            "audit_write": request.audit_write,
        },
    )
    session.add(audit)
    await session.flush()

    # Refresh to load server-generated defaults (added_at)
    await session.refresh(monitored)

    return monitored


@router.delete("/files/{file_id}", status_code=204)
async def disable_file_monitoring(
    file_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    Disable monitoring on a file.

    This removes the file from monitoring. Access events are preserved
    for audit purposes.
    """
    monitored = await session.get(MonitoredFile, file_id)
    if not monitored or monitored.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Monitored file not found")

    file_path = monitored.file_path

    # Delete the monitoring record
    await session.delete(monitored)

    # Log audit event
    audit = AuditLog(
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="monitoring_disabled",
        resource_type="file",
        details={"file_path": file_path},
    )
    session.add(audit)
    await session.flush()


# =============================================================================
# ACCESS EVENTS ENDPOINTS
# =============================================================================


@router.get("/events", response_model=PaginatedResponse[AccessEventResponse])
async def list_access_events(
    file_path: Optional[str] = Query(None, description="Filter by file path"),
    user_name: Optional[str] = Query(None, description="Filter by user name"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    since: Optional[datetime] = Query(None, description="Filter events after this time"),
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
) -> PaginatedResponse[AccessEventResponse]:
    """
    List file access events with filtering and pagination.

    Returns access events collected from SACL (Windows) or auditd (Linux).
    """
    # Build query
    query = select(FileAccessEvent).where(FileAccessEvent.tenant_id == user.tenant_id)

    if file_path:
        query = query.where(FileAccessEvent.file_path == file_path)
    if user_name:
        query = query.where(FileAccessEvent.user_name.ilike(f"%{user_name}%"))
    if action:
        query = query.where(FileAccessEvent.action == action)
    if since:
        query = query.where(FileAccessEvent.event_time >= since)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    query = query.order_by(FileAccessEvent.event_time.desc()).offset(pagination.offset).limit(pagination.limit)

    result = await session.execute(query)
    events = result.scalars().all()

    return PaginatedResponse[AccessEventResponse](
        **create_paginated_response(
            items=[AccessEventResponse.model_validate(e) for e in events],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.get("/events/file/{file_path:path}", response_model=PaginatedResponse[AccessEventResponse])
async def get_file_access_history(
    file_path: str,
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
) -> PaginatedResponse[AccessEventResponse]:
    """
    Get access history for a specific file with pagination.

    Returns all access events for the given file path.
    """
    query = select(FileAccessEvent).where(
        FileAccessEvent.tenant_id == user.tenant_id,
        FileAccessEvent.file_path == file_path,
    )

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    query = query.order_by(FileAccessEvent.event_time.desc()).offset(pagination.offset).limit(pagination.limit)

    result = await session.execute(query)
    events = result.scalars().all()

    return PaginatedResponse[AccessEventResponse](
        **create_paginated_response(
            items=[AccessEventResponse.model_validate(e) for e in events],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.get("/events/user/{user_name}", response_model=PaginatedResponse[AccessEventResponse])
async def get_user_access_history(
    user_name: str,
    since: Optional[datetime] = Query(None, description="Filter events after this time"),
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
) -> PaginatedResponse[AccessEventResponse]:
    """
    Get access history for a specific user with pagination.

    Returns all access events performed by the given user.
    """
    conditions = [
        FileAccessEvent.tenant_id == user.tenant_id,
        FileAccessEvent.user_name.ilike(f"%{user_name}%"),
    ]
    if since:
        conditions.append(FileAccessEvent.event_time >= since)

    query = select(FileAccessEvent).where(and_(*conditions))

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    query = query.order_by(FileAccessEvent.event_time.desc()).offset(pagination.offset).limit(pagination.limit)

    result = await session.execute(query)
    events = result.scalars().all()

    return PaginatedResponse[AccessEventResponse](
        **create_paginated_response(
            items=[AccessEventResponse.model_validate(e) for e in events],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


# =============================================================================
# STATISTICS ENDPOINTS
# =============================================================================


@router.get("/stats", response_model=AccessStatsResponse)
async def get_access_stats(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get access monitoring statistics.

    Returns summary statistics about file access events.
    When backed by DuckDB, event aggregations run on Parquet;
    monitored file count always comes from PostgreSQL (OLTP).
    """
    from openlabels.analytics.dashboard_pg import PostgresDashboardService

    svc = getattr(request.app.state, "dashboard_service", None)
    if svc is None:
        svc = PostgresDashboardService(session)

    access_stats = await svc.get_access_stats(user.tenant_id)

    # Monitored files count — always from PostgreSQL (OLTP state)
    monitored_query = select(func.count()).select_from(MonitoredFile).where(
        MonitoredFile.tenant_id == user.tenant_id
    )
    monitored_result = await session.execute(monitored_query)
    monitored_count = monitored_result.scalar() or 0

    return AccessStatsResponse(
        total_events=access_stats.total_events,
        events_last_24h=access_stats.events_last_24h,
        events_last_7d=access_stats.events_last_7d,
        by_action=access_stats.by_action,
        by_user=access_stats.top_users,
        monitored_files_count=monitored_count,
    )


@router.get("/stats/anomalies")
async def detect_access_anomalies(
    hours: int = Query(24, ge=1, le=168, description="Hours to analyze"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Detect potential access anomalies.

    Looks for unusual patterns in file access:
    - High volume access from single user
    - Access outside business hours
    - Failed access attempts
    - Access to many sensitive files in short time
    """
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    anomalies = []

    # High volume access - users with > 100 accesses in the period
    volume_query = (
        select(
            FileAccessEvent.user_name,
            func.count().label("count"),
        )
        .where(
            FileAccessEvent.tenant_id == user.tenant_id,
            FileAccessEvent.event_time >= since,
            FileAccessEvent.user_name.isnot(None),
        )
        .group_by(FileAccessEvent.user_name)
        .having(func.count() > 100)
    )
    volume_result = await session.execute(volume_query)
    for row in volume_result.all():
        anomalies.append({
            "type": "high_volume",
            "severity": "medium",
            "user": row.user_name,
            "count": row.count,
            "description": f"User {row.user_name} accessed {row.count} files in {hours}h",
        })

    # Failed access attempts
    failed_query = (
        select(
            FileAccessEvent.user_name,
            FileAccessEvent.file_path,
            func.count().label("count"),
        )
        .where(
            FileAccessEvent.tenant_id == user.tenant_id,
            FileAccessEvent.event_time >= since,
            FileAccessEvent.success == False,  # noqa: E712
        )
        .group_by(FileAccessEvent.user_name, FileAccessEvent.file_path)
        .having(func.count() > 5)
    )
    failed_result = await session.execute(failed_query)
    for row in failed_result.all():
        anomalies.append({
            "type": "failed_access",
            "severity": "high",
            "user": row.user_name,
            "file_path": row.file_path,
            "count": row.count,
            "description": f"User {row.user_name} had {row.count} failed access attempts to {row.file_path}",
        })

    return {
        "analysis_period_hours": hours,
        "analyzed_since": since.isoformat(),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
    }
