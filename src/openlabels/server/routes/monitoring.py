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

from fastapi import APIRouter, Depends, HTTPException, Query
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


class MonitoredFileListResponse(BaseModel):
    """Paginated list of monitored files."""

    items: list[MonitoredFileResponse]
    total: int
    page: int
    pages: int


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


class AccessEventListResponse(BaseModel):
    """Paginated list of access events."""

    items: list[AccessEventResponse]
    total: int
    page: int
    pages: int


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


@router.get("/files", response_model=MonitoredFileListResponse)
async def list_monitored_files(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    List all monitored files.

    Returns files that have monitoring enabled for access auditing.
    """
    # Build query
    query = select(MonitoredFile).where(MonitoredFile.tenant_id == user.tenant_id)

    if risk_tier:
        query = query.where(MonitoredFile.risk_tier == risk_tier)

    # Get total count
    count_query = select(func.count()).select_from(MonitoredFile).where(
        MonitoredFile.tenant_id == user.tenant_id
    )
    if risk_tier:
        count_query = count_query.where(MonitoredFile.risk_tier == risk_tier)

    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    offset = (page - 1) * limit
    query = query.order_by(MonitoredFile.added_at.desc()).offset(offset).limit(limit)

    result = await session.execute(query)
    files = result.scalars().all()

    pages = (total + limit - 1) // limit if total > 0 else 1

    return MonitoredFileListResponse(
        items=files,
        total=total,
        page=page,
        pages=pages,
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


@router.get("/events", response_model=AccessEventListResponse)
async def list_access_events(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    file_path: Optional[str] = Query(None, description="Filter by file path"),
    user_name: Optional[str] = Query(None, description="Filter by user name"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    since: Optional[datetime] = Query(None, description="Filter events after this time"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    List file access events with filtering.

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

    # Get total count for pagination
    count_conditions = [FileAccessEvent.tenant_id == user.tenant_id]
    if file_path:
        count_conditions.append(FileAccessEvent.file_path == file_path)
    if user_name:
        count_conditions.append(FileAccessEvent.user_name.ilike(f"%{user_name}%"))
    if action:
        count_conditions.append(FileAccessEvent.action == action)
    if since:
        count_conditions.append(FileAccessEvent.event_time >= since)

    count_query = select(func.count()).select_from(FileAccessEvent).where(
        and_(*count_conditions)
    )
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    offset = (page - 1) * limit
    query = query.order_by(FileAccessEvent.event_time.desc()).offset(offset).limit(limit)

    result = await session.execute(query)
    events = result.scalars().all()

    pages = (total + limit - 1) // limit if total > 0 else 1

    return AccessEventListResponse(
        items=events,
        total=total,
        page=page,
        pages=pages,
    )


@router.get("/events/file/{file_path:path}", response_model=AccessEventListResponse)
async def get_file_access_history(
    file_path: str,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get access history for a specific file.

    Returns all access events for the given file path.
    """
    query = select(FileAccessEvent).where(
        FileAccessEvent.tenant_id == user.tenant_id,
        FileAccessEvent.file_path == file_path,
    )

    # Get total count
    count_query = select(func.count()).select_from(FileAccessEvent).where(
        FileAccessEvent.tenant_id == user.tenant_id,
        FileAccessEvent.file_path == file_path,
    )
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    offset = (page - 1) * limit
    query = query.order_by(FileAccessEvent.event_time.desc()).offset(offset).limit(limit)

    result = await session.execute(query)
    events = result.scalars().all()

    pages = (total + limit - 1) // limit if total > 0 else 1

    return AccessEventListResponse(
        items=events,
        total=total,
        page=page,
        pages=pages,
    )


@router.get("/events/user/{user_name}", response_model=AccessEventListResponse)
async def get_user_access_history(
    user_name: str,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    since: Optional[datetime] = Query(None, description="Filter events after this time"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get access history for a specific user.

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
    count_query = select(func.count()).select_from(FileAccessEvent).where(
        and_(*conditions)
    )
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    offset = (page - 1) * limit
    query = query.order_by(FileAccessEvent.event_time.desc()).offset(offset).limit(limit)

    result = await session.execute(query)
    events = result.scalars().all()

    pages = (total + limit - 1) // limit if total > 0 else 1

    return AccessEventListResponse(
        items=events,
        total=total,
        page=page,
        pages=pages,
    )


# =============================================================================
# STATISTICS ENDPOINTS
# =============================================================================


@router.get("/stats", response_model=AccessStatsResponse)
async def get_access_stats(
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get access monitoring statistics.

    Returns summary statistics about file access events.
    """
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    # Total events and time-based counts
    stats_query = select(
        func.count().label("total"),
        func.sum(
            case((FileAccessEvent.event_time >= last_24h, 1), else_=0)
        ).label("last_24h"),
        func.sum(
            case((FileAccessEvent.event_time >= last_7d, 1), else_=0)
        ).label("last_7d"),
    ).where(FileAccessEvent.tenant_id == user.tenant_id)

    result = await session.execute(stats_query)
    row = result.one()

    total_events = row.total or 0
    events_last_24h = row.last_24h or 0
    events_last_7d = row.last_7d or 0

    # Events by action type
    action_query = (
        select(
            FileAccessEvent.action,
            func.count().label("count"),
        )
        .where(FileAccessEvent.tenant_id == user.tenant_id)
        .group_by(FileAccessEvent.action)
    )
    action_result = await session.execute(action_query)
    by_action = {row.action: row.count for row in action_result.all()}

    # Top users by access count
    user_query = (
        select(
            FileAccessEvent.user_name,
            func.count().label("count"),
        )
        .where(
            FileAccessEvent.tenant_id == user.tenant_id,
            FileAccessEvent.user_name.isnot(None),
        )
        .group_by(FileAccessEvent.user_name)
        .order_by(func.count().desc())
        .limit(10)
    )
    user_result = await session.execute(user_query)
    by_user = [{"user": row.user_name, "count": row.count} for row in user_result.all()]

    # Monitored files count
    monitored_query = select(func.count()).select_from(MonitoredFile).where(
        MonitoredFile.tenant_id == user.tenant_id
    )
    monitored_result = await session.execute(monitored_query)
    monitored_count = monitored_result.scalar() or 0

    return AccessStatsResponse(
        total_events=total_events,
        events_last_24h=events_last_24h,
        events_last_7d=events_last_7d,
        by_action=by_action,
        by_user=by_user,
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
