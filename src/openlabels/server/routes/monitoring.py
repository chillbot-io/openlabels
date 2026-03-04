"""
File monitoring and access events API endpoints.

Provides:
- File access event queries with risk enrichment
- Monitored file management
- Access statistics and anomaly detection
- Event type metadata with badge styling
- Folder tree for filter panels
- Event retention settings and purge
- Alert rule CRUD for suspicious patterns
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import get_current_user, require_admin
from openlabels.core.path_validation import PathValidationError, validate_path
from openlabels.server.db import get_session
from openlabels.server.models import (
    AlertRule,
    AuditLog,
    FileAccessEvent,
    FileInventory,
    MonitoredFile,
    ScanResult,
    generate_uuid,
)
from openlabels.server.routes import get_or_404
from openlabels.server.schemas.pagination import (
    CursorPaginatedResponse,
    CursorPaginationParams,
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
    cursor_paginate_query,
    paginate_query,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# RESPONSE MODELS
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
    last_event_at: datetime | None
    access_count: int

    model_config = ConfigDict(from_attributes=True)


class AccessEventResponse(BaseModel):
    """File access event response."""

    id: UUID
    file_path: str
    action: str
    success: bool
    user_name: str | None
    user_domain: str | None
    process_name: str | None
    event_time: datetime
    risk_tier: str | None = None
    scan_result_id: UUID | None = None

    model_config = ConfigDict(from_attributes=True)


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


class EventTypeInfo(BaseModel):
    """Event type metadata with badge styling."""

    action: str
    label: str
    badge_color: str
    description: str


class FolderNode(BaseModel):
    """Folder tree node for filtering."""

    path: str
    name: str
    event_count: int
    children: list[FolderNode] = []


class RetentionSettings(BaseModel):
    """Event retention configuration."""

    retention_days: int = Field(90, ge=1, le=3650, description="Days to retain events")
    archive_enabled: bool = Field(False, description="Archive events before purging")
    archive_format: str = Field("parquet", description="Archive format: parquet or csv")


class RetentionPurgeResponse(BaseModel):
    """Result of a retention purge operation."""

    purged_count: int
    cutoff_date: str
    archived: bool


class AlertRuleResponse(BaseModel):
    """Alert rule response."""

    id: UUID
    name: str
    description: str | None
    enabled: bool
    rule_type: str
    conditions: dict
    severity: str
    actions: list
    created_at: datetime
    updated_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class AlertRuleCreateRequest(BaseModel):
    """Request to create an alert rule."""

    name: str = Field(..., max_length=255)
    description: str | None = None
    enabled: bool = True
    rule_type: str = Field(..., description="Rule type: high_volume, failed_access, off_hours, sensitive_file_access, permission_change")
    conditions: dict = Field(..., description="Condition parameters for the rule type")
    severity: str = Field("medium", description="Severity: low, medium, high, critical")
    actions: list[str] = Field(default=["log"], description="Actions: log, notify, webhook")


class AlertRuleUpdateRequest(BaseModel):
    """Request to update an alert rule."""

    name: str | None = Field(None, max_length=255)
    description: str | None = None
    enabled: bool | None = None
    conditions: dict | None = None
    severity: str | None = None
    actions: list[str] | None = None


# Valid alert rule types and severities
VALID_RULE_TYPES = {"high_volume", "failed_access", "off_hours", "sensitive_file_access", "permission_change"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}

# Event type metadata
EVENT_TYPES: list[dict] = [
    {"action": "read", "label": "Read", "badge_color": "#3B82F6", "description": "File was read or opened"},
    {"action": "write", "label": "Write", "badge_color": "#F97316", "description": "File was modified or created"},
    {"action": "delete", "label": "Delete", "badge_color": "#EF4444", "description": "File was deleted"},
    {"action": "permission_change", "label": "Permission Change", "badge_color": "#8B5CF6", "description": "File permissions were modified"},
    {"action": "rename", "label": "Rename", "badge_color": "#6366F1", "description": "File was renamed or moved"},
    {"action": "execute", "label": "Execute", "badge_color": "#EC4899", "description": "File was executed"},
]


async def _enrich_events(
    events: list,
    session: AsyncSession,
    tenant_id: UUID,
) -> list[AccessEventResponse]:
    """Enrich access events with risk_tier from MonitoredFile and scan_result_id from ScanResult."""
    if not events:
        return []

    file_paths = list({e.file_path for e in events})

    # Batch lookup monitored file risk tiers
    mf_result = await session.execute(
        select(MonitoredFile.file_path, MonitoredFile.risk_tier)
        .where(
            MonitoredFile.tenant_id == tenant_id,
            MonitoredFile.file_path.in_(file_paths),
        )
    )
    risk_map = {row.file_path: row.risk_tier for row in mf_result.all()}

    # Batch lookup scan result IDs
    sr_result = await session.execute(
        select(ScanResult.file_path, ScanResult.id)
        .where(
            ScanResult.tenant_id == tenant_id,
            ScanResult.file_path.in_(file_paths),
        )
        .order_by(ScanResult.scanned_at.desc())
    )
    # Take the most recent scan result per file_path
    result_map: dict[str, UUID] = {}
    for row in sr_result.all():
        if row.file_path not in result_map:
            result_map[row.file_path] = row.id

    enriched = []
    for e in events:
        resp = AccessEventResponse.model_validate(e)
        resp.risk_tier = risk_map.get(e.file_path)
        resp.scan_result_id = result_map.get(e.file_path)
        enriched.append(resp)
    return enriched


# MONITORED FILES ENDPOINTS
@router.get("/files", response_model=PaginatedResponse[MonitoredFileResponse])
async def list_monitored_files(
    risk_tier: str | None = Query(None, description="Filter by risk tier"),
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
) -> PaginatedResponse[MonitoredFileResponse]:
    """
    List all monitored files with pagination.

    Returns files that have monitoring enabled for access auditing.
    """
    query = select(MonitoredFile).where(MonitoredFile.tenant_id == user.tenant_id)
    if risk_tier:
        query = query.where(MonitoredFile.risk_tier == risk_tier)
    query = query.order_by(MonitoredFile.added_at.desc())

    result = await paginate_query(
        session, query, pagination,
        transformer=lambda f: MonitoredFileResponse.model_validate(f),
    )
    return PaginatedResponse[MonitoredFileResponse](**result)


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
        logger.warning("Path validation failed: %s", e)
        raise HTTPException(status_code=400, detail="Invalid file path") from e

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
    monitored = await get_or_404(session, MonitoredFile, file_id, tenant_id=user.tenant_id)

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


# ACCESS EVENTS ENDPOINTS
@router.get("/events", response_model=PaginatedResponse[AccessEventResponse])
async def list_access_events(
    file_path: str | None = Query(None, description="Filter by file path"),
    user_name: str | None = Query(None, description="Filter by user name"),
    action: str | None = Query(None, description="Filter by action type"),
    since: datetime | None = Query(None, description="Filter events after this time"),
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
        # SECURITY: Escape LIKE wildcards to prevent data enumeration
        safe_name = user_name.replace("%", r"\%").replace("_", r"\_")
        query = query.where(FileAccessEvent.user_name.ilike(f"%{safe_name}%"))
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
    enriched = await _enrich_events(events, session, user.tenant_id)

    return PaginatedResponse[AccessEventResponse](
        **create_paginated_response(
            items=enriched,
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.get("/events/cursor", response_model=CursorPaginatedResponse[AccessEventResponse])
async def list_access_events_cursor(
    file_path: str | None = Query(None, description="Filter by file path"),
    user_name: str | None = Query(None, description="Filter by user name"),
    action: str | None = Query(None, description="Filter by action type"),
    since: datetime | None = Query(None, description="Filter events after this time"),
    pagination: CursorPaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
) -> CursorPaginatedResponse[AccessEventResponse]:
    """
    List file access events using cursor-based pagination.

    Designed for large event datasets and infinite-scroll UIs.
    Cursors are HMAC-signed and based on (event_time, id) for stable ordering.
    """
    conditions = [FileAccessEvent.tenant_id == user.tenant_id]

    if file_path:
        # Support both exact file match and folder prefix filtering
        if file_path.endswith("/") or file_path.endswith("\\"):
            safe_path = file_path.replace("%", r"\%").replace("_", r"\_")
            conditions.append(FileAccessEvent.file_path.ilike(f"{safe_path}%"))
        else:
            conditions.append(FileAccessEvent.file_path.startswith(file_path))
    if user_name:
        safe_name = user_name.replace("%", r"\%").replace("_", r"\_")
        conditions.append(FileAccessEvent.user_name.ilike(f"%{safe_name}%"))
    if action:
        conditions.append(FileAccessEvent.action == action)
    if since:
        conditions.append(FileAccessEvent.event_time >= since)

    query = (
        select(FileAccessEvent)
        .where(*conditions)
        .order_by(FileAccessEvent.event_time.desc(), FileAccessEvent.id.desc())
    )

    result = await cursor_paginate_query(
        session,
        query,
        pagination,
        cursor_columns=[
            (FileAccessEvent.event_time, "event_time"),
            (FileAccessEvent.id, "id"),
        ],
        transformer=lambda e: AccessEventResponse.model_validate(e),
    )

    return CursorPaginatedResponse[AccessEventResponse](**result)


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
    since: datetime | None = Query(None, description="Filter events after this time"),
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
) -> PaginatedResponse[AccessEventResponse]:
    """
    Get access history for a specific user with pagination.

    Returns all access events performed by the given user.
    """
    # SECURITY: Escape LIKE wildcards to prevent data enumeration
    safe_name = user_name.replace("%", r"\%").replace("_", r"\_")
    conditions = [
        FileAccessEvent.tenant_id == user.tenant_id,
        FileAccessEvent.user_name.ilike(f"%{safe_name}%"),
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


# STATISTICS ENDPOINTS
@router.get("/stats", response_model=AccessStatsResponse)
async def get_access_stats(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get access monitoring statistics.

    Returns summary statistics about file access events.
    Event aggregations run on DuckDB/Parquet; monitored file count
    always comes from PostgreSQL (OLTP).
    """
    svc = getattr(request.app.state, "dashboard_service", None)
    if svc is None:
        raise HTTPException(status_code=503, detail="Analytics engine unavailable")

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
    volume_query = volume_query.limit(100)
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
    failed_query = failed_query.limit(100)
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


# ── Event type metadata ──────────────────────────────────────────────

@router.get("/events/types", response_model=list[EventTypeInfo])
async def list_event_types(
    _user=Depends(get_current_user),
) -> list[EventTypeInfo]:
    """List event types with badge colors and descriptions.

    Returns metadata for rendering event type badges in the UI.
    """
    return [EventTypeInfo(**t) for t in EVENT_TYPES]


# ── Folder tree ─────────────────────────────────────────────────────

@router.get("/events/folders", response_model=list[FolderNode])
async def list_event_folders(
    depth: int = Query(3, ge=1, le=10, description="Maximum folder depth"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
) -> list[FolderNode]:
    """Build a folder tree from file access event paths.

    Returns a hierarchical folder structure with event counts
    for use in the folder filter tree panel.
    """
    result = await session.execute(
        select(
            FileAccessEvent.file_path,
            func.count(FileAccessEvent.id).label("event_count"),
        )
        .where(FileAccessEvent.tenant_id == user.tenant_id)
        .group_by(FileAccessEvent.file_path)
        .limit(50_000)
    )
    rows = result.all()

    # Build intermediate tree
    tree: dict = {}
    for row in rows:
        parts = row.file_path.replace("\\", "/").split("/")
        parts = [p for p in parts if p][:depth]
        current = tree
        for part in parts[:-1]:
            if part not in current:
                current[part] = {"_count": 0, "_children": {}}
            current[part]["_count"] += row.event_count
            current = current[part]["_children"]
        # Leaf level
        if parts:
            leaf = parts[-1]
            if leaf not in current:
                current[leaf] = {"_count": 0, "_children": {}}
            current[leaf]["_count"] += row.event_count

    def _build_nodes(subtree: dict, prefix: str) -> list[FolderNode]:
        nodes = []
        for name, data in subtree.items():
            path = f"{prefix}/{name}" if prefix else name
            children = _build_nodes(data.get("_children", {}), path)
            nodes.append(FolderNode(
                path=path,
                name=name,
                event_count=data["_count"],
                children=children,
            ))
        nodes.sort(key=lambda n: n.event_count, reverse=True)
        return nodes

    return _build_nodes(tree, "")


# ── Retention settings ──────────────────────────────────────────────

# Per-tenant retention overrides keyed by tenant_id.
# Falls back to global config defaults when no override exists.
# Production deployments should persist these in the database.
_tenant_retention_overrides: dict[UUID, RetentionSettings] = {}


def _get_tenant_retention(tenant_id: UUID) -> RetentionSettings:
    """Return retention settings for a tenant, falling back to global config defaults."""
    if tenant_id in _tenant_retention_overrides:
        return _tenant_retention_overrides[tenant_id]
    from openlabels.server.config import get_settings
    settings = get_settings().monitoring
    return RetentionSettings(
        retention_days=getattr(settings, "retention_days", 90),
        archive_enabled=getattr(settings, "archive_enabled", False),
        archive_format=getattr(settings, "archive_format", "parquet"),
    )


@router.get("/retention", response_model=RetentionSettings)
async def get_retention_settings(
    _user=Depends(require_admin),
) -> RetentionSettings:
    """Get current event retention settings for the tenant.

    Returns the configured retention policy for file access events.
    """
    return _get_tenant_retention(_user.tenant_id)


@router.put("/retention", response_model=RetentionSettings)
async def update_retention_settings(
    body: RetentionSettings,
    _user=Depends(require_admin),
) -> RetentionSettings:
    """Update event retention settings for the current tenant.

    Note: Settings are applied on the next purge cycle.
    """
    # Persist per-tenant override in memory for current process;
    # production deployments should store in the database.
    _tenant_retention_overrides[_user.tenant_id] = body
    return body


@router.post("/retention/purge", response_model=RetentionPurgeResponse)
async def purge_old_events(
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
) -> RetentionPurgeResponse:
    """Purge file access events older than the retention period.

    Removes events beyond the configured retention window.
    """
    retention_days = _get_tenant_retention(user.tenant_id).retention_days
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    # Count events to purge
    count_result = await session.execute(
        select(func.count(FileAccessEvent.id)).where(
            FileAccessEvent.tenant_id == user.tenant_id,
            FileAccessEvent.event_time < cutoff,
        )
    )
    purge_count = count_result.scalar() or 0

    if purge_count > 0:
        from sqlalchemy import delete
        await session.execute(
            delete(FileAccessEvent).where(
                FileAccessEvent.tenant_id == user.tenant_id,
                FileAccessEvent.event_time < cutoff,
            )
        )
        await session.commit()

    return RetentionPurgeResponse(
        purged_count=purge_count,
        cutoff_date=cutoff.strftime("%Y-%m-%d"),
        archived=False,
    )


# ── Alert rules ─────────────────────────────────────────────────────

@router.post("/alert-rules", response_model=AlertRuleResponse, status_code=201)
async def create_alert_rule(
    body: AlertRuleCreateRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
) -> AlertRuleResponse:
    """Create a new alert rule for suspicious file access patterns."""
    if body.rule_type not in VALID_RULE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid rule_type. Must be one of: {', '.join(sorted(VALID_RULE_TYPES))}",
        )
    if body.severity not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}",
        )

    rule = AlertRule(
        id=generate_uuid(),
        tenant_id=user.tenant_id,
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        rule_type=body.rule_type,
        conditions=body.conditions,
        severity=body.severity,
        actions=body.actions,
        created_by=user.id,
    )
    session.add(rule)
    await session.commit()
    await session.refresh(rule)
    return AlertRuleResponse.model_validate(rule)


@router.get("/alert-rules", response_model=list[AlertRuleResponse])
async def list_alert_rules(
    rule_type: str | None = Query(None, description="Filter by rule type"),
    enabled: bool | None = Query(None, description="Filter by enabled status"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
) -> list[AlertRuleResponse]:
    """List alert rules for the current tenant."""
    query = select(AlertRule).where(AlertRule.tenant_id == user.tenant_id)
    if rule_type:
        query = query.where(AlertRule.rule_type == rule_type)
    if enabled is not None:
        query = query.where(AlertRule.enabled == enabled)
    query = query.order_by(AlertRule.created_at.desc())

    result = await session.execute(query)
    rules = result.scalars().all()
    return [AlertRuleResponse.model_validate(r) for r in rules]


@router.get("/alert-rules/{rule_id}", response_model=AlertRuleResponse)
async def get_alert_rule(
    rule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
) -> AlertRuleResponse:
    """Get an alert rule by ID."""
    rule = await get_or_404(session, AlertRule, rule_id, tenant_id=user.tenant_id)
    return AlertRuleResponse.model_validate(rule)


@router.put("/alert-rules/{rule_id}", response_model=AlertRuleResponse)
async def update_alert_rule(
    rule_id: UUID,
    body: AlertRuleUpdateRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
) -> AlertRuleResponse:
    """Update an alert rule."""
    rule = await get_or_404(session, AlertRule, rule_id, tenant_id=user.tenant_id)

    if body.name is not None:
        rule.name = body.name
    if body.description is not None:
        rule.description = body.description
    if body.enabled is not None:
        rule.enabled = body.enabled
    if body.conditions is not None:
        rule.conditions = body.conditions
    if body.severity is not None:
        if body.severity not in VALID_SEVERITIES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}",
            )
        rule.severity = body.severity
    if body.actions is not None:
        rule.actions = body.actions

    await session.commit()
    await session.refresh(rule)
    return AlertRuleResponse.model_validate(rule)


@router.delete("/alert-rules/{rule_id}", status_code=204)
async def delete_alert_rule(
    rule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
) -> None:
    """Delete an alert rule."""
    rule = await get_or_404(session, AlertRule, rule_id, tenant_id=user.tenant_id)
    await session.delete(rule)
    await session.commit()


# ── Remote monitoring (WinRM) endpoints ─────────────────────────────

class RemoteTestRequest(BaseModel):
    """Request to test WinRM connectivity to a remote host."""
    host: str = Field(..., description="Target hostname or IP")
    username: str = Field(..., description="Account with audit privileges")
    password: str = Field(..., description="Password")
    use_ssl: bool = Field(True, description="Use HTTPS (port 5986). Disable only for isolated test environments.")


class RemoteTestResponse(BaseModel):
    """Result of WinRM connectivity test."""
    success: bool
    message: str
    hostname: str | None = None
    os: str | None = None
    has_audit_privilege: bool | None = None
    audit_policy_enabled: bool | None = None
    error: str | None = None


class RemoteConfigureRequest(BaseModel):
    """Request to configure audit policy on a remote file server."""
    host: str = Field(..., description="Target hostname or IP")
    username: str = Field(..., description="Account with audit privileges")
    password: str = Field(..., description="Password")
    share_paths: list[str] = Field(..., description="Local paths on the server to audit")
    use_ssl: bool = Field(True, description="Use HTTPS (port 5986). Disable only for isolated test environments.")


class RemoteConfigureResponse(BaseModel):
    """Result of remote audit configuration."""
    success: bool
    message: str
    paths: list[dict] | None = None
    error: str | None = None


@router.post("/remote/test", response_model=RemoteTestResponse)
async def test_remote_connection(
    body: RemoteTestRequest,
    _user=Depends(require_admin),
) -> RemoteTestResponse:
    """Test WinRM connectivity to a remote Windows file server.

    Verifies the account has SeSecurityPrivilege (required for SACL
    management) and checks whether the audit policy for File System
    access is already enabled.
    """
    from openlabels.monitoring.winrm_remote import test_connection

    result = await test_connection(
        host=body.host,
        username=body.username,
        password=body.password,
        use_ssl=body.use_ssl,
    )

    data = result.data or {}
    return RemoteTestResponse(
        success=result.success,
        message=result.message,
        hostname=data.get("hostname"),
        os=data.get("os"),
        has_audit_privilege=data.get("has_audit_privilege"),
        audit_policy_enabled=data.get("audit_policy_enabled"),
        error=result.error,
    )


@router.post("/remote/configure", response_model=RemoteConfigureResponse)
async def configure_remote_audit(
    body: RemoteConfigureRequest,
    _user=Depends(require_admin),
) -> RemoteConfigureResponse:
    """Configure SACL audit rules on a remote Windows file server via WinRM.

    Enables the "Audit object access → File System" audit policy and adds
    SACL entries (Everyone → Read, Write → Success, Failure) on each
    specified share path.
    """
    from openlabels.monitoring.winrm_remote import configure_audit_policy

    result = await configure_audit_policy(
        host=body.host,
        username=body.username,
        password=body.password,
        share_paths=body.share_paths,
        use_ssl=body.use_ssl,
    )

    data = result.data or {}
    return RemoteConfigureResponse(
        success=result.success,
        message=result.message,
        paths=data.get("paths"),
        error=result.error,
    )


# ── Windows Event Forwarding (WEF) endpoints ────────────────────────

class WEFSubscriptionResponse(BaseModel):
    """WEF subscription status."""
    name: str
    enabled: bool
    source_count: int
    delivery_mode: str
    status: str
    error: str | None = None


class WEFSetupResponse(BaseModel):
    """Result of WEF setup operation."""
    success: bool
    message: str
    gpo_config: str | None = None


class WEFCreateRequest(BaseModel):
    """Request to create a WEF subscription."""
    subscription_name: str = Field(
        "OpenLabels-FileAccess",
        description="Subscription identifier",
        pattern=r'^[\w\-]+$',
    )
    transport: Literal["HTTP", "HTTPS"] = Field("HTTP", description="Transport: HTTP or HTTPS")


@router.post("/wef/init", response_model=WEFSetupResponse)
async def init_wef_collector(
    _user=Depends(require_admin),
) -> WEFSetupResponse:
    """Initialize the Windows Event Collector service.

    Must be run once before creating subscriptions.  Equivalent to
    ``wecutil qc`` — enables and starts the WEC service.
    """
    from openlabels.monitoring.wef_setup import init_collector

    success, message = await init_collector()
    return WEFSetupResponse(success=success, message=message)


@router.post("/wef/subscriptions", response_model=WEFSetupResponse)
async def create_wef_subscription(
    body: WEFCreateRequest,
    _user=Depends(require_admin),
) -> WEFSetupResponse:
    """Create a WEF source-initiated subscription for file access events.

    After creating the subscription, deploy the GPO config returned in
    ``gpo_config`` to your file servers so they start pushing events
    to this collector.
    """
    from openlabels.monitoring.wef_setup import create_subscription, get_gpo_config
    from openlabels.server.config import get_settings

    settings = get_settings()

    success, message = await create_subscription(
        subscription_name=body.subscription_name,
        transport=body.transport,
    )

    gpo = None
    if success:
        fqdn = settings.monitoring.wef_collector_fqdn
        if not fqdn:
            import socket
            fqdn = socket.getfqdn()
        gpo = get_gpo_config(
            collector_fqdn=fqdn,
            use_https=body.transport.upper() == "HTTPS",
        )

    return WEFSetupResponse(success=success, message=message, gpo_config=gpo)


@router.get("/wef/subscriptions", response_model=list[WEFSubscriptionResponse])
async def list_wef_subscriptions(
    _user=Depends(require_admin),
) -> list[WEFSubscriptionResponse]:
    """List all WEF subscriptions and their status."""
    from openlabels.monitoring.wef_setup import get_subscription_status, list_subscriptions

    names = await list_subscriptions()
    results = []
    for name in names:
        info = await get_subscription_status(name)
        results.append(WEFSubscriptionResponse(
            name=info.name,
            enabled=info.enabled,
            source_count=info.source_count,
            delivery_mode=info.delivery_mode,
            status=info.status,
            error=info.error,
        ))
    return results


@router.get("/wef/subscriptions/{name}", response_model=WEFSubscriptionResponse)
async def get_wef_subscription(
    name: str,
    _user=Depends(require_admin),
) -> WEFSubscriptionResponse:
    """Get status of a specific WEF subscription."""
    from openlabels.monitoring.wef_setup import get_subscription_status

    info = await get_subscription_status(name)
    return WEFSubscriptionResponse(
        name=info.name,
        enabled=info.enabled,
        source_count=info.source_count,
        delivery_mode=info.delivery_mode,
        status=info.status,
        error=info.error,
    )


@router.delete("/wef/subscriptions/{name}", response_model=WEFSetupResponse)
async def delete_wef_subscription(
    name: str,
    _user=Depends(require_admin),
) -> WEFSetupResponse:
    """Delete a WEF subscription."""
    from openlabels.monitoring.wef_setup import delete_subscription

    success, message = await delete_subscription(name)
    return WEFSetupResponse(success=success, message=message)


@router.get("/wef/gpo-config")
async def get_wef_gpo_config(
    _user=Depends(require_admin),
) -> dict:
    """Get the GPO configuration string to deploy to file servers.

    Paste this value into:
    Computer Configuration > Policies > Administrative Templates >
    Windows Components > Event Forwarding > Configure target
    Subscription Manager
    """
    from openlabels.monitoring.wef_setup import get_gpo_config
    from openlabels.server.config import get_settings

    settings = get_settings()
    fqdn = settings.monitoring.wef_collector_fqdn
    if not fqdn:
        import socket
        fqdn = socket.getfqdn()

    return {
        "gpo_path": (
            "Computer Configuration > Policies > Administrative Templates > "
            "Windows Components > Event Forwarding > Configure target Subscription Manager"
        ),
        "value": get_gpo_config(
            collector_fqdn=fqdn,
            use_https=settings.monitoring.wef_use_https,
        ),
    }


# ── Service identity / gMSA endpoints ───────────────────────────────

class ServiceIdentityResponse(BaseModel):
    """Current process identity information."""
    account_name: str
    domain: str | None = None
    is_gmsa: bool
    is_local_system: bool
    is_network_service: bool
    sid: str | None = None


class GmsaSetupScriptRequest(BaseModel):
    """Parameters for generating a gMSA setup script."""
    account_name: str = Field("svc-openlabels", pattern=r'^[\w\-]+$')
    server_group: str = Field("OpenLabels-Servers", pattern=r'^[\w\- ]+$')
    domain: str = Field("", description="Domain DNS name (blank = auto-detect)")


class AuditPolicyScriptRequest(BaseModel):
    """Parameters for generating an audit policy GPO script."""
    share_paths: list[str] = Field(default_factory=list, description="File share paths to audit")


@router.get("/identity", response_model=ServiceIdentityResponse)
async def get_service_identity(
    _user=Depends(require_admin),
) -> ServiceIdentityResponse:
    """Detect the Windows account running the OpenLabels process.

    Returns whether the service is running as a gMSA, Local System,
    Network Service, or a regular account.  Useful for the setup wizard
    to guide admins toward the recommended gMSA configuration.
    """
    from openlabels.monitoring.gmsa import detect_service_identity

    identity = detect_service_identity()
    return ServiceIdentityResponse(
        account_name=identity.account_name,
        domain=identity.domain,
        is_gmsa=identity.is_gmsa,
        is_local_system=identity.is_local_system,
        is_network_service=identity.is_network_service,
        sid=identity.sid,
    )


@router.post("/gmsa/setup-script")
async def generate_gmsa_script(
    body: GmsaSetupScriptRequest,
    _user=Depends(require_admin),
) -> dict:
    """Generate a PowerShell script to create a gMSA for OpenLabels.

    The admin copies this script and runs it on a Domain Controller
    (or any machine with the AD PowerShell module).
    """
    from openlabels.monitoring.gmsa import generate_gmsa_setup_script

    script = generate_gmsa_setup_script(
        account_name=body.account_name,
        server_group=body.server_group,
        domain=body.domain,
    )
    return {"script": script}


@router.post("/audit-policy/script")
async def generate_audit_policy_script(
    body: AuditPolicyScriptRequest,
    _user=Depends(require_admin),
) -> dict:
    """Generate a PowerShell script to configure file access audit policy.

    Enables 'Audit File System' and sets SACLs on the specified share
    paths.  Deploy via GPO startup script or run directly on file servers.
    """
    from openlabels.monitoring.gmsa import generate_audit_gpo_script

    script = generate_audit_gpo_script(share_paths=body.share_paths or None)
    return {"script": script}
