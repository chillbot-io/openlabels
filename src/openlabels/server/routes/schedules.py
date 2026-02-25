"""
Scan schedule management API endpoints (Story 9).

Provides:
- CRUD for scan schedules with cron expressions
- Cron validation with human-readable preview
- Enable / disable toggle
- Bulk 'Schedule All Targets' action
- Manual trigger for immediate execution
- Schedule execution history
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import CurrentUser, get_current_user, require_admin
from openlabels.core.types import JobStatus
from openlabels.jobs import (
    JobQueue,
    get_cron_description,
    parse_cron_expression,
    validate_cron_expression,
)
from openlabels.server.db import get_session
from openlabels.server.models import ScanJob, ScanSchedule, ScanTarget
from openlabels.server.routes import audit_log, get_or_404
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    paginate_query,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ScheduleCreate(BaseModel):
    """Request to create a scan schedule."""

    name: str = Field(max_length=255)
    target_id: UUID
    cron: str | None = None  # Cron expression, None = on-demand only


class BulkScheduleCreate(BaseModel):
    """Create schedules for all enabled targets with a shared cron expression."""

    cron: str = Field(..., description="Cron expression for all schedules")
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    """Request to update a scan schedule."""

    name: str | None = Field(default=None, max_length=255)
    cron: str | None = None
    target_id: UUID | None = None
    enabled: bool | None = None


class ScheduleToggle(BaseModel):
    """Request to enable/disable a schedule."""

    enabled: bool


class ScheduleResponse(BaseModel):
    """Scan schedule response."""

    id: UUID
    name: str
    target_id: UUID
    target_name: str | None = None
    cron: str | None
    cron_description: str | None = None
    enabled: bool
    last_run_at: datetime | None
    next_run_at: datetime | None
    created_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class CronValidationRequest(BaseModel):
    """Request to validate a cron expression."""

    cron: str


class CronValidationResponse(BaseModel):
    """Cron validation result."""

    valid: bool
    cron: str
    description: str | None = None
    next_runs: list[datetime] = Field(default_factory=list)
    error: str | None = None


class JobHistoryItem(BaseModel):
    """A scan job from schedule execution history."""

    id: UUID
    name: str | None
    status: str
    files_scanned: int
    files_with_pii: int
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None = None
    created_at: datetime | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _enrich_schedule(
    schedule: ScanSchedule,
    session: AsyncSession,
) -> ScheduleResponse:
    """Build a ScheduleResponse enriched with target_name and cron_description."""
    target_name = None
    try:
        result = await session.execute(
            select(ScanTarget.name).where(ScanTarget.id == schedule.target_id)
        )
        target_name = result.scalar_one_or_none()
    except Exception:
        pass

    cron_desc = None
    if schedule.cron:
        cron_desc = get_cron_description(schedule.cron)

    created_at = None
    try:
        created_at = schedule.created_at
    except Exception:
        pass

    return ScheduleResponse(
        id=schedule.id,
        name=schedule.name,
        target_id=schedule.target_id,
        target_name=target_name,
        cron=schedule.cron,
        cron_description=cron_desc,
        enabled=schedule.enabled,
        last_run_at=schedule.last_run_at,
        next_run_at=schedule.next_run_at,
        created_at=created_at,
    )


# ---------------------------------------------------------------------------
# Cron validation
# ---------------------------------------------------------------------------

@router.post("/validate-cron", response_model=CronValidationResponse)
async def validate_cron(
    request: CronValidationRequest,
    _user: CurrentUser = Depends(get_current_user),
) -> CronValidationResponse:
    """Validate a cron expression and return a human-readable preview.

    Returns the next 5 scheduled run times if the expression is valid.
    """
    is_valid = validate_cron_expression(request.cron)

    if not is_valid:
        return CronValidationResponse(
            valid=False,
            cron=request.cron,
            error="Invalid cron expression. Expected 5 fields: minute hour day month weekday",
        )

    description = get_cron_description(request.cron)

    # Calculate next 5 run times
    from croniter import croniter

    next_runs: list[datetime] = []
    try:
        cron = croniter(request.cron, datetime.now(timezone.utc))
        for _ in range(5):
            next_runs.append(cron.get_next(datetime))
    except Exception:
        pass

    return CronValidationResponse(
        valid=True,
        cron=request.cron,
        description=description,
        next_runs=next_runs,
    )


# ---------------------------------------------------------------------------
# Bulk scheduling
# ---------------------------------------------------------------------------

@router.post("/bulk", response_model=list[ScheduleResponse], status_code=201)
async def create_bulk_schedules(
    request: BulkScheduleCreate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> list[ScheduleResponse]:
    """Create scan schedules for all enabled targets.

    Skips targets that already have a schedule with the same cron expression.
    Used by the "Schedule All Targets" action in the UI.
    """
    # Validate cron first
    if not validate_cron_expression(request.cron):
        raise HTTPException(status_code=400, detail="Invalid cron expression")

    # Get all enabled targets for this tenant
    targets_result = await session.execute(
        select(ScanTarget)
        .where(ScanTarget.tenant_id == user.tenant_id, ScanTarget.enabled.is_(True))
        .order_by(ScanTarget.name)
    )
    targets = targets_result.scalars().all()

    if not targets:
        raise HTTPException(status_code=400, detail="No enabled targets found")

    # Get existing schedules to avoid duplicates
    existing_result = await session.execute(
        select(ScanSchedule.target_id, ScanSchedule.cron)
        .where(ScanSchedule.tenant_id == user.tenant_id)
    )
    existing_pairs = {(row[0], row[1]) for row in existing_result.all()}

    created = []
    for target in targets:
        # Skip if this target already has a schedule with the same cron
        if (target.id, request.cron) in existing_pairs:
            logger.info("Skipping target %s — schedule with cron %r already exists", target.name, request.cron)
            continue

        schedule = ScanSchedule(
            tenant_id=user.tenant_id,
            name=f"{target.name} — Scheduled",
            target_id=target.id,
            cron=request.cron,
            enabled=request.enabled,
            created_by=user.id,
        )

        if request.cron:
            schedule.next_run_at = parse_cron_expression(request.cron)

        session.add(schedule)
        created.append(schedule)

    if created:
        await session.flush()

        audit_log(
            session, tenant_id=user.tenant_id, user_id=user.id,
            action="schedule_created", resource_type="scan_schedule",
            resource_id=created[0].id,
            details={
                "count": len(created),
                "cron": request.cron,
                "target_ids": [str(s.target_id) for s in created],
            },
        )

        # Refresh all to load server-generated defaults
        for schedule in created:
            await session.refresh(schedule)

    return [await _enrich_schedule(s, session) for s in created]


# ---------------------------------------------------------------------------
# CRUD endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=PaginatedResponse[ScheduleResponse])
async def list_schedules(
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> PaginatedResponse[ScheduleResponse]:
    """List configured scan schedules with pagination."""
    query = (
        select(ScanSchedule)
        .where(ScanSchedule.tenant_id == user.tenant_id)
        .order_by(ScanSchedule.created_at.desc())
    )

    # Use manual pagination to enrich with target_name
    from sqlalchemy import func as sa_func

    count_query = select(sa_func.count()).select_from(query.subquery())
    count_result = await session.execute(count_query)
    total = count_result.scalar() or 0

    total_pages = (total + pagination.page_size - 1) // pagination.page_size if total > 0 else 1

    paginated_query = query.offset(pagination.offset).limit(pagination.limit)
    result = await session.execute(paginated_query)
    schedules = result.scalars().all()

    items = [await _enrich_schedule(s, session) for s in schedules]

    return PaginatedResponse[ScheduleResponse](
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=total_pages,
        has_next=pagination.page < total_pages,
        has_previous=pagination.page > 1,
    )


@router.post("", response_model=ScheduleResponse, status_code=201)
async def create_schedule(
    request: ScheduleCreate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> ScheduleResponse:
    """Create a new scan schedule."""
    await get_or_404(session, ScanTarget, request.target_id, tenant_id=user.tenant_id)

    # Validate cron expression if provided
    if request.cron and not validate_cron_expression(request.cron):
        raise HTTPException(status_code=400, detail="Invalid cron expression")

    try:
        schedule = ScanSchedule(
            tenant_id=user.tenant_id,
            name=request.name,
            target_id=request.target_id,
            cron=request.cron,
            enabled=True,  # Explicitly set default to ensure it's available before flush
            created_by=user.id,
        )

        # Calculate next run time if cron is set
        if request.cron:
            schedule.next_run_at = parse_cron_expression(request.cron)

        session.add(schedule)
        await session.flush()

        audit_log(
            session, tenant_id=user.tenant_id, user_id=user.id,
            action="schedule_created", resource_type="scan_schedule", resource_id=schedule.id,
            details={"name": request.name, "cron": request.cron, "target_id": str(request.target_id)},
        )

        # Refresh to load server-generated defaults and ensure proper types
        await session.refresh(schedule)

        return await _enrich_schedule(schedule, session)
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error creating schedule: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred") from e


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(
    schedule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ScheduleResponse:
    """Get schedule details."""
    schedule = await get_or_404(session, ScanSchedule, schedule_id, tenant_id=user.tenant_id)
    return await _enrich_schedule(schedule, session)


@router.put("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: UUID,
    request: ScheduleUpdate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> ScheduleResponse:
    """Update a scan schedule."""
    schedule = await get_or_404(session, ScanSchedule, schedule_id, tenant_id=user.tenant_id)

    if request.name is not None:
        schedule.name = request.name
    if request.cron is not None:
        if not validate_cron_expression(request.cron):
            raise HTTPException(status_code=400, detail="Invalid cron expression")
        schedule.cron = request.cron
        # Recalculate next run time
        schedule.next_run_at = parse_cron_expression(request.cron)
    if request.target_id is not None:
        # Validate the new target belongs to the tenant
        await get_or_404(session, ScanTarget, request.target_id, tenant_id=user.tenant_id)
        schedule.target_id = request.target_id
    if request.enabled is not None:
        schedule.enabled = request.enabled

    details = {
        k: str(v) if isinstance(v, UUID) else v
        for k, v in request.model_dump(exclude_unset=True).items()
    }
    audit_log(
        session, tenant_id=user.tenant_id, user_id=user.id,
        action="schedule_updated", resource_type="scan_schedule", resource_id=schedule.id,
        details=details,
    )

    return await _enrich_schedule(schedule, session)


@router.delete("/{schedule_id}")
async def delete_schedule(
    schedule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Delete a scan schedule."""
    schedule = await get_or_404(session, ScanSchedule, schedule_id, tenant_id=user.tenant_id)

    schedule_name = schedule.name
    audit_log(
        session, tenant_id=user.tenant_id, user_id=user.id,
        action="schedule_deleted", resource_type="scan_schedule", resource_id=schedule.id,
        details={"name": schedule_name},
    )
    await session.delete(schedule)
    await session.flush()

    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Toggle enable/disable
# ---------------------------------------------------------------------------

@router.patch("/{schedule_id}/toggle", response_model=ScheduleResponse)
async def toggle_schedule(
    schedule_id: UUID,
    request: ScheduleToggle,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> ScheduleResponse:
    """Enable or disable a scan schedule."""
    schedule = await get_or_404(session, ScanSchedule, schedule_id, tenant_id=user.tenant_id)
    schedule.enabled = request.enabled

    # Recalculate next_run_at when enabling
    if request.enabled and schedule.cron:
        schedule.next_run_at = parse_cron_expression(schedule.cron)
    elif not request.enabled:
        schedule.next_run_at = None

    audit_log(
        session, tenant_id=user.tenant_id, user_id=user.id,
        action="schedule_updated", resource_type="scan_schedule", resource_id=schedule.id,
        details={"enabled": request.enabled},
    )

    return await _enrich_schedule(schedule, session)


# ---------------------------------------------------------------------------
# Manual trigger
# ---------------------------------------------------------------------------

@router.post("/{schedule_id}/run", status_code=202)
async def trigger_schedule(
    schedule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> dict:
    """Trigger an immediate run of a schedule."""
    schedule = await get_or_404(session, ScanSchedule, schedule_id, tenant_id=user.tenant_id)

    job = ScanJob(
        tenant_id=user.tenant_id,
        target_id=schedule.target_id,
        name=f"{schedule.name} (manual trigger)",
        status=JobStatus.PENDING,
        created_by=user.id,
    )
    session.add(job)
    await session.flush()

    # Enqueue the scan job
    queue = JobQueue(session, user.tenant_id)
    await queue.enqueue(
        task_type="scan",
        payload={"job_id": str(job.id)},
        priority=70,  # Higher priority for manual triggers
    )

    audit_log(
        session, tenant_id=user.tenant_id, user_id=user.id,
        action="scan_started", resource_type="scan_job", resource_id=job.id,
        details={"trigger": "manual", "schedule_id": str(schedule_id)},
    )

    # Update last run time
    schedule.last_run_at = datetime.now(timezone.utc)

    return {
        "message": "Scan triggered",
        "schedule_id": str(schedule_id),
        "job_id": str(job.id),
    }


# ---------------------------------------------------------------------------
# Execution history
# ---------------------------------------------------------------------------

@router.get("/{schedule_id}/history", response_model=PaginatedResponse[JobHistoryItem])
async def get_schedule_history(
    schedule_id: UUID,
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> PaginatedResponse[JobHistoryItem]:
    """Get execution history for a schedule.

    Returns past scan jobs ordered by most recent first.
    """
    # Verify schedule belongs to tenant
    await get_or_404(session, ScanSchedule, schedule_id, tenant_id=user.tenant_id)

    query = (
        select(ScanJob)
        .where(
            ScanJob.schedule_id == schedule_id,
            ScanJob.tenant_id == user.tenant_id,
        )
        .order_by(ScanJob.created_at.desc())
    )

    def _to_history_item(job: ScanJob) -> JobHistoryItem:
        duration = None
        if job.started_at and job.completed_at:
            duration = (job.completed_at - job.started_at).total_seconds()

        created_at = None
        try:
            created_at = job.created_at
        except Exception:
            pass

        return JobHistoryItem(
            id=job.id,
            name=job.name,
            status=job.status,
            files_scanned=job.files_scanned,
            files_with_pii=job.files_with_pii,
            started_at=job.started_at,
            completed_at=job.completed_at,
            duration_seconds=duration,
            created_at=created_at,
        )

    result = await paginate_query(
        session, query, pagination,
        transformer=_to_history_item,
    )

    return PaginatedResponse[JobHistoryItem](**result)
