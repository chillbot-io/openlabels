"""
Scan schedule management API endpoints.
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session

logger = logging.getLogger(__name__)
from openlabels.server.models import ScanSchedule, ScanTarget, ScanJob
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    paginate_query,
)
from openlabels.server.exceptions import NotFoundError
from openlabels.auth.dependencies import get_current_user, require_admin, CurrentUser
from openlabels.jobs import JobQueue, parse_cron_expression

router = APIRouter()


class ScheduleCreate(BaseModel):
    """Request to create a scan schedule."""

    name: str = Field(max_length=255)
    target_id: UUID
    cron: Optional[str] = None  # Cron expression, None = on-demand only


class ScheduleUpdate(BaseModel):
    """Request to update a scan schedule."""

    name: Optional[str] = Field(default=None, max_length=255)
    cron: Optional[str] = None
    enabled: Optional[bool] = None


class ScheduleResponse(BaseModel):
    """Scan schedule response."""

    id: UUID
    name: str
    target_id: UUID
    cron: Optional[str]
    enabled: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]

    class Config:
        from_attributes = True


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

    result = await paginate_query(
        session,
        query,
        pagination,
        transformer=lambda s: ScheduleResponse.model_validate(s),
    )

    return PaginatedResponse[ScheduleResponse](**result)


@router.post("", response_model=ScheduleResponse, status_code=201)
async def create_schedule(
    request: ScheduleCreate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> ScheduleResponse:
    """Create a new scan schedule."""
    # Verify target exists
    target = await session.get(ScanTarget, request.target_id)
    if not target or target.tenant_id != user.tenant_id:
        raise NotFoundError(
            message="Target not found",
            resource_type="ScanTarget",
            resource_id=str(request.target_id),
        )

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

        # Refresh to load server-generated defaults and ensure proper types
        await session.refresh(schedule)

        return schedule
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error creating schedule: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred")


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(
    schedule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ScheduleResponse:
    """Get schedule details."""
    schedule = await session.get(ScanSchedule, schedule_id)
    if not schedule or schedule.tenant_id != user.tenant_id:
        raise NotFoundError(
            message="Schedule not found",
            resource_type="ScanSchedule",
            resource_id=str(schedule_id),
        )
    return schedule


@router.put("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: UUID,
    request: ScheduleUpdate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> ScheduleResponse:
    """Update a scan schedule."""
    schedule = await session.get(ScanSchedule, schedule_id)
    if not schedule or schedule.tenant_id != user.tenant_id:
        raise NotFoundError(
            message="Schedule not found",
            resource_type="ScanSchedule",
            resource_id=str(schedule_id),
        )

    if request.name is not None:
        schedule.name = request.name
    if request.cron is not None:
        schedule.cron = request.cron
        # Recalculate next run time
        schedule.next_run_at = parse_cron_expression(request.cron)
    if request.enabled is not None:
        schedule.enabled = request.enabled

    return schedule


@router.delete("/{schedule_id}")
async def delete_schedule(
    schedule_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Delete a scan schedule."""
    schedule = await session.get(ScanSchedule, schedule_id)
    if not schedule or schedule.tenant_id != user.tenant_id:
        raise NotFoundError(
            message="Schedule not found",
            resource_type="ScanSchedule",
            resource_id=str(schedule_id),
        )

    schedule_name = schedule.name
    await session.delete(schedule)
    await session.flush()

    # Check if this is an HTMX request
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="",
            status_code=200,
            headers={
                "HX-Trigger": f'{{"notify": {{"message": "Schedule \\"{schedule_name}\\" deleted", "type": "success"}}, "refreshSchedules": true}}',
            },
        )

    # Regular REST response
    return Response(status_code=204)


@router.post("/{schedule_id}/run", status_code=202)
async def trigger_schedule(
    schedule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> dict:
    """Trigger an immediate run of a schedule."""
    schedule = await session.get(ScanSchedule, schedule_id)
    if not schedule or schedule.tenant_id != user.tenant_id:
        raise NotFoundError(
            message="Schedule not found",
            resource_type="ScanSchedule",
            resource_id=str(schedule_id),
        )

    # Create scan job
    target = await session.get(ScanTarget, schedule.target_id)
    job = ScanJob(
        tenant_id=user.tenant_id,
        target_id=schedule.target_id,
        name=f"{schedule.name} (manual trigger)",
        status="pending",
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

    # Update last run time
    schedule.last_run_at = datetime.now(timezone.utc)

    return {
        "message": "Scan triggered",
        "schedule_id": str(schedule_id),
        "job_id": str(job.id),
    }
