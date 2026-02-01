"""
Scan schedule management API endpoints.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import ScanSchedule, ScanTarget
from openlabels.auth.dependencies import get_current_user, require_admin

router = APIRouter()


class ScheduleCreate(BaseModel):
    """Request to create a scan schedule."""

    name: str
    target_id: UUID
    cron: Optional[str] = None  # Cron expression, None = on-demand only


class ScheduleUpdate(BaseModel):
    """Request to update a scan schedule."""

    name: Optional[str] = None
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


@router.get("", response_model=list[ScheduleResponse])
async def list_schedules(
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """List configured scan schedules."""
    query = select(ScanSchedule).where(ScanSchedule.tenant_id == user.tenant_id)
    result = await session.execute(query)
    schedules = result.scalars().all()
    return [ScheduleResponse.model_validate(s) for s in schedules]


@router.post("", response_model=ScheduleResponse, status_code=201)
async def create_schedule(
    request: ScheduleCreate,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Create a new scan schedule."""
    # Verify target exists
    target = await session.get(ScanTarget, request.target_id)
    if not target or target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Target not found")

    schedule = ScanSchedule(
        tenant_id=user.tenant_id,
        name=request.name,
        target_id=request.target_id,
        cron=request.cron,
        created_by=user.id,
    )

    # Calculate next run time if cron is set
    if request.cron:
        # TODO: Calculate next run from cron expression
        pass

    session.add(schedule)
    await session.flush()
    return schedule


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(
    schedule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """Get schedule details."""
    schedule = await session.get(ScanSchedule, schedule_id)
    if not schedule or schedule.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return schedule


@router.put("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: UUID,
    request: ScheduleUpdate,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Update a scan schedule."""
    schedule = await session.get(ScanSchedule, schedule_id)
    if not schedule or schedule.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if request.name is not None:
        schedule.name = request.name
    if request.cron is not None:
        schedule.cron = request.cron
        # TODO: Recalculate next run time
    if request.enabled is not None:
        schedule.enabled = request.enabled

    return schedule


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Delete a scan schedule."""
    schedule = await session.get(ScanSchedule, schedule_id)
    if not schedule or schedule.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Schedule not found")

    await session.delete(schedule)


@router.post("/{schedule_id}/run", status_code=202)
async def trigger_schedule(
    schedule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Trigger an immediate run of a schedule."""
    schedule = await session.get(ScanSchedule, schedule_id)
    if not schedule or schedule.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # TODO: Create and enqueue scan job
    return {"message": "Scan triggered", "schedule_id": schedule_id}
