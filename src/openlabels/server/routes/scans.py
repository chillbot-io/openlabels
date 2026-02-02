"""
Scan management API endpoints.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import ScanJob, ScanTarget
from openlabels.auth.dependencies import get_current_user, require_admin
from openlabels.jobs import JobQueue

router = APIRouter()


class ScanCreate(BaseModel):
    """Request to create a new scan."""

    target_id: UUID
    name: Optional[str] = None


class ScanResponse(BaseModel):
    """Scan job response."""

    id: UUID
    target_id: UUID
    name: Optional[str]
    status: str
    progress: Optional[dict] = None
    files_scanned: int = 0
    files_with_pii: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Paginated list of scans."""

    items: list[ScanResponse]
    total: int
    page: int
    pages: int


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    request: ScanCreate,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Create a new scan job."""
    # Verify target exists
    target = await session.get(ScanTarget, request.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Create scan job
    job = ScanJob(
        tenant_id=user.tenant_id,
        target_id=request.target_id,
        name=request.name or f"Scan: {target.name}",
        status="pending",
        created_by=user.id,
    )
    session.add(job)
    await session.flush()

    # Enqueue the job in the job queue
    queue = JobQueue(session, user.tenant_id)
    await queue.enqueue(
        task_type="scan",
        payload={"job_id": str(job.id)},
        priority=50,
    )

    return job


@router.get("", response_model=ScanListResponse)
async def list_scans(
    status: Optional[str] = Query(None, description="Filter by status"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """List scan jobs."""
    query = select(ScanJob).where(ScanJob.tenant_id == user.tenant_id)

    if status:
        query = query.where(ScanJob.status == status)

    query = query.order_by(ScanJob.created_at.desc())

    # Count total
    count_query = select(ScanJob.id).where(ScanJob.tenant_id == user.tenant_id)
    if status:
        count_query = count_query.where(ScanJob.status == status)
    result = await session.execute(count_query)
    total = len(result.all())

    # Paginate
    query = query.offset((page - 1) * limit).limit(limit)
    result = await session.execute(query)
    jobs = result.scalars().all()

    return ScanListResponse(
        items=[ScanResponse.model_validate(j) for j in jobs],
        total=total,
        page=page,
        pages=(total + limit - 1) // limit,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """Get scan job details."""
    job = await session.get(ScanJob, scan_id)
    if not job or job.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return job


@router.delete("/{scan_id}", status_code=204)
async def cancel_scan(
    scan_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Cancel a running scan."""
    job = await session.get(ScanJob, scan_id)
    if not job or job.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    if job.status not in ("pending", "running"):
        raise HTTPException(status_code=400, detail="Scan cannot be cancelled")

    job.status = "cancelled"
    job.completed_at = datetime.utcnow()
    await session.flush()

    # Note: The queue job will still execute, but the scan task checks
    # job.status before processing and will exit early if cancelled.
