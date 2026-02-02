"""
Job queue management API endpoints.

Provides access to queue statistics and dead letter queue management.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.jobs.queue import JobQueue
from openlabels.auth.dependencies import get_current_user, require_admin

router = APIRouter()


class JobResponse(BaseModel):
    """Job details response."""

    id: UUID
    task_type: str
    payload: dict
    priority: int
    status: str
    scheduled_for: Optional[datetime]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    worker_id: Optional[str]
    result: Optional[dict]
    error: Optional[str]
    retry_count: int
    max_retries: int
    created_at: datetime

    class Config:
        from_attributes = True


class QueueStatsResponse(BaseModel):
    """Queue statistics response."""

    pending: int
    running: int
    completed: int
    failed: int
    cancelled: int
    failed_by_type: dict[str, int]


class PaginatedJobsResponse(BaseModel):
    """Paginated list of jobs."""

    items: list[JobResponse]
    total: int
    page: int
    page_size: int


class RequeueRequest(BaseModel):
    """Request to requeue a failed job."""

    reset_retries: bool = True


class RequeueAllRequest(BaseModel):
    """Request to requeue all failed jobs."""

    task_type: Optional[str] = None
    reset_retries: bool = True


class PurgeRequest(BaseModel):
    """Request to purge failed jobs."""

    task_type: Optional[str] = None
    older_than_days: Optional[int] = None


@router.get("/stats", response_model=QueueStatsResponse)
async def get_queue_stats(
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get job queue statistics.

    Returns counts of jobs by status and failed jobs by task type.
    """
    queue = JobQueue(session, user.tenant_id)
    stats = await queue.get_queue_stats()
    return QueueStatsResponse(**stats)


@router.get("/failed", response_model=PaginatedJobsResponse)
async def list_failed_jobs(
    task_type: Optional[str] = Query(None, description="Filter by task type"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    List failed jobs (dead letter queue).

    Admin access required.
    """
    queue = JobQueue(session, user.tenant_id)

    # Get total count
    total = await queue.get_failed_count(task_type)

    # Get paginated results
    offset = (page - 1) * page_size
    jobs = await queue.get_failed_jobs(task_type, limit=page_size, offset=offset)

    return PaginatedJobsResponse(
        items=[JobResponse.model_validate(job) for job in jobs],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """Get job details."""
    queue = JobQueue(session, user.tenant_id)
    job = await queue.get_job(job_id)

    if not job or job.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Job not found")

    return JobResponse.model_validate(job)


@router.post("/{job_id}/requeue")
async def requeue_job(
    job_id: UUID,
    request: RequeueRequest = RequeueRequest(),
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    Requeue a failed job from the dead letter queue.

    Admin access required.
    """
    queue = JobQueue(session, user.tenant_id)
    success = await queue.requeue_failed(job_id, reset_retries=request.reset_retries)

    if not success:
        raise HTTPException(
            status_code=404,
            detail="Job not found or not in failed status",
        )

    return {"message": "Job requeued successfully", "job_id": str(job_id)}


@router.post("/requeue-all")
async def requeue_all_failed(
    request: RequeueAllRequest = RequeueAllRequest(),
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    Requeue all failed jobs.

    Admin access required. Use with caution in production.
    """
    queue = JobQueue(session, user.tenant_id)
    count = await queue.requeue_all_failed(
        task_type=request.task_type,
        reset_retries=request.reset_retries,
    )

    return {"message": f"Requeued {count} failed jobs", "count": count}


@router.post("/purge")
async def purge_failed_jobs(
    request: PurgeRequest = PurgeRequest(),
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    Delete failed jobs from the dead letter queue.

    Admin access required. Use with caution - this action is irreversible.
    """
    queue = JobQueue(session, user.tenant_id)
    count = await queue.purge_failed(
        task_type=request.task_type,
        older_than_days=request.older_than_days,
    )

    return {"message": f"Purged {count} failed jobs", "count": count}


@router.post("/{job_id}/cancel")
async def cancel_job(
    job_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    Cancel a pending or running job.

    Admin access required.
    """
    queue = JobQueue(session, user.tenant_id)
    success = await queue.cancel(job_id)

    if not success:
        raise HTTPException(
            status_code=400,
            detail="Job not found or not in cancellable status",
        )

    return {"message": "Job cancelled successfully", "job_id": str(job_id)}
