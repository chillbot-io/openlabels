"""
Job queue management API endpoints.

Provides access to queue statistics and dead letter queue management.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.errors import NotFoundError, BadRequestError
from openlabels.jobs.queue import JobQueue
from openlabels.auth.dependencies import get_current_user, require_admin, CurrentUser

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
    """
    Paginated list of jobs.

    Uses standardized pagination format with consistent field naming.
    """

    items: list[JobResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_more: bool


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


@router.get("", response_model=QueueStatsResponse)
async def list_jobs(
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> QueueStatsResponse:
    """
    Get job queue statistics.

    Returns counts of jobs by status and failed jobs by task type.
    This is the default endpoint for /api/jobs.
    """
    queue = JobQueue(session, user.tenant_id)
    stats = await queue.get_queue_stats()
    return QueueStatsResponse(**stats)


@router.get("/stats", response_model=QueueStatsResponse)
async def get_queue_stats(
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> QueueStatsResponse:
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
    user: CurrentUser = Depends(require_admin),
) -> PaginatedJobsResponse:
    """
    List failed jobs (dead letter queue).

    Admin access required.

    Uses standardized pagination format with consistent field naming:
    - `items`: List of failed jobs
    - `total`: Total number of failed jobs
    - `page`: Current page number
    - `page_size`: Items per page
    - `total_pages`: Total number of pages
    - `has_more`: Whether there are more pages
    """
    queue = JobQueue(session, user.tenant_id)

    # Get total count
    total = await queue.get_failed_count(task_type)

    # Calculate pagination
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    # Get paginated results
    offset = (page - 1) * page_size
    jobs = await queue.get_failed_jobs(task_type, limit=page_size, offset=offset)

    return PaginatedJobsResponse(
        items=[JobResponse.model_validate(job) for job in jobs],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        has_more=page < total_pages,
    )


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> JobResponse:
    """Get job details."""
    queue = JobQueue(session, user.tenant_id)
    job = await queue.get_job(job_id)

    if not job or job.tenant_id != user.tenant_id:
        raise NotFoundError(
            message="Job not found",
            details={"job_id": str(job_id)}
        )

    return JobResponse.model_validate(job)


@router.post("/{job_id}/requeue")
async def requeue_job(
    job_id: UUID,
    request: RequeueRequest = RequeueRequest(),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> dict:
    """
    Requeue a failed job from the dead letter queue.

    Admin access required.
    """
    queue = JobQueue(session, user.tenant_id)
    success = await queue.requeue_failed(job_id, reset_retries=request.reset_retries)

    if not success:
        raise NotFoundError(
            message="Job not found or not in failed status",
            details={"job_id": str(job_id)}
        )

    return {"message": "Job requeued successfully", "job_id": str(job_id)}


@router.post("/requeue-all")
async def requeue_all_failed(
    request: RequeueAllRequest = RequeueAllRequest(),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> dict:
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
    user: CurrentUser = Depends(require_admin),
) -> dict:
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
    user: CurrentUser = Depends(require_admin),
) -> dict:
    """
    Cancel a pending or running job.

    Admin access required.
    """
    queue = JobQueue(session, user.tenant_id)
    success = await queue.cancel(job_id)

    if not success:
        raise BadRequestError(
            message="Job not found or not in cancellable status",
            details={"job_id": str(job_id)}
        )

    return {"message": "Job cancelled successfully", "job_id": str(job_id)}


# =============================================================================
# Worker Pool Configuration
# =============================================================================


class WorkerConfigRequest(BaseModel):
    """Request to update worker configuration."""

    concurrency: int = Query(ge=1, le=32, description="Number of concurrent workers (1-32)")


class WorkerStatusResponse(BaseModel):
    """Worker status response."""

    worker_id: Optional[str]
    status: str
    concurrency: int
    target_concurrency: int
    pid: Optional[int]


@router.get("/workers/status", response_model=WorkerStatusResponse)
async def get_worker_status(
    user: CurrentUser = Depends(require_admin),
) -> WorkerStatusResponse:
    """
    Get current worker pool status.

    Returns the current worker configuration and status.
    Admin access required.
    """
    from openlabels.jobs.worker import get_worker_state

    state = get_worker_state()

    return WorkerStatusResponse(
        worker_id=state.get("worker_id"),
        status=state.get("status", "unknown"),
        concurrency=state.get("concurrency", 0),
        target_concurrency=state.get("target_concurrency", 0),
        pid=state.get("pid"),
    )


@router.post("/workers/config")
async def update_worker_config(
    request: WorkerConfigRequest,
    user: CurrentUser = Depends(require_admin),
) -> dict:
    """
    Update worker pool configuration.

    Adjusts the number of concurrent workers at runtime.
    Changes take effect within a few seconds.

    Admin access required.
    """
    from openlabels.jobs.worker import set_worker_state, get_worker_state

    current = get_worker_state()

    if current.get("status") != "running":
        raise BadRequestError(
            message="No worker is currently running",
            details={"current_status": current.get("status")}
        )

    old_concurrency = current.get("target_concurrency", 0)

    # Update target concurrency
    set_worker_state({"target_concurrency": request.concurrency})

    return {
        "message": f"Worker concurrency updated: {old_concurrency} -> {request.concurrency}",
        "previous_concurrency": old_concurrency,
        "new_concurrency": request.concurrency,
    }
