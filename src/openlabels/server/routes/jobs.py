"""
Job queue management API endpoints.

Provides access to queue statistics and dead letter queue management.
"""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from openlabels.exceptions import BadRequestError
from openlabels.server.dependencies import (
    AdminContextDep,
    JobServiceDep,
    TenantContextDep,
)
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)

router = APIRouter()


class JobResponse(BaseModel):
    """Job details response."""

    id: UUID
    task_type: str
    payload: dict
    priority: int
    status: str
    scheduled_for: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    worker_id: str | None
    result: dict | None
    error: str | None
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


class RequeueRequest(BaseModel):
    """Request to requeue a failed job."""

    reset_retries: bool = True


class RequeueAllRequest(BaseModel):
    """Request to requeue all failed jobs."""

    task_type: str | None = None
    reset_retries: bool = True


class PurgeRequest(BaseModel):
    """Request to purge failed jobs."""

    task_type: str | None = None
    older_than_days: int | None = None


@router.get("", response_model=QueueStatsResponse)
async def list_jobs(
    job_service: JobServiceDep,
    _tenant: TenantContextDep,
) -> QueueStatsResponse:
    """
    Get job queue statistics.

    Returns counts of jobs by status and failed jobs by task type.
    This is the default endpoint for /api/jobs.
    """
    stats = await job_service.get_queue_stats()
    return QueueStatsResponse(**stats)


@router.get("/stats", response_model=QueueStatsResponse)
async def get_queue_stats(
    job_service: JobServiceDep,
    _tenant: TenantContextDep,
) -> QueueStatsResponse:
    """
    Get job queue statistics.

    Returns counts of jobs by status and failed jobs by task type.
    """
    stats = await job_service.get_queue_stats()
    return QueueStatsResponse(**stats)


@router.get("/failed", response_model=PaginatedResponse[JobResponse])
async def list_failed_jobs(
    job_service: JobServiceDep,
    _admin: AdminContextDep,
    task_type: str | None = Query(None, description="Filter by task type"),
    pagination: PaginationParams = Depends(),
) -> PaginatedResponse[JobResponse]:
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
    jobs, total = await job_service.get_failed_jobs(
        task_type=task_type,
        limit=pagination.limit,
        offset=pagination.offset,
    )

    return PaginatedResponse[JobResponse](
        **create_paginated_response(
            items=[JobResponse.model_validate(job) for job in jobs],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: UUID,
    job_service: JobServiceDep,
    _tenant: TenantContextDep,
) -> JobResponse:
    """Get job details."""
    job = await job_service.get_job(job_id)
    return JobResponse.model_validate(job)


@router.post("/{job_id}/requeue")
async def requeue_job(
    job_id: UUID,
    job_service: JobServiceDep,
    _admin: AdminContextDep,
    request: RequeueRequest = RequeueRequest(),
) -> dict:
    """
    Requeue a failed job from the dead letter queue.

    Admin access required.
    """
    await job_service.requeue_failed(job_id, reset_retries=request.reset_retries)
    return {"message": "Job requeued successfully", "job_id": str(job_id)}


@router.post("/requeue-all")
async def requeue_all_failed(
    job_service: JobServiceDep,
    _admin: AdminContextDep,
    request: RequeueAllRequest = RequeueAllRequest(),
) -> dict:
    """
    Requeue all failed jobs.

    Admin access required. Use with caution in production.
    """
    count = await job_service.requeue_all_failed(
        task_type=request.task_type,
        reset_retries=request.reset_retries,
    )

    return {"message": f"Requeued {count} failed jobs", "count": count}


@router.post("/purge")
async def purge_failed_jobs(
    job_service: JobServiceDep,
    _admin: AdminContextDep,
    request: PurgeRequest = PurgeRequest(),
) -> dict:
    """
    Delete failed jobs from the dead letter queue.

    Admin access required. Use with caution - this action is irreversible.
    """
    count = await job_service.purge_failed(
        task_type=request.task_type,
        older_than_days=request.older_than_days,
    )

    return {"message": f"Purged {count} failed jobs", "count": count}


@router.post("/{job_id}/cancel")
async def cancel_job(
    job_id: UUID,
    job_service: JobServiceDep,
    _admin: AdminContextDep,
) -> dict:
    """
    Cancel a pending or running job.

    Admin access required.
    """
    await job_service.cancel_job(job_id)
    return {"message": "Job cancelled successfully", "job_id": str(job_id)}


# =============================================================================
# Worker Pool Configuration
# =============================================================================


class WorkerConfigRequest(BaseModel):
    """Request to update worker configuration."""

    concurrency: int = Query(ge=1, le=32, description="Number of concurrent workers (1-32)")


class WorkerStatusResponse(BaseModel):
    """Worker status response."""

    worker_id: str | None
    status: str
    concurrency: int
    target_concurrency: int
    pid: int | None


@router.get("/workers/status", response_model=WorkerStatusResponse)
async def get_worker_status(
    _admin: AdminContextDep,
) -> WorkerStatusResponse:
    """
    Get current worker pool status.

    Returns the current worker configuration and status from Redis.
    Admin access required.
    """
    from openlabels.jobs.worker import get_worker_state_manager

    state_manager = await get_worker_state_manager()
    workers = await state_manager.get_all_workers()

    # Return the first running worker found, or empty status
    for worker_id, state in workers.items():
        if state.get("status") == "running":
            return WorkerStatusResponse(
                worker_id=state.get("worker_id"),
                status=state.get("status", "unknown"),
                concurrency=state.get("concurrency", 0),
                target_concurrency=state.get("target_concurrency", 0),
                pid=state.get("pid"),
            )

    # No running workers found
    return WorkerStatusResponse(
        worker_id=None,
        status="stopped",
        concurrency=0,
        target_concurrency=0,
        pid=None,
    )


@router.post("/workers/config")
async def update_worker_config(
    request: WorkerConfigRequest,
    _admin: AdminContextDep,
) -> dict:
    """
    Update worker pool configuration.

    Adjusts the number of concurrent workers at runtime.
    Changes take effect within a few seconds.

    Admin access required.
    """
    from openlabels.jobs.worker import get_worker_state_manager

    state_manager = await get_worker_state_manager()
    workers = await state_manager.get_all_workers()

    # Find a running worker to update
    running_worker = None
    for worker_id, state in workers.items():
        if state.get("status") == "running":
            running_worker = (worker_id, state)
            break

    if not running_worker:
        raise BadRequestError(
            message="No worker is currently running",
            details={"current_status": "stopped"},
        )

    worker_id, current = running_worker
    old_concurrency = current.get("target_concurrency", 0)

    # Update target concurrency in the worker's state
    current["target_concurrency"] = request.concurrency
    await state_manager.set_state(worker_id, current)

    return {
        "message": f"Worker concurrency updated: {old_concurrency} -> {request.concurrency}",
        "previous_concurrency": old_concurrency,
        "new_concurrency": request.concurrency,
    }
