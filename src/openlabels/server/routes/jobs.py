"""
Job queue management API endpoints.

Provides access to queue statistics and dead letter queue management.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)
from openlabels.server.dependencies import (
    JobServiceDep,
    TenantContextDep,
    AdminContextDep,
)
from openlabels.server.exceptions import NotFoundError, BadRequestError

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
    job_service: JobServiceDep = Depends(),
    _tenant: TenantContextDep = Depends(),
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
    job_service: JobServiceDep = Depends(),
    _tenant: TenantContextDep = Depends(),
) -> QueueStatsResponse:
    """
    Get job queue statistics.

    Returns counts of jobs by status and failed jobs by task type.
    """
    stats = await job_service.get_queue_stats()
    return QueueStatsResponse(**stats)


@router.get("/failed", response_model=PaginatedResponse[JobResponse])
async def list_failed_jobs(
    task_type: Optional[str] = Query(None, description="Filter by task type"),
    pagination: PaginationParams = Depends(),
    job_service: JobServiceDep = Depends(),
    _admin: AdminContextDep = Depends(),
) -> PaginatedResponse[JobResponse]:
    """
    List failed jobs (dead letter queue).

    Admin access required.
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
    job_service: JobServiceDep = Depends(),
    _tenant: TenantContextDep = Depends(),
) -> JobResponse:
    """Get job details."""
    job = await job_service.get_job(job_id)
    return JobResponse.model_validate(job)


@router.post("/{job_id}/requeue")
async def requeue_job(
    job_id: UUID,
    request: RequeueRequest = RequeueRequest(),
    job_service: JobServiceDep = Depends(),
    _admin: AdminContextDep = Depends(),
) -> dict:
    """
    Requeue a failed job from the dead letter queue.

    Admin access required.
    """
    await job_service.requeue_failed(job_id, reset_retries=request.reset_retries)
    return {"message": "Job requeued successfully", "job_id": str(job_id)}


@router.post("/requeue-all")
async def requeue_all_failed(
    request: RequeueAllRequest = RequeueAllRequest(),
    job_service: JobServiceDep = Depends(),
    _admin: AdminContextDep = Depends(),
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
    request: PurgeRequest = PurgeRequest(),
    job_service: JobServiceDep = Depends(),
    _admin: AdminContextDep = Depends(),
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
    job_service: JobServiceDep = Depends(),
    _admin: AdminContextDep = Depends(),
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

    worker_id: Optional[str]
    status: str
    concurrency: int
    target_concurrency: int
    pid: Optional[int]


@router.get("/workers/status", response_model=WorkerStatusResponse)
async def get_worker_status(
    _admin: AdminContextDep = Depends(),
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
    _admin: AdminContextDep = Depends(),
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
            details={"current_status": current.get("status")},
        )

    old_concurrency = current.get("target_concurrency", 0)

    # Update target concurrency
    set_worker_state({"target_concurrency": request.concurrency})

    return {
        "message": f"Worker concurrency updated: {old_concurrency} -> {request.concurrency}",
        "previous_concurrency": old_concurrency,
        "new_concurrency": request.concurrency,
    }
