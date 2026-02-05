"""
Scan management API endpoints.
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from openlabels.server.db import get_session
from openlabels.server.config import get_settings
from openlabels.server.models import ScanJob, ScanTarget
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)
from openlabels.server.exceptions import NotFoundError, BadRequestError
from openlabels.auth.dependencies import get_current_user, require_admin, CurrentUser
from openlabels.jobs import JobQueue

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


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


@router.post("", response_model=ScanResponse, status_code=201)
@limiter.limit(lambda: get_settings().rate_limit.scan_create_limit)
async def create_scan(
    request: Request,
    scan_request: ScanCreate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> ScanResponse:
    """Create a new scan job."""
    # Verify target exists AND belongs to user's tenant (prevent cross-tenant access)
    target = await session.get(ScanTarget, scan_request.target_id)
    if not target or target.tenant_id != user.tenant_id:
        raise NotFoundError(
            message="Target not found",
            resource_type="ScanTarget",
            resource_id=str(scan_request.target_id),
        )

    # Create scan job
    job = ScanJob(
        tenant_id=user.tenant_id,
        target_id=scan_request.target_id,
        name=scan_request.name or f"Scan: {target.name}",
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

    # Refresh to load server-generated defaults (created_at)
    await session.refresh(job)

    return job


@router.get("", response_model=PaginatedResponse[ScanResponse])
async def list_scans(
    status: Optional[str] = Query(None, description="Filter by status"),
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> PaginatedResponse[ScanResponse]:
    """List scan jobs with pagination."""
    from sqlalchemy import func

    # Build base conditions
    conditions = [ScanJob.tenant_id == user.tenant_id]
    if status:
        conditions.append(ScanJob.status == status)

    # Count total using SQL COUNT (efficient, no row loading)
    count_query = select(func.count()).select_from(ScanJob).where(*conditions)
    count_result = await session.execute(count_query)
    total = count_result.scalar() or 0

    # Get paginated results
    query = (
        select(ScanJob)
        .where(*conditions)
        .order_by(ScanJob.created_at.desc())
        .offset(pagination.offset)
        .limit(pagination.limit)
    )
    result = await session.execute(query)
    jobs = result.scalars().all()

    return PaginatedResponse[ScanResponse](
        **create_paginated_response(
            items=[ScanResponse.model_validate(j) for j in jobs],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ScanResponse:
    """Get scan job details."""
    job = await session.get(ScanJob, scan_id)
    if not job or job.tenant_id != user.tenant_id:
        raise NotFoundError(
            message="Scan not found",
            resource_type="ScanJob",
            resource_id=str(scan_id),
        )
    return job


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> None:
    """Cancel a running scan (DELETE method)."""
    job = await session.get(ScanJob, scan_id)
    if not job or job.tenant_id != user.tenant_id:
        raise NotFoundError(
            message="Scan not found",
            resource_type="ScanJob",
            resource_id=str(scan_id),
        )

    if job.status not in ("pending", "running"):
        raise BadRequestError(
            message="Scan cannot be cancelled",
            details={"current_status": job.status, "allowed_statuses": ["pending", "running"]},
        )

    job.status = "cancelled"
    job.completed_at = datetime.now(timezone.utc)
    await session.flush()


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Cancel a running scan (POST method for HTMX)."""
    from fastapi.responses import HTMLResponse, Response

    job = await session.get(ScanJob, scan_id)
    if not job or job.tenant_id != user.tenant_id:
        raise NotFoundError(
            message="Scan not found",
            resource_type="ScanJob",
            resource_id=str(scan_id),
        )

    if job.status not in ("pending", "running"):
        raise BadRequestError(
            message="Scan cannot be cancelled",
            details={"current_status": job.status, "allowed_statuses": ["pending", "running"]},
        )

    job.status = "cancelled"
    job.completed_at = datetime.now(timezone.utc)
    await session.flush()

    # Check if this is an HTMX request
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="",
            status_code=200,
            headers={
                "HX-Trigger": '{"notify": {"message": "Scan cancelled", "type": "success"}, "refreshScans": true}',
            },
        )

    return Response(status_code=204)


@router.post("/{scan_id}/retry")
async def retry_scan(
    scan_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Retry a failed scan by creating a new scan job."""
    from fastapi.responses import HTMLResponse, Response

    job = await session.get(ScanJob, scan_id)
    if not job or job.tenant_id != user.tenant_id:
        raise NotFoundError(
            message="Scan not found",
            resource_type="ScanJob",
            resource_id=str(scan_id),
        )

    if job.status not in ("failed", "cancelled"):
        raise BadRequestError(
            message="Only failed or cancelled scans can be retried",
            details={"current_status": job.status, "allowed_statuses": ["failed", "cancelled"]},
        )

    # Get the target
    target = await session.get(ScanTarget, job.target_id)
    if not target:
        raise NotFoundError(
            message="Target no longer exists",
            resource_type="ScanTarget",
            resource_id=str(job.target_id),
        )

    # Create a new scan job
    new_job = ScanJob(
        tenant_id=user.tenant_id,
        target_id=job.target_id,
        target_name=target.name,
        name=f"{job.name} (retry)",
        status="pending",
        created_by=user.id,
    )
    session.add(new_job)
    await session.flush()

    # Enqueue the job
    queue = JobQueue(session, user.tenant_id)
    await queue.enqueue(
        task_type="scan",
        payload={"job_id": str(new_job.id)},
        priority=60,  # Slightly higher priority for retries
    )

    # Check if this is an HTMX request
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="",
            status_code=200,
            headers={
                "HX-Trigger": '{"notify": {"message": "Scan retry queued", "type": "success"}, "refreshScans": true}',
            },
        )

    return {"message": "Scan retry created", "new_job_id": str(new_job.id)}
