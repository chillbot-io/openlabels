"""
Scan management API endpoints.
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from openlabels.server.db import get_session
from openlabels.server.config import get_settings
from openlabels.server.models import ScanJob, ScanTarget
from openlabels.auth.dependencies import get_current_user, require_admin, CurrentUser
from openlabels.jobs import JobQueue

logger = logging.getLogger(__name__)

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


class ScanListResponse(BaseModel):
    """
    Paginated list of scans.

    Uses standardized pagination format with consistent field naming.
    """

    items: list[ScanResponse]
    total: int
    page: int
    page_size: int = Field(description="Items per page")
    total_pages: int = Field(description="Total number of pages")
    has_more: bool = Field(description="Whether there are more pages")


@router.post("", response_model=ScanResponse, status_code=201)
@limiter.limit(lambda: get_settings().rate_limit.scan_create_limit)
async def create_scan(
    request: Request,
    scan_request: ScanCreate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> ScanResponse:
    """Create a new scan job."""
    settings = get_settings()
    try:
        # Verify target exists AND belongs to user's tenant (prevent cross-tenant access)
        target = await session.get(ScanTarget, scan_request.target_id)
        if not target or target.tenant_id != user.tenant_id:
            raise HTTPException(status_code=404, detail="Target not found")

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
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error in create_scan: {e}")
        await session.rollback()
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in create_scan: {e}")
        await session.rollback()
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


@router.get("", response_model=ScanListResponse)
async def list_scans(
    status: Optional[str] = Query(None, description="Filter by status"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, alias="limit", description="Items per page"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ScanListResponse:
    """
    List scan jobs with pagination.

    Uses standardized pagination format with consistent field naming:
    - `items`: List of scans
    - `total`: Total number of scans
    - `page`: Current page number
    - `page_size`: Items per page
    - `total_pages`: Total number of pages
    - `has_more`: Whether there are more pages
    """
    settings = get_settings()
    try:
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

        # Calculate pagination
        total_pages = (total + page_size - 1) // page_size if total > 0 else 1

        # Paginate
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await session.execute(query)
        jobs = result.scalars().all()

        return ScanListResponse(
            items=[ScanResponse.model_validate(j) for j in jobs],
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            has_more=page < total_pages,
        )
    except SQLAlchemyError as e:
        logger.error(f"Database error in list_scans: {e}")
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in list_scans: {e}")
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ScanResponse:
    """Get scan job details."""
    settings = get_settings()
    try:
        job = await session.get(ScanJob, scan_id)
        if not job or job.tenant_id != user.tenant_id:
            raise HTTPException(status_code=404, detail="Scan not found")
        return job
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error in get_scan: {e}")
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in get_scan: {e}")
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> None:
    """Cancel a running scan (DELETE method)."""
    settings = get_settings()
    try:
        job = await session.get(ScanJob, scan_id)
        if not job or job.tenant_id != user.tenant_id:
            raise HTTPException(status_code=404, detail="Scan not found")

        if job.status not in ("pending", "running"):
            raise HTTPException(status_code=400, detail="Scan cannot be cancelled")

        job.status = "cancelled"
        job.completed_at = datetime.now(timezone.utc)
        await session.flush()
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error in delete_scan: {e}")
        await session.rollback()
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in delete_scan: {e}")
        await session.rollback()
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Cancel a running scan (POST method for HTMX)."""
    from fastapi.responses import HTMLResponse, Response

    settings = get_settings()
    try:
        job = await session.get(ScanJob, scan_id)
        if not job or job.tenant_id != user.tenant_id:
            raise HTTPException(status_code=404, detail="Scan not found")

        if job.status not in ("pending", "running"):
            raise HTTPException(status_code=400, detail="Scan cannot be cancelled")

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
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error in cancel_scan: {e}")
        await session.rollback()
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in cancel_scan: {e}")
        await session.rollback()
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


@router.post("/{scan_id}/retry")
async def retry_scan(
    scan_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Retry a failed scan by creating a new scan job."""
    from fastapi.responses import HTMLResponse, Response

    settings = get_settings()
    try:
        job = await session.get(ScanJob, scan_id)
        if not job or job.tenant_id != user.tenant_id:
            raise HTTPException(status_code=404, detail="Scan not found")

        if job.status not in ("failed", "cancelled"):
            raise HTTPException(status_code=400, detail="Only failed or cancelled scans can be retried")

        # Get the target
        target = await session.get(ScanTarget, job.target_id)
        if not target:
            raise HTTPException(status_code=404, detail="Target no longer exists")

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
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error in retry_scan: {e}")
        await session.rollback()
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in retry_scan: {e}")
        await session.rollback()
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)
