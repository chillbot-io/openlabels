"""
Scan management API endpoints.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, Union
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func, tuple_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from openlabels.server.db import get_session
from openlabels.server.errors import (
    NotFoundError,
    BadRequestError,
    InternalServerError,
    ErrorCode,
)
from openlabels.server.pagination import (
    encode_cursor,
    decode_cursor,
)

logger = logging.getLogger(__name__)
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
    """Paginated list of scans (offset-based)."""

    items: list[ScanResponse]
    total: int
    page: int
    page_size: int = Field(description="Items per page")
    total_pages: int = Field(description="Total number of pages")
    has_more: bool = Field(description="Whether there are more pages")


class CursorScanListResponse(BaseModel):
    """Paginated list of scans (cursor-based).

    This response format is more efficient for large datasets as it uses
    cursor-based pagination instead of offset-based pagination.
    """

    items: list[ScanResponse]
    next_cursor: Optional[str] = None
    has_more: bool = False


@router.post("", response_model=ScanResponse, status_code=201)
@limiter.limit(lambda: get_settings().rate_limit.scan_create_limit)
async def create_scan(
    request: Request,
    scan_request: ScanCreate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> ScanResponse:
    """Create a new scan job."""
    try:
        # Verify target exists AND belongs to user's tenant (prevent cross-tenant access)
        target = await session.get(ScanTarget, scan_request.target_id)
        if not target or target.tenant_id != user.tenant_id:
            raise NotFoundError(
                code=ErrorCode.TARGET_NOT_FOUND,
                message="Target not found",
                details={"target_id": str(scan_request.target_id)},
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
    except (NotFoundError, BadRequestError):
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error creating scan for target {scan_request.target_id}: {e}")
        raise InternalServerError(
            code=ErrorCode.DATABASE_ERROR,
            message="Database error occurred while creating scan",
        )


@router.get("", response_model=Union[ScanListResponse, CursorScanListResponse])
async def list_scans(
    status: Optional[str] = Query(None, description="Filter by status"),
    # Offset-based pagination parameters (backward compatible)
    page: Optional[int] = Query(None, ge=1, description="Page number for offset-based pagination"),
    # Cursor-based pagination parameters
    cursor: Optional[str] = Query(None, description="Cursor for cursor-based pagination (more efficient for large datasets)"),
    limit: int = Query(50, ge=1, le=100, description="Number of items per page"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> Union[ScanListResponse, CursorScanListResponse]:
    """List scan jobs with pagination.

    Supports two pagination modes:
    - Offset-based (default): Use `page` parameter. Returns total count and page info.
    - Cursor-based: Use `cursor` parameter. More efficient for large datasets (OFFSET 10000 scans 10K rows,
      cursor-based uses WHERE clause with indexed columns).

    If `cursor` is provided, cursor-based pagination is used.
    If `page` is provided (or neither), offset-based pagination is used for backward compatibility.
    """
    try:
        # Build base filter conditions
        conditions = [ScanJob.tenant_id == user.tenant_id]

        if status:
            conditions.append(ScanJob.status == status)

        # Determine pagination mode: cursor-based if cursor provided, else offset-based
        use_cursor_pagination = cursor is not None

        if use_cursor_pagination:
            # Cursor-based pagination (efficient for large datasets)
            # Order by created_at DESC, id DESC for consistent ordering
            query = (
                select(ScanJob)
                .where(*conditions)
                .order_by(ScanJob.created_at.desc(), ScanJob.id.desc())
            )

            # Apply cursor filter if provided
            cursor_data = decode_cursor(cursor)
            if cursor_data:
                # WHERE (created_at, id) < (cursor_timestamp, cursor_id)
                # This efficiently seeks to the correct position using index
                query = query.where(
                    tuple_(ScanJob.created_at, ScanJob.id)
                    < (cursor_data.timestamp, cursor_data.id)
                )

            # Fetch one extra to check if there are more results
            query = query.limit(limit + 1)
            result = await session.execute(query)
            jobs = list(result.scalars().all())

            # Check if there are more results
            has_more = len(jobs) > limit
            if has_more:
                jobs = jobs[:limit]  # Remove the extra item

            # Generate next cursor from last item
            next_cursor = None
            if jobs and has_more:
                last_item = jobs[-1]
                next_cursor = encode_cursor(last_item.id, last_item.created_at)

            return CursorScanListResponse(
                items=[ScanResponse.model_validate(j) for j in jobs],
                next_cursor=next_cursor,
                has_more=has_more,
            )
        else:
            # Offset-based pagination (backward compatible)
            effective_page = page if page is not None else 1

            query = select(ScanJob).where(*conditions).order_by(ScanJob.created_at.desc())

            # Count total
            count_query = select(func.count()).select_from(
                select(ScanJob.id).where(*conditions)
            )
            result = await session.execute(count_query)
            total = result.scalar() or 0

            # Paginate
            query = query.offset((effective_page - 1) * limit).limit(limit)
            result = await session.execute(query)
            jobs = result.scalars().all()

            return ScanListResponse(
                items=[ScanResponse.model_validate(j) for j in jobs],
                total=total,
                page=effective_page,
                pages=(total + limit - 1) // limit if total > 0 else 1,
            )
    except SQLAlchemyError as e:
        logger.error(f"Database error listing scans: {e}")
        raise InternalServerError(
            code=ErrorCode.DATABASE_ERROR,
            message="Database error occurred while listing scans",
        )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ScanResponse:
    """Get scan job details."""
    try:
        job = await session.get(ScanJob, scan_id)
        if not job or job.tenant_id != user.tenant_id:
            raise NotFoundError(
                code=ErrorCode.SCAN_NOT_FOUND,
                message="The specified scan does not exist",
                details={"scan_id": str(scan_id)},
            )
        return job
    except NotFoundError:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error getting scan {scan_id}: {e}")
        raise InternalServerError(
            code=ErrorCode.DATABASE_ERROR,
            message="Database error occurred while retrieving scan",
        )


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> None:
    """Cancel a running scan (DELETE method)."""
    try:
        job = await session.get(ScanJob, scan_id)
        if not job or job.tenant_id != user.tenant_id:
            raise NotFoundError(
                code=ErrorCode.SCAN_NOT_FOUND,
                message="The specified scan does not exist",
                details={"scan_id": str(scan_id)},
            )

        if job.status not in ("pending", "running"):
            raise BadRequestError(
                code=ErrorCode.SCAN_CANNOT_CANCEL,
                message="Scan cannot be cancelled",
                details={"scan_id": str(scan_id), "current_status": job.status},
            )

        job.status = "cancelled"
        job.completed_at = datetime.now(timezone.utc)
        await session.flush()
    except (NotFoundError, BadRequestError):
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error cancelling scan {scan_id}: {e}")
        raise InternalServerError(
            code=ErrorCode.DATABASE_ERROR,
            message="Database error occurred while cancelling scan",
        )


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Cancel a running scan (POST method for HTMX)."""
    from fastapi.responses import HTMLResponse, Response

    try:
        job = await session.get(ScanJob, scan_id)
        if not job or job.tenant_id != user.tenant_id:
            raise NotFoundError(
                code=ErrorCode.SCAN_NOT_FOUND,
                message="The specified scan does not exist",
                details={"scan_id": str(scan_id)},
            )

        if job.status not in ("pending", "running"):
            raise BadRequestError(
                code=ErrorCode.SCAN_CANNOT_CANCEL,
                message="Scan cannot be cancelled",
                details={"scan_id": str(scan_id), "current_status": job.status},
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
    except (NotFoundError, BadRequestError):
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error cancelling scan {scan_id}: {e}")
        raise InternalServerError(
            code=ErrorCode.DATABASE_ERROR,
            message="Database error occurred while cancelling scan",
        )


@router.post("/{scan_id}/retry")
async def retry_scan(
    scan_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Retry a failed scan by creating a new scan job."""
    from fastapi.responses import HTMLResponse, Response

    try:
        job = await session.get(ScanJob, scan_id)
        if not job or job.tenant_id != user.tenant_id:
            raise NotFoundError(
                code=ErrorCode.SCAN_NOT_FOUND,
                message="The specified scan does not exist",
                details={"scan_id": str(scan_id)},
            )

        if job.status not in ("failed", "cancelled"):
            raise BadRequestError(
                code=ErrorCode.SCAN_CANNOT_RETRY,
                message="Only failed or cancelled scans can be retried",
                details={"scan_id": str(scan_id), "current_status": job.status},
            )

        # Get the target
        target = await session.get(ScanTarget, job.target_id)
        if not target:
            raise NotFoundError(
                code=ErrorCode.TARGET_NOT_AVAILABLE,
                message="Target no longer exists",
                details={"target_id": str(job.target_id)},
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
    except (NotFoundError, BadRequestError):
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error retrying scan {scan_id}: {e}")
        raise InternalServerError(
            code=ErrorCode.DATABASE_ERROR,
            message="Database error occurred while retrying scan",
        )
