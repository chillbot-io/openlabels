"""
Scan management API endpoints.
"""

import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from openlabels.server.config import get_settings
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)
from openlabels.server.dependencies import (
    ScanServiceDep,
    TenantContextDep,
    AdminContextDep,
)
from openlabels.auth.dependencies import require_admin
from openlabels.server.exceptions import NotFoundError, BadRequestError, InternalServerError, ErrorCode
from sqlalchemy.exc import SQLAlchemyError

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


@router.post("", response_model=ScanResponse, status_code=201)
@limiter.limit(lambda: get_settings().rate_limit.scan_create_limit)
async def create_scan(
    request: Request,
    scan_request: ScanCreate,
    scan_service: ScanServiceDep,
    _admin: AdminContextDep,
) -> ScanResponse:
    """Create a new scan job."""
    job = await scan_service.create_scan(
        target_id=scan_request.target_id,
        name=scan_request.name,
    )
    return ScanResponse.model_validate(job)


@router.get("", response_model=PaginatedResponse[ScanResponse])
async def list_scans(
    scan_service: ScanServiceDep,
    _tenant: TenantContextDep,
    status: Optional[str] = Query(None, description="Filter by status"),
    pagination: PaginationParams = Depends(),
) -> PaginatedResponse[ScanResponse]:
    """List scan jobs with pagination."""
    jobs, total = await scan_service.list_scans(
        status=status,
        limit=pagination.limit,
        offset=pagination.offset,
    )

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
    scan_service: ScanServiceDep,
    _tenant: TenantContextDep,
) -> ScanResponse:
    """Get scan job details."""
    job = await scan_service.get_scan(scan_id)
    return ScanResponse.model_validate(job)


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: UUID,
    scan_service: ScanServiceDep,
    _admin: AdminContextDep,
) -> None:
    """Cancel a running scan (DELETE method)."""
    await scan_service.cancel_scan(scan_id)


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: UUID,
    request: Request,
    scan_service: ScanServiceDep,
    _admin: AdminContextDep,
):
    """Cancel a running scan (POST method for HTMX)."""
    await scan_service.cancel_scan(scan_id)

    # Check if this is an HTMX request
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="",
            status_code=200,
            headers={
                "HX-Trigger": '{"notify": {"message": "Scan cancelled", "type": "success"}, "refreshScans": true}',
            },
        )


@router.post("/{scan_id}/retry")
async def retry_scan(
    scan_id: UUID,
    request: Request,
    scan_service: ScanServiceDep,
    _admin: AdminContextDep,
):
    """Retry a failed scan by creating a new scan job."""
    try:
        new_job = await scan_service.retry_scan(scan_id)

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
