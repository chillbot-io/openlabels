"""
Scan management API endpoints.
"""

from __future__ import annotations

import logging
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.exc import SQLAlchemyError

from openlabels.exceptions import BadRequestError, NotFoundError
from openlabels.server.config import get_settings
from openlabels.server.dependencies import (
    AdminContextDep,
    ScanServiceDep,
    TenantContextDep,
)
from openlabels.server.errors import ErrorCode, raise_database_error
from openlabels.server.routes import htmx_notify
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)

logger = logging.getLogger(__name__)

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


class ScanCreate(BaseModel):
    target_id: UUID
    name: str | None = Field(default=None, max_length=255)


class ScanResponse(BaseModel):
    id: UUID
    target_id: UUID
    name: str | None
    status: str
    progress: dict | None = None
    files_scanned: int = 0
    files_with_pii: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


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
    status: str | None = Query(None, description="Filter by status"),
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
@limiter.limit("10/minute")
async def delete_scan(
    scan_id: UUID,
    request: Request,
    scan_service: ScanServiceDep,
    _admin: AdminContextDep,
) -> None:
    """Cancel a running scan (DELETE method)."""
    await scan_service.cancel_scan(scan_id)


@router.post("/{scan_id}/cancel")
@limiter.limit("10/minute")
async def cancel_scan(
    scan_id: UUID,
    request: Request,
    scan_service: ScanServiceDep,
    _admin: AdminContextDep,
):
    """Cancel a running scan (POST method for HTMX)."""
    await scan_service.cancel_scan(scan_id)

    if request.headers.get("HX-Request"):
        return htmx_notify("Scan cancelled", refreshScans=True)

    return {"message": "Scan cancelled", "scan_id": str(scan_id)}


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

        if request.headers.get("HX-Request"):
            return htmx_notify("Scan retry queued", refreshScans=True)

        return {"message": "Scan retry created", "new_job_id": str(new_job.id)}
    except (NotFoundError, BadRequestError):
        raise
    except SQLAlchemyError as e:
        raise_database_error("retrying scan", e)
