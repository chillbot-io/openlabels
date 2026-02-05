"""
Scan results API endpoints.

Supports both cursor-based and offset-based pagination:
- Cursor-based (recommended for large datasets): Use `cursor` parameter
- Offset-based (backward compatible): Use `page` and `page_size` parameters

Cursor-based pagination is more efficient for large datasets as it:
- Avoids the performance penalty of large OFFSETs
- Provides consistent results even when data changes between requests
"""

import logging
from datetime import datetime
from typing import Optional, Union
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel

from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    CursorPaginatedResponse,
    CursorPaginationParams,
    create_paginated_response,
)
from openlabels.server.dependencies import (
    ResultServiceDep,
    TenantContextDep,
    AdminContextDep,
    DbSessionDep,
)
from openlabels.server.exceptions import NotFoundError, BadRequestError

router = APIRouter()


class ResultResponse(BaseModel):
    """Scan result response."""

    id: UUID
    job_id: UUID
    file_path: str
    file_name: str
    file_size: Optional[int] = None
    risk_score: int
    risk_tier: str
    entity_counts: dict
    total_entities: int
    exposure_level: Optional[str] = None
    owner: Optional[str] = None
    current_label_name: Optional[str] = None
    recommended_label_name: Optional[str] = None
    label_applied: bool = False
    scanned_at: datetime

    class Config:
        from_attributes = True


class ResultDetailResponse(ResultResponse):
    """Detailed scan result with findings."""

    content_score: Optional[float] = None
    exposure_multiplier: Optional[float] = None
    co_occurrence_rules: Optional[list[str]] = None
    findings: Optional[dict] = None
    label_applied_at: Optional[datetime] = None
    label_error: Optional[str] = None


class ResultStats(BaseModel):
    """Aggregated result statistics."""

    total_files: int
    files_with_pii: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    minimal_count: int
    top_entity_types: dict[str, int]
    labels_applied: int
    labels_pending: int = 0


@router.get("", response_model=PaginatedResponse[ResultResponse])
async def list_results(
    result_service: ResultServiceDep,
    _tenant: TenantContextDep,
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier"),
    has_pii: Optional[bool] = Query(None, description="Filter files with PII"),
    pagination: PaginationParams = Depends(),
) -> PaginatedResponse[ResultResponse]:
    """List scan results with filtering and pagination."""
    # Note: has_pii filter is handled at query level in service
    results, total = await result_service.list_results(
        job_id=job_id,
        risk_tier=risk_tier,
        limit=pagination.limit,
        offset=pagination.offset,
    )

    return PaginatedResponse[ResultResponse](
        **create_paginated_response(
            items=[ResultResponse.model_validate(r) for r in results],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.get("/cursor", response_model=CursorPaginatedResponse[ResultResponse])
async def list_results_cursor(
    db: DbSessionDep,
    _tenant: TenantContextDep,
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier"),
    has_pii: Optional[bool] = Query(None, description="Filter files with PII"),
    pagination: CursorPaginationParams = Depends(),
) -> CursorPaginatedResponse[ResultResponse]:
    """
    List scan results using cursor-based pagination.

    Cursor pagination is more efficient for large datasets and provides
    stable pagination even when data changes between requests.
    """
    from sqlalchemy import select
    from openlabels.server.models import ScanResult
    from openlabels.server.schemas.pagination import cursor_paginate_query

    # Build base filter conditions
    conditions = [ScanResult.tenant_id == _tenant.tenant_id]

    if job_id:
        conditions.append(ScanResult.job_id == job_id)
    if risk_tier:
        conditions.append(ScanResult.risk_tier == risk_tier)
    if has_pii is not None:
        if has_pii:
            conditions.append(ScanResult.total_entities > 0)
        else:
            conditions.append(ScanResult.total_entities == 0)

    # Build query sorted by scanned_at desc, id desc for stable cursor
    query = (
        select(ScanResult)
        .where(*conditions)
        .order_by(ScanResult.scanned_at.desc(), ScanResult.id.desc())
    )

    result = await cursor_paginate_query(
        db,
        query,
        pagination,
        cursor_columns=[(ScanResult.scanned_at, "scanned_at"), (ScanResult.id, "id")],
        transformer=lambda r: ResultResponse.model_validate(r),
    )

    return CursorPaginatedResponse[ResultResponse](**result)


@router.get("/stats", response_model=ResultStats)
async def get_result_stats(
    result_service: ResultServiceDep,
    _tenant: TenantContextDep,
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
) -> ResultStats:
    """
    Get aggregated statistics for scan results using efficient SQL aggregation.

    Combines multiple counts into a single query using CASE expressions for
    better database performance.
    """
    stats = await result_service.get_stats(job_id=job_id)
    entity_stats = await result_service.get_entity_type_stats(job_id=job_id)

    return ResultStats(
        total_files=stats["total_files"],
        files_with_pii=stats["files_with_pii"],
        critical_count=stats["critical_count"],
        high_count=stats["high_count"],
        medium_count=stats["medium_count"],
        low_count=stats["low_count"],
        minimal_count=stats["minimal_count"],
        top_entity_types=entity_stats,
        labels_applied=stats["labels_applied"],
        labels_pending=0,  # Default since service may not track this separately
    )


@router.get("/export")
async def export_results(
    result_service: ResultServiceDep,
    _tenant: TenantContextDep,
    job_id: Optional[UUID] = Query(None, alias="scan_id", description="Job/Scan ID to export (optional)"),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier"),
    has_label: Optional[str] = Query(None, description="Filter by label status"),
    format: str = Query("csv", description="Export format (csv or json)"),
) -> StreamingResponse:
    """Export scan results as CSV or JSON using memory-efficient streaming."""
    import csv
    import io
    import json

    # Generate filename based on filters
    filename_parts = ["results"]
    if job_id:
        filename_parts.append(str(job_id)[:8])
    if risk_tier:
        filename_parts.append(risk_tier.lower())
    filename = "_".join(filename_parts)

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "file_path", "file_name", "risk_score", "risk_tier",
            "total_entities", "exposure_level", "owner",
            "current_label", "recommended_label", "label_applied",
        ])

        # Stream results using service
        async for row_dict in result_service.stream_results_as_dicts(job_id=job_id):
            # Apply additional filters if needed
            if risk_tier and row_dict.get("risk_tier") != risk_tier:
                continue
            if has_label == "true" and not row_dict.get("label_applied"):
                continue
            if has_label == "false" and row_dict.get("label_applied"):
                continue

            writer.writerow([
                row_dict.get("file_path", ""),
                row_dict.get("file_name", ""),
                row_dict.get("risk_score", 0),
                row_dict.get("risk_tier", ""),
                row_dict.get("total_entities", 0),
                row_dict.get("exposure_level", ""),
                row_dict.get("owner", ""),
                row_dict.get("current_label_name", ""),
                row_dict.get("recommended_label_name", ""),
                row_dict.get("label_applied", False),
            ])

        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}.csv"},
        )
    else:
        # JSON export
        data = []
        async for row_dict in result_service.stream_results_as_dicts(job_id=job_id):
            # Apply additional filters if needed
            if risk_tier and row_dict.get("risk_tier") != risk_tier:
                continue
            if has_label == "true" and not row_dict.get("label_applied"):
                continue
            if has_label == "false" and row_dict.get("label_applied"):
                continue
            data.append(row_dict)

        return StreamingResponse(
            iter([json.dumps(data, indent=2)]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}.json"},
        )


@router.get("/{result_id}", response_model=ResultDetailResponse)
async def get_result(
    result_id: UUID,
    result_service: ResultServiceDep,
    _tenant: TenantContextDep,
) -> ResultDetailResponse:
    """Get detailed scan result."""
    result = await result_service.get_result(result_id)
    if not result:
        raise NotFoundError(
            message="Result not found",
            resource_type="ScanResult",
            resource_id=str(result_id),
        )
    return ResultDetailResponse.model_validate(result)


@router.delete("")
async def clear_all_results(
    request: Request,
    result_service: ResultServiceDep,
    _admin: AdminContextDep,
):
    """Clear all scan results for the tenant."""
    deleted_count = await result_service.delete_results(job_id=None)

    # Check if this is an HTMX request
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="",
            status_code=200,
            headers={
                "HX-Trigger": f'{{"notify": {{"message": "{deleted_count} results cleared", "type": "success"}}}}',
            },
        )


@router.delete("/{result_id}")
async def delete_result(
    result_id: UUID,
    request: Request,
    db: DbSessionDep,
    result_service: ResultServiceDep,
    _admin: AdminContextDep,
):
    """Delete a single scan result."""
    from openlabels.server.models import ScanResult

    result = await result_service.get_result(result_id)
    if not result:
        raise NotFoundError(
            message="Result not found",
            resource_type="ScanResult",
            resource_id=str(result_id),
        )

    file_name = result.file_name
    await db.delete(result)
    await db.flush()

    # Check if this is an HTMX request
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="",
            status_code=200,
            headers={
                "HX-Trigger": f'{{"notify": {{"message": "Result for \\"{file_name}\\" deleted", "type": "success"}}, "refreshResults": true}}',
            },
        )


@router.post("/{result_id}/apply-label")
async def apply_recommended_label(
    result_id: UUID,
    request: Request,
    db: DbSessionDep,
    result_service: ResultServiceDep,
    admin: AdminContextDep,
):
    """Apply the recommended label to a scan result."""
    from openlabels.jobs import JobQueue

    result = await result_service.get_result(result_id)
    if not result:
        raise NotFoundError(
            message="Result not found",
            resource_type="ScanResult",
            resource_id=str(result_id),
        )

    # Check if there's a recommended label
    if not result.recommended_label_id:
        raise BadRequestError(
            message="No recommended label for this result",
            details={"result_id": str(result_id)},
        )

    try:
        # Enqueue labeling job
        queue = JobQueue(db, admin.tenant_id)
        job_id = await queue.enqueue(
            task_type="label",
            payload={
                "result_id": str(result_id),
                "label_id": result.recommended_label_id,
                "file_path": result.file_path,
            },
            priority=60,
        )

        # Check if HTMX request
        if request.headers.get("HX-Request"):
            return HTMLResponse(
                content="",
                status_code=200,
                headers={
                    "HX-Trigger": '{"notify": {"message": "Label application queued", "type": "success"}}',
                },
            )

        return {"message": "Label application queued", "job_id": str(job_id)}
    except (NotFoundError, BadRequestError):
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error applying label to result {result_id}: {e}")
        raise InternalServerError(
            code=ErrorCode.DATABASE_ERROR,
            message="Database error occurred while applying label",
        )


@router.post("/{result_id}/rescan")
async def rescan_file(
    result_id: UUID,
    request: Request,
    db: DbSessionDep,
    result_service: ResultServiceDep,
    admin: AdminContextDep,
):
    """Rescan a specific file."""
    from openlabels.server.models import ScanJob
    from openlabels.jobs import JobQueue

    result = await result_service.get_result(result_id)
    if not result:
        raise NotFoundError(
            message="Result not found",
            resource_type="ScanResult",
            resource_id=str(result_id),
        )

    # Get the target info from the original job
    target_name = "Rescan"
    target_id = None
    if result.job_id:
        job = await db.get(ScanJob, result.job_id)
        if job:
            target_name = job.target_name or "Rescan"
            target_id = job.target_id

    # target_id is required - if we can't find it, return an error
    if target_id is None:
        raise BadRequestError(
            message="Cannot rescan: original scan target not found",
            details={"result_id": str(result_id)},
        )

    # Create a new scan job for just this file
    new_job = ScanJob(
        tenant_id=admin.tenant_id,
        target_id=target_id,
        target_name=f"{target_name}: {result.file_name}",
        name=f"Rescan: {result.file_name}",
        status="pending",
        created_by=admin.user_id,
    )
    db.add(new_job)
    await db.flush()

    # Enqueue the job
    queue = JobQueue(db, admin.tenant_id)
    await queue.enqueue(
        task_type="rescan",
        payload={
            "job_id": str(new_job.id),
            "file_path": result.file_path,
            "result_id": str(result_id),
        },
        priority=70,  # Higher priority for single file rescan
    )

    # Check if HTMX request
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="",
            status_code=200,
            headers={
                "HX-Trigger": '{"notify": {"message": "Rescan queued", "type": "success"}}',
            },
        )

    return {"message": "Rescan queued", "job_id": str(new_job.id)}
