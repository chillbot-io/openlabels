"""Scan results API endpoints."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.exc import SQLAlchemyError

from openlabels.exceptions import BadRequestError, NotFoundError
from openlabels.server.dependencies import (
    AdminContextDep,
    DbSessionDep,
    ResultServiceDep,
    TenantContextDep,
)
from openlabels.server.errors import ErrorCode, raise_database_error
from openlabels.server.routes import htmx_notify
from openlabels.server.utils import get_client_ip

from slowapi import Limiter
from openlabels.server.schemas.pagination import (
    CursorPaginatedResponse,
    CursorPaginationParams,
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)

logger = logging.getLogger(__name__)

router = APIRouter()
_limiter = Limiter(key_func=get_client_ip)


class ResultResponse(BaseModel):
    id: UUID
    job_id: UUID
    file_path: str
    file_name: str
    file_size: int | None = None
    risk_score: int
    risk_tier: str
    entity_counts: dict
    total_entities: int
    exposure_level: str | None = None
    owner: str | None = None
    current_label_name: str | None = None
    recommended_label_name: str | None = None
    label_applied: bool = False
    scanned_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ResultDetailResponse(ResultResponse):
    content_score: float | None = None
    exposure_multiplier: float | None = None
    co_occurrence_rules: list[str] | None = None
    findings: dict | None = None
    policy_violations: list[dict] | None = None
    label_applied_at: datetime | None = None
    label_error: str | None = None


class ResultStats(BaseModel):
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
    job_id: UUID | None = Query(None, description="Filter by job ID"),
    risk_tier: Literal["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = Query(None, description="Filter by risk tier"),
    pagination: PaginationParams = Depends(),
) -> PaginatedResponse[ResultResponse]:
    """List scan results with filtering and pagination."""
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
    job_id: UUID | None = Query(None, description="Filter by job ID"),
    risk_tier: Literal["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = Query(None, description="Filter by risk tier"),
    pagination: CursorPaginationParams = Depends(),
) -> CursorPaginatedResponse[ResultResponse]:
    """List scan results using cursor-based pagination."""
    from sqlalchemy import select

    from openlabels.server.models import ScanResult
    from openlabels.server.schemas.pagination import cursor_paginate_query

    conditions = [ScanResult.tenant_id == _tenant.tenant_id]

    if job_id:
        conditions.append(ScanResult.job_id == job_id)
    if risk_tier:
        conditions.append(ScanResult.risk_tier == risk_tier)

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
    job_id: UUID | None = Query(None, description="Filter by job ID"),
) -> ResultStats:
    """Get aggregated statistics for scan results."""
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
        labels_pending=stats["labels_pending"],
    )


@router.get("/export")
async def export_results(
    request: Request,
    result_service: ResultServiceDep,
    _tenant: TenantContextDep,
    job_id: UUID | None = Query(None, alias="scan_id", description="Job/Scan ID to export (optional)"),
    risk_tier: Literal["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = Query(None, description="Filter by risk tier"),
    has_label: str | None = Query(None, description="Filter by label status"),
    format: Literal["csv", "json"] = Query("csv", description="Export format (csv or json)"),
) -> StreamingResponse:
    """Export scan results as CSV or JSON."""
    import csv
    import io
    import json

    filename_parts = ["results"]
    if job_id:
        filename_parts.append(str(job_id)[:8])
    if risk_tier:
        filename_parts.append(risk_tier.lower())
    filename = "_".join(filename_parts)

    _EXPORT_COLS = [
        "file_path", "file_name", "risk_score", "risk_tier",
        "total_entities", "exposure_level", "owner",
        "current_label_name", "recommended_label_name", "label_applied",
    ]

    # Resolve data source — DuckDB (all filters pushed down) or PG (post-filter)
    analytics = getattr(request.app.state, "analytics", None)
    if analytics is not None:
        has_label_bool = None
        if has_label == "true":
            has_label_bool = True
        elif has_label == "false":
            has_label_bool = False
        rows = await analytics.export_scan_results(
            _tenant.tenant_id,
            job_id=job_id,
            risk_tier=risk_tier,
            has_label=has_label_bool,
        )
        return _build_export_response(rows, format, filename, _EXPORT_COLS)

    # PostgreSQL fallback — stream with post-filtering
    def _matches_filters(row_dict: dict) -> bool:
        if risk_tier and row_dict.get("risk_tier") != risk_tier:
            return False
        if has_label == "true" and not row_dict.get("label_applied"):
            return False
        if has_label == "false" and row_dict.get("label_applied"):
            return False
        return True

    async def _pg_row_iter():
        async for row_dict in result_service.stream_results_as_dicts(job_id=job_id):
            if not _matches_filters(row_dict):
                continue
            yield row_dict

    if format == "csv":
        async def _csv_generator():
            header_buf = io.StringIO()
            writer = csv.writer(header_buf)
            writer.writerow(_EXPORT_COLS)
            yield header_buf.getvalue()

            async for row_dict in _pg_row_iter():
                row_buf = io.StringIO()
                row_writer = csv.writer(row_buf)
                row_writer.writerow([row_dict.get(c, "") for c in _EXPORT_COLS])
                yield row_buf.getvalue()

        return StreamingResponse(
            _csv_generator(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}.csv"},
        )
    else:
        async def _json_generator():
            yield "[\n"
            first = True
            async for row_dict in _pg_row_iter():
                if not first:
                    yield ",\n"
                first = False
                yield json.dumps(
                    {c: row_dict.get(c) for c in _EXPORT_COLS},
                    indent=2,
                    default=str,
                )
            yield "\n]\n"

        return StreamingResponse(
            _json_generator(),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}.json"},
        )


def _build_export_response(
    rows: list[dict], format: str, filename: str, columns: list[str],
) -> StreamingResponse:
    """Build a CSV or JSON streaming response from pre-fetched DuckDB rows."""
    import csv
    import io
    import json

    if format == "csv":
        def _csv_gen():
            header_buf = io.StringIO()
            writer = csv.writer(header_buf)
            writer.writerow(columns)
            yield header_buf.getvalue()
            for r in rows:
                buf = io.StringIO()
                csv.writer(buf).writerow([r.get(c, "") for c in columns])
                yield buf.getvalue()

        return StreamingResponse(
            _csv_gen(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}.csv"},
        )
    else:
        def _json_gen():
            yield "[\n"
            for i, r in enumerate(rows):
                if i:
                    yield ",\n"
                yield json.dumps({c: r.get(c) for c in columns}, indent=2)
            yield "\n]\n"

        return StreamingResponse(
            _json_gen(),
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
@_limiter.limit("5/minute")
async def clear_all_results(
    request: Request,
    result_service: ResultServiceDep,
    _admin: AdminContextDep,
):
    """Clear all scan results for the tenant."""
    deleted_count = await result_service.delete_results(job_id=None)

    if request.headers.get("HX-Request"):
        return htmx_notify(f"{deleted_count} results cleared")

    return {"deleted_count": deleted_count}


@router.delete("/{result_id}")
@_limiter.limit("20/minute")
async def delete_result(
    result_id: UUID,
    request: Request,
    db: DbSessionDep,
    result_service: ResultServiceDep,
    _admin: AdminContextDep,
):
    """Delete a single scan result."""

    result = await result_service.get_result(result_id)
    if not result:
        raise NotFoundError(
            message="Result not found",
            resource_type="ScanResult",
            resource_id=str(result_id),
        )

    file_name = result.file_name
    await db.delete(result)
    await db.commit()

    if request.headers.get("HX-Request"):
        return htmx_notify(f'Result for "{file_name}" deleted', refreshResults=True)

    return JSONResponse(status_code=200, content={"message": f'Result for "{file_name}" deleted'})


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

    if not result.recommended_label_id:
        raise BadRequestError(
            message="No recommended label for this result",
            details={"result_id": str(result_id)},
        )

    try:
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

        if request.headers.get("HX-Request"):
            return htmx_notify("Label application queued")

        return {"message": "Label application queued", "job_id": str(job_id)}
    except (NotFoundError, BadRequestError):
        raise
    except SQLAlchemyError as e:
        raise_database_error("applying label", e)


@router.post("/{result_id}/rescan")
async def rescan_file(
    result_id: UUID,
    request: Request,
    db: DbSessionDep,
    result_service: ResultServiceDep,
    admin: AdminContextDep,
):
    """Rescan a specific file."""
    from openlabels.jobs import JobQueue
    from openlabels.server.models import ScanJob

    result = await result_service.get_result(result_id)
    if not result:
        raise NotFoundError(
            message="Result not found",
            resource_type="ScanResult",
            resource_id=str(result_id),
        )

    target_name = "Rescan"
    target_id = None
    if result.job_id:
        job = await db.get(ScanJob, result.job_id)
        if job:
            target_name = job.target_name or "Rescan"
            target_id = job.target_id

    if target_id is None:
        raise BadRequestError(
            message="Cannot rescan: original scan target not found",
            details={"result_id": str(result_id)},
        )

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

    if request.headers.get("HX-Request"):
        return htmx_notify("Rescan queued")

    return {"message": "Rescan queued", "job_id": str(new_job.id)}
