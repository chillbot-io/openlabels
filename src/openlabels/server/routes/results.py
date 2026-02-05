"""
Scan results API endpoints.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import ScanResult
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    CursorPaginatedResponse,
    CursorPaginationParams,
    create_paginated_response,
    cursor_paginate_query,
)
from openlabels.auth.dependencies import get_current_user, require_admin, CurrentUser

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
    labels_pending: int


@router.get("", response_model=PaginatedResponse[ResultResponse])
async def list_results(
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier"),
    has_pii: Optional[bool] = Query(None, description="Filter files with PII"),
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> PaginatedResponse[ResultResponse]:
    """List scan results with filtering and pagination."""
    # Build base filter conditions
    conditions = [ScanResult.tenant_id == user.tenant_id]

    if job_id:
        conditions.append(ScanResult.job_id == job_id)
    if risk_tier:
        conditions.append(ScanResult.risk_tier == risk_tier)
    if has_pii is not None:
        if has_pii:
            conditions.append(ScanResult.total_entities > 0)
        else:
            conditions.append(ScanResult.total_entities == 0)

    # Build main query
    query = select(ScanResult).where(*conditions).order_by(ScanResult.risk_score.desc())

    # Count total (with same filters)
    count_query = select(func.count()).select_from(query.subquery())
    count_result = await session.execute(count_query)
    total = count_result.scalar() or 0

    # Paginate
    query = query.offset(pagination.offset).limit(pagination.limit)
    result = await session.execute(query)
    results = result.scalars().all()

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
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier"),
    has_pii: Optional[bool] = Query(None, description="Filter files with PII"),
    pagination: CursorPaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> CursorPaginatedResponse[ResultResponse]:
    """
    List scan results using cursor-based pagination.

    Cursor pagination is more efficient for large datasets and provides
    stable pagination even when data changes between requests.
    """
    # Build base filter conditions
    conditions = [ScanResult.tenant_id == user.tenant_id]

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
        session,
        query,
        pagination,
        cursor_columns=[(ScanResult.scanned_at, "scanned_at"), (ScanResult.id, "id")],
        transformer=lambda r: ResultResponse.model_validate(r),
    )

    return CursorPaginatedResponse[ResultResponse](**result)


@router.get("/stats", response_model=ResultStats)
async def get_result_stats(
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ResultStats:
    """
    Get aggregated statistics for scan results using efficient SQL aggregation.

    Combines multiple counts into a single query using CASE expressions for
    better database performance.
    """
    from sqlalchemy import case

    # Build base filter conditions
    conditions = [ScanResult.tenant_id == user.tenant_id]
    if job_id:
        conditions.append(ScanResult.job_id == job_id)

    # Combined aggregation query - get all counts in a single database round-trip
    stats_query = select(
        func.count().label("total_files"),
        func.sum(case((ScanResult.total_entities > 0, 1), else_=0)).label("files_with_pii"),
        func.sum(case((ScanResult.risk_tier == "CRITICAL", 1), else_=0)).label("critical_count"),
        func.sum(case((ScanResult.risk_tier == "HIGH", 1), else_=0)).label("high_count"),
        func.sum(case((ScanResult.risk_tier == "MEDIUM", 1), else_=0)).label("medium_count"),
        func.sum(case((ScanResult.risk_tier == "LOW", 1), else_=0)).label("low_count"),
        func.sum(case((ScanResult.risk_tier == "MINIMAL", 1), else_=0)).label("minimal_count"),
        func.sum(case((ScanResult.label_applied == True, 1), else_=0)).label("labels_applied"),  # noqa: E712
        func.sum(case(
            (ScanResult.label_applied == False, case((ScanResult.recommended_label_id.isnot(None), 1), else_=0)),  # noqa: E712
            else_=0
        )).label("labels_pending"),
    ).where(*conditions)

    stats_result = await session.execute(stats_query)
    row = stats_result.one()

    # For entity type aggregation, use a limited sample to avoid memory issues
    # Only fetch entity_counts for files with entities, with a reasonable limit
    entity_query = select(ScanResult.entity_counts).where(
        *conditions,
        ScanResult.entity_counts.isnot(None),
        ScanResult.total_entities > 0,
    ).limit(5000)  # Cap to prevent memory issues on very large datasets

    entity_result = await session.execute(entity_query)
    entity_rows = entity_result.scalars().all()

    # Aggregate entity counts in Python (JSON aggregation varies by DB)
    entity_totals: dict[str, int] = {}
    for entity_counts in entity_rows:
        if entity_counts:
            for entity_type, count in entity_counts.items():
                entity_totals[entity_type] = entity_totals.get(entity_type, 0) + count

    # Top 10 entity types
    top_entities = dict(sorted(entity_totals.items(), key=lambda x: x[1], reverse=True)[:10])

    return ResultStats(
        total_files=row.total_files or 0,
        files_with_pii=row.files_with_pii or 0,
        critical_count=row.critical_count or 0,
        high_count=row.high_count or 0,
        medium_count=row.medium_count or 0,
        low_count=row.low_count or 0,
        minimal_count=row.minimal_count or 0,
        top_entity_types=top_entities,
        labels_applied=row.labels_applied or 0,
        labels_pending=row.labels_pending or 0,
    )


@router.get("/export")
async def export_results(
    job_id: Optional[UUID] = Query(None, alias="scan_id", description="Job/Scan ID to export (optional)"),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier"),
    has_label: Optional[str] = Query(None, description="Filter by label status"),
    format: str = Query("csv", description="Export format (csv or json)"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> StreamingResponse:
    """Export scan results as CSV or JSON."""
    query = select(ScanResult).where(ScanResult.tenant_id == user.tenant_id)

    # Apply filters
    if job_id:
        query = query.where(ScanResult.job_id == job_id)
    if risk_tier:
        query = query.where(ScanResult.risk_tier == risk_tier)
    if has_label == "true":
        query = query.where(ScanResult.label_applied == True)  # noqa: E712
    elif has_label == "false":
        query = query.where(ScanResult.label_applied == False)  # noqa: E712

    result = await session.execute(query)
    results = result.scalars().all()

    # Generate filename based on filters
    filename_parts = ["results"]
    if job_id:
        filename_parts.append(str(job_id)[:8])
    if risk_tier:
        filename_parts.append(risk_tier.lower())
    filename = "_".join(filename_parts)

    if format == "csv":
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "file_path", "file_name", "risk_score", "risk_tier",
            "total_entities", "exposure_level", "owner",
            "current_label", "recommended_label", "label_applied",
        ])
        for r in results:
            writer.writerow([
                r.file_path, r.file_name, r.risk_score, r.risk_tier,
                r.total_entities, r.exposure_level, r.owner,
                r.current_label_name, r.recommended_label_name, r.label_applied,
            ])
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}.csv"},
        )
    else:
        import json
        data = [ResultResponse.model_validate(r).model_dump(mode="json") for r in results]
        return StreamingResponse(
            iter([json.dumps(data, indent=2)]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}.json"},
        )


@router.get("/{result_id}", response_model=ResultDetailResponse)
async def get_result(
    result_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ResultDetailResponse:
    """Get detailed scan result."""
    result = await session.get(ScanResult, result_id)
    if not result or result.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Result not found")
    return result


@router.delete("")
async def clear_all_results(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Clear all scan results for the tenant."""
    # Count results before deletion
    count_query = select(func.count()).where(ScanResult.tenant_id == user.tenant_id)
    count_result = await session.execute(count_query)
    deleted_count = count_result.scalar() or 0

    # Delete all results for tenant
    delete_query = delete(ScanResult).where(ScanResult.tenant_id == user.tenant_id)
    await session.execute(delete_query)
    await session.flush()

    # Check if this is an HTMX request
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="",
            status_code=200,
            headers={
                "HX-Trigger": f'{{"notify": {{"message": "{deleted_count} results cleared", "type": "success"}}}}',
            },
        )

    # Regular REST response
    return Response(status_code=204)


@router.delete("/{result_id}")
async def delete_result(
    result_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Delete a single scan result."""
    result = await session.get(ScanResult, result_id)
    if not result or result.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Result not found")

    file_name = result.file_name
    await session.delete(result)
    await session.flush()

    # Check if this is an HTMX request
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="",
            status_code=200,
            headers={
                "HX-Trigger": f'{{"notify": {{"message": "Result for \\"{file_name}\\" deleted", "type": "success"}}, "refreshResults": true}}',
            },
        )

    # Regular REST response
    return Response(status_code=204)


@router.post("/{result_id}/apply-label")
async def apply_recommended_label(
    result_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Apply the recommended label to a scan result."""
    from openlabels.jobs import JobQueue

    result = await session.get(ScanResult, result_id)
    if not result or result.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Result not found")

    # Check if there's a recommended label
    if not result.recommended_label_id:
        raise HTTPException(status_code=400, detail="No recommended label for this result")

    # Enqueue labeling job
    queue = JobQueue(session, user.tenant_id)
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


@router.post("/{result_id}/rescan")
async def rescan_file(
    result_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Rescan a specific file."""
    from openlabels.server.models import ScanJob
    from openlabels.jobs import JobQueue

    result = await session.get(ScanResult, result_id)
    if not result or result.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Result not found")

    # Get the target info from the original job
    target_name = "Rescan"
    target_id = None
    if result.job_id:
        job = await session.get(ScanJob, result.job_id)
        if job:
            target_name = job.target_name or "Rescan"
            target_id = job.target_id

    # target_id is required - if we can't find it, return an error
    if target_id is None:
        raise HTTPException(status_code=400, detail="Cannot rescan: original scan target not found")

    # Create a new scan job for just this file
    new_job = ScanJob(
        tenant_id=user.tenant_id,
        target_id=target_id,
        target_name=f"{target_name}: {result.file_name}",
        name=f"Rescan: {result.file_name}",
        status="pending",
        created_by=user.id,
    )
    session.add(new_job)
    await session.flush()

    # Enqueue the job
    queue = JobQueue(session, user.tenant_id)
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
