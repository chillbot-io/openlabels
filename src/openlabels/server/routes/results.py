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


class ResultListResponse(BaseModel):
    """Paginated list of results."""

    items: list[ResultResponse]
    total: int
    page: int
    pages: int


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


@router.get("", response_model=ResultListResponse)
async def list_results(
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier"),
    has_pii: Optional[bool] = Query(None, description="Filter files with PII"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ResultListResponse:
    """List scan results with filtering and pagination."""
    query = select(ScanResult).where(ScanResult.tenant_id == user.tenant_id)

    if job_id:
        query = query.where(ScanResult.job_id == job_id)
    if risk_tier:
        query = query.where(ScanResult.risk_tier == risk_tier)
    if has_pii is not None:
        if has_pii:
            query = query.where(ScanResult.total_entities > 0)
        else:
            query = query.where(ScanResult.total_entities == 0)

    query = query.order_by(ScanResult.risk_score.desc())

    # Count total
    count_query = select(func.count()).select_from(
        select(ScanResult.id).where(ScanResult.tenant_id == user.tenant_id)
    )
    result = await session.execute(count_query)
    total = result.scalar() or 0

    # Paginate
    query = query.offset((page - 1) * limit).limit(limit)
    result = await session.execute(query)
    results = result.scalars().all()

    return ResultListResponse(
        items=[ResultResponse.model_validate(r) for r in results],
        total=total,
        page=page,
        pages=(total + limit - 1) // limit if total > 0 else 1,
    )


@router.get("/stats", response_model=ResultStats)
async def get_result_stats(
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ResultStats:
    """Get aggregated statistics for scan results."""
    base_query = select(ScanResult).where(ScanResult.tenant_id == user.tenant_id)
    if job_id:
        base_query = base_query.where(ScanResult.job_id == job_id)

    result = await session.execute(base_query)
    results = result.scalars().all()

    # Calculate stats
    total_files = len(results)
    files_with_pii = sum(1 for r in results if r.total_entities > 0)

    tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
    entity_totals: dict[str, int] = {}
    labels_applied = 0
    labels_pending = 0

    for r in results:
        tier_counts[r.risk_tier] = tier_counts.get(r.risk_tier, 0) + 1
        for entity_type, count in (r.entity_counts or {}).items():
            entity_totals[entity_type] = entity_totals.get(entity_type, 0) + count
        if r.label_applied:
            labels_applied += 1
        elif r.recommended_label_id:
            labels_pending += 1

    # Top 10 entity types
    top_entities = dict(sorted(entity_totals.items(), key=lambda x: x[1], reverse=True)[:10])

    return ResultStats(
        total_files=total_files,
        files_with_pii=files_with_pii,
        critical_count=tier_counts["CRITICAL"],
        high_count=tier_counts["HIGH"],
        medium_count=tier_counts["MEDIUM"],
        low_count=tier_counts["LOW"],
        minimal_count=tier_counts["MINIMAL"],
        top_entity_types=top_entities,
        labels_applied=labels_applied,
        labels_pending=labels_pending,
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

    # Get the target name from the original job if available
    target_name = "Rescan"
    if result.job_id:
        job = await session.get(ScanJob, result.job_id)
        if job:
            target_name = job.target_name or "Rescan"

    # Create a new scan job for just this file
    new_job = ScanJob(
        tenant_id=user.tenant_id,
        target_id=None,  # No specific target
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
