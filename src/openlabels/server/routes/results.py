"""
Scan results API endpoints.
"""

import logging
from datetime import datetime
from typing import Optional, Union
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select, func, delete, tuple_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.pagination import (
    encode_cursor,
    decode_cursor,
)

logger = logging.getLogger(__name__)
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
    """Paginated list of results (offset-based)."""

    items: list[ResultResponse]
    total: int
    page: int
    pages: int


class CursorResultListResponse(BaseModel):
    """Paginated list of results (cursor-based).

    This response format is more efficient for large datasets as it uses
    cursor-based pagination instead of offset-based pagination.
    """

    items: list[ResultResponse]
    next_cursor: Optional[str] = None
    has_more: bool = False


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


@router.get("", response_model=Union[ResultListResponse, CursorResultListResponse])
async def list_results(
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier"),
    has_pii: Optional[bool] = Query(None, description="Filter files with PII"),
    # Offset-based pagination parameters (backward compatible)
    page: Optional[int] = Query(None, ge=1, description="Page number for offset-based pagination"),
    # Cursor-based pagination parameters
    cursor: Optional[str] = Query(None, description="Cursor for cursor-based pagination (more efficient for large datasets)"),
    limit: int = Query(50, ge=1, le=100, description="Number of items per page"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> Union[ResultListResponse, CursorResultListResponse]:
    """List scan results with filtering and pagination.

    Supports two pagination modes:
    - Offset-based (default): Use `page` parameter. Returns total count and page info.
    - Cursor-based: Use `cursor` parameter. More efficient for large datasets (OFFSET 10000 scans 10K rows,
      cursor-based uses WHERE clause with indexed columns).

    If `cursor` is provided, cursor-based pagination is used.
    If `page` is provided (or neither), offset-based pagination is used for backward compatibility.
    """
    try:
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

        # Determine pagination mode: cursor-based if cursor provided, else offset-based
        use_cursor_pagination = cursor is not None

        if use_cursor_pagination:
            # Cursor-based pagination (efficient for large datasets)
            # Order by scanned_at DESC, id DESC for consistent ordering
            query = (
                select(ScanResult)
                .where(*conditions)
                .order_by(ScanResult.scanned_at.desc(), ScanResult.id.desc())
            )

            # Apply cursor filter if provided
            cursor_data = decode_cursor(cursor)
            if cursor_data:
                # WHERE (scanned_at, id) < (cursor_timestamp, cursor_id)
                # This efficiently seeks to the correct position using index
                query = query.where(
                    tuple_(ScanResult.scanned_at, ScanResult.id)
                    < (cursor_data.timestamp, cursor_data.id)
                )

            # Fetch one extra to check if there are more results
            query = query.limit(limit + 1)
            result = await session.execute(query)
            results = list(result.scalars().all())

            # Check if there are more results
            has_more = len(results) > limit
            if has_more:
                results = results[:limit]  # Remove the extra item

            # Generate next cursor from last item
            next_cursor = None
            if results and has_more:
                last_item = results[-1]
                next_cursor = encode_cursor(last_item.id, last_item.scanned_at)

            return CursorResultListResponse(
                items=[ResultResponse.model_validate(r) for r in results],
                next_cursor=next_cursor,
                has_more=has_more,
            )
        else:
            # Offset-based pagination (backward compatible)
            effective_page = page if page is not None else 1

            # Build main query with original ordering (by risk_score)
            query = select(ScanResult).where(*conditions).order_by(ScanResult.risk_score.desc())

            # Count total (with same filters)
            count_query = select(func.count()).select_from(
                select(ScanResult.id).where(*conditions)
            )
            result = await session.execute(count_query)
            total = result.scalar() or 0

            # Paginate
            query = query.offset((effective_page - 1) * limit).limit(limit)
            result = await session.execute(query)
            results = result.scalars().all()

            return ResultListResponse(
                items=[ResultResponse.model_validate(r) for r in results],
                total=total,
                page=effective_page,
                pages=(total + limit - 1) // limit if total > 0 else 1,
            )
    except SQLAlchemyError as e:
        logger.error(f"Database error listing results: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred")


@router.get("/stats", response_model=ResultStats)
async def get_result_stats(
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ResultStats:
    """Get aggregated statistics for scan results using efficient SQL aggregation."""
    try:
        # Build base filter conditions
        conditions = [ScanResult.tenant_id == user.tenant_id]
        if job_id:
            conditions.append(ScanResult.job_id == job_id)

        # Total files count
        total_query = select(func.count()).select_from(ScanResult).where(*conditions)
        total_result = await session.execute(total_query)
        total_files = total_result.scalar() or 0

        # Files with PII count
        pii_conditions = conditions + [ScanResult.total_entities > 0]
        pii_query = select(func.count()).select_from(ScanResult).where(*pii_conditions)
        pii_result = await session.execute(pii_query)
        files_with_pii = pii_result.scalar() or 0

        # Count by risk tier (single aggregation query)
        tier_query = (
            select(ScanResult.risk_tier, func.count())
            .where(*conditions)
            .group_by(ScanResult.risk_tier)
        )
        tier_result = await session.execute(tier_query)
        tier_counts_raw = dict(tier_result.all())
        tier_counts = {
            "CRITICAL": tier_counts_raw.get("CRITICAL", 0),
            "HIGH": tier_counts_raw.get("HIGH", 0),
            "MEDIUM": tier_counts_raw.get("MEDIUM", 0),
            "LOW": tier_counts_raw.get("LOW", 0),
            "MINIMAL": tier_counts_raw.get("MINIMAL", 0),
        }

        # Labels applied count
        applied_conditions = conditions + [ScanResult.label_applied == True]  # noqa: E712
        applied_query = select(func.count()).select_from(ScanResult).where(*applied_conditions)
        applied_result = await session.execute(applied_query)
        labels_applied = applied_result.scalar() or 0

        # Labels pending count (has recommended but not applied)
        pending_conditions = conditions + [
            ScanResult.label_applied == False,  # noqa: E712
            ScanResult.recommended_label_id.isnot(None),
        ]
        pending_query = select(func.count()).select_from(ScanResult).where(*pending_conditions)
        pending_result = await session.execute(pending_query)
        labels_pending = pending_result.scalar() or 0

        # For entity type aggregation, we need to query entity_counts JSON
        # This requires fetching just the entity_counts column, not full rows
        entity_query = select(ScanResult.entity_counts).where(
            *conditions,
            ScanResult.entity_counts.isnot(None),
        )
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
    except SQLAlchemyError as e:
        logger.error(f"Database error getting result stats: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred")


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
    try:
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
    except SQLAlchemyError as e:
        logger.error(f"Database error exporting results: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred")


@router.get("/{result_id}", response_model=ResultDetailResponse)
async def get_result(
    result_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ResultDetailResponse:
    """Get detailed scan result."""
    try:
        result = await session.get(ScanResult, result_id)
        if not result or result.tenant_id != user.tenant_id:
            raise HTTPException(status_code=404, detail="Result not found")
        return result
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error getting result {result_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred")


@router.delete("")
async def clear_all_results(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Clear all scan results for the tenant."""
    try:
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
    except SQLAlchemyError as e:
        logger.error(f"Database error clearing results: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred")


@router.delete("/{result_id}")
async def delete_result(
    result_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Delete a single scan result."""
    try:
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
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error deleting result {result_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred")


@router.post("/{result_id}/apply-label")
async def apply_recommended_label(
    result_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Apply the recommended label to a scan result."""
    from openlabels.jobs import JobQueue

    try:
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
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error applying label to result {result_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred")


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

    try:
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
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error rescanning result {result_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred")
