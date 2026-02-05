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

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.config import get_settings
from openlabels.server.models import ScanResult

logger = logging.getLogger(__name__)
from openlabels.server.pagination import (
    HybridPaginationParams,
    PaginatedResponse,
    CursorPaginatedResponse,
    LegacyPaginatedResponse,
    PaginationMeta,
    CursorPaginationMeta,
    apply_cursor_pagination,
    build_cursor_response,
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


# Legacy response format for backward compatibility
class ResultListResponse(BaseModel):
    """
    Paginated list of results (legacy format).

    DEPRECATED: New clients should use the standardized format with
    `data` and `pagination` fields. This format is maintained for
    backward compatibility.
    """

    items: list[ResultResponse]
    total: int
    page: int
    pages: int
    # New fields for forward compatibility
    page_size: Optional[int] = None
    has_more: Optional[bool] = None


# New standardized response formats
class ResultPaginatedResponse(BaseModel):
    """
    Standardized paginated response for scan results.

    Supports both cursor-based and offset-based pagination.
    """

    data: list[ResultResponse] = Field(description="List of scan results")
    pagination: Union[CursorPaginationMeta, PaginationMeta] = Field(
        description="Pagination metadata"
    )


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


@router.get("")
async def list_results(
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier"),
    has_pii: Optional[bool] = Query(None, description="Filter files with PII"),
    # Cursor-based pagination (recommended for large datasets)
    cursor: Optional[str] = Query(
        None,
        description="Cursor for next page (use this for efficient pagination of large datasets)",
    ),
    # Offset-based pagination (for backward compatibility)
    page: int = Query(1, ge=1, description="Page number (ignored if cursor is provided)"),
    limit: int = Query(50, ge=1, le=100, alias="page_size", description="Items per page"),
    # Optional total count
    include_total: bool = Query(
        True,
        description="Include total count (set to false for faster queries on large datasets)",
    ),
    # Response format
    format: str = Query(
        "legacy",
        description="Response format: 'legacy' (items/total/page/pages), 'standard' (data/pagination)",
    ),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> Union[ResultListResponse, ResultPaginatedResponse]:
    """
    List scan results with filtering and pagination.

    Supports two pagination modes:
    - **Cursor-based** (recommended for large datasets): Pass `cursor` from previous response
    - **Offset-based** (backward compatible): Use `page` and `page_size` parameters

    Supports two response formats:
    - **legacy** (default): `{items, total, page, pages}` for backward compatibility
    - **standard**: `{data, pagination}` with cursor support

    Example cursor-based pagination:
    ```
    GET /api/results?page_size=50&format=standard
    # Returns: {"data": [...], "pagination": {"cursor": "abc123", "has_more": true}}

    GET /api/results?cursor=abc123&page_size=50&format=standard
    # Returns next page
    ```
    """
    settings = get_settings()
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

        # Count total if requested (skip for cursor-based pagination without include_total)
        total = None
        if include_total:
            count_query = select(func.count()).select_from(
                select(ScanResult.id).where(*conditions).subquery()
            )
            result = await session.execute(count_query)
            total = result.scalar() or 0

        # Use cursor-based pagination if cursor is provided or standard format requested
        if cursor is not None or format == "standard":
            # Cursor-based pagination using scanned_at as sort key
            from openlabels.server.pagination import (
                CursorPaginationParams,
                decode_cursor,
                encode_cursor,
            )

            # Build base query with filters
            query = select(ScanResult).where(*conditions)

            # Apply cursor-based pagination
            pagination_params = CursorPaginationParams(
                cursor=cursor,
                limit=limit,
                include_total=include_total,
            )
            query, cursor_info = apply_cursor_pagination(
                query,
                ScanResult,
                pagination_params,
                sort_column=ScanResult.scanned_at,
                sort_desc=True,
            )

            result = await session.execute(query)
            results = list(result.scalars().all())

            # Build pagination metadata
            pagination_meta = build_cursor_response(results, cursor_info, total)

            # Trim extra result used for has_more check
            actual_results = results[: pagination_params.limit]

            if format == "standard":
                return ResultPaginatedResponse(
                    data=[ResultResponse.model_validate(r) for r in actual_results],
                    pagination=pagination_meta,
                )
            else:
                # Legacy format with cursor info added
                pages = (total + limit - 1) // limit if total and total > 0 else 1
                return ResultListResponse(
                    items=[ResultResponse.model_validate(r) for r in actual_results],
                    total=total or 0,
                    page=page,
                    pages=pages,
                    page_size=limit,
                    has_more=pagination_meta.has_more,
                )

        # Offset-based pagination (legacy mode)
        query = (
            select(ScanResult)
            .where(*conditions)
            .order_by(ScanResult.scanned_at.desc())
            .offset((page - 1) * limit)
            .limit(limit)
        )
        result = await session.execute(query)
        results = result.scalars().all()

        # For offset pagination without total, we need to count
        if total is None:
            count_query = select(func.count()).select_from(
                select(ScanResult.id).where(*conditions).subquery()
            )
            result = await session.execute(count_query)
            total = result.scalar() or 0

        pages = (total + limit - 1) // limit if total > 0 else 1

        if format == "standard":
            return ResultPaginatedResponse(
                data=[ResultResponse.model_validate(r) for r in results],
                pagination=PaginationMeta.from_offset(total, page, limit),
            )

        return ResultListResponse(
            items=[ResultResponse.model_validate(r) for r in results],
            total=total,
            page=page,
            pages=pages,
            page_size=limit,
            has_more=page < pages,
        )
    except SQLAlchemyError as e:
        logger.error(f"Database error in list_results: {e}")
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in list_results: {e}")
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


@router.get("/stats", response_model=ResultStats)
async def get_result_stats(
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ResultStats:
    """Get aggregated statistics for scan results using efficient SQL aggregation."""
    settings = get_settings()
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
        logger.error(f"Database error in get_result_stats: {e}")
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in get_result_stats: {e}")
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


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
    settings = get_settings()
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
        logger.error(f"Database error in export_results: {e}")
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in export_results: {e}")
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


@router.get("/{result_id}", response_model=ResultDetailResponse)
async def get_result(
    result_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> ResultDetailResponse:
    """Get detailed scan result."""
    settings = get_settings()
    try:
        result = await session.get(ScanResult, result_id)
        if not result or result.tenant_id != user.tenant_id:
            raise HTTPException(status_code=404, detail="Result not found")
        return result
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error in get_result: {e}")
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in get_result: {e}")
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


@router.delete("")
async def clear_all_results(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Clear all scan results for the tenant."""
    settings = get_settings()
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
        logger.error(f"Database error in clear_all_results: {e}")
        await session.rollback()
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in clear_all_results: {e}")
        await session.rollback()
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


@router.delete("/{result_id}")
async def delete_result(
    result_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Delete a single scan result."""
    settings = get_settings()
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
        logger.error(f"Database error in delete_result: {e}")
        await session.rollback()
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in delete_result: {e}")
        await session.rollback()
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


@router.post("/{result_id}/apply-label")
async def apply_recommended_label(
    result_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Apply the recommended label to a scan result."""
    from openlabels.jobs import JobQueue

    settings = get_settings()
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
        logger.error(f"Database error in apply_recommended_label: {e}")
        await session.rollback()
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in apply_recommended_label: {e}")
        await session.rollback()
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)


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

    settings = get_settings()
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
        logger.error(f"Database error in rescan_file: {e}")
        await session.rollback()
        detail = f"Database error: {str(e)}" if settings.server.environment != "production" else "Database operation failed"
        raise HTTPException(status_code=500, detail=detail)
    except Exception as e:
        logger.error(f"Unexpected error in rescan_file: {e}")
        await session.rollback()
        detail = f"Internal error: {str(e)}" if settings.server.environment != "production" else "An unexpected error occurred"
        raise HTTPException(status_code=500, detail=detail)
