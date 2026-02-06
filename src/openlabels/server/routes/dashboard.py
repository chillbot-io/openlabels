"""
Dashboard API endpoints for statistics and visualizations.

All dashboard queries use SQL aggregation for performance at scale.
Statistics are computed in PostgreSQL, not Python.

Performance:
- Dashboard stats are cached with short TTL (60s) since data changes frequently
- Trends data uses longer cache TTL since historical data is stable
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func, case, cast, Date, and_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import ScanJob, ScanResult
from openlabels.server.cache import get_cache_manager
from openlabels.auth.dependencies import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter()

# Cache key prefixes and TTLs
DASHBOARD_STATS_CACHE_PREFIX = "dashboard:stats"
DASHBOARD_STATS_TTL = 60  # 60 seconds - stats change frequently


class OverallStats(BaseModel):
    """Overall dashboard statistics."""

    total_scans: int
    total_files_scanned: int
    files_with_pii: int
    labels_applied: int
    critical_files: int
    high_files: int
    active_scans: int


class TrendPoint(BaseModel):
    """Single point in a trend."""

    date: str
    files_scanned: int
    files_with_pii: int
    labels_applied: int


class TrendResponse(BaseModel):
    """Trend data over time."""

    points: list[TrendPoint]


class HeatmapNode(BaseModel):
    """Node in the heatmap tree."""

    name: str
    path: str
    type: str  # 'folder' | 'file'
    risk_score: int
    entity_counts: dict[str, int]
    children: Optional[list["HeatmapNode"]] = None


class HeatmapResponse(BaseModel):
    """Heatmap tree data."""

    roots: list[HeatmapNode]
    truncated: bool = False
    total_files: int = 0
    limit_applied: int = 0


@router.get("/stats", response_model=OverallStats)
async def get_overall_stats(
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get overall dashboard statistics.

    Uses SQL aggregation for efficient computation at scale.
    All counts are computed in PostgreSQL, not Python.

    Results are cached for 60 seconds to reduce database load.
    """
    # Try to get from cache first
    cache_key = f"{DASHBOARD_STATS_CACHE_PREFIX}:tenant:{user.tenant_id}"
    try:
        cache = await get_cache_manager()
        cached = await cache.get(cache_key)
        if cached is not None:
            logger.debug(f"Cache hit for dashboard stats (tenant: {user.tenant_id})")
            return OverallStats(**cached)
    except (ConnectionError, OSError, RuntimeError) as e:
        logger.debug(f"Cache read failed: {e}")

    # Count total and active scans in one query
    scan_stats_query = select(
        func.count().label("total"),
        func.sum(
            case((ScanJob.status.in_(["pending", "running"]), 1), else_=0)
        ).label("active"),
    ).where(ScanJob.tenant_id == user.tenant_id)

    result = await session.execute(scan_stats_query)
    scan_row = result.one()
    total_scans = scan_row.total or 0
    active_scans = scan_row.active or 0

    # Get all result stats in one aggregation query
    result_stats_query = select(
        func.count().label("total_files"),
        func.sum(case((ScanResult.total_entities > 0, 1), else_=0)).label("files_with_pii"),
        func.sum(case((ScanResult.label_applied == True, 1), else_=0)).label("labels_applied"),  # noqa: E712
        func.sum(case((ScanResult.risk_tier == "CRITICAL", 1), else_=0)).label("critical_files"),
        func.sum(case((ScanResult.risk_tier == "HIGH", 1), else_=0)).label("high_files"),
    ).where(ScanResult.tenant_id == user.tenant_id)

    result = await session.execute(result_stats_query)
    stats_row = result.one()

    response = OverallStats(
        total_scans=total_scans,
        total_files_scanned=stats_row.total_files or 0,
        files_with_pii=stats_row.files_with_pii or 0,
        labels_applied=stats_row.labels_applied or 0,
        critical_files=stats_row.critical_files or 0,
        high_files=stats_row.high_files or 0,
        active_scans=active_scans,
    )

    # Cache the result with short TTL
    try:
        cache = await get_cache_manager()
        await cache.set(cache_key, response.model_dump(), ttl=DASHBOARD_STATS_TTL)
        logger.debug(f"Cached dashboard stats for tenant: {user.tenant_id}")
    except (ConnectionError, OSError, RuntimeError) as e:
        logger.debug(f"Cache write failed: {e}")

    return response


@router.get("/trends", response_model=TrendResponse)
async def get_trends(
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get trend data over time.

    Uses SQL GROUP BY for efficient aggregation at scale.
    Results are grouped by date in PostgreSQL.
    """
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)

    # Use SQL aggregation with GROUP BY date
    # Cast scanned_at to date for grouping
    scan_date = cast(ScanResult.scanned_at, Date)

    trend_query = (
        select(
            scan_date.label("scan_date"),
            func.count().label("files_scanned"),
            func.sum(case((ScanResult.total_entities > 0, 1), else_=0)).label("files_with_pii"),
            func.sum(case((ScanResult.label_applied == True, 1), else_=0)).label("labels_applied"),  # noqa: E712
        )
        .where(
            and_(
                ScanResult.tenant_id == user.tenant_id,
                ScanResult.scanned_at >= start_date,
            )
        )
        .group_by(scan_date)
        .order_by(scan_date)
    )

    result = await session.execute(trend_query)
    rows = result.all()

    # Convert to dict for easy lookup
    daily_stats = {
        row.scan_date.strftime("%Y-%m-%d"): {
            "files_scanned": row.files_scanned or 0,
            "files_with_pii": row.files_with_pii or 0,
            "labels_applied": row.labels_applied or 0,
        }
        for row in rows
    }

    # Fill in missing dates with zeros
    points = []
    current = start_date
    while current <= end_date:
        date_str = current.strftime("%Y-%m-%d")
        stats = daily_stats.get(date_str, {
            "files_scanned": 0,
            "files_with_pii": 0,
            "labels_applied": 0,
        })
        points.append(TrendPoint(date=date_str, **stats))
        current += timedelta(days=1)

    return TrendResponse(points=points)


class EntityTrendsResponse(BaseModel):
    """Entity type trends over time for charts."""

    series: dict[str, list[tuple[str, int]]]  # entity_type -> [(date, count), ...]
    truncated: bool = False
    total_records: int = 0


# Maximum number of records to process for entity aggregation
ENTITY_TRENDS_LIMIT = 50000


@router.get("/entity-trends", response_model=EntityTrendsResponse)
async def get_entity_trends(
    days: int = Query(14, ge=1, le=90, description="Number of days to include"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get entity type detection trends over time.

    Returns counts by entity type per day, suitable for time series charts.
    Uses SQL aggregation with LIMIT to avoid loading excessive data into memory.
    """
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)
    scan_date = cast(ScanResult.scanned_at, Date)

    # First, get daily totals using SQL aggregation (efficient)
    totals_query = (
        select(
            scan_date.label("scan_date"),
            func.sum(ScanResult.total_entities).label("total"),
        )
        .where(
            and_(
                ScanResult.tenant_id == user.tenant_id,
                ScanResult.scanned_at >= start_date,
                ScanResult.total_entities > 0,
            )
        )
        .group_by(scan_date)
        .order_by(scan_date)
    )
    totals_result = await session.execute(totals_query)
    daily_totals = {
        row.scan_date.strftime("%Y-%m-%d"): row.total or 0
        for row in totals_result.all()
    }

    # For entity type breakdown, use a limited sample to determine top types
    # This avoids loading massive JSONB data while still providing useful trends
    # Limit to recent files with entities to keep query efficient
    sample_query = select(
        ScanResult.entity_counts,
    ).where(
        and_(
            ScanResult.tenant_id == user.tenant_id,
            ScanResult.scanned_at >= start_date,
            ScanResult.entity_counts.isnot(None),
            ScanResult.total_entities > 0,
        )
    ).order_by(ScanResult.scanned_at.desc()).limit(1000)  # Sample recent files

    sample_result = await session.execute(sample_query)
    sample_rows = sample_result.scalars().all()

    # Aggregate entity types from sample to find top types
    type_totals: dict[str, int] = {}
    for entity_counts in sample_rows:
        if entity_counts:
            for entity_type, count in entity_counts.items():
                type_totals[entity_type] = type_totals.get(entity_type, 0) + count

    top_types = sorted(type_totals.keys(), key=lambda t: type_totals[t], reverse=True)[:6]

    # For top types, get daily counts with a more targeted query
    # Only fetch scanned_at and entity_counts for files with entities
    daily_counts: dict[str, dict[str, int]] = {}
    total_records = 0
    detail_limit = 5000
    if top_types:
        detailed_query = select(
            ScanResult.scanned_at,
            ScanResult.entity_counts,
        ).where(
            and_(
                ScanResult.tenant_id == user.tenant_id,
                ScanResult.scanned_at >= start_date,
                ScanResult.entity_counts.isnot(None),
                ScanResult.total_entities > 0,
            )
        ).limit(detail_limit)  # Cap to prevent memory issues on very large datasets

        detailed_result = await session.execute(detailed_query)
        rows = detailed_result.all()
        total_records = len(rows)
        for row in rows:
            date_str = row.scanned_at.strftime("%Y-%m-%d")
            if date_str not in daily_counts:
                daily_counts[date_str] = {}
            entity_counts = row.entity_counts or {}
            for entity_type in top_types:
                if entity_type in entity_counts:
                    daily_counts[date_str][entity_type] = (
                        daily_counts[date_str].get(entity_type, 0) + entity_counts[entity_type]
                    )
    truncated = total_records >= detail_limit

    # Build series data - always include Total
    series: dict[str, list[tuple[str, int]]] = {"Total": []}
    for entity_type in top_types:
        series[entity_type] = []

    # Fill in data for each date
    current = start_date
    while current <= end_date:
        date_str = current.strftime("%Y-%m-%d")

        # Total from SQL aggregation
        series["Total"].append((date_str, daily_totals.get(date_str, 0)))

        # By type from detailed query
        day_counts = daily_counts.get(date_str, {})
        for entity_type in top_types:
            series[entity_type].append((date_str, day_counts.get(entity_type, 0)))

        current += timedelta(days=1)

    return EntityTrendsResponse(series=series, truncated=truncated, total_records=total_records)


async def _aggregate_entity_counts_streaming(
    session: AsyncSession,
    tenant_id: UUID,
    start_date: datetime,
    limit: int,
) -> dict[str, dict[str, int]]:
    """
    Fallback streaming aggregation for entity counts.

    Uses server-side cursor to stream results in batches, avoiding memory explosion.
    """
    from sqlalchemy import select

    daily_counts: dict[str, dict[str, int]] = {}
    processed = 0
    batch_size = 1000

    # Use yield_per for streaming to avoid loading all into memory
    query = (
        select(
            cast(ScanResult.scanned_at, Date).label("scan_date"),
            ScanResult.entity_counts,
        )
        .where(
            and_(
                ScanResult.tenant_id == tenant_id,
                ScanResult.scanned_at >= start_date,
                ScanResult.entity_counts.isnot(None),
            )
        )
        .order_by(ScanResult.scanned_at.desc())
        .limit(limit)
    )

    # Execute with streaming
    result = await session.stream(query)

    async for partition in result.partitions(batch_size):
        for row in partition:
            date_str = row.scan_date.strftime("%Y-%m-%d")
            if date_str not in daily_counts:
                daily_counts[date_str] = {}

            entity_counts = row.entity_counts or {}
            for entity_type, count in entity_counts.items():
                if entity_type not in daily_counts[date_str]:
                    daily_counts[date_str][entity_type] = 0
                daily_counts[date_str][entity_type] += count

            processed += 1

        # Safety check
        if processed >= limit:
            break

    return daily_counts


class AccessHeatmapResponse(BaseModel):
    """File access heatmap data (7 days x 24 hours)."""

    data: list[list[int]]  # 7x24 matrix


@router.get("/access-heatmap", response_model=AccessHeatmapResponse)
async def get_access_heatmap(
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get file access activity heatmap by hour and day of week.

    Returns a 7x24 matrix where data[day][hour] = access count.
    Day 0 = Monday, day 6 = Sunday.

    Uses SQL GROUP BY with EXTRACT for efficient aggregation instead of
    loading all events into Python memory.
    """
    from openlabels.server.models import FileAccessEvent
    from sqlalchemy import extract

    # Get access events from last 4 weeks
    cutoff = datetime.now(timezone.utc) - timedelta(days=28)

    # Build 7x24 matrix
    heatmap = [[0] * 24 for _ in range(7)]

    try:
        # Use SQL aggregation with EXTRACT for day of week and hour
        # PostgreSQL: EXTRACT(DOW FROM timestamp) returns 0=Sunday, 1=Monday, etc.
        # We need to adjust to Python's weekday() which is 0=Monday
        # ISODOW returns 1=Monday through 7=Sunday (ISO 8601)
        heatmap_query = (
            select(
                extract('isodow', FileAccessEvent.event_time).label("day_of_week"),
                extract('hour', FileAccessEvent.event_time).label("hour"),
                func.count().label("count"),
            )
            .where(
                and_(
                    FileAccessEvent.tenant_id == user.tenant_id,
                    FileAccessEvent.event_time >= cutoff,
                )
            )
            .group_by(
                extract('isodow', FileAccessEvent.event_time),
                extract('hour', FileAccessEvent.event_time),
            )
        )

        result = await session.execute(heatmap_query)
        rows = result.all()

        # Populate heatmap from aggregated results
        # ISODOW: 1=Monday, 7=Sunday -> convert to 0=Monday, 6=Sunday
        for row in rows:
            day = int(row.day_of_week) - 1  # Convert ISODOW to 0-indexed Monday
            if day == -1:  # Handle edge case if DOW returns 0
                day = 6
            hour = int(row.hour)
            if 0 <= day < 7 and 0 <= hour < 24:
                heatmap[day][hour] = row.count

    except (SQLAlchemyError, RuntimeError) as e:
        # FileAccessEvent table may not exist, return empty heatmap
        logger.debug(f"Access heatmap query failed (table may not exist): {e}")

    return AccessHeatmapResponse(data=heatmap)


# Maximum number of files to load for heatmap to prevent memory explosion
HEATMAP_MAX_FILES = 10000

# Maximum depth for folder aggregation (deeper files rolled up)
HEATMAP_MAX_DEPTH = 10


@router.get("/heatmap", response_model=HeatmapResponse)
async def get_heatmap(
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
    limit: int = Query(HEATMAP_MAX_FILES, ge=1, le=HEATMAP_MAX_FILES, description="Max files to include"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get heatmap tree data for visualization.

    To prevent memory explosion with large datasets:
    - Limited to top N files by risk_score (default 10,000)
    - Uses streaming to build tree incrementally
    - Returns truncation indicator if limit was hit
    """
    # First, get total count to determine if truncation is needed
    count_query = select(func.count()).select_from(ScanResult).where(
        ScanResult.tenant_id == user.tenant_id
    )
    if job_id:
        count_query = count_query.where(ScanResult.job_id == job_id)

    count_result = await session.execute(count_query)
    total_files = count_result.scalar() or 0

    truncated = total_files > limit
    if truncated:
        logger.warning(
            f"Heatmap query truncated: {total_files} files exceed limit of {limit}. "
            "Returning highest risk files only."
        )

    # Query with limit, ordered by risk_score to get most important files first
    # Only select needed columns to reduce memory usage
    query = (
        select(
            ScanResult.file_path,
            ScanResult.risk_score,
            ScanResult.entity_counts,
        )
        .where(ScanResult.tenant_id == user.tenant_id)
        .order_by(ScanResult.risk_score.desc())
        .limit(limit)
    )
    if job_id:
        query = query.where(ScanResult.job_id == job_id)

    # Use streaming to avoid loading all results at once
    result = await session.stream(query)

    # Build tree structure incrementally from file paths
    tree: dict = {}
    files_processed = 0

    async for partition in result.partitions(1000):
        for row in partition:
            files_processed += 1
            parts = row.file_path.replace("\\", "/").split("/")
            # Filter out empty parts (from leading slashes like /path/to/file)
            parts = [p for p in parts if p]
            if not parts:
                continue

            # Limit depth to prevent excessive nesting
            if len(parts) > HEATMAP_MAX_DEPTH:
                # Roll up deep paths: keep first (DEPTH-1) folders + "..." + filename
                truncated_parts = parts[:HEATMAP_MAX_DEPTH - 1] + ["..."] + [parts[-1]]
                parts = truncated_parts

            current = tree
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {"_children": {}, "_stats": {"risk_score": 0, "entity_counts": {}}}
                current = current[part]["_children"]

            # Add file
            filename = parts[-1]
            current[filename] = {
                "_is_file": True,
                "_stats": {
                    "risk_score": row.risk_score or 0,
                    "entity_counts": row.entity_counts or {},
                },
            }

    def build_node(name: str, data: dict, path: str) -> HeatmapNode:
        """Recursively build heatmap nodes."""
        if data.get("_is_file"):
            return HeatmapNode(
                name=name,
                path=path,
                type="file",
                risk_score=data["_stats"]["risk_score"],
                entity_counts=data["_stats"]["entity_counts"],
            )

        # It's a folder - process children
        children = []
        total_score = 0
        total_entities: dict[str, int] = {}

        for child_name, child_data in data.get("_children", {}).items():
            child_path = f"{path}/{child_name}" if path else child_name
            child_node = build_node(child_name, child_data, child_path)
            children.append(child_node)
            total_score += child_node.risk_score
            # Aggregate entity counts
            for entity_type, count in (child_node.entity_counts or {}).items():
                total_entities[entity_type] = total_entities.get(entity_type, 0) + count

        # Sort children by risk_score descending for better visualization
        children.sort(key=lambda n: n.risk_score, reverse=True)

        return HeatmapNode(
            name=name,
            path=path,
            type="folder",
            risk_score=total_score,
            entity_counts=total_entities,
            children=children if children else None,
        )

    # Build response tree
    roots = []
    for root_name, root_data in tree.items():
        roots.append(build_node(root_name, root_data, root_name))

    # Sort roots by risk_score descending
    roots.sort(key=lambda n: n.risk_score, reverse=True)

    return HeatmapResponse(
        roots=roots,
        truncated=truncated,
        total_files=total_files,
        limit_applied=limit,
    )
