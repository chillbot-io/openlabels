"""
Dashboard API endpoints for statistics and visualizations.

All dashboard queries use SQL aggregation for performance at scale.
Statistics are computed in PostgreSQL, not Python.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query

logger = logging.getLogger(__name__)
from pydantic import BaseModel
from sqlalchemy import select, func, case, cast, Date, and_
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import ScanJob, ScanResult
from openlabels.auth.dependencies import get_current_user

router = APIRouter()


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


@router.get("/stats", response_model=OverallStats)
async def get_overall_stats(
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get overall dashboard statistics.

    Uses SQL aggregation for efficient computation at scale.
    All counts are computed in PostgreSQL, not Python.
    """
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

    return OverallStats(
        total_scans=total_scans,
        total_files_scanned=stats_row.total_files or 0,
        files_with_pii=stats_row.files_with_pii or 0,
        labels_applied=stats_row.labels_applied or 0,
        critical_files=stats_row.critical_files or 0,
        high_files=stats_row.high_files or 0,
        active_scans=active_scans,
    )


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


@router.get("/entity-trends", response_model=EntityTrendsResponse)
async def get_entity_trends(
    days: int = Query(14, ge=1, le=90, description="Number of days to include"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get entity type detection trends over time.

    Returns counts by entity type per day, suitable for time series charts.
    """
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)

    # Get results with entity counts
    results_query = select(
        ScanResult.scanned_at,
        ScanResult.entity_counts,
    ).where(
        and_(
            ScanResult.tenant_id == user.tenant_id,
            ScanResult.scanned_at >= start_date,
            ScanResult.entity_counts.isnot(None),
        )
    )

    result = await session.execute(results_query)
    rows = result.all()

    # Aggregate by date and entity type
    daily_counts: dict[str, dict[str, int]] = {}  # date -> {entity_type -> count}

    for row in rows:
        date_str = row.scanned_at.strftime("%Y-%m-%d")
        if date_str not in daily_counts:
            daily_counts[date_str] = {}

        entity_counts = row.entity_counts or {}
        for entity_type, count in entity_counts.items():
            if entity_type not in daily_counts[date_str]:
                daily_counts[date_str][entity_type] = 0
            daily_counts[date_str][entity_type] += count

    # Collect all entity types
    all_entity_types = set()
    for counts in daily_counts.values():
        all_entity_types.update(counts.keys())

    # Build series data - always include Total
    series: dict[str, list[tuple[str, int]]] = {"Total": []}

    # Add top entity types (by total count)
    type_totals = {}
    for entity_type in all_entity_types:
        type_totals[entity_type] = sum(
            daily_counts[d].get(entity_type, 0) for d in daily_counts
        )

    top_types = sorted(type_totals.keys(), key=lambda t: type_totals[t], reverse=True)[:6]

    for entity_type in top_types:
        series[entity_type] = []

    # Fill in data for each date
    current = start_date
    while current <= end_date:
        date_str = current.strftime("%Y-%m-%d")
        day_counts = daily_counts.get(date_str, {})

        # Total
        total = sum(day_counts.values())
        series["Total"].append((date_str, total))

        # By type
        for entity_type in top_types:
            count = day_counts.get(entity_type, 0)
            series[entity_type].append((date_str, count))

        current += timedelta(days=1)

    return EntityTrendsResponse(series=series)


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
    """
    from openlabels.server.models import FileAccessEvent

    # Get access events from last 4 weeks
    cutoff = datetime.now(timezone.utc) - timedelta(days=28)

    try:
        events_query = select(
            FileAccessEvent.accessed_at,
        ).where(
            and_(
                FileAccessEvent.tenant_id == user.tenant_id,
                FileAccessEvent.accessed_at >= cutoff,
            )
        )

        result = await session.execute(events_query)
        rows = result.all()

        # Build 7x24 matrix
        heatmap = [[0] * 24 for _ in range(7)]

        for row in rows:
            day = row.accessed_at.weekday()
            hour = row.accessed_at.hour
            heatmap[day][hour] += 1

    except Exception as e:
        # FileAccessEvent table may not exist, return empty heatmap
        logger.debug(f"Access heatmap query failed (table may not exist): {e}")
        heatmap = [[0] * 24 for _ in range(7)]

    return AccessHeatmapResponse(data=heatmap)


@router.get("/heatmap", response_model=HeatmapResponse)
async def get_heatmap(
    job_id: Optional[UUID] = Query(None, description="Filter by job ID"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """Get heatmap tree data for visualization."""
    query = select(ScanResult).where(ScanResult.tenant_id == user.tenant_id)
    if job_id:
        query = query.where(ScanResult.job_id == job_id)

    result = await session.execute(query)
    results = result.scalars().all()

    # Build tree structure from file paths
    tree: dict = {}
    for r in results:
        parts = r.file_path.replace("\\", "/").split("/")
        current = tree
        for i, part in enumerate(parts[:-1]):
            if part not in current:
                current[part] = {"_children": {}, "_stats": {"risk_score": 0, "entity_counts": {}}}
            current = current[part]["_children"]

        # Add file
        filename = parts[-1]
        current[filename] = {
            "_is_file": True,
            "_stats": {
                "risk_score": r.risk_score,
                "entity_counts": r.entity_counts or {},
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

        children = []
        total_score = 0
        total_entities: dict[str, int] = {}

        for child_name, child_data in data.get("_children", {}).items():
            child_path = f"{path}/{child_name}" if path else child_name
            child_node = build_node(child_name, child_data, child_path)
            children.append(child_node)
            total_score += child_node.risk_score
            for entity_type, count in child_node.entity_counts.items():
                total_entities[entity_type] = total_entities.get(entity_type, 0) + count

        return HeatmapNode(
            name=name,
            path=path,
            type="folder",
            risk_score=total_score,
            entity_counts=total_entities,
            children=children if children else None,
        )

    roots = []
    for root_name, root_data in tree.items():
        roots.append(build_node(root_name, root_data, root_name))

    return HeatmapResponse(roots=roots)
