"""
Dashboard API endpoints for statistics and visualizations.

Analytical queries are served by the DuckDB-backed
:class:`DashboardQueryService`, reading columnar Parquet files with no
sampling caps or streaming workarounds.

Route handlers are backend-agnostic: they call the service, format the
response, and manage caching.

Performance:
- Dashboard stats are cached with short TTL (60s) since data changes frequently
- Trends data uses longer cache TTL since historical data is stable
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.analytics.service import (
    DashboardQueryService,
)
from openlabels.auth.dependencies import get_current_user
from openlabels.server.cache import get_cache_manager
from openlabels.server.db import get_session
from openlabels.server.models import ScanJob

logger = logging.getLogger(__name__)

router = APIRouter()

# Cache key prefixes and TTLs
DASHBOARD_STATS_CACHE_PREFIX = "dashboard:stats"
DASHBOARD_STATS_TTL = 60  # 60 seconds - stats change frequently


# ── Response models ──────────────────────────────────────────────────

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
    children: list[HeatmapNode] | None = None


class HeatmapResponse(BaseModel):
    """Heatmap tree data."""

    roots: list[HeatmapNode]
    truncated: bool = False
    total_files: int = 0
    limit_applied: int = 0


class EntityTrendsResponse(BaseModel):
    """Entity type trends over time for charts."""

    series: dict[str, list[tuple[str, int]]]  # entity_type -> [(date, count), ...]
    truncated: bool = False
    total_records: int = 0


class AccessHeatmapResponse(BaseModel):
    """File access heatmap data (7 days x 24 hours)."""

    data: list[list[int]]  # 7x24 matrix


# Maximum number of records to process for entity aggregation
ENTITY_TRENDS_LIMIT = 50000

# Maximum number of files to load for heatmap to prevent memory explosion
HEATMAP_MAX_FILES = 10000

# Maximum depth for folder aggregation (deeper files rolled up)
HEATMAP_MAX_DEPTH = 10


# ── Service resolution ────────────────────────────────────────────────

def _get_dashboard_service(request: Request) -> DashboardQueryService:
    """Return the DuckDB-backed dashboard service.

    Raises HTTP 503 if the analytics engine failed to initialize at
    startup — this surfaces the problem instead of silently degrading
    to slow PostgreSQL full-table scans.
    """
    svc = getattr(request.app.state, "dashboard_service", None)
    if svc is None:
        raise HTTPException(
            status_code=503,
            detail="Analytics engine unavailable — check server logs",
        )
    return svc


# ── Endpoints ─────────────────────────────────────────────────────────

@router.get("/stats", response_model=OverallStats)
async def get_overall_stats(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get overall dashboard statistics.

    Results are cached for 60 seconds to reduce database load.
    ``active_scans`` always comes from PostgreSQL (OLTP concern).
    """
    # Try cache first
    cache_key = f"{DASHBOARD_STATS_CACHE_PREFIX}:tenant:{user.tenant_id}"
    try:
        cache = await get_cache_manager()
        cached = await cache.get(cache_key)
        if cached is not None:
            logger.debug(f"Cache hit for dashboard stats (tenant: {user.tenant_id})")
            return OverallStats(**cached)
    except (ConnectionError, OSError, RuntimeError) as e:
        logger.debug(f"Cache read failed: {e}")

    svc = _get_dashboard_service(request)

    # Active scans + total files always from PostgreSQL (real-time OLTP state)
    scan_stats_query = select(
        func.count().label("total"),
        func.sum(
            case((ScanJob.status.in_(["pending", "running"]), 1), else_=0)
        ).label("active"),
        func.coalesce(func.sum(ScanJob.files_scanned), 0).label("total_files_scanned"),
    ).where(ScanJob.tenant_id == user.tenant_id)
    result = await session.execute(scan_stats_query)
    scan_row = result.one()
    total_scans = scan_row.total or 0
    active_scans = scan_row.active or 0
    total_files_scanned = scan_row.total_files_scanned or 0

    # File aggregation from the active service (DuckDB or PG)
    file_stats = await svc.get_file_stats(user.tenant_id)

    # total_files comes from ScanJob (counts every file processed),
    # not from ScanResult/parquet which only holds sensitive files.
    response = OverallStats(
        total_scans=total_scans,
        total_files_scanned=file_stats.total_files or total_files_scanned,
        files_with_pii=file_stats.files_with_pii,
        labels_applied=file_stats.labels_applied,
        critical_files=file_stats.critical_files,
        high_files=file_stats.high_files,
        active_scans=active_scans,
    )

    # Cache with short TTL
    try:
        cache = await get_cache_manager()
        await cache.set(cache_key, response.model_dump(), ttl=DASHBOARD_STATS_TTL)
    except (ConnectionError, OSError, RuntimeError) as e:
        logger.debug(f"Cache write failed: {e}")

    return response


@router.get("/trends", response_model=TrendResponse)
async def get_trends(
    request: Request,
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get trend data over time.

    When backed by DuckDB, this runs a full columnar GROUP BY with no
    sampling.  When backed by PostgreSQL, the existing SQL aggregation
    is used.
    """
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)

    svc = _get_dashboard_service(request)
    svc_points = await svc.get_trends(user.tenant_id, start_date, end_date)

    # Build lookup from service results
    daily_stats = {
        p.date: {
            "files_scanned": p.files_scanned,
            "files_with_pii": p.files_with_pii,
            "labels_applied": p.labels_applied,
        }
        for p in svc_points
    }

    # Fill in missing dates with zeros
    points: list[TrendPoint] = []
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


@router.get("/entity-trends", response_model=EntityTrendsResponse)
async def get_entity_trends(
    request: Request,
    days: int = Query(14, ge=1, le=90, description="Number of days to include"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get entity type detection trends over time.

    When backed by DuckDB, this uses native MAP column unnesting with no
    sampling cap.  When backed by PostgreSQL, falls back to the existing
    sampling approach.
    """
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)

    svc = _get_dashboard_service(request)
    data = await svc.get_entity_trends(
        user.tenant_id, start_date, end_date, top_n=6,
    )

    return EntityTrendsResponse(
        series=data.series,
        truncated=data.truncated,
        total_records=data.total_records,
    )


@router.get("/access-heatmap", response_model=AccessHeatmapResponse)
async def get_access_heatmap(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get file access activity heatmap by hour and day of week.

    Returns a 7x24 matrix where data[day][hour] = access count.
    Day 0 = Monday, day 6 = Sunday.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=28)

    svc = _get_dashboard_service(request)
    heatmap = await svc.get_access_heatmap(user.tenant_id, cutoff)

    return AccessHeatmapResponse(data=heatmap)


@router.get("/heatmap", response_model=HeatmapResponse)
async def get_heatmap(
    request: Request,
    job_id: UUID | None = Query(None, description="Filter by job ID"),
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
    svc = _get_dashboard_service(request)
    file_rows, total_files = await svc.get_heatmap_data(
        user.tenant_id, job_id=job_id, limit=limit,
    )

    truncated = total_files > limit
    if truncated:
        logger.warning(
            "Heatmap query truncated: %d files exceed limit of %d. "
            "Returning highest risk files only.",
            total_files, limit,
        )

    # Build tree structure from file rows
    tree: dict = {}
    for row in file_rows:
        parts = row.file_path.replace("\\", "/").split("/")
        parts = [p for p in parts if p]
        if not parts:
            continue

        if len(parts) > HEATMAP_MAX_DEPTH:
            parts = parts[:HEATMAP_MAX_DEPTH - 1] + ["..."] + [parts[-1]]

        current = tree
        for part in parts[:-1]:
            if part not in current:
                current[part] = {"_children": {}, "_stats": {"risk_score": 0, "entity_counts": {}}}
            current = current[part]["_children"]

        filename = parts[-1]
        current[filename] = {
            "_is_file": True,
            "_stats": {
                "risk_score": row.risk_score,
                "entity_counts": row.entity_counts or {},
            },
        }

    # Build response tree
    roots = [
        _build_heatmap_node(name, data, name)
        for name, data in tree.items()
    ]
    roots.sort(key=lambda n: n.risk_score, reverse=True)

    return HeatmapResponse(
        roots=roots,
        truncated=truncated,
        total_files=total_files,
        limit_applied=limit,
    )


# ── Heatmap tree builder ─────────────────────────────────────────────

def _build_heatmap_node(name: str, data: dict, path: str) -> HeatmapNode:
    """Recursively build heatmap nodes from the intermediate tree dict."""
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
        child_node = _build_heatmap_node(child_name, child_data, child_path)
        children.append(child_node)
        total_score += child_node.risk_score
        for entity_type, count in (child_node.entity_counts or {}).items():
            total_entities[entity_type] = total_entities.get(entity_type, 0) + count

    children.sort(key=lambda n: n.risk_score, reverse=True)

    return HeatmapNode(
        name=name,
        path=path,
        type="folder",
        risk_score=total_score,
        entity_counts=total_entities,
        children=children if children else None,
    )
