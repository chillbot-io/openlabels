"""
Dashboard API endpoints for statistics and visualizations.
"""

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func
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
    """Get overall dashboard statistics."""
    # Count scans
    scan_query = select(func.count()).where(ScanJob.tenant_id == user.tenant_id)
    result = await session.execute(scan_query)
    total_scans = result.scalar() or 0

    # Count active scans
    active_query = select(func.count()).where(
        ScanJob.tenant_id == user.tenant_id,
        ScanJob.status.in_(["pending", "running"]),
    )
    result = await session.execute(active_query)
    active_scans = result.scalar() or 0

    # Get result stats
    result_query = select(ScanResult).where(ScanResult.tenant_id == user.tenant_id)
    result = await session.execute(result_query)
    results = result.scalars().all()

    total_files = len(results)
    files_with_pii = sum(1 for r in results if r.total_entities > 0)
    labels_applied = sum(1 for r in results if r.label_applied)
    critical_files = sum(1 for r in results if r.risk_tier == "CRITICAL")
    high_files = sum(1 for r in results if r.risk_tier == "HIGH")

    return OverallStats(
        total_scans=total_scans,
        total_files_scanned=total_files,
        files_with_pii=files_with_pii,
        labels_applied=labels_applied,
        critical_files=critical_files,
        high_files=high_files,
        active_scans=active_scans,
    )


@router.get("/trends", response_model=TrendResponse)
async def get_trends(
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """Get trend data over time."""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)

    # Get results in date range
    query = select(ScanResult).where(
        ScanResult.tenant_id == user.tenant_id,
        ScanResult.scanned_at >= start_date,
    )
    result = await session.execute(query)
    results = result.scalars().all()

    # Group by date
    daily_stats: dict[str, dict] = {}
    for r in results:
        date_str = r.scanned_at.strftime("%Y-%m-%d")
        if date_str not in daily_stats:
            daily_stats[date_str] = {
                "files_scanned": 0,
                "files_with_pii": 0,
                "labels_applied": 0,
            }
        daily_stats[date_str]["files_scanned"] += 1
        if r.total_entities > 0:
            daily_stats[date_str]["files_with_pii"] += 1
        if r.label_applied:
            daily_stats[date_str]["labels_applied"] += 1

    # Fill in missing dates
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
