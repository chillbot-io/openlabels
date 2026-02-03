"""
Web UI routes for OpenLabels.

Serves Jinja2 templates with HTMX support for dynamic updates.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, case, desc
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import ScanJob, ScanResult, ScanTarget, AuditLog
from openlabels.auth.dependencies import get_current_user, get_optional_user

logger = logging.getLogger(__name__)

router = APIRouter()

# Set up templates directory
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


def format_relative_time(dt: Optional[datetime]) -> str:
    """Format datetime as relative time string."""
    if not dt:
        return "Never"

    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    diff = now - dt
    seconds = diff.total_seconds()

    if seconds < 60:
        return "Just now"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes}m ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours}h ago"
    elif seconds < 604800:
        days = int(seconds / 86400)
        return f"{days}d ago"
    else:
        return dt.strftime("%Y-%m-%d")


# Register template filters
templates.env.filters["relative_time"] = format_relative_time


# Page routes
@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Redirect to dashboard."""
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "active_page": "dashboard"},
    )


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard page."""
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "active_page": "dashboard"},
    )


@router.get("/targets", response_class=HTMLResponse)
async def targets_page(request: Request):
    """Targets management page."""
    return templates.TemplateResponse(
        "targets.html",
        {"request": request, "active_page": "targets"},
    )


@router.get("/targets/new", response_class=HTMLResponse)
async def new_target_page(request: Request):
    """New target form page."""
    return templates.TemplateResponse(
        "targets_form.html",
        {"request": request, "active_page": "targets", "target": None, "mode": "create"},
    )


@router.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request):
    """Scans page."""
    return templates.TemplateResponse(
        "scans.html",
        {"request": request, "active_page": "scans"},
    )


@router.get("/scans/new", response_class=HTMLResponse)
async def new_scan_page(request: Request):
    """New scan form page."""
    return templates.TemplateResponse(
        "scans_form.html",
        {"request": request, "active_page": "scans"},
    )


@router.get("/results", response_class=HTMLResponse)
async def results_page(request: Request):
    """Results page."""
    return templates.TemplateResponse(
        "results.html",
        {"request": request, "active_page": "results"},
    )


@router.get("/labels", response_class=HTMLResponse)
async def labels_page(request: Request):
    """Labels management page."""
    return templates.TemplateResponse(
        "labels.html",
        {"request": request, "active_page": "labels"},
    )


@router.get("/labels/sync", response_class=HTMLResponse)
async def labels_sync_page(request: Request):
    """Labels sync page."""
    return templates.TemplateResponse(
        "labels_sync.html",
        {"request": request, "active_page": "labels"},
    )


@router.get("/monitoring", response_class=HTMLResponse)
async def monitoring_page(request: Request):
    """Monitoring page."""
    return templates.TemplateResponse(
        "monitoring.html",
        {"request": request, "active_page": "monitoring"},
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page."""
    return templates.TemplateResponse(
        "settings.html",
        {"request": request, "active_page": "settings"},
    )


# Partial routes for HTMX
@router.get("/partials/dashboard-stats", response_class=HTMLResponse)
async def dashboard_stats_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Dashboard stats partial for HTMX updates."""
    stats = {
        "total_files": 0,
        "total_findings": 0,
        "critical_findings": 0,
        "active_scans": 0,
    }

    if user:
        # Get file stats
        file_stats_query = select(
            func.count().label("total_files"),
            func.sum(ScanResult.total_entities).label("total_findings"),
            func.sum(case((ScanResult.risk_tier == "CRITICAL", 1), else_=0)).label("critical_files"),
        ).where(ScanResult.tenant_id == user.tenant_id)

        result = await session.execute(file_stats_query)
        row = result.one()
        stats["total_files"] = row.total_files or 0
        stats["total_findings"] = row.total_findings or 0
        stats["critical_findings"] = row.critical_files or 0

        # Get active scans
        active_query = select(func.count()).where(
            ScanJob.tenant_id == user.tenant_id,
            ScanJob.status.in_(["pending", "running"]),
        )
        result = await session.execute(active_query)
        stats["active_scans"] = result.scalar() or 0

    return templates.TemplateResponse(
        "partials/dashboard_stats.html",
        {"request": request, "stats": stats},
    )


@router.get("/partials/recent-scans", response_class=HTMLResponse)
async def recent_scans_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Recent scans partial for HTMX updates."""
    recent_scans = []

    if user:
        query = (
            select(ScanJob)
            .where(ScanJob.tenant_id == user.tenant_id)
            .order_by(desc(ScanJob.created_at))
            .limit(5)
        )
        result = await session.execute(query)
        scans = result.scalars().all()

        for scan in scans:
            recent_scans.append({
                "id": str(scan.id),
                "target_name": scan.target_name or "Unknown",
                "status": scan.status,
                "files_scanned": scan.files_scanned or 0,
                "created_at": scan.created_at,
            })

    return templates.TemplateResponse(
        "partials/recent_scans.html",
        {"request": request, "recent_scans": recent_scans},
    )


@router.get("/partials/findings-by-type", response_class=HTMLResponse)
async def findings_by_type_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Findings by type partial for HTMX updates."""
    findings_by_type = []

    if user:
        # Get all results with entity counts
        query = select(ScanResult.entity_counts, ScanResult.risk_tier).where(
            ScanResult.tenant_id == user.tenant_id,
            ScanResult.entity_counts.isnot(None),
        )
        result = await session.execute(query)
        rows = result.all()

        # Aggregate by entity type
        type_counts: dict[str, dict] = {}
        for row in rows:
            entity_counts = row.entity_counts or {}
            risk = row.risk_tier or "LOW"
            for entity_type, count in entity_counts.items():
                if entity_type not in type_counts:
                    type_counts[entity_type] = {"count": 0, "risk": risk}
                type_counts[entity_type]["count"] += count
                # Keep highest risk
                risk_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                if risk_order.get(risk, 0) > risk_order.get(type_counts[entity_type]["risk"], 0):
                    type_counts[entity_type]["risk"] = risk

        # Sort by count and calculate percentages
        total = sum(tc["count"] for tc in type_counts.values()) or 1
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1]["count"], reverse=True)[:10]

        for entity_type, data in sorted_types:
            findings_by_type.append({
                "entity_type": entity_type,
                "count": data["count"],
                "risk": data["risk"],
                "percentage": round(data["count"] / total * 100, 1),
            })

    return templates.TemplateResponse(
        "partials/findings_by_type.html",
        {"request": request, "findings_by_type": findings_by_type},
    )


@router.get("/partials/risk-distribution", response_class=HTMLResponse)
async def risk_distribution_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Risk distribution partial for HTMX updates."""
    risk_distribution = []

    if user:
        query = select(
            ScanResult.risk_tier,
            func.count().label("count"),
        ).where(
            ScanResult.tenant_id == user.tenant_id,
        ).group_by(ScanResult.risk_tier)

        result = await session.execute(query)
        rows = result.all()

        total = sum(row.count for row in rows) or 1
        risk_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        risk_data = {row.risk_tier: row.count for row in rows}

        for level in risk_order:
            count = risk_data.get(level, 0)
            risk_distribution.append({
                "level": level,
                "count": count,
                "percentage": round(count / total * 100, 1),
            })

    return templates.TemplateResponse(
        "partials/risk_distribution.html",
        {"request": request, "risk_distribution": risk_distribution},
    )


@router.get("/partials/recent-activity", response_class=HTMLResponse)
async def recent_activity_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Recent activity partial for HTMX updates."""
    recent_activity = []

    if user:
        query = (
            select(AuditLog)
            .where(AuditLog.tenant_id == user.tenant_id)
            .order_by(desc(AuditLog.created_at))
            .limit(10)
        )
        result = await session.execute(query)
        logs = result.scalars().all()

        for log in logs:
            activity_type = log.action
            description = log.action.replace("_", " ").title()
            details = None

            if log.details:
                if "name" in log.details:
                    details = log.details["name"]
                elif "file_path" in log.details:
                    details = log.details["file_path"]

            recent_activity.append({
                "type": activity_type,
                "description": description,
                "details": details,
                "timestamp": format_relative_time(log.created_at),
            })

    return templates.TemplateResponse(
        "partials/recent_activity.html",
        {"request": request, "recent_activity": recent_activity},
    )


@router.get("/partials/health-status", response_class=HTMLResponse)
async def health_status_partial(request: Request):
    """Health status partial for HTMX updates."""
    # Simple health check
    health = {"status": "healthy"}

    return templates.TemplateResponse(
        "partials/health_status.html",
        {"request": request, "health": health},
    )


@router.get("/partials/targets-list", response_class=HTMLResponse)
async def targets_list_partial(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    adapter: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Targets list partial for HTMX updates."""
    targets = []
    total = 0

    if user:
        query = select(ScanTarget).where(ScanTarget.tenant_id == user.tenant_id)
        if adapter:
            query = query.where(ScanTarget.adapter == adapter)

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        result = await session.execute(count_query)
        total = result.scalar() or 0

        # Get page
        query = query.order_by(desc(ScanTarget.created_at))
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await session.execute(query)
        target_rows = result.scalars().all()

        for target in target_rows:
            targets.append({
                "id": str(target.id),
                "name": target.name,
                "adapter": target.adapter,
                "enabled": target.enabled,
                "created_at": target.created_at,
            })

    return templates.TemplateResponse(
        "partials/targets_list.html",
        {
            "request": request,
            "targets": targets,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        },
    )


@router.get("/partials/scans-list", response_class=HTMLResponse)
async def scans_list_partial(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    status: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Scans list partial for HTMX updates."""
    scans = []
    total = 0

    if user:
        query = select(ScanJob).where(ScanJob.tenant_id == user.tenant_id)
        if status:
            query = query.where(ScanJob.status == status)

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        result = await session.execute(count_query)
        total = result.scalar() or 0

        # Get page
        query = query.order_by(desc(ScanJob.created_at))
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await session.execute(query)
        scan_rows = result.scalars().all()

        for scan in scan_rows:
            progress = 0
            if scan.total_files and scan.total_files > 0:
                progress = int((scan.files_scanned or 0) / scan.total_files * 100)
            elif scan.status == "completed":
                progress = 100

            scans.append({
                "id": str(scan.id),
                "target_name": scan.target_name or "Unknown",
                "status": scan.status,
                "files_scanned": scan.files_scanned or 0,
                "progress": progress,
                "created_at": scan.created_at,
            })

    return templates.TemplateResponse(
        "partials/scans_list.html",
        {
            "request": request,
            "scans": scans,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        },
    )


@router.get("/partials/results-list", response_class=HTMLResponse)
async def results_list_partial(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    risk_tier: Optional[str] = None,
    entity_type: Optional[str] = None,
    has_label: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Results list partial for HTMX updates."""
    results = []
    total = 0

    if user:
        query = select(ScanResult).where(ScanResult.tenant_id == user.tenant_id)
        if risk_tier:
            query = query.where(ScanResult.risk_tier == risk_tier)
        if has_label == "true":
            query = query.where(ScanResult.label_applied == True)  # noqa: E712
        elif has_label == "false":
            query = query.where(ScanResult.label_applied == False)  # noqa: E712

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        result = await session.execute(count_query)
        total = result.scalar() or 0

        # Get page
        query = query.order_by(desc(ScanResult.scanned_at))
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await session.execute(query)
        result_rows = result.scalars().all()

        for r in result_rows:
            file_path = r.file_path or ""
            file_name = file_path.split("/")[-1] if "/" in file_path else file_path.split("\\")[-1]
            file_type = file_name.split(".")[-1].lower() if "." in file_name else ""

            results.append({
                "id": str(r.id),
                "file_path": file_path,
                "file_name": file_name,
                "file_type": file_type,
                "risk_tier": r.risk_tier,
                "risk_score": r.risk_score or 0,
                "entity_counts": r.entity_counts or {},
                "label_applied": r.label_applied,
                "label_name": r.label_name,
                "scanned_at": r.scanned_at,
            })

    return templates.TemplateResponse(
        "partials/results_list.html",
        {
            "request": request,
            "results": results,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        },
    )


@router.get("/partials/activity-log", response_class=HTMLResponse)
async def activity_log_partial(
    request: Request,
    action: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Activity log partial for HTMX updates."""
    activity_logs = []

    if user:
        query = select(AuditLog).where(AuditLog.tenant_id == user.tenant_id)
        if action:
            query = query.where(AuditLog.action == action)
        query = query.order_by(desc(AuditLog.created_at)).limit(50)

        result = await session.execute(query)
        logs = result.scalars().all()

        for log in logs:
            activity_logs.append({
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": str(log.resource_id) if log.resource_id else None,
                "details": log.details,
                "user_email": None,  # Would need to join with User table
                "created_at": log.created_at,
            })

    return templates.TemplateResponse(
        "partials/activity_log.html",
        {"request": request, "activity_logs": activity_logs},
    )


@router.get("/partials/job-queue", response_class=HTMLResponse)
async def job_queue_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Job queue partial for HTMX updates."""
    from openlabels.server.models import JobQueue as JobQueueModel

    stats = {
        "pending": 0,
        "running": 0,
        "completed": 0,
        "failed": 0,
        "cancelled": 0,
    }
    failed_jobs = []

    if user:
        # Get stats
        stats_query = select(
            JobQueueModel.status,
            func.count().label("count"),
        ).where(
            JobQueueModel.tenant_id == user.tenant_id
        ).group_by(JobQueueModel.status)

        result = await session.execute(stats_query)
        for row in result.all():
            if row.status in stats:
                stats[row.status] = row.count

        # Get recent failed jobs
        failed_query = (
            select(JobQueueModel)
            .where(
                JobQueueModel.tenant_id == user.tenant_id,
                JobQueueModel.status == "failed",
            )
            .order_by(desc(JobQueueModel.updated_at))
            .limit(5)
        )
        result = await session.execute(failed_query)
        for job in result.scalars().all():
            failed_jobs.append({
                "id": str(job.id),
                "task_type": job.task_type,
                "error": job.error,
                "failed_at": job.updated_at,
            })

    return templates.TemplateResponse(
        "partials/job_queue.html",
        {"request": request, "stats": stats, "failed_jobs": failed_jobs},
    )


@router.get("/partials/system-health", response_class=HTMLResponse)
async def system_health_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """System health partial for HTMX updates."""
    health = {
        "status": "healthy",
        "components": {
            "database": "ok",
            "queue": "ok",
        },
    }

    # Check database
    try:
        await session.execute(select(1))
    except Exception:
        health["status"] = "unhealthy"
        health["components"]["database"] = "error"

    return templates.TemplateResponse(
        "partials/system_health.html",
        {"request": request, "health": health},
    )


@router.get("/partials/labels-list", response_class=HTMLResponse)
async def labels_list_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Labels list partial for HTMX updates."""
    labels = []

    if user:
        from openlabels.server.models import SensitivityLabel

        query = (
            select(SensitivityLabel)
            .where(SensitivityLabel.tenant_id == user.tenant_id)
            .order_by(SensitivityLabel.priority)
        )
        result = await session.execute(query)
        for label in result.scalars().all():
            labels.append({
                "id": str(label.id),
                "name": label.name,
                "description": label.description,
                "color": label.color,
                "priority": label.priority,
                "synced_at": label.updated_at,
            })

    return templates.TemplateResponse(
        "partials/labels_list.html",
        {"request": request, "labels": labels},
    )


@router.get("/partials/label-mappings", response_class=HTMLResponse)
async def label_mappings_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Label mappings partial for HTMX updates."""
    labels = []
    mappings = {}

    if user:
        from openlabels.server.models import SensitivityLabel

        query = (
            select(SensitivityLabel)
            .where(SensitivityLabel.tenant_id == user.tenant_id)
            .order_by(SensitivityLabel.priority)
        )
        result = await session.execute(query)
        for label in result.scalars().all():
            labels.append({
                "id": str(label.id),
                "name": label.name,
            })

    return templates.TemplateResponse(
        "partials/label_mappings.html",
        {"request": request, "labels": labels, "mappings": mappings},
    )


@router.get("/partials/target-checkboxes", response_class=HTMLResponse)
async def target_checkboxes_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Target checkboxes partial for scan form."""
    targets = []

    if user:
        query = (
            select(ScanTarget)
            .where(
                ScanTarget.tenant_id == user.tenant_id,
                ScanTarget.enabled == True,  # noqa: E712
            )
            .order_by(ScanTarget.name)
        )
        result = await session.execute(query)
        for target in result.scalars().all():
            targets.append({
                "id": str(target.id),
                "name": target.name,
                "adapter": target.adapter,
            })

    if targets:
        html = '<div class="divide-y divide-gray-200">'
        for target in targets:
            html += f'''
            <label class="flex items-center p-3 hover:bg-gray-50 cursor-pointer">
                <input type="checkbox" name="target_ids[]" value="{target['id']}"
                    class="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded">
                <div class="ml-3">
                    <span class="text-sm font-medium text-gray-900">{target['name']}</span>
                    <span class="ml-2 text-xs text-gray-500">{target['adapter']}</span>
                </div>
            </label>'''
        html += '</div>'
    else:
        html = '''
        <div class="p-4 text-center text-gray-500">
            <p>No enabled targets found.</p>
            <a href="/ui/targets/new" class="text-primary-600 hover:text-primary-800">Create a target</a>
        </div>'''

    return HTMLResponse(content=html)
