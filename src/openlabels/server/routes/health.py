"""
Health and status API endpoints.

Health and status endpoints for monitoring dashboards.

Provides:
- Component health dashboard (API, workers, DB, Redis)
- Job queue depth and processing rate
- Worker status: active, idle, error
- System resource usage (CPU, memory, disk)
- Alert configuration for system failures
- Scan throughput metrics
- Error log viewer
- Background task status
- Cache health
"""

from __future__ import annotations

import logging
import os
import platform
import sys
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import Integer, case, func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import get_current_user, get_optional_user, require_admin
from openlabels.core.circuit_breaker import CircuitBreaker
from openlabels.core.types import JobStatus
from openlabels.jobs.queue import JobQueue as JobQueueService
from openlabels.server.cache import get_cache_stats
from openlabels.server.db import get_pool_stats, get_session
from openlabels.server.models import AuditLog, JobQueue, ScanJob, ScanResult

logger = logging.getLogger(__name__)
router = APIRouter()


class CircuitBreakerStatus(BaseModel):
    """Status of a single circuit breaker."""

    name: str
    state: str  # closed, open, half_open
    failure_count: int
    success_count: int
    time_until_recovery: float
    stats: dict[str, int]


class JobMetrics(BaseModel):
    """Job queue metrics."""

    pending_count: int
    running_count: int
    failed_count: int
    completed_count: int
    stuck_jobs_count: int = 0
    stale_pending_count: int = 0
    oldest_pending_hours: float | None = None
    oldest_running_hours: float | None = None


class HealthStatus(BaseModel):
    """Health status response."""

    # Server status
    api: str  # healthy, warning, error
    api_text: str
    db: str
    db_text: str
    queue: str
    queue_text: str

    # Service status
    ml: str
    ml_text: str
    mip: str
    mip_text: str
    ocr: str
    ocr_text: str

    # Statistics
    scans_today: int
    files_processed: int
    success_rate: float

    # Circuit breakers
    circuit_breakers: list[CircuitBreakerStatus] | None = None

    # Job metrics
    job_metrics: JobMetrics | None = None

    # Database pool
    db_pool: dict[str, int] | None = None

    # Optional extended info
    python_version: str | None = None
    platform: str | None = None
    uptime_seconds: int | None = None


# Track server start time for uptime
_server_start_time = datetime.now(timezone.utc)


@router.get("/status", response_model=HealthStatus)
async def get_health_status(
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """
    Get system health status.

    Authentication is optional — unauthenticated requests (e.g. load
    balancer probes) receive component health without tenant-specific
    scan statistics.

    Returns status of all system components:
    - API server
    - Database connection
    - Job queue
    - ML models
    - MIP SDK
    - OCR engine
    - Scan statistics (authenticated only)
    """
    status = {
        "api": "healthy",
        "api_text": "OK",
        "db": "unknown",
        "db_text": "",
        "queue": "unknown",
        "queue_text": "",
        "ml": "unknown",
        "ml_text": "",
        "mip": "unknown",
        "mip_text": "",
        "ocr": "unknown",
        "ocr_text": "",
        "scans_today": 0,
        "files_processed": 0,
        "success_rate": 0.0,
    }

    # Check database connection
    try:
        result = await session.execute(text("SELECT 1"))
        result.scalar()
        status["db"] = "healthy"
        status["db_text"] = "Connected"
    except (SQLAlchemyError, ConnectionError, OSError) as e:
        logger.warning(f"Database health check failed: {e}")
        status["db"] = "error"
        status["db_text"] = "Disconnected"

    # SECURITY: Detailed component checks only for authenticated users.
    # Unauthenticated probes (load balancers) only see api/db status.
    if user is not None:
        # Check job queue — counts only exposed to authenticated users
        pending_count = 0
        failed_count = 0
        try:
            queue_query = select(
                func.count().label("total"),
                func.sum(func.cast(JobQueue.status == JobStatus.PENDING, Integer)).label("pending"),
                func.sum(func.cast(JobQueue.status == JobStatus.FAILED, Integer)).label("failed"),
            )
            # Simplified query - just count pending jobs
            pending_query = select(func.count()).select_from(JobQueue).where(
                JobQueue.status == JobStatus.PENDING
            )
            result = await session.execute(pending_query)
            pending_count = result.scalar() or 0

            failed_query = select(func.count()).select_from(JobQueue).where(
                JobQueue.status == JobStatus.FAILED
            )
            result = await session.execute(failed_query)
            failed_count = result.scalar() or 0

            if failed_count > 10:
                status["queue"] = "error"
                status["queue_text"] = f"{failed_count} failed"
            elif pending_count > 100:
                status["queue"] = "warning"
                status["queue_text"] = f"{pending_count} pending"
            else:
                status["queue"] = "healthy"
                status["queue_text"] = f"{pending_count} pending"
        except (SQLAlchemyError, ConnectionError, OSError) as e:
            logger.warning(f"Queue health check failed: {e}")
            status["queue"] = "warning"
            status["queue_text"] = "Unknown"

        # Check ML models
        try:
            models_available = []
            try:
                from openlabels.core.detectors.gliner import GLiNERDetector
                models_available.append("GLiNER")
            except ImportError:
                logger.info("GLiNER detector not available")

            try:
                from openlabels.core.detectors.phi_detector import StanfordPHIDetector  # noqa: F401
                from openlabels.core.constants import DEFAULT_MODELS_DIR
                phi_dir = DEFAULT_MODELS_DIR / "stanford_phi"
                if phi_dir.is_dir() and (phi_dir / "config.json").exists():
                    models_available.append("Stanford-PHI")
            except ImportError:
                logger.info("Stanford PHI detector not available")

            if models_available:
                status["ml"] = "healthy"
                status["ml_text"] = ", ".join(models_available)
            else:
                status["ml"] = "warning"
                status["ml_text"] = "No models"
        except (OSError, RuntimeError, ValueError) as e:
            logger.warning(f"ML health check failed: {type(e).__name__}: {e}")
            status["ml"] = "warning"
            status["ml_text"] = "Not loaded"

        # Check MIP SDK
        try:
            if sys.platform == "win32":
                from openlabels.labeling.mip import MIPClient
                status["mip"] = "healthy"
                status["mip_text"] = "Available"
            else:
                status["mip"] = "warning"
                status["mip_text"] = "Windows only"
        except ImportError:
            status["mip"] = "warning"
            status["mip_text"] = "Not installed"
        except (OSError, RuntimeError) as e:
            logger.info(f"MIP SDK check failed (labeling unavailable): {type(e).__name__}: {e}")
            status["mip"] = "warning"
            status["mip_text"] = "Not available"

        # Check OCR
        try:
            import pytesseract
            version = pytesseract.get_tesseract_version()
            status["ocr"] = "healthy"
            status["ocr_text"] = f"Tesseract {version}"
        except ImportError:
            status["ocr"] = "warning"
            status["ocr_text"] = "Not installed"
        except (OSError, RuntimeError) as e:
            logger.info(f"OCR check failed (image text extraction unavailable): {type(e).__name__}: {e}")
            status["ocr"] = "warning"
            status["ocr_text"] = "Not available"

    # Get scan statistics (tenant-specific, requires authentication)
    if user is not None:
        try:
            today = datetime.now(timezone.utc).date()
            today_start = datetime.combine(today, datetime.min.time(), tzinfo=timezone.utc)

            # Scans today
            scans_query = select(func.count()).select_from(ScanJob).where(
                ScanJob.tenant_id == user.tenant_id,
                ScanJob.created_at >= today_start,
            )
            result = await session.execute(scans_query)
            status["scans_today"] = result.scalar() or 0

            # Files processed (all time for tenant)
            files_query = select(func.count()).select_from(ScanResult).where(
                ScanResult.tenant_id == user.tenant_id,
            )
            result = await session.execute(files_query)
            status["files_processed"] = result.scalar() or 0

            # Success rate (completed vs failed scans in last 7 days)
            week_ago = datetime.now(timezone.utc) - timedelta(days=7)
            success_query = select(
                func.count().label("total"),
                func.sum(func.cast(ScanJob.status == JobStatus.COMPLETED, Integer)).label("completed"),
            ).where(
                ScanJob.tenant_id == user.tenant_id,
                ScanJob.created_at >= week_ago,
            )
            result = await session.execute(success_query)
            row = result.one()
            total = row.total or 0
            completed = row.completed or 0
            status["success_rate"] = (completed / total * 100) if total > 0 else 100.0

        except (SQLAlchemyError, ConnectionError, OSError) as e:
            logger.warning(f"Stats query failed: {e}")

    # SECURITY: Detailed system info only for authenticated users
    if user is not None:
        # Add circuit breaker status
        try:
            cb_statuses = []
            for name, cb in CircuitBreaker._registry.items():
                cb_status = cb.get_status()
                cb_statuses.append(CircuitBreakerStatus(
                    name=cb_status["name"],
                    state=cb_status["state"],
                    failure_count=cb_status["failure_count"],
                    success_count=cb_status["success_count"],
                    time_until_recovery=cb_status["time_until_recovery"],
                    stats=cb_status["stats"],
                ))
            status["circuit_breakers"] = cb_statuses
        except (RuntimeError, KeyError, AttributeError) as e:
            logger.debug(f"Could not retrieve circuit breaker status: {type(e).__name__}: {e}")

        # Add job metrics (tenant-specific)
        try:
            job_queue = JobQueueService(session, user.tenant_id)
            age_stats = await job_queue.get_job_age_stats()
            stale_jobs = await job_queue.get_stale_pending_jobs()

            tenant_pending_query = select(func.count()).select_from(JobQueue).where(
                JobQueue.status == JobStatus.PENDING,
                JobQueue.tenant_id == user.tenant_id,
            )
            tenant_pending = (await session.execute(tenant_pending_query)).scalar() or 0

            tenant_failed_query = select(func.count()).select_from(JobQueue).where(
                JobQueue.status == JobStatus.FAILED,
                JobQueue.tenant_id == user.tenant_id,
            )
            tenant_failed = (await session.execute(tenant_failed_query)).scalar() or 0

            status["job_metrics"] = JobMetrics(
                pending_count=tenant_pending,
                running_count=age_stats.get("running_count", 0),
                failed_count=tenant_failed,
                completed_count=age_stats.get("completed_count", 0),
                stuck_jobs_count=age_stats.get("stuck_count", 0),
                stale_pending_count=len(stale_jobs),
                oldest_pending_hours=age_stats.get("oldest_pending_hours"),
                oldest_running_hours=age_stats.get("oldest_running_hours"),
            )
        except (SQLAlchemyError, ConnectionError, OSError, RuntimeError) as e:
            logger.info(f"Could not retrieve job metrics: {type(e).__name__}: {e}")

        # DB pool stats
        pool_stats = get_pool_stats()
        if pool_stats:
            status["db_pool"] = pool_stats

        # System info — only for authenticated users
        status["python_version"] = platform.python_version()
        status["platform"] = platform.system()
        status["uptime_seconds"] = int((datetime.now(timezone.utc) - _server_start_time).total_seconds())

    return HealthStatus(**status)


@router.get("/ready")
async def readiness_probe(
    session: AsyncSession = Depends(get_session),
):
    """Lightweight readiness probe for load balancers and container orchestrators.

    Returns 200 if the database is reachable, 503 otherwise.
    No authentication required.
    """
    try:
        await session.execute(text("SELECT 1"))
        return {"status": "ok"}
    except (SQLAlchemyError, ConnectionError, OSError):
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=503,
            content={"status": "unavailable", "detail": "database not reachable"},
        )


@router.get("/tasks")
async def get_task_status(
    request: Request,
    user=Depends(get_current_user),
):
    """Get status of all managed background tasks.

    Returns per-task health, uptime, cycle count, and error info.
    """
    task_mgr = getattr(request.app.state, "task_manager", None)
    if task_mgr is None:
        return {"tasks": [], "healthy": True}
    return {
        "tasks": task_mgr.get_status(),
        "healthy": task_mgr.is_healthy(),
    }


class CacheStats(BaseModel):
    """Cache statistics response."""

    enabled: bool
    backend: dict[str, Any]
    default_ttl: int
    key_prefix: str


@router.get("/cache", response_model=CacheStats)
async def get_cache_health(
    user=Depends(get_current_user),
):
    """
    Get cache statistics and health status.

    Returns:
    - Cache enabled status
    - Backend type (redis or memory)
    - Connection status (for Redis)
    - Hit/miss statistics
    - Hit rate percentage
    """
    try:
        stats = await get_cache_stats()
        return CacheStats(**stats)
    except (ConnectionError, OSError, RuntimeError) as e:
        logger.warning(f"Failed to get cache stats: {e}")
        return CacheStats(
            enabled=False,
            backend={"type": "unknown", "error": str(e)},
            default_ttl=0,
            key_prefix="",
        )


# ── System resource usage (CPU, memory, disk) ───────────────────────

class SystemResourceUsage(BaseModel):
    """System resource usage metrics."""

    cpu_percent: float
    cpu_count: int
    memory_total_mb: int
    memory_used_mb: int
    memory_percent: float
    disk_total_gb: float
    disk_used_gb: float
    disk_free_gb: float
    disk_percent: float
    load_average: list[float] | None = None


@router.get("/resources", response_model=SystemResourceUsage)
async def get_system_resources(
    user=Depends(get_current_user),
) -> SystemResourceUsage:
    """Get system resource usage (CPU, memory, disk).

    Returns current resource utilisation for the host machine.
    """
    try:
        import psutil

        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count() or 1
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        load = None
        if hasattr(os, "getloadavg"):
            load = list(os.getloadavg())

        return SystemResourceUsage(
            cpu_percent=cpu_percent,
            cpu_count=cpu_count,
            memory_total_mb=int(mem.total / (1024 * 1024)),
            memory_used_mb=int(mem.used / (1024 * 1024)),
            memory_percent=mem.percent,
            disk_total_gb=round(disk.total / (1024**3), 1),
            disk_used_gb=round(disk.used / (1024**3), 1),
            disk_free_gb=round(disk.free / (1024**3), 1),
            disk_percent=disk.percent,
            load_average=load,
        )
    except ImportError:
        # psutil not installed — return stub values from /proc if possible
        cpu_count = os.cpu_count() or 1
        load = list(os.getloadavg()) if hasattr(os, "getloadavg") else None
        return SystemResourceUsage(
            cpu_percent=0.0,
            cpu_count=cpu_count,
            memory_total_mb=0,
            memory_used_mb=0,
            memory_percent=0.0,
            disk_total_gb=0.0,
            disk_used_gb=0.0,
            disk_free_gb=0.0,
            disk_percent=0.0,
            load_average=load,
        )


# ── Worker status ────────────────────────────────────────────────────

class WorkerInfo(BaseModel):
    """Individual worker status."""

    worker_id: str
    status: str  # running, idle, error, stopped
    concurrency: int
    target_concurrency: int
    pid: int | None = None
    hostname: str | None = None
    last_heartbeat: str | None = None
    jobs_completed: int = 0


class WorkersResponse(BaseModel):
    """All workers status response."""

    workers: list[WorkerInfo]
    total_active: int
    total_idle: int
    total_error: int


@router.get("/workers", response_model=WorkersResponse)
async def get_workers_status(
    user=Depends(get_current_user),
) -> WorkersResponse:
    """Get status of all registered workers.

    Returns active, idle, and errored workers with their current state.
    """
    try:
        from openlabels.jobs.worker import get_worker_state_manager

        state_manager = await get_worker_state_manager()
        all_workers = await state_manager.get_all_workers()
    except Exception as e:
        logger.info(f"Could not retrieve worker states: {type(e).__name__}: {e}")
        all_workers = {}

    workers: list[WorkerInfo] = []
    active = idle = error = 0

    for worker_id, state in all_workers.items():
        w_status = state.get("status", "unknown")
        if w_status == "running":
            active += 1
        elif w_status == "idle":
            idle += 1
        elif w_status in ("error", "crashed"):
            error += 1

        workers.append(WorkerInfo(
            worker_id=state.get("worker_id", worker_id),
            status=w_status,
            concurrency=state.get("concurrency", 0),
            target_concurrency=state.get("target_concurrency", 0),
            pid=state.get("pid"),
            hostname=state.get("hostname"),
            last_heartbeat=state.get("last_heartbeat"),
            jobs_completed=state.get("jobs_completed", 0),
        ))

    return WorkersResponse(
        workers=workers,
        total_active=active,
        total_idle=idle,
        total_error=error,
    )


# ── Scan throughput metrics ──────────────────────────────────────────

class ThroughputBucket(BaseModel):
    """A time bucket for throughput data."""

    period: str  # e.g. "2026-02-25 14:00"
    scans_completed: int
    files_scanned: int
    files_with_pii: int


class ScanThroughputResponse(BaseModel):
    """Scan throughput metrics over time."""

    period_hours: int
    buckets: list[ThroughputBucket]
    total_scans: int
    total_files: int
    avg_files_per_hour: float
    avg_scan_duration_seconds: float | None = None


@router.get("/throughput", response_model=ScanThroughputResponse)
async def get_scan_throughput(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    bucket_size: int = Query(1, ge=1, le=24, description="Bucket size in hours"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
) -> ScanThroughputResponse:
    """Get scan throughput metrics over time.

    Returns hourly (or custom bucket) breakdown of completed scans,
    files processed, and average scan duration.
    """
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Get completed scans in the period
    scans_query = (
        select(
            ScanJob.completed_at,
            ScanJob.started_at,
            ScanJob.files_scanned,
            ScanJob.files_with_pii,
        )
        .where(
            ScanJob.tenant_id == user.tenant_id,
            ScanJob.status == JobStatus.COMPLETED,
            ScanJob.completed_at >= since,
            ScanJob.completed_at.isnot(None),
        )
        .order_by(ScanJob.completed_at)
    )
    result = await session.execute(scans_query)
    rows = result.all()

    # Build time buckets
    buckets_map: dict[str, ThroughputBucket] = {}
    total_files = 0
    total_duration = 0.0
    duration_count = 0

    for row in rows:
        # Truncate to bucket
        completed = row.completed_at
        if completed is None:
            continue
        bucket_hour = completed.replace(
            minute=0, second=0, microsecond=0,
            hour=(completed.hour // bucket_size) * bucket_size,
        )
        key = bucket_hour.strftime("%Y-%m-%d %H:%M")

        if key not in buckets_map:
            buckets_map[key] = ThroughputBucket(
                period=key, scans_completed=0, files_scanned=0, files_with_pii=0,
            )
        buckets_map[key].scans_completed += 1
        buckets_map[key].files_scanned += row.files_scanned or 0
        buckets_map[key].files_with_pii += row.files_with_pii or 0
        total_files += row.files_scanned or 0

        if row.started_at and row.completed_at:
            dur = (row.completed_at - row.started_at).total_seconds()
            if dur > 0:
                total_duration += dur
                duration_count += 1

    avg_dur = round(total_duration / duration_count, 1) if duration_count else None
    effective_hours = max(hours, 1)

    return ScanThroughputResponse(
        period_hours=hours,
        buckets=list(buckets_map.values()),
        total_scans=len(rows),
        total_files=total_files,
        avg_files_per_hour=round(total_files / effective_hours, 1),
        avg_scan_duration_seconds=avg_dur,
    )


# ── Error log viewer ─────────────────────────────────────────────────

class ErrorLogEntry(BaseModel):
    """An error log entry from recent job failures or system errors."""

    id: str
    source: str  # "job", "task", "system"
    severity: str  # "error", "warning", "critical"
    message: str
    details: dict | None = None
    timestamp: str


class ErrorLogResponse(BaseModel):
    """Paginated error log response."""

    entries: list[ErrorLogEntry]
    total: int
    page: int
    page_size: int
    has_next: bool


@router.get("/errors", response_model=ErrorLogResponse)
async def get_error_log(
    source: str | None = Query(None, description="Filter: job, task, system"),
    severity: str | None = Query(None, description="Filter: error, warning, critical"),
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    request: Request = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
) -> ErrorLogResponse:
    """Get recent error log entries from jobs, background tasks, and system.

    Aggregates errors from:
    - Failed jobs (source=job)
    - Background task crashes (source=task)
    - Audit log error entries (source=system)
    """
    entries: list[ErrorLogEntry] = []
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # 1. Failed jobs
    if source is None or source == "job":
        failed_query = (
            select(JobQueue)
            .where(
                JobQueue.tenant_id == user.tenant_id,
                JobQueue.status == JobStatus.FAILED,
                JobQueue.created_at >= since,
            )
            .order_by(JobQueue.created_at.desc())
            .limit(200)
        )
        result = await session.execute(failed_query)
        for job in result.scalars().all():
            sev = "error"
            if job.retry_count >= (job.max_retries or 3):
                sev = "critical"
            entries.append(ErrorLogEntry(
                id=str(job.id),
                source="job",
                severity=sev,
                message=job.error or f"Job {job.task_type} failed",
                details={
                    "task_type": job.task_type,
                    "retry_count": job.retry_count,
                    "worker_id": job.worker_id,
                },
                timestamp=job.created_at.isoformat() if job.created_at else since.isoformat(),
            ))

    # 2. Background task errors (from task manager)
    if source is None or source == "task":
        task_mgr = getattr(request.app.state, "task_manager", None) if request else None
        if task_mgr:
            for t in task_mgr.get_status():
                if t.get("last_error"):
                    sev = "critical" if t.get("consecutive_failures", 0) > 3 else "error"
                    entries.append(ErrorLogEntry(
                        id=f"task-{t['name']}",
                        source="task",
                        severity=sev,
                        message=t["last_error"],
                        details={
                            "task_name": t["name"],
                            "status": t.get("status"),
                            "consecutive_failures": t.get("consecutive_failures", 0),
                            "errors_total": t.get("errors_total", 0),
                        },
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))

    # 3. System audit log errors (only actions that exist in the audit_action enum)
    if source is None or source == "system":
        error_actions = [
            "scan_failed", "scan_cancelled", "policy_violation",
        ]
        try:
            audit_query = (
                select(AuditLog)
                .where(
                    AuditLog.tenant_id == user.tenant_id,
                    AuditLog.action.in_(error_actions),
                    AuditLog.created_at >= since,
                )
                .order_by(AuditLog.created_at.desc())
                .limit(200)
            )
            result = await session.execute(audit_query)
            for entry in result.scalars().all():
                entries.append(ErrorLogEntry(
                    id=str(entry.id),
                    source="system",
                    severity="warning" if entry.action == "policy_violation" else "error",
                    message=f"{entry.action}: {entry.resource_type or 'unknown'}",
                    details=entry.details if entry.details else None,
                    timestamp=entry.created_at.isoformat() if entry.created_at else since.isoformat(),
                ))
        except (SQLAlchemyError, ConnectionError, OSError) as e:
            logger.info(f"Could not query audit log for errors: {type(e).__name__}: {e}")

    # Apply severity filter
    if severity:
        entries = [e for e in entries if e.severity == severity]

    # Sort by timestamp descending
    entries.sort(key=lambda e: e.timestamp, reverse=True)

    total = len(entries)
    start = (page - 1) * page_size
    page_entries = entries[start : start + page_size]

    return ErrorLogResponse(
        entries=page_entries,
        total=total,
        page=page,
        page_size=page_size,
        has_next=(start + page_size) < total,
    )


# ── System alert configuration ───────────────────────────────────────

# In-memory alert rules store keyed by tenant_id for isolation
# (production: persist in DB or config per-tenant)
_system_alert_rules: dict[UUID, dict[str, dict]] = {}

VALID_ALERT_COMPONENTS = {"api", "db", "queue", "redis", "worker", "task", "disk", "memory", "cpu"}
VALID_ALERT_CONDITIONS = {"unhealthy", "threshold_exceeded", "offline"}
VALID_ALERT_ACTIONS = {"log", "notify", "webhook"}


class SystemAlertRule(BaseModel):
    """System failure alert rule."""

    id: str
    name: str
    component: str
    condition: str
    threshold: float | None = None
    actions: list[str] = Field(default=["log"])
    enabled: bool = True
    created_at: str


class SystemAlertRuleCreate(BaseModel):
    """Create a system alert rule."""

    name: str = Field(..., max_length=255)
    component: str = Field(..., description="Component to monitor: api, db, queue, redis, worker, task, disk, memory, cpu")
    condition: str = Field("unhealthy", description="Condition: unhealthy, threshold_exceeded, offline")
    threshold: float | None = Field(None, description="Threshold percentage (for threshold_exceeded condition)")
    actions: list[str] = Field(default=["log"], description="Actions: log, notify, webhook")
    enabled: bool = True


@router.get("/alerts", response_model=list[SystemAlertRule])
async def list_system_alerts(
    user=Depends(get_current_user),
) -> list[SystemAlertRule]:
    """List configured system alert rules for the current tenant."""
    tenant_rules = _system_alert_rules.get(user.tenant_id, {})
    return [SystemAlertRule(**rule) for rule in tenant_rules.values()]


@router.post("/alerts", response_model=SystemAlertRule, status_code=201)
async def create_system_alert(
    body: SystemAlertRuleCreate,
    user=Depends(require_admin),
) -> SystemAlertRule:
    """Create a system alert rule for failure detection."""
    if body.component not in VALID_ALERT_COMPONENTS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid component. Must be one of: {', '.join(sorted(VALID_ALERT_COMPONENTS))}",
        )
    if body.condition not in VALID_ALERT_CONDITIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid condition. Must be one of: {', '.join(sorted(VALID_ALERT_CONDITIONS))}",
        )

    from uuid import uuid4
    rule_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()

    rule_data = {
        "id": rule_id,
        "name": body.name,
        "component": body.component,
        "condition": body.condition,
        "threshold": body.threshold,
        "actions": body.actions,
        "enabled": body.enabled,
        "created_at": now,
    }
    _system_alert_rules.setdefault(user.tenant_id, {})[rule_id] = rule_data
    return SystemAlertRule(**rule_data)


@router.delete("/alerts/{alert_id}", status_code=204)
async def delete_system_alert(
    alert_id: str,
    user=Depends(require_admin),
) -> None:
    """Delete a system alert rule."""
    tenant_rules = _system_alert_rules.get(user.tenant_id, {})
    if alert_id not in tenant_rules:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    del tenant_rules[alert_id]


@router.put("/alerts/{alert_id}", response_model=SystemAlertRule)
async def update_system_alert(
    alert_id: str,
    body: SystemAlertRuleCreate,
    user=Depends(require_admin),
) -> SystemAlertRule:
    """Update a system alert rule."""
    tenant_rules = _system_alert_rules.get(user.tenant_id, {})
    if alert_id not in tenant_rules:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    if body.component not in VALID_ALERT_COMPONENTS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid component. Must be one of: {', '.join(sorted(VALID_ALERT_COMPONENTS))}",
        )

    rule = tenant_rules[alert_id]
    rule.update({
        "name": body.name,
        "component": body.component,
        "condition": body.condition,
        "threshold": body.threshold,
        "actions": body.actions,
        "enabled": body.enabled,
    })
    return SystemAlertRule(**rule)
