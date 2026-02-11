"""
Health and status API endpoints.

Provides comprehensive system health information for monitoring dashboards.
"""

from __future__ import annotations

import logging
import platform
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import Integer, func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import get_current_user, get_optional_user
from openlabels.core.circuit_breaker import CircuitBreaker
from openlabels.jobs.queue import JobQueue as JobQueueService
from openlabels.server.cache import get_cache_stats
from openlabels.server.db import get_session
from openlabels.server.models import JobQueue, ScanJob, ScanResult

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
    """Comprehensive health status response."""

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
    Get comprehensive system health status.

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

    # Check job queue
    pending_count = 0
    failed_count = 0
    try:
        queue_query = select(
            func.count().label("total"),
            func.sum(func.cast(JobQueue.status == "pending", Integer)).label("pending"),
            func.sum(func.cast(JobQueue.status == "failed", Integer)).label("failed"),
        )
        # Simplified query - just count pending jobs
        pending_query = select(func.count()).select_from(JobQueue).where(
            JobQueue.status == "pending"
        )
        result = await session.execute(pending_query)
        pending_count = result.scalar() or 0

        failed_query = select(func.count()).select_from(JobQueue).where(
            JobQueue.status == "failed"
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
        from openlabels.core.detectors.ml_onnx import PHIBertONNXDetector, PIIBertONNXDetector
        # Check if models are loadable
        models_available = []
        try:
            detector = PIIBertONNXDetector()
            if detector._session is not None:
                models_available.append("PII-BERT")
        except (OSError, RuntimeError, ValueError) as e:
            # Model loading failures are expected if models aren't installed
            logger.info(f"PII-BERT model not available: {type(e).__name__}: {e}")

        try:
            detector = PHIBertONNXDetector()
            if detector._session is not None:
                models_available.append("PHI-BERT")
        except (OSError, RuntimeError, ValueError) as e:
            # Model loading failures are expected if models aren't installed
            logger.info(f"PHI-BERT model not available: {type(e).__name__}: {e}")

        if models_available:
            status["ml"] = "healthy"
            status["ml_text"] = f"{len(models_available)} models"
        else:
            status["ml"] = "warning"
            status["ml_text"] = "No models"
    except ImportError:
        status["ml"] = "warning"
        status["ml_text"] = "Not installed"
    except (OSError, RuntimeError, ValueError) as e:
        # Log ML check failures - may indicate configuration issues
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
        # Log MIP SDK failures - labeling features will be unavailable
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
        # Log OCR failures - image processing will be degraded
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
                func.sum(func.cast(ScanJob.status == "completed", Integer)).label("completed"),
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
                JobQueue.status == "pending",
                JobQueue.tenant_id == user.tenant_id,
            )
            tenant_pending = (await session.execute(tenant_pending_query)).scalar() or 0

            tenant_failed_query = select(func.count()).select_from(JobQueue).where(
                JobQueue.status == "failed",
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

        # System info — only for authenticated users
        status["python_version"] = platform.python_version()
        status["platform"] = platform.system()
        status["uptime_seconds"] = int((datetime.now(timezone.utc) - _server_start_time).total_seconds())

    return HealthStatus(**status)


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
