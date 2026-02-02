"""
Health and status API endpoints.

Provides comprehensive system health information for monitoring dashboards.
"""

import logging
import platform
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, func, text, Integer
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import ScanJob, ScanResult, JobQueue
from openlabels.auth.dependencies import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()


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

    # Optional extended info
    python_version: Optional[str] = None
    platform: Optional[str] = None
    uptime_seconds: Optional[int] = None


# Track server start time for uptime
_server_start_time = datetime.now(timezone.utc)


@router.get("/status", response_model=HealthStatus)
async def get_health_status(
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """
    Get comprehensive system health status.

    Returns status of all system components:
    - API server
    - Database connection
    - Job queue
    - ML models
    - MIP SDK
    - OCR engine
    - Scan statistics
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
    except Exception as e:
        logger.warning(f"Database health check failed: {e}")
        status["db"] = "error"
        status["db_text"] = "Disconnected"

    # Check job queue
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
    except Exception as e:
        logger.warning(f"Queue health check failed: {e}")
        status["queue"] = "warning"
        status["queue_text"] = "Unknown"

    # Check ML models
    try:
        from openlabels.core.detectors.ml_onnx import PIIBertONNXDetector, PHIBertONNXDetector
        # Check if models are loadable
        models_available = []
        try:
            detector = PIIBertONNXDetector()
            if detector._session is not None:
                models_available.append("PII-BERT")
        except Exception as e:
            logger.debug(f"PII-BERT model not available: {e}")

        try:
            detector = PHIBertONNXDetector()
            if detector._session is not None:
                models_available.append("PHI-BERT")
        except Exception as e:
            logger.debug(f"PHI-BERT model not available: {e}")

        if models_available:
            status["ml"] = "healthy"
            status["ml_text"] = f"{len(models_available)} models"
        else:
            status["ml"] = "warning"
            status["ml_text"] = "No models"
    except ImportError:
        status["ml"] = "warning"
        status["ml_text"] = "Not installed"
    except Exception as e:
        logger.debug(f"ML check failed: {e}")
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
    except Exception as e:
        logger.debug(f"MIP SDK check failed: {e}")
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
    except Exception as e:
        logger.debug(f"OCR check failed: {e}")
        status["ocr"] = "warning"
        status["ocr_text"] = "Not available"

    # Get scan statistics
    try:
        today = datetime.now(timezone.utc).date()
        today_start = datetime.combine(today, datetime.min.time())

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

    except Exception as e:
        logger.warning(f"Stats query failed: {e}")

    # Add system info
    status["python_version"] = platform.python_version()
    status["platform"] = platform.system()
    status["uptime_seconds"] = int((datetime.now(timezone.utc) - _server_start_time).total_seconds())

    return HealthStatus(**status)
