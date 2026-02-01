"""
Scan task implementation.
"""

import logging
from typing import Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import ScanJob, ScanTarget, ScanResult
from openlabels.adapters import FilesystemAdapter, SharePointAdapter, OneDriveAdapter
from openlabels.server.config import get_settings

logger = logging.getLogger(__name__)


async def execute_scan_task(
    session: AsyncSession,
    payload: dict,
) -> dict:
    """
    Execute a scan task.

    Args:
        session: Database session
        payload: Task payload containing job_id

    Returns:
        Result dictionary with scan statistics
    """
    job_id = UUID(payload["job_id"])
    job = await session.get(ScanJob, job_id)

    if not job:
        raise ValueError(f"Job not found: {job_id}")

    target = await session.get(ScanTarget, job.target_id)
    if not target:
        raise ValueError(f"Target not found: {job.target_id}")

    # Update job status
    job.status = "running"
    await session.flush()

    # Get adapter
    adapter = _get_adapter(target.adapter, target.config)

    # Scan statistics
    stats = {
        "files_scanned": 0,
        "files_with_pii": 0,
        "total_entities": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "minimal_count": 0,
    }

    try:
        # Get target path from config
        target_path = target.config.get("path") or target.config.get("site_id")

        async for file_info in adapter.list_files(target_path):
            try:
                # Read file content
                content = await adapter.read_file(file_info)

                # Run detection
                result = await _detect_and_score(content, file_info)

                # Save result
                scan_result = ScanResult(
                    tenant_id=job.tenant_id,
                    job_id=job.id,
                    file_path=file_info.path,
                    file_name=file_info.name,
                    file_size=file_info.size,
                    file_modified=file_info.modified,
                    risk_score=result["risk_score"],
                    risk_tier=result["risk_tier"],
                    entity_counts=result["entity_counts"],
                    total_entities=result["total_entities"],
                    exposure_level=file_info.exposure.value,
                    owner=file_info.owner,
                    content_score=result.get("content_score"),
                    exposure_multiplier=result.get("exposure_multiplier"),
                    findings=result.get("findings"),
                )
                session.add(scan_result)

                # Update stats
                stats["files_scanned"] += 1
                if result["total_entities"] > 0:
                    stats["files_with_pii"] += 1
                stats["total_entities"] += result["total_entities"]
                stats[f"{result['risk_tier'].lower()}_count"] += 1

                # Update job progress
                job.files_scanned = stats["files_scanned"]
                job.files_with_pii = stats["files_with_pii"]
                job.progress = {
                    "current_file": file_info.name,
                    "files_scanned": stats["files_scanned"],
                }

                # Commit periodically
                if stats["files_scanned"] % 100 == 0:
                    await session.commit()

            except Exception as e:
                logger.warning(f"Error scanning file {file_info.path}: {e}")
                continue

        # Mark job as completed
        job.status = "completed"
        await session.commit()

        return stats

    except Exception as e:
        job.status = "failed"
        job.error = str(e)
        await session.commit()
        raise


def _get_adapter(adapter_type: str, config: dict):
    """Get the appropriate adapter instance."""
    settings = get_settings()

    if adapter_type == "filesystem":
        return FilesystemAdapter(
            service_account=config.get("service_account"),
        )
    elif adapter_type == "sharepoint":
        return SharePointAdapter(
            tenant_id=settings.auth.tenant_id,
            client_id=settings.auth.client_id,
            client_secret=settings.auth.client_secret,
        )
    elif adapter_type == "onedrive":
        return OneDriveAdapter(
            tenant_id=settings.auth.tenant_id,
            client_id=settings.auth.client_id,
            client_secret=settings.auth.client_secret,
        )
    else:
        raise ValueError(f"Unknown adapter type: {adapter_type}")


async def _detect_and_score(content: bytes, file_info) -> dict:
    """
    Run detection and scoring on file content.

    This is a placeholder that will be replaced with actual detection
    engine integration from openrisk.
    """
    # TODO: Integrate with openrisk detection engine
    # For now, return placeholder results

    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        text = ""

    # Placeholder detection - to be replaced with real detection
    entity_counts = {}
    total_entities = 0

    # Simple pattern matching placeholder
    import re

    # SSN pattern
    ssn_matches = len(re.findall(r"\b\d{3}-\d{2}-\d{4}\b", text))
    if ssn_matches:
        entity_counts["SSN"] = ssn_matches
        total_entities += ssn_matches

    # Email pattern
    email_matches = len(re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text))
    if email_matches:
        entity_counts["EMAIL"] = email_matches
        total_entities += email_matches

    # Credit card pattern
    cc_matches = len(re.findall(r"\b(?:\d{4}[- ]?){3}\d{4}\b", text))
    if cc_matches:
        entity_counts["CREDIT_CARD"] = cc_matches
        total_entities += cc_matches

    # Calculate risk score
    risk_score = min(100, total_entities * 10)

    # Determine risk tier
    if risk_score >= 80:
        risk_tier = "CRITICAL"
    elif risk_score >= 60:
        risk_tier = "HIGH"
    elif risk_score >= 40:
        risk_tier = "MEDIUM"
    elif risk_score >= 20:
        risk_tier = "LOW"
    else:
        risk_tier = "MINIMAL"

    return {
        "risk_score": risk_score,
        "risk_tier": risk_tier,
        "entity_counts": entity_counts,
        "total_entities": total_entities,
        "content_score": float(risk_score),
        "exposure_multiplier": 1.0,
    }
