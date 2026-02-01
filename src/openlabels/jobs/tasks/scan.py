"""
Scan task implementation.

Integrates the detection engine with the job system to scan files
for sensitive data and compute risk scores.
"""

import logging
from typing import Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import ScanJob, ScanTarget, ScanResult
from openlabels.adapters import FilesystemAdapter, SharePointAdapter, OneDriveAdapter
from openlabels.server.config import get_settings
from openlabels.core.processor import FileProcessor

logger = logging.getLogger(__name__)

# Global processor instance (reuse for efficiency)
_processor: Optional[FileProcessor] = None


def get_processor(enable_ml: bool = False) -> FileProcessor:
    """Get or create the file processor."""
    global _processor
    if _processor is None:
        settings = get_settings()
        _processor = FileProcessor(
            enable_ml=enable_ml,
            ml_model_dir=getattr(settings, 'ml_model_dir', None),
            confidence_threshold=getattr(settings, 'confidence_threshold', 0.70),
        )
    return _processor


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

    Uses the OpenLabels detection engine with:
    - Checksum detectors (SSN, CC, NPI, DEA, IBAN, etc.)
    - Secrets detectors (API keys, tokens, credentials)
    - Financial detectors (crypto addresses, securities)
    - Government detectors (classification markings)
    - Optional ML detectors (PHI-BERT, PII-BERT)

    Args:
        content: Raw file bytes
        file_info: File metadata (path, name, exposure, etc.)

    Returns:
        Dict with risk_score, risk_tier, entity_counts, etc.
    """
    processor = get_processor()

    # Get exposure level from file info
    exposure_level = "PRIVATE"
    if hasattr(file_info, 'exposure'):
        exposure_level = file_info.exposure.value if hasattr(file_info.exposure, 'value') else str(file_info.exposure)

    try:
        # Process file through the detection engine
        result = await processor.process_file(
            file_path=file_info.path,
            content=content,
            exposure_level=exposure_level,
            file_size=file_info.size if hasattr(file_info, 'size') else len(content),
        )

        # Build findings list from spans (for detailed reporting)
        findings = []
        for span in result.spans[:50]:  # Limit to first 50 findings
            findings.append({
                "entity_type": span.entity_type,
                "start": span.start,
                "end": span.end,
                "confidence": span.confidence,
                "detector": span.detector,
                "tier": span.tier.name,
            })

        return {
            "risk_score": result.risk_score,
            "risk_tier": result.risk_tier.value,
            "entity_counts": result.entity_counts,
            "total_entities": sum(result.entity_counts.values()),
            "content_score": float(result.risk_score),
            "exposure_multiplier": 1.0,  # Already factored into risk_score
            "findings": findings,
            "processing_time_ms": result.processing_time_ms,
            "error": result.error,
        }

    except Exception as e:
        logger.error(f"Detection failed for {file_info.path}: {e}")
        return {
            "risk_score": 0,
            "risk_tier": "MINIMAL",
            "entity_counts": {},
            "total_entities": 0,
            "content_score": 0.0,
            "exposure_multiplier": 1.0,
            "error": str(e),
        }
