"""
Scan task implementation.

Integrates the detection engine with the job system to scan files
for sensitive data and compute risk scores.

Supports two execution modes:
- Sequential: Traditional file-by-file processing (fallback)
- Pipeline: Bounded-concurrency processing with overlapped I/O and compute (default)
- Fan-out: Coordinator splits work across multiple workers (large targets)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.adapters import (
    AzureBlobAdapter,
    FilesystemAdapter,
    GCSAdapter,
    OneDriveAdapter,
    S3Adapter,
    SharePointAdapter,
)
from openlabels.adapters.base import ExposureLevel, FileInfo
from openlabels.core.policies.engine import get_policy_engine
from openlabels.core.policies.schema import EntityMatch
from openlabels.core.processor import FileProcessor
from openlabels.exceptions import AdapterError, JobError
from openlabels.jobs.pipeline import FilePipeline, PipelineConfig, PipelineContext
from openlabels.labeling.engine import LabelingEngine
from openlabels.server.config import get_settings
from openlabels.server.metrics import (
    record_entities_found,
    record_file_processed,
    record_processing_duration,
)
from openlabels.server.models import LabelRule, ScanJob, ScanResult, ScanTarget, SensitivityLabel

logger = logging.getLogger(__name__)

# WebSocket streaming support
_ws_streaming_enabled = True
try:
    from openlabels.server.routes.ws import (
        send_scan_completed,
        send_scan_file_result,
        send_scan_progress,
    )
except ImportError:
    _ws_streaming_enabled = False
    logger.debug("WebSocket streaming not available")

# Global processor instance (reuse for efficiency within job lifecycle)
# IMPORTANT: Call cleanup_processor() during worker shutdown to release memory
_processor: FileProcessor | None = None

# Registry of shutdown callbacks for graceful cleanup
_shutdown_callbacks: list = []


def register_shutdown_callback(callback) -> None:
    """
    Register a callback to be called during worker shutdown.

    Args:
        callback: Callable that takes no arguments
    """
    _shutdown_callbacks.append(callback)


def get_processor(enable_ml: bool = False) -> FileProcessor:
    """
    Get or create the file processor.

    The processor is cached globally for efficiency during job execution.
    Call cleanup_processor() during worker shutdown to release resources.
    """
    global _processor
    if _processor is None:
        settings = get_settings()
        from openlabels.core.detectors.config import DetectionConfig
        _processor = FileProcessor(
            config=DetectionConfig(
                enable_ml=enable_ml,
                ml_model_dir=getattr(settings, 'ml_model_dir', None),
                confidence_threshold=getattr(settings, 'confidence_threshold', 0.70),
            ),
        )
        logger.debug("Created ML processor instance")
    return _processor


def cleanup_processor() -> None:
    """
    Release the global processor and free ML model memory.

    This should be called during worker graceful shutdown to release
    the 200-500MB of memory held by ML models. The processor will be
    recreated on next use if needed.
    """
    global _processor
    if _processor is not None:
        try:
            _processor.cleanup()
            logger.info("Global file processor cleaned up")
        except (RuntimeError, OSError, AttributeError) as e:
            logger.warning(f"Error during processor cleanup: {e}")
        finally:
            _processor = None


def run_shutdown_callbacks() -> None:
    """
    Run all registered shutdown callbacks.

    Called by the worker during graceful shutdown.
    """
    # Always cleanup the processor
    cleanup_processor()

    # Run any additional registered callbacks
    for callback in _shutdown_callbacks:
        try:
            callback()
        except (RuntimeError, OSError) as e:
            logger.warning(f"Error in shutdown callback: {e}")

    _shutdown_callbacks.clear()
    logger.info("All shutdown callbacks completed")


async def _check_cancellation(session: AsyncSession, job_id: UUID) -> bool:
    """
    Check if a job has been cancelled.

    Refreshes the job from the database to get current status.
    Returns True if job should stop (cancelled).
    """
    # Refresh job status from database
    result = await session.execute(
        select(ScanJob.status).where(ScanJob.id == job_id)
    )
    current_status = result.scalar_one_or_none()
    return current_status == "cancelled"


# How often to check for cancellation (every N files)
CANCELLATION_CHECK_INTERVAL = 10


async def execute_scan_task(
    session: AsyncSession,
    payload: dict,
) -> dict:
    """
    Execute a scan task with delta scanning support.

    Supports mid-scan cancellation - checks job status periodically
    and stops processing if cancelled.

    Args:
        session: Database session
        payload: Task payload containing:
            - job_id: UUID of the scan job
            - force_full_scan: bool (optional) - Force full scan, ignore inventory

    Returns:
        Result dictionary with scan statistics
    """
    from openlabels.jobs.inventory import InventoryService, get_folder_path

    job_id = UUID(payload["job_id"])
    force_full_scan = payload.get("force_full_scan", False)

    job = await session.get(ScanJob, job_id)

    if not job:
        raise JobError(
            "Scan job not found in database",
            job_id=str(job_id),
            job_type="scan",
            context="job may have been deleted or never created",
        )

    # Check if job was cancelled before we start
    if job.status == "cancelled":
        logger.info(f"Scan job {job_id} was cancelled before processing")
        return {"status": "cancelled", "files_scanned": 0}

    target = await session.get(ScanTarget, job.target_id)
    if not target:
        raise JobError(
            "Scan target not found for job",
            job_id=str(job_id),
            job_type="scan",
            context=f"target_id={job.target_id} may have been deleted",
        )

    # Check if this scan should be split into partitions (fan-out)
    if not payload.get("_skip_fanout"):
        try:
            from openlabels.jobs.coordinator import ScanCoordinator
            coordinator = ScanCoordinator(session, job.tenant_id)
            temp_adapter = _get_adapter(target.adapter, target.config)
            await temp_adapter.__aenter__()
            try:
                decision = await coordinator.evaluate(job, target, temp_adapter)
                if decision.should_fanout:
                    logger.info(
                        "Fan-out scan for job %s: %d estimated files → %d partitions (%s)",
                        job_id, decision.estimated_files, decision.num_partitions, decision.reason,
                    )
                    await coordinator.create_partitions(
                        job, target, temp_adapter,
                        num_partitions=decision.num_partitions,
                        estimated_files=decision.estimated_files,
                    )
                    return {
                        "status": "fanout",
                        "partitions": decision.num_partitions,
                        "estimated_files": decision.estimated_files,
                    }
                else:
                    logger.debug("Single-worker scan for job %s: %s", job_id, decision.reason)
            finally:
                await temp_adapter.__aexit__(None, None, None)
        except (ImportError, RuntimeError, ValueError, OSError, ConnectionError) as e:
            logger.warning("Fan-out evaluation failed, falling back to single-worker: %s", e)

    # Update job status
    job.status = "running"
    await session.flush()

    # Get adapter (use as async context manager for proper resource cleanup)
    adapter = _get_adapter(target.adapter, target.config)
    await adapter.__aenter__()

    # Initialize inventory service for delta scanning (on-demand lookups, no bulk load)
    inventory = InventoryService(session, job.tenant_id, target.id)
    folder_stats: dict[str, dict] = {}

    # Security: Get max file size limit to prevent DoS via memory exhaustion
    settings = get_settings()
    max_file_size_bytes = settings.detection.max_file_size_mb * 1024 * 1024

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
        "files_skipped": 0,  # Delta scan skips
        "scan_mode": "full" if force_full_scan else "delta",
    }

    try:
        # Get target path from config
        target_path = target.config.get("path") or target.config.get("site_id")

        # Support scan_all_sites / scan_all_users auto-discovery
        scan_paths: list[str] = []
        if target.adapter == "sharepoint" and settings.adapters.sharepoint.scan_all_sites and not target_path:
            sp_adapter: SharePointAdapter = adapter  # type: ignore[assignment]
            sites = await sp_adapter.list_sites()
            scan_paths = [s["id"] for s in sites if s.get("id")]
            logger.info("scan_all_sites enabled: discovered %d sites", len(scan_paths))
        elif target.adapter == "onedrive" and settings.adapters.onedrive.scan_all_users and not target_path:
            od_adapter: OneDriveAdapter = adapter  # type: ignore[assignment]
            all_users = await od_adapter.list_users()
            scan_paths = [u["id"] for u in all_users if u.get("id")]
            logger.info("scan_all_users enabled: discovered %d users", len(scan_paths))
        else:
            scan_paths = [target_path] if target_path else []

        if not scan_paths:
            logger.warning(
                "No scan paths discovered for target %s (adapter=%s). "
                "Check adapter config and scan_all_sites/scan_all_users settings.",
                target.id, target.adapter,
            )

        async def _iter_all_files():
            for sp in scan_paths:
                try:
                    async for fi in adapter.list_files(sp):
                        yield fi
                except (ConnectionError, OSError, RuntimeError, ValueError) as list_err:
                    logger.error(
                        "Failed to list files for path %r (adapter=%s): %s",
                        sp, target.adapter, list_err,
                    )
                    # Continue to next path instead of aborting entire scan

        # Build per-file processing function for the pipeline
        async def _process_one_file(file_info: FileInfo, ctx: PipelineContext) -> None:
            """Process a single file — called concurrently by the pipeline."""
            folder_path = get_folder_path(file_info.path)

            # Track folder stats
            if folder_path not in folder_stats:
                folder_stats[folder_path] = {
                    "file_count": 0,
                    "total_size": 0,
                    "has_sensitive": False,
                    "highest_risk": None,
                    "total_entities": 0,
                }
            folder_stats[folder_path]["file_count"] += 1
            folder_stats[folder_path]["total_size"] += file_info.size

            # Security: Skip files that exceed size limit to prevent DoS
            if file_info.size > max_file_size_bytes:
                logger.warning(
                    "Skipping file exceeding size limit: %s (%d bytes > %d bytes)",
                    file_info.path, file_info.size, max_file_size_bytes,
                )
                ctx.stats.files_skipped += 1
                return

            # Read file content with size limit
            content = await adapter.read_file(file_info, max_size_bytes=max_file_size_bytes)
            content_hash = inventory.compute_content_hash(content)

            # Check if file needs scanning (delta mode)
            should_scan, scan_reason = await inventory.should_scan_file(
                file_info, content_hash, force_full_scan
            )
            if not should_scan:
                ctx.stats.files_skipped += 1
                logger.debug("Skipping unchanged file: %s", file_info.path)
                return

            # Run detection
            result = await _detect_and_score(content, file_info, target.adapter)

            # Update pipeline stats (all files, regardless of sensitivity)
            ctx.stats.record_result(result["risk_tier"], result["total_entities"])

            # Only persist ScanResult + inventory for sensitive files
            if result["total_entities"] > 0:
                scan_result = ScanResult(
                    tenant_id=job.tenant_id,
                    job_id=job.id,
                    file_path=file_info.path,
                    file_name=file_info.name,
                    file_size=file_info.size,
                    file_modified=file_info.modified,
                    content_hash=content_hash,
                    adapter_item_id=file_info.item_id,
                    risk_score=result["risk_score"],
                    risk_tier=result["risk_tier"],
                    entity_counts=result["entity_counts"],
                    total_entities=result["total_entities"],
                    exposure_level=file_info.exposure.value,
                    owner=file_info.owner,
                    content_score=result.get("content_score"),
                    exposure_multiplier=result.get("exposure_multiplier"),
                    co_occurrence_rules=result.get("co_occurrence_rules"),
                    findings=result.get("findings"),
                    policy_violations=result.get("policy_violations"),
                )
                session.add(scan_result)

                # Execute policy-triggered remediation actions
                if result.get("policy_violations"):
                    try:
                        from openlabels.core.policies.actions import (
                            PolicyActionContext,
                            PolicyActionExecutor,
                        )
                        await session.flush()
                        action_ctx = PolicyActionContext(
                            file_path=file_info.path,
                            tenant_id=job.tenant_id,
                            scan_result_id=scan_result.id,
                            risk_tier=result["risk_tier"],
                            violations=result["policy_violations"],
                        )
                        executor = PolicyActionExecutor()
                        action_results = await executor.execute_all(action_ctx)
                        for ar in action_results:
                            if not ar.success:
                                logger.warning(
                                    "Policy action %s failed for %s: %s",
                                    ar.action, file_info.path, ar.error,
                                )
                    except (ImportError, RuntimeError, ValueError, OSError, ConnectionError) as e:
                        logger.error("Policy action failed for %s: %s", file_info.path, e)

                # Update folder stats for inventory
                folder_stats[folder_path]["has_sensitive"] = True
                folder_stats[folder_path]["total_entities"] += result["total_entities"]
                risk_priority = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "MINIMAL": 1}
                current_risk = folder_stats[folder_path]["highest_risk"]
                new_risk = result["risk_tier"]
                if current_risk is None or risk_priority.get(new_risk, 0) > risk_priority.get(current_risk, 0):
                    folder_stats[folder_path]["highest_risk"] = new_risk

                try:
                    await inventory.update_file_inventory(
                        file_info=file_info,
                        scan_result=scan_result,
                        content_hash=content_hash,
                        job_id=job.id,
                    )
                except (OSError, RuntimeError, ValueError) as inv_err:
                    logger.warning("Inventory update failed for %s: %s", file_info.path, inv_err)

            # Update job progress
            job.files_scanned = ctx.stats.files_scanned
            job.files_with_pii = ctx.stats.files_with_pii
            job.progress = {
                "current_file": file_info.name,
                "files_scanned": ctx.stats.files_scanned,
                "files_skipped": ctx.stats.files_skipped,
            }

            # Stream file result via WebSocket
            if _ws_streaming_enabled:
                try:
                    await send_scan_file_result(
                        scan_id=job.id,
                        file_path=file_info.path,
                        risk_score=result["risk_score"],
                        risk_tier=result["risk_tier"],
                        entity_counts=result["entity_counts"],
                    )
                except (ConnectionError, OSError) as ws_err:
                    logger.debug("WebSocket broadcast failed: %s", ws_err)

            # Stream progress periodically
            if ctx.stats.files_scanned % 10 == 0 and _ws_streaming_enabled:
                try:
                    await send_scan_progress(
                        scan_id=job.id,
                        status="running",
                        progress={
                            "files_scanned": ctx.stats.files_scanned,
                            "files_with_pii": ctx.stats.files_with_pii,
                            "files_skipped": ctx.stats.files_skipped,
                            "current_file": file_info.name,
                        },
                    )
                except (ConnectionError, OSError) as ws_err:
                    logger.debug("WebSocket progress failed: %s", ws_err)

        # Determine pipeline configuration
        pipeline_config = await _build_pipeline_config(settings, job.tenant_id, session)

        # Run the pipeline
        pipeline = FilePipeline(
            config=pipeline_config,
            process_fn=_process_one_file,
            commit_fn=session.commit,
            cancellation_fn=lambda: _check_cancellation(session, job_id),
        )
        pipeline_stats = await pipeline.run(_iter_all_files())

        # Merge pipeline stats into legacy stats dict for backward compat
        stats.update(pipeline_stats.to_dict())

        # Handle cancellation detected by pipeline
        if pipeline.cancelled:
            logger.info("Scan job %s cancelled mid-scan at %d files", job_id, stats["files_scanned"])
            job.status = "cancelled"
            stats["status"] = "cancelled"
            await session.commit()
            if _ws_streaming_enabled:
                try:
                    await send_scan_completed(
                        scan_id=job.id,
                        status="cancelled",
                        summary={
                            "files_scanned": stats["files_scanned"],
                            "files_with_pii": stats["files_with_pii"],
                            "reason": "User cancelled",
                        },
                    )
                except (ConnectionError, OSError):
                    pass
            return stats

        # Update folder inventory
        for folder_path, fstats in folder_stats.items():
            try:
                await inventory.update_folder_inventory(
                    folder_path=folder_path,
                    adapter=target.adapter,
                    job_id=job.id,
                    file_count=fstats["file_count"],
                    total_size=fstats["total_size"],
                    has_sensitive=fstats["has_sensitive"],
                    highest_risk=fstats["highest_risk"],
                    total_entities=fstats["total_entities"],
                )
            except (OSError, RuntimeError, ValueError) as inv_err:
                logger.warning("Folder inventory update failed for %s: %s", folder_path, inv_err)

        # Mark files that weren't seen (may be deleted/moved)
        missing_count = await inventory.mark_missing_files(job.id)
        if missing_count > 0:
            logger.info(f"Marked {missing_count} files for rescan (not seen in current scan)")
            stats["files_missing"] = missing_count

        # Get inventory stats
        inv_stats = await inventory.get_inventory_stats()
        stats["inventory"] = inv_stats

        # Mark job as completed
        job.status = "completed"
        await session.commit()

        # Stream completion via WebSocket
        if _ws_streaming_enabled:
            try:
                await send_scan_completed(
                    scan_id=job.id,
                    status="completed",
                    summary={
                        "files_scanned": stats["files_scanned"],
                        "files_with_pii": stats["files_with_pii"],
                        "files_skipped": stats["files_skipped"],
                        "total_entities": stats["total_entities"],
                        "scan_mode": stats["scan_mode"],
                        "risk_breakdown": {
                            "critical": stats["critical_count"],
                            "high": stats["high_count"],
                            "medium": stats["medium_count"],
                            "low": stats["low_count"],
                            "minimal": stats["minimal_count"],
                        },
                    },
                )
            except (ConnectionError, OSError) as ws_err:
                logger.debug(f"WebSocket completion failed: {ws_err}")

        # Auto-labeling if enabled
        settings = get_settings()
        if settings.labeling.enabled and settings.labeling.mode == "auto":
            try:
                auto_label_stats = await _auto_label_results(session, job)
                stats["auto_labeled"] = auto_label_stats.get("labeled", 0)
                stats["auto_label_errors"] = auto_label_stats.get("errors", 0)
            except PermissionError as e:
                logger.error(f"Auto-labeling failed - permission denied: {e}")
                stats["auto_label_error"] = str(e)
            except OSError as e:
                logger.error(f"Auto-labeling failed - OS error: {e}")
                stats["auto_label_error"] = str(e)
            except RuntimeError as e:
                logger.error(f"Auto-labeling failed - runtime error: {e}")
                stats["auto_label_error"] = str(e)

        # Cloud label sync-back for S3/GCS adapters (Phase L, non-fatal)
        target = await session.get(ScanTarget, job.target_id)
        if target and target.adapter in ("s3", "gcs") and settings.labeling.enabled:
            adapter_settings = getattr(settings.adapters, target.adapter, None)
            if adapter_settings and getattr(adapter_settings, "label_sync_enabled", False):
                try:
                    sync_stats = await _cloud_label_sync_back(
                        session, job, target, settings
                    )
                    stats["label_sync_back"] = sync_stats
                except (ConnectionError, OSError, RuntimeError, ValueError) as e:
                    logger.warning(
                        "Cloud label sync-back failed for job %s: %s", job.id, e
                    )
                    stats["label_sync_back_error"] = str(e)

        # Flush scan results + inventory to Parquet data lake (non-fatal)
        try:
            from openlabels.analytics.flush import flush_scan_to_catalog
            from openlabels.analytics.storage import create_storage

            _catalog_storage = create_storage(settings.catalog)
            flushed = await flush_scan_to_catalog(session, job, _catalog_storage)
            stats["catalog_flushed"] = flushed
        except (ImportError, OSError, RuntimeError, ValueError) as e:
            logger.warning(
                "Catalog flush failed for job %s; data lake will catch up on next flush: %s",
                job.id,
                e,
            )
            stats["catalog_flush_error"] = str(e)

        # Post-scan SIEM export (fire-and-forget, non-fatal)
        if settings.siem_export.enabled and settings.siem_export.mode == "post_scan":
            try:
                from openlabels.export.engine import (
                    ExportEngine,
                    scan_result_to_export_records,
                )
                from openlabels.export.setup import build_adapters_from_settings

                adapters = build_adapters_from_settings(settings.siem_export)
                if adapters:
                    engine = ExportEngine(adapters)
                    # Stream scan results in batches to avoid loading all into memory
                    batch_size = 500
                    total_exported = {}
                    result_stream = await session.stream(
                        select(ScanResult).where(ScanResult.job_id == job.id)
                    )
                    async for batch in result_stream.scalars().partitions(batch_size):
                        result_dicts = [
                            {
                                "file_path": r.file_path,
                                "risk_score": r.risk_score,
                                "risk_tier": r.risk_tier,
                                "entity_counts": r.entity_counts,
                                "policy_violations": r.policy_violations,
                                "owner": r.owner,
                                "scanned_at": r.scanned_at,
                            }
                            for r in batch
                        ]
                        export_records = scan_result_to_export_records(
                            result_dicts, job.tenant_id,
                        )
                        batch_results = await engine.export_full(
                            job.tenant_id,
                            export_records,
                            record_types=settings.siem_export.export_record_types or None,
                        )
                        for key, val in batch_results.items():
                            total_exported[key] = total_exported.get(key, 0) + val
                    stats["siem_export"] = total_exported
                    logger.info(
                        "Post-scan SIEM export for job %s: %s",
                        job.id, total_exported,
                    )
            except (ImportError, ConnectionError, OSError, RuntimeError, ValueError) as e:
                logger.warning(
                    "SIEM export failed for job %s (non-fatal): %s",
                    job.id, e,
                )
                stats["siem_export_error"] = str(e)

        # Generate pre-aggregated summary for fast dashboard queries
        try:
            from openlabels.jobs.summaries import generate_scan_summary
            auto_label_stats_dict = None
            if "auto_labeled" in stats or "auto_label_errors" in stats:
                auto_label_stats_dict = {
                    "labeled": stats.get("auto_labeled", 0),
                    "errors": stats.get("auto_label_errors", 0),
                }
            await generate_scan_summary(session, job, auto_label_stats_dict)
            await session.commit()
        except Exception as e:  # Non-fatal: don't fail the scan if summary fails
            logger.warning("Summary generation failed for job %s: %s", job.id, e)

        return stats

    except PermissionError as e:
        job.status = "failed"
        job.error = f"Permission denied: {e}"
        await session.commit()

        # Stream failure via WebSocket
        if _ws_streaming_enabled:
            try:
                await send_scan_completed(
                    scan_id=job.id,
                    status="failed",
                    summary={
                        "error": f"Permission denied: {e}",
                        "files_scanned": stats.get("files_scanned", 0),
                    },
                )
            except (ConnectionError, OSError) as ws_err:
                logger.debug(f"Failed to send scan failed event: {ws_err}")

        raise

    except OSError as e:
        job.status = "failed"
        job.error = f"OS error: {e}"
        await session.commit()

        if _ws_streaming_enabled:
            try:
                await send_scan_completed(
                    scan_id=job.id,
                    status="failed",
                    summary={
                        "error": f"OS error: {e}",
                        "files_scanned": stats.get("files_scanned", 0),
                    },
                )
            except (ConnectionError, OSError) as ws_err:
                logger.debug(f"Failed to send scan failed event: {ws_err}")

        raise

    finally:
        # Close adapter to release HTTP connections and SDK sessions
        try:
            await adapter.__aexit__(None, None, None)
        except (ConnectionError, OSError, RuntimeError) as adapter_err:
            logger.debug("Adapter cleanup error (non-fatal): %s", adapter_err)

        # Release ML processor to free memory (200-500MB)
        # This ensures cleanup happens whether scan completes, fails, or is cancelled
        cleanup_processor()


def _get_adapter(adapter_type: str, config: dict):
    """
    Get the appropriate adapter instance.

    Args:
        adapter_type: Type of adapter (filesystem, sharepoint, onedrive, s3, gcs)
        config: Adapter-specific configuration

    Returns:
        Configured adapter instance

    Raises:
        AdapterError: If adapter type is unknown or configuration is invalid
    """
    settings = get_settings()

    if adapter_type == "filesystem":
        return FilesystemAdapter(
            service_account=config.get("service_account"),
        )
    elif adapter_type == "sharepoint":
        if not settings.auth.tenant_id or not settings.auth.client_id:
            raise AdapterError(
                "SharePoint adapter requires auth configuration",
                adapter_type="sharepoint",
                context="missing tenant_id or client_id in settings",
            )
        return SharePointAdapter(
            tenant_id=settings.auth.tenant_id,
            client_id=settings.auth.client_id,
            client_secret=settings.auth.client_secret,
        )
    elif adapter_type == "onedrive":
        if not settings.auth.tenant_id or not settings.auth.client_id:
            raise AdapterError(
                "OneDrive adapter requires auth configuration",
                adapter_type="onedrive",
                context="missing tenant_id or client_id in settings",
            )
        return OneDriveAdapter(
            tenant_id=settings.auth.tenant_id,
            client_id=settings.auth.client_id,
            client_secret=settings.auth.client_secret,
        )
    elif adapter_type == "s3":
        return S3Adapter(
            bucket=config.get("bucket", ""),
            prefix=config.get("prefix", ""),
            region=config.get("region", settings.adapters.s3.region),
            access_key=config.get("access_key", settings.adapters.s3.access_key),
            secret_key=config.get("secret_key", settings.adapters.s3.secret_key),
            endpoint_url=config.get("endpoint_url", settings.adapters.s3.endpoint_url),
        )
    elif adapter_type == "gcs":
        return GCSAdapter(
            bucket=config.get("bucket", ""),
            prefix=config.get("prefix", ""),
            project=config.get("project", settings.adapters.gcs.project),
            credentials_path=config.get(
                "credentials_path", settings.adapters.gcs.credentials_path
            ),
        )
    elif adapter_type == "azure_blob":
        return AzureBlobAdapter(
            storage_account=config.get(
                "storage_account", settings.adapters.azure_blob.storage_account
            ),
            container=config.get("container", ""),
            prefix=config.get("prefix", ""),
            connection_string=config.get(
                "connection_string", settings.adapters.azure_blob.connection_string
            ),
            account_key=config.get(
                "account_key", settings.adapters.azure_blob.account_key
            ),
            sas_token=config.get(
                "sas_token", settings.adapters.azure_blob.sas_token
            ),
        )
    else:
        raise AdapterError(
            f"Unknown adapter type: {adapter_type}",
            adapter_type=adapter_type,
            context="valid types are: filesystem, sharepoint, onedrive, s3, gcs, azure_blob",
        )


async def _auto_label_results(session: AsyncSession, job: ScanJob) -> dict:
    """
    Automatically apply labels to scan results based on rules.

    Args:
        session: Database session
        job: Completed scan job

    Returns:
        Dict with labeling statistics
    """
    settings = get_settings()
    stats = {"labeled": 0, "errors": 0, "skipped": 0}

    # Get label rules ordered by priority (highest first)
    rules_query = (
        select(LabelRule, SensitivityLabel)
        .join(SensitivityLabel, LabelRule.label_id == SensitivityLabel.id)
        .where(LabelRule.tenant_id == job.tenant_id)
        .order_by(LabelRule.priority.desc())
        .limit(500)
    )
    rules_result = await session.execute(rules_query)
    rules_data = rules_result.all()

    # Prefetch all labels by name for settings fallback (avoids N+1 queries)
    # This loads all tenant labels once instead of querying per-result
    labels_by_name: dict[str, SensitivityLabel] = {}
    if settings.labeling.risk_tier_mapping and any(settings.labeling.risk_tier_mapping.values()):
        label_names_needed = [name for name in settings.labeling.risk_tier_mapping.values() if name]
        if label_names_needed:
            labels_query = select(SensitivityLabel).where(
                SensitivityLabel.tenant_id == job.tenant_id,
                SensitivityLabel.name.in_(label_names_needed),
            )
            labels_result = await session.execute(labels_query)
            labels_by_name = {label.name: label for label in labels_result.scalars().all()}

    if not rules_data:
        # No rules configured, use risk_tier_mapping from settings
        risk_tier_mapping = settings.labeling.risk_tier_mapping
        if not any(risk_tier_mapping.values()):
            logger.info("No label rules or risk tier mappings configured")
            return stats
        # Build lookup from prefetched labels
        risk_tier_rules = {}
        entity_type_rules = {}
    else:
        # Build risk_tier and entity_type rule lookups
        risk_tier_rules = {}
        entity_type_rules = {}

        for rule, label in rules_data:
            if rule.rule_type == "risk_tier":
                if rule.match_value not in risk_tier_rules:
                    risk_tier_rules[rule.match_value] = (rule, label)
            elif rule.rule_type == "entity_type":
                if rule.match_value not in entity_type_rules:
                    entity_type_rules[rule.match_value] = (rule, label)

    # Initialize labeling engine
    labeling_engine = LabelingEngine(
        tenant_id=settings.auth.tenant_id,
        client_id=settings.auth.client_id,
        client_secret=settings.auth.client_secret,
    )

    # Get target for adapter info
    target = await session.get(ScanTarget, job.target_id)

    # Stream unlabeled results in batches to avoid loading all into memory
    results_query = (
        select(ScanResult)
        .where(ScanResult.job_id == job.id)
        .where(ScanResult.label_applied == False)
    )
    result_stream = await session.stream(results_query)
    has_results = False

    async for partition in result_stream.scalars().partitions(500):
        for result in partition:
            has_results = True
            try:
                matched_label = None
                matched_label_name = None

                # Try to match by entity type first (highest priority)
                if entity_type_rules and result.entity_counts:
                    for entity_type in result.entity_counts.keys():
                        if entity_type in entity_type_rules:
                            rule, label = entity_type_rules[entity_type]
                            matched_label = label.id
                            matched_label_name = label.name
                            break

                # Fall back to risk tier matching
                if not matched_label:
                    if risk_tier_rules and result.risk_tier in risk_tier_rules:
                        rule, label = risk_tier_rules[result.risk_tier]
                        matched_label = label.id
                        matched_label_name = label.name
                    elif settings.labeling.risk_tier_mapping:
                        # Use settings mapping as fallback with prefetched labels
                        label_name = settings.labeling.risk_tier_mapping.get(result.risk_tier)
                        if label_name and label_name in labels_by_name:
                            label = labels_by_name[label_name]
                            matched_label = label.id
                            matched_label_name = label.name

                if not matched_label:
                    stats["skipped"] += 1
                    continue

                # Build FileInfo for labeling engine
                file_info = FileInfo(
                    path=result.file_path,
                    name=result.file_name,
                    size=result.file_size or 0,
                    modified=result.file_modified or datetime.now(timezone.utc),
                    adapter=target.adapter if target else "filesystem",
                    exposure=ExposureLevel(result.exposure_level) if result.exposure_level else ExposureLevel.PRIVATE,
                    item_id=result.adapter_item_id,
                )

                # Apply label
                label_result = await labeling_engine.apply_label(
                    file_info=file_info,
                    label_id=matched_label,
                    label_name=matched_label_name,
                )

                if label_result.success:
                    result.current_label_id = matched_label
                    result.current_label_name = matched_label_name
                    result.label_applied = True
                    result.label_applied_at = datetime.now(timezone.utc)
                    stats["labeled"] += 1
                    logger.info(f"Applied label '{matched_label_name}' to {result.file_path}")
                else:
                    result.label_error = label_result.error
                    stats["errors"] += 1
                    logger.warning(f"Failed to label {result.file_path}: {label_result.error}")

            except PermissionError as e:
                stats["errors"] += 1
                logger.error(f"Permission denied auto-labeling {result.file_path}: {e}")
            except OSError as e:
                stats["errors"] += 1
                logger.error(f"OS error auto-labeling {result.file_path}: {e}")
            except RuntimeError as e:
                stats["errors"] += 1
                logger.error(f"Runtime error auto-labeling {result.file_path}: {e}")

    if not has_results:
        logger.info(f"No unlabeled results for job {job.id}")

    await session.commit()
    return stats


async def _cloud_label_sync_back(
    session: AsyncSession,
    job: ScanJob,
    target: ScanTarget,
    settings,
) -> dict:
    """Re-upload labeled files to S3/GCS with label metadata (Phase L).

    After auto-labeling writes labels to the DB, this step syncs those
    labels back to the cloud object by re-uploading with updated metadata.
    Uses conditional writes (ETag for S3, generation for GCS) to avoid
    overwriting concurrent modifications.

    Returns:
        Dict with sync-back statistics.
    """
    sync_stats = {"synced": 0, "skipped": 0, "errors": 0}

    # Stream labeled results in batches to avoid loading all into memory
    results_query = (
        select(ScanResult)
        .where(ScanResult.job_id == job.id)
        .where(ScanResult.label_applied == True)
        .where(ScanResult.current_label_id.isnot(None))
    )

    adapter = _get_adapter(target.adapter, target.config)

    async with adapter:
        result_stream = await session.stream(results_query)
        async for batch in result_stream.scalars().partitions(500):
            for result in batch:
                item_id = (
                    result.file_path.split("://", 1)[-1].split("/", 1)[-1]
                    if "://" in result.file_path
                    else result.file_path
                )
                file_info = FileInfo(
                    path=result.file_path,
                    name=result.file_name,
                    size=result.file_size or 0,
                    modified=result.file_modified or datetime.now(timezone.utc),
                    adapter=target.adapter,
                    item_id=item_id,
                )

                try:
                    # Refresh metadata to get current ETag/generation for conflict detection
                    file_info = await adapter.get_metadata(file_info)

                    sync_result = await adapter.apply_label_and_sync(
                        file_info=file_info,
                        label_id=str(result.current_label_id),
                        label_name=result.current_label_name,
                    )

                    if sync_result.get("success"):
                        sync_stats["synced"] += 1
                    elif sync_result.get("method") == "skipped":
                        sync_stats["skipped"] += 1
                        logger.debug(
                            "Skipped label sync for %s: %s",
                            result.file_path,
                            sync_result.get("error"),
                        )
                    else:
                        sync_stats["errors"] += 1
                        logger.warning(
                            "Label sync-back failed for %s: %s",
                            result.file_path,
                            sync_result.get("error"),
                        )
                except (ConnectionError, OSError, RuntimeError, ValueError) as e:
                    sync_stats["errors"] += 1
                    logger.error("Label sync-back error for %s: %s", result.file_path, e)

    logger.info(
        "Cloud label sync-back for job %s: synced=%d, skipped=%d, errors=%d",
        job.id,
        sync_stats["synced"],
        sync_stats["skipped"],
        sync_stats["errors"],
    )
    return sync_stats


async def _build_pipeline_config(settings, tenant_id=None, session=None) -> PipelineConfig:
    """Build pipeline config from settings, with optional tenant overrides.

    If *tenant_id* and *session* are provided, per-tenant overrides from
    ``TenantSettings.pipeline_max_concurrent_files`` and
    ``TenantSettings.pipeline_memory_budget_mb`` take precedence over the
    global configuration.
    """
    jobs = getattr(settings, "jobs", None)

    max_concurrent = getattr(jobs, "pipeline_max_concurrent_files", 8) if jobs else 8
    memory_budget = getattr(jobs, "pipeline_memory_budget_mb", 512) if jobs else 512
    pipeline_enabled = getattr(jobs, "pipeline_enabled", True) if jobs else True

    # Ensure we have valid int values (guard against mock objects in tests)
    if not isinstance(max_concurrent, int):
        max_concurrent = 8
    if not isinstance(memory_budget, int):
        memory_budget = 512

    # Per-tenant overrides from TenantSettings
    if tenant_id is not None and session is not None:
        try:
            from sqlalchemy import select as sa_select

            from openlabels.server.models import TenantSettings

            result = await session.execute(
                sa_select(TenantSettings).where(
                    TenantSettings.tenant_id == tenant_id
                )
            )
            tenant_settings = result.scalar_one_or_none()
            if tenant_settings is not None:
                ts_concurrent = getattr(tenant_settings, "pipeline_max_concurrent_files", None)
                if isinstance(ts_concurrent, int) and ts_concurrent > 0:
                    max_concurrent = ts_concurrent
                ts_memory = getattr(tenant_settings, "pipeline_memory_budget_mb", None)
                if isinstance(ts_memory, int) and ts_memory > 0:
                    memory_budget = ts_memory
        except Exception:
            logger.debug("Could not load tenant pipeline overrides for %s", tenant_id)

    config = PipelineConfig(
        max_concurrent_files=max_concurrent,
        memory_budget_mb=memory_budget,
    )

    # If pipeline is disabled globally, set concurrency to 1 (sequential)
    if not pipeline_enabled:
        config.max_concurrent_files = 1

    return config


async def _detect_and_score(content: bytes, file_info, adapter_type: str = "filesystem") -> dict:
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
        adapter_type: Type of adapter being used (for metrics)

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

        # Record Prometheus metrics
        record_file_processed(adapter_type)
        if result.entity_counts:
            record_entities_found(result.entity_counts)
        if result.processing_time_ms:
            record_processing_duration(adapter_type, result.processing_time_ms / 1000.0)

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

        # Policy evaluation
        policy_data = None
        policy_violations = None
        if result.spans:
            try:
                entity_matches = [
                    EntityMatch(
                        entity_type=span.entity_type,
                        value=span.text,
                        confidence=span.confidence,
                        start=span.start,
                        end=span.end,
                        source=span.detector,
                    )
                    for span in result.spans
                ]
                engine = get_policy_engine()
                policy_result = engine.evaluate(entity_matches)
                if policy_result.is_sensitive:
                    policy_data = policy_result.to_dict()
                    # Map policy names to their framework categories
                    name_to_framework = {
                        p.name: p.category.value
                        for p in engine._policies
                    }
                    # Build per-violation records for the dedicated column
                    policy_violations = [
                        {
                            "policy_name": match.policy_name,
                            "framework": name_to_framework.get(
                                match.policy_name, "custom"
                            ),
                            "severity": policy_result.risk_level.value,
                            "trigger_type": match.trigger_type,
                            "matched_entities": match.matched_entities,
                        }
                        for match in policy_result.matches
                    ]
            except (ValueError, KeyError, RuntimeError) as e:
                logger.error(f"Policy evaluation failed for {file_info.path}: {e}")

        # Merge policy data into findings dict
        findings_dict = {"entities": findings}
        if policy_data:
            findings_dict["policy"] = policy_data

        return {
            "risk_score": result.risk_score,
            "risk_tier": result.risk_tier.value,
            "entity_counts": result.entity_counts,
            "total_entities": sum(result.entity_counts.values()),
            "content_score": result.content_score,
            "exposure_multiplier": result.exposure_multiplier,
            "co_occurrence_rules": result.co_occurrence_rules,
            "findings": findings_dict,
            "policy_violations": policy_violations,
            "processing_time_ms": result.processing_time_ms,
            "error": result.error,
        }

    except UnicodeDecodeError as e:
        logger.error(f"Encoding error during detection for {file_info.path}: {e}")
        return {
            "risk_score": 0,
            "risk_tier": "MINIMAL",
            "entity_counts": {},
            "total_entities": 0,
            "content_score": 0.0,
            "exposure_multiplier": 1.0,
            "error": f"Encoding error: {e}",
        }
    except ValueError as e:
        logger.error(f"Value error during detection for {file_info.path}: {e}")
        return {
            "risk_score": 0,
            "risk_tier": "MINIMAL",
            "entity_counts": {},
            "total_entities": 0,
            "content_score": 0.0,
            "exposure_multiplier": 1.0,
            "error": f"Value error: {e}",
        }
    except OSError as e:
        logger.error(f"OS error during detection for {file_info.path}: {e}")
        return {
            "risk_score": 0,
            "risk_tier": "MINIMAL",
            "entity_counts": {},
            "total_entities": 0,
            "content_score": 0.0,
            "exposure_multiplier": 1.0,
            "error": f"OS error: {e}",
        }


