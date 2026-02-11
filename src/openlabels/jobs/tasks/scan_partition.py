"""
Partitioned scan task for horizontal scaling.

Processes a single partition of a fan-out scan job. Each partition scans
a slice of the target keyspace (e.g. an S3 prefix range) independently.
When a partition completes, it checks if all sibling partitions are done
and aggregates results into the parent ScanJob if so.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.adapters.base import PartitionSpec
from openlabels.exceptions import JobError
from openlabels.jobs.pipeline import FilePipeline, PipelineConfig, PipelineContext
from openlabels.jobs.tasks.scan import (
    CANCELLATION_CHECK_INTERVAL,
    _build_pipeline_config,
    _check_cancellation,
    _detect_and_score,
    _get_adapter,
    cleanup_processor,
    get_processor,
)
from openlabels.server.config import get_settings
from openlabels.server.models import ScanJob, ScanPartition, ScanResult, ScanTarget

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


async def execute_scan_partition_task(
    session: AsyncSession,
    payload: dict,
) -> dict:
    """
    Execute a single partition of a fan-out scan.

    Args:
        session: Database session
        payload: Task payload containing:
            - partition_id: UUID of the ScanPartition
            - job_id: UUID of the parent ScanJob

    Returns:
        Result dictionary with partition scan statistics
    """
    from openlabels.jobs.inventory import InventoryService, get_folder_path

    partition_id = UUID(payload["partition_id"])
    job_id = UUID(payload["job_id"])

    partition = await session.get(ScanPartition, partition_id)
    if not partition:
        raise JobError(
            "Scan partition not found",
            job_id=str(job_id),
            job_type="scan_partition",
            context=f"partition_id={partition_id}",
        )

    job = await session.get(ScanJob, job_id)
    if not job:
        raise JobError(
            "Parent scan job not found",
            job_id=str(job_id),
            job_type="scan_partition",
        )

    # Check if parent was cancelled
    if job.status == "cancelled":
        partition.status = "cancelled"
        await session.commit()
        return {"status": "cancelled"}

    target = await session.get(ScanTarget, job.target_id)
    if not target:
        raise JobError(
            "Scan target not found",
            job_id=str(job_id),
            job_type="scan_partition",
            context=f"target_id={job.target_id}",
        )

    # Mark partition as running
    partition.status = "running"
    partition.started_at = datetime.now(timezone.utc)
    await session.flush()

    # Build partition spec
    spec = PartitionSpec.from_dict(partition.partition_spec)

    # Get adapter
    adapter = _get_adapter(target.adapter, target.config)
    await adapter.__aenter__()

    # Initialize inventory
    inventory = InventoryService(session, job.tenant_id, target.id)
    folder_stats: dict[str, dict] = {}

    settings = get_settings()
    max_file_size_bytes = settings.detection.max_file_size_mb * 1024 * 1024
    force_full_scan = job.progress.get("force_full_scan", False) if job.progress else False

    stats = {
        "files_scanned": 0,
        "files_with_pii": 0,
        "total_entities": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "minimal_count": 0,
        "files_skipped": 0,
        "partition_index": partition.partition_index,
    }

    try:
        # Get target path
        target_path = target.config.get("path") or target.config.get("site_id") or ""

        # Build per-file processing function for the pipeline
        async def _process_one_file(file_info, ctx: PipelineContext) -> None:
            folder_path = get_folder_path(file_info.path)

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

            # Skip oversized files
            if file_info.size > max_file_size_bytes:
                ctx.stats.files_skipped += 1
                return

            # Read + hash + delta check
            content = await adapter.read_file(file_info, max_size_bytes=max_file_size_bytes)
            content_hash = inventory.compute_content_hash(content)

            should_scan, scan_reason = await inventory.should_scan_file(
                file_info, content_hash, force_full_scan
            )
            if not should_scan:
                ctx.stats.files_skipped += 1
                return

            # Detection
            result = await _detect_and_score(content, file_info, target.adapter)

            # Save result
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

            # Policy actions
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
                    await executor.execute_all(action_ctx)
                except (ImportError, RuntimeError, ValueError, OSError, ConnectionError) as e:
                    logger.error("Policy action failed for %s: %s", file_info.path, e)

            # Update pipeline stats
            ctx.stats.record_result(result["risk_tier"], result["total_entities"])

            # Update folder stats
            if result["total_entities"] > 0:
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

            # Update partition progress
            partition.files_scanned = ctx.stats.files_scanned
            partition.files_with_pii = ctx.stats.files_with_pii
            partition.files_skipped = ctx.stats.files_skipped
            partition.total_entities = ctx.stats.total_entities
            partition.last_processed_path = file_info.path

            # Stream progress via WebSocket
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
                            "partition": partition.partition_index,
                            "total_partitions": partition.total_partitions,
                        },
                    )
                except (ConnectionError, OSError):
                    pass

        # Build pipeline config and run
        pipeline_config = await _build_pipeline_config(settings, job.tenant_id, session)
        pipeline = FilePipeline(
            config=pipeline_config,
            process_fn=_process_one_file,
            commit_fn=session.commit,
            cancellation_fn=lambda: _check_cancellation(session, job_id),
        )
        pipeline_stats = await pipeline.run(
            adapter.list_files(target_path, partition=spec)
        )

        # Merge stats from pipeline
        stats.update(pipeline_stats.to_dict())

        # Handle cancellation
        if pipeline.cancelled:
            logger.info(
                "Partition %d of job %s cancelled at %d files",
                partition.partition_index, job_id, stats["files_scanned"],
            )
            partition.status = "cancelled"
            partition.stats = stats
            await session.commit()
            return {**stats, "status": "cancelled"}

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
                logger.warning("Folder inventory failed for %s: %s", folder_path, inv_err)

        # Mark partition completed
        partition.status = "completed"
        partition.completed_at = datetime.now(timezone.utc)
        partition.stats = stats
        await session.commit()

        logger.info(
            "Partition %d/%d of job %s completed: %d files scanned, %d with PII",
            partition.partition_index + 1,
            partition.total_partitions,
            job.id,
            stats["files_scanned"],
            stats["files_with_pii"],
        )

        # Check if all partitions are done → aggregate
        await _check_and_aggregate(session, job)

        return stats

    except Exception:
        # Mark partition failed
        partition.status = "failed"
        partition.completed_at = datetime.now(timezone.utc)
        partition.stats = stats
        await session.commit()
        raise

    finally:
        try:
            await adapter.__aexit__(None, None, None)
        except (ConnectionError, OSError, RuntimeError):
            pass
        cleanup_processor()


async def _check_and_aggregate(
    session: AsyncSession,
    job: ScanJob,
) -> None:
    """
    Check if all partitions are complete and aggregate results.

    Uses an advisory lock to prevent race conditions when multiple
    partitions complete simultaneously.
    """
    from openlabels.server.advisory_lock import try_advisory_lock

    # Use job ID hash as lock ID to serialize per-job aggregation
    lock_id = abs(hash(str(job.id))) % (2**31)
    if not await try_advisory_lock(session, lock_id):
        logger.debug("Another worker is aggregating job %s", job.id)
        return

    # Count incomplete partitions
    incomplete = await session.execute(
        select(func.count()).select_from(ScanPartition).where(
            ScanPartition.job_id == job.id,
            ScanPartition.status.notin_(["completed", "failed", "cancelled"]),
        )
    )
    remaining = incomplete.scalar() or 0

    if remaining > 0:
        logger.debug("Job %s has %d partitions still running", job.id, remaining)
        return

    # All partitions done — aggregate
    logger.info("All partitions done for job %s, aggregating results", job.id)

    # Sum up stats from all partitions
    partitions_result = await session.execute(
        select(ScanPartition).where(ScanPartition.job_id == job.id)
    )
    partitions = partitions_result.scalars().all()

    total_scanned = 0
    total_with_pii = 0
    total_entities = 0
    completed_count = 0
    failed_count = 0

    for p in partitions:
        if p.status == "completed":
            completed_count += 1
            total_scanned += p.files_scanned or 0
            total_with_pii += p.files_with_pii or 0
            total_entities += p.total_entities or 0
        elif p.status == "failed":
            failed_count += 1

    # Update parent job
    job.files_scanned = total_scanned
    job.files_with_pii = total_with_pii
    job.partitions_completed = completed_count
    job.partitions_failed = failed_count
    job.completed_at = datetime.now(timezone.utc)

    if failed_count > 0 and completed_count == 0:
        job.status = "failed"
        job.error = f"All {failed_count} partitions failed"
    elif failed_count > 0:
        job.status = "completed"
        job.error = f"{failed_count}/{len(partitions)} partitions failed"
    else:
        job.status = "completed"

    await session.commit()

    # Run post-scan operations (auto-labeling, catalog flush, SIEM export)
    await _run_post_scan_operations(session, job)

    # Stream completion via WebSocket
    if _ws_streaming_enabled:
        try:
            await send_scan_completed(
                scan_id=job.id,
                status=job.status,
                summary={
                    "files_scanned": total_scanned,
                    "files_with_pii": total_with_pii,
                    "total_entities": total_entities,
                    "scan_mode": "fanout",
                    "partitions": len(partitions),
                    "partitions_completed": completed_count,
                    "partitions_failed": failed_count,
                },
            )
        except (ConnectionError, OSError):
            pass

    logger.info(
        "Job %s aggregation complete: %d files, %d with PII, %d/%d partitions succeeded",
        job.id, total_scanned, total_with_pii, completed_count, len(partitions),
    )


async def _run_post_scan_operations(
    session: AsyncSession,
    job: ScanJob,
) -> None:
    """Run post-scan hooks that should only execute once after all partitions complete."""
    settings = get_settings()

    # Auto-labeling
    if settings.labeling.enabled and settings.labeling.mode == "auto":
        try:
            from openlabels.jobs.tasks.scan import _auto_label_results
            await _auto_label_results(session, job)
        except (PermissionError, OSError, RuntimeError) as e:
            logger.error("Auto-labeling failed for job %s: %s", job.id, e)

    # Cloud label sync-back
    target = await session.get(ScanTarget, job.target_id)
    if target and target.adapter in ("s3", "gcs") and settings.labeling.enabled:
        adapter_settings = getattr(settings.adapters, target.adapter, None)
        if adapter_settings and getattr(adapter_settings, "label_sync_enabled", False):
            try:
                from openlabels.jobs.tasks.scan import _cloud_label_sync_back
                await _cloud_label_sync_back(session, job, target, settings)
            except (ConnectionError, OSError, RuntimeError, ValueError) as e:
                logger.warning("Cloud label sync-back failed for job %s: %s", job.id, e)

    # Catalog flush
    if settings.catalog.enabled:
        try:
            from openlabels.analytics.flush import flush_scan_to_catalog
            from openlabels.analytics.storage import create_storage
            storage = create_storage(settings.catalog)
            await flush_scan_to_catalog(session, job, storage)
        except (ImportError, OSError, RuntimeError, ValueError) as e:
            logger.warning("Catalog flush failed for job %s: %s", job.id, e)

    # SIEM export
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
                batch_size = 500
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
                    await engine.export_full(
                        job.tenant_id,
                        export_records,
                        record_types=settings.siem_export.export_record_types or None,
                    )
        except (ImportError, ConnectionError, OSError, RuntimeError, ValueError) as e:
            logger.warning("SIEM export failed for job %s: %s", job.id, e)

    # Generate pre-aggregated summary for fast dashboard queries
    try:
        from openlabels.jobs.summaries import generate_scan_summary
        await generate_scan_summary(session, job)
        await session.commit()
    except Exception as e:  # Non-fatal: don't fail the scan if summary fails
        logger.warning("Summary generation failed for job %s: %s", job.id, e)
