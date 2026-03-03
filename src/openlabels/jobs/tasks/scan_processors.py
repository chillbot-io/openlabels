"""
Execution mode implementations for scan tasks.

Contains:
- ``_run_agent_pool_scan``: Multi-process NER classification via agent pool.
- ``_run_post_scan_steps``: Shared post-scan workflow (auto-label, SIEM, catalog, summary).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.adapters import OneDriveAdapter, SharePointAdapter
from openlabels.core.types import AdapterType, JobStatus
from openlabels.server.models import ScanJob, ScanResult, ScanTarget

logger = logging.getLogger(__name__)

# WebSocket streaming support
_ws_streaming_enabled = True
try:
    from openlabels.server.routes.ws import send_scan_completed
except ImportError:
    _ws_streaming_enabled = False


async def _run_agent_pool_scan(
    *,
    session: AsyncSession,
    job: ScanJob,
    target: ScanTarget,
    adapter,
    inventory,
    settings,
    force_full_scan: bool,
) -> dict:
    """Run a scan using the multi-process agent pool.

    Spawns N classification worker processes (one NER model each) and
    feeds files through them in parallel.  The ``ScanOrchestrator``
    handles the full pipeline: walk -> read -> delta -> classify -> score ->
    persist -> WebSocket events.

    After the orchestrator completes, runs the same post-scan steps as
    the single-process path: auto-labeling, SIEM export, catalog flush,
    and summary generation.

    Returns:
        Stats dict compatible with the single-process path.

    Raises:
        ImportError: If agent pool dependencies are missing.
        RuntimeError: If orchestrator encounters a fatal error.
        OSError: On I/O failures during setup.
    """
    from openlabels.core.agents.pool import AgentPoolConfig, ScanOrchestrator

    logger.info(
        "Using agent pool for scan job %s (target=%s, adapter=%s)",
        job.id, target.id, target.adapter,
    )

    # Resolve target paths (same logic as the pipeline path)
    target_path = target.config.get("path") or target.config.get("site_id") or ""

    scan_paths: list[str] = []
    if target.adapter == AdapterType.SHAREPOINT and settings.adapters.sharepoint.scan_all_sites and not target_path:
        sp_adapter: SharePointAdapter = adapter  # type: ignore[assignment]
        sites = await sp_adapter.list_sites()
        scan_paths = [s["id"] for s in sites if s.get("id")]
    elif target.adapter == AdapterType.ONEDRIVE and settings.adapters.onedrive.scan_all_users and not target_path:
        od_adapter: OneDriveAdapter = adapter  # type: ignore[assignment]
        all_users = await od_adapter.list_users()
        scan_paths = [u["id"] for u in all_users if u.get("id")]
    else:
        scan_paths = [target_path] if target_path else [""]

    # Build a FullWalkProvider that iterates all scan paths
    class _MultiPathProvider:
        """Walk multiple adapter paths as a single stream."""

        def __init__(self, _adapter, paths: list[str]):
            self._adapter = _adapter
            self._paths = paths

        async def changed_files(self):
            for sp in self._paths:
                try:
                    async for fi in self._adapter.list_files(sp):
                        yield fi
                except (ConnectionError, OSError, RuntimeError, ValueError) as e:
                    logger.error("list_files failed for %r: %s", sp, e)

    change_provider = _MultiPathProvider(adapter, scan_paths)

    # Configure the agent pool based on system resources
    pool_config = AgentPoolConfig(
        num_agents=0,  # auto-detect from CPU/memory
        input_queue_size=200,
        output_queue_size=2000,
    )

    # Tag the job so delta checks know whether to force
    if force_full_scan:
        job._force_full_scan = True  # type: ignore[attr-defined]

    orchestrator = ScanOrchestrator(
        pool_config=pool_config,
        adapter=adapter,
        change_provider=change_provider,
        inventory=inventory,
        session=session,
        job=job,
        settings=settings,
    )

    try:
        pool_stats = await orchestrator.run()
    except Exception as run_err:
        # Mark the ScanJob as failed (the worker only marks the JobQueue entry)
        job.status = JobStatus.FAILED
        job.error = f"Agent pool scan failed: {type(run_err).__name__}: {run_err}"
        job.completed_at = datetime.now(timezone.utc)
        try:
            await session.commit()
        except SQLAlchemyError:
            pass  # Best effort -- the raise below lets the worker handle the rest
        raise

    # Merge orchestrator stats into the standard format
    stats = {
        **orchestrator.stats,
        "scan_mode": "agent_pool",
        "agent_pool": {
            "items_submitted": pool_stats.items_submitted,
            "items_completed": pool_stats.items_completed,
            "items_failed": pool_stats.items_failed,
            "avg_processing_ms": round(pool_stats.avg_processing_ms, 1),
            "throughput_per_sec": round(pool_stats.throughput_per_second, 1),
        },
    }

    logger.info(
        "Agent pool scan completed for job %s: %d files scanned, "
        "%d with PII, %d entities (%.1f files/sec)",
        job.id,
        stats["files_scanned"],
        stats["files_with_pii"],
        stats["total_entities"],
        pool_stats.throughput_per_second,
    )

    # Mark job as completed
    job.status = JobStatus.COMPLETED
    job.completed_at = datetime.now(timezone.utc)
    await session.commit()

    # Stream completion via WebSocket
    if _ws_streaming_enabled:
        try:
            await send_scan_completed(
                scan_id=job.id,
                status=JobStatus.COMPLETED,
                summary={
                    "files_scanned": stats["files_scanned"],
                    "files_with_pii": stats["files_with_pii"],
                    "files_skipped": stats["files_skipped"],
                    "total_entities": stats["total_entities"],
                    "scan_mode": "agent_pool",
                    "risk_breakdown": {
                        "critical": stats.get("critical_count", 0),
                        "high": stats.get("high_count", 0),
                        "medium": stats.get("medium_count", 0),
                        "low": stats.get("low_count", 0),
                        "minimal": stats.get("minimal_count", 0),
                    },
                },
            )
        except (ConnectionError, OSError):
            pass

    # -- Post-scan steps (same as pipeline path) --
    await _run_post_scan_steps(session, job, target, settings, stats)

    return stats


async def _run_post_scan_steps(
    session: AsyncSession,
    job: ScanJob,
    target: ScanTarget,
    settings,
    stats: dict,
) -> None:
    """Run post-scan steps common to both pipeline and agent-pool paths.

    Non-fatal: each step is wrapped in its own try/except so a failure
    in one step doesn't prevent the others from running.
    """
    from openlabels.jobs.tasks.scan_labeling import (
        _auto_label_results,
        _cloud_label_sync_back,
    )

    # Auto-labeling
    if settings.labeling.enabled and settings.labeling.mode == "auto":
        try:
            auto_label_stats = await _auto_label_results(session, job)
            stats["auto_labeled"] = auto_label_stats.get("labeled", 0)
            stats["auto_label_errors"] = auto_label_stats.get("errors", 0)
        except (PermissionError, OSError, RuntimeError) as e:
            logger.error("Auto-labeling failed: %s", e)
            stats["auto_label_error"] = str(e)

    # Cloud label sync-back
    target = await session.get(ScanTarget, job.target_id)
    if target and target.adapter in (AdapterType.S3, AdapterType.GCS) and settings.labeling.enabled:
        adapter_settings = getattr(settings.adapters, target.adapter, None)
        if adapter_settings and getattr(adapter_settings, "label_sync_enabled", False):
            try:
                sync_stats = await _cloud_label_sync_back(session, job, target, settings)
                stats["label_sync_back"] = sync_stats
            except (ConnectionError, OSError, RuntimeError, ValueError) as e:
                logger.warning("Cloud label sync-back failed: %s", e)
                stats["label_sync_back_error"] = str(e)

    # Catalog flush
    try:
        from openlabels.analytics.flush import flush_scan_to_catalog
        from openlabels.analytics.storage import create_storage

        _catalog_storage = create_storage(settings.catalog)
        flushed = await flush_scan_to_catalog(session, job, _catalog_storage)
        stats["catalog_flushed"] = flushed
    except (ImportError, OSError, RuntimeError, ValueError) as e:
        logger.warning("Catalog flush failed for job %s: %s", job.id, e)
        stats["catalog_flush_error"] = str(e)

    # SIEM export
    if settings.siem_export.enabled and settings.siem_export.mode == "post_scan":
        try:
            from openlabels.export.engine import (
                ExportEngine,
                scan_result_to_export_records,
                scan_results_to_dicts,
            )
            from openlabels.export.setup import build_adapters_from_settings

            adapters = build_adapters_from_settings(settings.siem_export)
            if adapters:
                engine = ExportEngine(adapters)
                batch_size = 500
                total_exported = {}
                result_stream = await session.stream(
                    select(ScanResult).where(ScanResult.job_id == job.id)
                )
                async for batch in result_stream.scalars().partitions(batch_size):
                    export_records = scan_result_to_export_records(
                        scan_results_to_dicts(batch), job.tenant_id,
                    )
                    batch_results = await engine.export_full(
                        job.tenant_id,
                        export_records,
                        record_types=settings.siem_export.export_record_types or None,
                    )
                    for key, val in batch_results.items():
                        total_exported[key] = total_exported.get(key, 0) + val
                stats["siem_export"] = total_exported
        except (ImportError, ConnectionError, OSError, RuntimeError, ValueError) as e:
            logger.warning("SIEM export failed for job %s: %s", job.id, e)
            stats["siem_export_error"] = str(e)

    # Summary generation
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
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, AttributeError) as e:
        logger.warning("Summary generation failed for job %s: %s", job.id, e)
