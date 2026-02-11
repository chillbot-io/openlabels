"""
Pre-aggregated scan summary generation.

After a scan job completes (single-worker or fan-out), this module computes
aggregate statistics and stores them in the ``scan_summaries`` table. Dashboard
endpoints read from this table instead of running expensive GROUP BY queries
on multi-million-row scan_results.

Usage::

    from openlabels.jobs.summaries import generate_scan_summary
    await generate_scan_summary(session, job)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import ScanJob, ScanResult, ScanSummary

logger = logging.getLogger(__name__)


async def generate_scan_summary(
    session: AsyncSession,
    job: ScanJob,
    auto_label_stats: dict | None = None,
) -> ScanSummary:
    """Compute and persist a pre-aggregated summary for a completed scan job.

    Runs a single aggregate query against scan_results, avoiding the need
    for dashboard endpoints to re-compute these values on every request.

    Args:
        session: Active database session.
        job: The completed ScanJob.
        auto_label_stats: Optional dict with ``labeled`` and ``errors`` counts
            from auto-labeling (populated if labeling ran).

    Returns:
        The created ScanSummary row.
    """
    now = datetime.now(timezone.utc)

    # Aggregate risk tier counts in a single query
    tier_query = (
        select(
            ScanResult.risk_tier,
            func.count().label("cnt"),
        )
        .where(ScanResult.job_id == job.id)
        .group_by(ScanResult.risk_tier)
    )
    tier_result = await session.execute(tier_query)
    tier_counts = {row.risk_tier: row.cnt for row in tier_result}

    # Aggregate entity type counts (merge JSONB entity_counts across results)
    # Uses a streaming approach to avoid loading all results into memory
    entity_type_totals: dict[str, int] = {}
    result_stream = await session.stream(
        select(ScanResult.entity_counts).where(
            ScanResult.job_id == job.id,
            ScanResult.total_entities > 0,
        )
    )
    async for (entity_counts_row,) in result_stream:
        if entity_counts_row:
            for entity_type, count in entity_counts_row.items():
                entity_type_totals[entity_type] = (
                    entity_type_totals.get(entity_type, 0) + count
                )

    # Total files and entities
    totals_query = (
        select(
            func.count().label("files_scanned"),
            func.count().filter(ScanResult.total_entities > 0).label("files_with_pii"),
            func.coalesce(func.sum(ScanResult.total_entities), 0).label("total_entities"),
        )
        .where(ScanResult.job_id == job.id)
    )
    totals = (await session.execute(totals_query)).one()

    # Compute scan duration
    scan_duration = None
    if job.started_at and job.completed_at:
        scan_duration = (job.completed_at - job.started_at).total_seconds()
    elif job.started_at:
        scan_duration = (now - job.started_at).total_seconds()

    summary = ScanSummary(
        tenant_id=job.tenant_id,
        job_id=job.id,
        target_id=job.target_id,
        files_scanned=totals.files_scanned,
        files_with_pii=totals.files_with_pii,
        files_skipped=job.progress.get("files_skipped", 0) if job.progress else 0,
        total_entities=totals.total_entities,
        critical_count=tier_counts.get("CRITICAL", 0),
        high_count=tier_counts.get("HIGH", 0),
        medium_count=tier_counts.get("MEDIUM", 0),
        low_count=tier_counts.get("LOW", 0),
        minimal_count=tier_counts.get("MINIMAL", 0),
        entity_type_counts=entity_type_totals if entity_type_totals else None,
        scan_mode=job.scan_mode or "single",
        total_partitions=job.total_partitions,
        scan_duration_seconds=scan_duration,
        files_labeled=(auto_label_stats or {}).get("labeled", 0),
        files_label_failed=(auto_label_stats or {}).get("errors", 0),
        completed_at=job.completed_at or now,
    )
    session.add(summary)
    await session.flush()

    logger.info(
        "Generated scan summary for job %s: %d files, %d with PII, %d entities",
        job.id,
        summary.files_scanned,
        summary.files_with_pii,
        summary.total_entities,
    )
    return summary
