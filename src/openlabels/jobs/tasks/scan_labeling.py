"""
Auto-labeling and cloud label sync-back workflows for scan tasks.

Contains:
- ``_auto_label_results``: Apply sensitivity labels to scan results based on rules.
- ``_cloud_label_sync_back``: Re-upload labeled files to S3/GCS with label metadata.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.adapters.base import FileInfo
from openlabels.core.constants import DEFAULT_QUERY_LIMIT
from openlabels.core.types import ExposureLevel
from openlabels.labeling.engine import create_labeling_engine
from openlabels.server.config import get_settings
from openlabels.server.models import LabelRule, ScanJob, ScanResult, ScanTarget, SensitivityLabel

logger = logging.getLogger(__name__)


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
        .limit(DEFAULT_QUERY_LIMIT)
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
    labeling_engine = create_labeling_engine()

    # Get target for adapter info
    target = await session.get(ScanTarget, job.target_id)

    # Stream unlabeled results in batches to avoid loading all into memory
    results_query = (
        select(ScanResult)
        .where(ScanResult.job_id == job.id)
        .where(not ScanResult.label_applied)
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
                file_info = FileInfo.from_scan_result(
                    result,
                    adapter=target.adapter if target else "filesystem",
                    exposure=ExposureLevel(result.exposure_level) if result.exposure_level else None,
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
    from openlabels.jobs.tasks.scan import _get_adapter

    sync_stats = {"synced": 0, "skipped": 0, "errors": 0}

    # Stream labeled results in batches to avoid loading all into memory
    results_query = (
        select(ScanResult)
        .where(ScanResult.job_id == job.id)
        .where(ScanResult.label_applied)
        .where(ScanResult.current_label_id.isnot(None))
    )

    adapter = _get_adapter(target.adapter, target.config)

    async with adapter:
        result_stream = await session.stream(results_query)
        async for batch in result_stream.scalars().partitions(500):
            for result in batch:
                cloud_item_id = (
                    result.file_path.split("://", 1)[-1].split("/", 1)[-1]
                    if "://" in result.file_path
                    else result.file_path
                )
                file_info = FileInfo.from_scan_result(
                    result,
                    adapter=target.adapter,
                    item_id_override=cloud_item_id,
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
