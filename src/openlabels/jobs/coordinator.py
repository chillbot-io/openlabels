"""
Scan coordinator for horizontal scaling.

Splits large scan jobs into partitions that can be processed by multiple
workers in parallel. Uses adapter-specific strategies to partition the
keyspace (S3 prefixes, filesystem directories, etc.).

Decision flow:
1. User starts a scan → enqueues a ``scan`` job
2. Worker picks it up → coordinator checks if fan-out is warranted
3. If target is small (< threshold): run single-worker scan (existing path)
4. If target is large: create N ScanPartition rows + enqueue N ``scan_partition`` jobs
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.adapters.base import PartitionSpec
from openlabels.server.models import (
    ScanJob,
    ScanPartition,
    ScanTarget,
    TenantSettings,
    generate_uuid,
)

logger = logging.getLogger(__name__)

# Defaults when no tenant settings exist
DEFAULT_FANOUT_ENABLED = True
DEFAULT_FANOUT_THRESHOLD = 10_000
DEFAULT_FANOUT_MAX_PARTITIONS = 16
MIN_PARTITION_SIZE = 1000  # Don't create partitions smaller than this


class FanoutDecision:
    """Result of the coordinator's decision on whether to fan out."""

    def __init__(
        self,
        should_fanout: bool,
        reason: str,
        estimated_files: int = 0,
        num_partitions: int = 0,
    ):
        self.should_fanout = should_fanout
        self.reason = reason
        self.estimated_files = estimated_files
        self.num_partitions = num_partitions


class ScanCoordinator:
    """
    Decides whether to fan out a scan job and creates partitions.

    Reads user-configurable settings from TenantSettings:
    - fanout_enabled: master switch (default True)
    - fanout_threshold: min files to trigger fan-out (default 10,000)
    - fanout_max_partitions: max partitions per job (default 16)
    """

    def __init__(self, session: AsyncSession, tenant_id: UUID):
        self.session = session
        self.tenant_id = tenant_id
        self._settings: TenantSettings | None = None

    async def _load_settings(self) -> None:
        """Load tenant fan-out settings (cached per instance)."""
        if self._settings is not None:
            return
        result = await self.session.execute(
            select(TenantSettings).where(
                TenantSettings.tenant_id == self.tenant_id
            )
        )
        self._settings = result.scalar_one_or_none()

    @property
    def fanout_enabled(self) -> bool:
        if self._settings and self._settings.fanout_enabled is not None:
            return self._settings.fanout_enabled
        return DEFAULT_FANOUT_ENABLED

    @property
    def fanout_threshold(self) -> int:
        if self._settings and self._settings.fanout_threshold is not None:
            return self._settings.fanout_threshold
        return DEFAULT_FANOUT_THRESHOLD

    @property
    def fanout_max_partitions(self) -> int:
        if self._settings and self._settings.fanout_max_partitions is not None:
            return self._settings.fanout_max_partitions
        return DEFAULT_FANOUT_MAX_PARTITIONS

    async def evaluate(
        self,
        job: ScanJob,
        target: ScanTarget,
        adapter,
    ) -> FanoutDecision:
        """
        Decide whether this scan should be split into partitions.

        Args:
            job: The scan job to evaluate
            target: Scan target configuration
            adapter: Initialized adapter instance

        Returns:
            FanoutDecision with the verdict and reasoning
        """
        await self._load_settings()

        # Master switch
        if not self.fanout_enabled:
            return FanoutDecision(False, "fanout_disabled")

        # Only cloud object stores benefit from fan-out
        if target.adapter not in ("s3", "gcs", "azure_blob"):
            return FanoutDecision(False, f"adapter_{target.adapter}_not_partitionable")

        # Check if adapter has estimation capability
        if not hasattr(adapter, "estimate_object_count"):
            return FanoutDecision(False, "adapter_missing_estimate_method")

        # Quick estimate of file count
        try:
            target_path = target.config.get("path") or target.config.get("bucket") or ""
            estimated_count, sample_keys = await adapter.estimate_object_count(
                target_path, sample_limit=self.fanout_threshold + 1
            )
        except (ConnectionError, OSError, RuntimeError, ValueError) as e:
            logger.warning("Failed to estimate object count for %s: %s", target.id, e)
            return FanoutDecision(False, f"estimate_failed: {e}")

        # Below threshold — single worker is fine
        if estimated_count < self.fanout_threshold:
            return FanoutDecision(
                False,
                f"below_threshold ({estimated_count} < {self.fanout_threshold})",
                estimated_files=estimated_count,
            )

        # Calculate partition count
        num_partitions = min(
            self.fanout_max_partitions,
            max(2, estimated_count // MIN_PARTITION_SIZE),
        )

        return FanoutDecision(
            should_fanout=True,
            reason=f"above_threshold ({estimated_count} >= {self.fanout_threshold})",
            estimated_files=estimated_count,
            num_partitions=num_partitions,
        )

    async def create_partitions(
        self,
        job: ScanJob,
        target: ScanTarget,
        adapter,
        num_partitions: int,
        estimated_files: int,
    ) -> list[ScanPartition]:
        """
        Create partition records and enqueue partition tasks.

        Args:
            job: Parent scan job
            target: Scan target
            adapter: Initialized adapter
            num_partitions: Number of partitions to create
            estimated_files: Estimated total file count

        Returns:
            List of created ScanPartition objects
        """
        target_path = target.config.get("path") or target.config.get("bucket") or ""

        # Try prefix-based partitioning first (natural directory boundaries)
        partition_specs = await self._compute_prefix_partitions(
            adapter, target_path, num_partitions
        )

        # Fall back to key-range partitioning if we don't have enough prefixes
        if len(partition_specs) < 2:
            partition_specs = await self._compute_keyrange_partitions(
                adapter, target_path, num_partitions
            )

        actual_count = len(partition_specs)

        # Update parent job
        job.scan_mode = "fanout"
        job.total_partitions = actual_count
        job.partitions_completed = 0
        job.partitions_failed = 0
        job.total_files_estimated = estimated_files
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)

        # Create partition rows
        partitions = []
        for i, spec in enumerate(partition_specs):
            partition = ScanPartition(
                id=generate_uuid(),
                tenant_id=job.tenant_id,
                job_id=job.id,
                partition_index=i,
                total_partitions=actual_count,
                partition_spec=spec.to_dict(),
                status="pending",
            )
            self.session.add(partition)
            partitions.append(partition)

        await self.session.flush()

        # Enqueue partition tasks in the job queue
        from openlabels.jobs.queue import JobQueue
        queue = JobQueue(self.session, job.tenant_id)
        for partition in partitions:
            await queue.enqueue(
                task_type="scan_partition",
                payload={
                    "partition_id": str(partition.id),
                    "job_id": str(job.id),
                },
                priority=60,  # Slightly above default to process promptly
            )

        await self.session.commit()

        logger.info(
            "Created %d partitions for scan job %s (estimated %d files)",
            actual_count, job.id, estimated_files,
        )

        return partitions

    async def _compute_prefix_partitions(
        self,
        adapter,
        target_path: str,
        num_partitions: int,
    ) -> list[PartitionSpec]:
        """
        Try to partition by top-level prefixes (virtual directories).

        This is the preferred strategy because it follows the natural data
        organization and tends to produce well-balanced partitions.
        """
        if not hasattr(adapter, "list_top_level_prefixes"):
            return []

        try:
            prefixes = await adapter.list_top_level_prefixes(target_path)
        except (ConnectionError, OSError, RuntimeError, ValueError) as e:
            logger.warning("Failed to list prefixes: %s", e)
            return []

        if len(prefixes) < 2:
            return []

        # If we have more prefixes than partitions, group them
        if len(prefixes) <= num_partitions:
            # One partition per prefix
            return [
                PartitionSpec(prefix=p)
                for p in prefixes
            ]

        # Group prefixes into N partitions
        specs = []
        chunk_size = len(prefixes) // num_partitions
        for i in range(num_partitions):
            start = i * chunk_size
            end = start + chunk_size if i < num_partitions - 1 else len(prefixes)
            group = prefixes[start:end]
            if group:
                # Use key-range boundaries from the prefix names
                spec = PartitionSpec(
                    start_after=group[0].rstrip("/") if i > 0 else None,
                    end_before=prefixes[end].rstrip("/") if end < len(prefixes) else None,
                )
                specs.append(spec)

        return specs

    async def _compute_keyrange_partitions(
        self,
        adapter,
        target_path: str,
        num_partitions: int,
    ) -> list[PartitionSpec]:
        """
        Partition by lexicographic key ranges using sampled keys.

        Samples keys from the bucket and uses quantile boundaries to split
        them into roughly equal ranges.
        """
        try:
            _, sample_keys = await adapter.estimate_object_count(
                target_path, sample_limit=10000
            )
        except (ConnectionError, OSError, RuntimeError, ValueError) as e:
            logger.warning("Failed to sample keys for partitioning: %s", e)
            return [PartitionSpec()]  # Single partition fallback

        if len(sample_keys) < num_partitions * 2:
            return [PartitionSpec()]  # Not enough keys to partition meaningfully

        sample_keys.sort()

        # Pick quantile boundaries
        specs = []
        step = len(sample_keys) // num_partitions
        for i in range(num_partitions):
            start_after = sample_keys[i * step] if i > 0 else None
            end_idx = (i + 1) * step
            end_before = sample_keys[end_idx] if end_idx < len(sample_keys) else None
            specs.append(PartitionSpec(start_after=start_after, end_before=end_before))

        return specs
