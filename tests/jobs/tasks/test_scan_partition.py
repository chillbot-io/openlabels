"""
Tests for the partitioned scan task and aggregation logic.

Tests cover:
- Partition execution (file scanning within partition boundaries)
- Aggregation (all partitions complete → parent job marked done)
- Partial failure (some partitions fail → parent completes with error note)
- Cancellation propagation
- Post-scan operations (auto-labeling, catalog flush, SIEM export)
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch

from openlabels.jobs.tasks.scan_partition import (
    _check_and_aggregate,
)


# ── Helpers ──────────────────────────────────────────────────────────

def _make_partition(
    job_id,
    index=0,
    total=4,
    status="completed",
    files_scanned=100,
    files_with_pii=10,
    total_entities=25,
):
    p = MagicMock()
    p.id = uuid4()
    p.job_id = job_id
    p.partition_index = index
    p.total_partitions = total
    p.status = status
    p.files_scanned = files_scanned
    p.files_with_pii = files_with_pii
    p.total_entities = total_entities
    p.stats = {
        "files_scanned": files_scanned,
        "files_with_pii": files_with_pii,
        "total_entities": total_entities,
    }
    return p


def _make_job(status="running", scan_mode="fanout"):
    job = MagicMock()
    job.id = uuid4()
    job.tenant_id = uuid4()
    job.target_id = uuid4()
    job.status = status
    job.scan_mode = scan_mode
    job.total_partitions = 4
    job.partitions_completed = 0
    job.partitions_failed = 0
    job.files_scanned = 0
    job.files_with_pii = 0
    job.completed_at = None
    job.error = None
    return job


# ── Aggregation tests ────────────────────────────────────────────────

class TestCheckAndAggregate:
    """Tests for _check_and_aggregate."""

    @pytest.mark.asyncio
    async def test_aggregation_all_completed(self):
        """When all partitions complete, parent job is marked completed."""
        job = _make_job()
        partitions = [
            _make_partition(job.id, i, 4, "completed", 100, 10, 25)
            for i in range(4)
        ]

        session = AsyncMock()

        # Mock advisory lock
        with patch("openlabels.server.advisory_lock.try_advisory_lock", return_value=True):
            # Mock count of incomplete partitions
            incomplete_result = MagicMock()
            incomplete_result.scalar.return_value = 0

            # Mock partition query
            partitions_result = MagicMock()
            partitions_result.scalars.return_value.all.return_value = partitions

            session.execute = AsyncMock(side_effect=[incomplete_result, partitions_result])
            session.commit = AsyncMock()

            # Mock post-scan operations
            with patch("openlabels.jobs.tasks.scan_partition._run_post_scan_operations", new_callable=AsyncMock):
                with patch("openlabels.jobs.tasks.scan_partition._ws_streaming_enabled", False):
                    await _check_and_aggregate(session, job)

        assert job.status == "completed"
        assert job.files_scanned == 400  # 4 partitions * 100
        assert job.files_with_pii == 40  # 4 partitions * 10
        assert job.partitions_completed == 4
        assert job.partitions_failed == 0
        assert job.error is None

    @pytest.mark.asyncio
    async def test_aggregation_some_failed(self):
        """When some partitions fail, parent completes with error note."""
        job = _make_job()
        partitions = [
            _make_partition(job.id, 0, 4, "completed", 100, 10, 25),
            _make_partition(job.id, 1, 4, "completed", 200, 20, 50),
            _make_partition(job.id, 2, 4, "failed", 0, 0, 0),
            _make_partition(job.id, 3, 4, "completed", 150, 15, 30),
        ]

        session = AsyncMock()

        with patch("openlabels.server.advisory_lock.try_advisory_lock", return_value=True):
            incomplete_result = MagicMock()
            incomplete_result.scalar.return_value = 0
            partitions_result = MagicMock()
            partitions_result.scalars.return_value.all.return_value = partitions
            session.execute = AsyncMock(side_effect=[incomplete_result, partitions_result])
            session.commit = AsyncMock()

            with patch("openlabels.jobs.tasks.scan_partition._run_post_scan_operations", new_callable=AsyncMock):
                with patch("openlabels.jobs.tasks.scan_partition._ws_streaming_enabled", False):
                    await _check_and_aggregate(session, job)

        assert job.status == "completed"
        assert job.files_scanned == 450  # 100 + 200 + 0 + 150
        assert job.partitions_completed == 3
        assert job.partitions_failed == 1
        assert "1/4 partitions failed" in job.error

    @pytest.mark.asyncio
    async def test_aggregation_all_failed(self):
        """When all partitions fail, parent is marked failed."""
        job = _make_job()
        partitions = [
            _make_partition(job.id, i, 4, "failed", 0, 0, 0)
            for i in range(4)
        ]

        session = AsyncMock()

        with patch("openlabels.server.advisory_lock.try_advisory_lock", return_value=True):
            incomplete_result = MagicMock()
            incomplete_result.scalar.return_value = 0
            partitions_result = MagicMock()
            partitions_result.scalars.return_value.all.return_value = partitions
            session.execute = AsyncMock(side_effect=[incomplete_result, partitions_result])
            session.commit = AsyncMock()

            with patch("openlabels.jobs.tasks.scan_partition._run_post_scan_operations", new_callable=AsyncMock):
                with patch("openlabels.jobs.tasks.scan_partition._ws_streaming_enabled", False):
                    await _check_and_aggregate(session, job)

        assert job.status == "failed"
        assert "All 4 partitions failed" in job.error

    @pytest.mark.asyncio
    async def test_aggregation_skips_when_partitions_still_running(self):
        """Don't aggregate when some partitions are still running."""
        job = _make_job()
        session = AsyncMock()

        with patch("openlabels.server.advisory_lock.try_advisory_lock", return_value=True):
            incomplete_result = MagicMock()
            incomplete_result.scalar.return_value = 2  # 2 still running

            session.execute = AsyncMock(return_value=incomplete_result)

            with patch("openlabels.jobs.tasks.scan_partition._ws_streaming_enabled", False):
                await _check_and_aggregate(session, job)

        # Parent job should not be touched
        assert job.status == "running"
        assert job.completed_at is None

    @pytest.mark.asyncio
    async def test_aggregation_skips_when_lock_held(self):
        """Don't aggregate when another worker holds the advisory lock."""
        job = _make_job()
        session = AsyncMock()

        with patch("openlabels.server.advisory_lock.try_advisory_lock", return_value=False):
            await _check_and_aggregate(session, job)

        # Parent job should not be touched
        assert job.status == "running"


# ── Partition task execution tests ───────────────────────────────────

class TestPartitionTaskExecution:
    """Tests for execute_scan_partition_task."""

    @pytest.mark.asyncio
    async def test_cancelled_parent_skips_partition(self):
        """Partition should be cancelled if parent job is cancelled."""
        from openlabels.jobs.tasks.scan_partition import execute_scan_partition_task

        partition = MagicMock()
        partition.id = uuid4()
        partition.partition_index = 0
        partition.status = "pending"

        job = MagicMock()
        job.id = uuid4()
        job.status = "cancelled"

        session = AsyncMock()
        session.get = AsyncMock(side_effect=lambda model, pk: {
            type(partition).__name__: partition,
            type(job).__name__: job,
        }.get(model.__name__))

        # Patch to use our mock models
        with patch("openlabels.jobs.tasks.scan_partition.ScanPartition", partition.__class__):
            with patch("openlabels.jobs.tasks.scan_partition.ScanJob", job.__class__):
                session.get = AsyncMock(side_effect=[partition, job])
                result = await execute_scan_partition_task(session, {
                    "partition_id": str(partition.id),
                    "job_id": str(job.id),
                })

        assert result["status"] == "cancelled"
        assert partition.status == "cancelled"

    @pytest.mark.asyncio
    async def test_partition_not_found_raises(self):
        """Missing partition should raise JobError."""
        from openlabels.jobs.tasks.scan_partition import execute_scan_partition_task
        from openlabels.exceptions import JobError

        session = AsyncMock()
        session.get = AsyncMock(return_value=None)

        with pytest.raises(JobError, match="not found"):
            await execute_scan_partition_task(session, {
                "partition_id": str(uuid4()),
                "job_id": str(uuid4()),
            })
