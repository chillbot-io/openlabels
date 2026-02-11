"""
Tests for the scan coordinator (horizontal scaling fan-out).

Tests cover:
- Fan-out decision logic (threshold, adapter types, settings)
- Partition boundary computation (prefix-based and key-range)
- Partition creation and job queue integration
- User-configurable settings (enabled/disabled, threshold, max partitions)
- Edge cases (empty buckets, single prefix, estimation failures)
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch

from openlabels.adapters.base import PartitionSpec
from openlabels.jobs.coordinator import (
    DEFAULT_FANOUT_MAX_PARTITIONS,
    DEFAULT_FANOUT_THRESHOLD,
    MIN_PARTITION_SIZE,
    FanoutDecision,
    ScanCoordinator,
)


# ── PartitionSpec tests ──────────────────────────────────────────────

class TestPartitionSpec:
    """Tests for the PartitionSpec dataclass."""

    def test_to_dict_minimal(self):
        spec = PartitionSpec()
        assert spec.to_dict() == {}

    def test_to_dict_s3_range(self):
        spec = PartitionSpec(start_after="data/a", end_before="data/m")
        result = spec.to_dict()
        assert result == {"start_after": "data/a", "end_before": "data/m"}

    def test_to_dict_prefix(self):
        spec = PartitionSpec(prefix="logs/2024/")
        assert spec.to_dict() == {"prefix": "logs/2024/"}

    def test_to_dict_filesystem(self):
        spec = PartitionSpec(directory="/mnt/share/finance")
        assert spec.to_dict() == {"directory": "/mnt/share/finance"}

    def test_from_dict_roundtrip(self):
        original = PartitionSpec(start_after="a", end_before="z", prefix="data/")
        restored = PartitionSpec.from_dict(original.to_dict())
        assert restored.start_after == "a"
        assert restored.end_before == "z"
        assert restored.prefix == "data/"

    def test_from_dict_empty(self):
        spec = PartitionSpec.from_dict({})
        assert spec.start_after is None
        assert spec.end_before is None
        assert spec.prefix is None

    def test_to_dict_excludes_none(self):
        spec = PartitionSpec(start_after="a")
        d = spec.to_dict()
        assert "end_before" not in d
        assert "prefix" not in d


# ── FanoutDecision tests ─────────────────────────────────────────────

class TestFanoutDecision:
    def test_no_fanout(self):
        decision = FanoutDecision(False, "below_threshold")
        assert not decision.should_fanout
        assert decision.reason == "below_threshold"
        assert decision.num_partitions == 0

    def test_fanout(self):
        decision = FanoutDecision(True, "above_threshold", estimated_files=50000, num_partitions=8)
        assert decision.should_fanout
        assert decision.estimated_files == 50000
        assert decision.num_partitions == 8


# ── Coordinator evaluate() tests ─────────────────────────────────────

def _make_coordinator(settings=None):
    """Create a coordinator with mocked session and optional settings."""
    session = AsyncMock()
    coordinator = ScanCoordinator(session, uuid4())
    coordinator._settings = settings  # Skip DB lookup
    return coordinator


def _make_target(adapter_type="s3"):
    target = MagicMock()
    target.adapter = adapter_type
    target.id = uuid4()
    target.config = {"bucket": "my-bucket", "path": ""}
    return target


def _make_job():
    job = MagicMock()
    job.id = uuid4()
    job.tenant_id = uuid4()
    job.target_id = uuid4()
    job.status = "pending"
    job.progress = None
    return job


class TestCoordinatorEvaluate:
    """Tests for ScanCoordinator.evaluate()."""

    @pytest.mark.asyncio
    async def test_fanout_disabled_in_settings(self):
        """When fanout_enabled=False in tenant settings, never fan out."""
        settings = MagicMock()
        settings.fanout_enabled = False
        settings.fanout_threshold = 100
        settings.fanout_max_partitions = 16
        coordinator = _make_coordinator(settings)

        decision = await coordinator.evaluate(_make_job(), _make_target(), AsyncMock())
        assert not decision.should_fanout
        assert decision.reason == "fanout_disabled"

    @pytest.mark.asyncio
    async def test_filesystem_not_partitionable(self):
        """Filesystem adapter shouldn't trigger fan-out."""
        coordinator = _make_coordinator(MagicMock(
            fanout_enabled=True, fanout_threshold=1000, fanout_max_partitions=8
        ))
        decision = await coordinator.evaluate(
            _make_job(), _make_target("filesystem"), AsyncMock()
        )
        assert not decision.should_fanout
        assert "filesystem" in decision.reason

    @pytest.mark.asyncio
    async def test_below_threshold(self):
        """When estimated count is below threshold, don't fan out."""
        coordinator = _make_coordinator(MagicMock(
            fanout_enabled=True, fanout_threshold=10000, fanout_max_partitions=8
        ))
        adapter = AsyncMock()
        adapter.estimate_object_count = AsyncMock(return_value=(5000, ["key1", "key2"]))

        decision = await coordinator.evaluate(_make_job(), _make_target(), adapter)
        assert not decision.should_fanout
        assert "below_threshold" in decision.reason
        assert decision.estimated_files == 5000

    @pytest.mark.asyncio
    async def test_above_threshold_fans_out(self):
        """When estimated count exceeds threshold, fan out."""
        coordinator = _make_coordinator(MagicMock(
            fanout_enabled=True, fanout_threshold=10000, fanout_max_partitions=8
        ))
        adapter = AsyncMock()
        adapter.estimate_object_count = AsyncMock(
            return_value=(15000, [f"key{i}" for i in range(15000)])
        )

        decision = await coordinator.evaluate(_make_job(), _make_target(), adapter)
        assert decision.should_fanout
        assert decision.estimated_files == 15000
        assert 2 <= decision.num_partitions <= 8

    @pytest.mark.asyncio
    async def test_max_partitions_capped(self):
        """Partition count should not exceed fanout_max_partitions."""
        coordinator = _make_coordinator(MagicMock(
            fanout_enabled=True, fanout_threshold=100, fanout_max_partitions=4
        ))
        adapter = AsyncMock()
        adapter.estimate_object_count = AsyncMock(
            return_value=(1000000, [f"key{i}" for i in range(10001)])
        )

        decision = await coordinator.evaluate(_make_job(), _make_target(), adapter)
        assert decision.should_fanout
        assert decision.num_partitions <= 4

    @pytest.mark.asyncio
    async def test_estimate_failure_falls_back(self):
        """If estimation fails, don't fan out."""
        coordinator = _make_coordinator(MagicMock(
            fanout_enabled=True, fanout_threshold=100, fanout_max_partitions=8
        ))
        adapter = AsyncMock()
        adapter.estimate_object_count = AsyncMock(side_effect=ConnectionError("timeout"))

        decision = await coordinator.evaluate(_make_job(), _make_target(), adapter)
        assert not decision.should_fanout
        assert "estimate_failed" in decision.reason

    @pytest.mark.asyncio
    async def test_gcs_adapter_supported(self):
        """GCS adapter should be eligible for fan-out."""
        coordinator = _make_coordinator(MagicMock(
            fanout_enabled=True, fanout_threshold=100, fanout_max_partitions=8
        ))
        adapter = AsyncMock()
        adapter.estimate_object_count = AsyncMock(return_value=(5000, [f"k{i}" for i in range(5000)]))

        decision = await coordinator.evaluate(_make_job(), _make_target("gcs"), adapter)
        assert decision.should_fanout

    @pytest.mark.asyncio
    async def test_azure_blob_supported(self):
        """Azure Blob adapter should be eligible for fan-out."""
        coordinator = _make_coordinator(MagicMock(
            fanout_enabled=True, fanout_threshold=100, fanout_max_partitions=8
        ))
        adapter = AsyncMock()
        adapter.estimate_object_count = AsyncMock(return_value=(5000, [f"k{i}" for i in range(5000)]))

        decision = await coordinator.evaluate(_make_job(), _make_target("azure_blob"), adapter)
        assert decision.should_fanout

    @pytest.mark.asyncio
    async def test_default_settings_when_no_tenant_settings(self):
        """Uses defaults when tenant has no settings row."""
        coordinator = _make_coordinator(None)

        assert coordinator.fanout_enabled == True
        assert coordinator.fanout_threshold == DEFAULT_FANOUT_THRESHOLD
        assert coordinator.fanout_max_partitions == DEFAULT_FANOUT_MAX_PARTITIONS

    @pytest.mark.asyncio
    async def test_custom_threshold(self):
        """User-configurable threshold is respected."""
        # Threshold set to 50,000 — adapter estimates 30,000 — should NOT fan out
        coordinator = _make_coordinator(MagicMock(
            fanout_enabled=True, fanout_threshold=50000, fanout_max_partitions=8
        ))
        adapter = AsyncMock()
        adapter.estimate_object_count = AsyncMock(return_value=(30000, []))

        decision = await coordinator.evaluate(_make_job(), _make_target(), adapter)
        assert not decision.should_fanout


# ── Partition boundary computation tests ─────────────────────────────

class TestPartitionComputation:
    """Tests for partition boundary calculation."""

    @pytest.mark.asyncio
    async def test_prefix_partitions(self):
        """Should create one partition per top-level prefix."""
        coordinator = _make_coordinator()
        adapter = AsyncMock()
        adapter.list_top_level_prefixes = AsyncMock(
            return_value=["data/2023/", "data/2024/", "data/2025/", "logs/"]
        )

        specs = await coordinator._compute_prefix_partitions(adapter, "", 8)
        assert len(specs) == 4
        assert specs[0].prefix == "data/2023/"
        assert specs[3].prefix == "logs/"

    @pytest.mark.asyncio
    async def test_prefix_partitions_empty(self):
        """No prefixes should return empty list."""
        coordinator = _make_coordinator()
        adapter = AsyncMock()
        adapter.list_top_level_prefixes = AsyncMock(return_value=[])

        specs = await coordinator._compute_prefix_partitions(adapter, "", 4)
        assert specs == []

    @pytest.mark.asyncio
    async def test_prefix_partitions_single_prefix(self):
        """Single prefix should return empty (not enough to partition)."""
        coordinator = _make_coordinator()
        adapter = AsyncMock()
        adapter.list_top_level_prefixes = AsyncMock(return_value=["data/"])

        specs = await coordinator._compute_prefix_partitions(adapter, "", 4)
        assert specs == []

    @pytest.mark.asyncio
    async def test_keyrange_partitions(self):
        """Should create N partitions from sampled keys."""
        coordinator = _make_coordinator()
        adapter = AsyncMock()
        # 100 keys spanning a-z
        keys = [f"file_{chr(65 + i % 26)}_{j:04d}.csv" for i in range(26) for j in range(4)]
        adapter.estimate_object_count = AsyncMock(return_value=(len(keys), keys))

        specs = await coordinator._compute_keyrange_partitions(adapter, "", 4)
        assert len(specs) == 4
        # First partition starts from beginning
        assert specs[0].start_after is None
        # Last partition goes to the end
        assert specs[-1].end_before is None

    @pytest.mark.asyncio
    async def test_keyrange_too_few_keys(self):
        """Too few keys should fall back to single partition."""
        coordinator = _make_coordinator()
        adapter = AsyncMock()
        adapter.estimate_object_count = AsyncMock(return_value=(3, ["a", "b", "c"]))

        specs = await coordinator._compute_keyrange_partitions(adapter, "", 4)
        assert len(specs) == 1  # Single partition fallback

    @pytest.mark.asyncio
    async def test_keyrange_estimation_error(self):
        """Estimation error should fall back to single partition."""
        coordinator = _make_coordinator()
        adapter = AsyncMock()
        adapter.estimate_object_count = AsyncMock(side_effect=OSError("network error"))

        specs = await coordinator._compute_keyrange_partitions(adapter, "", 4)
        assert len(specs) == 1
