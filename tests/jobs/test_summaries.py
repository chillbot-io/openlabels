"""Tests for pre-aggregated scan summary generation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest


class FakeAsyncIter:
    """Helper to create a proper async iterable from a list of rows."""

    def __init__(self, rows):
        self._rows = rows

    def __aiter__(self):
        return self._iter()

    async def _iter(self):
        for row in self._rows:
            yield row


class TestGenerateScanSummary:
    """Tests for the generate_scan_summary function."""

    @pytest.mark.asyncio
    async def test_generates_summary_with_results(self):
        """Should aggregate risk tiers and entity types from scan results."""
        from openlabels.jobs.summaries import generate_scan_summary

        job_id = uuid4()
        tenant_id = uuid4()
        target_id = uuid4()
        now = datetime.now(timezone.utc)

        # Mock the job
        job = MagicMock()
        job.id = job_id
        job.tenant_id = tenant_id
        job.target_id = target_id
        job.scan_mode = "single"
        job.total_partitions = None
        job.started_at = now - timedelta(minutes=5)
        job.completed_at = now
        job.progress = {"files_skipped": 10}

        # Mock tier query result
        tier_row_critical = MagicMock()
        tier_row_critical.risk_tier = "CRITICAL"
        tier_row_critical.cnt = 3
        tier_row_high = MagicMock()
        tier_row_high.risk_tier = "HIGH"
        tier_row_high.cnt = 7

        # Mock totals
        totals_row = MagicMock()
        totals_row.files_scanned = 20
        totals_row.files_with_pii = 10
        totals_row.total_entities = 45

        # Mock entity counts streaming
        entity_rows = [
            ({"SSN": 5, "EMAIL": 3},),
            ({"SSN": 2, "CREDIT_CARD": 1},),
            (None,),
        ]

        # Build mock session
        session = AsyncMock()

        # First execute → tier query, second → totals query
        tier_result = MagicMock()
        tier_result.__iter__ = MagicMock(return_value=iter([tier_row_critical, tier_row_high]))

        totals_result = MagicMock()
        totals_result.one.return_value = totals_row

        session.execute = AsyncMock(side_effect=[tier_result, totals_result])

        # Mock stream for entity counts
        session.stream = AsyncMock(return_value=FakeAsyncIter(entity_rows))
        session.add = MagicMock()
        session.flush = AsyncMock()

        summary = await generate_scan_summary(session, job, {"labeled": 5, "errors": 1})

        assert summary.files_scanned == 20
        assert summary.files_with_pii == 10
        assert summary.total_entities == 45
        assert summary.critical_count == 3
        assert summary.high_count == 7
        assert summary.files_skipped == 10
        assert summary.scan_mode == "single"
        assert summary.files_labeled == 5
        assert summary.files_label_failed == 1
        assert summary.entity_type_counts == {"SSN": 7, "EMAIL": 3, "CREDIT_CARD": 1}
        assert summary.scan_duration_seconds == pytest.approx(300.0, abs=1.0)
        session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_generates_summary_no_results(self):
        """Should handle a scan with zero results gracefully."""
        from openlabels.jobs.summaries import generate_scan_summary

        job = MagicMock()
        job.id = uuid4()
        job.tenant_id = uuid4()
        job.target_id = uuid4()
        job.scan_mode = "fanout"
        job.total_partitions = 4
        job.started_at = datetime.now(timezone.utc)
        job.completed_at = datetime.now(timezone.utc)
        job.progress = None

        # Empty tier result
        tier_result = MagicMock()
        tier_result.__iter__ = MagicMock(return_value=iter([]))

        totals_row = MagicMock()
        totals_row.files_scanned = 0
        totals_row.files_with_pii = 0
        totals_row.total_entities = 0

        totals_result = MagicMock()
        totals_result.one.return_value = totals_row

        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[tier_result, totals_result])

        # Empty entity stream
        session.stream = AsyncMock(return_value=FakeAsyncIter([]))
        session.add = MagicMock()
        session.flush = AsyncMock()

        summary = await generate_scan_summary(session, job)

        assert summary.files_scanned == 0
        assert summary.total_entities == 0
        assert summary.entity_type_counts is None
        assert summary.scan_mode == "fanout"
        assert summary.total_partitions == 4

    @pytest.mark.asyncio
    async def test_generates_summary_without_label_stats(self):
        """When auto_label_stats is None, label counts should be 0."""
        from openlabels.jobs.summaries import generate_scan_summary

        job = MagicMock()
        job.id = uuid4()
        job.tenant_id = uuid4()
        job.target_id = uuid4()
        job.scan_mode = None
        job.total_partitions = None
        job.started_at = None
        job.completed_at = None
        job.progress = {}

        tier_result = MagicMock()
        tier_result.__iter__ = MagicMock(return_value=iter([]))
        totals_row = MagicMock(files_scanned=0, files_with_pii=0, total_entities=0)
        totals_result = MagicMock()
        totals_result.one.return_value = totals_row

        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[tier_result, totals_result])
        session.stream = AsyncMock(return_value=FakeAsyncIter([]))
        session.add = MagicMock()
        session.flush = AsyncMock()

        summary = await generate_scan_summary(session, job, None)

        assert summary.files_labeled == 0
        assert summary.files_label_failed == 0
