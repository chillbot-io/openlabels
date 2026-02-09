"""Tests for ExportEngine — cursor tracking, adapter dispatch, record building."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from openlabels.export.adapters.base import ExportRecord
from openlabels.export.engine import ExportEngine, scan_result_to_export_records


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def tenant_id() -> UUID:
    return UUID("12345678-1234-1234-1234-123456789abc")


@pytest.fixture
def sample_records(tenant_id: UUID) -> list[ExportRecord]:
    return [
        ExportRecord(
            record_type="scan_result",
            timestamp=datetime(2026, 2, 8, 12, i, 0, tzinfo=timezone.utc),
            tenant_id=tenant_id,
            file_path=f"/data/file_{i}.txt",
            risk_score=50 + i * 10,
            risk_tier="HIGH",
            entity_types=["EMAIL"],
            entity_counts={"EMAIL": i + 1},
        )
        for i in range(5)
    ]


def _make_mock_adapter(name: str = "mock", export_count: int | None = None):
    adapter = AsyncMock()
    adapter.format_name.return_value = name
    adapter.test_connection.return_value = True
    if export_count is not None:
        adapter.export_batch.return_value = export_count
    else:
        # Default: return len(records) passed in
        adapter.export_batch.side_effect = lambda records: len(records)
    return adapter


# ── ExportEngine ─────────────────────────────────────────────────────

class TestExportEngine:
    def test_adapter_names(self):
        a1 = _make_mock_adapter("splunk")
        a2 = _make_mock_adapter("sentinel")
        engine = ExportEngine([a1, a2])
        assert engine.adapter_names == ["splunk", "sentinel"]

    @pytest.mark.asyncio
    async def test_export_scan(self, tenant_id, sample_records):
        adapter = _make_mock_adapter("splunk", export_count=5)
        engine = ExportEngine([adapter])

        results = await engine.export_scan(uuid4(), tenant_id, sample_records)
        assert results == {"splunk": 5}
        adapter.export_batch.assert_called_once_with(sample_records)

    @pytest.mark.asyncio
    async def test_export_to_multiple_adapters(self, tenant_id, sample_records):
        a1 = _make_mock_adapter("splunk", export_count=5)
        a2 = _make_mock_adapter("sentinel", export_count=5)
        engine = ExportEngine([a1, a2])

        results = await engine.export_scan(uuid4(), tenant_id, sample_records)
        assert results == {"splunk": 5, "sentinel": 5}

    @pytest.mark.asyncio
    async def test_cursor_tracking(self, tenant_id, sample_records):
        adapter = _make_mock_adapter("splunk", export_count=5)
        engine = ExportEngine([adapter])

        await engine.export_scan(uuid4(), tenant_id, sample_records)
        assert "splunk" in engine.cursors
        # Cursor should be the max timestamp
        assert engine.cursors["splunk"] == "2026-02-08T12:04:00+00:00"

    @pytest.mark.asyncio
    async def test_export_since_last_filters_old(self, tenant_id, sample_records):
        adapter = _make_mock_adapter("splunk")
        engine = ExportEngine([adapter])
        # Set cursor to minute 2 — only minutes 3 and 4 should be exported
        engine._cursors["splunk"] = datetime(2026, 2, 8, 12, 2, 0, tzinfo=timezone.utc)

        results = await engine.export_since_last(tenant_id, sample_records)
        assert results["splunk"] == 2  # minutes 3 and 4

    @pytest.mark.asyncio
    async def test_export_since_last_no_cursor(self, tenant_id, sample_records):
        adapter = _make_mock_adapter("splunk")
        engine = ExportEngine([adapter])

        results = await engine.export_since_last(tenant_id, sample_records)
        assert results["splunk"] == 5  # All records

    @pytest.mark.asyncio
    async def test_export_full_with_since_filter(self, tenant_id, sample_records):
        adapter = _make_mock_adapter("splunk")
        engine = ExportEngine([adapter])

        results = await engine.export_full(
            tenant_id,
            sample_records,
            since=datetime(2026, 2, 8, 12, 3, 0, tzinfo=timezone.utc),
        )
        # Only minutes 3 and 4
        assert results["splunk"] == 2

    @pytest.mark.asyncio
    async def test_export_full_with_record_type_filter(self, tenant_id):
        records = [
            ExportRecord(
                record_type="scan_result",
                timestamp=datetime(2026, 2, 8, tzinfo=timezone.utc),
                tenant_id=tenant_id,
                file_path="/a.txt",
            ),
            ExportRecord(
                record_type="access_event",
                timestamp=datetime(2026, 2, 8, tzinfo=timezone.utc),
                tenant_id=tenant_id,
                file_path="/b.txt",
            ),
        ]
        adapter = _make_mock_adapter("splunk")
        engine = ExportEngine([adapter])

        results = await engine.export_full(
            tenant_id, records, record_types=["scan_result"],
        )
        assert results["splunk"] == 1

    @pytest.mark.asyncio
    async def test_adapter_failure_is_handled(self, tenant_id, sample_records):
        adapter = _make_mock_adapter("splunk")
        adapter.export_batch.side_effect = ConnectionError("timeout")
        engine = ExportEngine([adapter])

        results = await engine.export_scan(uuid4(), tenant_id, sample_records)
        assert results["splunk"] == 0  # Failed gracefully

    @pytest.mark.asyncio
    async def test_test_connections(self):
        a1 = _make_mock_adapter("splunk")
        a1.test_connection.return_value = True
        a2 = _make_mock_adapter("sentinel")
        a2.test_connection.return_value = False
        engine = ExportEngine([a1, a2])

        results = await engine.test_connections()
        assert results == {"splunk": True, "sentinel": False}

    def test_get_status(self):
        engine = ExportEngine([_make_mock_adapter("splunk")])
        status = engine.get_status()
        assert status["adapter_count"] == 1
        assert "splunk" in status["adapters"]


# ── Record builders ──────────────────────────────────────────────────

class TestScanResultToExportRecords:
    def test_basic_conversion(self, tenant_id):
        rows = [
            {
                "file_path": "/data/test.xlsx",
                "risk_score": 75,
                "risk_tier": "HIGH",
                "entity_counts": {"SSN": 2, "EMAIL": 3},
                "policy_violations": [
                    {"policy_name": "HIPAA PHI", "framework": "hipaa"},
                ],
                "owner": "jdoe",
                "scanned_at": datetime(2026, 2, 8, tzinfo=timezone.utc),
            },
        ]
        records = scan_result_to_export_records(rows, tenant_id)
        assert len(records) == 1
        r = records[0]
        assert r.record_type == "scan_result"
        assert r.file_path == "/data/test.xlsx"
        assert r.risk_score == 75
        assert r.entity_types == ["SSN", "EMAIL"]
        assert r.policy_violations == ["HIPAA PHI"]
        assert r.user == "jdoe"

    def test_empty_input(self, tenant_id):
        records = scan_result_to_export_records([], tenant_id)
        assert records == []

    def test_null_fields(self, tenant_id):
        rows = [
            {
                "file_path": "/x.txt",
                "risk_score": None,
                "risk_tier": None,
                "entity_counts": None,
                "policy_violations": None,
                "owner": None,
                "scanned_at": None,
            },
        ]
        records = scan_result_to_export_records(rows, tenant_id)
        assert len(records) == 1
        r = records[0]
        assert r.entity_types == []
        assert r.policy_violations == []
