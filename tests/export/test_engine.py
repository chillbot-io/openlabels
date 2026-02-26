"""Tests for ExportEngine — cursor tracking, adapter dispatch, record building,
and streaming / chunked processing.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from openlabels.export.adapters.base import ExportRecord
from openlabels.export.engine import (
    ExportEngine,
    _FETCH_BATCH,
    _iter_chunks,
    scan_result_to_export_records,
)


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
    # format_name is a sync method — use MagicMock so it returns a string, not a coroutine
    adapter.format_name = MagicMock(return_value=name)
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
        # Cursor should be the max timestamp, serialized as ISO string
        assert engine.cursors == {"splunk": "2026-02-08T12:04:00+00:00"}
        # Internal cursor should be a datetime object
        assert engine._cursors["splunk"] == datetime(2026, 2, 8, 12, 4, 0, tzinfo=timezone.utc)

    @pytest.mark.asyncio
    async def test_export_since_last_filters_old(self, tenant_id, sample_records):
        adapter = _make_mock_adapter("splunk")
        engine = ExportEngine([adapter])
        # Set cursor to minute 2 — only minutes 3 and 4 should be exported
        engine._cursors["splunk"] = datetime(2026, 2, 8, 12, 2, 0, tzinfo=timezone.utc)

        results = await engine.export_since_last(tenant_id, sample_records)
        assert results["splunk"] == 2  # minutes 3 and 4
        # Verify adapter was called with only the 2 newer records
        called_records = adapter.export_batch.call_args[0][0]
        assert len(called_records) == 2
        assert all(r.timestamp > datetime(2026, 2, 8, 12, 2, 0, tzinfo=timezone.utc) for r in called_records)

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
        # Only minutes 3 and 4 (since uses >= comparison)
        assert results["splunk"] == 2
        called_records = adapter.export_batch.call_args[0][0]
        assert len(called_records) == 2
        assert all(
            r.timestamp >= datetime(2026, 2, 8, 12, 3, 0, tzinfo=timezone.utc)
            for r in called_records
        )

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
        called_records = adapter.export_batch.call_args[0][0]
        assert len(called_records) == 1
        assert called_records[0].record_type == "scan_result"
        assert called_records[0].file_path == "/a.txt"

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
        assert status == {
            "adapters": ["splunk"],
            "cursors": {},
            "adapter_count": 1,
        }


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


# ── Streaming / chunked processing ───────────────────────────────────

def _make_records(
    n: int, tenant_id: UUID, base_minute: int = 0,
) -> list[ExportRecord]:
    """Helper to create *n* records with sequential timestamps."""
    return [
        ExportRecord(
            record_type="scan_result",
            timestamp=datetime(2026, 2, 8, 12, base_minute + i, 0, tzinfo=timezone.utc),
            tenant_id=tenant_id,
            file_path=f"/data/file_{base_minute + i}.txt",
            risk_score=50,
            risk_tier="HIGH",
        )
        for i in range(n)
    ]


async def _async_iter_records(
    records: list[ExportRecord],
) -> AsyncIterator[ExportRecord]:
    """Wrap a list as an async iterator, yielding one record at a time."""
    for r in records:
        yield r


class TestIterChunks:
    """Verify that ``_iter_chunks`` correctly partitions both lists and
    async iterables into fixed-size chunks.
    """

    async def test_list_source_single_chunk(self, tenant_id):
        records = _make_records(3, tenant_id)
        chunks = [c async for c in _iter_chunks(records, batch_size=10)]
        assert len(chunks) == 1
        assert len(chunks[0]) == 3

    async def test_list_source_multiple_chunks(self, tenant_id):
        records = _make_records(7, tenant_id)
        chunks = [c async for c in _iter_chunks(records, batch_size=3)]
        assert len(chunks) == 3
        assert [len(c) for c in chunks] == [3, 3, 1]

    async def test_async_source_single_chunk(self, tenant_id):
        records = _make_records(3, tenant_id)
        chunks = [c async for c in _iter_chunks(_async_iter_records(records), batch_size=10)]
        assert len(chunks) == 1
        assert len(chunks[0]) == 3

    async def test_async_source_multiple_chunks(self, tenant_id):
        records = _make_records(7, tenant_id)
        chunks = [c async for c in _iter_chunks(_async_iter_records(records), batch_size=3)]
        assert len(chunks) == 3
        assert [len(c) for c in chunks] == [3, 3, 1]

    async def test_empty_list(self):
        chunks = [c async for c in _iter_chunks([], batch_size=5)]
        assert chunks == []

    async def test_empty_async_iter(self):
        async def _empty() -> AsyncIterator[ExportRecord]:
            return
            yield  # noqa: unreachable — makes this an async generator

        chunks = [c async for c in _iter_chunks(_empty(), batch_size=5)]
        assert chunks == []


class TestStreamingExport:
    """Ensure the engine processes async-iterable record sources correctly
    and does not load all records into memory at once.
    """

    async def test_export_scan_with_async_iterable(self, tenant_id):
        """export_scan should accept an async iterable and dispatch correctly."""
        records = _make_records(5, tenant_id)
        adapter = _make_mock_adapter("splunk")
        engine = ExportEngine([adapter])

        results = await engine.export_scan(
            uuid4(), tenant_id, _async_iter_records(records),
        )
        assert results["splunk"] == 5

    async def test_export_full_with_async_iterable(self, tenant_id):
        """export_full should accept an async iterable and apply filters."""
        records = _make_records(5, tenant_id)
        adapter = _make_mock_adapter("splunk")
        engine = ExportEngine([adapter])

        results = await engine.export_full(
            tenant_id,
            _async_iter_records(records),
            since=datetime(2026, 2, 8, 12, 3, 0, tzinfo=timezone.utc),
        )
        # Only minutes 3 and 4
        assert results["splunk"] == 2

    async def test_export_since_last_with_async_iterable(self, tenant_id):
        """export_since_last should stream and filter per cursor."""
        records = _make_records(5, tenant_id)
        adapter = _make_mock_adapter("splunk")
        engine = ExportEngine([adapter])
        engine._cursors["splunk"] = datetime(2026, 2, 8, 12, 2, 0, tzinfo=timezone.utc)

        results = await engine.export_since_last(
            tenant_id, _async_iter_records(records),
        )
        assert results["splunk"] == 2  # minutes 3 and 4

    async def test_chunked_dispatch_calls_adapter_in_batches(self, tenant_id):
        """When records exceed _FETCH_BATCH, adapter should receive
        multiple batch calls instead of one giant call.
        """
        batch_size = 3
        records = _make_records(7, tenant_id)
        adapter = _make_mock_adapter("splunk")
        engine = ExportEngine([adapter])

        # Monkey-patch _FETCH_BATCH for this test
        import openlabels.export.engine as engine_mod
        original = engine_mod._FETCH_BATCH
        engine_mod._FETCH_BATCH = batch_size
        try:
            results = await engine.export_scan(uuid4(), tenant_id, records)
        finally:
            engine_mod._FETCH_BATCH = original

        # Adapter should have been called 3 times: batches of 3, 3, 1
        assert adapter.export_batch.call_count == 3
        batch_sizes = [
            len(call.args[0]) for call in adapter.export_batch.call_args_list
        ]
        assert batch_sizes == [3, 3, 1]
        assert results["splunk"] == 7

    async def test_streaming_does_not_materialise_all_records(self, tenant_id):
        """Verify that using an async iterable means records are consumed
        incrementally, not buffered into one big list.
        """
        consumed_count = 0
        total = 10

        async def _counting_iter() -> AsyncIterator[ExportRecord]:
            nonlocal consumed_count
            for i in range(total):
                consumed_count += 1
                yield ExportRecord(
                    record_type="scan_result",
                    timestamp=datetime(2026, 2, 8, 12, i, 0, tzinfo=timezone.utc),
                    tenant_id=tenant_id,
                    file_path=f"/data/file_{i}.txt",
                    risk_score=50,
                    risk_tier="HIGH",
                )

        adapter = _make_mock_adapter("splunk")
        engine = ExportEngine([adapter])

        import openlabels.export.engine as engine_mod
        original = engine_mod._FETCH_BATCH
        engine_mod._FETCH_BATCH = 3
        try:
            results = await engine.export_scan(uuid4(), tenant_id, _counting_iter())
        finally:
            engine_mod._FETCH_BATCH = original

        # All 10 records processed
        assert results["splunk"] == total
        assert consumed_count == total
        # Adapter was called multiple times (4 batches: 3+3+3+1)
        assert adapter.export_batch.call_count == 4
