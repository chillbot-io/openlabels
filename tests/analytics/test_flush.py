"""Tests for the flush module: flush state persistence and partitioned writes."""

import json

import pyarrow as pa
import pytest

from openlabels.analytics.flush import (
    _write_partitioned_access_events,
    _write_partitioned_audit_logs,
    load_flush_state,
    save_flush_state,
)
from openlabels.analytics.schemas import ACCESS_EVENTS_SCHEMA, AUDIT_LOG_SCHEMA
from openlabels.analytics.storage import LocalStorage

from tests.analytics.conftest import TENANT_A, write_access_events


class TestFlushState:
    def test_load_default_state(self, storage: LocalStorage):
        state = load_flush_state(storage)
        assert state["schema_version"] == 1
        assert state["last_access_event_flush"] is None
        assert state["last_audit_log_flush"] is None

    def test_save_and_load_roundtrip(self, storage: LocalStorage):
        state = {
            "schema_version": 1,
            "last_access_event_flush": "2026-02-01T12:00:00+00:00",
            "last_audit_log_flush": "2026-02-01T11:00:00+00:00",
        }
        save_flush_state(storage, state)

        loaded = load_flush_state(storage)
        assert loaded["last_access_event_flush"] == "2026-02-01T12:00:00+00:00"
        assert loaded["last_audit_log_flush"] == "2026-02-01T11:00:00+00:00"

    def test_save_overwrites(self, storage: LocalStorage):
        save_flush_state(storage, {"schema_version": 1, "a": "first"})
        save_flush_state(storage, {"schema_version": 1, "a": "second"})

        loaded = load_flush_state(storage)
        assert loaded["a"] == "second"


class TestPartitionedWrites:
    """Tests for _write_partitioned_access_events and _write_partitioned_audit_logs."""

    def test_write_partitioned_access_events_creates_files(self, storage: LocalStorage):
        """Partitioned write should create Parquet files in hive-style directories."""
        from dataclasses import dataclass
        from datetime import datetime, timezone
        from uuid import uuid4

        @dataclass
        class FakeAccessEvent:
            tenant_id: object
            event_time: datetime

        now = datetime(2026, 2, 5, 14, 0, 0, tzinfo=timezone.utc)
        rows = [
            FakeAccessEvent(tenant_id=TENANT_A, event_time=now),
            FakeAccessEvent(tenant_id=TENANT_A, event_time=now),
        ]

        # Build a minimal Arrow table that matches the function's .take() call
        cols = {f.name: [] for f in ACCESS_EVENTS_SCHEMA}
        for _ in rows:
            for k in cols:
                cols[k].append(None)
        # Set non-null tenant_id and event_time for schema compliance
        table = pa.table(cols, schema=ACCESS_EVENTS_SCHEMA)

        _write_partitioned_access_events(storage, rows, table)

        # Should have created a parquet file in the correct partition
        parts = storage.list_partitions("access_events")
        assert len(parts) == 1
        assert str(TENANT_A) in parts[0]

    def test_write_partitioned_audit_logs_creates_files(self, storage: LocalStorage):
        """Partitioned write for audit logs should create hive-style directories."""
        from dataclasses import dataclass
        from datetime import datetime, timezone
        from uuid import uuid4

        @dataclass
        class FakeAuditLog:
            tenant_id: object
            created_at: datetime

        now = datetime(2026, 3, 10, 9, 0, 0, tzinfo=timezone.utc)
        rows = [FakeAuditLog(tenant_id=TENANT_A, created_at=now)]

        cols = {f.name: [] for f in AUDIT_LOG_SCHEMA}
        for _ in rows:
            for k in cols:
                cols[k].append(None)
        table = pa.table(cols, schema=AUDIT_LOG_SCHEMA)

        _write_partitioned_audit_logs(storage, rows, table)

        parts = storage.list_partitions("audit_log")
        assert len(parts) == 1
        assert str(TENANT_A) in parts[0]

    def test_multi_tenant_partitioned_events(self, storage: LocalStorage):
        """Events from different tenants should land in separate partitions."""
        from dataclasses import dataclass
        from datetime import datetime, timezone

        from tests.analytics.conftest import TENANT_B

        @dataclass
        class FakeAccessEvent:
            tenant_id: object
            event_time: datetime

        now = datetime(2026, 2, 5, 14, 0, 0, tzinfo=timezone.utc)
        rows = [
            FakeAccessEvent(tenant_id=TENANT_A, event_time=now),
            FakeAccessEvent(tenant_id=TENANT_B, event_time=now),
        ]

        cols = {f.name: [] for f in ACCESS_EVENTS_SCHEMA}
        for _ in rows:
            for k in cols:
                cols[k].append(None)
        table = pa.table(cols, schema=ACCESS_EVENTS_SCHEMA)

        _write_partitioned_access_events(storage, rows, table)

        parts = storage.list_partitions("access_events")
        assert len(parts) == 2
