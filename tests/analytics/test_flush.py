"""Tests for the flush module: flush state persistence and partitioned writes."""

import json

import pytest

from openlabels.analytics.flush import load_flush_state, save_flush_state
from openlabels.analytics.storage import LocalStorage


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
