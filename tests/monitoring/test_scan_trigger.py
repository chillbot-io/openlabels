"""Tests for ScanTriggerBuffer (Phase I)."""

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from openlabels.monitoring.providers.base import RawAccessEvent
from openlabels.monitoring.scan_trigger import (
    ScanTriggerBuffer,
    PendingScan,
    _DEBOUNCE_BY_TIER,
    _TIER_PRIORITY,
)


def _make_event(path: str = "/test/file.txt", action: str = "write") -> RawAccessEvent:
    return RawAccessEvent(
        file_path=path,
        event_time=datetime.now(timezone.utc),
        action=action,
        event_source="test",
    )


@dataclass
class _MockWatchedFile:
    path: Path
    risk_tier: str


def _mock_registry(tier: str = "HIGH"):
    """Return a registry lookup that always returns a watched file."""
    def lookup(path):
        return _MockWatchedFile(path=path, risk_tier=tier)
    return lookup


class TestDebounceConfig:
    """Tests for debounce tier configuration."""

    def test_critical_debounce_is_shortest(self):
        assert _DEBOUNCE_BY_TIER["CRITICAL"] < _DEBOUNCE_BY_TIER["HIGH"]

    def test_high_debounce_less_than_medium(self):
        assert _DEBOUNCE_BY_TIER["HIGH"] < _DEBOUNCE_BY_TIER["MEDIUM"]

    def test_critical_priority_is_highest(self):
        assert _TIER_PRIORITY["CRITICAL"] < _TIER_PRIORITY["HIGH"]
        assert _TIER_PRIORITY["HIGH"] < _TIER_PRIORITY["MEDIUM"]


class TestScanTriggerInit:
    """Tests for ScanTriggerBuffer initialization."""

    def test_defaults(self):
        trigger = ScanTriggerBuffer()
        assert trigger._rate_limit == 10
        assert trigger._cooldown == 60.0
        assert trigger._min_tier == "MEDIUM"

    def test_custom_settings(self):
        trigger = ScanTriggerBuffer(
            rate_limit=5,
            cooldown_seconds=30.0,
            min_risk_tier="HIGH",
        )
        assert trigger._rate_limit == 5
        assert trigger._cooldown == 30.0
        assert trigger._min_tier == "HIGH"


class TestOnEvent:
    """Tests for event handling and filtering."""

    def test_unregistered_file_filtered(self):
        trigger = ScanTriggerBuffer(
            registry_lookup=lambda p: None,  # Nothing registered
        )
        trigger.on_event(_make_event("/unknown.txt"))
        assert trigger.total_events_filtered == 1
        assert len(trigger._pending) == 0

    def test_registered_file_creates_pending(self):
        trigger = ScanTriggerBuffer(
            registry_lookup=_mock_registry("HIGH"),
        )
        trigger.on_event(_make_event("/important.docx"))
        assert len(trigger._pending) == 1
        assert "/important.docx" in trigger._pending

    def test_low_risk_filtered_with_medium_threshold(self):
        trigger = ScanTriggerBuffer(
            registry_lookup=_mock_registry("LOW"),
            min_risk_tier="MEDIUM",
        )
        trigger.on_event(_make_event("/low_risk.txt"))
        assert trigger.total_events_filtered == 1

    def test_critical_passes_high_threshold(self):
        trigger = ScanTriggerBuffer(
            registry_lookup=_mock_registry("CRITICAL"),
            min_risk_tier="HIGH",
        )
        trigger.on_event(_make_event("/critical.docx"))
        assert len(trigger._pending) == 1

    def test_debounce_increments_event_count(self):
        trigger = ScanTriggerBuffer(
            registry_lookup=_mock_registry("HIGH"),
        )
        trigger.on_event(_make_event("/file.txt"))
        trigger.on_event(_make_event("/file.txt"))
        trigger.on_event(_make_event("/file.txt"))

        assert len(trigger._pending) == 1
        assert trigger._pending["/file.txt"].event_count == 3
        assert trigger.total_events_debounced == 2

    def test_different_files_separate_entries(self):
        trigger = ScanTriggerBuffer(
            registry_lookup=_mock_registry("HIGH"),
        )
        trigger.on_event(_make_event("/a.txt"))
        trigger.on_event(_make_event("/b.txt"))

        assert len(trigger._pending) == 2

    def test_cooldown_filters_events(self):
        trigger = ScanTriggerBuffer(
            registry_lookup=_mock_registry("HIGH"),
        )
        # Set an active cooldown
        trigger._cooldowns["/cooled.txt"] = time.monotonic() + 100
        trigger.on_event(_make_event("/cooled.txt"))
        assert trigger.total_events_filtered == 1

    def test_no_registry_filters_everything(self):
        trigger = ScanTriggerBuffer(registry_lookup=lambda p: None)
        trigger.on_event(_make_event("/test.txt"))
        assert trigger.total_events_filtered == 1


class TestDispatch:
    """Tests for scan dispatch logic."""

    @pytest.mark.asyncio
    async def test_dispatch_after_debounce_expires(self):
        dispatched = []
        trigger = ScanTriggerBuffer(
            registry_lookup=_mock_registry("HIGH"),
            dispatch_callback=lambda path, tier: dispatched.append((path, tier)),
            cooldown_seconds=0.1,
        )

        trigger.on_event(_make_event("/file.txt"))
        # Set debounce to expired
        trigger._pending["/file.txt"].debounce_until = time.monotonic() - 1

        await trigger._dispatch_ready()

        assert len(dispatched) == 1
        assert dispatched[0] == ("/file.txt", "HIGH")
        assert trigger.total_scans_dispatched == 1

    @pytest.mark.asyncio
    async def test_pending_not_dispatched_before_debounce(self):
        dispatched = []
        trigger = ScanTriggerBuffer(
            registry_lookup=_mock_registry("HIGH"),
            dispatch_callback=lambda path, tier: dispatched.append((path, tier)),
        )

        trigger.on_event(_make_event("/file.txt"))
        # Don't expire the debounce

        await trigger._dispatch_ready()

        assert len(dispatched) == 0
        assert len(trigger._pending) == 1

    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        dispatched = []
        trigger = ScanTriggerBuffer(
            registry_lookup=_mock_registry("HIGH"),
            dispatch_callback=lambda path, tier: dispatched.append((path, tier)),
            rate_limit=2,
            cooldown_seconds=0.1,
        )

        # Create 5 pending scans, all expired
        for i in range(5):
            trigger.on_event(_make_event(f"/file_{i}.txt"))
            trigger._pending[f"/file_{i}.txt"].debounce_until = time.monotonic() - 1

        await trigger._dispatch_ready()

        # Only 2 should have been dispatched (rate limit)
        assert len(dispatched) == 2
        assert trigger.total_events_rate_limited == 3

    @pytest.mark.asyncio
    async def test_priority_ordering(self):
        dispatched = []
        trigger = ScanTriggerBuffer(
            dispatch_callback=lambda path, tier: dispatched.append((path, tier)),
            rate_limit=10,
            cooldown_seconds=0.1,
            min_risk_tier="MEDIUM",
        )

        # Manually create pending scans with different priorities
        now = time.monotonic() - 1
        trigger._pending["/medium.txt"] = PendingScan(
            file_path="/medium.txt", risk_tier="MEDIUM",
            debounce_until=now, priority=2,
        )
        trigger._pending["/critical.txt"] = PendingScan(
            file_path="/critical.txt", risk_tier="CRITICAL",
            debounce_until=now, priority=0,
        )
        trigger._pending["/high.txt"] = PendingScan(
            file_path="/high.txt", risk_tier="HIGH",
            debounce_until=now, priority=1,
        )

        await trigger._dispatch_ready()

        assert len(dispatched) == 3
        assert dispatched[0][1] == "CRITICAL"
        assert dispatched[1][1] == "HIGH"
        assert dispatched[2][1] == "MEDIUM"

    @pytest.mark.asyncio
    async def test_cooldown_set_after_dispatch(self):
        trigger = ScanTriggerBuffer(
            registry_lookup=_mock_registry("HIGH"),
            dispatch_callback=lambda path, tier: None,
            cooldown_seconds=60.0,
        )

        trigger.on_event(_make_event("/file.txt"))
        trigger._pending["/file.txt"].debounce_until = time.monotonic() - 1

        await trigger._dispatch_ready()

        assert "/file.txt" in trigger._cooldowns
        assert trigger._cooldowns["/file.txt"] > time.monotonic()


class TestStats:
    """Tests for stats reporting."""

    def test_initial_stats(self):
        trigger = ScanTriggerBuffer()
        stats = trigger.get_stats()
        assert stats["total_events_received"] == 0
        assert stats["total_scans_dispatched"] == 0
        assert stats["pending_scans"] == 0
        assert stats["active_cooldowns"] == 0

    def test_stats_after_events(self):
        trigger = ScanTriggerBuffer(
            registry_lookup=_mock_registry("HIGH"),
        )
        trigger.on_event(_make_event("/a.txt"))
        trigger.on_event(_make_event("/b.txt"))

        stats = trigger.get_stats()
        assert stats["total_events_received"] == 2
        assert stats["pending_scans"] == 2


class TestRunLoop:
    """Tests for the main run loop."""

    @pytest.mark.asyncio
    async def test_run_stops_on_shutdown(self):
        trigger = ScanTriggerBuffer()
        shutdown = asyncio.Event()

        async def stop_soon():
            await asyncio.sleep(0.1)
            shutdown.set()

        asyncio.create_task(stop_soon())
        await trigger.run(shutdown, tick_interval=0.05)
        # Verify the shutdown event was set and run() returned
        assert shutdown.is_set()
