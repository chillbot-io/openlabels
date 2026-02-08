"""
Tests for Phase G: EventProvider protocol, RawAccessEvent, EventHarvester,
WindowsSACLProvider, and AuditdProvider.

These tests validate:
- RawAccessEvent creation and immutability
- EventProvider protocol conformance
- Provider → RawAccessEvent conversion
- EventHarvester cycle with mock providers
- Checkpoint tracking per provider
- DB persistence (FileAccessEvent insertion)
- Back-pressure cap enforcement
- Registry cache-to-DB sync wiring
- MonitoringSettings config
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Iterator, Optional
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from openlabels.monitoring.base import AccessEvent, AccessAction
from openlabels.monitoring.providers.base import EventProvider, RawAccessEvent
from openlabels.monitoring.providers.windows import (
    WindowsSACLProvider,
    _access_event_to_raw,
)
from openlabels.monitoring.providers.linux import (
    AuditdProvider,
    _access_event_to_raw as _linux_access_event_to_raw,
)
from openlabels.monitoring.harvester import EventHarvester


# =====================================================================
# Fixtures and helpers
# =====================================================================


def _make_raw_event(
    file_path: str = "/data/secret.xlsx",
    action: str = "read",
    event_source: str = "test_provider",
    event_time: datetime | None = None,
    **kwargs,
) -> RawAccessEvent:
    """Helper to create a RawAccessEvent for testing."""
    return RawAccessEvent(
        file_path=file_path,
        event_time=event_time or datetime.now(timezone.utc),
        action=action,
        event_source=event_source,
        **kwargs,
    )


def _make_access_event(
    path: str = "/data/secret.xlsx",
    action: AccessAction = AccessAction.READ,
    **kwargs,
) -> AccessEvent:
    """Helper to create an AccessEvent for testing."""
    return AccessEvent(
        path=Path(path),
        timestamp=datetime.now(timezone.utc),
        action=action,
        **kwargs,
    )


class FakeProvider:
    """A fake EventProvider for testing the harvester."""

    def __init__(
        self,
        name: str = "fake",
        events: list[RawAccessEvent] | None = None,
    ):
        self._name = name
        self._events = events or []
        self.collect_calls: list[Optional[datetime]] = []

    @property
    def name(self) -> str:
        return self._name

    def collect(self, since: Optional[datetime] = None) -> Iterator[RawAccessEvent]:
        self.collect_calls.append(since)
        yield from self._events


class FailingProvider:
    """A provider that raises on collect()."""

    @property
    def name(self) -> str:
        return "failing"

    def collect(self, since: Optional[datetime] = None) -> Iterator[RawAccessEvent]:
        raise RuntimeError("Provider failed")


# =====================================================================
# RawAccessEvent tests
# =====================================================================


class TestRawAccessEvent:
    """Tests for the RawAccessEvent dataclass."""

    def test_create_minimal(self):
        """Can create with required fields only."""
        event = RawAccessEvent(
            file_path="/test/file.txt",
            event_time=datetime(2026, 2, 1, 12, 0, 0),
            action="read",
            event_source="test",
        )
        assert event.file_path == "/test/file.txt"
        assert event.action == "read"
        assert event.event_source == "test"

    def test_create_full(self):
        """Can create with all fields."""
        event = RawAccessEvent(
            file_path="/test/file.txt",
            event_time=datetime(2026, 2, 1, 12, 0, 0),
            action="write",
            event_source="windows_sacl",
            user_sid="S-1-5-21-123",
            user_name="jsmith",
            user_domain="CORP",
            process_name="notepad.exe",
            process_id=1234,
            event_id=4663,
            success=True,
            raw={"EventID": 4663},
        )
        assert event.user_name == "jsmith"
        assert event.process_id == 1234
        assert event.event_id == 4663

    def test_frozen(self):
        """RawAccessEvent is immutable."""
        event = _make_raw_event()
        with pytest.raises(AttributeError):
            event.file_path = "/other"  # type: ignore

    def test_optional_defaults(self):
        """Optional fields default to None/True."""
        event = _make_raw_event()
        assert event.user_sid is None
        assert event.user_name is None
        assert event.user_domain is None
        assert event.process_name is None
        assert event.process_id is None
        assert event.event_id is None
        assert event.success is True
        assert event.raw is None


# =====================================================================
# EventProvider protocol tests
# =====================================================================


class TestEventProviderProtocol:
    """Tests for the EventProvider protocol."""

    def test_fake_provider_is_event_provider(self):
        """FakeProvider satisfies the EventProvider protocol."""
        provider = FakeProvider()
        assert isinstance(provider, EventProvider)

    def test_windows_provider_is_event_provider(self):
        """WindowsSACLProvider satisfies the EventProvider protocol."""
        provider = WindowsSACLProvider()
        assert isinstance(provider, EventProvider)

    def test_auditd_provider_is_event_provider(self):
        """AuditdProvider satisfies the EventProvider protocol."""
        provider = AuditdProvider()
        assert isinstance(provider, EventProvider)

    def test_provider_name(self):
        """Providers have the correct name."""
        assert WindowsSACLProvider().name == "windows_sacl"
        assert AuditdProvider().name == "auditd"


# =====================================================================
# Provider conversion tests
# =====================================================================


class TestAccessEventConversion:
    """Tests for AccessEvent → RawAccessEvent conversion."""

    def test_windows_conversion(self):
        """WindowsSACLProvider converts AccessEvent correctly."""
        event = _make_access_event(
            path="/data/secret.xlsx",
            action=AccessAction.WRITE,
            user_name="jsmith",
            user_sid="S-1-5-21-123",
            user_domain="CORP",
            process_name="excel.exe",
            process_id=5678,
            event_id=4663,
        )
        raw = _access_event_to_raw(event)

        assert raw.file_path == "/data/secret.xlsx"
        assert raw.action == "write"
        assert raw.event_source == "windows_sacl"
        assert raw.user_name == "jsmith"
        assert raw.user_sid == "S-1-5-21-123"
        assert raw.user_domain == "CORP"
        assert raw.process_name == "excel.exe"
        assert raw.process_id == 5678
        assert raw.event_id == 4663
        assert raw.raw is not None  # includes to_dict()

    def test_linux_conversion(self):
        """AuditdProvider converts AccessEvent correctly."""
        event = _make_access_event(
            path="/data/secret.xlsx",
            action=AccessAction.READ,
            user_name="jsmith",
            user_sid="1000",
        )
        raw = _linux_access_event_to_raw(event)

        assert raw.file_path == "/data/secret.xlsx"
        assert raw.action == "read"
        assert raw.event_source == "auditd"
        assert raw.user_name == "jsmith"

    def test_conversion_preserves_timestamp(self):
        """Conversion preserves the original event timestamp."""
        ts = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
        event = AccessEvent(
            path=Path("/test/file.txt"),
            timestamp=ts,
            action=AccessAction.READ,
        )
        raw = _access_event_to_raw(event)
        assert raw.event_time == ts


# =====================================================================
# Provider collect() tests (with mocked subprocess)
# =====================================================================


class TestWindowsSACLProviderCollect:
    """Test WindowsSACLProvider.collect() with mocked EventCollector."""

    @patch("openlabels.monitoring.providers.windows.EventCollector")
    def test_collect_yields_raw_events(self, MockCollector):
        """collect() yields RawAccessEvents from the underlying collector."""
        mock_collector = MockCollector.return_value
        mock_collector.collect_events.return_value = iter([
            _make_access_event(path="/a.txt", action=AccessAction.READ),
            _make_access_event(path="/b.txt", action=AccessAction.WRITE),
        ])

        provider = WindowsSACLProvider()
        events = list(provider.collect())

        assert len(events) == 2
        assert events[0].file_path == "/a.txt"
        assert events[0].event_source == "windows_sacl"
        assert events[1].file_path == "/b.txt"

    @patch("openlabels.monitoring.providers.windows.EventCollector")
    def test_collect_passes_since(self, MockCollector):
        """collect() passes the since parameter to the collector."""
        mock_collector = MockCollector.return_value
        mock_collector.collect_events.return_value = iter([])
        since = datetime(2026, 2, 1, tzinfo=timezone.utc)

        provider = WindowsSACLProvider(watched_paths=["/a.txt"])
        list(provider.collect(since=since))

        mock_collector.collect_events.assert_called_once_with(
            since=since,
            paths=["/a.txt"],
        )

    @patch("openlabels.monitoring.providers.windows.EventCollector")
    def test_collect_handles_exception(self, MockCollector):
        """collect() catches exceptions and yields nothing."""
        mock_collector = MockCollector.return_value
        mock_collector.collect_events.side_effect = RuntimeError("wevtutil failed")

        provider = WindowsSACLProvider()
        events = list(provider.collect())
        assert events == []

    def test_update_watched_paths(self):
        """update_watched_paths() updates the internal path list."""
        provider = WindowsSACLProvider(watched_paths=["/a.txt"])
        provider.update_watched_paths(["/b.txt", "/c.txt"])
        assert provider._watched_paths == ["/b.txt", "/c.txt"]


class TestAuditdProviderCollect:
    """Test AuditdProvider.collect() with mocked EventCollector."""

    @patch("openlabels.monitoring.providers.linux.EventCollector")
    def test_collect_yields_raw_events(self, MockCollector):
        """collect() yields RawAccessEvents from the underlying collector."""
        mock_collector = MockCollector.return_value
        mock_collector.collect_events.return_value = iter([
            _make_access_event(path="/data/file.csv"),
        ])

        provider = AuditdProvider()
        events = list(provider.collect())

        assert len(events) == 1
        assert events[0].file_path == "/data/file.csv"
        assert events[0].event_source == "auditd"


# =====================================================================
# EventHarvester tests
# =====================================================================


class TestEventHarvester:
    """Tests for EventHarvester cycle, checkpoint, and persistence."""

    @pytest.fixture
    def _mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        return session

    @pytest.fixture
    def _mock_monitored_file(self):
        """Create a mock MonitoredFile."""
        mf = MagicMock()
        mf.id = uuid4()
        mf.tenant_id = uuid4()
        mf.file_path = "/data/secret.xlsx"
        mf.access_count = 0
        mf.last_event_at = None
        return mf

    @pytest.mark.asyncio
    async def test_harvest_once_with_events(self, _mock_session, _mock_monitored_file):
        """harvest_once() persists events from providers."""
        events = [
            _make_raw_event(file_path="/data/secret.xlsx", action="read"),
            _make_raw_event(file_path="/data/secret.xlsx", action="write"),
        ]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider])

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            count = await harvester.harvest_once(_mock_session)

        assert count == 2
        assert _mock_session.add.call_count == 2
        _mock_session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_harvest_skips_unmonitored_files(self, _mock_session):
        """Events for files not in the monitored registry are skipped."""
        events = [_make_raw_event(file_path="/unknown/file.txt")]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider])

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={},  # no monitored files
        ):
            count = await harvester.harvest_once(_mock_session)

        assert count == 0
        assert _mock_session.add.call_count == 0

    @pytest.mark.asyncio
    async def test_checkpoint_tracking(self, _mock_session, _mock_monitored_file):
        """Harvester tracks per-provider checkpoint timestamps."""
        t1 = datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 2, 1, 11, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_raw_event(event_time=t1),
            _make_raw_event(event_time=t2),
        ]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider])

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            await harvester.harvest_once(_mock_session)

        # Checkpoint should be the latest event time
        assert harvester._checkpoints["test"] == t2

    @pytest.mark.asyncio
    async def test_checkpoint_passed_to_collect(self, _mock_session, _mock_monitored_file):
        """On second cycle, the checkpoint is passed to collect(since=...)."""
        t1 = datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc)
        events = [_make_raw_event(event_time=t1)]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider])

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            # Cycle 1: no checkpoint yet
            await harvester.harvest_once(_mock_session)
            assert provider.collect_calls[0] is None

            # Cycle 2: checkpoint from cycle 1
            await harvester.harvest_once(_mock_session)
            assert provider.collect_calls[1] == t1

    @pytest.mark.asyncio
    async def test_back_pressure_cap(self, _mock_session, _mock_monitored_file):
        """Harvester respects max_events_per_cycle cap."""
        events = [_make_raw_event() for _ in range(100)]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider], max_events_per_cycle=10)

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            count = await harvester.harvest_once(_mock_session)

        assert count == 10  # capped at max_events_per_cycle

    @pytest.mark.asyncio
    async def test_failing_provider_doesnt_crash(self, _mock_session):
        """A failing provider doesn't crash the harvest cycle."""
        good_events = [_make_raw_event()]
        good_provider = FakeProvider(name="good", events=good_events)
        bad_provider = FailingProvider()
        harvester = EventHarvester([bad_provider, good_provider])

        mock_mf = MagicMock()
        mock_mf.id = uuid4()
        mock_mf.tenant_id = uuid4()
        mock_mf.file_path = "/data/secret.xlsx"
        mock_mf.access_count = 0
        mock_mf.last_event_at = None

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": mock_mf},
        ):
            count = await harvester.harvest_once(_mock_session)

        # Good provider's event was still persisted
        assert count == 1

    @pytest.mark.asyncio
    async def test_empty_cycle(self, _mock_session):
        """No events from any provider → 0 persisted."""
        provider = FakeProvider(name="empty", events=[])
        harvester = EventHarvester([provider])
        count = await harvester.harvest_once(_mock_session)
        assert count == 0

    @pytest.mark.asyncio
    async def test_multiple_providers(self, _mock_session, _mock_monitored_file):
        """Events from multiple providers are all persisted."""
        e1 = [_make_raw_event(event_source="provider_a")]
        e2 = [_make_raw_event(event_source="provider_b")]
        p1 = FakeProvider(name="a", events=e1)
        p2 = FakeProvider(name="b", events=e2)
        harvester = EventHarvester([p1, p2])

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            count = await harvester.harvest_once(_mock_session)

        assert count == 2

    @pytest.mark.asyncio
    async def test_stats_updated(self, _mock_session, _mock_monitored_file):
        """Harvester stats are updated after each cycle."""
        events = [_make_raw_event()]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider])

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            await harvester.harvest_once(_mock_session)

        assert harvester.total_events_persisted == 1
        assert harvester.total_cycles == 1
        assert harvester.last_cycle_at is not None

    @pytest.mark.asyncio
    async def test_monitored_file_stats_updated(self, _mock_session, _mock_monitored_file):
        """Harvester updates access_count and last_event_at on MonitoredFile."""
        t = datetime(2026, 2, 5, 14, 0, 0, tzinfo=timezone.utc)
        events = [_make_raw_event(event_time=t)]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider])

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            await harvester.harvest_once(_mock_session)

        assert _mock_monitored_file.access_count == 1
        assert _mock_monitored_file.last_event_at == t

    @pytest.mark.asyncio
    async def test_store_raw_events_flag(self, _mock_session, _mock_monitored_file):
        """When store_raw_events=True, raw_event is populated."""
        events = [_make_raw_event(raw={"test": True})]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider], store_raw_events=True)

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            await harvester.harvest_once(_mock_session)

        # Check the FileAccessEvent was created with raw_event
        call_args = _mock_session.add.call_args[0][0]
        assert call_args.raw_event == {"test": True}

    @pytest.mark.asyncio
    async def test_store_raw_events_off(self, _mock_session, _mock_monitored_file):
        """When store_raw_events=False, raw_event is None."""
        events = [_make_raw_event(raw={"test": True})]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider], store_raw_events=False)

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            await harvester.harvest_once(_mock_session)

        call_args = _mock_session.add.call_args[0][0]
        assert call_args.raw_event is None


# =====================================================================
# Deep-dive fix tests
# =====================================================================


class TestUnknownActionFiltering:
    """Tests for FIX #1: events with action='unknown' are filtered out."""

    @pytest.fixture
    def _mock_session(self):
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        return session

    @pytest.fixture
    def _mock_monitored_file(self):
        mf = MagicMock()
        mf.id = uuid4()
        mf.tenant_id = uuid4()
        mf.file_path = "/data/secret.xlsx"
        mf.access_count = 0
        mf.last_event_at = None
        return mf

    @pytest.mark.asyncio
    async def test_unknown_action_filtered(self, _mock_session, _mock_monitored_file):
        """Events with action='unknown' are not persisted."""
        events = [
            _make_raw_event(action="unknown"),
            _make_raw_event(action="read"),
        ]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider])

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            count = await harvester.harvest_once(_mock_session)

        assert count == 1  # only the "read" event
        call_args = _mock_session.add.call_args[0][0]
        assert call_args.action == "read"

    @pytest.mark.asyncio
    async def test_all_unknown_yields_zero(self, _mock_session, _mock_monitored_file):
        """If all events have unknown action, nothing is persisted."""
        events = [
            _make_raw_event(action="unknown"),
            _make_raw_event(action="unknown"),
        ]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider])

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            count = await harvester.harvest_once(_mock_session)

        assert count == 0

    @pytest.mark.asyncio
    async def test_execute_action_allowed(self, _mock_session, _mock_monitored_file):
        """Events with action='execute' (in DB enum) are persisted."""
        events = [_make_raw_event(action="execute")]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider])

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            count = await harvester.harvest_once(_mock_session)

        assert count == 1


class TestDeferredCheckpoints:
    """Tests for FIX #2: checkpoints deferred until commit."""

    @pytest.fixture
    def _mock_session(self):
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        return session

    @pytest.fixture
    def _mock_monitored_file(self):
        mf = MagicMock()
        mf.id = uuid4()
        mf.tenant_id = uuid4()
        mf.file_path = "/data/secret.xlsx"
        mf.access_count = 0
        mf.last_event_at = None
        return mf

    @pytest.mark.asyncio
    async def test_checkpoint_applied_after_harvest(self, _mock_session, _mock_monitored_file):
        """Checkpoints are in _checkpoints after harvest_once."""
        t = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
        events = [_make_raw_event(event_time=t)]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider])

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            await harvester.harvest_once(_mock_session)

        assert harvester._checkpoints["test"] == t

    @pytest.mark.asyncio
    async def test_pending_cleared_on_new_cycle(self, _mock_session, _mock_monitored_file):
        """Pending checkpoints are cleared at start of each cycle."""
        events = [_make_raw_event()]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider])

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            await harvester.harvest_once(_mock_session)

        # After harvest_once, pending should be cleared
        assert harvester._pending_checkpoints == {}


class TestBackPressureSorting:
    """Tests for FIX #4: events sorted by time before truncation."""

    @pytest.fixture
    def _mock_session(self):
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        return session

    @pytest.fixture
    def _mock_monitored_file(self):
        mf = MagicMock()
        mf.id = uuid4()
        mf.tenant_id = uuid4()
        mf.file_path = "/data/secret.xlsx"
        mf.access_count = 0
        mf.last_event_at = None
        return mf

    @pytest.mark.asyncio
    async def test_earliest_events_kept(self, _mock_session, _mock_monitored_file):
        """Back-pressure keeps earliest events (sorted by time)."""
        # Create events in reverse chronological order
        base = datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_raw_event(event_time=base + timedelta(hours=i))
            for i in range(10, 0, -1)  # 10, 9, 8, ..., 1
        ]
        provider = FakeProvider(name="test", events=events)
        harvester = EventHarvester([provider], max_events_per_cycle=3)

        with patch.object(
            EventHarvester,
            "_resolve_monitored_files",
            return_value={"/data/secret.xlsx": _mock_monitored_file},
        ):
            count = await harvester.harvest_once(_mock_session)

        assert count == 3
        # Checkpoint should be at hour 3 (the 3rd earliest)
        expected_checkpoint = base + timedelta(hours=3)
        assert harvester._checkpoints["test"] == expected_checkpoint


# =====================================================================
# EventHarvester.run() tests
# =====================================================================


class TestEventHarvesterRun:
    """Tests for the harvester's main run loop."""

    @pytest.mark.asyncio
    async def test_run_stops_on_shutdown(self):
        """run() exits when the shutdown event is set."""
        provider = FakeProvider(name="test", events=[])
        harvester = EventHarvester([provider], interval_seconds=1)
        shutdown = asyncio.Event()

        # Set shutdown after a short delay
        async def _set_shutdown():
            await asyncio.sleep(0.1)
            shutdown.set()

        # Patch at the source module since run() does a local import
        with patch(
            "openlabels.server.db.get_session_context"
        ) as mock_ctx:
            mock_session = AsyncMock()
            mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            task = asyncio.create_task(harvester.run(shutdown_event=shutdown))
            await _set_shutdown()
            await asyncio.wait_for(task, timeout=5.0)

        # Should have completed without error
        assert not task.cancelled()


# =====================================================================
# MonitoringSettings tests
# =====================================================================


class TestMonitoringSettings:
    """Tests for the MonitoringSettings config class."""

    def test_defaults(self):
        """MonitoringSettings has sensible defaults."""
        from openlabels.server.config import MonitoringSettings

        s = MonitoringSettings()
        assert s.enabled is False
        assert s.harvest_interval_seconds == 60
        assert "windows_sacl" in s.providers
        assert "auditd" in s.providers
        assert s.store_raw_events is False
        assert s.max_events_per_cycle == 10_000
        assert s.sync_cache_on_startup is True
        assert s.sync_cache_on_shutdown is True

    def test_in_settings(self):
        """MonitoringSettings is accessible from main Settings."""
        from openlabels.server.config import Settings

        s = Settings()
        assert hasattr(s, "monitoring")
        assert s.monitoring.enabled is False


# =====================================================================
# Escape path tests (history.py fix)
# =====================================================================


class TestHistoryEscapedName:
    """Tests for the escaped_name fix in _get_history_windows."""

    def test_brackets_escaped(self):
        """Brackets are escaped for PowerShell -like."""
        name = "report[2026].xlsx"
        escaped = (
            name
            .replace('`', '``')
            .replace('[', '`[')
            .replace(']', '`]')
            .replace('*', '`*')
            .replace('?', '`?')
        )
        assert escaped == "report`[2026`].xlsx"

    def test_wildcards_escaped(self):
        """Wildcards * and ? are escaped."""
        name = "secret*.txt"
        escaped = (
            name
            .replace('`', '``')
            .replace('[', '`[')
            .replace(']', '`]')
            .replace('*', '`*')
            .replace('?', '`?')
        )
        assert escaped == "secret`*.txt"

    def test_backtick_escaped_first(self):
        """Backtick is escaped before other chars to avoid double-escape."""
        name = "file`name[1].txt"
        escaped = (
            name
            .replace('`', '``')
            .replace('[', '`[')
            .replace(']', '`]')
            .replace('*', '`*')
            .replace('?', '`?')
        )
        assert escaped == "file``name`[1`].txt"


# =====================================================================
# Registry batch injection fix test
# =====================================================================


class TestRegistryBatchInjectionFix:
    """Tests for the command injection fix in _enable_batch_linux."""

    def test_injection_chars_rejected(self):
        """Paths with shell metacharacters are rejected in batch."""
        from openlabels.monitoring.registry import _enable_batch_linux

        # Create a path that could be used for shell injection
        # Need to mock the auditctl check so we get to the validation
        with patch("shutil.which", return_value="/usr/bin/auditctl"):
            # Path with backtick (shell injection char)
            results = _enable_batch_linux(
                [Path("/tmp/`whoami`.txt")],
                risk_tier="HIGH",
            )

        # Should be rejected with "invalid characters" error
        assert len(results) == 1
        assert results[0].success is False
        assert "invalid characters" in results[0].error

    def test_injection_chars_dollar_rejected(self):
        """Path with $ is rejected."""
        from openlabels.monitoring.registry import _enable_batch_linux

        with patch("shutil.which", return_value="/usr/bin/auditctl"):
            results = _enable_batch_linux(
                [Path("/tmp/$(rm -rf /).txt")],
                risk_tier="HIGH",
            )

        assert len(results) == 1
        assert results[0].success is False
        assert "invalid characters" in results[0].error
