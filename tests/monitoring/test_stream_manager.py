"""Tests for EventStreamManager (Phase I)."""

import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openlabels.monitoring.providers.base import RawAccessEvent
from openlabels.monitoring.stream_manager import EventStreamManager


def _make_event(path: str = "/test/file.txt", action: str = "write") -> RawAccessEvent:
    return RawAccessEvent(
        file_path=path,
        event_time=datetime.now(timezone.utc),
        action=action,
        event_source="test",
    )


class _MockStreamProvider:
    """Mock streaming provider for testing."""

    def __init__(self, batches: list[list[RawAccessEvent]] | None = None):
        self._batches = batches or []
        self._name = "mock_stream"

    @property
    def name(self) -> str:
        return self._name

    async def stream(self, shutdown_event, poll_interval=0.1):
        for batch in self._batches:
            if shutdown_event.is_set():
                break
            yield batch
            await asyncio.sleep(0.01)


class TestEventStreamManagerInit:
    """Tests for EventStreamManager initialization."""

    def test_default_settings(self):
        manager = EventStreamManager(providers=[])
        assert manager._batch_size == 500
        assert manager._flush_interval == 5.0
        assert manager._max_buffer_size == 50_000
        assert manager.total_events_received == 0
        assert manager.total_events_flushed == 0

    def test_custom_settings(self):
        manager = EventStreamManager(
            providers=[],
            batch_size=100,
            flush_interval=1.0,
            max_buffer_size=1000,
        )
        assert manager._batch_size == 100
        assert manager._flush_interval == 1.0
        assert manager._max_buffer_size == 1000


class TestEventStreamManagerBuffer:
    """Tests for buffering and back-pressure."""

    @pytest.mark.asyncio
    async def test_events_buffered_from_provider(self):
        events = [_make_event(f"/test/{i}.txt") for i in range(5)]
        provider = _MockStreamProvider(batches=[events])

        manager = EventStreamManager(
            providers=[provider],
            batch_size=1000,
            flush_interval=10.0,
        )

        shutdown = asyncio.Event()

        async def stop_after_delay():
            await asyncio.sleep(0.2)
            shutdown.set()

        # Patch _persist_events to avoid DB access
        manager._persist_events = AsyncMock(return_value=0)

        task = asyncio.create_task(manager.run(shutdown))
        await stop_after_delay()
        await task

        assert manager.total_events_received == 5

    @pytest.mark.asyncio
    async def test_back_pressure_drops_events(self):
        """Events should be dropped when buffer is full."""
        events = [_make_event(f"/test/{i}.txt") for i in range(10)]
        provider = _MockStreamProvider(batches=[events])

        manager = EventStreamManager(
            providers=[provider],
            batch_size=1000,
            flush_interval=10.0,
            max_buffer_size=5,
        )

        shutdown = asyncio.Event()

        async def stop_after_delay():
            await asyncio.sleep(0.2)
            shutdown.set()

        manager._persist_events = AsyncMock(return_value=0)

        task = asyncio.create_task(manager.run(shutdown))
        await stop_after_delay()
        await task

        assert manager.total_events_dropped > 0

    @pytest.mark.asyncio
    async def test_multiple_providers(self):
        """Events from multiple providers should be combined."""
        p1 = _MockStreamProvider(batches=[[_make_event("/a.txt")]])
        p1._name = "provider_1"
        p2 = _MockStreamProvider(batches=[[_make_event("/b.txt")]])
        p2._name = "provider_2"

        manager = EventStreamManager(
            providers=[p1, p2],
            batch_size=1000,
            flush_interval=10.0,
        )

        shutdown = asyncio.Event()

        async def stop_after_delay():
            await asyncio.sleep(0.2)
            shutdown.set()

        manager._persist_events = AsyncMock(return_value=0)

        task = asyncio.create_task(manager.run(shutdown))
        await stop_after_delay()
        await task

        assert manager.total_events_received == 2


class TestEventStreamManagerStats:
    """Tests for stats reporting."""

    def test_get_stats(self):
        p = _MockStreamProvider()
        manager = EventStreamManager(providers=[p])
        stats = manager.get_stats()
        assert stats["total_events_received"] == 0
        assert stats["total_events_flushed"] == 0
        assert stats["total_events_dropped"] == 0
        assert stats["buffer_size"] == 0
        assert stats["providers"] == ["mock_stream"]

    @pytest.mark.asyncio
    async def test_flush_calls_persist(self):
        """Flushing should call _persist_events with the buffer contents."""
        event = _make_event("/test.txt")
        manager = EventStreamManager(providers=[])
        manager._buffer = [event]

        manager._persist_events = AsyncMock(return_value=1)
        await manager._flush_buffer()

        manager._persist_events.assert_called_once()
        # Verify the correct events were passed to _persist_events
        persisted_events = manager._persist_events.call_args[0][0]
        assert len(persisted_events) == 1
        assert persisted_events[0].file_path == "/test.txt"
        # Buffer should be cleared after flush
        assert len(manager._buffer) == 0
        assert manager.total_events_flushed == 1
        assert manager.total_flush_cycles == 1

    @pytest.mark.asyncio
    async def test_flush_empty_buffer_noop(self):
        """Flushing an empty buffer should be a no-op."""
        manager = EventStreamManager(providers=[])
        manager._persist_events = AsyncMock(return_value=0)

        await manager._flush_buffer()

        manager._persist_events.assert_not_called()
        assert manager.total_flush_cycles == 0


class TestEventStreamManagerScanTrigger:
    """Tests for scan trigger integration."""

    @pytest.mark.asyncio
    async def test_scan_trigger_called_on_events(self):
        events = [_make_event("/important.docx")]
        provider = _MockStreamProvider(batches=[events])

        mock_trigger = MagicMock()
        mock_trigger.on_event = MagicMock()

        manager = EventStreamManager(
            providers=[provider],
            batch_size=1000,
            flush_interval=10.0,
            scan_trigger=mock_trigger,
        )

        shutdown = asyncio.Event()

        async def stop_after_delay():
            await asyncio.sleep(0.2)
            shutdown.set()

        manager._persist_events = AsyncMock(return_value=0)

        task = asyncio.create_task(manager.run(shutdown))
        await stop_after_delay()
        await task

        mock_trigger.on_event.assert_called_once()
        # Verify the correct event was passed to the scan trigger
        passed_event = mock_trigger.on_event.call_args[0][0]
        assert passed_event.file_path == "/important.docx"
        assert passed_event.action == "write"

    @pytest.mark.asyncio
    async def test_change_providers_notified_on_events(self):
        events = [_make_event("/changed.docx", action="write")]
        provider = _MockStreamProvider(batches=[events])

        mock_cp = MagicMock()
        mock_cp.notify = MagicMock()

        manager = EventStreamManager(
            providers=[provider],
            batch_size=1000,
            flush_interval=10.0,
            change_providers=[mock_cp],
        )

        shutdown = asyncio.Event()

        async def stop_after_delay():
            await asyncio.sleep(0.2)
            shutdown.set()

        manager._persist_events = AsyncMock(return_value=0)

        task = asyncio.create_task(manager.run(shutdown))
        await stop_after_delay()
        await task

        mock_cp.notify.assert_called_once_with("/changed.docx", "write")


class _AsyncContextManagerMock:
    """Helper that creates a mock async context manager yielding a session."""

    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *args):
        return False


class TestMultiTenantEventRouting:
    """Tests that events are persisted for ALL tenants monitoring a path.

    Validates fix for H-B12: previously only the first tenant per path
    received events; subsequent tenants were silently dropped.
    """

    def _make_monitored_file(
        self,
        file_path: str,
        tenant_id: uuid.UUID | None = None,
        file_id: uuid.UUID | None = None,
    ) -> MagicMock:
        """Create a mock MonitoredFile row."""
        mf = MagicMock()
        mf.id = file_id or uuid.uuid4()
        mf.tenant_id = tenant_id or uuid.uuid4()
        mf.file_path = file_path
        mf.access_count = 0
        mf.last_event_at = None
        return mf

    def _mock_persist_deps(self, mock_session):
        """Create a patch context for all _persist_events dependencies."""
        mock_select = MagicMock()
        mock_select.return_value.where.return_value.order_by.return_value = "query"

        return {
            "select": patch("openlabels.server.db.get_session_context",
                            return_value=_AsyncContextManagerMock(mock_session)),
            "models": patch.dict("sys.modules", {}),
        }

    @pytest.mark.asyncio
    async def test_multiple_tenants_same_path_all_receive_events(self):
        """When two tenants monitor the same path, both should get events."""
        tenant_a = uuid.uuid4()
        tenant_b = uuid.uuid4()
        shared_path = "/shared/report.xlsx"

        mf_a = self._make_monitored_file(shared_path, tenant_id=tenant_a)
        mf_b = self._make_monitored_file(shared_path, tenant_id=tenant_b)

        event = _make_event(shared_path, action="write")

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mf_a, mf_b]
        mock_session.execute.return_value = mock_result
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        manager = EventStreamManager(providers=[])

        with patch(
            "openlabels.server.db.get_session_context",
            return_value=_AsyncContextManagerMock(mock_session),
        ):
            count = await manager._persist_events([event])

        # Both tenants should get an event
        assert count == 2
        assert mock_session.add.call_count == 2

    @pytest.mark.asyncio
    async def test_three_tenants_same_path_all_receive_events(self):
        """Three tenants monitoring the same path should all get events."""
        tenants = [uuid.uuid4() for _ in range(3)]
        path = "/shared/data.csv"

        monitored_files = [
            self._make_monitored_file(path, tenant_id=tid) for tid in tenants
        ]

        event = _make_event(path, action="read")

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = monitored_files
        mock_session.execute.return_value = mock_result
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        manager = EventStreamManager(providers=[])

        with patch(
            "openlabels.server.db.get_session_context",
            return_value=_AsyncContextManagerMock(mock_session),
        ):
            count = await manager._persist_events([event])

        assert count == 3
        assert mock_session.add.call_count == 3

    @pytest.mark.asyncio
    async def test_different_paths_different_tenants(self):
        """Different tenants monitoring different paths should each get their events."""
        tenant_a = uuid.uuid4()
        tenant_b = uuid.uuid4()

        mf_a = self._make_monitored_file("/path/a.txt", tenant_id=tenant_a)
        mf_b = self._make_monitored_file("/path/b.txt", tenant_id=tenant_b)

        event_a = _make_event("/path/a.txt", action="write")
        event_b = _make_event("/path/b.txt", action="read")

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mf_a, mf_b]
        mock_session.execute.return_value = mock_result
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        manager = EventStreamManager(providers=[])

        with patch(
            "openlabels.server.db.get_session_context",
            return_value=_AsyncContextManagerMock(mock_session),
        ):
            count = await manager._persist_events([event_a, event_b])

        assert count == 2
        assert mock_session.add.call_count == 2

    @pytest.mark.asyncio
    async def test_unmonitored_path_skipped(self):
        """Events for paths with no MonitoredFile rows should be skipped."""
        event = _make_event("/unmonitored/file.txt", action="write")

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        manager = EventStreamManager(providers=[])

        with patch(
            "openlabels.server.db.get_session_context",
            return_value=_AsyncContextManagerMock(mock_session),
        ):
            count = await manager._persist_events([event])

        assert count == 0
        mock_session.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_monitored_file_stats_updated_for_each_tenant(self):
        """access_count and last_event_at should be updated for all tenants."""
        tenant_a = uuid.uuid4()
        tenant_b = uuid.uuid4()
        path = "/shared/file.xlsx"

        mf_a = self._make_monitored_file(path, tenant_id=tenant_a)
        mf_a.access_count = 5
        mf_a.last_event_at = None

        mf_b = self._make_monitored_file(path, tenant_id=tenant_b)
        mf_b.access_count = 10
        mf_b.last_event_at = None

        event = _make_event(path, action="write")

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mf_a, mf_b]
        mock_session.execute.return_value = mock_result
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        manager = EventStreamManager(providers=[])

        with patch(
            "openlabels.server.db.get_session_context",
            return_value=_AsyncContextManagerMock(mock_session),
        ):
            await manager._persist_events([event])

        # Both monitored files should have updated stats
        assert mf_a.access_count == 6
        assert mf_b.access_count == 11
        assert mf_a.last_event_at is not None
        assert mf_b.last_event_at is not None

    @pytest.mark.asyncio
    async def test_invalid_action_events_filtered_out(self):
        """Events with invalid actions should not be persisted."""
        event = RawAccessEvent(
            file_path="/test/file.txt",
            event_time=datetime.now(timezone.utc),
            action="invalid_action",
            event_source="test",
        )

        manager = EventStreamManager(providers=[])

        mock_session = AsyncMock()
        mock_session.commit = AsyncMock()

        with patch(
            "openlabels.server.db.get_session_context",
            return_value=_AsyncContextManagerMock(mock_session),
        ):
            count = await manager._persist_events([event])

        assert count == 0
