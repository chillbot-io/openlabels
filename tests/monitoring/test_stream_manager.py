"""Tests for EventStreamManager (Phase I)."""

import asyncio
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
        """Flushing should call _persist_events."""
        manager = EventStreamManager(providers=[])
        manager._buffer = [_make_event("/test.txt")]

        manager._persist_events = AsyncMock(return_value=1)
        await manager._flush_buffer()

        manager._persist_events.assert_called_once()
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
