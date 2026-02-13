"""
EventStreamManager — long-lived async task runner for continuous event
streams (Phase I).

Manages one or more streaming providers (USN journal, fanotify) and
performs batched database writes.  Runs alongside the existing
``EventHarvester`` which handles periodic/polling sources.

Design:
* Each streaming provider runs in its own ``asyncio.Task``.
* Events are buffered in-memory and flushed to the database either
  when the buffer reaches *batch_size* or every *flush_interval* seconds.
* Integrates with ``ScanTriggerBuffer`` to queue real-time scans.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Protocol, runtime_checkable

from openlabels.monitoring.providers.base import RawAccessEvent

logger = logging.getLogger(__name__)

# Valid action values for the DB access_action enum (shared with harvester).
_VALID_DB_ACTIONS = frozenset({
    "read", "write", "delete", "rename", "permission_change", "execute",
})



@runtime_checkable
class StreamProvider(Protocol):
    """Protocol for providers that support continuous streaming."""

    @property
    def name(self) -> str: ...

    async def stream(
        self,
        shutdown_event: asyncio.Event,
        poll_interval: float = ...,
    ):
        """Yield batches of RawAccessEvent."""
        ...




class EventStreamManager:
    """Manage long-lived event stream tasks with batched DB writes.

    Usage::

        manager = EventStreamManager(
            providers=[usn_provider, fanotify_provider],
            batch_size=500,
            flush_interval=5.0,
        )
        await manager.run(shutdown_event)
    """

    def __init__(
        self,
        providers: list[StreamProvider],
        *,
        batch_size: int = 500,
        flush_interval: float = 5.0,
        max_buffer_size: int = 50_000,
        scan_trigger: object | None = None,
        change_providers: list | None = None,
    ) -> None:
        self._providers = providers
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._max_buffer_size = max_buffer_size
        self._scan_trigger = scan_trigger
        self._change_providers = change_providers or []

        # Shared event buffer (append-only from provider tasks, drained
        # by the flush task — guarded by an asyncio.Lock)
        self._buffer: list[RawAccessEvent] = []
        self._buffer_lock = asyncio.Lock()

        # Stats
        self.total_events_received: int = 0
        self.total_events_flushed: int = 0
        self.total_flush_cycles: int = 0
        self.total_events_dropped: int = 0

    async def run(
        self,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Main entry point — runs until *shutdown_event* is set."""
        tasks: list[asyncio.Task] = []

        # Start a reader task per provider
        for provider in self._providers:
            task = asyncio.create_task(
                self._reader_loop(provider, shutdown_event),
                name=f"stream-reader-{provider.name}",
            )
            tasks.append(task)

        # Start the flush task
        flush_task = asyncio.create_task(
            self._flush_loop(shutdown_event),
            name="stream-flush",
        )
        tasks.append(flush_task)

        logger.info(
            "EventStreamManager started: %d providers, batch_size=%d, "
            "flush_interval=%.1fs",
            len(self._providers),
            self._batch_size,
            self._flush_interval,
        )

        try:
            # Wait for shutdown
            await shutdown_event.wait()
        finally:
            # Cancel all tasks
            for t in tasks:
                if not t.done():
                    t.cancel()

            # Wait for tasks to finish with timeout
            await asyncio.gather(*tasks, return_exceptions=True)

            # Final flush
            await self._flush_buffer()

            logger.info(
                "EventStreamManager stopped: received=%d, flushed=%d, "
                "dropped=%d, flush_cycles=%d",
                self.total_events_received,
                self.total_events_flushed,
                self.total_events_dropped,
                self.total_flush_cycles,
            )

    async def _reader_loop(
        self,
        provider: StreamProvider,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Read events from a streaming provider and buffer them."""
        try:
            async for batch in provider.stream(shutdown_event):
                async with self._buffer_lock:
                    # Apply back-pressure: drop oldest if buffer is full
                    headroom = self._max_buffer_size - len(self._buffer)
                    if headroom <= 0:
                        drop_count = len(batch)
                        self.total_events_dropped += drop_count
                        logger.warning(
                            "Buffer full (%d), dropping %d events from %s",
                            self._max_buffer_size,
                            drop_count,
                            provider.name,
                        )
                        continue

                    if len(batch) > headroom:
                        dropped = len(batch) - headroom
                        batch = batch[:headroom]
                        self.total_events_dropped += dropped
                        logger.warning(
                            "Buffer nearly full, dropped %d events from %s",
                            dropped,
                            provider.name,
                        )

                    self._buffer.extend(batch)
                    self.total_events_received += len(batch)

                    # Notify scan trigger and change providers (non-blocking)
                    if self._scan_trigger is not None or self._change_providers:
                        for event in batch:
                            if self._scan_trigger is not None:
                                self._scan_trigger.on_event(event)
                            for cp in self._change_providers:
                                cp.notify(event.file_path, event.action)

                # Flush immediately if buffer exceeds batch size
                if len(self._buffer) >= self._batch_size:
                    await self._flush_buffer()

        except asyncio.CancelledError:
            pass
        except Exception:  # noqa: BLE001 — catch-all for provider crash
            logger.error(
                "Stream reader for %s crashed", provider.name, exc_info=True,
            )

    async def _flush_loop(
        self,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Periodically flush the event buffer to the database."""
        try:
            while not shutdown_event.is_set():
                try:
                    await asyncio.wait_for(
                        shutdown_event.wait(),
                        timeout=self._flush_interval,
                    )
                    break  # Shutdown signalled
                except asyncio.TimeoutError:
                    pass

                await self._flush_buffer()
        except asyncio.CancelledError:
            pass

    async def _flush_buffer(self) -> None:
        """Drain the buffer and persist events to the database."""
        async with self._buffer_lock:
            if not self._buffer:
                return
            batch = list(self._buffer)
            self._buffer.clear()

        if not batch:
            return

        try:
            count = await self._persist_events(batch)
            self.total_events_flushed += count
            self.total_flush_cycles += 1

            if count > 0:
                logger.debug(
                    "Stream flush: %d events persisted (cycle %d)",
                    count,
                    self.total_flush_cycles,
                )
        except Exception:  # noqa: BLE001 — catch-all for flush resilience
            # Re-buffer events on failure (best-effort)
            async with self._buffer_lock:
                headroom = self._max_buffer_size - len(self._buffer)
                re_buffered = batch[:headroom]
                self._buffer[:0] = re_buffered
                dropped = len(batch) - len(re_buffered)
                if dropped:
                    self.total_events_dropped += dropped
            logger.error("Stream flush failed", exc_info=True)

    async def _persist_events(
        self, events: list[RawAccessEvent],
    ) -> int:
        """Write events to the database.

        Mirrors ``EventHarvester._persist_events`` — resolves monitored
        files from the DB and creates ``FileAccessEvent`` rows.
        """
        from sqlalchemy import select

        from openlabels.server.db import get_session_context
        from openlabels.server.models import FileAccessEvent, MonitoredFile

        valid_events = [e for e in events if e.action in _VALID_DB_ACTIONS]
        if not valid_events:
            return 0

        persisted = 0

        async with get_session_context() as session:
            # Batch-resolve file paths to MonitoredFile rows
            file_paths = {e.file_path for e in valid_events}
            result = await session.execute(
                select(MonitoredFile)
                .where(MonitoredFile.file_path.in_(file_paths))
                .order_by(MonitoredFile.tenant_id)
            )
            rows = result.scalars().all()
            path_to_monitored: dict[str, MonitoredFile] = {}
            for row in rows:
                if row.file_path not in path_to_monitored:
                    path_to_monitored[row.file_path] = row

            for event in valid_events:
                monitored = path_to_monitored.get(event.file_path)
                if monitored is None:
                    continue

                session.add(FileAccessEvent(
                    tenant_id=monitored.tenant_id,
                    monitored_file_id=monitored.id,
                    file_path=event.file_path,
                    action=event.action,
                    success=event.success,
                    user_sid=event.user_sid,
                    user_name=event.user_name,
                    user_domain=event.user_domain,
                    process_name=event.process_name,
                    process_id=event.process_id,
                    event_id=event.event_id,
                    event_source=event.event_source,
                    event_time=event.event_time,
                ))
                persisted += 1

                # Update monitored file stats
                monitored.access_count = (monitored.access_count or 0) + 1
                if (
                    monitored.last_event_at is None
                    or event.event_time > monitored.last_event_at
                ):
                    monitored.last_event_at = event.event_time

            await session.commit()

        return persisted


    def get_stats(self) -> dict:
        """Return current stream manager statistics."""
        return {
            "total_events_received": self.total_events_received,
            "total_events_flushed": self.total_events_flushed,
            "total_events_dropped": self.total_events_dropped,
            "total_flush_cycles": self.total_flush_cycles,
            "buffer_size": len(self._buffer),
            "providers": [p.name for p in self._providers],
        }
