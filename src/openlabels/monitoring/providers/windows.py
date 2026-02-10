"""
Windows SACL event provider.

Wraps :class:`~openlabels.monitoring.collector.EventCollector` (Windows
path) behind the :class:`EventProvider` protocol, converting each
``AccessEvent`` into a ``RawAccessEvent``.

The synchronous subprocess call (``wevtutil``) is run in a thread
executor so that the async ``collect()`` interface is non-blocking.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from openlabels.monitoring.base import AccessEvent
from openlabels.monitoring.collector import EventCollector

from .base import RawAccessEvent

logger = logging.getLogger(__name__)

EVENT_SOURCE = "windows_sacl"


class WindowsSACLProvider:
    """Collect file-access events from the Windows Security Event Log.

    Delegates to ``EventCollector._collect_windows()`` and converts
    each ``AccessEvent`` to a ``RawAccessEvent``.

    Parameters
    ----------
    watched_paths:
        If provided, only events touching these paths are returned.
        Passed through to ``EventCollector.collect_events(paths=...)``.
    """

    def __init__(
        self,
        watched_paths: Optional[list[str]] = None,
    ) -> None:
        self._collector = EventCollector()
        self._watched_paths = watched_paths

    @property
    def name(self) -> str:
        return EVENT_SOURCE

    async def collect(self, since: Optional[datetime] = None) -> list[RawAccessEvent]:
        """Collect events from the Windows Security Event Log.

        The underlying ``wevtutil`` subprocess is blocking, so the
        work is dispatched to a thread executor.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self._collect_sync(since),
        )

    def _collect_sync(self, since: Optional[datetime] = None) -> list[RawAccessEvent]:
        """Synchronous collection — runs in a thread executor."""
        try:
            return [
                _access_event_to_raw(event)
                for event in self._collector.collect_events(
                    since=since,
                    paths=self._watched_paths,
                )
            ]
        except Exception:
            logger.exception("WindowsSACLProvider.collect() failed")
            return []

    def update_watched_paths(self, paths: list[str]) -> None:
        """Update the set of watched paths (called by harvester on refresh)."""
        self._watched_paths = paths


def _access_event_to_raw(event: AccessEvent) -> RawAccessEvent:
    """Convert a monitoring.base.AccessEvent to a RawAccessEvent."""
    return RawAccessEvent(
        file_path=str(event.path),
        event_time=event.timestamp,
        action=event.action.value,
        event_source=EVENT_SOURCE,
        user_sid=event.user_sid,
        user_name=event.user_name,
        user_domain=event.user_domain,
        process_name=event.process_name,
        process_id=event.process_id,
        event_id=event.event_id,
        success=event.success,
        raw=event.to_dict(),
    )
