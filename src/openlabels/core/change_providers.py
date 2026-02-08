"""
Change provider protocol and default implementations.

A ChangeProvider yields files that should be considered for scanning.
The orchestrator then runs each file through the adapter for content
reading, the inventory service for delta checks, and the classification
agents for entity detection.

Implementations
---------------
- ``FullWalkProvider`` — lists every file via the adapter (default)
- ``USNChangeProvider`` — Windows NTFS USN journal (Phase I)
- ``FanotifyChangeProvider`` — Linux fanotify (Phase I)

Future providers (Phases K, L) plug in here:
- SQSChangeProvider — S3 event notifications
- PubSubChangeProvider — GCS notifications
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import AsyncIterator, Optional, Protocol, runtime_checkable

from openlabels.adapters.base import FileInfo, FilterConfig, ReadAdapter

logger = logging.getLogger(__name__)


@runtime_checkable
class ChangeProvider(Protocol):
    """Yields files that *may* need scanning.

    The orchestrator still runs delta checks (inventory.should_scan_file)
    on each file, so a provider that is overly inclusive is safe — just
    slower.
    """

    async def changed_files(self) -> AsyncIterator[FileInfo]:
        """Yield files that may need scanning."""
        ...


class FullWalkProvider:
    """Default provider: list every file via the adapter.

    This is equivalent to the current behaviour of
    ``ScanOrchestrator._walk_files()`` and ``execute_scan_task()``.

    Parameters
    ----------
    adapter:
        A ReadAdapter (filesystem, sharepoint, onedrive, …).
    target:
        Path / site_id / URL handed to ``adapter.list_files()``.
    recursive:
        Walk subdirectories.
    filter_config:
        Optional filter for extensions, paths, size limits, etc.
    """

    def __init__(
        self,
        adapter: ReadAdapter,
        target: str,
        *,
        recursive: bool = True,
        filter_config: Optional[FilterConfig] = None,
    ) -> None:
        self._adapter = adapter
        self._target = target
        self._recursive = recursive
        self._filter_config = filter_config

    async def changed_files(self) -> AsyncIterator[FileInfo]:
        """Yield every file the adapter exposes."""
        async for file_info in self._adapter.list_files(
            self._target,
            recursive=self._recursive,
            filter_config=self._filter_config,
        ):
            yield file_info


# ── Real-time change providers (Phase I) ─────────────────────────────


class _StreamChangeProvider:
    """Base for change providers backed by a streaming event source.

    Buffers file-change events and yields them as ``FileInfo`` objects
    when ``changed_files()`` is called by the scan orchestrator.
    """

    def __init__(self) -> None:
        self._changed: dict[str, tuple[datetime, str]] = {}
        self._lock = asyncio.Lock()

    def notify(self, file_path: str, change_type: str = "modified") -> None:
        """Record a file change (called from EventStreamManager)."""
        self._changed[file_path] = (datetime.now(timezone.utc), change_type)

    async def changed_files(self) -> AsyncIterator[FileInfo]:
        """Yield files that changed since the last call, then clear."""
        async with self._lock:
            snapshot = dict(self._changed)
            self._changed.clear()

        for path, (modified, change_type) in snapshot.items():
            from pathlib import Path as _Path

            p = _Path(path)
            try:
                stat = p.stat()
                size = stat.st_size
            except OSError:
                size = 0

            yield FileInfo(
                path=path,
                name=p.name,
                size=size,
                modified=modified,
                change_type=change_type,
            )


class USNChangeProvider(_StreamChangeProvider):
    """Adapts USN journal events as a ``ChangeProvider`` for the scan pipeline.

    Wire to an ``EventStreamManager`` or ``USNJournalProvider`` that
    calls ``notify(file_path)`` on each relevant event.
    """

    pass


class FanotifyChangeProvider(_StreamChangeProvider):
    """Adapts fanotify events as a ``ChangeProvider`` for the scan pipeline.

    Wire to an ``EventStreamManager`` or ``FanotifyProvider`` that
    calls ``notify(file_path)`` on each relevant event.
    """

    pass
