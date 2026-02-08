"""
Change provider protocol and default implementations.

A ChangeProvider yields files that should be considered for scanning.
The orchestrator then runs each file through the adapter for content
reading, the inventory service for delta checks, and the classification
agents for entity detection.

Implementations
---------------
- ``FullWalkProvider`` — lists every file via the adapter (default)

Future providers (Phases G, I, K) plug in here:
- USNChangeProvider — Windows NTFS USN journal
- FanotifyChangeProvider — Linux fanotify
- SQSChangeProvider — S3 event notifications
- PubSubChangeProvider — GCS notifications
"""

from __future__ import annotations

import logging
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
