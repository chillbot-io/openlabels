"""
OpenLabels Agent.

On-premises file system scanning and monitoring agent.

The agent provides:
- Local file system metadata collection (NTFS ACLs, POSIX permissions)
- Real-time file system monitoring
- Background scanning with priority queuing
- Integration with the OpenLabels scoring engine

Components:
- collector: Metadata collection from local files
- posix: Linux/macOS permission handling
- ntfs: Windows ACL handling (when on Windows)
- watcher: File system change monitoring

Example:
    >>> from openlabels.agent import FileCollector, start_watcher
    >>>
    >>> # Collect metadata for a file
    >>> collector = FileCollector()
    >>> metadata = collector.collect("/path/to/file.pdf")
    >>> print(f"Exposure: {metadata.exposure}")
    >>>
    >>> # Start watching a directory
    >>> watcher = start_watcher("/data", on_change=handle_change)
    >>> watcher.stop()
"""

from .collector import (
    FileCollector,
    FileMetadata,
    collect_metadata,
    collect_directory,
)

from .posix import (
    get_posix_permissions,
    posix_mode_to_exposure,
    get_owner_info,
)

from .watcher import (
    FileWatcher,
    WatchEvent,
    EventType,
    start_watcher,
    watch_directory,
)

__all__ = [
    # Collector
    "FileCollector",
    "FileMetadata",
    "collect_metadata",
    "collect_directory",
    # POSIX
    "get_posix_permissions",
    "posix_mode_to_exposure",
    "get_owner_info",
    # Watcher
    "FileWatcher",
    "WatchEvent",
    "EventType",
    "start_watcher",
    "watch_directory",
]
