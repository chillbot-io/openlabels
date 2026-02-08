"""
Targeted monitoring for sensitive files.

Provides access monitoring for files that have been identified as sensitive.
Unlike full-scope monitoring solutions, OpenLabels only monitors files that
have been explicitly registered, dramatically reducing event volume.

Usage:
    from openlabels.monitoring import enable_monitoring, get_access_history

    # Register a sensitive file for monitoring
    enable_monitoring(
        path=Path("/data/sensitive.xlsx"),
        risk_tier="CRITICAL",
    )

    # Later: see who accessed it
    events = get_access_history(
        path=Path("/data/sensitive.xlsx"),
        days=30,
    )
    for event in events:
        print(f"{event.user} accessed at {event.timestamp}")
"""

from .base import (
    AccessEvent,
    WatchedFile,
    MonitoringResult,
)
from openlabels.exceptions import MonitoringError
from .registry import (
    enable_monitoring,
    disable_monitoring,
    enable_monitoring_async,
    disable_monitoring_async,
    enable_monitoring_batch,
    is_monitored,
    get_watched_files,
    populate_cache_from_db,
    sync_cache_to_db,
)
from .collector import EventCollector
from .history import (
    get_access_history,
)
from . import db  # noqa: F401 – async DB persistence helpers
from .providers.base import EventProvider, RawAccessEvent
from .harvester import EventHarvester

__all__ = [
    # Types
    "AccessEvent",
    "WatchedFile",
    "MonitoringResult",
    # Errors
    "MonitoringError",
    # Registry
    "enable_monitoring",
    "disable_monitoring",
    "is_monitored",
    "get_watched_files",
    # Registry – async DB integration
    "enable_monitoring_async",
    "disable_monitoring_async",
    "populate_cache_from_db",
    "sync_cache_to_db",
    "db",
    # Bulk
    "enable_monitoring_batch",
    # Event collection
    "EventCollector",
    # History
    "get_access_history",
    # Providers (Phase G)
    "EventProvider",
    "RawAccessEvent",
    # Harvester (Phase G)
    "EventHarvester",
]
