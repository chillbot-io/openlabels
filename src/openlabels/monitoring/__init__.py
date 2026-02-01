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
    MonitoringError,
)
from .registry import (
    enable_monitoring,
    disable_monitoring,
    is_monitored,
    get_watched_files,
)
from .history import (
    get_access_history,
)

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
    # History
    "get_access_history",
]
