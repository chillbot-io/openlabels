"""
EventProvider protocol and RawAccessEvent dataclass.

These are the foundational types for the event harvesting pipeline:

    OS audit log  →  EventProvider.collect()  →  RawAccessEvent  →  EventHarvester  →  FileAccessEvent (DB)

``RawAccessEvent`` is an intermediate representation that decouples the
provider from the database model.  The harvester maps it to a
``FileAccessEvent`` ORM instance for persistence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Optional, Protocol, runtime_checkable


@dataclass(frozen=True)
class RawAccessEvent:
    """A single file-access event collected from an OS audit subsystem.

    This is a provider-neutral intermediate representation.  The
    ``EventHarvester`` converts each instance into a
    ``FileAccessEvent`` database row.

    Attributes
    ----------
    file_path:
        Absolute path of the accessed file.
    event_time:
        When the access occurred (from the OS event).
    action:
        One of the ``AccessAction`` enum values as a string:
        ``"read"``, ``"write"``, ``"delete"``, ``"rename"``,
        ``"permission_change"``, ``"unknown"``.
    event_source:
        Identifies the provider that produced this event
        (e.g. ``"windows_sacl"``, ``"auditd"``).
    user_sid:
        Windows SID or Linux UID.
    user_name:
        Resolved username.
    user_domain:
        Windows domain (None on Linux).
    process_name:
        Executable that performed the access.
    process_id:
        PID of the accessing process.
    event_id:
        Windows Event ID or auditd serial number.
    success:
        Whether the access succeeded.
    raw:
        Optional dict of the raw event data (for debugging /
        ``FileAccessEvent.raw_event``).
    """

    file_path: str
    event_time: datetime
    action: str  # AccessAction.value
    event_source: str

    user_sid: Optional[str] = None
    user_name: Optional[str] = None
    user_domain: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    event_id: Optional[int] = None
    success: bool = True
    raw: Optional[dict] = field(default=None, hash=False, compare=False)


@runtime_checkable
class EventProvider(Protocol):
    """Yields raw access events from an OS audit subsystem.

    Implementations must be synchronous iterators because the
    underlying OS tools (``wevtutil``, ``ausearch``) are synchronous
    subprocess calls.  The harvester runs them in a thread executor.

    The ``since`` parameter is the exclusive lower bound: only events
    *after* this timestamp should be yielded.  The provider may use
    it to build more efficient queries.  Passing ``None`` means
    "return all available events".
    """

    @property
    def name(self) -> str:
        """Short identifier for this provider (e.g. ``"windows_sacl"``)."""
        ...

    def collect(self, since: Optional[datetime] = None) -> Iterator[RawAccessEvent]:
        """Yield events that occurred after *since*."""
        ...
