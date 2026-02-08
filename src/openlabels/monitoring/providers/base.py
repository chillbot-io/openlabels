"""
EventProvider protocol and RawAccessEvent dataclass.

These are the foundational types for the event harvesting pipeline:

    audit source  →  EventProvider.collect()  →  RawAccessEvent  →  EventHarvester  →  FileAccessEvent (DB)

``RawAccessEvent`` is an intermediate representation that decouples the
provider from the database model.  The harvester maps it to a
``FileAccessEvent`` ORM instance for persistence.

The ``EventProvider`` protocol is **async**.  All providers — whether
they call synchronous subprocesses (Windows SACL, Linux auditd) or
async HTTP APIs (M365 audit, Graph webhooks) — present the same
``async def collect()`` interface.  Sync providers wrap their blocking
I/O in ``asyncio.get_running_loop().run_in_executor()`` internally,
keeping the harvester simple and uniform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Protocol, runtime_checkable


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
    """Collects raw access events from an audit subsystem.

    The protocol is async so that all providers — sync OS tools and
    async HTTP APIs alike — present a uniform interface.  Providers
    that wrap synchronous I/O (subprocess calls to ``wevtutil`` or
    ``ausearch``) should run the blocking work inside
    ``asyncio.get_running_loop().run_in_executor()``.

    The ``since`` parameter is the exclusive lower bound: only events
    *after* this timestamp should be returned.  The provider may use
    it to build more efficient queries.  Passing ``None`` means
    "return all available events".
    """

    @property
    def name(self) -> str:
        """Short identifier for this provider (e.g. ``"windows_sacl"``)."""
        ...

    async def collect(self, since: Optional[datetime] = None) -> list[RawAccessEvent]:
        """Return events that occurred after *since*."""
        ...
