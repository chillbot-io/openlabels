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

import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


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

    user_sid: str | None = None
    user_name: str | None = None
    user_domain: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    event_id: int | None = None
    success: bool = True
    raw: dict | None = field(default=None, hash=False, compare=False)


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

    async def collect(self, since: datetime | None = None) -> list[RawAccessEvent]:
        """Return events that occurred after *since*."""
        ...


async def poll_events(
    read_fn: Callable[[], list[RawAccessEvent]],
    shutdown_event: asyncio.Event,
    provider_name: str,
    poll_interval: float = 0.5,
) -> AsyncIterator[list[RawAccessEvent]]:
    """Shared polling loop for event providers.

    Runs *read_fn* (a synchronous callable) in the default executor
    every *poll_interval* seconds, yielding non-empty batches, until
    *shutdown_event* is set.
    """
    loop = asyncio.get_running_loop()
    while not shutdown_event.is_set():
        try:
            events = await loop.run_in_executor(None, read_fn)
            if events:
                yield events
        except Exception:
            logger.warning("%s stream read failed", provider_name, exc_info=True)

        try:
            await asyncio.wait_for(
                shutdown_event.wait(), timeout=poll_interval,
            )
            break
        except asyncio.TimeoutError:
            pass
