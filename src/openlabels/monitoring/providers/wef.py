"""
Windows Event Forwarding (WEF) event provider.

Reads file access events from the local "ForwardedEvents" event log,
which is populated by remote file servers that push events via WEF
source-initiated subscriptions.

This is architecturally similar to ``WindowsSACLProvider`` but:
- Reads from "ForwardedEvents" instead of "Security"
- Extracts the originating computer name from the event
- Uses ``event_source="wef"`` so the harvester can distinguish them

The provider is pull-based (queries the local log) but the events
themselves are push-based (remote servers deliver them to the
collector automatically).
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from datetime import datetime
from pathlib import Path

from openlabels.monitoring.base import WINDOWS_ACCESS_MASKS, AccessAction

from .base import RawAccessEvent

logger = logging.getLogger(__name__)

EVENT_SOURCE = "wef"

# Event log to read — WEF deposits forwarded events here.
_LOG_NAME = "ForwardedEvents"


class WEFProvider:
    """Collect file access events from the ForwardedEvents log.

    Events are pushed to this log by remote file servers via Windows
    Event Forwarding.  This provider reads them locally using
    ``wevtutil`` — no remote connections needed.

    Parameters
    ----------
    watched_paths:
        If provided, only events touching these file paths are returned.
    """

    def __init__(self, watched_paths: list[str] | None = None) -> None:
        self._watched_paths = watched_paths

    @property
    def name(self) -> str:
        return EVENT_SOURCE

    async def collect(self, since: datetime | None = None) -> list[RawAccessEvent]:
        """Read forwarded file access events from the local event log."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self._collect_sync(since),
        )

    def _collect_sync(self, since: datetime | None) -> list[RawAccessEvent]:
        """Synchronous collection via wevtutil (runs in executor)."""
        time_filter = ""
        if since:
            iso = since.strftime("%Y-%m-%dT%H:%M:%S")
            time_filter = f" and TimeCreated[@SystemTime>='{iso}']"

        query = f"*[System[(EventID=4663 or EventID=4656){time_filter}]]"
        cmd = ["wevtutil", "qe", _LOG_NAME, "/q:" + query, "/f:text"]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
            )
        except FileNotFoundError:
            logger.debug("wevtutil not found — WEF provider requires Windows")
            return []
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.warning("wevtutil query on %s failed: %s", _LOG_NAME, e)
            return []

        if proc.returncode != 0:
            # Empty log returns non-zero; only warn on unexpected errors
            if "no events" not in proc.stderr.lower() and proc.stderr.strip():
                logger.debug(
                    "wevtutil qe %s returned %d: %s",
                    _LOG_NAME, proc.returncode, proc.stderr.strip(),
                )
            return []

        return self._parse_text_output(proc.stdout)

    def _parse_text_output(self, output: str) -> list[RawAccessEvent]:
        """Parse wevtutil /f:text output into RawAccessEvent instances.

        Forwarded events include a "Computer:" field identifying the
        source machine that generated the event.
        """
        events: list[RawAccessEvent] = []
        current: dict[str, str] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                if current:
                    ev = self._parse_event(current)
                    if ev:
                        events.append(ev)
                    current = {}
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                current[key.strip()] = value.strip()

        # Last event
        if current:
            ev = self._parse_event(current)
            if ev:
                events.append(ev)

        return events

    def _parse_event(self, fields: dict[str, str]) -> RawAccessEvent | None:
        """Convert wevtutil text fields to a RawAccessEvent."""
        object_name = fields.get("Object Name", "")
        if not object_name:
            return None

        # Path filtering
        if self._watched_paths and object_name not in self._watched_paths:
            return None

        # Action from access mask
        action = "read"
        mask_str = fields.get("Access Mask", "")
        if mask_str:
            try:
                mask = int(mask_str, 0)
                for bit, act in WINDOWS_ACCESS_MASKS.items():
                    if mask & bit:
                        action = act.value
                        break
            except ValueError:
                pass

        # Timestamp
        try:
            ts = datetime.fromisoformat(fields.get("Date", ""))
        except (ValueError, TypeError):
            ts = datetime.now()

        # Source computer (populated by WEF for forwarded events)
        source_computer = fields.get("Computer", "")

        return RawAccessEvent(
            file_path=object_name,
            event_time=ts,
            action=action,
            event_source=f"{EVENT_SOURCE}:{source_computer}" if source_computer else EVENT_SOURCE,
            user_sid=fields.get("Security ID"),
            user_name=fields.get("Account Name"),
            user_domain=fields.get("Account Domain"),
            process_name=fields.get("Process Name"),
            process_id=int(fields["Process ID"]) if fields.get("Process ID", "").isdigit() else None,
            event_id=int(fields["Event ID"]) if fields.get("Event ID", "").isdigit() else None,
            success=True,
            raw={**fields, "_source_computer": source_computer} if source_computer else dict(fields),
        )

    @staticmethod
    def is_available() -> bool:
        """Check if WEF is available (Windows with wevtutil + ForwardedEvents log)."""
        import platform
        if platform.system() != "Windows":
            return False
        try:
            proc = subprocess.run(
                ["wevtutil", "gl", _LOG_NAME],
                capture_output=True, text=True, timeout=5,
            )
            return proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False
