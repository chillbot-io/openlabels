"""Collect file access events from OS audit subsystems.

Windows: queries the Security Event Log for SACL-triggered events
(Event IDs 4663/4656) via ``wevtutil``.

Linux: queries auditd logs via ``ausearch`` for rules keyed with
``openlabels``.
"""

import logging
import platform
import subprocess
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from .base import WINDOWS_ACCESS_MASKS, AccessAction, AccessEvent

logger = logging.getLogger(__name__)


class EventCollector:
    """Collect file access events from the OS audit subsystem."""

    def collect_events(
        self,
        since: datetime | None = None,
        paths: list[str] | None = None,
    ) -> Iterator[AccessEvent]:
        """Yield access events, optionally filtered by time and paths.

        Args:
            since: Only return events after this timestamp.
            paths: If provided, only return events for these file paths.
        """
        if platform.system() == "Windows":
            yield from self._collect_windows(since, paths)
        else:
            yield from self._collect_linux(since, paths)

    # ------------------------------------------------------------------
    # Windows
    # ------------------------------------------------------------------

    def _collect_windows(
        self,
        since: datetime | None,
        paths: list[str] | None,
    ) -> Iterator[AccessEvent]:
        """Query Windows Security Event Log for file access events.

        Uses ``wevtutil`` to query Event IDs 4663 (object access attempt)
        and 4656 (handle requested).  Output is line-based text that we
        parse with simple regex.
        """
        time_filter = ""
        if since:
            iso = since.strftime("%Y-%m-%dT%H:%M:%S")
            time_filter = f" and TimeCreated[@SystemTime>='{iso}']"

        query = (
            f"*[System[(EventID=4663 or EventID=4656){time_filter}]]"
        )
        cmd = ["wevtutil", "qe", "Security", "/q:" + query, "/f:text"]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            logger.warning("wevtutil query failed: %s", e)
            return

        # Parse text output into events
        current: dict = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                if current:
                    event = self._parse_windows_event(current)
                    if event and (not paths or str(event.path) in paths):
                        yield event
                    current = {}
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                current[key.strip()] = value.strip()

        # Last event
        if current:
            event = self._parse_windows_event(current)
            if event and (not paths or str(event.path) in paths):
                yield event

    @staticmethod
    def _parse_windows_event(fields: dict) -> AccessEvent | None:
        """Convert wevtutil text fields into an AccessEvent."""
        object_name = fields.get("Object Name", "")
        if not object_name:
            return None

        # Determine action from access mask
        action = AccessAction.UNKNOWN
        mask_str = fields.get("Access Mask", "")
        if mask_str:
            try:
                mask = int(mask_str, 0)
                for bit, act in WINDOWS_ACCESS_MASKS.items():
                    if mask & bit:
                        action = act
                        break
            except ValueError:
                pass

        try:
            ts = datetime.fromisoformat(fields.get("Date", ""))
        except (ValueError, TypeError):
            ts = datetime.now()

        return AccessEvent(
            path=Path(object_name),
            timestamp=ts,
            action=action,
            user_sid=fields.get("Security ID"),
            user_name=fields.get("Account Name"),
            user_domain=fields.get("Account Domain"),
            process_name=fields.get("Process Name"),
            process_id=int(fields["Process ID"]) if fields.get("Process ID", "").isdigit() else None,
            event_id=int(fields["Event ID"]) if fields.get("Event ID", "").isdigit() else None,
        )

    # ------------------------------------------------------------------
    # Linux
    # ------------------------------------------------------------------

    def _collect_linux(
        self,
        since: datetime | None,
        paths: list[str] | None,
    ) -> Iterator[AccessEvent]:
        """Query auditd logs via ``ausearch``."""
        cmd = ["ausearch", "-k", "openlabels", "--format", "csv"]
        if since:
            cmd.extend(["--start", since.strftime("%m/%d/%Y %H:%M:%S")])

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            logger.warning("ausearch query failed: %s", e)
            return

        if proc.returncode != 0:
            logger.debug("ausearch returned %d: %s", proc.returncode, proc.stderr)
            return

        # ausearch --format csv: columns vary by version.  We look for
        # common fields: NODE,TYPE,TIME,SERIAL,FILE,SYSCALL,UID,…
        lines = proc.stdout.strip().splitlines()
        if len(lines) < 2:
            return

        header = lines[0].lower().split(",")
        col = {name: idx for idx, name in enumerate(header)}

        for row in lines[1:]:
            cols = row.split(",")
            event = self._parse_linux_row(cols, col, paths)
            if event:
                yield event

    @staticmethod
    def _parse_linux_row(
        cols: list,
        col: dict,
        paths: list[str] | None,
    ) -> AccessEvent | None:
        """Parse a single ausearch CSV row into an AccessEvent."""
        def _get(name: str) -> str:
            idx = col.get(name)
            if idx is not None and idx < len(cols):
                return cols[idx].strip().strip('"')
            return ""

        file_path = _get("file") or _get("name")
        if not file_path:
            return None

        if paths and file_path not in paths:
            return None

        # Parse timestamp
        time_str = _get("time")
        try:
            ts = datetime.fromisoformat(time_str)
        except (ValueError, TypeError):
            ts = datetime.now()

        # Determine action from syscall name
        syscall = _get("syscall").lower()
        if "read" in syscall or "open" in syscall:
            action = AccessAction.READ
        elif "write" in syscall or "truncate" in syscall:
            action = AccessAction.WRITE
        elif "unlink" in syscall or "rmdir" in syscall:
            action = AccessAction.DELETE
        elif "rename" in syscall:
            action = AccessAction.RENAME
        elif "chmod" in syscall or "chown" in syscall:
            action = AccessAction.PERMISSION_CHANGE
        else:
            action = AccessAction.UNKNOWN

        uid = _get("uid")
        return AccessEvent(
            path=Path(file_path),
            timestamp=ts,
            action=action,
            user_sid=uid,
            user_name=_get("auid") or uid,
            process_name=_get("comm") or _get("exe"),
            process_id=int(_get("pid")) if _get("pid").isdigit() else None,
            event_id=int(_get("serial")) if _get("serial").isdigit() else None,
        )
