"""
WinRM EventProvider — collects file access events from remote Windows
file servers via PowerShell Remoting (WinRM).

Unlike the local ``WindowsSACLProvider`` (which reads the local event
log), this provider queries remote machines using credentials stored
in the ``SavedCredential`` table.  On each harvest cycle it re-reads
the database so that newly added targets are picked up without a
restart.

Pipeline::

    SavedCredential (source_type="smb")
        → decrypt host / username / password
            → WinRM collect_events()
                → parse PowerShell JSON
                    → RawAccessEvent

Registered as a supervised background task in
:mod:`openlabels.server.lifespan` alongside the local event harvester
and M365 harvester.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from openlabels.monitoring.providers.base import EventProvider, RawAccessEvent

logger = logging.getLogger(__name__)

EVENT_SOURCE = "winrm"

# Windows access mask → OpenLabels action mapping.
# Event IDs 4663 / 4656 encode the requested access as a hex mask.
_ACCESS_MASK_MAP: dict[int, str] = {
    0x1:     "read",    # ReadData / ListDirectory
    0x2:     "write",   # WriteData / AddFile
    0x4:     "write",   # AppendData / AddSubdirectory
    0x20:    "execute",  # Execute / Traverse
    0x10000: "delete",  # DELETE
    0x40000: "write",   # WRITE_DAC
    0x80000: "permission_change",  # WRITE_OWNER
}


def _access_mask_to_action(mask_str: str | int | None) -> str:
    """Convert a Windows access mask value to an OpenLabels action string."""
    if mask_str is None:
        return "read"
    try:
        if isinstance(mask_str, str):
            mask = int(mask_str, 16) if mask_str.startswith("0x") else int(mask_str)
        else:
            mask = int(mask_str)
    except (ValueError, TypeError):
        return "read"

    # Check from most specific to least
    for bit, action in _ACCESS_MASK_MAP.items():
        if mask & bit:
            return action
    return "read"


class WinRMProvider:
    """Collect file access events from remote Windows servers via WinRM.

    Queries the ``SavedCredential`` table for SMB-type credentials on
    each ``collect()`` call, so newly configured targets are picked up
    automatically without restarting the harvester.

    Parameters
    ----------
    targets:
        Pre-resolved list of ``(host, username, password, use_ssl)``
        tuples.  When provided, the database query is skipped (useful
        for testing or when a single run is needed).
    max_events_per_host:
        Cap on events fetched per remote host per cycle.
    since_hours_default:
        Hours of history to fetch when no ``since`` checkpoint exists.
    """

    def __init__(
        self,
        targets: list[tuple[str, str, str, bool]] | None = None,
        max_events_per_host: int = 500,
        since_hours_default: int = 1,
    ) -> None:
        self._static_targets = targets
        self._max_events_per_host = max_events_per_host
        self._since_hours_default = since_hours_default

    @property
    def name(self) -> str:
        return EVENT_SOURCE

    async def collect(self, since: datetime | None = None) -> list[RawAccessEvent]:
        """Collect events from all configured WinRM targets.

        If ``since`` is provided, computes ``since_hours`` from the
        timedelta.  Otherwise falls back to ``since_hours_default``.
        """
        targets = self._static_targets
        if targets is None:
            targets = await self._load_targets_from_db()

        if not targets:
            logger.debug("WinRM provider: no targets configured")
            return []

        # Compute hours lookback from checkpoint
        if since is not None:
            delta = datetime.now(timezone.utc) - since
            since_hours = max(int(delta.total_seconds() / 3600) + 1, 1)
        else:
            since_hours = self._since_hours_default

        all_events: list[RawAccessEvent] = []
        for host, username, password, use_ssl in targets:
            try:
                host_events = await self._collect_from_host(
                    host, username, password, use_ssl,
                    since_hours=since_hours,
                )
                all_events.extend(host_events)
            except Exception:
                logger.warning(
                    "WinRM collection from %s failed", host, exc_info=True,
                )

        if all_events:
            logger.info(
                "WinRM provider collected %d events from %d hosts",
                len(all_events), len(targets),
            )
        return all_events

    async def _collect_from_host(
        self,
        host: str,
        username: str,
        password: str,
        use_ssl: bool,
        since_hours: int,
    ) -> list[RawAccessEvent]:
        """Collect events from a single remote host."""
        from openlabels.monitoring.winrm_remote import collect_events

        result = await collect_events(
            host=host,
            username=username,
            password=password,
            since_hours=since_hours,
            max_events=self._max_events_per_host,
            use_ssl=use_ssl,
        )

        if not result.success:
            logger.warning(
                "WinRM collection from %s returned error: %s",
                host, result.error,
            )
            return []

        raw_events = (result.data or {}).get("events", [])
        return self._parse_events(raw_events, host)

    def _parse_events(
        self,
        raw_events: list[dict],
        host: str,
    ) -> list[RawAccessEvent]:
        """Convert PowerShell JSON event dicts to RawAccessEvent instances."""
        events: list[RawAccessEvent] = []

        for ev in raw_events:
            # Parse timestamp
            time_str = ev.get("time")
            if not time_str:
                continue
            try:
                event_time = datetime.fromisoformat(time_str)
                if event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue

            object_name = ev.get("object_name", "")
            if not object_name:
                continue

            action = _access_mask_to_action(ev.get("access_mask"))

            events.append(RawAccessEvent(
                file_path=object_name,
                event_time=event_time,
                action=action,
                event_source=EVENT_SOURCE,
                user_sid=ev.get("user_sid"),
                user_name=ev.get("user_name"),
                user_domain=ev.get("domain"),
                process_name=ev.get("process"),
                event_id=ev.get("event_id"),
                success=True,  # Events 4663/4656 are successful accesses
                raw=ev,
            ))

        return events

    @staticmethod
    async def _load_targets_from_db() -> list[tuple[str, str, str, bool]]:
        """Load WinRM targets from SavedCredential table.

        Looks for credentials with ``source_type="smb"`` and extracts
        host, username, password, and use_ssl from the encrypted data.
        """
        try:
            from openlabels.server.db import get_session_context
            from openlabels.server.models import SavedCredential
            from sqlalchemy import select

            # Import the public decrypt API from the credentials module.
            # Falls back to the private name for backward compatibility.
            try:
                from openlabels.server.routes.credentials import decrypt
            except ImportError:
                from openlabels.server.routes.credentials import _decrypt as decrypt

            async with get_session_context() as session:
                result = await session.execute(
                    select(SavedCredential).where(
                        SavedCredential.source_type == "smb",
                    )
                )
                rows = result.scalars().all()

            targets = []
            for row in rows:
                try:
                    creds = decrypt(row.encrypted_data)
                    host = creds.get("host") or creds.get("hostname", "")
                    username = creds.get("username", "")
                    password = creds.get("password", "")
                    use_ssl = creds.get("use_ssl", False)
                    if host and username and password:
                        targets.append((host, username, password, bool(use_ssl)))
                except Exception:
                    logger.warning(
                        "Failed to decrypt WinRM credentials %s", row.id,
                    )

            return targets

        except Exception:
            logger.warning(
                "Failed to load WinRM targets from database", exc_info=True,
            )
            return []
