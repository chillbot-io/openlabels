"""
EventHarvester — periodic background task that collects access events
from OS audit subsystems and persists them to the database.

Pipeline::

    EventProvider.collect(since)
        → RawAccessEvent
            → filter invalid actions
                → resolve monitored_file_id
                    → INSERT FileAccessEvent row

The harvester tracks a per-provider checkpoint timestamp so that each
cycle only fetches *new* events.  Checkpoints are updated only after
the transaction commits successfully.

Registered as an ``asyncio.Task`` in :mod:`openlabels.server.lifespan`
alongside the periodic Parquet flush task.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.monitoring.providers.base import EventProvider, RawAccessEvent
from openlabels.server.models import FileAccessEvent, MonitoredFile

logger = logging.getLogger(__name__)

# Valid action values for the DB access_action enum.
# AccessAction.UNKNOWN ("unknown") is NOT in the DB enum and must be
# filtered out before persistence.
_VALID_DB_ACTIONS = frozenset({
    "read", "write", "delete", "rename", "permission_change", "execute",
})


class EventHarvester:
    """Periodically collect events from providers and persist to DB.

    Parameters
    ----------
    providers:
        One or more ``EventProvider`` implementations.
    interval_seconds:
        Seconds between harvest cycles.
    max_events_per_cycle:
        Back-pressure cap per cycle.  If a provider yields more than
        this many events, the remainder is left for the next cycle.
        Events are sorted by time and the *earliest* are kept so that
        the checkpoint advances monotonically.
    store_raw_events:
        Whether to populate ``FileAccessEvent.raw_event`` with the
        raw dict from the provider.
    """

    def __init__(
        self,
        providers: list[EventProvider],
        *,
        interval_seconds: int = 60,
        max_events_per_cycle: int = 10_000,
        store_raw_events: bool = False,
        advisory_lock_id: int | None = None,
    ) -> None:
        self._providers = providers
        self._interval = interval_seconds
        self._max_events = max_events_per_cycle
        self._store_raw = store_raw_events
        self._advisory_lock_id = advisory_lock_id

        # Per-provider checkpoint: provider.name → last processed event_time
        self._checkpoints: dict[str, datetime] = {}
        # Pending checkpoint updates — applied only after commit
        self._pending_checkpoints: dict[str, datetime] = {}

        # Stats for observability
        self.total_events_persisted: int = 0
        self.total_cycles: int = 0
        self.last_cycle_at: datetime | None = None

    # Public API
    async def run(
        self,
        shutdown_event: asyncio.Event | None = None,
    ) -> None:
        """Main loop — runs until *shutdown_event* is set.

        Each cycle:
        1. For each provider, run ``collect(since=checkpoint)`` in a
           thread executor (the providers use synchronous subprocess calls).
        2. Filter out events with invalid action values.
        3. Resolve ``file_path → monitored_file_id`` via a DB lookup.
        4. Batch-insert ``FileAccessEvent`` rows.
        5. Update the checkpoint for each provider (only on commit).
        """
        from openlabels.server.db import get_session_context

        _stop = shutdown_event or asyncio.Event()

        logger.info(
            "EventHarvester started (interval=%ds, providers=%s)",
            self._interval,
            [p.name for p in self._providers],
        )

        while not _stop.is_set():
            try:
                async with get_session_context() as session:
                    # If an advisory lock is configured, only one instance
                    # runs the harvest per cycle (used for cloud providers
                    # like M365 that query a shared remote API).
                    if self._advisory_lock_id is not None:
                        from openlabels.server.advisory_lock import try_advisory_lock
                        if not await try_advisory_lock(session, self._advisory_lock_id):
                            logger.debug("Harvest cycle: another instance is running, skipping")
                            continue  # skip to sleep
                    total = await self._harvest_cycle(session)
                # If we reach here, session.commit() succeeded in __aexit__.
                # NOW it is safe to apply pending checkpoints and update stats.
                self._apply_pending_checkpoints()
                self.total_events_persisted += total
                self.total_cycles += 1
                self.last_cycle_at = datetime.now(timezone.utc)
                if total > 0:
                    logger.info("Harvest cycle: persisted %d events", total)
                else:
                    logger.debug("Harvest cycle: no new events")
            except Exception:  # noqa: BLE001 — catch-all for harvest cycle retry
                # Transaction rolled back — discard pending checkpoints.
                # Stats are NOT updated because the commit failed.
                self._pending_checkpoints.clear()
                logger.warning(
                    "Harvest cycle failed; will retry next cycle",
                    exc_info=True,
                )

            # Wait for the next cycle or shutdown
            try:
                await asyncio.wait_for(_stop.wait(), timeout=self._interval)
                break  # shutdown_event was set
            except asyncio.TimeoutError:
                pass  # normal timeout — loop again

        logger.info(
            "EventHarvester stopped (total_cycles=%d, total_events=%d)",
            self.total_cycles,
            self.total_events_persisted,
        )

    async def harvest_once(self, session: AsyncSession) -> int:
        """Run a single harvest cycle (useful for testing).

        Callers are responsible for committing the session.
        Checkpoints and stats are applied immediately (test helper).
        """
        count = await self._harvest_cycle(session)
        self._apply_pending_checkpoints()
        self.total_events_persisted += count
        self.total_cycles += 1
        self.last_cycle_at = datetime.now(timezone.utc)
        return count

    # Internals
    def _apply_pending_checkpoints(self) -> None:
        """Move pending checkpoints to the active checkpoint dict."""
        self._checkpoints.update(self._pending_checkpoints)
        self._pending_checkpoints.clear()

    async def _harvest_cycle(self, session: AsyncSession) -> int:
        """Execute one full harvest cycle across all providers."""
        total_persisted = 0
        self._pending_checkpoints = {}

        for provider in self._providers:
            since = self._checkpoints.get(provider.name)
            try:
                raw_events = await provider.collect(since=since)
            except Exception:  # noqa: BLE001 — catch-all for provider error
                logger.warning(
                    "Provider %s failed to collect events",
                    provider.name,
                    exc_info=True,
                )
                continue

            if not raw_events:
                continue

            # Filter out events with actions not in the DB enum
            valid_events = [e for e in raw_events if e.action in _VALID_DB_ACTIONS]
            skipped = len(raw_events) - len(valid_events)
            if skipped:
                logger.debug(
                    "Provider %s: skipped %d events with invalid action",
                    provider.name,
                    skipped,
                )
            raw_events = valid_events

            if not raw_events:
                continue

            # Sort by event_time before applying back-pressure cap
            # so we keep the earliest events and the checkpoint
            # advances monotonically.
            raw_events.sort(key=lambda e: e.event_time)

            if len(raw_events) > self._max_events:
                logger.warning(
                    "Provider %s returned %d events (cap=%d), truncating",
                    provider.name,
                    len(raw_events),
                    self._max_events,
                )
                raw_events = raw_events[: self._max_events]

            persisted = await self._persist_events(session, raw_events)
            total_persisted += persisted

            # Stage checkpoint update (applied after commit in run())
            if raw_events:
                latest = raw_events[-1].event_time  # already sorted
                self._pending_checkpoints[provider.name] = latest

        return total_persisted

    async def _persist_events(
        self,
        session: AsyncSession,
        events: list[RawAccessEvent],
    ) -> int:
        """Map RawAccessEvents to FileAccessEvent rows and add to session."""
        if not events:
            return 0

        # Build a set of unique file paths for a single batch lookup
        file_paths = {e.file_path for e in events}
        path_to_monitored = await self._resolve_monitored_files(
            session, file_paths,
        )

        persisted = 0
        for event in events:
            monitored = path_to_monitored.get(event.file_path)
            if monitored is None:
                # File is not in the monitored registry — skip
                logger.debug(
                    "Skipping event for unmonitored file: %s",
                    event.file_path,
                )
                continue

            row = FileAccessEvent(
                tenant_id=monitored.tenant_id,
                monitored_file_id=monitored.id,
                file_path=event.file_path,
                action=event.action,
                success=event.success,
                user_sid=event.user_sid,
                user_name=event.user_name,
                user_domain=event.user_domain,
                process_name=event.process_name,
                process_id=event.process_id,
                event_id=event.event_id,
                event_source=event.event_source,
                event_time=event.event_time,
                raw_event=event.raw if self._store_raw else None,
            )
            session.add(row)
            persisted += 1

            # Update monitored file stats
            monitored.access_count = (monitored.access_count or 0) + 1
            if (
                monitored.last_event_at is None
                or event.event_time > monitored.last_event_at
            ):
                monitored.last_event_at = event.event_time

        if persisted:
            await session.flush()

        return persisted

    @staticmethod
    async def _resolve_monitored_files(
        session: AsyncSession,
        file_paths: set[str],
    ) -> dict[str, MonitoredFile]:
        """Batch-resolve file paths to MonitoredFile instances.

        Returns a dict mapping ``file_path`` → ``MonitoredFile`` for
        paths that have a row in the database.  Paths not found are
        simply omitted.

        Note: in a multi-tenant deployment, the same file_path may
        exist under multiple tenants.  We return only the first match
        per file_path (ordered by tenant_id for determinism).  The
        harvester runs globally and attributes events to the tenant
        that owns the monitored file.  If multiple tenants monitor
        the same path, the first tenant (by ID) wins.
        """
        if not file_paths:
            return {}

        result = await session.execute(
            select(MonitoredFile)
            .where(MonitoredFile.file_path.in_(file_paths))
            .order_by(MonitoredFile.tenant_id)
        )
        rows = result.scalars().all()
        # First-match-wins: only the first tenant's MonitoredFile is
        # used for each path.  This is deterministic across cycles.
        mapping: dict[str, MonitoredFile] = {}
        for row in rows:
            if row.file_path not in mapping:
                mapping[row.file_path] = row
        return mapping


# Convenience coroutine for lifespan registration
async def periodic_event_harvest(
    *,
    interval_seconds: int = 60,
    max_events_per_cycle: int = 10_000,
    store_raw_events: bool = False,
    enabled_providers: list[str] | None = None,
    providers: list[EventProvider] | None = None,
    shutdown_event: asyncio.Event | None = None,
) -> None:
    """Top-level coroutine for ``asyncio.create_task()``.

    If *providers* is ``None``, providers are auto-detected from the
    current platform, filtered by *enabled_providers*.
    """
    import platform as _platform

    if providers is None:
        providers = []
        # Import here to avoid circular imports at module level
        from openlabels.monitoring.registry import get_watched_files

        watched_paths = [str(wf.path) for wf in get_watched_files()]

        system = _platform.system()
        if system == "Windows":
            if enabled_providers is None or "windows_sacl" in enabled_providers:
                from openlabels.monitoring.providers.windows import WindowsSACLProvider
                providers.append(WindowsSACLProvider(watched_paths=watched_paths or None))
        else:
            if enabled_providers is None or "auditd" in enabled_providers:
                from openlabels.monitoring.providers.linux import AuditdProvider
                providers.append(AuditdProvider(watched_paths=watched_paths or None))

    if not providers:
        logger.warning("No event providers available — harvester not started")
        return

    harvester = EventHarvester(
        providers,
        interval_seconds=interval_seconds,
        max_events_per_cycle=max_events_per_cycle,
        store_raw_events=store_raw_events,
    )
    await harvester.run(shutdown_event=shutdown_event)


async def periodic_m365_harvest(
    *,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    interval_seconds: int = 300,
    max_events_per_cycle: int = 10_000,
    store_raw_events: bool = False,
    monitored_site_urls: list[str] | None = None,
    graph_client: object | None = None,
    webhook_url: str = "",
    webhook_client_state: str = "",
    enabled_providers: list[str] | None = None,
    shutdown_event: asyncio.Event | None = None,
) -> None:
    """Top-level coroutine for M365 cloud providers.

    Runs a **separate** ``EventHarvester`` instance with a longer
    interval (default 5 min) for cloud API providers:

    - ``M365AuditProvider`` — Management Activity API audit events
    - ``GraphWebhookProvider`` — Graph change notifications + delta queries

    Parameters
    ----------
    tenant_id, client_id, client_secret:
        Azure AD app registration credentials (same as Graph API).
    graph_client:
        Optional shared :class:`GraphClient` for the webhook provider.
        If ``None``, the webhook provider is not started.
    """
    providers: list[EventProvider] = []

    m365_provider = None
    if enabled_providers is None or "m365_audit" in enabled_providers:
        from openlabels.monitoring.providers.m365_audit import M365AuditProvider

        m365_provider = M365AuditProvider(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            monitored_site_urls=monitored_site_urls or None,
        )
        providers.append(m365_provider)

    if graph_client is not None and (
        enabled_providers is None or "graph_webhook" in enabled_providers
    ):
        from openlabels.monitoring.providers.graph_webhook import GraphWebhookProvider

        providers.append(
            GraphWebhookProvider(
                graph_client,
                webhook_url=webhook_url,
                client_state=webhook_client_state,
            )
        )

    if not providers:
        logger.warning("No M365 providers available — M365 harvester not started")
        return

    from openlabels.server.advisory_lock import AdvisoryLockID

    harvester = EventHarvester(
        providers,
        interval_seconds=interval_seconds,
        max_events_per_cycle=max_events_per_cycle,
        store_raw_events=store_raw_events,
        advisory_lock_id=AdvisoryLockID.M365_HARVEST,
    )
    try:
        await harvester.run(shutdown_event=shutdown_event)
    finally:
        # Close M365AuditProvider's httpx client on shutdown
        if m365_provider is not None:
            try:
                await m365_provider.close()
            except (ConnectionError, OSError, RuntimeError):
                pass
