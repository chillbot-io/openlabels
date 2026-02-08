"""
Periodic flush task — exports new access events and audit logs to the
Parquet data lake at a configurable interval (default 5 minutes).

Registered as a background task alongside the existing scheduler in
:mod:`openlabels.server.lifespan`.
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


async def periodic_event_flush(
    *,
    interval_seconds: int = 300,
    shutdown_event: asyncio.Event | None = None,
) -> None:
    """Run :func:`flush_events_to_catalog` on a fixed interval.

    Parameters
    ----------
    interval_seconds:
        Pause between flushes (sourced from
        ``CatalogSettings.event_flush_interval_seconds``).
    shutdown_event:
        When set, the loop exits gracefully.
    """
    from openlabels.analytics.flush import flush_events_to_catalog
    from openlabels.analytics.storage import create_storage
    from openlabels.server.config import get_settings
    from openlabels.server.db import get_session_context

    settings = get_settings()
    if not settings.catalog.enabled:
        return

    storage = create_storage(settings.catalog)
    _stop = shutdown_event or asyncio.Event()

    logger.info(
        "Periodic event flush started (interval=%ds)",
        interval_seconds,
    )

    while not _stop.is_set():
        try:
            async with get_session_context() as session:
                counts = await flush_events_to_catalog(session, storage)
                total = counts.get("access_events", 0) + counts.get("audit_logs", 0)
                if total > 0:
                    logger.info(
                        "Periodic flush: %d access events, %d audit logs",
                        counts["access_events"],
                        counts["audit_logs"],
                    )
                else:
                    logger.debug("Periodic flush: nothing new to flush")

                # Update catalog health metrics (best-effort)
                try:
                    from openlabels.server.metrics import record_catalog_flush, update_catalog_health
                    record_catalog_flush(success=True)
                    update_catalog_health(storage)
                except Exception:
                    pass

        except Exception:
            logger.warning(
                "Periodic event flush failed; will retry next cycle",
                exc_info=True,
            )
            try:
                from openlabels.server.metrics import record_catalog_flush
                record_catalog_flush(success=False)
            except Exception:
                pass

        # Wait for the next cycle or shutdown
        try:
            await asyncio.wait_for(_stop.wait(), timeout=interval_seconds)
            break  # shutdown_event was set
        except asyncio.TimeoutError:
            pass  # normal timeout — loop again

    logger.info("Periodic event flush stopped")
