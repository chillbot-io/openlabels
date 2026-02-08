"""
Periodic flush task — export access events, audit logs, and remediation
actions to Parquet.

This task runs on the configured interval (default: every 5 minutes) to
incrementally flush new rows from PostgreSQL into the partitioned
Parquet catalog.

Scan results are flushed immediately on completion (see ``scan.py``),
so this task handles only the periodic/event-driven data.
"""

from __future__ import annotations

import logging

from openlabels.server.config import get_settings

logger = logging.getLogger(__name__)


async def periodic_event_flush(session) -> dict[str, int]:
    """Flush pending events, audit logs, and remediation actions to the Parquet catalog.

    This is a no-op when ``catalog.enabled`` is ``False``.

    Parameters
    ----------
    session:
        An active SQLAlchemy ``AsyncSession``.

    Returns
    -------
    dict[str, int]
        Counts of flushed rows.
    """
    settings = get_settings()
    if not settings.catalog.enabled:
        return {"access_events": 0, "audit_logs": 0, "remediation_actions": 0}

    from openlabels.analytics.flush import flush_events_to_catalog
    from openlabels.analytics.storage import create_storage

    try:
        storage = create_storage(settings.catalog)
        counts = await flush_events_to_catalog(session, storage)
        logger.info(
            "Periodic event flush complete: %d access events, %d audit logs, %d remediation actions",
            counts["access_events"],
            counts["audit_logs"],
            counts["remediation_actions"],
        )
        return counts
    except Exception:
        logger.warning("Periodic event flush failed", exc_info=True)
        return {"access_events": 0, "audit_logs": 0, "remediation_actions": 0}
