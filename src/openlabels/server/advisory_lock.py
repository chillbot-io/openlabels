"""PostgreSQL advisory locks for distributed task coordination.

Prevents duplicate work when multiple API instances run behind a load
balancer.  Each periodic background task is assigned a stable lock ID.
Before each cycle, the task tries ``pg_try_advisory_xact_lock(id)`` —
if another instance already holds the lock, this instance skips the
cycle and waits for the next interval.

Advisory locks are automatically released when the transaction (or
session) ends, so a crashed instance never permanently blocks others.

Usage::

    from openlabels.server.advisory_lock import try_advisory_lock, AdvisoryLockID

    async with get_session_context() as session:
        if await try_advisory_lock(session, AdvisoryLockID.EVENT_FLUSH):
            await flush_events_to_catalog(session, storage)
        else:
            logger.debug("Another instance is running the flush, skipping")
"""

import enum
import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class AdvisoryLockID(enum.IntEnum):
    """Stable lock IDs for distributed background tasks.

    Values are arbitrary but must be unique and never change once
    deployed.  Using an enum prevents accidental collisions.
    """

    EVENT_FLUSH = 100_001
    SIEM_EXPORT = 100_002
    EVENT_HARVEST = 100_003
    M365_HARVEST = 100_004
    MONITORING_SYNC = 100_005
    LABEL_SYNC = 100_006
    STUCK_JOB_RECLAIM = 100_007
    JOB_CLEANUP = 100_008


async def try_advisory_lock(session: AsyncSession, lock_id: AdvisoryLockID) -> bool:
    """Try to acquire a transaction-scoped advisory lock.

    Returns True if the lock was acquired (this instance should run
    the task).  Returns False if another instance already holds it
    (this instance should skip).

    The lock is automatically released when the transaction commits
    or rolls back — no explicit unlock needed.
    """
    result = await session.execute(
        text("SELECT pg_try_advisory_xact_lock(:lock_id)"),
        {"lock_id": int(lock_id)},
    )
    acquired = result.scalar()
    if not acquired:
        logger.debug(
            "Advisory lock %s (%d) held by another instance, skipping",
            lock_id.name, lock_id,
        )
    return bool(acquired)
