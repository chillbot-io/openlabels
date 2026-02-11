"""
Database persistence for the monitoring registry.

Provides async functions to persist monitoring state to the database
via the MonitoredFile model. The in-memory registry in registry.py
acts as a process-local cache; these functions ensure state survives
restarts and is shared across workers.

Usage from async context (e.g., FastAPI routes, startup hooks):

    from openlabels.server.db import get_session_context
    from openlabels.monitoring import db as monitoring_db

    # On startup, populate the in-memory cache
    async with get_session_context() as session:
        files = await monitoring_db.load_monitored_files(session, tenant_id)
        for f in files:
            ...

    # After enabling monitoring
    async with get_session_context() as session:
        await monitoring_db.upsert_monitored_file(session, ...)

    # After disabling monitoring
    async with get_session_context() as session:
        await monitoring_db.remove_monitored_file(session, tenant_id, file_path)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import MonitoredFile

logger = logging.getLogger(__name__)


async def load_monitored_files(
    session: AsyncSession,
    tenant_id: UUID,
) -> list[MonitoredFile]:
    """
    Load all monitored files for a tenant from the database.

    Use this at startup to pre-populate the in-memory ``_watched_files``
    cache in :mod:`openlabels.monitoring.registry`.

    Args:
        session: An active async database session.
        tenant_id: The tenant whose monitored files to load.

    Returns:
        List of MonitoredFile rows for the tenant.
    """
    result = await session.execute(
        select(MonitoredFile)
        .where(MonitoredFile.tenant_id == tenant_id)
        .order_by(MonitoredFile.added_at)
        .limit(100_000)
    )
    files = list(result.scalars().all())
    logger.info(
        "Loaded %d monitored files from database for tenant %s",
        len(files),
        tenant_id,
    )
    return files


async def upsert_monitored_file(
    session: AsyncSession,
    tenant_id: UUID,
    file_path: str,
    risk_tier: str = "HIGH",
    sacl_enabled: bool = False,
    audit_rule_enabled: bool = False,
    audit_read: bool = True,
    audit_write: bool = True,
    enabled_by: str | None = None,
    file_inventory_id: UUID | None = None,
) -> MonitoredFile:
    """
    Insert or update a monitored file record in the database.

    If a record already exists for the given (tenant_id, file_path) pair,
    it is updated in place.  Otherwise a new row is created.

    This should be called after :func:`registry.enable_monitoring` succeeds,
    so that the database reflects the current OS-level monitoring state.

    Args:
        session: An active async database session.
        tenant_id: The owning tenant.
        file_path: Absolute path of the monitored file.
        risk_tier: Risk classification (e.g. "CRITICAL", "HIGH").
        sacl_enabled: Whether a Windows SACL was configured.
        audit_rule_enabled: Whether a Linux auditd rule was configured.
        audit_read: Whether read access is being audited.
        audit_write: Whether write access is being audited.
        enabled_by: Email or identifier of the user who enabled monitoring.
        file_inventory_id: Optional FK to the file_inventory table.

    Returns:
        The created or updated MonitoredFile instance.
    """
    # Check for existing record
    result = await session.execute(
        select(MonitoredFile).where(
            MonitoredFile.tenant_id == tenant_id,
            MonitoredFile.file_path == file_path,
        )
    )
    existing = result.scalar_one_or_none()

    if existing is not None:
        # Update mutable fields
        existing.risk_tier = risk_tier
        existing.sacl_enabled = sacl_enabled
        existing.audit_rule_enabled = audit_rule_enabled
        existing.audit_read = audit_read
        existing.audit_write = audit_write
        if enabled_by is not None:
            existing.enabled_by = enabled_by
        logger.debug("Updated monitored file record: %s", file_path)
        await session.flush()
        return existing

    # Create new record
    monitored = MonitoredFile(
        tenant_id=tenant_id,
        file_inventory_id=file_inventory_id,
        file_path=file_path,
        risk_tier=risk_tier,
        sacl_enabled=sacl_enabled,
        audit_rule_enabled=audit_rule_enabled,
        audit_read=audit_read,
        audit_write=audit_write,
        enabled_by=enabled_by,
    )
    session.add(monitored)
    await session.flush()
    logger.info("Persisted new monitored file to database: %s", file_path)
    return monitored


async def remove_monitored_file(
    session: AsyncSession,
    tenant_id: UUID,
    file_path: str,
) -> bool:
    """
    Remove a monitored file record from the database.

    This should be called after :func:`registry.disable_monitoring` succeeds,
    so that the database reflects the current OS-level monitoring state.

    Args:
        session: An active async database session.
        tenant_id: The owning tenant.
        file_path: Absolute path of the file to stop monitoring.

    Returns:
        True if a record was deleted, False if no matching record existed.
    """
    result = await session.execute(
        delete(MonitoredFile).where(
            MonitoredFile.tenant_id == tenant_id,
            MonitoredFile.file_path == file_path,
        )
    )
    await session.flush()
    deleted = result.rowcount > 0
    if deleted:
        logger.info("Removed monitored file from database: %s", file_path)
    else:
        logger.debug(
            "No database record found for monitored file: %s (tenant %s)",
            file_path,
            tenant_id,
        )
    return deleted


async def sync_to_db(
    session: AsyncSession,
    tenant_id: UUID,
    watched_files: dict,
) -> int:
    """
    Bulk-sync the in-memory watched files cache to the database.

    For each entry in *watched_files*, an upsert is performed.  Database
    records that no longer appear in the cache are removed.

    This is useful as a periodic consistency check or graceful-shutdown hook.

    Args:
        session: An active async database session.
        tenant_id: The owning tenant.
        watched_files: The ``_watched_files`` dict from registry.py,
            mapping ``str(path)`` to ``WatchedFile`` dataclass instances.

    Returns:
        The number of records that were written (inserted + updated).
    """
    # Upsert every cached entry
    count = 0
    for path_str, wf in watched_files.items():
        await upsert_monitored_file(
            session=session,
            tenant_id=tenant_id,
            file_path=path_str,
            risk_tier=wf.risk_tier,
            sacl_enabled=wf.sacl_enabled,
            audit_rule_enabled=wf.audit_rule_enabled,
        )
        count += 1

    # Remove DB rows whose paths are no longer in the cache
    result = await session.execute(
        select(MonitoredFile.file_path).where(
            MonitoredFile.tenant_id == tenant_id,
        ).limit(100_000)
    )
    db_paths = {row[0] for row in result.all()}
    stale_paths = db_paths - set(watched_files.keys())

    for stale in stale_paths:
        await remove_monitored_file(session, tenant_id, stale)

    if stale_paths:
        logger.info(
            "Removed %d stale monitored file records during sync",
            len(stale_paths),
        )

    logger.info(
        "Synced %d monitored files to database for tenant %s",
        count,
        tenant_id,
    )
    return count


async def load_from_db(
    session: AsyncSession,
    tenant_id: UUID,
) -> dict:
    """
    Load monitored files from the database and return them as a dict
    suitable for populating the in-memory ``_watched_files`` cache.

    The returned dict maps ``file_path`` (str) to a dict of WatchedFile-
    compatible fields.  The caller is responsible for constructing actual
    ``WatchedFile`` instances.

    Args:
        session: An active async database session.
        tenant_id: The owning tenant.

    Returns:
        Dict mapping file_path -> dict with keys: path, risk_tier,
        added_at, sacl_enabled, audit_rule_enabled, last_event_at,
        access_count.
    """
    from pathlib import Path

    rows = await load_monitored_files(session, tenant_id)
    result = {}
    for row in rows:
        result[row.file_path] = {
            "path": Path(row.file_path),
            "risk_tier": row.risk_tier,
            "added_at": row.added_at or datetime.now(timezone.utc),
            "sacl_enabled": row.sacl_enabled,
            "audit_rule_enabled": row.audit_rule_enabled,
            "last_event_at": row.last_event_at,
            "access_count": row.access_count,
        }
    logger.info(
        "Prepared %d watched file entries from database for tenant %s",
        len(result),
        tenant_id,
    )
    return result
