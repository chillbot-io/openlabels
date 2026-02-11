"""Directory tree delta sync service.

Incrementally updates the ``directory_tree`` table by detecting
changes since the last sync checkpoint.  Three strategies:

1. **Timestamp diff** (all platforms): Re-walk the filesystem and
   compare ``dir_modified`` against stored values.  Only upsert changed
   directories; detect and remove deleted ones.  This is O(walk) but
   skips ~90% of DB writes on a typical delta.

2. **USN journal** (Windows NTFS): Read change records from the NTFS
   Update Sequence Number journal since the stored cursor.  True
   O(changes) — no full walk needed.  Requires ``win32file``.

3. **Graph API delta** (SharePoint/OneDrive): Use the delta endpoint
   with a stored token to get incremental folder changes.

Strategy 1 is the universal fallback.  Strategies 2 and 3 are
activated automatically when the platform/adapter supports them.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import PurePosixPath
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.adapters.base import FolderInfo
from openlabels.server.models import DirectoryTree, IndexCheckpoint, generate_uuid

logger = logging.getLogger(__name__)

UPSERT_BATCH_SIZE = 2000


# ── Checkpoint helpers ──────────────────────────────────────────────


async def get_checkpoint(
    session: AsyncSession,
    tenant_id: UUID,
    target_id: UUID,
) -> IndexCheckpoint | None:
    """Fetch the sync checkpoint for a target, if one exists."""
    result = await session.execute(
        select(IndexCheckpoint).where(
            IndexCheckpoint.tenant_id == tenant_id,
            IndexCheckpoint.target_id == target_id,
        )
    )
    return result.scalar_one_or_none()


async def upsert_checkpoint(
    session: AsyncSession,
    tenant_id: UUID,
    target_id: UUID,
    *,
    last_full_sync: datetime | None = None,
    last_delta_sync: datetime | None = None,
    dirs_at_last_sync: int = 0,
    delta_token: str | None = None,
    usn_journal_cursor: int | None = None,
) -> None:
    """Create or update the sync checkpoint for a target."""
    values = {
        "id": generate_uuid(),
        "tenant_id": tenant_id,
        "target_id": target_id,
        "last_full_sync": last_full_sync,
        "last_delta_sync": last_delta_sync,
        "dirs_at_last_sync": dirs_at_last_sync,
        "delta_token": delta_token,
        "usn_journal_cursor": usn_journal_cursor,
    }
    stmt = pg_insert(IndexCheckpoint.__table__).values(values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["tenant_id", "target_id"],
        set_={
            "last_full_sync": stmt.excluded.last_full_sync,
            "last_delta_sync": stmt.excluded.last_delta_sync,
            "dirs_at_last_sync": stmt.excluded.dirs_at_last_sync,
            "delta_token": stmt.excluded.delta_token,
            "usn_journal_cursor": stmt.excluded.usn_journal_cursor,
            "updated_at": datetime.now(timezone.utc),
        },
    )
    await session.execute(stmt)


# ── Timestamp-based delta sync ──────────────────────────────────────


async def delta_sync_directory_tree(
    session: AsyncSession,
    adapter,
    tenant_id: UUID,
    target_id: UUID,
    scan_path: str,
    on_progress: Callable[[int], None] | None = None,
    collect_sd: bool = True,
    on_sd_progress: Callable[[int, int], None] | None = None,
) -> dict:
    """Incrementally sync the directory tree from the filesystem.

    Compares the live filesystem state against the database and applies
    only the differences:

    - **New** directories are inserted.
    - **Modified** directories (mtime changed) are updated.
    - **Deleted** directories (in DB but not on disk) are removed.
    - Unchanged directories are skipped entirely.

    After applying changes, re-resolves parent links for new dirs and
    optionally collects security descriptors for new/changed dirs.

    Args:
        session: Active async database session.
        adapter: Adapter instance with ``list_folders()`` method.
        tenant_id: Tenant UUID.
        target_id: Scan target UUID.
        scan_path: Root path to enumerate.
        on_progress: Optional callback with count of dirs processed.
        collect_sd: Collect SDs for new/changed directories.
        on_sd_progress: Optional SD progress callback.

    Returns:
        Dict with ``inserted``, ``updated``, ``deleted``, ``unchanged``,
        ``elapsed_seconds``, and optionally ``sd_stats``.
    """
    start = time.monotonic()

    # Load existing directory state from DB
    existing = await _load_existing_dirs(session, tenant_id, target_id)
    # existing: {dir_path: (id, dir_modified_ts)} where ts is epoch float or None

    seen_paths: set[str] = set()
    insert_batch: list[dict] = []
    update_batch: list[dict] = []
    inserted = 0
    updated = 0
    unchanged = 0
    processed = 0

    async for folder_info in adapter.list_folders(scan_path, recursive=True):
        path = folder_info.path
        seen_paths.add(path)
        processed += 1

        if path in existing:
            # Directory exists — check if modified
            existing_id, existing_mtime = existing[path]
            live_mtime = _to_epoch(folder_info.modified)

            if existing_mtime is not None and live_mtime is not None and abs(live_mtime - existing_mtime) < 1.0:
                # Unchanged — skip
                unchanged += 1
            else:
                # Modified — queue update
                update_batch.append(_update_row(existing_id, folder_info))
                if len(update_batch) >= UPSERT_BATCH_SIZE:
                    await _apply_updates(session, update_batch)
                    updated += len(update_batch)
                    update_batch.clear()
        else:
            # New directory — queue insert
            insert_batch.append(_folder_info_to_row(folder_info, tenant_id, target_id))
            if len(insert_batch) >= UPSERT_BATCH_SIZE:
                await _upsert_batch(session, insert_batch)
                inserted += len(insert_batch)
                insert_batch.clear()

        if on_progress and processed % 5000 == 0:
            on_progress(processed)

    # Flush remaining batches
    if insert_batch:
        await _upsert_batch(session, insert_batch)
        inserted += len(insert_batch)
    if update_batch:
        await _apply_updates(session, update_batch)
        updated += len(update_batch)

    # Detect deletions: paths in DB but not seen on disk
    deleted_paths = set(existing.keys()) - seen_paths
    deleted = 0
    if deleted_paths:
        deleted = await _delete_missing(session, tenant_id, target_id, deleted_paths)

    await session.flush()

    # Resolve parent links for newly inserted directories
    parent_resolved = 0
    if inserted > 0:
        from openlabels.jobs.index import _resolve_parent_ids, _resolve_parent_ids_by_path
        parent_resolved = await _resolve_parent_ids(session, tenant_id, target_id)
        parent_resolved += await _resolve_parent_ids_by_path(session, tenant_id, target_id)

    # Collect SDs for new/changed directories (those with NULL sd_hash)
    sd_stats: dict | None = None
    if collect_sd and (inserted > 0 or updated > 0):
        from openlabels.jobs.sd_collect import collect_security_descriptors
        sd_stats = await collect_security_descriptors(
            session=session,
            tenant_id=tenant_id,
            target_id=target_id,
            on_progress=on_sd_progress,
        )

    # Update checkpoint
    total_dirs = len(seen_paths)
    now = datetime.now(timezone.utc)
    await upsert_checkpoint(
        session,
        tenant_id,
        target_id,
        last_delta_sync=now,
        dirs_at_last_sync=total_dirs,
    )
    await session.flush()

    elapsed = time.monotonic() - start

    logger.info(
        "Delta sync complete: +%d -%d ~%d =%d (total %d) in %.1fs",
        inserted, deleted, updated, unchanged, total_dirs, elapsed,
    )

    result = {
        "inserted": inserted,
        "updated": updated,
        "deleted": deleted,
        "unchanged": unchanged,
        "total_dirs": total_dirs,
        "parent_links_resolved": parent_resolved,
        "elapsed_seconds": round(elapsed, 2),
    }
    if sd_stats:
        result["sd_stats"] = sd_stats

    return result


# ── Internal helpers ────────────────────────────────────────────────


async def _load_existing_dirs(
    session: AsyncSession,
    tenant_id: UUID,
    target_id: UUID,
) -> dict[str, tuple[UUID, float | None]]:
    """Load all existing directory paths and their mtimes from the DB.

    Returns:
        Dict mapping ``dir_path → (id, epoch_timestamp)``.
    """
    result = await session.execute(
        text("""
            SELECT id, dir_path, dir_modified
              FROM directory_tree
             WHERE tenant_id = :tenant_id
               AND target_id = :target_id
        """),
        {"tenant_id": tenant_id, "target_id": target_id},
    )
    dirs = {}
    for row in result.all():
        mtime = row.dir_modified.timestamp() if row.dir_modified else None
        dirs[row.dir_path] = (row.id, mtime)
    return dirs


def _to_epoch(dt: datetime | None) -> float | None:
    """Convert datetime to epoch seconds, or None."""
    if dt is None:
        return None
    return dt.timestamp()


def _folder_info_to_row(info: FolderInfo, tenant_id: UUID, target_id: UUID) -> dict:
    """Convert a FolderInfo to a dict for INSERT."""
    name = info.name
    if not name:
        name = PurePosixPath(info.path).name or info.path

    return {
        "id": generate_uuid(),
        "tenant_id": tenant_id,
        "target_id": target_id,
        "dir_ref": info.inode,
        "parent_ref": info.parent_inode,
        "dir_path": info.path,
        "dir_name": name,
        "dir_modified": info.modified,
        "child_dir_count": info.child_dir_count,
        "child_file_count": info.child_file_count,
        "flags": 0,
        "discovered_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }


def _update_row(existing_id: UUID, info: FolderInfo) -> dict:
    """Build an update dict for a modified directory."""
    return {
        "id": existing_id,
        "dir_modified": info.modified,
        "dir_ref": info.inode,
        "parent_ref": info.parent_inode,
        "child_dir_count": info.child_dir_count,
        "child_file_count": info.child_file_count,
        # Clear sd_hash so SD collection re-processes this dir
        "sd_hash": None,
        "updated_at": datetime.now(timezone.utc),
    }


async def _upsert_batch(session: AsyncSession, rows: list[dict]) -> None:
    """Upsert new directories using INSERT ... ON CONFLICT UPDATE."""
    stmt = pg_insert(DirectoryTree.__table__).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=["tenant_id", "target_id", "dir_path"],
        set_={
            "dir_ref": stmt.excluded.dir_ref,
            "parent_ref": stmt.excluded.parent_ref,
            "dir_name": stmt.excluded.dir_name,
            "dir_modified": stmt.excluded.dir_modified,
            "child_dir_count": stmt.excluded.child_dir_count,
            "child_file_count": stmt.excluded.child_file_count,
            "updated_at": stmt.excluded.updated_at,
        },
    )
    await session.execute(stmt)


async def _apply_updates(session: AsyncSession, rows: list[dict]) -> None:
    """Batch-update modified directories via a VALUES join."""
    if not rows:
        return

    values_sql = ", ".join(
        f"(:id_{i}::uuid, :mod_{i}::timestamptz, :ref_{i}::bigint, "
        f":pref_{i}::bigint, :dcount_{i}::int, :fcount_{i}::int)"
        for i in range(len(rows))
    )
    params: dict = {}
    for i, row in enumerate(rows):
        params[f"id_{i}"] = row["id"]
        params[f"mod_{i}"] = row["dir_modified"]
        params[f"ref_{i}"] = row["dir_ref"]
        params[f"pref_{i}"] = row["parent_ref"]
        params[f"dcount_{i}"] = row["child_dir_count"]
        params[f"fcount_{i}"] = row["child_file_count"]

    await session.execute(
        text(f"""
            UPDATE directory_tree AS dt
               SET dir_modified = v.dir_modified,
                   dir_ref = v.dir_ref,
                   parent_ref = v.parent_ref,
                   child_dir_count = v.child_dir_count,
                   child_file_count = v.child_file_count,
                   sd_hash = NULL,
                   updated_at = now()
              FROM (VALUES {values_sql})
                   AS v(id, dir_modified, dir_ref, parent_ref,
                        child_dir_count, child_file_count)
             WHERE dt.id = v.id
        """),
        params,
    )


async def _delete_missing(
    session: AsyncSession,
    tenant_id: UUID,
    target_id: UUID,
    deleted_paths: set[str],
) -> int:
    """Delete directory_tree rows for paths that no longer exist.

    Processes in batches to avoid overly large IN clauses.
    """
    total_deleted = 0
    path_list = list(deleted_paths)

    for i in range(0, len(path_list), UPSERT_BATCH_SIZE):
        batch = path_list[i:i + UPSERT_BATCH_SIZE]
        placeholders = ", ".join(f":p_{j}" for j in range(len(batch)))
        params: dict = {
            "tenant_id": tenant_id,
            "target_id": target_id,
        }
        for j, p in enumerate(batch):
            params[f"p_{j}"] = p

        result = await session.execute(
            text(f"""
                DELETE FROM directory_tree
                 WHERE tenant_id = :tenant_id
                   AND target_id = :target_id
                   AND dir_path IN ({placeholders})
            """),
            params,
        )
        total_deleted += result.rowcount

    return total_deleted
