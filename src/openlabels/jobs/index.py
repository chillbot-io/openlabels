"""Directory tree bootstrap service.

Populates the ``directory_tree`` table from adapter.list_folders().
Used by the ``openlabels index`` CLI command.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import PurePosixPath
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.adapters.base import FolderInfo
from openlabels.server.models import DirectoryTree, generate_uuid

logger = logging.getLogger(__name__)

# Batch size for bulk upserts
UPSERT_BATCH_SIZE = 2000


async def bootstrap_directory_tree(
    session: AsyncSession,
    adapter,
    tenant_id: UUID,
    target_id: UUID,
    scan_path: str,
    on_progress: Callable[[int], None] | None = None,
    collect_sd: bool = False,
    on_sd_progress: Callable[[int, int], None] | None = None,
) -> dict:
    """Enumerate directories via adapter and populate directory_tree.

    Args:
        session: Active async database session.
        adapter: Adapter instance with ``list_folders()`` method.
        tenant_id: Tenant UUID.
        target_id: Scan target UUID.
        scan_path: Root path to enumerate.
        on_progress: Optional callback invoked with folder count after
            each batch insert.
        collect_sd: If True, collect security descriptors after indexing.
        on_sd_progress: Optional ``(processed, total)`` callback for SD
            collection progress.

    Returns:
        Dict with ``total_dirs``, ``elapsed_seconds``, and optionally
        ``sd_stats`` if ``collect_sd=True``.
    """
    start = time.monotonic()
    total = 0
    batch: list[dict] = []

    async for folder_info in adapter.list_folders(scan_path, recursive=True):
        row = _folder_info_to_row(folder_info, tenant_id, target_id)
        batch.append(row)

        if len(batch) >= UPSERT_BATCH_SIZE:
            await _upsert_batch(session, batch)
            total += len(batch)
            batch.clear()
            if on_progress:
                on_progress(total)

    # Flush remaining
    if batch:
        await _upsert_batch(session, batch)
        total += len(batch)
        if on_progress:
            on_progress(total)

    await session.flush()

    # Resolve parent_id from filesystem-native parent_inode values
    resolved = await _resolve_parent_ids(session, tenant_id, target_id)

    # Resolve parent_id from path-based parent matching for adapters
    # that don't provide inode data (cloud adapters)
    resolved += await _resolve_parent_ids_by_path(session, tenant_id, target_id)

    # Collect security descriptors (filesystem targets only)
    sd_stats: dict | None = None
    if collect_sd:
        from openlabels.jobs.sd_collect import collect_security_descriptors

        sd_stats = await collect_security_descriptors(
            session=session,
            tenant_id=tenant_id,
            target_id=target_id,
            on_progress=on_sd_progress,
        )

    elapsed = time.monotonic() - start

    logger.info(
        "Bootstrap complete: %d directories indexed, %d parent links resolved in %.1fs",
        total, resolved, elapsed,
    )

    result = {
        "total_dirs": total,
        "parent_links_resolved": resolved,
        "elapsed_seconds": round(elapsed, 2),
    }
    if sd_stats:
        result["sd_stats"] = sd_stats

    return result


def _folder_info_to_row(info: FolderInfo, tenant_id: UUID, target_id: UUID) -> dict:
    """Convert a FolderInfo to a dict suitable for bulk insert."""
    # Compute basename from path if name is empty
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


async def _upsert_batch(session: AsyncSession, rows: list[dict]) -> None:
    """Upsert a batch of directory rows using INSERT ... ON CONFLICT UPDATE."""
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


async def _resolve_parent_ids(
    session: AsyncSession,
    tenant_id: UUID,
    target_id: UUID,
) -> int:
    """Resolve parent_id from parent_ref (inode/MFT-based).

    For filesystem adapters that provide inode numbers, this resolves
    parent_ref → parent_id via a self-join on dir_ref.

    Returns:
        Number of rows updated.
    """
    result = await session.execute(
        text("""
            UPDATE directory_tree AS child
               SET parent_id = parent.id
              FROM directory_tree AS parent
             WHERE child.parent_ref = parent.dir_ref
               AND child.tenant_id = parent.tenant_id
               AND child.target_id = parent.target_id
               AND child.tenant_id = :tenant_id
               AND child.target_id = :target_id
               AND child.parent_id IS NULL
               AND child.parent_ref IS NOT NULL
               AND child.id != parent.id
        """),
        {"tenant_id": tenant_id, "target_id": target_id},
    )
    return result.rowcount


async def _resolve_parent_ids_by_path(
    session: AsyncSession,
    tenant_id: UUID,
    target_id: UUID,
) -> int:
    """Resolve parent_id from path hierarchy.

    For adapters that don't provide inode data (cloud adapters), compute
    parent path by stripping the last path component and matching.

    Returns:
        Number of rows updated.
    """
    # Use a path-based approach: parent of "/a/b/c" is "/a/b"
    # This handles both Unix paths and cloud URI paths.
    # We match on the longest path that is a prefix of the child,
    # which is simply everything before the last '/'.
    result = await session.execute(
        text("""
            UPDATE directory_tree AS child
               SET parent_id = parent.id
              FROM directory_tree AS parent
             WHERE child.tenant_id = :tenant_id
               AND child.target_id = :target_id
               AND parent.tenant_id = :tenant_id
               AND parent.target_id = :target_id
               AND child.parent_id IS NULL
               AND child.id != parent.id
               AND parent.dir_path = CASE
                   -- Handle trailing slash (cloud paths like "s3://bucket/prefix/")
                   WHEN child.dir_path LIKE '%/'
                   THEN regexp_replace(
                       left(child.dir_path, length(child.dir_path) - 1),
                       '/[^/]*$', ''
                   ) || '/'
                   -- Handle no trailing slash (filesystem paths like "/home/user/dir")
                   ELSE regexp_replace(child.dir_path, '/[^/]*$', '')
               END
        """),
        {"tenant_id": tenant_id, "target_id": target_id},
    )
    return result.rowcount


async def get_index_stats(
    session: AsyncSession,
    tenant_id: UUID,
    target_id: UUID,
) -> dict:
    """Get statistics about the directory tree index for a target.

    Returns:
        Dict with ``total_dirs``, ``with_parent_link``, ``with_sd_hash``,
        ``with_share``, ``last_updated``.
    """
    result = await session.execute(
        text("""
            SELECT count(*) AS total_dirs,
                   count(parent_id) AS with_parent_link,
                   count(sd_hash) AS with_sd_hash,
                   count(share_id) AS with_share,
                   max(updated_at) AS last_updated
              FROM directory_tree
             WHERE tenant_id = :tenant_id
               AND target_id = :target_id
        """),
        {"tenant_id": tenant_id, "target_id": target_id},
    )
    row = result.one()
    return {
        "total_dirs": row.total_dirs,
        "with_parent_link": row.with_parent_link,
        "with_sd_hash": row.with_sd_hash,
        "with_share": row.with_share,
        "last_updated": row.last_updated,
    }


async def clear_directory_tree(
    session: AsyncSession,
    tenant_id: UUID,
    target_id: UUID,
) -> int:
    """Delete all directory_tree rows for a target.

    Returns:
        Number of rows deleted.
    """
    result = await session.execute(
        text("""
            DELETE FROM directory_tree
             WHERE tenant_id = :tenant_id
               AND target_id = :target_id
        """),
        {"tenant_id": tenant_id, "target_id": target_id},
    )
    return result.rowcount
