"""Security descriptor collection service.

Walks the ``directory_tree`` table and collects filesystem permissions
for each directory, populating the ``security_descriptors`` table and
linking via ``directory_tree.sd_hash``.

Design:
  - **Separate pass**: SD collection runs *after* the bootstrap walk
    so the hot path (directory enumeration) isn't burdened with per-dir
    ``GetFileSecurity`` / ``stat`` calls.
  - **Deduplication**: A typical volume has 3K–50K unique permission
    sets shared across millions of directories.  We SHA-256 hash the
    canonical form and only INSERT new hashes.
  - **Platform support**: Linux (uid/gid/mode) first, Windows NTFS
    (DACL/SDDL) when ``win32security`` is available.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import stat as stat_mod
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from sqlalchemy import text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import DirectoryTree, SecurityDescriptor

logger = logging.getLogger(__name__)

# Batch size for reading dir_paths from DB and for SD upserts
_READ_BATCH = 5000
_UPSERT_BATCH = 2000


# ── Canonical form & hashing ────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SDInfo:
    """Canonical security descriptor for a single directory."""

    owner_sid: str | None  # uid string (Linux) or SID string (Windows)
    group_sid: str | None  # gid string (Linux) or SID string (Windows)
    dacl_sddl: str | None  # POSIX mode string or SDDL
    permissions_json: dict | None  # Structured permission data
    world_accessible: bool
    authenticated_users: bool
    custom_acl: bool

    def canonical_bytes(self) -> bytes:
        """Return a deterministic byte string for hashing.

        The canonical form is a JSON object with sorted keys.  Two
        directories sharing identical permissions will produce the
        same bytes (and therefore the same SHA-256 hash).
        """
        obj = {
            "owner": self.owner_sid,
            "group": self.group_sid,
            "dacl": self.dacl_sddl,
            "wa": self.world_accessible,
            "au": self.authenticated_users,
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

    def sd_hash(self) -> bytes:
        """SHA-256 of the canonical form (32 bytes)."""
        return hashlib.sha256(self.canonical_bytes()).digest()


# ── Platform collectors ─────────────────────────────────────────────


def collect_posix_sd(dir_path: str) -> SDInfo | None:
    """Collect POSIX security info (uid, gid, mode) for a directory.

    Returns None if the path is inaccessible.
    """
    try:
        st = os.stat(dir_path)
    except (OSError, PermissionError):
        return None

    uid = st.st_uid
    gid = st.st_gid
    mode = st.st_mode

    # Determine flags
    other_read = bool(mode & stat_mod.S_IROTH)
    group_read = bool(mode & stat_mod.S_IRGRP)
    other_write = bool(mode & stat_mod.S_IWOTH)

    # world_accessible: "other" has read (or write) access
    world_accessible = other_read or other_write

    # authenticated_users: "group" has read access (rough analog)
    authenticated_users = group_read and not world_accessible

    # custom_acl: check for POSIX ACLs beyond standard uid/gid/mode
    custom_acl = _has_posix_acl(dir_path)

    mode_str = oct(mode & 0o7777)  # e.g. "0o755"

    # Owner/group resolution (best-effort)
    owner_str = str(uid)
    group_str = str(gid)
    try:
        import pwd
        owner_str = pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        pass
    try:
        import grp
        group_str = grp.getgrgid(gid).gr_name
    except (ImportError, KeyError):
        pass

    permissions = {
        "uid": uid,
        "gid": gid,
        "mode": mode_str,
        "owner_read": bool(mode & stat_mod.S_IRUSR),
        "owner_write": bool(mode & stat_mod.S_IWUSR),
        "owner_exec": bool(mode & stat_mod.S_IXUSR),
        "group_read": group_read,
        "group_write": bool(mode & stat_mod.S_IWGRP),
        "group_exec": bool(mode & stat_mod.S_IXGRP),
        "other_read": other_read,
        "other_write": other_write,
        "other_exec": bool(mode & stat_mod.S_IXOTH),
    }

    return SDInfo(
        owner_sid=owner_str,
        group_sid=group_str,
        dacl_sddl=mode_str,
        permissions_json=permissions,
        world_accessible=world_accessible,
        authenticated_users=authenticated_users,
        custom_acl=custom_acl,
    )


def _has_posix_acl(dir_path: str) -> bool:
    """Check if a directory has extended POSIX ACLs (beyond uid/gid/mode)."""
    try:
        import posix1e  # pylibacl

        acl = posix1e.ACL(file=dir_path)
        # Standard POSIX has 3 entries (user, group, other).
        # If there are more, there's an extended ACL.
        entry_count = sum(1 for _ in acl)
        return entry_count > 3
    except (ImportError, OSError):
        return False


def collect_windows_sd(dir_path: str) -> SDInfo | None:
    """Collect Windows NTFS security descriptor for a directory.

    Returns None if win32security is unavailable or the path is
    inaccessible.
    """
    try:
        import win32security
    except ImportError:
        return None

    try:
        sd = win32security.GetFileSecurity(
            dir_path,
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.GROUP_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION,
        )
    except (OSError, PermissionError):
        return None

    # Owner & group SIDs
    owner_sid = win32security.ConvertSidToStringSid(
        sd.GetSecurityDescriptorOwner()
    )
    group_sid = win32security.ConvertSidToStringSid(
        sd.GetSecurityDescriptorGroup()
    )

    # SDDL string for the full descriptor
    sddl = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
        sd,
        win32security.SDDL_REVISION_1,
        win32security.DACL_SECURITY_INFORMATION,
    )

    # Analyze DACL for flags
    dacl = sd.GetSecurityDescriptorDacl()
    world_accessible = False
    authenticated_users = False
    custom_acl = False

    if dacl:
        everyone_sid_str = "S-1-1-0"
        auth_users_sid_str = "S-1-5-11"

        aces = []
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            sid = ace[2]
            sid_str = win32security.ConvertSidToStringSid(sid)
            aces.append({"sid": sid_str, "mask": ace[1]})

            if sid_str == everyone_sid_str:
                world_accessible = True
            elif sid_str == auth_users_sid_str:
                authenticated_users = True

            # Check for non-inherited explicit ACE (custom)
            ace_flags = ace[0][1]
            INHERITED_ACE = 0x10
            if not (ace_flags & INHERITED_ACE):
                custom_acl = True

    return SDInfo(
        owner_sid=owner_sid,
        group_sid=group_sid,
        dacl_sddl=sddl,
        permissions_json={"aces": aces} if dacl else None,
        world_accessible=world_accessible,
        authenticated_users=authenticated_users,
        custom_acl=custom_acl,
    )


def collect_sd(dir_path: str) -> SDInfo | None:
    """Auto-detect platform and collect security descriptor."""
    if platform.system() == "Windows":
        return collect_windows_sd(dir_path)
    return collect_posix_sd(dir_path)


# ── Batch collection helpers ────────────────────────────────────────


def _collect_batch_sync(paths: list[str]) -> list[tuple[str, SDInfo]]:
    """Collect SDs for a batch of paths (synchronous, runs in thread).

    Returns list of (dir_path, sd_info) pairs for paths that succeeded.
    """
    results = []
    for p in paths:
        sd = collect_sd(p)
        if sd is not None:
            results.append((p, sd))
    return results


# ── Main async entry point ──────────────────────────────────────────


async def collect_security_descriptors(
    session: AsyncSession,
    tenant_id: UUID,
    target_id: UUID,
    on_progress: Callable[[int, int], None] | None = None,
) -> dict:
    """Collect security descriptors for all directories in a target.

    Reads ``directory_tree`` rows (those without an ``sd_hash``),
    collects filesystem permissions, deduplicates, and writes to
    ``security_descriptors`` + updates ``directory_tree.sd_hash``.

    Args:
        session: Active async database session.
        tenant_id: Tenant UUID.
        target_id: Scan target UUID.
        on_progress: Optional ``(processed, total)`` callback.

    Returns:
        Dict with ``total_dirs``, ``unique_sds``, ``world_accessible``,
        ``elapsed_seconds``.
    """
    import asyncio

    start = time.monotonic()

    # Count dirs needing SD collection
    count_result = await session.execute(
        text("""
            SELECT count(*) FROM directory_tree
             WHERE tenant_id = :tenant_id
               AND target_id = :target_id
               AND sd_hash IS NULL
        """),
        {"tenant_id": tenant_id, "target_id": target_id},
    )
    total_dirs = count_result.scalar() or 0

    if total_dirs == 0:
        logger.info("All directories already have security descriptors.")
        return {
            "total_dirs": 0,
            "unique_sds": 0,
            "world_accessible": 0,
            "elapsed_seconds": 0.0,
        }

    logger.info("Collecting security descriptors for %d directories...", total_dirs)

    # Track unique SDs across all batches (in-memory — typically <50K)
    seen_hashes: set[bytes] = set()
    sd_rows: list[dict] = []  # Pending SD upserts
    update_rows: list[dict] = []  # Pending directory_tree sd_hash updates
    processed = 0
    world_accessible_count = 0
    offset = 0

    while True:
        # Read a batch of dir_paths that need SD collection
        result = await session.execute(
            text("""
                SELECT id, dir_path FROM directory_tree
                 WHERE tenant_id = :tenant_id
                   AND target_id = :target_id
                   AND sd_hash IS NULL
                 ORDER BY dir_path
                 LIMIT :limit OFFSET :offset
            """),
            {
                "tenant_id": tenant_id,
                "target_id": target_id,
                "limit": _READ_BATCH,
                "offset": offset,
            },
        )
        rows = result.all()
        if not rows:
            break

        paths = [r.dir_path for r in rows]
        id_by_path = {r.dir_path: r.id for r in rows}

        # Collect SDs in a thread (blocking I/O)
        collected = await asyncio.to_thread(_collect_batch_sync, paths)

        for dir_path, sd_info in collected:
            h = sd_info.sd_hash()
            dir_id = id_by_path[dir_path]

            # Track world-accessible
            if sd_info.world_accessible:
                world_accessible_count += 1

            # Queue directory_tree update
            update_rows.append({"dir_id": dir_id, "sd_hash": h})

            # Queue new SD if not seen before
            if h not in seen_hashes:
                seen_hashes.add(h)
                sd_rows.append({
                    "sd_hash": h,
                    "tenant_id": tenant_id,
                    "owner_sid": sd_info.owner_sid,
                    "group_sid": sd_info.group_sid,
                    "dacl_sddl": sd_info.dacl_sddl,
                    "permissions_json": sd_info.permissions_json,
                    "world_accessible": sd_info.world_accessible,
                    "authenticated_users": sd_info.authenticated_users,
                    "custom_acl": sd_info.custom_acl,
                })

            # Flush SD upserts when batch is full
            if len(sd_rows) >= _UPSERT_BATCH:
                await _upsert_sd_batch(session, sd_rows)
                sd_rows.clear()

            # Flush directory_tree updates when batch is full
            if len(update_rows) >= _UPSERT_BATCH:
                await _update_dirtree_hashes(session, update_rows)
                update_rows.clear()

        processed += len(rows)
        offset += len(rows)

        if on_progress:
            on_progress(processed, total_dirs)

    # Flush remaining
    if sd_rows:
        await _upsert_sd_batch(session, sd_rows)
    if update_rows:
        await _update_dirtree_hashes(session, update_rows)

    await session.flush()

    elapsed = time.monotonic() - start
    unique_count = len(seen_hashes)

    logger.info(
        "SD collection complete: %d dirs processed, %d unique SDs, "
        "%d world-accessible in %.1fs",
        processed, unique_count, world_accessible_count, elapsed,
    )

    return {
        "total_dirs": processed,
        "unique_sds": unique_count,
        "world_accessible": world_accessible_count,
        "elapsed_seconds": round(elapsed, 2),
    }


async def _upsert_sd_batch(session: AsyncSession, rows: list[dict]) -> None:
    """Upsert security descriptors (INSERT ... ON CONFLICT skip)."""
    stmt = pg_insert(SecurityDescriptor.__table__).values(rows)
    # If the sd_hash already exists, do nothing (it's content-addressed)
    stmt = stmt.on_conflict_do_nothing(index_elements=["sd_hash"])
    await session.execute(stmt)


async def _update_dirtree_hashes(session: AsyncSession, rows: list[dict]) -> None:
    """Batch-update directory_tree.sd_hash for collected directories.

    Uses a VALUES-based UPDATE join for efficiency.
    """
    if not rows:
        return

    # Build a VALUES clause and join-update
    # This is more efficient than individual UPDATEs
    values_sql = ", ".join(
        f"(:id_{i}::uuid, :hash_{i}::bytea)"
        for i in range(len(rows))
    )
    params = {}
    for i, row in enumerate(rows):
        params[f"id_{i}"] = row["dir_id"]
        params[f"hash_{i}"] = row["sd_hash"]

    await session.execute(
        text(f"""
            UPDATE directory_tree AS dt
               SET sd_hash = v.sd_hash,
                   updated_at = now()
              FROM (VALUES {values_sql}) AS v(id, sd_hash)
             WHERE dt.id = v.id
        """),
        params,
    )


async def get_sd_stats(
    session: AsyncSession,
    tenant_id: UUID,
    target_id: UUID,
) -> dict:
    """Get security descriptor statistics for a target.

    Returns:
        Dict with ``unique_sds``, ``world_accessible``, ``custom_acl``,
        ``authenticated_users``.
    """
    result = await session.execute(
        text("""
            SELECT count(DISTINCT sd.sd_hash) AS unique_sds,
                   count(DISTINCT sd.sd_hash) FILTER (WHERE sd.world_accessible) AS world_accessible,
                   count(DISTINCT sd.sd_hash) FILTER (WHERE sd.custom_acl) AS custom_acl,
                   count(DISTINCT sd.sd_hash) FILTER (WHERE sd.authenticated_users) AS authenticated_users
              FROM directory_tree dt
              JOIN security_descriptors sd ON dt.sd_hash = sd.sd_hash
             WHERE dt.tenant_id = :tenant_id
               AND dt.target_id = :target_id
        """),
        {"tenant_id": tenant_id, "target_id": target_id},
    )
    row = result.one()
    return {
        "unique_sds": row.unique_sds,
        "world_accessible": row.world_accessible,
        "custom_acl": row.custom_acl,
        "authenticated_users": row.authenticated_users,
    }
