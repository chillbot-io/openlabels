"""Directory tree browse API.

Provides tree-navigation endpoints backed by the ``directory_tree``
table.  Each response includes child counts, permission flags (from
``security_descriptors``), and scan-time risk state (from
``folder_inventory``) so the UI can render a complete tree view
without filesystem round-trips.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.dependencies import DbSessionDep, TenantContextDep
from openlabels.server.models import DirectoryTree, FolderInventory, SecurityDescriptor

router = APIRouter()


# ── Response models ──────────────────────────────────────────────────

class BrowseFolder(BaseModel):
    """A single directory entry in a browse response."""

    id: UUID
    dir_path: str
    dir_name: str
    child_dir_count: int | None = None
    child_file_count: int | None = None
    dir_modified: str | None = None

    # Security descriptor (joined)
    world_accessible: bool | None = None
    authenticated_users: bool | None = None
    custom_acl: bool | None = None

    # Scan state (joined from folder_inventory)
    has_sensitive_files: bool | None = None
    highest_risk_tier: str | None = None
    total_entities_found: int | None = None
    last_scanned_at: str | None = None

    model_config = ConfigDict(from_attributes=True)


class BrowseResponse(BaseModel):
    """Response for a directory tree browse request."""

    target_id: UUID
    parent_id: UUID | None = None
    parent_path: str | None = None
    folders: list[BrowseFolder]
    total: int


class TreeStatsResponse(BaseModel):
    """Summary statistics for a target's directory tree."""

    target_id: UUID
    total_dirs: int
    with_parent_link: int
    with_sd_hash: int
    with_share: int
    world_accessible_dirs: int
    last_updated: str | None = None


# ── Endpoints ────────────────────────────────────────────────────────

@router.get("/{target_id}", response_model=BrowseResponse)
async def browse_folders(
    target_id: UUID,
    db: DbSessionDep,
    tenant: TenantContextDep,
    parent_id: UUID | None = Query(None, description="Parent directory ID (omit for root directories)"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> BrowseResponse:
    """List child directories of a given parent.

    Omit ``parent_id`` to list root-level directories (those with no parent).
    Joins to ``security_descriptors`` and ``folder_inventory`` for inline
    permission and risk data.
    """
    # Build the base query
    stmt = (
        select(
            DirectoryTree.id,
            DirectoryTree.dir_path,
            DirectoryTree.dir_name,
            DirectoryTree.child_dir_count,
            DirectoryTree.child_file_count,
            DirectoryTree.dir_modified,
            # Security descriptor flags
            SecurityDescriptor.world_accessible,
            SecurityDescriptor.authenticated_users,
            SecurityDescriptor.custom_acl,
            # Folder inventory scan state
            FolderInventory.has_sensitive_files,
            FolderInventory.highest_risk_tier,
            FolderInventory.total_entities_found,
            FolderInventory.last_scanned_at,
        )
        .outerjoin(
            SecurityDescriptor,
            DirectoryTree.sd_hash == SecurityDescriptor.sd_hash,
        )
        .outerjoin(
            FolderInventory,
            (FolderInventory.tenant_id == DirectoryTree.tenant_id)
            & (FolderInventory.target_id == DirectoryTree.target_id)
            & (FolderInventory.folder_path == DirectoryTree.dir_path),
        )
        .where(DirectoryTree.tenant_id == tenant.tenant_id)
        .where(DirectoryTree.target_id == target_id)
    )

    if parent_id is not None:
        stmt = stmt.where(DirectoryTree.parent_id == parent_id)
    else:
        stmt = stmt.where(DirectoryTree.parent_id.is_(None))

    # Count total before pagination
    count_stmt = select(func.count()).select_from(
        select(DirectoryTree.id)
        .where(DirectoryTree.tenant_id == tenant.tenant_id)
        .where(DirectoryTree.target_id == target_id)
        .where(
            DirectoryTree.parent_id == parent_id
            if parent_id is not None
            else DirectoryTree.parent_id.is_(None)
        )
        .subquery()
    )
    total = (await db.execute(count_stmt)).scalar() or 0

    # Fetch page
    stmt = stmt.order_by(DirectoryTree.dir_name).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).all()

    # Look up parent path if parent_id provided
    parent_path = None
    if parent_id is not None:
        parent_row = await db.get(DirectoryTree, parent_id)
        if parent_row:
            parent_path = parent_row.dir_path

    folders = []
    for row in rows:
        folders.append(BrowseFolder(
            id=row.id,
            dir_path=row.dir_path,
            dir_name=row.dir_name,
            child_dir_count=row.child_dir_count,
            child_file_count=row.child_file_count,
            dir_modified=row.dir_modified.isoformat() if row.dir_modified else None,
            world_accessible=row.world_accessible,
            authenticated_users=row.authenticated_users,
            custom_acl=row.custom_acl,
            has_sensitive_files=row.has_sensitive_files,
            highest_risk_tier=str(row.highest_risk_tier) if row.highest_risk_tier else None,
            total_entities_found=row.total_entities_found,
            last_scanned_at=row.last_scanned_at.isoformat() if row.last_scanned_at else None,
        ))

    return BrowseResponse(
        target_id=target_id,
        parent_id=parent_id,
        parent_path=parent_path,
        folders=folders,
        total=total,
    )


@router.get("/{target_id}/stats", response_model=TreeStatsResponse)
async def tree_stats(
    target_id: UUID,
    db: DbSessionDep,
    tenant: TenantContextDep,
) -> TreeStatsResponse:
    """Get summary statistics for a target's directory tree index."""
    result = await db.execute(
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
        {"tenant_id": tenant.tenant_id, "target_id": target_id},
    )
    row = result.one()

    # Count world-accessible directories
    wa_result = await db.execute(
        text("""
            SELECT count(*) AS cnt
              FROM directory_tree d
              JOIN security_descriptors sd ON d.sd_hash = sd.sd_hash
             WHERE d.tenant_id = :tenant_id
               AND d.target_id = :target_id
               AND sd.world_accessible = true
        """),
        {"tenant_id": tenant.tenant_id, "target_id": target_id},
    )
    wa_count = wa_result.scalar() or 0

    return TreeStatsResponse(
        target_id=target_id,
        total_dirs=row.total_dirs,
        with_parent_link=row.with_parent_link,
        with_sd_hash=row.with_sd_hash,
        with_share=row.with_share,
        world_accessible_dirs=wa_count,
        last_updated=row.last_updated.isoformat() if row.last_updated else None,
    )
