"""Directory tree browse API."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.dependencies import DbSessionDep, TenantContextDep
from openlabels.server.models import DirectoryTree, FileInventory, FolderInventory, SecurityDescriptor

router = APIRouter()


class BrowseFolder(BaseModel):

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

    Omit ``parent_id`` to list root-level directories.
    """
    stmt = (
        select(
            DirectoryTree.id,
            DirectoryTree.dir_path,
            DirectoryTree.dir_name,
            DirectoryTree.child_dir_count,
            DirectoryTree.child_file_count,
            DirectoryTree.dir_modified,
            SecurityDescriptor.world_accessible,
            SecurityDescriptor.authenticated_users,
            SecurityDescriptor.custom_acl,
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

    stmt = stmt.order_by(DirectoryTree.dir_name).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).all()

    parent_path = None
    if parent_id is not None:
        parent_row = (await db.execute(
            select(DirectoryTree.dir_path).where(
                DirectoryTree.id == parent_id,
                DirectoryTree.tenant_id == tenant.tenant_id,
            )
        )).scalar_one_or_none()
        if parent_row:
            parent_path = parent_row

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


class BrowseFile(BaseModel):
    """A single file in a directory listing."""

    id: UUID
    file_path: str
    file_name: str
    file_size: int | None = None
    file_modified: str | None = None
    risk_score: int = 0
    risk_tier: str = "MINIMAL"
    entity_counts: dict[str, int] = {}
    total_entities: int = 0
    exposure_level: str | None = None
    owner: str | None = None
    current_label_name: str | None = None
    last_scanned_at: str | None = None

    model_config = ConfigDict(from_attributes=True)


class BrowseFilesResponse(BaseModel):
    """Response for file listing within a directory."""

    target_id: UUID
    folder_path: str | None = None
    files: list[BrowseFile]
    total: int


@router.get("/{target_id}/files", response_model=BrowseFilesResponse)
async def browse_files(
    target_id: UUID,
    db: DbSessionDep,
    tenant: TenantContextDep,
    folder_path: str | None = Query(None, description="Filter by folder path"),
    risk_tier: str | None = Query(None, description="Filter by risk tier (CRITICAL, HIGH, MEDIUM, LOW, MINIMAL)"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> BrowseFilesResponse:
    """List individual files within a target, optionally filtered by folder path.

    Returns file-level details including risk score, entity counts,
    exposure level, and labeling status from the FileInventory table.
    """
    base_filter = [
        FileInventory.tenant_id == tenant.tenant_id,
        FileInventory.target_id == target_id,
    ]

    if folder_path is not None:
        # Match files whose path starts with the given folder
        # Append / to avoid matching folders that share a prefix
        folder_prefix = folder_path.rstrip("/\\") + "/"
        base_filter.append(FileInventory.file_path.startswith(folder_prefix))

    if risk_tier is not None:
        base_filter.append(FileInventory.risk_tier == risk_tier)

    # Count
    count_stmt = select(func.count()).select_from(
        select(FileInventory.id).where(*base_filter).subquery()
    )
    total = (await db.execute(count_stmt)).scalar() or 0

    # Fetch
    stmt = (
        select(FileInventory)
        .where(*base_filter)
        .order_by(FileInventory.risk_score.desc(), FileInventory.file_name)
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(stmt)).scalars().all()

    files = []
    for f in rows:
        files.append(BrowseFile(
            id=f.id,
            file_path=f.file_path,
            file_name=f.file_name,
            file_size=f.file_size,
            file_modified=f.file_modified.isoformat() if f.file_modified else None,
            risk_score=f.risk_score,
            risk_tier=str(f.risk_tier),
            entity_counts=f.entity_counts or {},
            total_entities=f.total_entities,
            exposure_level=str(f.exposure_level) if f.exposure_level else None,
            owner=f.owner,
            current_label_name=f.current_label_name,
            last_scanned_at=f.last_scanned_at.isoformat() if f.last_scanned_at else None,
        ))

    return BrowseFilesResponse(
        target_id=target_id,
        folder_path=folder_path,
        files=files,
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
