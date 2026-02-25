"""
Permissions Explorer API endpoints.

Provides ACL viewing, exposure analysis, and principal lookup for
the frontend Permissions Explorer feature.

Endpoints:
- GET /exposure                        — Tenant-wide exposure summary
- GET /at-risk                         — Directories with sensitive files AND high exposure
- GET /export                          — Export exposure report as CSV
- GET /{target_id}/directories         — List directories with security descriptors
- GET /{target_id}/tree                — Folder tree with exposure-level badges
- GET /{target_id}/acl/{dir_id}        — Detailed ACL for a specific directory
- GET /{target_id}/acl/{dir_id}/remediation — Remediation actions for a directory
- GET /principal/{principal}           — Find directories accessible by a principal
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select, text

from openlabels.server.dependencies import DbSessionDep, TenantContextDep
from openlabels.server.models import (
    DirectoryTree,
    FolderInventory,
    RemediationAction,
    SecurityDescriptor,
)
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# Response models
class ExposureSummary(BaseModel):
    """Tenant-wide exposure summary across all targets."""

    total_directories: int
    with_security_descriptor: int
    world_accessible: int
    authenticated_users: int
    custom_acl: int
    private: int  # directories with SD but none of the above flags


class DirectoryPermissions(BaseModel):
    """Directory with its security descriptor flags."""

    id: UUID
    dir_path: str
    dir_name: str
    target_id: UUID
    child_dir_count: int | None = None
    child_file_count: int | None = None
    # Security descriptor flags
    world_accessible: bool | None = None
    authenticated_users: bool | None = None
    custom_acl: bool | None = None
    # Derived exposure level
    exposure_level: str  # PUBLIC, ORG_WIDE, INTERNAL, PRIVATE, UNKNOWN

    model_config = ConfigDict(from_attributes=True)


class ACLDetail(BaseModel):
    """Detailed ACL information for a single directory."""

    dir_id: UUID
    dir_path: str
    dir_name: str
    target_id: UUID
    # Raw security descriptor fields
    owner_sid: str | None = None
    group_sid: str | None = None
    dacl_sddl: str | None = None
    permissions_json: dict | None = None
    # Derived flags
    world_accessible: bool = False
    authenticated_users: bool = False
    custom_acl: bool = False
    exposure_level: str = "UNKNOWN"


class PrincipalAccess(BaseModel):
    """A directory accessible by a specific principal."""

    dir_id: UUID
    dir_path: str
    dir_name: str
    target_id: UUID
    permissions: list[str]  # Permissions granted to this principal


class TreeNode(BaseModel):
    """A node in the folder tree with exposure badge."""

    id: UUID
    dir_path: str
    dir_name: str
    exposure_level: str
    child_dir_count: int | None = None
    child_file_count: int | None = None
    children: list[TreeNode] = []


class AtRiskDirectory(BaseModel):
    """Directory with both sensitive files and high exposure."""

    dir_id: UUID
    dir_path: str
    dir_name: str
    target_id: UUID
    exposure_level: str
    has_sensitive_files: bool
    highest_risk_tier: str | None = None
    total_entities_found: int = 0
    child_file_count: int | None = None
    world_accessible: bool | None = None
    authenticated_users: bool | None = None


class DirectoryRemediationAction(BaseModel):
    """A remediation action linked to a directory's files."""

    id: UUID
    action_type: str
    status: str
    source_path: str
    dest_path: str | None = None
    performed_by: str
    label_name: str | None = None
    created_at: datetime | None = None
    completed_at: datetime | None = None


# Helpers
def _exposure_level(
    world_accessible: bool | None,
    authenticated_users: bool | None,
    custom_acl: bool | None,
    sd_exists: bool,
) -> str:
    """Derive exposure level from security descriptor flags."""
    if not sd_exists:
        return "UNKNOWN"
    if world_accessible:
        return "PUBLIC"
    if authenticated_users:
        return "ORG_WIDE"
    if custom_acl:
        return "INTERNAL"
    return "PRIVATE"


# Endpoints
@router.get("/exposure", response_model=ExposureSummary)
async def get_exposure_summary(
    db: DbSessionDep,
    tenant: TenantContextDep,
    target_id: UUID | None = Query(None, description="Scope to a specific target"),
) -> ExposureSummary:
    """
    Get tenant-wide (or target-scoped) exposure summary.

    Counts directories by their exposure level based on security
    descriptor flags.
    """
    conditions = ["d.tenant_id = :tenant_id"]
    params: dict = {"tenant_id": str(tenant.tenant_id)}

    if target_id:
        conditions.append("d.target_id = :target_id")
        params["target_id"] = str(target_id)

    where = " AND ".join(conditions)

    result = await db.execute(
        text(f"""
            SELECT
                count(*)                                                AS total_directories,
                count(sd.sd_hash)                                       AS with_sd,
                count(*) FILTER (WHERE sd.world_accessible = true)      AS world_accessible,
                count(*) FILTER (WHERE sd.authenticated_users = true)   AS authenticated_users,
                count(*) FILTER (WHERE sd.custom_acl = true)            AS custom_acl,
                count(*) FILTER (
                    WHERE sd.sd_hash IS NOT NULL
                      AND sd.world_accessible = false
                      AND sd.authenticated_users = false
                      AND sd.custom_acl = false
                )                                                       AS private_dirs
            FROM directory_tree d
            LEFT JOIN security_descriptors sd ON d.sd_hash = sd.sd_hash
            WHERE {where}
        """),
        params,
    )
    row = result.one()

    return ExposureSummary(
        total_directories=row.total_directories,
        with_security_descriptor=row.with_sd,
        world_accessible=row.world_accessible,
        authenticated_users=row.authenticated_users,
        custom_acl=row.custom_acl,
        private=row.private_dirs,
    )


@router.get(
    "/{target_id}/directories",
    response_model=PaginatedResponse[DirectoryPermissions],
)
async def list_directory_permissions(
    target_id: UUID,
    db: DbSessionDep,
    tenant: TenantContextDep,
    parent_id: UUID | None = Query(None, description="Parent directory ID (omit for roots)"),
    exposure: Literal["PUBLIC", "ORG_WIDE", "INTERNAL", "PRIVATE", "UNKNOWN"] | None = Query(
        None,
        description="Filter by exposure level",
    ),
    pagination: PaginationParams = Depends(),
) -> PaginatedResponse[DirectoryPermissions]:
    """
    List directories with their security descriptor flags for a target.

    Supports filtering by exposure level and parent directory.
    """
    stmt = (
        select(
            DirectoryTree.id,
            DirectoryTree.dir_path,
            DirectoryTree.dir_name,
            DirectoryTree.target_id,
            DirectoryTree.child_dir_count,
            DirectoryTree.child_file_count,
            SecurityDescriptor.world_accessible,
            SecurityDescriptor.authenticated_users,
            SecurityDescriptor.custom_acl,
            SecurityDescriptor.sd_hash.label("has_sd"),
        )
        .outerjoin(SecurityDescriptor, DirectoryTree.sd_hash == SecurityDescriptor.sd_hash)
        .where(DirectoryTree.tenant_id == tenant.tenant_id)
        .where(DirectoryTree.target_id == target_id)
    )

    if parent_id is not None:
        stmt = stmt.where(DirectoryTree.parent_id == parent_id)
    else:
        stmt = stmt.where(DirectoryTree.parent_id.is_(None))

    # Build count query before applying exposure filter that needs post-join logic
    # For exposure filtering, apply at SQL level
    if exposure == "PUBLIC":
        stmt = stmt.where(SecurityDescriptor.world_accessible == True)  # noqa: E712
    elif exposure == "ORG_WIDE":
        stmt = stmt.where(SecurityDescriptor.authenticated_users == True)  # noqa: E712
        stmt = stmt.where(SecurityDescriptor.world_accessible == False)  # noqa: E712
    elif exposure == "INTERNAL":
        stmt = stmt.where(SecurityDescriptor.custom_acl == True)  # noqa: E712
        stmt = stmt.where(SecurityDescriptor.world_accessible == False)  # noqa: E712
        stmt = stmt.where(SecurityDescriptor.authenticated_users == False)  # noqa: E712
    elif exposure == "PRIVATE":
        stmt = stmt.where(SecurityDescriptor.sd_hash.isnot(None))
        stmt = stmt.where(SecurityDescriptor.world_accessible == False)  # noqa: E712
        stmt = stmt.where(SecurityDescriptor.authenticated_users == False)  # noqa: E712
        stmt = stmt.where(SecurityDescriptor.custom_acl == False)  # noqa: E712
    elif exposure == "UNKNOWN":
        stmt = stmt.where(DirectoryTree.sd_hash.is_(None))

    # Count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Paginate
    stmt = stmt.order_by(DirectoryTree.dir_name).offset(pagination.offset).limit(pagination.limit)
    rows = (await db.execute(stmt)).all()

    items = []
    for row in rows:
        has_sd = row.has_sd is not None
        exp = _exposure_level(row.world_accessible, row.authenticated_users, row.custom_acl, has_sd)
        items.append(DirectoryPermissions(
            id=row.id,
            dir_path=row.dir_path,
            dir_name=row.dir_name,
            target_id=row.target_id,
            child_dir_count=row.child_dir_count,
            child_file_count=row.child_file_count,
            world_accessible=row.world_accessible,
            authenticated_users=row.authenticated_users,
            custom_acl=row.custom_acl,
            exposure_level=exp,
        ))

    return PaginatedResponse[DirectoryPermissions](
        **create_paginated_response(
            items=items,
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.get("/{target_id}/acl/{dir_id}", response_model=ACLDetail)
async def get_directory_acl(
    target_id: UUID,
    dir_id: UUID,
    db: DbSessionDep,
    tenant: TenantContextDep,
) -> ACLDetail:
    """
    Get detailed ACL information for a specific directory.

    Returns the full security descriptor including owner, group, DACL,
    and parsed permissions JSON.
    """
    stmt = (
        select(
            DirectoryTree.id,
            DirectoryTree.dir_path,
            DirectoryTree.dir_name,
            DirectoryTree.target_id,
            SecurityDescriptor.owner_sid,
            SecurityDescriptor.group_sid,
            SecurityDescriptor.dacl_sddl,
            SecurityDescriptor.permissions_json,
            SecurityDescriptor.world_accessible,
            SecurityDescriptor.authenticated_users,
            SecurityDescriptor.custom_acl,
            SecurityDescriptor.sd_hash.label("has_sd"),
        )
        .outerjoin(SecurityDescriptor, DirectoryTree.sd_hash == SecurityDescriptor.sd_hash)
        .where(
            DirectoryTree.id == dir_id,
            DirectoryTree.target_id == target_id,
            DirectoryTree.tenant_id == tenant.tenant_id,
        )
    )

    row = (await db.execute(stmt)).one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Directory not found")

    has_sd = row.has_sd is not None
    exp = _exposure_level(row.world_accessible, row.authenticated_users, row.custom_acl, has_sd)

    return ACLDetail(
        dir_id=row.id,
        dir_path=row.dir_path,
        dir_name=row.dir_name,
        target_id=row.target_id,
        owner_sid=row.owner_sid,
        group_sid=row.group_sid,
        dacl_sddl=row.dacl_sddl,
        permissions_json=row.permissions_json,
        world_accessible=row.world_accessible or False,
        authenticated_users=row.authenticated_users or False,
        custom_acl=row.custom_acl or False,
        exposure_level=exp,
    )


@router.get(
    "/principal/{principal}",
    response_model=PaginatedResponse[PrincipalAccess],
)
async def lookup_principal_access(
    principal: str,
    db: DbSessionDep,
    tenant: TenantContextDep,
    target_id: UUID | None = Query(None, description="Scope to a specific target"),
    pagination: PaginationParams = Depends(),
) -> PaginatedResponse[PrincipalAccess]:
    """
    Find all directories accessible by a given principal (SID or name).

    Searches the ``permissions_json`` JSONB field on security descriptors
    for entries matching the principal. Returns directories with the
    specific permissions granted.
    """
    # Build conditions
    conditions = [
        "d.tenant_id = :tenant_id",
        "sd.permissions_json IS NOT NULL",
        "sd.permissions_json ? :principal",  # JSONB ? operator: key exists
    ]
    params: dict = {
        "tenant_id": str(tenant.tenant_id),
        "principal": principal,
    }

    if target_id:
        conditions.append("d.target_id = :target_id")
        params["target_id"] = str(target_id)

    where = " AND ".join(conditions)

    # Count query
    count_result = await db.execute(
        text(f"""
            SELECT count(*) AS cnt
            FROM directory_tree d
            JOIN security_descriptors sd ON d.sd_hash = sd.sd_hash
            WHERE {where}
        """),
        params,
    )
    total = count_result.scalar() or 0

    # Data query
    params["limit"] = pagination.limit
    params["offset"] = pagination.offset
    result = await db.execute(
        text(f"""
            SELECT
                d.id AS dir_id,
                d.dir_path,
                d.dir_name,
                d.target_id,
                sd.permissions_json -> :principal AS principal_perms
            FROM directory_tree d
            JOIN security_descriptors sd ON d.sd_hash = sd.sd_hash
            WHERE {where}
            ORDER BY d.dir_path
            LIMIT :limit OFFSET :offset
        """),
        params,
    )
    rows = result.all()

    items = []
    for row in rows:
        perms = row.principal_perms
        if isinstance(perms, str):
            perms = json.loads(perms)
        if isinstance(perms, list):
            perm_list = perms
        elif isinstance(perms, dict):
            perm_list = list(perms.keys())
        else:
            perm_list = []

        items.append(PrincipalAccess(
            dir_id=row.dir_id,
            dir_path=row.dir_path,
            dir_name=row.dir_name,
            target_id=row.target_id,
            permissions=perm_list,
        ))

    return PaginatedResponse[PrincipalAccess](
        **create_paginated_response(
            items=items,
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.get(
    "/{target_id}/tree",
    response_model=list[TreeNode],
)
async def get_folder_tree(
    target_id: UUID,
    db: DbSessionDep,
    tenant: TenantContextDep,
    parent_id: UUID | None = Query(None, description="Root of subtree (omit for top-level)"),
    depth: int = Query(2, ge=1, le=5, description="Tree depth to return"),
) -> list[TreeNode]:
    """
    Return a folder tree with exposure-level badges.

    Recursively fetches directories up to ``depth`` levels and returns
    them as a nested tree structure. Each node carries its derived
    exposure level so the frontend can render badges.
    """
    stmt = (
        select(
            DirectoryTree.id,
            DirectoryTree.dir_path,
            DirectoryTree.dir_name,
            DirectoryTree.parent_id,
            DirectoryTree.child_dir_count,
            DirectoryTree.child_file_count,
            SecurityDescriptor.world_accessible,
            SecurityDescriptor.authenticated_users,
            SecurityDescriptor.custom_acl,
            SecurityDescriptor.sd_hash.label("has_sd"),
        )
        .outerjoin(SecurityDescriptor, DirectoryTree.sd_hash == SecurityDescriptor.sd_hash)
        .where(DirectoryTree.tenant_id == tenant.tenant_id)
        .where(DirectoryTree.target_id == target_id)
        .order_by(DirectoryTree.dir_name)
    )

    rows = (await db.execute(stmt)).all()

    # Build lookup structures
    nodes_by_id: dict[UUID, TreeNode] = {}
    children_by_parent: dict[UUID | None, list[UUID]] = {}

    for row in rows:
        has_sd = row.has_sd is not None
        exp = _exposure_level(row.world_accessible, row.authenticated_users, row.custom_acl, has_sd)
        node = TreeNode(
            id=row.id,
            dir_path=row.dir_path,
            dir_name=row.dir_name,
            exposure_level=exp,
            child_dir_count=row.child_dir_count,
            child_file_count=row.child_file_count,
        )
        nodes_by_id[row.id] = node
        children_by_parent.setdefault(row.parent_id, []).append(row.id)

    # Recursive tree builder with depth limit
    def _build(parent: UUID | None, current_depth: int) -> list[TreeNode]:
        if current_depth > depth:
            return []
        result = []
        for child_id in children_by_parent.get(parent, []):
            node = nodes_by_id[child_id]
            node.children = _build(child_id, current_depth + 1)
            result.append(node)
        return result

    return _build(parent_id, 1)


@router.get(
    "/at-risk",
    response_model=PaginatedResponse[AtRiskDirectory],
)
async def list_at_risk_directories(
    db: DbSessionDep,
    tenant: TenantContextDep,
    target_id: UUID | None = Query(None, description="Scope to a specific target"),
    min_exposure: Literal["PUBLIC", "ORG_WIDE"] = Query(
        "PUBLIC",
        description="Minimum exposure level to include",
    ),
    pagination: PaginationParams = Depends(),
) -> PaginatedResponse[AtRiskDirectory]:
    """
    List directories that have BOTH sensitive files AND high exposure.

    Joins DirectoryTree → SecurityDescriptor for exposure level and
    DirectoryTree → FolderInventory for sensitive file indicators.
    This highlights the highest-priority remediation targets.
    """
    stmt = (
        select(
            DirectoryTree.id.label("dir_id"),
            DirectoryTree.dir_path,
            DirectoryTree.dir_name,
            DirectoryTree.target_id,
            DirectoryTree.child_file_count,
            SecurityDescriptor.world_accessible,
            SecurityDescriptor.authenticated_users,
            SecurityDescriptor.sd_hash.label("has_sd"),
            FolderInventory.has_sensitive_files,
            FolderInventory.highest_risk_tier,
            FolderInventory.total_entities_found,
        )
        .join(SecurityDescriptor, DirectoryTree.sd_hash == SecurityDescriptor.sd_hash)
        .join(
            FolderInventory,
            (FolderInventory.tenant_id == DirectoryTree.tenant_id)
            & (FolderInventory.target_id == DirectoryTree.target_id)
            & (FolderInventory.folder_path == DirectoryTree.dir_path),
        )
        .where(DirectoryTree.tenant_id == tenant.tenant_id)
        .where(FolderInventory.has_sensitive_files == True)  # noqa: E712
    )

    if target_id:
        stmt = stmt.where(DirectoryTree.target_id == target_id)

    # Filter by exposure level
    if min_exposure == "PUBLIC":
        stmt = stmt.where(SecurityDescriptor.world_accessible == True)  # noqa: E712
    else:  # ORG_WIDE — include both PUBLIC and ORG_WIDE
        stmt = stmt.where(
            (SecurityDescriptor.world_accessible == True)  # noqa: E712
            | (SecurityDescriptor.authenticated_users == True)  # noqa: E712
        )

    # Count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Paginate
    stmt = stmt.order_by(DirectoryTree.dir_path).offset(pagination.offset).limit(pagination.limit)
    rows = (await db.execute(stmt)).all()

    items = []
    for row in rows:
        has_sd = row.has_sd is not None
        exp = _exposure_level(row.world_accessible, row.authenticated_users, None, has_sd)
        items.append(AtRiskDirectory(
            dir_id=row.dir_id,
            dir_path=row.dir_path,
            dir_name=row.dir_name,
            target_id=row.target_id,
            exposure_level=exp,
            has_sensitive_files=row.has_sensitive_files,
            highest_risk_tier=str(row.highest_risk_tier) if row.highest_risk_tier else None,
            total_entities_found=row.total_entities_found or 0,
            child_file_count=row.child_file_count,
            world_accessible=row.world_accessible,
            authenticated_users=row.authenticated_users,
        ))

    return PaginatedResponse[AtRiskDirectory](
        **create_paginated_response(
            items=items,
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.get(
    "/{target_id}/acl/{dir_id}/remediation",
    response_model=list[DirectoryRemediationAction],
)
async def list_directory_remediation(
    target_id: UUID,
    dir_id: UUID,
    db: DbSessionDep,
    tenant: TenantContextDep,
    limit: int = Query(50, ge=1, le=200),
) -> list[DirectoryRemediationAction]:
    """
    List remediation actions linked to files within a directory.

    Finds all remediation_actions whose ``source_path`` starts with the
    directory's path, allowing security auditors to see what actions
    have already been taken on over-exposed directories.
    """
    # Resolve directory path
    dir_row = (
        await db.execute(
            select(DirectoryTree.dir_path).where(
                DirectoryTree.id == dir_id,
                DirectoryTree.target_id == target_id,
                DirectoryTree.tenant_id == tenant.tenant_id,
            )
        )
    ).scalar_one_or_none()

    if dir_row is None:
        raise HTTPException(status_code=404, detail="Directory not found")

    dir_path = dir_row
    # Append separator to avoid prefix collisions (e.g. /data matching /data2)
    path_prefix = dir_path.rstrip("/\\") + "/"

    # Find remediation actions for files under this directory
    stmt = (
        select(RemediationAction)
        .where(
            RemediationAction.tenant_id == tenant.tenant_id,
            (RemediationAction.source_path.startswith(path_prefix))
            | (RemediationAction.source_path == dir_path),
        )
        .order_by(RemediationAction.created_at.desc())
        .limit(limit)
    )

    rows = (await db.execute(stmt)).scalars().all()

    return [
        DirectoryRemediationAction(
            id=a.id,
            action_type=a.action_type,
            status=a.status,
            source_path=a.source_path,
            dest_path=a.dest_path,
            performed_by=a.performed_by,
            label_name=a.label_name,
            created_at=a.created_at,
            completed_at=a.completed_at,
        )
        for a in rows
    ]


@router.get("/export")
async def export_exposure_report(
    db: DbSessionDep,
    tenant: TenantContextDep,
    target_id: UUID | None = Query(None, description="Scope to a specific target"),
    exposure: Literal["PUBLIC", "ORG_WIDE", "INTERNAL", "PRIVATE", "UNKNOWN"] | None = Query(
        None,
        description="Filter by exposure level",
    ),
) -> StreamingResponse:
    """
    Export an exposure report as CSV.

    Each row contains a directory, its exposure level, security descriptor
    flags, owner, and folder-level sensitivity indicators. Suitable for
    compliance reporting and offline analysis.
    """
    conditions = ["d.tenant_id = :tenant_id"]
    params: dict = {"tenant_id": str(tenant.tenant_id)}

    if target_id:
        conditions.append("d.target_id = :target_id")
        params["target_id"] = str(target_id)

    if exposure == "PUBLIC":
        conditions.append("sd.world_accessible = true")
    elif exposure == "ORG_WIDE":
        conditions.append("sd.authenticated_users = true")
        conditions.append("sd.world_accessible = false")
    elif exposure == "INTERNAL":
        conditions.append("sd.custom_acl = true")
        conditions.append("sd.world_accessible = false")
        conditions.append("sd.authenticated_users = false")
    elif exposure == "PRIVATE":
        conditions.append("sd.sd_hash IS NOT NULL")
        conditions.append("sd.world_accessible = false")
        conditions.append("sd.authenticated_users = false")
        conditions.append("sd.custom_acl = false")
    elif exposure == "UNKNOWN":
        conditions.append("d.sd_hash IS NULL")

    where = " AND ".join(conditions)

    result = await db.execute(
        text(f"""
            SELECT
                d.dir_path,
                d.dir_name,
                d.target_id,
                d.child_dir_count,
                d.child_file_count,
                sd.owner_sid,
                sd.group_sid,
                sd.world_accessible,
                sd.authenticated_users,
                sd.custom_acl,
                fi.has_sensitive_files,
                fi.highest_risk_tier,
                fi.total_entities_found
            FROM directory_tree d
            LEFT JOIN security_descriptors sd ON d.sd_hash = sd.sd_hash
            LEFT JOIN folder_inventory fi
                ON fi.tenant_id = d.tenant_id
                AND fi.target_id = d.target_id
                AND fi.folder_path = d.dir_path
            WHERE {where}
            ORDER BY d.dir_path
        """),
        params,
    )
    rows = result.all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "dir_path",
        "dir_name",
        "target_id",
        "exposure_level",
        "owner_sid",
        "group_sid",
        "world_accessible",
        "authenticated_users",
        "custom_acl",
        "child_dir_count",
        "child_file_count",
        "has_sensitive_files",
        "highest_risk_tier",
        "total_entities_found",
    ])

    for row in rows:
        has_sd = row.world_accessible is not None or row.authenticated_users is not None
        exp = _exposure_level(row.world_accessible, row.authenticated_users, row.custom_acl, has_sd)
        writer.writerow([
            row.dir_path,
            row.dir_name,
            str(row.target_id),
            exp,
            row.owner_sid or "",
            row.group_sid or "",
            row.world_accessible if row.world_accessible is not None else "",
            row.authenticated_users if row.authenticated_users is not None else "",
            row.custom_acl if row.custom_acl is not None else "",
            row.child_dir_count if row.child_dir_count is not None else "",
            row.child_file_count if row.child_file_count is not None else "",
            row.has_sensitive_files if row.has_sensitive_files is not None else "",
            str(row.highest_risk_tier) if row.highest_risk_tier else "",
            row.total_entities_found if row.total_entities_found is not None else "",
        ])

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=exposure_report.csv"},
    )
