"""
Permissions Explorer API endpoints.

Provides ACL viewing, exposure analysis, and principal lookup for
the frontend Permissions Explorer feature.

Endpoints:
- GET /exposure                — Tenant-wide exposure summary
- GET /{target_id}/directories — List directories with security descriptors
- GET /{target_id}/acl/{dir_id} — Detailed ACL for a specific directory
- GET /principal/{principal}   — Find directories accessible by a principal
"""

from __future__ import annotations

import json
import logging
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select, text

from openlabels.server.dependencies import DbSessionDep, TenantContextDep
from openlabels.server.models import DirectoryTree, SecurityDescriptor
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
