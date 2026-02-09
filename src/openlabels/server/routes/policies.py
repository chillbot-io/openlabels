"""
Policy management API endpoints (Phase J).

Provides:
- CRUD for tenant-scoped policies
- List built-in policy packs
- Load a built-in pack into tenant
- Dry-run evaluation against existing scan results
- Compliance statistics
"""

from __future__ import annotations

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)
from openlabels.server.dependencies import (
    AdminContextDep,
    DbSessionDep,
    TenantContextDep,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Request / Response models ───────────────────────────────────────


class PolicyResponse(BaseModel):
    """Policy resource representation."""

    id: UUID
    name: str
    description: Optional[str] = None
    framework: str
    risk_level: str
    enabled: bool
    config: dict
    priority: int

    class Config:
        from_attributes = True


class PolicyCreate(BaseModel):
    """Request to create a custom policy."""

    name: str = Field(..., max_length=255)
    description: Optional[str] = None
    framework: str = Field(..., max_length=50)
    risk_level: str = Field("high", max_length=20)
    enabled: bool = True
    config: dict = Field(..., description="Full PolicyPack definition as JSON")
    priority: int = 0


class PolicyUpdate(BaseModel):
    """Request to update a policy (partial)."""

    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    framework: Optional[str] = Field(None, max_length=50)
    risk_level: Optional[str] = Field(None, max_length=20)
    enabled: Optional[bool] = None
    config: Optional[dict] = None
    priority: Optional[int] = None


class PolicyToggle(BaseModel):
    """Request to enable/disable a policy."""

    enabled: bool


class BuiltinPackResponse(BaseModel):
    """Metadata for a built-in policy pack."""

    name: str
    description: str
    framework: str
    risk_level: str


class LoadPackRequest(BaseModel):
    """Request to load a built-in pack."""

    pack_name: str


class EvaluateRequest(BaseModel):
    """Dry-run evaluation request."""

    job_id: Optional[UUID] = None
    result_ids: Optional[list[UUID]] = None
    limit: int = Field(100, ge=1, le=500)


class EvaluateResultItem(BaseModel):
    """Single result from dry-run evaluation."""

    result_id: str
    file_path: str
    risk_tier: str
    violations: list[dict]


class ComplianceStatsResponse(BaseModel):
    """Compliance statistics."""

    total_results: int
    results_with_violations: int
    compliance_pct: float
    violations_by_framework: dict[str, int]
    violations_by_severity: dict[str, int]


# ── Dependency ──────────────────────────────────────────────────────

async def _get_policy_service(
    db: DbSessionDep,
    tenant: TenantContextDep,
):
    """Inline dependency — avoids circular import with dependencies.py."""
    from openlabels.server.services.policy_service import PolicyService
    from openlabels.server.services.base import TenantContext as ServiceTenantContext
    from openlabels.server.config import get_settings

    svc_tenant = ServiceTenantContext(
        tenant_id=tenant.tenant_id,
        user_id=tenant.user_id,
        user_email=tenant.user_email,
        user_role="admin" if tenant.is_admin else "viewer",
    )
    return PolicyService(db, svc_tenant, get_settings())


PolicyServiceDep = Depends(_get_policy_service)


# ── Collection endpoints (no path params) ───────────────────────────


@router.get("", response_model=PaginatedResponse[PolicyResponse])
async def list_policies(
    _tenant: TenantContextDep,
    svc=PolicyServiceDep,
    pagination: PaginationParams = Depends(),
    framework: Optional[str] = Query(None),
    enabled_only: bool = Query(False),
):
    """List policies for the current tenant."""
    items, total = await svc.list_policies(
        framework=framework,
        enabled_only=enabled_only,
        limit=pagination.limit,
        offset=pagination.offset,
    )
    return PaginatedResponse[PolicyResponse](
        **create_paginated_response(
            items=[PolicyResponse.model_validate(p) for p in items],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.post("", response_model=PolicyResponse, status_code=201)
async def create_policy(
    request: PolicyCreate,
    _admin: AdminContextDep,
    svc=PolicyServiceDep,
):
    """Create a custom policy."""
    policy = await svc.create_policy(request.model_dump())
    await svc.commit()
    return PolicyResponse.model_validate(policy)


# ── Static sub-paths (must come BEFORE /{policy_id}) ────────────────


@router.get("/builtins", response_model=list[BuiltinPackResponse])
async def list_builtin_packs(
    _tenant: TenantContextDep,
    svc=PolicyServiceDep,
):
    """List available built-in policy packs."""
    packs = await svc.list_builtin_packs()
    return [BuiltinPackResponse(**p) for p in packs]


@router.post("/builtins/load", response_model=PolicyResponse, status_code=201)
async def load_builtin_pack(
    request: LoadPackRequest,
    _admin: AdminContextDep,
    svc=PolicyServiceDep,
):
    """Load a built-in policy pack into the tenant's active policies."""
    policy = await svc.load_builtin_pack(request.pack_name)
    await svc.commit()
    return PolicyResponse.model_validate(policy)


@router.post("/evaluate", response_model=list[EvaluateResultItem])
async def evaluate_policies(
    request: EvaluateRequest,
    _tenant: TenantContextDep,
    svc=PolicyServiceDep,
):
    """Dry-run: evaluate existing scan results against the tenant's active policies.

    Does **not** persist any changes — returns the evaluation output for review.
    """
    results = await svc.evaluate_results(
        job_id=request.job_id,
        result_ids=request.result_ids,
        limit=request.limit,
    )
    return [EvaluateResultItem(**r) for r in results]


@router.get("/compliance/stats", response_model=ComplianceStatsResponse)
async def compliance_stats(
    _tenant: TenantContextDep,
    svc=PolicyServiceDep,
):
    """Get compliance statistics for the current tenant."""
    stats = await svc.compliance_stats()
    return ComplianceStatsResponse(**stats)


# ── Per-policy endpoints (/{policy_id} must come LAST) ──────────────


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: UUID,
    _tenant: TenantContextDep,
    svc=PolicyServiceDep,
):
    """Get a specific policy by ID."""
    policy = await svc.get_policy(policy_id)
    return PolicyResponse.model_validate(policy)


@router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: UUID,
    request: PolicyUpdate,
    _admin: AdminContextDep,
    svc=PolicyServiceDep,
):
    """Update an existing policy."""
    data = request.model_dump(exclude_unset=True)
    policy = await svc.update_policy(policy_id, data)
    await svc.commit()
    return PolicyResponse.model_validate(policy)


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: UUID,
    _admin: AdminContextDep,
    svc=PolicyServiceDep,
):
    """Delete a policy."""
    await svc.delete_policy(policy_id)
    await svc.commit()


@router.patch("/{policy_id}/toggle", response_model=PolicyResponse)
async def toggle_policy(
    policy_id: UUID,
    request: PolicyToggle,
    _admin: AdminContextDep,
    svc=PolicyServiceDep,
):
    """Enable or disable a policy."""
    policy = await svc.toggle_policy(policy_id, request.enabled)
    await svc.commit()
    return PolicyResponse.model_validate(policy)
