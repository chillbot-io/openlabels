"""
Policy management API endpoints (Phase J / Story 8).

Provides:
- CRUD for tenant-scoped policies
- Rule builder (trigger management)
- Co-occurrence combination rules
- Exposure-based scoring multipliers
- Policy-to-target assignment
- List built-in policy packs
- Load a built-in pack into tenant
- Dry-run evaluation / simulation against existing scan results
- Import / export policy definitions
- Compliance statistics
"""

from __future__ import annotations

import logging
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from openlabels.server.dependencies import (
    AdminContextDep,
    DbSessionDep,
    TenantContextDep,
)
from openlabels.server.routes import audit_log
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helper: compute rule_count from config triggers
# ---------------------------------------------------------------------------

def _count_rules(config: dict) -> int:
    """Count the number of trigger rules in a policy config."""
    triggers = config.get("triggers", {})
    if not isinstance(triggers, dict):
        return 0
    count = 0
    count += len(triggers.get("any_of", []))
    count += len(triggers.get("all_of", []))
    count += len(triggers.get("combinations", []))
    return count


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class PolicyResponse(BaseModel):
    """Policy resource representation."""

    id: UUID
    name: str
    description: str | None = None
    framework: str
    risk_level: str
    enabled: bool
    config: dict
    priority: int
    rule_count: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


def _policy_response(policy) -> PolicyResponse:
    """Build a PolicyResponse with computed rule_count.

    Constructs the response manually to avoid triggering lazy attribute
    loading for ``updated_at`` (which uses ``onupdate`` and may not be
    loaded in the current greenlet).
    """
    # Access only eagerly-loaded columns to avoid MissingGreenlet errors
    created_at = None
    updated_at = None
    try:
        created_at = policy.created_at
    except Exception:
        pass
    try:
        updated_at = policy.updated_at
    except Exception:
        pass

    return PolicyResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        framework=policy.framework,
        risk_level=policy.risk_level,
        enabled=policy.enabled,
        config=policy.config,
        priority=policy.priority,
        rule_count=_count_rules(policy.config or {}),
        created_at=created_at,
        updated_at=updated_at,
    )


class PolicyCreate(BaseModel):
    """Request to create a custom policy."""

    name: str = Field(..., max_length=255)
    description: str | None = None
    framework: str = Field(..., max_length=50)
    risk_level: str = Field("high", max_length=20)
    enabled: bool = True
    config: dict = Field(..., description="Full PolicyPack definition as JSON")
    priority: int = 0


class PolicyUpdate(BaseModel):
    """Request to update a policy (partial)."""

    name: str | None = Field(None, max_length=255)
    description: str | None = None
    framework: str | None = Field(None, max_length=50)
    risk_level: str | None = Field(None, max_length=20)
    enabled: bool | None = None
    config: dict | None = None
    priority: int | None = None


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

    job_id: UUID | None = None
    result_ids: list[UUID] | None = None
    policy_ids: list[UUID] | None = Field(
        None,
        description="Evaluate specific policies (even if disabled). "
                    "If omitted, all enabled policies are used.",
    )
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


class RulesResponse(BaseModel):
    """Structured trigger rules for a policy."""

    any_of: list[str] = Field(default_factory=list)
    all_of: list[str] = Field(default_factory=list)
    combinations: list[list[str]] = Field(default_factory=list)
    min_confidence: float = 0.5
    min_count: int = 1
    exclude_if_only: list[str] = Field(default_factory=list)


class RulesUpdate(BaseModel):
    """Replace trigger rules for a policy."""

    any_of: list[str] | None = None
    all_of: list[str] | None = None
    combinations: list[list[str]] | None = None
    min_confidence: float | None = None
    min_count: int | None = None
    exclude_if_only: list[str] | None = None


class CombinationsUpdate(BaseModel):
    """Update co-occurrence combination rules."""

    combinations: list[list[str]]


class ExposureMultipliersResponse(BaseModel):
    """Exposure-based scoring multipliers for a policy."""

    public: float = 2.0
    external: float = 1.5
    internal: float = 1.0
    private: float = 1.0


class ExposureMultipliersUpdate(BaseModel):
    """Update exposure multipliers."""

    public: float = Field(2.0, ge=0.1, le=10.0)
    external: float = Field(1.5, ge=0.1, le=10.0)
    internal: float = Field(1.0, ge=0.1, le=10.0)
    private: float = Field(1.0, ge=0.1, le=10.0)


class AssignTargetsRequest(BaseModel):
    """Assign one or more targets to a policy."""

    target_ids: list[UUID]


class TargetAssignmentResponse(BaseModel):
    """A policy-target assignment."""

    id: UUID
    target_id: UUID
    target_name: str
    assigned_at: datetime | None = None


class PolicyImportItem(BaseModel):
    """Single policy definition for import."""

    name: str = Field(..., max_length=255)
    description: str | None = None
    framework: str = Field(..., max_length=50)
    risk_level: str = Field("high", max_length=20)
    enabled: bool = True
    config: dict = Field(...)
    priority: int = 0


class PolicyImportRequest(BaseModel):
    """Bulk import of policy definitions."""

    policies: list[PolicyImportItem]


class PolicyExportResponse(BaseModel):
    """Exported policy definition."""

    name: str
    description: str | None = None
    framework: str
    risk_level: str
    enabled: bool
    config: dict
    priority: int


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------

async def _get_policy_service(
    db: DbSessionDep,
    tenant: TenantContextDep,
):
    """Inline dependency — avoids circular import with dependencies.py."""
    from openlabels.server.config import get_settings
    from openlabels.server.services.base import TenantContext as ServiceTenantContext
    from openlabels.server.services.policy_service import PolicyService

    svc_tenant = ServiceTenantContext(
        tenant_id=tenant.tenant_id,
        user_id=tenant.user_id,
        user_email=tenant.user_email,
        user_role="admin" if tenant.is_admin else "viewer",
    )
    return PolicyService(db, svc_tenant, get_settings())


PolicyServiceDep = Depends(_get_policy_service)


# ---------------------------------------------------------------------------
# CRUD endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=PaginatedResponse[PolicyResponse])
async def list_policies(
    _tenant: TenantContextDep,
    svc=PolicyServiceDep,
    pagination: PaginationParams = Depends(),
    framework: str | None = Query(None),
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
            items=[_policy_response(p) for p in items],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.post("", response_model=PolicyResponse, status_code=201)
async def create_policy(
    request: PolicyCreate,
    _admin: AdminContextDep,
    db: DbSessionDep,
    svc=PolicyServiceDep,
):
    """Create a custom policy."""
    policy = await svc.create_policy(request.model_dump())

    audit_log(
        db, tenant_id=_admin.tenant_id, user_id=_admin.user_id,
        action="policy_created", resource_type="policy", resource_id=policy.id,
        details={"name": request.name, "framework": request.framework},
    )

    await svc.commit()
    return _policy_response(policy)


# ---------------------------------------------------------------------------
# Built-in packs
# ---------------------------------------------------------------------------

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
    db: DbSessionDep,
    svc=PolicyServiceDep,
):
    """Load a built-in policy pack into the tenant's active policies."""
    policy = await svc.load_builtin_pack(request.pack_name)

    audit_log(
        db, tenant_id=_admin.tenant_id, user_id=_admin.user_id,
        action="policy_created", resource_type="policy", resource_id=policy.id,
        details={"pack_name": request.pack_name, "source": "builtin"},
    )

    await svc.commit()
    return _policy_response(policy)


# ---------------------------------------------------------------------------
# Evaluate / simulate
# ---------------------------------------------------------------------------

@router.post("/evaluate", response_model=list[EvaluateResultItem])
async def evaluate_policies(
    request: EvaluateRequest,
    _tenant: TenantContextDep,
    svc=PolicyServiceDep,
):
    """Dry-run: evaluate existing scan results against policies.

    Does **not** persist any changes — returns the evaluation output for review.
    If ``policy_ids`` is provided, only those policies (even disabled ones) are
    evaluated, enabling "what-if" simulation.
    """
    results = await svc.evaluate_results(
        job_id=request.job_id,
        result_ids=request.result_ids,
        policy_ids=request.policy_ids,
        limit=request.limit,
    )
    return [EvaluateResultItem(**r) for r in results]


# ---------------------------------------------------------------------------
# Compliance statistics
# ---------------------------------------------------------------------------

@router.get("/compliance/stats", response_model=ComplianceStatsResponse)
async def compliance_stats(
    _tenant: TenantContextDep,
    svc=PolicyServiceDep,
):
    """Get compliance statistics for the current tenant."""
    stats = await svc.compliance_stats()
    return ComplianceStatsResponse(**stats)


# ---------------------------------------------------------------------------
# Import / export
# ---------------------------------------------------------------------------

@router.post("/import", response_model=list[PolicyResponse], status_code=201)
async def import_policies(
    request: PolicyImportRequest,
    _admin: AdminContextDep,
    db: DbSessionDep,
    svc=PolicyServiceDep,
):
    """Bulk import policy definitions."""
    results = []
    for item in request.policies:
        policy = await svc.create_policy(item.model_dump())
        audit_log(
            db, tenant_id=_admin.tenant_id, user_id=_admin.user_id,
            action="policy_created", resource_type="policy", resource_id=policy.id,
            details={"name": item.name, "source": "import"},
        )
        results.append(policy)

    await svc.commit()
    return [_policy_response(p) for p in results]


# ---------------------------------------------------------------------------
# Single-policy endpoints (must come after fixed-path routes)
# ---------------------------------------------------------------------------

@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: UUID,
    _tenant: TenantContextDep,
    svc=PolicyServiceDep,
):
    """Get a specific policy by ID."""
    policy = await svc.get_policy(policy_id)
    return _policy_response(policy)


@router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: UUID,
    request: PolicyUpdate,
    _admin: AdminContextDep,
    db: DbSessionDep,
    svc=PolicyServiceDep,
):
    """Update an existing policy."""
    data = request.model_dump(exclude_unset=True)
    policy = await svc.update_policy(policy_id, data)

    audit_log(
        db, tenant_id=_admin.tenant_id, user_id=_admin.user_id,
        action="policy_updated", resource_type="policy", resource_id=policy_id,
        details={"changes": data},
    )

    await svc.commit()
    return _policy_response(policy)


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: UUID,
    _admin: AdminContextDep,
    db: DbSessionDep,
    svc=PolicyServiceDep,
):
    """Delete a policy."""
    audit_log(
        db, tenant_id=_admin.tenant_id, user_id=_admin.user_id,
        action="policy_deleted", resource_type="policy", resource_id=policy_id,
    )

    await svc.delete_policy(policy_id)
    await svc.commit()


@router.patch("/{policy_id}/toggle", response_model=PolicyResponse)
async def toggle_policy(
    policy_id: UUID,
    request: PolicyToggle,
    _admin: AdminContextDep,
    db: DbSessionDep,
    svc=PolicyServiceDep,
):
    """Enable or disable a policy."""
    policy = await svc.toggle_policy(policy_id, request.enabled)

    audit_log(
        db, tenant_id=_admin.tenant_id, user_id=_admin.user_id,
        action="policy_updated", resource_type="policy", resource_id=policy_id,
        details={"enabled": request.enabled},
    )

    await svc.commit()
    return _policy_response(policy)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

@router.get("/{policy_id}/export", response_model=PolicyExportResponse)
async def export_policy(
    policy_id: UUID,
    _tenant: TenantContextDep,
    svc=PolicyServiceDep,
):
    """Export a policy definition as JSON."""
    policy = await svc.get_policy(policy_id)
    return PolicyExportResponse(
        name=policy.name,
        description=policy.description,
        framework=policy.framework,
        risk_level=policy.risk_level,
        enabled=policy.enabled,
        config=policy.config,
        priority=policy.priority,
    )


# ---------------------------------------------------------------------------
# Rule builder
# ---------------------------------------------------------------------------

@router.get("/{policy_id}/rules", response_model=RulesResponse)
async def get_policy_rules(
    policy_id: UUID,
    _tenant: TenantContextDep,
    svc=PolicyServiceDep,
):
    """Get the trigger rules for a policy."""
    policy = await svc.get_policy(policy_id)
    triggers = (policy.config or {}).get("triggers", {})
    return RulesResponse(
        any_of=triggers.get("any_of", []),
        all_of=triggers.get("all_of", []),
        combinations=triggers.get("combinations", []),
        min_confidence=triggers.get("min_confidence", 0.5),
        min_count=triggers.get("min_count", 1),
        exclude_if_only=triggers.get("exclude_if_only", []),
    )


@router.put("/{policy_id}/rules", response_model=RulesResponse)
async def update_policy_rules(
    policy_id: UUID,
    request: RulesUpdate,
    _admin: AdminContextDep,
    db: DbSessionDep,
    svc=PolicyServiceDep,
):
    """Update trigger rules for a policy."""
    policy = await svc.get_policy(policy_id)
    config = dict(policy.config or {})
    triggers = dict(config.get("triggers", {}))

    update_data = request.model_dump(exclude_unset=True)
    triggers.update(update_data)
    config["triggers"] = triggers

    policy = await svc.update_policy(policy_id, {"config": config})

    audit_log(
        db, tenant_id=_admin.tenant_id, user_id=_admin.user_id,
        action="policy_updated", resource_type="policy", resource_id=policy_id,
        details={"rules_updated": list(update_data.keys())},
    )

    await svc.commit()
    return RulesResponse(
        any_of=triggers.get("any_of", []),
        all_of=triggers.get("all_of", []),
        combinations=triggers.get("combinations", []),
        min_confidence=triggers.get("min_confidence", 0.5),
        min_count=triggers.get("min_count", 1),
        exclude_if_only=triggers.get("exclude_if_only", []),
    )


# ---------------------------------------------------------------------------
# Co-occurrence combination rules
# ---------------------------------------------------------------------------

@router.put("/{policy_id}/rules/combinations", response_model=RulesResponse)
async def update_combinations(
    policy_id: UUID,
    request: CombinationsUpdate,
    _admin: AdminContextDep,
    db: DbSessionDep,
    svc=PolicyServiceDep,
):
    """Update co-occurrence combination rules (e.g. SSN + DOB = CRITICAL)."""
    policy = await svc.get_policy(policy_id)
    config = dict(policy.config or {})
    triggers = dict(config.get("triggers", {}))

    triggers["combinations"] = request.combinations
    config["triggers"] = triggers

    policy = await svc.update_policy(policy_id, {"config": config})

    audit_log(
        db, tenant_id=_admin.tenant_id, user_id=_admin.user_id,
        action="policy_updated", resource_type="policy", resource_id=policy_id,
        details={"combinations_updated": len(request.combinations)},
    )

    await svc.commit()
    return RulesResponse(
        any_of=triggers.get("any_of", []),
        all_of=triggers.get("all_of", []),
        combinations=triggers.get("combinations", []),
        min_confidence=triggers.get("min_confidence", 0.5),
        min_count=triggers.get("min_count", 1),
        exclude_if_only=triggers.get("exclude_if_only", []),
    )


# ---------------------------------------------------------------------------
# Exposure-based scoring multipliers
# ---------------------------------------------------------------------------

_DEFAULT_EXPOSURE = {"public": 2.0, "external": 1.5, "internal": 1.0, "private": 1.0}


@router.get("/{policy_id}/exposure-multipliers", response_model=ExposureMultipliersResponse)
async def get_exposure_multipliers(
    policy_id: UUID,
    _tenant: TenantContextDep,
    svc=PolicyServiceDep,
):
    """Get exposure-based scoring multipliers for a policy."""
    policy = await svc.get_policy(policy_id)
    mults = (policy.config or {}).get("exposure_multipliers", _DEFAULT_EXPOSURE)
    return ExposureMultipliersResponse(**{k: mults.get(k, v) for k, v in _DEFAULT_EXPOSURE.items()})


@router.put("/{policy_id}/exposure-multipliers", response_model=ExposureMultipliersResponse)
async def update_exposure_multipliers(
    policy_id: UUID,
    request: ExposureMultipliersUpdate,
    _admin: AdminContextDep,
    db: DbSessionDep,
    svc=PolicyServiceDep,
):
    """Update exposure-based scoring multipliers for a policy."""
    policy = await svc.get_policy(policy_id)
    config = dict(policy.config or {})
    config["exposure_multipliers"] = request.model_dump()

    policy = await svc.update_policy(policy_id, {"config": config})

    audit_log(
        db, tenant_id=_admin.tenant_id, user_id=_admin.user_id,
        action="policy_updated", resource_type="policy", resource_id=policy_id,
        details={"exposure_multipliers_updated": True},
    )

    await svc.commit()
    return ExposureMultipliersResponse(**request.model_dump())


# ---------------------------------------------------------------------------
# Policy-target assignment
# ---------------------------------------------------------------------------

@router.get("/{policy_id}/targets", response_model=list[TargetAssignmentResponse])
async def list_policy_targets(
    policy_id: UUID,
    _tenant: TenantContextDep,
    svc=PolicyServiceDep,
):
    """List scan targets assigned to a policy."""
    # Verify policy exists and belongs to tenant
    await svc.get_policy(policy_id)
    assignments = await svc.list_assigned_targets(policy_id)
    return [TargetAssignmentResponse(**a) for a in assignments]


@router.post("/{policy_id}/targets", response_model=list[TargetAssignmentResponse], status_code=201)
async def assign_targets(
    policy_id: UUID,
    request: AssignTargetsRequest,
    _admin: AdminContextDep,
    db: DbSessionDep,
    svc=PolicyServiceDep,
):
    """Assign one or more scan targets to a policy."""
    await svc.get_policy(policy_id)
    assignments = await svc.assign_targets(policy_id, request.target_ids)

    audit_log(
        db, tenant_id=_admin.tenant_id, user_id=_admin.user_id,
        action="policy_updated", resource_type="policy", resource_id=policy_id,
        details={"targets_assigned": [str(t) for t in request.target_ids]},
    )

    await svc.commit()
    return [TargetAssignmentResponse(**a) for a in assignments]


@router.delete("/{policy_id}/targets/{target_id}", status_code=204)
async def unassign_target(
    policy_id: UUID,
    target_id: UUID,
    _admin: AdminContextDep,
    db: DbSessionDep,
    svc=PolicyServiceDep,
):
    """Remove a scan target assignment from a policy."""
    await svc.get_policy(policy_id)
    await svc.unassign_target(policy_id, target_id)

    audit_log(
        db, tenant_id=_admin.tenant_id, user_id=_admin.user_id,
        action="policy_updated", resource_type="policy", resource_id=policy_id,
        details={"target_unassigned": str(target_id)},
    )

    await svc.commit()
