"""
Policy service for OpenLabels server (Phase J).

Provides business logic for policy management:
- CRUD operations for tenant-scoped policies
- Dry-run policy evaluation against existing scan results
- Policy pack loading from built-in templates
- Compliance statistics
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import func, select

from openlabels.server.models import Policy, ScanResult
from openlabels.server.services.base import BaseService

if TYPE_CHECKING:
    from openlabels.core.policies.engine import PolicyEngine

logger = logging.getLogger(__name__)


class PolicyService(BaseService):
    """Service for managing policies and evaluating compliance.

    All methods automatically filter by ``tenant_id`` for proper isolation.
    """

    # ── CRUD ────────────────────────────────────────────────────────────

    async def list_policies(
        self,
        *,
        framework: str | None = None,
        enabled_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Policy], int]:
        """List policies for the current tenant with optional filters."""
        base = select(Policy).where(Policy.tenant_id == self.tenant_id)
        if framework:
            base = base.where(Policy.framework == framework)
        if enabled_only:
            base = base.where(Policy.enabled.is_(True))

        return await self.paginate(
            base.order_by(Policy.priority.desc(), Policy.created_at),
            limit=limit,
            offset=offset,
        )

    async def get_policy(self, policy_id: UUID) -> Policy:
        """Fetch a single policy by ID (tenant-isolated)."""
        return await self.get_tenant_entity(Policy, policy_id, "Policy")

    async def create_policy(self, data: dict) -> Policy:
        """Create a new policy for the current tenant."""
        from openlabels.server.models import generate_uuid

        policy = Policy(
            id=generate_uuid(),
            tenant_id=self.tenant_id,
            name=data["name"],
            description=data.get("description"),
            framework=data["framework"],
            risk_level=data.get("risk_level", "high"),
            enabled=data.get("enabled", True),
            config=data["config"],
            priority=data.get("priority", 0),
            created_by=self.user_id,
        )
        self.session.add(policy)
        await self.flush()
        self._log_info(f"Policy created: {policy.name} ({policy.framework})")
        return policy

    async def update_policy(self, policy_id: UUID, data: dict) -> Policy:
        """Update an existing policy."""
        policy = await self.get_policy(policy_id)

        for field in ("name", "description", "framework", "risk_level",
                       "enabled", "config", "priority"):
            if field in data:
                setattr(policy, field, data[field])

        await self.flush()
        self._log_info(f"Policy updated: {policy.name}")
        return policy

    async def delete_policy(self, policy_id: UUID) -> None:
        """Delete a policy."""
        policy = await self.get_policy(policy_id)
        await self.session.delete(policy)
        await self.flush()
        self._log_info(f"Policy deleted: {policy.name}")

    async def toggle_policy(self, policy_id: UUID, enabled: bool) -> Policy:
        """Enable or disable a policy."""
        policy = await self.get_policy(policy_id)
        policy.enabled = enabled
        await self.flush()
        return policy

    # ── Built-in packs ──────────────────────────────────────────────────

    async def load_builtin_pack(self, pack_name: str) -> Policy:
        """Load a built-in policy pack as a tenant-scoped Policy row.

        ``pack_name`` is matched case-insensitively against the built-in
        policy names (e.g. ``"HIPAA PHI"``, ``"soc2"``).
        """
        from openlabels.core.policies.loader import load_builtin_policies

        packs = load_builtin_policies()
        pack = next(
            (p for p in packs if p.name.lower() == pack_name.lower()),
            None,
        )
        if pack is None:
            from openlabels.exceptions import NotFoundError
            raise NotFoundError(
                message=f"Built-in policy pack not found: {pack_name}",
                resource_type="PolicyPack",
                resource_id=pack_name,
            )

        return await self.create_policy({
            "name": pack.name,
            "description": pack.description,
            "framework": pack.category.value,
            "risk_level": pack.risk_level.value,
            "config": _serialize_pack(pack),
            "priority": pack.priority,
        })

    async def list_builtin_packs(self) -> list[dict]:
        """Return metadata for every built-in policy pack."""
        from openlabels.core.policies.loader import load_builtin_policies

        return [
            {
                "name": p.name,
                "description": p.description,
                "framework": p.category.value,
                "risk_level": p.risk_level.value,
            }
            for p in load_builtin_policies()
        ]

    # ── Dry-run evaluation ──────────────────────────────────────────────

    async def evaluate_results(
        self,
        *,
        job_id: UUID | None = None,
        result_ids: list[UUID] | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Evaluate existing scan results against the tenant's active policies.

        Returns a list of dicts with ``result_id``, ``file_path``, and
        ``violations`` for each result that has at least one violation.
        """
        from openlabels.core.policies.schema import EntityMatch

        engine = await self._build_tenant_engine()
        if engine.policy_count == 0:
            return []

        # Fetch results
        q = (
            select(ScanResult)
            .where(ScanResult.tenant_id == self.tenant_id)
        )
        if result_ids:
            q = q.where(ScanResult.id.in_(result_ids))
        if job_id:
            q = q.where(ScanResult.job_id == job_id)
        q = q.order_by(ScanResult.scanned_at.desc()).limit(limit)

        rows = (await self.session.execute(q)).scalars().all()
        output: list[dict] = []

        for row in rows:
            findings = row.findings or {}
            entities_raw = findings.get("entities", [])
            if not entities_raw:
                continue

            entity_matches = [
                EntityMatch(
                    entity_type=e["entity_type"],
                    value="[redacted]",
                    confidence=e.get("confidence", 1.0),
                    start=e.get("start", 0),
                    end=e.get("end", 0),
                    source=e.get("detector", ""),
                )
                for e in entities_raw
            ]

            result = engine.evaluate(entity_matches)
            if result.is_sensitive:
                violations = [
                    {
                        "policy_name": m.policy_name,
                        "trigger_type": m.trigger_type,
                        "matched_entities": m.matched_entities,
                        "severity": result.risk_level.value,
                    }
                    for m in result.matches
                ]
                output.append({
                    "result_id": str(row.id),
                    "file_path": row.file_path,
                    "risk_tier": row.risk_tier,
                    "violations": violations,
                })

        return output

    # ── Compliance stats ────────────────────────────────────────────────

    async def compliance_stats(self) -> dict:
        """Aggregate compliance statistics for the tenant.

        Returns counts of total results, results with violations,
        violations by framework, and compliance percentage.
        """
        base = select(ScanResult).where(
            ScanResult.tenant_id == self.tenant_id,
        )

        total_q = select(func.count()).select_from(base.subquery())
        total = (await self.session.execute(total_q)).scalar_one()

        if total == 0:
            return {
                "total_results": 0,
                "results_with_violations": 0,
                "compliance_pct": 100.0,
                "violations_by_framework": {},
                "violations_by_severity": {},
            }

        # Results with at least one policy violation
        violated_q = (
            select(func.count())
            .select_from(
                select(ScanResult)
                .where(
                    ScanResult.tenant_id == self.tenant_id,
                    ScanResult.policy_violations.isnot(None),
                )
                .subquery()
            )
        )
        violated = (await self.session.execute(violated_q)).scalar_one()

        compliance_pct = round(((total - violated) / total) * 100, 2) if total else 100.0

        # Detailed breakdown requires iterating JSONB — keep it lightweight
        # by only scanning the first 500 results with violations.
        detail_q = (
            select(ScanResult.policy_violations)
            .where(
                ScanResult.tenant_id == self.tenant_id,
                ScanResult.policy_violations.isnot(None),
            )
            .limit(500)
        )
        rows = (await self.session.execute(detail_q)).scalars().all()

        by_framework: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for violations in rows:
            if not violations:
                continue
            for v in violations:
                fw = v.get("framework", "unknown")
                by_framework[fw] = by_framework.get(fw, 0) + 1
                sev = v.get("severity", "unknown")
                by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            "total_results": total,
            "results_with_violations": violated,
            "compliance_pct": compliance_pct,
            "violations_by_framework": by_framework,
            "violations_by_severity": by_severity,
        }

    # ── Internal helpers ────────────────────────────────────────────────

    async def _build_tenant_engine(self) -> PolicyEngine:
        """Build a PolicyEngine loaded with the tenant's active policies."""
        from openlabels.core.policies.engine import PolicyEngine
        from openlabels.core.policies.loader import load_policy_pack

        engine = PolicyEngine()

        q = (
            select(Policy)
            .where(
                Policy.tenant_id == self.tenant_id,
                Policy.enabled.is_(True),
            )
            .order_by(Policy.priority.desc())
        )
        rows = (await self.session.execute(q)).scalars().all()
        for row in rows:
            try:
                pack = load_policy_pack(row.config)
                engine.add_policy(pack)
            except Exception:
                logger.warning("Failed to load policy %s (%s)", row.name, row.id, exc_info=True)

        return engine


def _serialize_pack(pack) -> dict:
    """Serialize a ``PolicyPack`` dataclass to a JSON-safe dict."""
    from dataclasses import asdict

    raw = asdict(pack)
    # Convert enums to their string values
    if "category" in raw and hasattr(raw["category"], "value"):
        raw["category"] = raw["category"].value
    elif "category" in raw and isinstance(raw["category"], str):
        pass  # already string from asdict
    if "risk_level" in raw and hasattr(raw["risk_level"], "value"):
        raw["risk_level"] = raw["risk_level"].value
    elif "risk_level" in raw and isinstance(raw["risk_level"], str):
        pass
    return raw
