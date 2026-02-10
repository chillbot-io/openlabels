"""
Policy action executor (Phase J).

Connects policy violations to remediation actions:
- Quarantine high-risk files
- Apply sensitivity labels
- Enroll files in monitoring
- Log audit events

The executor is invoked by the scan pipeline when policy violations are
detected, or manually via the API for re-evaluation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

logger = logging.getLogger(__name__)


@dataclass
class ActionResult:
    """Outcome of a single remediation action."""

    action: str  # "quarantine", "label", "monitor", "audit"
    success: bool
    detail: str | None = None
    error: str | None = None


@dataclass
class PolicyActionContext:
    """Context passed to the executor for a single file."""

    file_path: str
    tenant_id: UUID
    scan_result_id: UUID
    risk_tier: str
    violations: list[dict] = field(default_factory=list)


class PolicyActionExecutor:
    """Execute remediation actions triggered by policy violations.

    Each action type is a separate method so callers can compose the
    set of actions they want.  The ``execute_all`` convenience method
    runs all applicable actions based on the violation metadata.

    Usage::

        executor = PolicyActionExecutor()
        results = await executor.execute_all(context)
    """

    async def execute_all(self, ctx: PolicyActionContext) -> list[ActionResult]:
        """Run all applicable actions for the given context."""
        results: list[ActionResult] = []

        severities = {v.get("severity", "").lower() for v in ctx.violations}

        # Quarantine critical violations
        if "critical" in severities:
            results.append(await self.quarantine(ctx))

        # Apply label for high+ severity
        if severities & {"critical", "high"}:
            results.append(await self.apply_label(ctx))

        # Enroll in monitoring for high+ severity
        if severities & {"critical", "high"}:
            results.append(await self.enroll_monitoring(ctx))

        # Always log an audit event for any violation
        results.append(await self.log_audit(ctx))

        return results

    async def quarantine(self, ctx: PolicyActionContext) -> ActionResult:
        """Move the file to quarantine."""
        try:
            from openlabels.remediation import quarantine as do_quarantine

            source = Path(ctx.file_path)
            if not source.exists():
                return ActionResult(
                    action="quarantine",
                    success=False,
                    error=f"File not found: {ctx.file_path}",
                )

            # Use a tenant-scoped quarantine directory
            quarantine_dir = Path("/var/openlabels/quarantine") / str(ctx.tenant_id)
            result = do_quarantine(source=source, destination=quarantine_dir)
            return ActionResult(
                action="quarantine",
                success=result.success,
                detail=str(result.dest_path) if result.dest_path else None,
                error=result.error,
            )
        except Exception as e:
            logger.error("Quarantine failed for %s: %s", ctx.file_path, e)
            return ActionResult(
                action="quarantine",
                success=False,
                error=str(e),
            )

    async def apply_label(self, ctx: PolicyActionContext) -> ActionResult:
        """Apply a sensitivity label based on policy violation severity."""
        try:
            from openlabels.labeling.engine import LabelingEngine

            engine = LabelingEngine()
            # Map risk tier to label recommendation
            label = engine.recommend_label(risk_tier=ctx.risk_tier)
            if label is None:
                return ActionResult(
                    action="label",
                    success=True,
                    detail="No matching label for risk tier",
                )

            applied = engine.apply_label(
                file_path=ctx.file_path,
                label_id=label.label_id,
                label_name=label.label_name,
            )
            return ActionResult(
                action="label",
                success=applied.success,
                detail=f"Applied label: {label.label_name}" if applied.success else None,
                error=applied.error,
            )
        except Exception as e:
            logger.error("Label application failed for %s: %s", ctx.file_path, e)
            return ActionResult(action="label", success=False, error=str(e))

    async def enroll_monitoring(self, ctx: PolicyActionContext) -> ActionResult:
        """Add the file to the monitoring registry."""
        try:
            from sqlalchemy import select

            from openlabels.server.db import get_session_context
            from openlabels.server.models import MonitoredFile

            async with get_session_context() as session:
                # Check if already monitored
                existing = await session.execute(
                    select(MonitoredFile).where(
                        MonitoredFile.tenant_id == ctx.tenant_id,
                        MonitoredFile.file_path == ctx.file_path,
                    )
                )
                if existing.scalar_one_or_none() is not None:
                    return ActionResult(
                        action="monitor",
                        success=True,
                        detail="Already monitored",
                    )

                from openlabels.server.models import generate_uuid

                session.add(MonitoredFile(
                    id=generate_uuid(),
                    tenant_id=ctx.tenant_id,
                    file_path=ctx.file_path,
                    risk_tier=ctx.risk_tier.upper(),
                ))
                await session.commit()

            return ActionResult(action="monitor", success=True)
        except Exception as e:
            logger.error("Monitor enrollment failed for %s: %s", ctx.file_path, e)
            return ActionResult(action="monitor", success=False, error=str(e))

    async def log_audit(self, ctx: PolicyActionContext) -> ActionResult:
        """Record an audit log entry for the policy violation."""
        try:
            from openlabels.server.db import get_session_context
            from openlabels.server.models import AuditLog, generate_uuid

            frameworks = [v.get("framework", "unknown") for v in ctx.violations]
            policies = [v.get("policy_name", "unknown") for v in ctx.violations]

            async with get_session_context() as session:
                session.add(AuditLog(
                    id=generate_uuid(),
                    tenant_id=ctx.tenant_id,
                    action="policy_violation",
                    resource_type="scan_result",
                    resource_id=ctx.scan_result_id,
                    details={
                        "file_path": ctx.file_path,
                        "risk_tier": ctx.risk_tier,
                        "frameworks": frameworks,
                        "policies": policies,
                        "violation_count": len(ctx.violations),
                    },
                ))
                await session.commit()

            return ActionResult(action="audit", success=True)
        except Exception as e:
            logger.error("Audit log failed for %s: %s", ctx.file_path, e)
            return ActionResult(action="audit", success=False, error=str(e))
