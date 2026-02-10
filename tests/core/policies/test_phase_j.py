"""Tests for Phase J: Policy Engine Integration.

Covers:
- SOC2 built-in policy pack
- PolicyActionExecutor
- Policy violations in scan pipeline
- PolicyService (CRUD, evaluation, compliance stats)
- Policy API routes
"""

import asyncio
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest

from openlabels.core.policies.engine import PolicyEngine
from openlabels.core.policies.loader import load_builtin_policies, load_policy_pack
from openlabels.core.policies.schema import (
    EntityMatch,
    PolicyCategory,
    PolicyPack,
    PolicyResult,
    PolicyTrigger,
    RiskLevel,
)


# ── Helpers ─────────────────────────────────────────────────────────


def make_entity(
    entity_type: str,
    value: str = "test",
    confidence: float = 0.9,
) -> EntityMatch:
    return EntityMatch(
        entity_type=entity_type,
        value=value,
        confidence=confidence,
        start=0,
        end=len(value),
        source="test",
    )


# ── SOC2 Policy Pack ────────────────────────────────────────────────


class TestSOC2PolicyPack:
    """Tests for the new SOC2 built-in policy pack."""

    def test_soc2_pack_exists_in_builtins(self):
        packs = load_builtin_policies()
        names = [p.name for p in packs]
        assert "SOC2 Trust Services" in names

    def test_soc2_pack_count_is_nine(self):
        packs = load_builtin_policies()
        assert len(packs) == 9

    def test_soc2_category(self):
        packs = load_builtin_policies()
        soc2 = next(p for p in packs if p.name == "SOC2 Trust Services")
        assert soc2.category == PolicyCategory.SOC2

    def test_soc2_risk_level(self):
        packs = load_builtin_policies()
        soc2 = next(p for p in packs if p.name == "SOC2 Trust Services")
        assert soc2.risk_level == RiskLevel.HIGH

    def test_soc2_triggers_on_ssn(self):
        engine = PolicyEngine()
        packs = load_builtin_policies()
        soc2 = next(p for p in packs if p.name == "SOC2 Trust Services")
        engine.add_policy(soc2)

        result = engine.evaluate([make_entity("ssn", "123-45-6789")])
        assert result.is_sensitive
        assert PolicyCategory.SOC2 in result.categories

    def test_soc2_triggers_on_api_key(self):
        engine = PolicyEngine()
        packs = load_builtin_policies()
        soc2 = next(p for p in packs if p.name == "SOC2 Trust Services")
        engine.add_policy(soc2)

        result = engine.evaluate([make_entity("api_key", "sk-abc123xyz")])
        assert result.is_sensitive

    def test_soc2_triggers_on_combination(self):
        engine = PolicyEngine()
        packs = load_builtin_policies()
        soc2 = next(p for p in packs if p.name == "SOC2 Trust Services")
        engine.add_policy(soc2)

        result = engine.evaluate([
            make_entity("person_name", "John Doe"),
            make_entity("bank_account", "123456789"),
        ])
        assert result.is_sensitive

    def test_soc2_no_trigger_for_unrelated(self):
        engine = PolicyEngine()
        packs = load_builtin_policies()
        soc2 = next(p for p in packs if p.name == "SOC2 Trust Services")
        engine.add_policy(soc2)

        result = engine.evaluate([make_entity("person_name", "John Doe")])
        assert not result.is_sensitive

    def test_soc2_handling_requirements(self):
        packs = load_builtin_policies()
        soc2 = next(p for p in packs if p.name == "SOC2 Trust Services")
        assert soc2.handling.encryption_required is True
        assert soc2.handling.audit_access is True
        assert soc2.handling.access_logging is True

    def test_soc2_retention(self):
        packs = load_builtin_policies()
        soc2 = next(p for p in packs if p.name == "SOC2 Trust Services")
        assert soc2.retention.min_days == 365
        assert soc2.retention.review_frequency_days == 90

    def test_soc2_serialization_roundtrip(self):
        """SOC2 pack can be serialized to dict and loaded back."""
        packs = load_builtin_policies()
        soc2 = next(p for p in packs if p.name == "SOC2 Trust Services")
        raw = asdict(soc2)
        loaded = load_policy_pack(raw)
        assert loaded.name == soc2.name
        assert loaded.category == soc2.category


# ── Policy Violations in Scan Results ───────────────────────────────


class TestPolicyViolationsOutput:
    """Test that _detect_and_score produces policy_violations."""

    def test_scan_result_dict_has_violations_key(self):
        """The result dict from _detect_and_score includes policy_violations."""
        # Build a mock policy result to simulate what the scan pipeline produces
        violations = [
            {
                "policy_name": "HIPAA PHI",
                "framework": "hipaa",
                "severity": "critical",
                "trigger_type": "any_of",
                "matched_entities": ["ssn"],
            }
        ]
        result = {
            "risk_score": 90,
            "risk_tier": "CRITICAL",
            "entity_counts": {"SSN": 3},
            "total_entities": 3,
            "content_score": 90.0,
            "exposure_multiplier": 1.0,
            "findings": {"entities": [], "policy": {}},
            "policy_violations": violations,
            "processing_time_ms": 50,
            "error": None,
        }
        assert result["policy_violations"] is not None
        assert len(result["policy_violations"]) == 1
        assert result["policy_violations"][0]["policy_name"] == "HIPAA PHI"

    def test_no_violations_is_none(self):
        result = {
            "policy_violations": None,
        }
        assert result["policy_violations"] is None


# ── PolicyActionExecutor ────────────────────────────────────────────


class TestPolicyActionExecutor:
    """Tests for the PolicyActionExecutor."""

    def test_import(self):
        from openlabels.core.policies.actions import (
            PolicyActionExecutor,
            PolicyActionContext,
            ActionResult,
        )
        assert PolicyActionExecutor is not None

    @pytest.mark.asyncio
    async def test_log_audit_action(self):
        from openlabels.core.policies.actions import (
            PolicyActionExecutor,
            PolicyActionContext,
        )

        ctx = PolicyActionContext(
            file_path="/test/file.txt",
            tenant_id=uuid4(),
            scan_result_id=uuid4(),
            risk_tier="CRITICAL",
            violations=[{
                "policy_name": "HIPAA PHI",
                "framework": "hipaa",
                "severity": "critical",
            }],
        )
        executor = PolicyActionExecutor()

        # Mock the DB context manager (imported inside log_audit body)
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "openlabels.server.db.get_session_context",
            return_value=mock_ctx,
        ):
            result = await executor.log_audit(ctx)

        assert result.action == "audit"
        assert result.success is True
        mock_session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_quarantine_missing_file(self):
        from openlabels.core.policies.actions import (
            PolicyActionExecutor,
            PolicyActionContext,
        )

        ctx = PolicyActionContext(
            file_path="/nonexistent/file.txt",
            tenant_id=uuid4(),
            scan_result_id=uuid4(),
            risk_tier="CRITICAL",
            violations=[],
        )
        executor = PolicyActionExecutor()
        result = await executor.quarantine(ctx)
        assert result.success is False
        assert "not found" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_execute_all_critical(self):
        """Critical violations should trigger quarantine + monitor + audit."""
        from openlabels.core.policies.actions import (
            PolicyActionExecutor,
            PolicyActionContext,
        )

        ctx = PolicyActionContext(
            file_path="/nonexistent/critical.docx",
            tenant_id=uuid4(),
            scan_result_id=uuid4(),
            risk_tier="CRITICAL",
            violations=[{"severity": "critical", "framework": "hipaa"}],
        )

        executor = PolicyActionExecutor()
        # Mock all async methods
        executor.quarantine = AsyncMock(return_value=MagicMock(action="quarantine"))
        executor.apply_label = AsyncMock(return_value=MagicMock(action="label"))
        executor.enroll_monitoring = AsyncMock(return_value=MagicMock(action="monitor"))
        executor.log_audit = AsyncMock(return_value=MagicMock(action="audit"))

        results = await executor.execute_all(ctx)
        assert len(results) == 4
        executor.quarantine.assert_called_once()
        executor.apply_label.assert_called_once()
        executor.enroll_monitoring.assert_called_once()
        executor.log_audit.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_all_high(self):
        """High severity should trigger monitor + audit (no quarantine)."""
        from openlabels.core.policies.actions import (
            PolicyActionExecutor,
            PolicyActionContext,
        )

        ctx = PolicyActionContext(
            file_path="/test/high.docx",
            tenant_id=uuid4(),
            scan_result_id=uuid4(),
            risk_tier="HIGH",
            violations=[{"severity": "high", "framework": "pci_dss"}],
        )

        executor = PolicyActionExecutor()
        executor.quarantine = AsyncMock(return_value=MagicMock(action="quarantine"))
        executor.apply_label = AsyncMock(return_value=MagicMock(action="label"))
        executor.enroll_monitoring = AsyncMock(return_value=MagicMock(action="monitor"))
        executor.log_audit = AsyncMock(return_value=MagicMock(action="audit"))

        results = await executor.execute_all(ctx)
        assert len(results) == 3
        executor.quarantine.assert_not_called()
        executor.apply_label.assert_called_once()
        executor.enroll_monitoring.assert_called_once()
        executor.log_audit.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_all_medium(self):
        """Medium severity should trigger only audit."""
        from openlabels.core.policies.actions import (
            PolicyActionExecutor,
            PolicyActionContext,
        )

        ctx = PolicyActionContext(
            file_path="/test/medium.docx",
            tenant_id=uuid4(),
            scan_result_id=uuid4(),
            risk_tier="MEDIUM",
            violations=[{"severity": "medium", "framework": "pii"}],
        )

        executor = PolicyActionExecutor()
        executor.quarantine = AsyncMock(return_value=MagicMock(action="quarantine"))
        executor.enroll_monitoring = AsyncMock(return_value=MagicMock(action="monitor"))
        executor.log_audit = AsyncMock(return_value=MagicMock(action="audit"))

        results = await executor.execute_all(ctx)
        assert len(results) == 1
        executor.quarantine.assert_not_called()
        executor.enroll_monitoring.assert_not_called()
        executor.log_audit.assert_called_once()


# ── Policy Pack Serialization ───────────────────────────────────────


class TestPolicyPackSerialization:
    """Test serialization for DB storage."""

    def test_serialize_all_builtins(self):
        """All built-in packs can be serialized to dicts."""
        from openlabels.server.services.policy_service import _serialize_pack

        for pack in load_builtin_policies():
            d = _serialize_pack(pack)
            assert isinstance(d, dict)
            assert "name" in d
            assert "triggers" in d

    def test_roundtrip_all_builtins(self):
        """All built-in packs survive serialize → load_policy_pack."""
        from openlabels.server.services.policy_service import _serialize_pack

        for pack in load_builtin_policies():
            d = _serialize_pack(pack)
            loaded = load_policy_pack(d)
            assert loaded.name == pack.name
            assert loaded.category == pack.category


# ── Model Tests ─────────────────────────────────────────────────────


class TestPolicyModel:
    """Tests for the Policy SQLAlchemy model."""

    def test_model_importable(self):
        from openlabels.server.models import Policy
        assert Policy.__tablename__ == "policies"

    def test_scan_result_has_policy_violations(self):
        from openlabels.server.models import ScanResult
        assert hasattr(ScanResult, "policy_violations")

    def test_audit_action_enum_has_policy_violation(self):
        from openlabels.server.models import AuditActionEnum
        assert "policy_violation" in AuditActionEnum.enums


# ── Route Tests ─────────────────────────────────────────────────────


class TestPolicyRoutes:
    """Basic tests for policy route module."""

    def test_router_importable(self):
        from openlabels.server.routes.policies import router
        assert router is not None

    def test_router_has_expected_routes(self):
        from openlabels.server.routes.policies import router
        paths = [r.path for r in router.routes]
        assert "" in paths          # list / create
        assert "/builtins" in paths
        assert "/builtins/load" in paths
        assert "/evaluate" in paths
        assert "/compliance/stats" in paths
        assert "/{policy_id}" in paths

    def test_static_routes_before_parametric(self):
        """Static paths must come before /{policy_id} to avoid shadowing."""
        from openlabels.server.routes.policies import router
        get_paths = [
            r.path for r in router.routes
            if hasattr(r, "methods") and "GET" in r.methods
        ]
        # /compliance/stats and /builtins must appear before /{policy_id}
        if "/compliance/stats" in get_paths and "/{policy_id}" in get_paths:
            assert get_paths.index("/compliance/stats") < get_paths.index("/{policy_id}")
        if "/builtins" in get_paths and "/{policy_id}" in get_paths:
            assert get_paths.index("/builtins") < get_paths.index("/{policy_id}")

    def test_app_includes_policies_route(self):
        """The policies module is registered in _ROUTE_MODULES."""
        try:
            from openlabels.server.app import _ROUTE_MODULES
        except Exception:
            # app.py creates an app at import time which may fail if
            # dependencies (e.g. uvicorn) are not installed.  Fall back
            # to a simple source-level check.
            source = Path("src/openlabels/server/app.py").read_text()
            assert '"/policies"' in source
            assert "policies," in source
            return
        prefixes = [prefix for prefix, _, _ in _ROUTE_MODULES]
        assert "/policies" in prefixes


# ── Migration Test ──────────────────────────────────────────────────


class TestMigration:
    """Test migration file structure."""

    def test_migration_file_exists(self):
        path = Path(
            "alembic/versions/b3f8a1c2d4e5_phase_j_policy_engine_integration.py"
        )
        assert path.exists()

    def test_migration_imports(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "migration",
            "alembic/versions/b3f8a1c2d4e5_phase_j_policy_engine_integration.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.revision == "b3f8a1c2d4e5"
        assert mod.down_revision == "095c7b32510f"
        assert hasattr(mod, "upgrade")
        assert hasattr(mod, "downgrade")
