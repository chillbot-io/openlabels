"""Tests for PolicyService."""

from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from openlabels.server.services.base import TenantContext
from openlabels.server.services.policy_service import PolicyService


def _make_service(session, tenant_id, user_id=None):
    tenant = TenantContext(tenant_id=tenant_id, user_id=user_id or uuid4())
    return PolicyService(session, tenant, MagicMock())


@pytest.fixture
async def policy_fixtures(test_db):
    """Create a tenant and user for policy tests."""
    from openlabels.server.models import Tenant, User

    tenant = Tenant(name="Policy Tenant", azure_tenant_id="policy-test-tid")
    test_db.add(tenant)
    await test_db.flush()

    user = User(tenant_id=tenant.id, email="policy@test.com", name="Policy Admin", role="admin")
    test_db.add(user)
    await test_db.commit()

    return {"tenant": tenant, "user": user, "session": test_db}


def _policy_data(name="Test Policy", framework="hipaa"):
    return {
        "name": name,
        "description": f"A {framework} policy",
        "framework": framework,
        "risk_level": "high",
        "enabled": True,
        "config": {"rules": [{"entity_types": ["SSN"], "threshold": 1}]},
        "priority": 10,
    }


class TestCRUD:
    @pytest.mark.asyncio
    async def test_create_policy(self, policy_fixtures):
        f = policy_fixtures
        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)

        policy = await svc.create_policy(_policy_data())
        assert policy.name == "Test Policy"
        assert policy.framework == "hipaa"
        assert policy.tenant_id == f["tenant"].id

    @pytest.mark.asyncio
    async def test_get_policy(self, policy_fixtures):
        f = policy_fixtures
        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)

        created = await svc.create_policy(_policy_data())
        fetched = await svc.get_policy(created.id)
        assert fetched.id == created.id

    @pytest.mark.asyncio
    async def test_get_policy_wrong_tenant(self, policy_fixtures):
        from openlabels.exceptions import NotFoundError

        f = policy_fixtures
        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        policy = await svc.create_policy(_policy_data())

        other = _make_service(f["session"], uuid4())
        with pytest.raises(NotFoundError):
            await other.get_policy(policy.id)

    @pytest.mark.asyncio
    async def test_update_policy(self, policy_fixtures):
        f = policy_fixtures
        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)

        policy = await svc.create_policy(_policy_data())
        updated = await svc.update_policy(policy.id, {"name": "Updated Policy", "enabled": False})

        assert updated.name == "Updated Policy"
        assert updated.enabled is False

    @pytest.mark.asyncio
    async def test_delete_policy(self, policy_fixtures):
        f = policy_fixtures
        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)

        policy = await svc.create_policy(_policy_data())
        await svc.delete_policy(policy.id)

        from openlabels.exceptions import NotFoundError
        with pytest.raises(NotFoundError):
            await svc.get_policy(policy.id)


class TestToggle:
    @pytest.mark.asyncio
    async def test_toggle_enables_and_disables(self, policy_fixtures):
        f = policy_fixtures
        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)

        policy = await svc.create_policy(_policy_data())
        assert policy.enabled is True

        toggled = await svc.toggle_policy(policy.id, False)
        assert toggled.enabled is False

        toggled = await svc.toggle_policy(policy.id, True)
        assert toggled.enabled is True


class TestListPolicies:
    @pytest.mark.asyncio
    async def test_list_all(self, policy_fixtures):
        f = policy_fixtures
        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)

        await svc.create_policy(_policy_data("HIPAA Policy", "hipaa"))
        await svc.create_policy(_policy_data("GDPR Policy", "gdpr"))
        await svc.create_policy(_policy_data("SOC2 Policy", "soc2"))

        policies, total = await svc.list_policies()
        assert total == 3

    @pytest.mark.asyncio
    async def test_list_by_framework(self, policy_fixtures):
        f = policy_fixtures
        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)

        await svc.create_policy(_policy_data("HIPAA Policy", "hipaa"))
        await svc.create_policy(_policy_data("GDPR Policy", "gdpr"))

        policies, total = await svc.list_policies(framework="hipaa")
        assert total == 1
        assert policies[0].framework == "hipaa"

    @pytest.mark.asyncio
    async def test_list_enabled_only(self, policy_fixtures):
        f = policy_fixtures
        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)

        p1 = await svc.create_policy(_policy_data("Enabled", "hipaa"))
        p2 = await svc.create_policy(_policy_data("Disabled", "gdpr"))
        await svc.toggle_policy(p2.id, False)

        policies, total = await svc.list_policies(enabled_only=True)
        assert total == 1


class TestBuiltinPacks:
    @pytest.mark.asyncio
    async def test_list_builtin_packs(self, policy_fixtures):
        f = policy_fixtures
        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)

        packs = await svc.list_builtin_packs()
        assert isinstance(packs, list)
        assert len(packs) > 0
        assert "name" in packs[0]
        assert "framework" in packs[0]


class TestComplianceStats:
    @pytest.mark.asyncio
    async def test_compliance_stats_empty(self, policy_fixtures):
        f = policy_fixtures
        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)

        stats = await svc.compliance_stats()
        assert stats["total_results"] == 0
        assert stats["compliance_pct"] == 100.0
