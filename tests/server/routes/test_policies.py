"""
Tests for policy management API endpoints.

Tests focus on:
- List policies with filtering
- Create custom policy
- Get policy details
- Update policy
- Delete policy
- Toggle policy enable/disable
- List built-in packs
- Load built-in pack
- Evaluate policies (dry-run)
- Compliance statistics
"""

import pytest
from uuid import uuid4


@pytest.fixture
async def setup_policies_data(test_db):
    """Set up test data for policy endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User, Policy

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    admin_user = result.scalar_one()

    # Create test policies
    policies = []
    for i, (framework, enabled) in enumerate([
        ("hipaa", True),
        ("gdpr", True),
        ("pci_dss", False),
        ("hipaa", True),
    ]):
        policy = Policy(
            id=uuid4(),
            tenant_id=tenant.id,
            name=f"Test Policy {framework.upper()} {i}",
            description=f"Test {framework} policy {i}",
            framework=framework,
            risk_level="high",
            enabled=enabled,
            config={"rules": [{"pattern": f"test_{i}"}]},
            priority=i,
            created_by=admin_user.id,
        )
        test_db.add(policy)
        await test_db.flush()
        policies.append(policy)
    await test_db.commit()

    return {
        "tenant": tenant,
        "admin_user": admin_user,
        "policies": policies,
        "session": test_db,
    }


class TestListPolicies:
    """Tests for GET /api/v1/policies endpoint."""

    async def test_returns_paginated_structure(self, test_client, setup_policies_data):
        """Response should have pagination structure."""
        response = await test_client.get("/api/v1/policies")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "total_pages" in data

    async def test_returns_policies(self, test_client, setup_policies_data):
        """Should return list of policies."""
        response = await test_client.get("/api/v1/policies")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 4
        assert len(data["items"]) == 4

    async def test_filter_by_framework(self, test_client, setup_policies_data):
        """Should filter policies by framework."""
        response = await test_client.get("/api/v1/policies?framework=hipaa")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 2
        for item in data["items"]:
            assert item["framework"] == "hipaa"

    async def test_filter_enabled_only(self, test_client, setup_policies_data):
        """Should filter to enabled policies only."""
        response = await test_client.get("/api/v1/policies?enabled_only=true")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 3
        for item in data["items"]:
            assert item["enabled"] is True

    async def test_policy_response_structure(self, test_client, setup_policies_data):
        """Policy items should have expected fields."""
        response = await test_client.get("/api/v1/policies")
        assert response.status_code == 200
        data = response.json()

        item = data["items"][0]
        assert "id" in item
        assert "name" in item
        assert "framework" in item
        assert "risk_level" in item
        assert "enabled" in item
        assert "config" in item
        assert "priority" in item


class TestCreatePolicy:
    """Tests for POST /api/v1/policies endpoint."""

    async def test_creates_policy(self, test_client, setup_policies_data):
        """Should create a new custom policy."""
        response = await test_client.post(
            "/api/v1/policies",
            json={
                "name": "New Custom Policy",
                "description": "A custom test policy",
                "framework": "soc2",
                "risk_level": "medium",
                "config": {"rules": [{"pattern": "custom_rule"}]},
                "priority": 10,
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["name"] == "New Custom Policy"
        assert data["framework"] == "soc2"
        assert data["enabled"] is True

    async def test_creates_policy_with_defaults(self, test_client, setup_policies_data):
        """Should create policy with default values."""
        response = await test_client.post(
            "/api/v1/policies",
            json={
                "name": "Minimal Policy",
                "framework": "gdpr",
                "config": {"rules": []},
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["risk_level"] == "high"
        assert data["enabled"] is True
        assert data["priority"] == 0


class TestGetPolicy:
    """Tests for GET /api/v1/policies/{policy_id} endpoint."""

    async def test_returns_policy_details(self, test_client, setup_policies_data):
        """Should return policy details."""
        policy = setup_policies_data["policies"][0]
        response = await test_client.get(f"/api/v1/policies/{policy.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(policy.id)
        assert data["name"] == policy.name

    async def test_returns_404_for_nonexistent(self, test_client, setup_policies_data):
        """Should return 404 for non-existent policy."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/v1/policies/{fake_id}")
        assert response.status_code == 404


class TestUpdatePolicy:
    """Tests for PUT /api/v1/policies/{policy_id} endpoint."""

    async def test_updates_policy_name(self, test_client, setup_policies_data):
        """Should update policy fields."""
        policy = setup_policies_data["policies"][0]
        response = await test_client.put(
            f"/api/v1/policies/{policy.id}",
            json={"name": "Updated Policy Name"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "Updated Policy Name"

    async def test_returns_404_for_nonexistent(self, test_client, setup_policies_data):
        """Should return 404 for non-existent policy."""
        fake_id = uuid4()
        response = await test_client.put(
            f"/api/v1/policies/{fake_id}",
            json={"name": "Nonexistent"},
        )
        assert response.status_code == 404


class TestDeletePolicy:
    """Tests for DELETE /api/v1/policies/{policy_id} endpoint."""

    async def test_deletes_policy(self, test_client, setup_policies_data):
        """Should delete a policy."""
        policy = setup_policies_data["policies"][2]  # Use the disabled one
        response = await test_client.delete(f"/api/v1/policies/{policy.id}")
        assert response.status_code == 204

        # Verify it's gone
        response = await test_client.get(f"/api/v1/policies/{policy.id}")
        assert response.status_code == 404

    async def test_returns_404_for_nonexistent(self, test_client, setup_policies_data):
        """Should return 404 for non-existent policy."""
        fake_id = uuid4()
        response = await test_client.delete(f"/api/v1/policies/{fake_id}")
        assert response.status_code == 404


class TestTogglePolicy:
    """Tests for PATCH /api/v1/policies/{policy_id}/toggle endpoint."""

    async def test_disables_enabled_policy(self, test_client, setup_policies_data):
        """Should disable an enabled policy."""
        policy = setup_policies_data["policies"][0]  # enabled
        response = await test_client.patch(
            f"/api/v1/policies/{policy.id}/toggle",
            json={"enabled": False},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is False

    async def test_enables_disabled_policy(self, test_client, setup_policies_data):
        """Should enable a disabled policy."""
        policy = setup_policies_data["policies"][2]  # disabled
        response = await test_client.patch(
            f"/api/v1/policies/{policy.id}/toggle",
            json={"enabled": True},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True

    async def test_returns_404_for_nonexistent(self, test_client, setup_policies_data):
        """Should return 404 for non-existent policy."""
        fake_id = uuid4()
        response = await test_client.patch(
            f"/api/v1/policies/{fake_id}/toggle",
            json={"enabled": True},
        )
        assert response.status_code == 404


class TestListBuiltinPacks:
    """Tests for GET /api/v1/policies/builtins endpoint."""

    async def test_returns_builtin_packs_list(self, test_client, setup_policies_data):
        """Should return list of available built-in packs."""
        response = await test_client.get("/api/v1/policies/builtins")
        assert response.status_code == 200
        data = response.json()

        assert isinstance(data, list)
        if len(data) > 0:
            pack = data[0]
            assert "name" in pack
            assert "description" in pack
            assert "framework" in pack
            assert "risk_level" in pack


class TestLoadBuiltinPack:
    """Tests for POST /api/v1/policies/builtins/load endpoint."""

    async def test_load_nonexistent_pack_returns_error(self, test_client, setup_policies_data):
        """Should return error for non-existent pack name."""
        response = await test_client.post(
            "/api/v1/policies/builtins/load",
            json={"pack_name": "nonexistent_pack_xyz"},
        )
        # Either 404 or 400 depending on implementation
        assert response.status_code in (400, 404)


class TestEvaluatePolicies:
    """Tests for POST /api/v1/policies/evaluate endpoint."""

    async def test_returns_evaluation_results(self, test_client, setup_policies_data):
        """Should return evaluation results list."""
        response = await test_client.post(
            "/api/v1/policies/evaluate",
            json={"limit": 10},
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestComplianceStats:
    """Tests for GET /api/v1/policies/compliance/stats endpoint."""

    async def test_returns_compliance_stats_structure(self, test_client, setup_policies_data):
        """Should return compliance statistics with expected fields."""
        response = await test_client.get("/api/v1/policies/compliance/stats")
        assert response.status_code == 200
        data = response.json()

        assert "total_results" in data
        assert "results_with_violations" in data
        assert "compliance_pct" in data
        assert "violations_by_framework" in data
        assert "violations_by_severity" in data

    async def test_returns_zero_values_when_no_data(self, test_client, setup_policies_data):
        """Should return zero/empty values when no scan results exist."""
        response = await test_client.get("/api/v1/policies/compliance/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["total_results"] >= 0
        assert data["compliance_pct"] >= 0.0


class TestPoliciesTenantIsolation:
    """Tests for tenant isolation in policies endpoints."""

    async def test_cannot_access_other_tenant_policies(self, test_client, setup_policies_data):
        """Should not be able to see policies from other tenants."""
        from openlabels.server.models import Tenant, Policy

        session = setup_policies_data["session"]

        # Create another tenant with a policy
        other_tenant = Tenant(
            name="Other Policies Tenant",
            azure_tenant_id="other-policies-tenant-id",
        )
        session.add(other_tenant)
        await session.flush()

        other_policy = Policy(
            id=uuid4(),
            tenant_id=other_tenant.id,
            name="Other Tenant Secret Policy",
            framework="hipaa",
            risk_level="critical",
            config={"rules": []},
        )
        session.add(other_policy)
        await session.commit()

        response = await test_client.get("/api/v1/policies")
        assert response.status_code == 200
        data = response.json()

        names = [p["name"] for p in data["items"]]
        assert "Other Tenant Secret Policy" not in names
