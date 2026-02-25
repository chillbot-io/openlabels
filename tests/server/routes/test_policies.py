"""
Tests for policy management API endpoints (Story 8).

Tests focus on:
- List policies with filtering, rule_count, timestamps
- Create custom policy
- Get policy details
- Update policy
- Delete policy
- Toggle policy enable/disable
- List built-in packs
- Load built-in pack
- Rule builder: GET/PUT rules
- Co-occurrence combinations: PUT combinations
- Exposure multipliers: GET/PUT
- Policy-target assignment: POST/GET/DELETE targets
- Evaluate policies (dry-run) with policy_ids simulation
- Import / export policy definitions
- Compliance statistics
- Tenant isolation
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

    # Create test policies with varied configs including triggers
    policies = []
    configs = [
        {
            "triggers": {
                "any_of": ["SSN", "DRIVERS_LICENSE"],
                "combinations": [["SSN", "DOB"], ["SSN", "ADDRESS"]],
                "min_confidence": 0.7,
            },
            "exposure_multipliers": {"public": 2.5, "external": 1.8, "internal": 1.0, "private": 1.0},
        },
        {
            "triggers": {
                "any_of": ["EMAIL", "PHONE"],
                "all_of": ["PERSON_NAME", "ADDRESS"],
            },
        },
        {"rules": [{"pattern": "test_pci"}]},
        {
            "triggers": {
                "any_of": ["MEDICAL_RECORD"],
                "combinations": [["PERSON_NAME", "DIAGNOSIS"]],
                "min_confidence": 0.8,
                "min_count": 2,
                "exclude_if_only": ["EMAIL"],
            },
        },
    ]

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
            config=configs[i],
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


@pytest.fixture
async def setup_scan_target(test_db, setup_policies_data):
    """Create a scan target for policy-target assignment tests."""
    from openlabels.server.models import ScanTarget

    tenant = setup_policies_data["tenant"]
    target = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="Test File Share",
        adapter="filesystem",
        config={"path": "/data/share"},
        enabled=True,
        created_by=setup_policies_data["admin_user"].id,
    )
    test_db.add(target)
    await test_db.commit()

    return {
        **setup_policies_data,
        "target": target,
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
        """Policy items should have expected fields including rule_count, rules, and timestamps."""
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
        assert "rule_count" in item
        assert "rules" in item
        assert isinstance(item["rules"], list)
        assert "created_at" in item
        assert "updated_at" in item

    async def test_rule_count_computed(self, test_client, setup_policies_data):
        """Rule count should reflect trigger rules in config."""
        policy = setup_policies_data["policies"][0]  # Has 2 any_of + 2 combinations = 4
        response = await test_client.get(f"/api/v1/policies/{policy.id}")
        assert response.status_code == 200
        data = response.json()

        # any_of: ["SSN", "DRIVERS_LICENSE"] = 2
        # combinations: [["SSN", "DOB"], ["SSN", "ADDRESS"]] = 2
        assert data["rule_count"] == 4

    async def test_rules_field_structure(self, test_client, setup_policies_data):
        """Rules field should contain structured PolicyRule objects from triggers."""
        policy = setup_policies_data["policies"][0]
        # Config: any_of: ["SSN", "DRIVERS_LICENSE"], combinations: [["SSN", "DOB"], ["SSN", "ADDRESS"]]
        response = await test_client.get(f"/api/v1/policies/{policy.id}")
        assert response.status_code == 200
        data = response.json()

        rules = data["rules"]
        assert len(rules) == 4  # 2 any_of + 2 combinations

        # Verify any_of rules
        any_of_rules = [r for r in rules if r["type"] == "any_of"]
        assert len(any_of_rules) == 2
        assert any_of_rules[0]["entities"] == ["SSN"]
        assert any_of_rules[1]["entities"] == ["DRIVERS_LICENSE"]
        assert any_of_rules[0]["min_confidence"] == 0.7

        # Verify combination rules
        combo_rules = [r for r in rules if r["type"] == "combination"]
        assert len(combo_rules) == 2
        assert combo_rules[0]["entities"] == ["SSN", "DOB"]
        assert combo_rules[1]["entities"] == ["SSN", "ADDRESS"]

    async def test_rules_field_with_all_of(self, test_client, setup_policies_data):
        """Rules field should include all_of trigger as a single rule."""
        policy = setup_policies_data["policies"][1]
        # Config: any_of: ["EMAIL", "PHONE"], all_of: ["PERSON_NAME", "ADDRESS"]
        response = await test_client.get(f"/api/v1/policies/{policy.id}")
        assert response.status_code == 200
        data = response.json()

        rules = data["rules"]
        all_of_rules = [r for r in rules if r["type"] == "all_of"]
        assert len(all_of_rules) == 1
        assert all_of_rules[0]["entities"] == ["PERSON_NAME", "ADDRESS"]

    async def test_rules_field_empty_when_no_triggers(self, test_client, setup_policies_data):
        """Rules field should be empty list when config has no triggers section."""
        policy = setup_policies_data["policies"][2]
        # Config: {"rules": [{"pattern": "test_pci"}]} — no triggers section
        response = await test_client.get(f"/api/v1/policies/{policy.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["rules"] == []

    async def test_rules_included_in_list_response(self, test_client, setup_policies_data):
        """Every policy in list response should include rules field."""
        response = await test_client.get("/api/v1/policies")
        assert response.status_code == 200
        data = response.json()

        for item in data["items"]:
            assert "rules" in item
            assert isinstance(item["rules"], list)


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
                "config": {"triggers": {"any_of": ["SSN"]}, "rules": [{"pattern": "custom_rule"}]},
                "priority": 10,
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["name"] == "New Custom Policy"
        assert data["framework"] == "soc2"
        assert data["enabled"] is True
        assert data["rule_count"] == 1
        # Story 14: rules field present in create response
        assert "rules" in data
        assert isinstance(data["rules"], list)
        assert len(data["rules"]) == 1
        assert data["rules"][0]["type"] == "any_of"
        assert data["rules"][0]["entities"] == ["SSN"]

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
        assert data["rules"] == []  # No triggers, empty rules


class TestGetPolicy:
    """Tests for GET /api/v1/policies/{policy_id} endpoint."""

    async def test_returns_policy_details(self, test_client, setup_policies_data):
        """Should return policy details including rules field."""
        policy = setup_policies_data["policies"][0]
        response = await test_client.get(f"/api/v1/policies/{policy.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(policy.id)
        assert data["name"] == policy.name
        # Story 14: get response includes rules
        assert "rules" in data
        assert isinstance(data["rules"], list)
        assert len(data["rules"]) > 0

    async def test_returns_404_for_nonexistent(self, test_client, setup_policies_data):
        """Should return 404 for non-existent policy."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/v1/policies/{fake_id}")
        assert response.status_code == 404


class TestUpdatePolicy:
    """Tests for PUT /api/v1/policies/{policy_id} endpoint."""

    async def test_updates_policy_name(self, test_client, setup_policies_data):
        """Should update policy fields and return rules in response."""
        policy = setup_policies_data["policies"][0]
        response = await test_client.put(
            f"/api/v1/policies/{policy.id}",
            json={"name": "Updated Policy Name"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "Updated Policy Name"
        # Story 14: update response includes rules
        assert "rules" in data
        assert isinstance(data["rules"], list)

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

    async def test_evaluate_with_specific_policy_ids(self, test_client, setup_policies_data):
        """Should accept policy_ids for what-if simulation."""
        disabled_policy = setup_policies_data["policies"][2]
        response = await test_client.post(
            "/api/v1/policies/evaluate",
            json={
                "policy_ids": [str(disabled_policy.id)],
                "limit": 10,
            },
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


class TestRuleBuilder:
    """Tests for GET/PUT /api/v1/policies/{id}/rules endpoint."""

    async def test_get_rules(self, test_client, setup_policies_data):
        """Should return structured trigger rules."""
        policy = setup_policies_data["policies"][0]
        response = await test_client.get(f"/api/v1/policies/{policy.id}/rules")
        assert response.status_code == 200
        data = response.json()

        assert data["any_of"] == ["SSN", "DRIVERS_LICENSE"]
        assert data["combinations"] == [["SSN", "DOB"], ["SSN", "ADDRESS"]]
        assert data["min_confidence"] == 0.7
        assert data["all_of"] == []

    async def test_get_rules_empty_triggers(self, test_client, setup_policies_data):
        """Should return defaults for policies without triggers."""
        policy = setup_policies_data["policies"][2]  # Has no triggers section
        response = await test_client.get(f"/api/v1/policies/{policy.id}/rules")
        assert response.status_code == 200
        data = response.json()

        assert data["any_of"] == []
        assert data["all_of"] == []
        assert data["combinations"] == []
        assert data["min_confidence"] == 0.5

    async def test_get_rules_full_config(self, test_client, setup_policies_data):
        """Should return all trigger fields including min_count and exclude_if_only."""
        policy = setup_policies_data["policies"][3]
        response = await test_client.get(f"/api/v1/policies/{policy.id}/rules")
        assert response.status_code == 200
        data = response.json()

        assert data["any_of"] == ["MEDICAL_RECORD"]
        assert data["combinations"] == [["PERSON_NAME", "DIAGNOSIS"]]
        assert data["min_confidence"] == 0.8
        assert data["min_count"] == 2
        assert data["exclude_if_only"] == ["EMAIL"]

    async def test_update_rules(self, test_client, setup_policies_data):
        """Should update trigger rules."""
        policy = setup_policies_data["policies"][0]
        response = await test_client.put(
            f"/api/v1/policies/{policy.id}/rules",
            json={
                "any_of": ["CREDIT_CARD", "BANK_ACCOUNT"],
                "min_confidence": 0.9,
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert data["any_of"] == ["CREDIT_CARD", "BANK_ACCOUNT"]
        assert data["min_confidence"] == 0.9
        # Combinations should remain unchanged
        assert data["combinations"] == [["SSN", "DOB"], ["SSN", "ADDRESS"]]

    async def test_update_rules_persists(self, test_client, setup_policies_data):
        """Updated rules should persist when fetched again."""
        policy = setup_policies_data["policies"][0]

        # Update
        await test_client.put(
            f"/api/v1/policies/{policy.id}/rules",
            json={"any_of": ["PASSPORT"]},
        )

        # Verify persistence
        response = await test_client.get(f"/api/v1/policies/{policy.id}/rules")
        assert response.status_code == 200
        data = response.json()
        assert data["any_of"] == ["PASSPORT"]

    async def test_update_rules_404(self, test_client, setup_policies_data):
        """Should return 404 for non-existent policy."""
        fake_id = uuid4()
        response = await test_client.put(
            f"/api/v1/policies/{fake_id}/rules",
            json={"any_of": ["SSN"]},
        )
        assert response.status_code == 404


class TestCombinations:
    """Tests for PUT /api/v1/policies/{id}/rules/combinations endpoint."""

    async def test_update_combinations(self, test_client, setup_policies_data):
        """Should update co-occurrence combination rules."""
        policy = setup_policies_data["policies"][0]
        response = await test_client.put(
            f"/api/v1/policies/{policy.id}/rules/combinations",
            json={
                "combinations": [
                    ["SSN", "DOB", "ADDRESS"],
                    ["CREDIT_CARD", "CVV"],
                ],
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert data["combinations"] == [
            ["SSN", "DOB", "ADDRESS"],
            ["CREDIT_CARD", "CVV"],
        ]
        # Other triggers should remain
        assert data["any_of"] == ["SSN", "DRIVERS_LICENSE"]

    async def test_update_combinations_persists(self, test_client, setup_policies_data):
        """Updated combinations should persist."""
        policy = setup_policies_data["policies"][0]

        await test_client.put(
            f"/api/v1/policies/{policy.id}/rules/combinations",
            json={"combinations": [["EMAIL", "PHONE", "ADDRESS"]]},
        )

        response = await test_client.get(f"/api/v1/policies/{policy.id}/rules")
        assert response.status_code == 200
        data = response.json()
        assert data["combinations"] == [["EMAIL", "PHONE", "ADDRESS"]]

    async def test_clear_combinations(self, test_client, setup_policies_data):
        """Should be able to clear all combinations."""
        policy = setup_policies_data["policies"][0]
        response = await test_client.put(
            f"/api/v1/policies/{policy.id}/rules/combinations",
            json={"combinations": []},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["combinations"] == []

    async def test_update_combinations_404(self, test_client, setup_policies_data):
        """Should return 404 for non-existent policy."""
        fake_id = uuid4()
        response = await test_client.put(
            f"/api/v1/policies/{fake_id}/rules/combinations",
            json={"combinations": [["SSN", "DOB"]]},
        )
        assert response.status_code == 404


class TestExposureMultipliers:
    """Tests for GET/PUT /api/v1/policies/{id}/exposure-multipliers endpoint."""

    async def test_get_exposure_multipliers(self, test_client, setup_policies_data):
        """Should return exposure multipliers from config."""
        policy = setup_policies_data["policies"][0]  # Has custom multipliers
        response = await test_client.get(f"/api/v1/policies/{policy.id}/exposure-multipliers")
        assert response.status_code == 200
        data = response.json()

        assert data["public"] == 2.5
        assert data["external"] == 1.8
        assert data["internal"] == 1.0
        assert data["private"] == 1.0

    async def test_get_exposure_multipliers_defaults(self, test_client, setup_policies_data):
        """Should return defaults when policy has no exposure_multipliers."""
        policy = setup_policies_data["policies"][1]  # No exposure_multipliers in config
        response = await test_client.get(f"/api/v1/policies/{policy.id}/exposure-multipliers")
        assert response.status_code == 200
        data = response.json()

        assert data["public"] == 2.0
        assert data["external"] == 1.5
        assert data["internal"] == 1.0
        assert data["private"] == 1.0

    async def test_update_exposure_multipliers(self, test_client, setup_policies_data):
        """Should update exposure multipliers."""
        policy = setup_policies_data["policies"][1]
        response = await test_client.put(
            f"/api/v1/policies/{policy.id}/exposure-multipliers",
            json={
                "public": 3.0,
                "external": 2.0,
                "internal": 1.2,
                "private": 1.0,
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert data["public"] == 3.0
        assert data["external"] == 2.0
        assert data["internal"] == 1.2

    async def test_update_exposure_multipliers_persists(self, test_client, setup_policies_data):
        """Updated multipliers should persist."""
        policy = setup_policies_data["policies"][1]

        await test_client.put(
            f"/api/v1/policies/{policy.id}/exposure-multipliers",
            json={"public": 5.0, "external": 3.0, "internal": 1.5, "private": 1.0},
        )

        response = await test_client.get(f"/api/v1/policies/{policy.id}/exposure-multipliers")
        assert response.status_code == 200
        data = response.json()
        assert data["public"] == 5.0
        assert data["external"] == 3.0

    async def test_update_exposure_multipliers_404(self, test_client, setup_policies_data):
        """Should return 404 for non-existent policy."""
        fake_id = uuid4()
        response = await test_client.put(
            f"/api/v1/policies/{fake_id}/exposure-multipliers",
            json={"public": 2.0, "external": 1.5, "internal": 1.0, "private": 1.0},
        )
        assert response.status_code == 404


class TestPolicyTargetAssignment:
    """Tests for policy-target assignment endpoints."""

    async def test_list_targets_empty(self, test_client, setup_scan_target):
        """Should return empty list when no targets assigned."""
        policy = setup_scan_target["policies"][0]
        response = await test_client.get(f"/api/v1/policies/{policy.id}/targets")
        assert response.status_code == 200
        data = response.json()
        assert data == []

    async def test_assign_target(self, test_client, setup_scan_target):
        """Should assign a target to a policy."""
        policy = setup_scan_target["policies"][0]
        target = setup_scan_target["target"]

        response = await test_client.post(
            f"/api/v1/policies/{policy.id}/targets",
            json={"target_ids": [str(target.id)]},
        )
        assert response.status_code == 201
        data = response.json()

        assert len(data) == 1
        assert data[0]["target_id"] == str(target.id)
        assert data[0]["target_name"] == "Test File Share"
        assert "id" in data[0]
        assert "assigned_at" in data[0]

    async def test_list_assigned_targets(self, test_client, setup_scan_target):
        """Should list assigned targets after assignment."""
        policy = setup_scan_target["policies"][0]
        target = setup_scan_target["target"]

        # Assign first
        await test_client.post(
            f"/api/v1/policies/{policy.id}/targets",
            json={"target_ids": [str(target.id)]},
        )

        # List
        response = await test_client.get(f"/api/v1/policies/{policy.id}/targets")
        assert response.status_code == 200
        data = response.json()

        assert len(data) == 1
        assert data[0]["target_id"] == str(target.id)
        assert data[0]["target_name"] == "Test File Share"

    async def test_unassign_target(self, test_client, setup_scan_target):
        """Should remove a target assignment."""
        policy = setup_scan_target["policies"][0]
        target = setup_scan_target["target"]

        # Assign
        await test_client.post(
            f"/api/v1/policies/{policy.id}/targets",
            json={"target_ids": [str(target.id)]},
        )

        # Unassign
        response = await test_client.delete(
            f"/api/v1/policies/{policy.id}/targets/{target.id}",
        )
        assert response.status_code == 204

        # Verify empty
        response = await test_client.get(f"/api/v1/policies/{policy.id}/targets")
        assert response.status_code == 200
        assert response.json() == []

    async def test_unassign_nonexistent_returns_404(self, test_client, setup_scan_target):
        """Should return 404 when unassigning a non-existent assignment."""
        policy = setup_scan_target["policies"][0]
        fake_target_id = uuid4()
        response = await test_client.delete(
            f"/api/v1/policies/{policy.id}/targets/{fake_target_id}",
        )
        assert response.status_code == 404

    async def test_assign_target_404_for_bad_policy(self, test_client, setup_scan_target):
        """Should return 404 for non-existent policy."""
        fake_id = uuid4()
        target = setup_scan_target["target"]
        response = await test_client.post(
            f"/api/v1/policies/{fake_id}/targets",
            json={"target_ids": [str(target.id)]},
        )
        assert response.status_code == 404


class TestImportExport:
    """Tests for import/export policy endpoints."""

    async def test_export_policy(self, test_client, setup_policies_data):
        """Should export a policy definition."""
        policy = setup_policies_data["policies"][0]
        response = await test_client.get(f"/api/v1/policies/{policy.id}/export")
        assert response.status_code == 200
        data = response.json()

        assert data["name"] == policy.name
        assert data["framework"] == policy.framework
        assert data["risk_level"] == policy.risk_level
        assert data["config"] == policy.config
        assert data["enabled"] == policy.enabled
        assert data["priority"] == policy.priority

    async def test_export_policy_404(self, test_client, setup_policies_data):
        """Should return 404 for non-existent policy."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/v1/policies/{fake_id}/export")
        assert response.status_code == 404

    async def test_import_policies(self, test_client, setup_policies_data):
        """Should bulk import policy definitions."""
        response = await test_client.post(
            "/api/v1/policies/import",
            json={
                "policies": [
                    {
                        "name": "Imported Policy 1",
                        "framework": "hipaa",
                        "risk_level": "critical",
                        "config": {"triggers": {"any_of": ["SSN"]}},
                        "priority": 5,
                    },
                    {
                        "name": "Imported Policy 2",
                        "framework": "gdpr",
                        "config": {"triggers": {"any_of": ["EMAIL", "PHONE"]}},
                    },
                ],
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert len(data) == 2
        assert data[0]["name"] == "Imported Policy 1"
        assert data[0]["framework"] == "hipaa"
        assert data[0]["risk_level"] == "critical"
        assert data[1]["name"] == "Imported Policy 2"
        assert data[1]["framework"] == "gdpr"

    async def test_import_export_roundtrip(self, test_client, setup_policies_data):
        """Exported policy should be importable."""
        policy = setup_policies_data["policies"][0]

        # Export
        export_resp = await test_client.get(f"/api/v1/policies/{policy.id}/export")
        assert export_resp.status_code == 200
        exported = export_resp.json()

        # Import the exported definition
        import_resp = await test_client.post(
            "/api/v1/policies/import",
            json={"policies": [exported]},
        )
        assert import_resp.status_code == 201
        imported = import_resp.json()

        assert len(imported) == 1
        assert imported[0]["name"] == exported["name"]
        assert imported[0]["framework"] == exported["framework"]
        assert imported[0]["config"] == exported["config"]


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
