"""
Comprehensive tests for labels API endpoints.

Tests focus on:
- Label listing
- Label sync endpoints
- Label rules CRUD
- Label mappings
- Apply label to file
- Cache invalidation
- Tenant isolation
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone


@pytest.fixture
async def setup_labels_data(test_db):
    """Set up test data for label endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User, SensitivityLabel

    # Get the existing tenant created by test_client (name includes random suffix)
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    admin_user = result.scalar_one()

    # Create some sensitivity labels
    labels = []
    for i, (name, priority) in enumerate([
        ("Confidential", 100),
        ("Internal", 50),
        ("Public", 10),
    ]):
        label = SensitivityLabel(
            id=f"label-{i}-{uuid4().hex[:8]}",
            tenant_id=tenant.id,
            name=name,
            description=f"{name} label for testing",
            priority=priority,
            color="#FF0000" if i == 0 else "#00FF00",
        )
        test_db.add(label)
        labels.append(label)

    await test_db.commit()

    return {
        "tenant": tenant,
        "admin_user": admin_user,
        "labels": labels,
        "session": test_db,
    }


class TestListLabels:
    """Tests for GET /api/labels endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_labels_data):
        """List labels should return 200 OK."""
        response = await test_client.get("/api/labels")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_list(self, test_client, setup_labels_data):
        """List labels should return a list."""
        response = await test_client.get("/api/labels")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_returns_labels(self, test_client, setup_labels_data):
        """List should return created labels."""
        response = await test_client.get("/api/labels")
        assert response.status_code == 200
        data = response.json()

        assert len(data) == 3
        names = [l["name"] for l in data]
        assert "Confidential" in names
        assert "Internal" in names
        assert "Public" in names

    @pytest.mark.asyncio
    async def test_label_response_structure(self, test_client, setup_labels_data):
        """Label response should have required fields."""
        response = await test_client.get("/api/labels")
        assert response.status_code == 200
        data = response.json()

        label = data[0]
        assert "id" in label
        assert "name" in label
        assert "description" in label
        assert "priority" in label
        assert "color" in label

    @pytest.mark.asyncio
    async def test_labels_ordered_by_priority(self, test_client, setup_labels_data):
        """Labels should be ordered by priority."""
        response = await test_client.get("/api/labels")
        assert response.status_code == 200
        data = response.json()

        # Should be ordered by priority (ascending)
        priorities = [l["priority"] for l in data]
        assert priorities == sorted(priorities)


class TestLabelSyncStatus:
    """Tests for GET /api/labels/sync/status endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_labels_data):
        """Sync status should return 200 OK."""
        response = await test_client.get("/api/labels/sync/status")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_status_structure(self, test_client, setup_labels_data):
        """Sync status should return required fields."""
        response = await test_client.get("/api/labels/sync/status")
        assert response.status_code == 200
        data = response.json()

        assert "label_count" in data
        assert "last_synced_at" in data

    @pytest.mark.asyncio
    async def test_returns_label_count(self, test_client, setup_labels_data):
        """Sync status should return correct label count."""
        response = await test_client.get("/api/labels/sync/status")
        assert response.status_code == 200
        data = response.json()

        assert data["label_count"] == 3


class TestInvalidateLabelCache:
    """Tests for POST /api/labels/cache/invalidate endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_labels_data):
        """Cache invalidate should return 200 OK."""
        response = await test_client.post("/api/labels/cache/invalidate")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_success_message(self, test_client, setup_labels_data):
        """Cache invalidate should return success message."""
        response = await test_client.post("/api/labels/cache/invalidate")
        assert response.status_code == 200
        data = response.json()

        assert "message" in data
        assert "invalidated" in data["message"].lower()


class TestListLabelRules:
    """Tests for GET /api/labels/rules endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_labels_data):
        """List rules should return 200 OK."""
        response = await test_client.get("/api/labels/rules")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_list(self, test_client, setup_labels_data):
        """List rules should return a list."""
        response = await test_client.get("/api/labels/rules")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_rules(self, test_client, setup_labels_data):
        """List should return empty when no rules exist."""
        response = await test_client.get("/api/labels/rules")
        assert response.status_code == 200
        data = response.json()
        assert data == []

    @pytest.mark.asyncio
    async def test_returns_rules(self, test_client, setup_labels_data):
        """List should return created rules."""
        from openlabels.server.models import LabelRule

        session = setup_labels_data["session"]
        tenant = setup_labels_data["tenant"]
        labels = setup_labels_data["labels"]
        admin_user = setup_labels_data["admin_user"]

        # Create a rule
        rule = LabelRule(
            tenant_id=tenant.id,
            rule_type="risk_tier",
            match_value="CRITICAL",
            label_id=labels[0].id,
            priority=100,
            created_by=admin_user.id,
        )
        session.add(rule)
        await session.commit()

        response = await test_client.get("/api/labels/rules")
        assert response.status_code == 200
        data = response.json()

        assert len(data) == 1
        assert data[0]["rule_type"] == "risk_tier"
        assert data[0]["match_value"] == "CRITICAL"


class TestCreateLabelRule:
    """Tests for POST /api/labels/rules endpoint."""

    @pytest.mark.asyncio
    async def test_returns_201_status(self, test_client, setup_labels_data):
        """Create rule should return 201 Created."""
        labels = setup_labels_data["labels"]

        response = await test_client.post(
            "/api/labels/rules",
            json={
                "rule_type": "risk_tier",
                "match_value": "HIGH",
                "label_id": labels[0].id,
                "priority": 50,
            },
        )
        assert response.status_code == 201

    @pytest.mark.asyncio
    async def test_returns_created_rule(self, test_client, setup_labels_data):
        """Create should return the created rule."""
        labels = setup_labels_data["labels"]

        response = await test_client.post(
            "/api/labels/rules",
            json={
                "rule_type": "entity_type",
                "match_value": "SSN",
                "label_id": labels[1].id,
                "priority": 75,
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["rule_type"] == "entity_type"
        assert data["match_value"] == "SSN"
        assert data["label_id"] == labels[1].id
        assert "id" in data

    @pytest.mark.asyncio
    async def test_includes_label_name(self, test_client, setup_labels_data):
        """Created rule should include label name."""
        labels = setup_labels_data["labels"]

        response = await test_client.post(
            "/api/labels/rules",
            json={
                "rule_type": "risk_tier",
                "match_value": "MEDIUM",
                "label_id": labels[1].id,
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["label_name"] == "Internal"

    @pytest.mark.asyncio
    async def test_rejects_invalid_rule_type(self, test_client, setup_labels_data):
        """Create should reject invalid rule_type."""
        labels = setup_labels_data["labels"]

        response = await test_client.post(
            "/api/labels/rules",
            json={
                "rule_type": "invalid_type",
                "match_value": "HIGH",
                "label_id": labels[0].id,
            },
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_rejects_nonexistent_label(self, test_client, setup_labels_data):
        """Create should reject nonexistent label_id."""
        response = await test_client.post(
            "/api/labels/rules",
            json={
                "rule_type": "risk_tier",
                "match_value": "HIGH",
                "label_id": "nonexistent-label-id",
            },
        )
        assert response.status_code == 404


class TestDeleteLabelRule:
    """Tests for DELETE /api/labels/rules/{rule_id} endpoint."""

    @pytest.mark.asyncio
    async def test_returns_204_status(self, test_client, setup_labels_data):
        """Delete rule should return 204 No Content."""
        from openlabels.server.models import LabelRule

        session = setup_labels_data["session"]
        tenant = setup_labels_data["tenant"]
        labels = setup_labels_data["labels"]
        admin_user = setup_labels_data["admin_user"]

        rule = LabelRule(
            tenant_id=tenant.id,
            rule_type="risk_tier",
            match_value="LOW",
            label_id=labels[2].id,
            priority=10,
            created_by=admin_user.id,
        )
        session.add(rule)
        await session.commit()

        response = await test_client.delete(f"/api/labels/rules/{rule.id}")
        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_rule_is_removed(self, test_client, setup_labels_data):
        """Deleted rule should no longer exist."""
        from openlabels.server.models import LabelRule

        session = setup_labels_data["session"]
        tenant = setup_labels_data["tenant"]
        labels = setup_labels_data["labels"]
        admin_user = setup_labels_data["admin_user"]

        rule = LabelRule(
            tenant_id=tenant.id,
            rule_type="entity_type",
            match_value="EMAIL",
            label_id=labels[1].id,
            priority=20,
            created_by=admin_user.id,
        )
        session.add(rule)
        await session.commit()
        rule_id = rule.id

        await test_client.delete(f"/api/labels/rules/{rule_id}")

        # Check rules list
        response = await test_client.get("/api/labels/rules")
        data = response.json()
        ids = [r["id"] for r in data]
        assert str(rule_id) not in ids

    @pytest.mark.asyncio
    async def test_returns_404_for_nonexistent_rule(self, test_client, setup_labels_data):
        """Delete nonexistent rule should return 404."""
        fake_id = uuid4()
        response = await test_client.delete(f"/api/labels/rules/{fake_id}")
        assert response.status_code == 404


class TestGetLabelMappings:
    """Tests for GET /api/labels/mappings endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_labels_data):
        """Get mappings should return 200 OK."""
        response = await test_client.get("/api/labels/mappings")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_mappings_structure(self, test_client, setup_labels_data):
        """Mappings should have required fields."""
        response = await test_client.get("/api/labels/mappings")
        assert response.status_code == 200
        data = response.json()

        assert "CRITICAL" in data
        assert "HIGH" in data
        assert "MEDIUM" in data
        assert "LOW" in data
        assert "labels" in data

    @pytest.mark.asyncio
    async def test_includes_available_labels(self, test_client, setup_labels_data):
        """Mappings should include available labels."""
        response = await test_client.get("/api/labels/mappings")
        assert response.status_code == 200
        data = response.json()

        assert len(data["labels"]) == 3

    @pytest.mark.asyncio
    async def test_returns_null_for_unmapped_tiers(self, test_client, setup_labels_data):
        """Unmapped tiers should be null."""
        response = await test_client.get("/api/labels/mappings")
        assert response.status_code == 200
        data = response.json()

        # No rules created yet
        assert data["CRITICAL"] is None
        assert data["HIGH"] is None

    @pytest.mark.asyncio
    async def test_returns_label_id_for_mapped_tiers(self, test_client, setup_labels_data):
        """Mapped tiers should have label_id."""
        from openlabels.server.models import LabelRule

        session = setup_labels_data["session"]
        tenant = setup_labels_data["tenant"]
        labels = setup_labels_data["labels"]
        admin_user = setup_labels_data["admin_user"]

        # Create risk_tier rule
        rule = LabelRule(
            tenant_id=tenant.id,
            rule_type="risk_tier",
            match_value="CRITICAL",
            label_id=labels[0].id,
            priority=100,
            created_by=admin_user.id,
        )
        session.add(rule)
        await session.commit()

        response = await test_client.get("/api/labels/mappings")
        assert response.status_code == 200
        data = response.json()

        assert data["CRITICAL"] == labels[0].id


class TestUpdateLabelMappings:
    """Tests for POST /api/labels/mappings endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status_json(self, test_client, setup_labels_data):
        """Update mappings should return 200 OK for JSON."""
        labels = setup_labels_data["labels"]

        response = await test_client.post(
            "/api/labels/mappings",
            json={
                "CRITICAL": labels[0].id,
                "HIGH": labels[1].id,
            },
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_creates_risk_tier_rules(self, test_client, setup_labels_data):
        """Update should create risk_tier rules."""
        labels = setup_labels_data["labels"]

        await test_client.post(
            "/api/labels/mappings",
            json={
                "CRITICAL": labels[0].id,
                "HIGH": labels[1].id,
            },
        )

        # Verify rules created
        response = await test_client.get("/api/labels/rules")
        data = response.json()

        assert len(data) == 2
        rule_values = {r["match_value"]: r["label_id"] for r in data}
        assert rule_values["CRITICAL"] == labels[0].id
        assert rule_values["HIGH"] == labels[1].id

    @pytest.mark.asyncio
    async def test_replaces_existing_rules(self, test_client, setup_labels_data):
        """Update should replace existing risk_tier rules."""
        from openlabels.server.models import LabelRule

        session = setup_labels_data["session"]
        tenant = setup_labels_data["tenant"]
        labels = setup_labels_data["labels"]
        admin_user = setup_labels_data["admin_user"]

        # Create existing rule
        rule = LabelRule(
            tenant_id=tenant.id,
            rule_type="risk_tier",
            match_value="CRITICAL",
            label_id=labels[0].id,
            priority=100,
            created_by=admin_user.id,
        )
        session.add(rule)
        await session.commit()

        # Update with new mapping
        await test_client.post(
            "/api/labels/mappings",
            json={
                "CRITICAL": labels[1].id,  # Different label
            },
        )

        response = await test_client.get("/api/labels/mappings")
        data = response.json()

        assert data["CRITICAL"] == labels[1].id

    @pytest.mark.asyncio
    async def test_htmx_request_returns_trigger(self, test_client, setup_labels_data):
        """HTMX request should return HX-Trigger header."""
        labels = setup_labels_data["labels"]

        response = await test_client.post(
            "/api/labels/mappings",
            data={
                "CRITICAL": labels[0].id,
            },
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200
        assert "HX-Trigger" in response.headers


class TestApplyLabel:
    """Tests for POST /api/labels/apply endpoint."""

    @pytest.mark.asyncio
    async def test_returns_202_status(self, test_client, setup_labels_data):
        """Apply label should return 202 Accepted."""
        from openlabels.server.models import ScanJob, ScanResult, ScanTarget

        session = setup_labels_data["session"]
        tenant = setup_labels_data["tenant"]
        labels = setup_labels_data["labels"]
        admin_user = setup_labels_data["admin_user"]

        # Create target, job and result
        target = ScanTarget(
            tenant_id=tenant.id,
            name="Label Test Target",
            adapter="filesystem",
            config={"path": "/test"},
            enabled=True,
            created_by=admin_user.id,
        )
        session.add(target)
        await session.flush()

        job = ScanJob(
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        session.add(job)
        await session.flush()

        result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/test/file.txt",
            file_name="file.txt",
            risk_score=80,
            risk_tier="HIGH",
            entity_counts={"SSN": 1},
            total_entities=1,
        )
        session.add(result)
        await session.commit()

        response = await test_client.post(
            "/api/labels/apply",
            json={
                "result_id": str(result.id),
                "label_id": labels[0].id,
            },
        )
        assert response.status_code == 202

    @pytest.mark.asyncio
    async def test_returns_job_id(self, test_client, setup_labels_data):
        """Apply label should return job_id."""
        from openlabels.server.models import ScanJob, ScanResult, ScanTarget

        session = setup_labels_data["session"]
        tenant = setup_labels_data["tenant"]
        labels = setup_labels_data["labels"]
        admin_user = setup_labels_data["admin_user"]

        target = ScanTarget(
            tenant_id=tenant.id,
            name="Apply Label Target",
            adapter="filesystem",
            config={"path": "/test"},
            enabled=True,
            created_by=admin_user.id,
        )
        session.add(target)
        await session.flush()

        job = ScanJob(
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        session.add(job)
        await session.flush()

        result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/test/apply.txt",
            file_name="apply.txt",
            risk_score=70,
            risk_tier="HIGH",
            entity_counts={},
            total_entities=0,
        )
        session.add(result)
        await session.commit()

        response = await test_client.post(
            "/api/labels/apply",
            json={
                "result_id": str(result.id),
                "label_id": labels[0].id,
            },
        )
        assert response.status_code == 202
        data = response.json()

        assert "job_id" in data
        assert "message" in data

    @pytest.mark.asyncio
    async def test_returns_404_for_nonexistent_result(self, test_client, setup_labels_data):
        """Apply to nonexistent result should return 404."""
        labels = setup_labels_data["labels"]
        fake_id = uuid4()

        response = await test_client.post(
            "/api/labels/apply",
            json={
                "result_id": str(fake_id),
                "label_id": labels[0].id,
            },
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_returns_404_for_nonexistent_label(self, test_client, setup_labels_data):
        """Apply nonexistent label should return 404."""
        from openlabels.server.models import ScanJob, ScanResult, ScanTarget

        session = setup_labels_data["session"]
        tenant = setup_labels_data["tenant"]
        admin_user = setup_labels_data["admin_user"]

        target = ScanTarget(
            tenant_id=tenant.id,
            name="Bad Label Target",
            adapter="filesystem",
            config={"path": "/test"},
            enabled=True,
            created_by=admin_user.id,
        )
        session.add(target)
        await session.flush()

        job = ScanJob(
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        session.add(job)
        await session.flush()

        result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/test/bad_label.txt",
            file_name="bad_label.txt",
            risk_score=50,
            risk_tier="MEDIUM",
            entity_counts={},
            total_entities=0,
        )
        session.add(result)
        await session.commit()

        response = await test_client.post(
            "/api/labels/apply",
            json={
                "result_id": str(result.id),
                "label_id": "nonexistent-label",
            },
        )
        assert response.status_code == 404


class TestLabelTenantIsolation:
    """Tests for tenant isolation in label endpoints."""

    @pytest.mark.asyncio
    async def test_cannot_access_other_tenant_labels(self, test_client, setup_labels_data):
        """Should not be able to see labels from other tenants."""
        from openlabels.server.models import Tenant, SensitivityLabel

        session = setup_labels_data["session"]

        # Create another tenant with label
        other_tenant = Tenant(
            name="Other Label Tenant",
            azure_tenant_id="other-label-tenant-id",
        )
        session.add(other_tenant)
        await session.flush()

        other_label = SensitivityLabel(
            id=f"other-label-{uuid4().hex[:8]}",
            tenant_id=other_tenant.id,
            name="Other Tenant Label",
            priority=50,
        )
        session.add(other_label)
        await session.commit()

        # List labels - should not include other tenant's label
        response = await test_client.get("/api/labels")
        assert response.status_code == 200
        data = response.json()

        names = [l["name"] for l in data]
        assert "Other Tenant Label" not in names


class TestLabelContentType:
    """Tests for response content type."""

    @pytest.mark.asyncio
    async def test_list_returns_json(self, test_client, setup_labels_data):
        """List labels should return JSON."""
        response = await test_client.get("/api/labels")
        assert "application/json" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_rules_returns_json(self, test_client, setup_labels_data):
        """List rules should return JSON."""
        response = await test_client.get("/api/labels/rules")
        assert "application/json" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_mappings_returns_json(self, test_client, setup_labels_data):
        """Get mappings should return JSON."""
        response = await test_client.get("/api/labels/mappings")
        assert "application/json" in response.headers.get("content-type", "")
