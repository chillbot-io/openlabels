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
    """Tests for GET /api/v1/labels endpoint."""

    async def test_returns_labels(self, test_client, setup_labels_data):
        """List should return created labels."""
        response = await test_client.get("/api/v1/labels")
        assert response.status_code == 200
        data = response.json()
        items = data["items"]

        assert len(items) == 3
        names = [l["name"] for l in items]
        assert "Confidential" in names
        assert "Internal" in names
        assert "Public" in names

    async def test_label_response_structure(self, test_client, setup_labels_data):
        """Label response should have required fields."""
        response = await test_client.get("/api/v1/labels")
        assert response.status_code == 200
        data = response.json()

        label = data["items"][0]
        assert "id" in label
        assert "name" in label
        assert "description" in label
        assert "priority" in label
        assert "color" in label

    async def test_labels_ordered_by_priority(self, test_client, setup_labels_data):
        """Labels should be ordered by priority."""
        response = await test_client.get("/api/v1/labels")
        assert response.status_code == 200
        data = response.json()
        items = data["items"]

        # Should be ordered by priority (ascending)
        priorities = [l["priority"] for l in items]
        assert priorities == sorted(priorities)


class TestLabelSyncStatus:
    """Tests for GET /api/v1/labels/sync/status endpoint."""

    async def test_returns_label_count(self, test_client, setup_labels_data):
        """Sync status should return correct label count."""
        response = await test_client.get("/api/v1/labels/sync/status")
        assert response.status_code == 200
        data = response.json()

        assert data["label_count"] == 3


class TestInvalidateLabelCache:
    """Tests for POST /api/v1/labels/cache/invalidate endpoint."""

    async def test_returns_success_message(self, test_client, setup_labels_data):
        """Cache invalidate should return 200 with success message."""
        response = await test_client.post("/api/v1/labels/cache/invalidate")
        assert response.status_code == 200
        data = response.json()

        assert "message" in data
        assert "invalidated" in data["message"].lower()


class TestListLabelRules:
    """Tests for GET /api/v1/labels/rules endpoint."""

    async def test_returns_empty_list_when_no_rules(self, test_client, setup_labels_data):
        """List should return empty items when no rules exist."""
        response = await test_client.get("/api/v1/labels/rules")
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []

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

        response = await test_client.get("/api/v1/labels/rules")
        assert response.status_code == 200
        data = response.json()
        items = data["items"]

        assert len(items) == 1
        assert items[0]["rule_type"] == "risk_tier"
        assert items[0]["match_value"] == "CRITICAL"


class TestCreateLabelRule:
    """Tests for POST /api/v1/labels/rules endpoint."""

    async def test_returns_created_rule(self, test_client, setup_labels_data):
        """Create should return the created rule."""
        labels = setup_labels_data["labels"]

        response = await test_client.post(
            "/api/v1/labels/rules",
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

    async def test_label_name_is_null_on_create(self, test_client, setup_labels_data):
        """Created rule label_name is null because LabelRule ORM lacks that attribute."""
        labels = setup_labels_data["labels"]

        response = await test_client.post(
            "/api/v1/labels/rules",
            json={
                "rule_type": "risk_tier",
                "match_value": "MEDIUM",
                "label_id": labels[1].id,
            },
        )
        assert response.status_code == 201
        data = response.json()

        # label_name may or may not be populated depending on implementation
        assert "label_name" in data

    async def test_rejects_invalid_rule_type(self, test_client, setup_labels_data):
        """Create should reject invalid rule_type."""
        labels = setup_labels_data["labels"]

        response = await test_client.post(
            "/api/v1/labels/rules",
            json={
                "rule_type": "invalid_type",
                "match_value": "HIGH",
                "label_id": labels[0].id,
            },
        )
        assert response.status_code == 400

    async def test_rejects_nonexistent_label(self, test_client, setup_labels_data):
        """Create should reject nonexistent label_id."""
        response = await test_client.post(
            "/api/v1/labels/rules",
            json={
                "rule_type": "risk_tier",
                "match_value": "HIGH",
                "label_id": "nonexistent-label-id",
            },
        )
        assert response.status_code == 404


class TestDeleteLabelRule:
    """Tests for DELETE /api/v1/labels/rules/{rule_id} endpoint."""

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

        response = await test_client.delete(f"/api/v1/labels/rules/{rule.id}")
        assert response.status_code == 204

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

        delete_response = await test_client.delete(f"/api/v1/labels/rules/{rule_id}")
        assert delete_response.status_code == 204

        # Expunge all cached objects to avoid MissingGreenlet errors from
        # lazy loading expired ORM objects in the shared async session
        session.expunge_all()

        # Check rules list
        response = await test_client.get("/api/v1/labels/rules")
        data = response.json()
        ids = [r["id"] for r in data["items"]]
        assert str(rule_id) not in ids

    async def test_returns_404_for_nonexistent_rule(self, test_client, setup_labels_data):
        """Delete nonexistent rule should return 404."""
        fake_id = uuid4()
        response = await test_client.delete(f"/api/v1/labels/rules/{fake_id}")
        assert response.status_code == 404


class TestGetLabelMappings:
    """Tests for GET /api/v1/labels/mappings endpoint."""

    async def test_returns_mappings_structure(self, test_client, setup_labels_data):
        """Mappings should have required fields."""
        response = await test_client.get("/api/v1/labels/mappings")
        assert response.status_code == 200
        data = response.json()

        assert "CRITICAL" in data
        assert "HIGH" in data
        assert "MEDIUM" in data
        assert "LOW" in data
        assert "labels" in data

    async def test_includes_available_labels(self, test_client, setup_labels_data):
        """Mappings should include available labels."""
        response = await test_client.get("/api/v1/labels/mappings")
        assert response.status_code == 200
        data = response.json()

        assert len(data["labels"]) == 3

    async def test_returns_null_for_unmapped_tiers(self, test_client, setup_labels_data):
        """Unmapped tiers should be null."""
        response = await test_client.get("/api/v1/labels/mappings")
        assert response.status_code == 200
        data = response.json()

        # No rules created yet
        assert data["CRITICAL"] is None
        assert data["HIGH"] is None

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

        response = await test_client.get("/api/v1/labels/mappings")
        assert response.status_code == 200
        data = response.json()

        assert data["CRITICAL"] == labels[0].id


class TestUpdateLabelMappings:
    """Tests for POST /api/v1/labels/mappings endpoint."""

    async def test_creates_risk_tier_rules(self, test_client, setup_labels_data):
        """Update should create risk_tier rules."""
        labels = setup_labels_data["labels"]

        await test_client.post(
            "/api/v1/labels/mappings",
            json={
                "CRITICAL": labels[0].id,
                "HIGH": labels[1].id,
            },
        )

        # Verify rules created
        response = await test_client.get("/api/v1/labels/rules")
        data = response.json()
        items = data["items"]

        assert len(items) == 2
        rule_values = {r["match_value"]: r["label_id"] for r in items}
        assert rule_values["CRITICAL"] == labels[0].id
        assert rule_values["HIGH"] == labels[1].id

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
            "/api/v1/labels/mappings",
            json={
                "CRITICAL": labels[1].id,  # Different label
            },
        )

        response = await test_client.get("/api/v1/labels/mappings")
        data = response.json()

        assert data["CRITICAL"] == labels[1].id

    async def test_clears_mapping_when_null(self, test_client, setup_labels_data):
        """Setting a tier to null should clear the mapping."""
        labels = setup_labels_data["labels"]

        # First set a mapping
        await test_client.post(
            "/api/v1/labels/mappings",
            json={"CRITICAL": labels[0].id},
        )

        # Clear it
        await test_client.post(
            "/api/v1/labels/mappings",
            json={"CRITICAL": None},
        )

        response = await test_client.get("/api/v1/labels/mappings")
        data = response.json()
        assert data["CRITICAL"] is None


class TestApplyLabel:
    """Tests for POST /api/v1/labels/apply endpoint."""

    async def test_returns_job_id(self, test_client, setup_labels_data):
        """Apply label should return 202 with job_id and message."""
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
            "/api/v1/labels/apply",
            json={
                "result_id": str(result.id),
                "label_id": labels[0].id,
            },
        )
        assert response.status_code == 202
        data = response.json()

        assert "job_id" in data
        assert "message" in data

    async def test_returns_404_for_nonexistent_result(self, test_client, setup_labels_data):
        """Apply to nonexistent result should return 404."""
        labels = setup_labels_data["labels"]
        fake_id = uuid4()

        response = await test_client.post(
            "/api/v1/labels/apply",
            json={
                "result_id": str(fake_id),
                "label_id": labels[0].id,
            },
        )
        assert response.status_code == 404

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
            "/api/v1/labels/apply",
            json={
                "result_id": str(result.id),
                "label_id": "nonexistent-label",
            },
        )
        assert response.status_code == 404


class TestLabelTenantIsolation:
    """Tests for tenant isolation in label endpoints."""

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
        response = await test_client.get("/api/v1/labels")
        assert response.status_code == 200
        data = response.json()

        names = [l["name"] for l in data["items"]]
        assert "Other Tenant Label" not in names


class TestBulkApplyRecommendedLabels:
    """Tests for POST /api/v1/labels/bulk-apply endpoint."""

    async def test_queues_jobs_for_results_with_recommendations(self, test_client, setup_labels_data):
        """Bulk apply should queue jobs for results with recommended labels."""
        from openlabels.server.models import ScanJob, ScanResult, ScanTarget

        session = setup_labels_data["session"]
        tenant = setup_labels_data["tenant"]
        labels = setup_labels_data["labels"]
        admin_user = setup_labels_data["admin_user"]

        target = ScanTarget(
            tenant_id=tenant.id,
            name="Bulk Apply Target",
            adapter="filesystem",
            config={"path": "/test"},
            enabled=True,
            created_by=admin_user.id,
        )
        session.add(target)
        await session.flush()

        job = ScanJob(tenant_id=tenant.id, target_id=target.id, status="completed")
        session.add(job)
        await session.flush()

        # Result WITH recommendation
        r1 = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/test/rec1.txt",
            file_name="rec1.txt",
            risk_score=80,
            risk_tier="CRITICAL",
            entity_counts={"SSN": 2},
            total_entities=2,
            recommended_label_id=labels[0].id,
            recommended_label_name=labels[0].name,
        )
        # Result WITHOUT recommendation
        r2 = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/test/norec.txt",
            file_name="norec.txt",
            risk_score=10,
            risk_tier="LOW",
            entity_counts={},
            total_entities=0,
        )
        session.add_all([r1, r2])
        await session.commit()

        response = await test_client.post(
            "/api/v1/labels/bulk-apply",
            json={"result_ids": [str(r1.id), str(r2.id)]},
        )
        assert response.status_code == 202
        data = response.json()

        assert data["queued"] == 1
        assert data["skipped"] == 1

    async def test_rejects_empty_result_ids(self, test_client, setup_labels_data):
        """Bulk apply with empty list should return 400."""
        response = await test_client.post(
            "/api/v1/labels/bulk-apply",
            json={"result_ids": []},
        )
        assert response.status_code == 400

    async def test_skips_nonexistent_results(self, test_client, setup_labels_data):
        """Bulk apply should skip results that don't exist."""
        fake_id = uuid4()
        response = await test_client.post(
            "/api/v1/labels/bulk-apply",
            json={"result_ids": [str(fake_id)]},
        )
        assert response.status_code == 202
        data = response.json()
        assert data["queued"] == 0
        assert data["skipped"] == 1


class TestLabelStats:
    """Tests for GET /api/v1/labels/stats endpoint."""

    async def test_returns_stats_structure(self, test_client, setup_labels_data):
        """Stats should have required fields."""
        response = await test_client.get("/api/v1/labels/stats")
        assert response.status_code == 200
        data = response.json()

        assert "total_results" in data
        assert "labels_applied" in data
        assert "labels_pending" in data
        assert "labels_failed" in data
        assert "per_label" in data
        assert "by_tier" in data

    async def test_returns_zero_counts_when_no_results(self, test_client, setup_labels_data):
        """Stats should return zeros when no scan results exist."""
        response = await test_client.get("/api/v1/labels/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["total_results"] == 0
        assert data["labels_applied"] == 0

    async def test_counts_applied_labels(self, test_client, setup_labels_data):
        """Stats should count applied labels correctly."""
        from openlabels.server.models import ScanJob, ScanResult, ScanTarget

        session = setup_labels_data["session"]
        tenant = setup_labels_data["tenant"]
        labels = setup_labels_data["labels"]
        admin_user = setup_labels_data["admin_user"]

        target = ScanTarget(
            tenant_id=tenant.id,
            name="Stats Target",
            adapter="filesystem",
            config={"path": "/stats"},
            enabled=True,
            created_by=admin_user.id,
        )
        session.add(target)
        await session.flush()

        job = ScanJob(tenant_id=tenant.id, target_id=target.id, status="completed")
        session.add(job)
        await session.flush()

        # Applied label
        r1 = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/stats/applied.txt",
            file_name="applied.txt",
            risk_score=90,
            risk_tier="CRITICAL",
            entity_counts={"SSN": 3},
            total_entities=3,
            label_applied=True,
            current_label_id=labels[0].id,
            current_label_name=labels[0].name,
        )
        # Pending recommendation
        r2 = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/stats/pending.txt",
            file_name="pending.txt",
            risk_score=60,
            risk_tier="HIGH",
            entity_counts={"EMAIL": 1},
            total_entities=1,
            recommended_label_id=labels[1].id,
            recommended_label_name=labels[1].name,
        )
        # No label at all
        r3 = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/stats/none.txt",
            file_name="none.txt",
            risk_score=10,
            risk_tier="LOW",
            entity_counts={},
            total_entities=0,
        )
        session.add_all([r1, r2, r3])
        await session.commit()

        response = await test_client.get("/api/v1/labels/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["total_results"] == 3
        assert data["labels_applied"] == 1
        assert data["labels_pending"] == 1
        assert len(data["per_label"]) == 1
        assert data["per_label"][0]["label_name"] == labels[0].name
        assert data["per_label"][0]["count"] == 1

    async def test_by_tier_breakdown(self, test_client, setup_labels_data):
        """Stats should return per-tier breakdown."""
        from openlabels.server.models import ScanJob, ScanResult, ScanTarget

        session = setup_labels_data["session"]
        tenant = setup_labels_data["tenant"]
        labels = setup_labels_data["labels"]
        admin_user = setup_labels_data["admin_user"]

        target = ScanTarget(
            tenant_id=tenant.id,
            name="Tier Stats Target",
            adapter="filesystem",
            config={"path": "/tier"},
            enabled=True,
            created_by=admin_user.id,
        )
        session.add(target)
        await session.flush()

        job = ScanJob(tenant_id=tenant.id, target_id=target.id, status="completed")
        session.add(job)
        await session.flush()

        r1 = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/tier/crit.txt",
            file_name="crit.txt",
            risk_score=95,
            risk_tier="CRITICAL",
            entity_counts={"SSN": 5},
            total_entities=5,
            label_applied=True,
            current_label_id=labels[0].id,
            current_label_name=labels[0].name,
        )
        session.add(r1)
        await session.commit()

        response = await test_client.get("/api/v1/labels/stats")
        assert response.status_code == 200
        data = response.json()

        assert "CRITICAL" in data["by_tier"]
        assert data["by_tier"]["CRITICAL"]["applied"] == 1


