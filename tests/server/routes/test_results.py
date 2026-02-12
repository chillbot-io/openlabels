"""
Comprehensive tests for results API endpoints.

Tests focus on:
- Results listing with filtering
- Result statistics
- Result export (CSV/JSON)
- Single result retrieval
- Result deletion
- Apply recommended label
- Rescan file
- Tenant isolation
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone


@pytest.fixture
async def setup_results_data(test_db):
    """Set up test data for result endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User, ScanJob, ScanTarget

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    admin_user = result.scalar_one()

    # Create a scan target and job
    target = ScanTarget(
        tenant_id=tenant.id,
        name="Results Test Target",
        adapter="filesystem",
        config={"path": "/test"},
        enabled=True,
        created_by=admin_user.id,
    )
    test_db.add(target)
    await test_db.flush()

    job = ScanJob(
        tenant_id=tenant.id,
        target_id=target.id,
        status="completed",
    )
    test_db.add(job)
    await test_db.commit()

    return {
        "tenant": tenant,
        "admin_user": admin_user,
        "target": target,
        "job": job,
        "session": test_db,
    }


class TestListResults:
    """Tests for GET /api/v1/results endpoint."""

    async def test_returns_paginated_structure(self, test_client, setup_results_data):
        """List should return paginated structure with correct types."""
        response = await test_client.get("/api/v1/results")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "total_pages" in data
        assert data["page"] == 1
        assert data["total"] >= 0

    async def test_returns_empty_when_no_results(self, test_client, setup_results_data):
        """List should return empty when no results."""
        response = await test_client.get("/api/v1/results")
        assert response.status_code == 200
        data = response.json()

        assert data["items"] == []
        assert data["total"] == 0

    async def test_returns_results(self, test_client, setup_results_data):
        """List should return scan results."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/test/file.txt",
            file_name="file.txt",
            risk_score=75,
            risk_tier="HIGH",
            entity_counts={"SSN": 2, "EMAIL": 1},
            total_entities=3,
        )
        session.add(result)
        await session.commit()

        response = await test_client.get("/api/v1/results")
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 1
        assert data["items"][0]["file_path"] == "/test/file.txt"

    async def test_result_response_structure(self, test_client, setup_results_data):
        """Result response should have required fields."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/test/structure.txt",
            file_name="structure.txt",
            risk_score=50,
            risk_tier="MEDIUM",
            entity_counts={},
            total_entities=0,
        )
        session.add(result)
        await session.commit()

        response = await test_client.get("/api/v1/results")
        assert response.status_code == 200
        data = response.json()

        item = data["items"][0]
        assert "id" in item
        assert "job_id" in item
        assert "file_path" in item
        assert "file_name" in item
        assert "risk_score" in item
        assert "risk_tier" in item
        assert "entity_counts" in item
        assert "total_entities" in item
        assert "scanned_at" in item

    async def test_filter_by_job_id(self, test_client, setup_results_data):
        """List should filter by job_id."""
        from openlabels.server.models import ScanResult, ScanJob

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        target = setup_results_data["target"]
        job = setup_results_data["job"]

        # Create another job
        job2 = ScanJob(
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        session.add(job2)
        await session.flush()

        # Add results to both jobs (flush after each to avoid asyncpg sentinel matching issues)
        result1 = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/job1/file.txt",
            file_name="file.txt",
            risk_score=50,
            risk_tier="MEDIUM",
            entity_counts={},
            total_entities=0,
        )
        session.add(result1)
        await session.flush()

        result2 = ScanResult(
            tenant_id=tenant.id,
            job_id=job2.id,
            file_path="/job2/file.txt",
            file_name="file.txt",
            risk_score=50,
            risk_tier="MEDIUM",
            entity_counts={},
            total_entities=0,
        )
        session.add(result2)
        await session.commit()

        response = await test_client.get(f"/api/v1/results?job_id={job.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 1
        assert data["items"][0]["file_path"] == "/job1/file.txt"

    async def test_filter_by_risk_tier(self, test_client, setup_results_data):
        """List should filter by risk_tier."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        for tier in ["CRITICAL", "HIGH", "HIGH", "MEDIUM"]:
            result = ScanResult(
                tenant_id=tenant.id,
                job_id=job.id,
                file_path=f"/tier/{tier}.txt",
                file_name=f"{tier}.txt",
                risk_score=90 if tier == "CRITICAL" else 70,
                risk_tier=tier,
                entity_counts={},
                total_entities=0,
            )
            session.add(result)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/results?risk_tier=HIGH")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 2

class TestListResultsCursor:
    """Tests for GET /api/v1/results/cursor endpoint."""

    async def test_returns_cursor_paginated_structure(self, test_client, setup_results_data):
        """Cursor list should return cursor-based pagination structure."""
        response = await test_client.get("/api/v1/results/cursor")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data

    async def test_returns_results_via_cursor(self, test_client, setup_results_data):
        """Should return scan results using cursor pagination."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        for i in range(3):
            result = ScanResult(
                tenant_id=tenant.id,
                job_id=job.id,
                file_path=f"/cursor/file_{i}.txt",
                file_name=f"file_{i}.txt",
                risk_score=50 + i * 10,
                risk_tier="MEDIUM",
                entity_counts={},
                total_entities=0,
            )
            session.add(result)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/results/cursor")
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 3

    async def test_filter_by_risk_tier(self, test_client, setup_results_data):
        """Cursor list should filter by risk_tier."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        for tier in ["HIGH", "HIGH", "MEDIUM"]:
            result = ScanResult(
                tenant_id=tenant.id,
                job_id=job.id,
                file_path=f"/cursor/{tier}.txt",
                file_name=f"{tier}.txt",
                risk_score=70 if tier == "HIGH" else 50,
                risk_tier=tier,
                entity_counts={},
                total_entities=0,
            )
            session.add(result)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/results/cursor?risk_tier=HIGH")
        assert response.status_code == 200
        data = response.json()

        for item in data["items"]:
            assert item["risk_tier"] == "HIGH"


class TestGetResultStats:
    """Tests for GET /api/v1/results/stats endpoint."""

    async def test_returns_stats_structure_with_zero_values(self, test_client, setup_results_data):
        """Stats should return all required fields with zero defaults when no data exists."""
        response = await test_client.get("/api/v1/results/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["total_files"] == 0
        assert data["files_with_pii"] == 0
        assert data["critical_count"] == 0
        assert data["high_count"] == 0
        assert data["medium_count"] == 0
        assert data["low_count"] == 0
        assert data["minimal_count"] == 0
        assert data["top_entity_types"] == {}
        assert data["labels_applied"] == 0
        assert data["labels_pending"] == 0

    async def test_counts_correctly(self, test_client, setup_results_data):
        """Stats should count files correctly."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        # Add results with different tiers
        results = [
            ("CRITICAL", 90, {"SSN": 5}),
            ("CRITICAL", 95, {"SSN": 3}),
            ("HIGH", 75, {"EMAIL": 2}),
            ("MEDIUM", 50, {}),
            ("MINIMAL", 10, {}),
        ]

        for tier, score, entities in results:
            result = ScanResult(
                tenant_id=tenant.id,
                job_id=job.id,
                file_path=f"/stats/{tier}_{score}.txt",
                file_name=f"{tier}_{score}.txt",
                risk_score=score,
                risk_tier=tier,
                entity_counts=entities,
                total_entities=sum(entities.values()),
            )
            session.add(result)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/results/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["total_files"] == 5
        assert data["files_with_pii"] == 3
        assert data["critical_count"] == 2
        assert data["high_count"] == 1


class TestExportResults:
    """Tests for GET /api/v1/results/export endpoint."""

    async def test_csv_export_returns_correct_headers_and_content(self, test_client, setup_results_data):
        """Export CSV should return correct content type, disposition, and CSV header row."""
        response = await test_client.get("/api/v1/results/export?format=csv")
        assert response.status_code == 200
        assert "text/csv" in response.headers.get("content-type", "")
        content_disposition = response.headers.get("content-disposition", "")
        assert "attachment" in content_disposition
        assert "results" in content_disposition
        assert ".csv" in content_disposition
        # Verify CSV header row is present
        body = response.text
        assert "file_path" in body
        assert "risk_score" in body

    async def test_json_export_returns_correct_headers_and_content(self, test_client, setup_results_data):
        """Export JSON should return correct content type, disposition, and valid JSON array."""
        response = await test_client.get("/api/v1/results/export?format=json")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")
        content_disposition = response.headers.get("content-disposition", "")
        assert "attachment" in content_disposition
        assert "results" in content_disposition
        assert ".json" in content_disposition
        # Verify valid JSON array
        import json
        data = json.loads(response.text)
        assert isinstance(data, list)


class TestGetResult:
    """Tests for GET /api/v1/results/{result_id} endpoint."""

    async def test_returns_result_details(self, test_client, setup_results_data):
        """Get should return result details."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/detail/result.txt",
            file_name="result.txt",
            risk_score=85,
            risk_tier="HIGH",
            entity_counts={"SSN": 3},
            total_entities=3,
        )
        session.add(result)
        await session.commit()

        response = await test_client.get(f"/api/v1/results/{result.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(result.id)
        assert data["file_path"] == "/detail/result.txt"
        assert data["risk_score"] == 85

    async def test_returns_404_for_nonexistent(self, test_client, setup_results_data):
        """Get nonexistent result should return 404."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/v1/results/{fake_id}")
        assert response.status_code == 404


class TestDeleteResult:
    """Tests for DELETE /api/v1/results/{result_id} endpoint."""

    async def test_result_is_removed(self, test_client, setup_results_data):
        """Deleted result should no longer exist."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/remove/result.txt",
            file_name="result.txt",
            risk_score=30,
            risk_tier="LOW",
            entity_counts={},
            total_entities=0,
        )
        session.add(result)
        await session.commit()
        result_id = result.id

        await test_client.delete(f"/api/v1/results/{result_id}")

        response = await test_client.get(f"/api/v1/results/{result_id}")
        assert response.status_code == 404

    async def test_returns_404_for_nonexistent(self, test_client, setup_results_data):
        """Delete nonexistent result should return 404."""
        fake_id = uuid4()
        response = await test_client.delete(f"/api/v1/results/{fake_id}")
        assert response.status_code == 404

    async def test_htmx_request_returns_trigger(self, test_client, setup_results_data):
        """HTMX delete should return HX-Trigger header."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/htmx/delete.txt",
            file_name="delete.txt",
            risk_score=20,
            risk_tier="MINIMAL",
            entity_counts={},
            total_entities=0,
        )
        session.add(result)
        await session.commit()

        response = await test_client.delete(
            f"/api/v1/results/{result.id}",
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200
        assert "hx-trigger" in response.headers


class TestClearAllResults:
    """Tests for DELETE /api/v1/results endpoint."""

    async def test_removes_all_results(self, test_client, setup_results_data):
        """Clear should remove all results for tenant."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        # Add multiple results (flush after each to avoid asyncpg sentinel issues)
        for i in range(5):
            result = ScanResult(
                tenant_id=tenant.id,
                job_id=job.id,
                file_path=f"/clear/file_{i}.txt",
                file_name=f"file_{i}.txt",
                risk_score=50,
                risk_tier="MEDIUM",
                entity_counts={},
                total_entities=0,
            )
            session.add(result)
            await session.flush()
        await session.commit()

        delete_response = await test_client.delete("/api/results")
        assert delete_response.status_code == 200

        # Expunge all cached objects to avoid MissingGreenlet errors from
        # lazy loading expired ORM objects in the shared async session
        session = setup_results_data["session"]
        session.expunge_all()

        response = await test_client.get("/api/v1/results")
        data = response.json()
        assert data["total"] == 0

    async def test_htmx_request_returns_trigger(self, test_client, setup_results_data):
        """HTMX clear should return HX-Trigger header."""
        response = await test_client.delete(
            "/api/v1/results",
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200
        assert "hx-trigger" in response.headers


class TestApplyRecommendedLabel:
    """Tests for POST /api/v1/results/{result_id}/apply-label endpoint."""

    async def test_returns_400_when_no_recommended_label(self, test_client, setup_results_data):
        """Apply should return 400 when no recommended label."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/no/label.txt",
            file_name="label.txt",
            risk_score=50,
            risk_tier="MEDIUM",
            entity_counts={},
            total_entities=0,
            recommended_label_id=None,  # No recommended label
        )
        session.add(result)
        await session.commit()

        response = await test_client.post(f"/api/v1/results/{result.id}/apply-label")
        assert response.status_code == 400

    async def test_returns_404_for_nonexistent(self, test_client, setup_results_data):
        """Apply to nonexistent result should return 404."""
        fake_id = uuid4()
        response = await test_client.post(f"/api/v1/results/{fake_id}/apply-label")
        assert response.status_code == 404


class TestRescanFile:
    """Tests for POST /api/v1/results/{result_id}/rescan endpoint."""

    async def test_returns_job_id(self, test_client, setup_results_data):
        """Rescan should return 200 with job_id and message."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/rescan/job.txt",
            file_name="job.txt",
            risk_score=70,
            risk_tier="HIGH",
            entity_counts={},
            total_entities=0,
        )
        session.add(result)
        await session.commit()

        response = await test_client.post(f"/api/v1/results/{result.id}/rescan")
        assert response.status_code == 200
        data = response.json()

        assert "job_id" in data
        assert "message" in data

    async def test_returns_404_for_nonexistent(self, test_client, setup_results_data):
        """Rescan nonexistent result should return 404."""
        fake_id = uuid4()
        response = await test_client.post(f"/api/v1/results/{fake_id}/rescan")
        assert response.status_code == 404


class TestResultsTenantIsolation:
    """Tests for tenant isolation in results endpoints."""

    async def test_cannot_access_other_tenant_results(self, test_client, setup_results_data):
        """Should not be able to see results from other tenants."""
        from openlabels.server.models import Tenant, User, ScanJob, ScanTarget, ScanResult

        session = setup_results_data["session"]

        # Create another tenant with results
        other_tenant = Tenant(
            name="Other Results Tenant",
            azure_tenant_id="other-results-tenant-id",
        )
        session.add(other_tenant)
        await session.flush()

        other_user = User(
            tenant_id=other_tenant.id,
            email="other-results@other.com",
            name="Other User",
            role="admin",
        )
        session.add(other_user)
        await session.flush()

        other_target = ScanTarget(
            tenant_id=other_tenant.id,
            name="Other Target",
            adapter="filesystem",
            config={"path": "/other"},
            enabled=True,
            created_by=other_user.id,
        )
        session.add(other_target)
        await session.flush()

        other_job = ScanJob(
            tenant_id=other_tenant.id,
            target_id=other_target.id,
            status="completed",
        )
        session.add(other_job)
        await session.flush()

        other_result = ScanResult(
            tenant_id=other_tenant.id,
            job_id=other_job.id,
            file_path="/other/tenant/file.txt",
            file_name="file.txt",
            risk_score=50,
            risk_tier="MEDIUM",
            entity_counts={},
            total_entities=0,
        )
        session.add(other_result)
        await session.commit()

        response = await test_client.get("/api/v1/results")
        assert response.status_code == 200
        data = response.json()

        paths = [r["file_path"] for r in data["items"]]
        assert "/other/tenant/file.txt" not in paths


