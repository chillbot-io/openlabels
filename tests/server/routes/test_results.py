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
    """Tests for GET /api/results endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_results_data):
        """List results should return 200 OK."""
        response = await test_client.get("/api/results")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_paginated_structure(self, test_client, setup_results_data):
        """List should return paginated structure."""
        response = await test_client.get("/api/results")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "total_pages" in data

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_results(self, test_client, setup_results_data):
        """List should return empty when no results."""
        response = await test_client.get("/api/results")
        assert response.status_code == 200
        data = response.json()

        assert data["items"] == []
        assert data["total"] == 0

    @pytest.mark.asyncio
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

        response = await test_client.get("/api/results")
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 1
        assert data["items"][0]["file_path"] == "/test/file.txt"

    @pytest.mark.asyncio
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

        response = await test_client.get("/api/results")
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

    @pytest.mark.asyncio
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

        response = await test_client.get(f"/api/results?job_id={job.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 1
        assert data["items"][0]["file_path"] == "/job1/file.txt"

    @pytest.mark.asyncio
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

        response = await test_client.get("/api/results?risk_tier=HIGH")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 2

    @pytest.mark.asyncio
    async def test_filter_by_has_pii(self, test_client, setup_results_data):
        """List should filter by has_pii."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        # Files with PII (flush after each to avoid asyncpg sentinel issues)
        for i in range(3):
            result = ScanResult(
                tenant_id=tenant.id,
                job_id=job.id,
                file_path=f"/pii/file_{i}.txt",
                file_name=f"file_{i}.txt",
                risk_score=80,
                risk_tier="HIGH",
                entity_counts={"SSN": 1},
                total_entities=1,
            )
            session.add(result)
            await session.flush()

        # Files without PII
        for i in range(2):
            result = ScanResult(
                tenant_id=tenant.id,
                job_id=job.id,
                file_path=f"/clean/file_{i}.txt",
                file_name=f"file_{i}.txt",
                risk_score=0,
                risk_tier="MINIMAL",
                entity_counts={},
                total_entities=0,
            )
            session.add(result)
            await session.flush()
        await session.commit()

        # Filter has_pii=true
        response = await test_client.get("/api/results?has_pii=true")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 3

        # Filter has_pii=false
        response = await test_client.get("/api/results?has_pii=false")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 2


class TestGetResultStats:
    """Tests for GET /api/results/stats endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_results_data):
        """Stats should return 200 OK."""
        response = await test_client.get("/api/results/stats")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_stats_structure(self, test_client, setup_results_data):
        """Stats should return required fields."""
        response = await test_client.get("/api/results/stats")
        assert response.status_code == 200
        data = response.json()

        assert "total_files" in data
        assert "files_with_pii" in data
        assert "critical_count" in data
        assert "high_count" in data
        assert "medium_count" in data
        assert "low_count" in data
        assert "minimal_count" in data
        assert "top_entity_types" in data
        assert "labels_applied" in data
        assert "labels_pending" in data

    @pytest.mark.asyncio
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

        response = await test_client.get("/api/results/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["total_files"] == 5
        assert data["files_with_pii"] == 3
        assert data["critical_count"] == 2
        assert data["high_count"] == 1


class TestExportResults:
    """Tests for GET /api/results/export endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status_csv(self, test_client, setup_results_data):
        """Export CSV should return 200 OK."""
        response = await test_client.get("/api/results/export?format=csv")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_200_status_json(self, test_client, setup_results_data):
        """Export JSON should return 200 OK."""
        response = await test_client.get("/api/results/export?format=json")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_csv_content_type(self, test_client, setup_results_data):
        """Export CSV should return text/csv content type."""
        response = await test_client.get("/api/results/export?format=csv")
        assert "text/csv" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_json_content_type(self, test_client, setup_results_data):
        """Export JSON should return application/json content type."""
        response = await test_client.get("/api/results/export?format=json")
        assert "application/json" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_csv_has_content_disposition(self, test_client, setup_results_data):
        """Export CSV should have Content-Disposition header."""
        response = await test_client.get("/api/results/export?format=csv")
        assert "Content-Disposition" in response.headers
        assert "attachment" in response.headers["Content-Disposition"]
        assert ".csv" in response.headers["Content-Disposition"]

    @pytest.mark.asyncio
    async def test_json_has_content_disposition(self, test_client, setup_results_data):
        """Export JSON should have Content-Disposition header."""
        response = await test_client.get("/api/results/export?format=json")
        assert "Content-Disposition" in response.headers
        assert "attachment" in response.headers["Content-Disposition"]
        assert ".json" in response.headers["Content-Disposition"]


class TestGetResult:
    """Tests for GET /api/results/{result_id} endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_results_data):
        """Get result should return 200 OK."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/get/result.txt",
            file_name="result.txt",
            risk_score=60,
            risk_tier="MEDIUM",
            entity_counts={},
            total_entities=0,
        )
        session.add(result)
        await session.commit()

        response = await test_client.get(f"/api/results/{result.id}")
        assert response.status_code == 200

    @pytest.mark.asyncio
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

        response = await test_client.get(f"/api/results/{result.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(result.id)
        assert data["file_path"] == "/detail/result.txt"
        assert data["risk_score"] == 85

    @pytest.mark.asyncio
    async def test_returns_404_for_nonexistent(self, test_client, setup_results_data):
        """Get nonexistent result should return 404."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/results/{fake_id}")
        assert response.status_code == 404


class TestDeleteResult:
    """Tests for DELETE /api/results/{result_id} endpoint."""

    @pytest.mark.asyncio
    async def test_returns_204_status(self, test_client, setup_results_data):
        """Delete result should return 204 No Content."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/delete/result.txt",
            file_name="result.txt",
            risk_score=40,
            risk_tier="LOW",
            entity_counts={},
            total_entities=0,
        )
        session.add(result)
        await session.commit()

        response = await test_client.delete(f"/api/results/{result.id}")
        assert response.status_code == 200

    @pytest.mark.asyncio
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

        await test_client.delete(f"/api/results/{result_id}")

        response = await test_client.get(f"/api/results/{result_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_returns_404_for_nonexistent(self, test_client, setup_results_data):
        """Delete nonexistent result should return 404."""
        fake_id = uuid4()
        response = await test_client.delete(f"/api/results/{fake_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
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
            f"/api/results/{result.id}",
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200
        assert "HX-Trigger" in response.headers


class TestClearAllResults:
    """Tests for DELETE /api/results endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_results_data):
        """Clear all results should return 200 OK."""
        response = await test_client.delete("/api/results")
        assert response.status_code == 200

    @pytest.mark.asyncio
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

        # Expire cached objects so the next query sees the deletions
        session = setup_results_data["session"]
        session.expire_all()

        response = await test_client.get("/api/results")
        data = response.json()
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_htmx_request_returns_trigger(self, test_client, setup_results_data):
        """HTMX clear should return HX-Trigger header."""
        response = await test_client.delete(
            "/api/results",
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200
        assert "HX-Trigger" in response.headers


class TestApplyRecommendedLabel:
    """Tests for POST /api/results/{result_id}/apply-label endpoint."""

    @pytest.mark.asyncio
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

        response = await test_client.post(f"/api/results/{result.id}/apply-label")
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_returns_404_for_nonexistent(self, test_client, setup_results_data):
        """Apply to nonexistent result should return 404."""
        fake_id = uuid4()
        response = await test_client.post(f"/api/results/{fake_id}/apply-label")
        assert response.status_code == 404


class TestRescanFile:
    """Tests for POST /api/results/{result_id}/rescan endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_results_data):
        """Rescan should return 200 OK."""
        from openlabels.server.models import ScanResult

        session = setup_results_data["session"]
        tenant = setup_results_data["tenant"]
        job = setup_results_data["job"]

        result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path="/rescan/file.txt",
            file_name="file.txt",
            risk_score=60,
            risk_tier="MEDIUM",
            entity_counts={},
            total_entities=0,
        )
        session.add(result)
        await session.commit()

        response = await test_client.post(f"/api/results/{result.id}/rescan")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_job_id(self, test_client, setup_results_data):
        """Rescan should return job_id."""
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

        response = await test_client.post(f"/api/results/{result.id}/rescan")
        assert response.status_code == 200
        data = response.json()

        assert "job_id" in data
        assert "message" in data

    @pytest.mark.asyncio
    async def test_returns_404_for_nonexistent(self, test_client, setup_results_data):
        """Rescan nonexistent result should return 404."""
        fake_id = uuid4()
        response = await test_client.post(f"/api/results/{fake_id}/rescan")
        assert response.status_code == 404


class TestResultsTenantIsolation:
    """Tests for tenant isolation in results endpoints."""

    @pytest.mark.asyncio
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

        response = await test_client.get("/api/results")
        assert response.status_code == 200
        data = response.json()

        paths = [r["file_path"] for r in data["items"]]
        assert "/other/tenant/file.txt" not in paths


class TestResultsContentType:
    """Tests for response content type."""

    @pytest.mark.asyncio
    async def test_list_returns_json(self, test_client, setup_results_data):
        """List results should return JSON."""
        response = await test_client.get("/api/results")
        assert "application/json" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_stats_returns_json(self, test_client, setup_results_data):
        """Stats should return JSON."""
        response = await test_client.get("/api/results/stats")
        assert "application/json" in response.headers.get("content-type", "")
