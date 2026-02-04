"""
Comprehensive tests for dashboard API endpoints.

Tests focus on:
- Overall statistics endpoint
- Trend data over time
- Entity trends by type
- Access heatmap data
- File heatmap visualization
- Tenant isolation
- Response structure validation
"""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4


@pytest.fixture
async def setup_dashboard_data(test_db):
    """Set up test data for dashboard endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import (
        Tenant, User, ScanJob, ScanResult, ScanTarget,
    )

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    user = result.scalar_one()

    # Create a scan target
    target = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="Dashboard Test Target",
        adapter="filesystem",
        config={"path": "/test"},
        enabled=True,
        created_by=user.id,
    )
    test_db.add(target)
    await test_db.commit()

    return {
        "tenant": tenant,
        "user": user,
        "target": target,
        "session": test_db,
    }


class TestOverallStats:
    """Tests for GET /api/dashboard/stats endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_dashboard_data):
        """Stats endpoint should return 200 OK."""
        response = await test_client.get("/api/dashboard/stats")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_all_required_fields(self, test_client, setup_dashboard_data):
        """Stats response should have all required fields."""
        response = await test_client.get("/api/dashboard/stats")
        assert response.status_code == 200
        data = response.json()

        assert "total_scans" in data
        assert "total_files_scanned" in data
        assert "files_with_pii" in data
        assert "labels_applied" in data
        assert "critical_files" in data
        assert "high_files" in data
        assert "active_scans" in data

    @pytest.mark.asyncio
    async def test_returns_zero_values_for_empty_tenant(self, test_client, setup_dashboard_data):
        """Stats should return zeros when no data exists."""
        response = await test_client.get("/api/dashboard/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["total_scans"] == 0
        assert data["total_files_scanned"] == 0
        assert data["files_with_pii"] == 0
        assert data["labels_applied"] == 0
        assert data["active_scans"] == 0

    @pytest.mark.asyncio
    async def test_counts_scans_correctly(self, test_client, setup_dashboard_data):
        """Stats should count scans correctly."""
        from openlabels.server.models import ScanJob

        session = setup_dashboard_data["session"]
        tenant = setup_dashboard_data["tenant"]
        target = setup_dashboard_data["target"]

        # Add scan jobs
        for i in range(5):
            scan = ScanJob(
                id=uuid4(),
                tenant_id=tenant.id,
                target_id=target.id,
                status="completed",
            )
            session.add(scan)
        await session.commit()

        response = await test_client.get("/api/dashboard/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["total_scans"] == 5

    @pytest.mark.asyncio
    async def test_counts_active_scans(self, test_client, setup_dashboard_data):
        """Stats should count active (pending/running) scans."""
        from openlabels.server.models import ScanJob

        session = setup_dashboard_data["session"]
        tenant = setup_dashboard_data["tenant"]
        target = setup_dashboard_data["target"]

        # Add active scans
        for status in ["pending", "running", "pending"]:
            scan = ScanJob(
                id=uuid4(),
                tenant_id=tenant.id,
                target_id=target.id,
                status=status,
            )
            session.add(scan)

        # Add completed scan (should not count as active)
        scan = ScanJob(
            id=uuid4(),
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        session.add(scan)
        await session.commit()

        response = await test_client.get("/api/dashboard/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["active_scans"] == 3
        assert data["total_scans"] == 4

    @pytest.mark.asyncio
    async def test_counts_files_with_pii(self, test_client, setup_dashboard_data):
        """Stats should count files with PII correctly."""
        from openlabels.server.models import ScanJob, ScanResult

        session = setup_dashboard_data["session"]
        tenant = setup_dashboard_data["tenant"]
        target = setup_dashboard_data["target"]

        # Create scan job
        scan = ScanJob(
            id=uuid4(),
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        session.add(scan)
        await session.flush()

        # Add results - some with PII, some without
        for i in range(3):
            result = ScanResult(
                id=uuid4(),
                tenant_id=tenant.id,
                job_id=scan.id,
                file_path=f"/test/file_with_pii_{i}.txt",
                file_name=f"file_with_pii_{i}.txt",
                risk_score=80,
                risk_tier="HIGH",
                entity_counts={"SSN": 2, "EMAIL": 1},
                total_entities=3,  # Has PII
            )
            session.add(result)

        for i in range(2):
            result = ScanResult(
                id=uuid4(),
                tenant_id=tenant.id,
                job_id=scan.id,
                file_path=f"/test/clean_file_{i}.txt",
                file_name=f"clean_file_{i}.txt",
                risk_score=0,
                risk_tier="MINIMAL",
                entity_counts={},
                total_entities=0,  # No PII
            )
            session.add(result)
        await session.commit()

        response = await test_client.get("/api/dashboard/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["total_files_scanned"] == 5
        assert data["files_with_pii"] == 3

    @pytest.mark.asyncio
    async def test_counts_risk_tiers(self, test_client, setup_dashboard_data):
        """Stats should count critical and high files correctly."""
        from openlabels.server.models import ScanJob, ScanResult

        session = setup_dashboard_data["session"]
        tenant = setup_dashboard_data["tenant"]
        target = setup_dashboard_data["target"]

        scan = ScanJob(
            id=uuid4(),
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        session.add(scan)
        await session.flush()

        # Add results with different risk tiers
        for tier, count in [("CRITICAL", 2), ("HIGH", 3), ("MEDIUM", 4), ("LOW", 5)]:
            for i in range(count):
                result = ScanResult(
                    id=uuid4(),
                    tenant_id=tenant.id,
                    job_id=scan.id,
                    file_path=f"/test/{tier}_{i}.txt",
                    file_name=f"{tier}_{i}.txt",
                    risk_score=90 if tier == "CRITICAL" else 70,
                    risk_tier=tier,
                    entity_counts={},
                    total_entities=1,
                )
                session.add(result)
        await session.commit()

        response = await test_client.get("/api/dashboard/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["critical_files"] == 2
        assert data["high_files"] == 3

    @pytest.mark.asyncio
    async def test_counts_labels_applied(self, test_client, setup_dashboard_data):
        """Stats should count files with labels applied."""
        from openlabels.server.models import ScanJob, ScanResult

        session = setup_dashboard_data["session"]
        tenant = setup_dashboard_data["tenant"]
        target = setup_dashboard_data["target"]

        scan = ScanJob(
            id=uuid4(),
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        session.add(scan)
        await session.flush()

        # Add results - some with labels, some without
        for i in range(4):
            result = ScanResult(
                id=uuid4(),
                tenant_id=tenant.id,
                job_id=scan.id,
                file_path=f"/test/labeled_{i}.txt",
                file_name=f"labeled_{i}.txt",
                risk_score=50,
                risk_tier="MEDIUM",
                entity_counts={},
                total_entities=1,
                label_applied=True,  # Label applied
            )
            session.add(result)

        for i in range(3):
            result = ScanResult(
                id=uuid4(),
                tenant_id=tenant.id,
                job_id=scan.id,
                file_path=f"/test/unlabeled_{i}.txt",
                file_name=f"unlabeled_{i}.txt",
                risk_score=50,
                risk_tier="MEDIUM",
                entity_counts={},
                total_entities=1,
                label_applied=False,  # No label
            )
            session.add(result)
        await session.commit()

        response = await test_client.get("/api/dashboard/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["labels_applied"] == 4


class TestTrends:
    """Tests for GET /api/dashboard/trends endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_dashboard_data):
        """Trends endpoint should return 200 OK."""
        response = await test_client.get("/api/dashboard/trends")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_points_array(self, test_client, setup_dashboard_data):
        """Trends response should have points array."""
        response = await test_client.get("/api/dashboard/trends")
        assert response.status_code == 200
        data = response.json()

        assert "points" in data
        assert isinstance(data["points"], list)

    @pytest.mark.asyncio
    async def test_default_30_days(self, test_client, setup_dashboard_data):
        """Trends should return 31 points by default (30 days + today)."""
        response = await test_client.get("/api/dashboard/trends")
        assert response.status_code == 200
        data = response.json()

        # Should have ~31 points (30 days + current day)
        assert len(data["points"]) >= 30

    @pytest.mark.asyncio
    async def test_custom_days_parameter(self, test_client, setup_dashboard_data):
        """Trends should respect days parameter."""
        response = await test_client.get("/api/dashboard/trends?days=7")
        assert response.status_code == 200
        data = response.json()

        # Should have 7-8 points
        assert len(data["points"]) >= 7
        assert len(data["points"]) <= 9

    @pytest.mark.asyncio
    async def test_point_structure(self, test_client, setup_dashboard_data):
        """Each trend point should have required fields."""
        response = await test_client.get("/api/dashboard/trends?days=7")
        assert response.status_code == 200
        data = response.json()

        for point in data["points"]:
            assert "date" in point
            assert "files_scanned" in point
            assert "files_with_pii" in point
            assert "labels_applied" in point

    @pytest.mark.asyncio
    async def test_days_validation_min(self, test_client, setup_dashboard_data):
        """Trends should reject days < 1."""
        response = await test_client.get("/api/dashboard/trends?days=0")
        assert response.status_code == 422  # Validation error

    @pytest.mark.asyncio
    async def test_days_validation_max(self, test_client, setup_dashboard_data):
        """Trends should reject days > 365."""
        response = await test_client.get("/api/dashboard/trends?days=400")
        assert response.status_code == 422  # Validation error

    @pytest.mark.asyncio
    async def test_aggregates_by_date(self, test_client, setup_dashboard_data):
        """Trends should aggregate results by date."""
        from openlabels.server.models import ScanJob, ScanResult

        session = setup_dashboard_data["session"]
        tenant = setup_dashboard_data["tenant"]
        target = setup_dashboard_data["target"]

        scan = ScanJob(
            id=uuid4(),
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        session.add(scan)
        await session.flush()

        # Add results for today
        now = datetime.now(timezone.utc)
        for i in range(5):
            result = ScanResult(
                id=uuid4(),
                tenant_id=tenant.id,
                job_id=scan.id,
                file_path=f"/test/today_{i}.txt",
                file_name=f"today_{i}.txt",
                risk_score=50,
                risk_tier="MEDIUM",
                entity_counts={"SSN": 1},
                total_entities=1,
                scanned_at=now,
            )
            session.add(result)
        await session.commit()

        response = await test_client.get("/api/dashboard/trends?days=7")
        assert response.status_code == 200
        data = response.json()

        # Today's point should have the data
        today_str = now.strftime("%Y-%m-%d")
        today_point = next((p for p in data["points"] if p["date"] == today_str), None)
        assert today_point is not None
        assert today_point["files_scanned"] == 5


class TestEntityTrends:
    """Tests for GET /api/dashboard/entity-trends endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_dashboard_data):
        """Entity trends endpoint should return 200 OK."""
        response = await test_client.get("/api/dashboard/entity-trends")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_series_dict(self, test_client, setup_dashboard_data):
        """Entity trends response should have series dict."""
        response = await test_client.get("/api/dashboard/entity-trends")
        assert response.status_code == 200
        data = response.json()

        assert "series" in data
        assert isinstance(data["series"], dict)

    @pytest.mark.asyncio
    async def test_includes_total_series(self, test_client, setup_dashboard_data):
        """Entity trends should always include Total series."""
        response = await test_client.get("/api/dashboard/entity-trends")
        assert response.status_code == 200
        data = response.json()

        assert "Total" in data["series"]

    @pytest.mark.asyncio
    async def test_default_14_days(self, test_client, setup_dashboard_data):
        """Entity trends should default to 14 days."""
        response = await test_client.get("/api/dashboard/entity-trends")
        assert response.status_code == 200
        data = response.json()

        # Total series should have ~15 points
        assert len(data["series"]["Total"]) >= 14

    @pytest.mark.asyncio
    async def test_custom_days_parameter(self, test_client, setup_dashboard_data):
        """Entity trends should respect days parameter."""
        response = await test_client.get("/api/dashboard/entity-trends?days=7")
        assert response.status_code == 200
        data = response.json()

        assert len(data["series"]["Total"]) >= 7
        assert len(data["series"]["Total"]) <= 9

    @pytest.mark.asyncio
    async def test_series_point_format(self, test_client, setup_dashboard_data):
        """Each series point should be [date, count] tuple."""
        response = await test_client.get("/api/dashboard/entity-trends?days=7")
        assert response.status_code == 200
        data = response.json()

        for point in data["series"]["Total"]:
            assert isinstance(point, list)
            assert len(point) == 2
            # First element is date string
            assert isinstance(point[0], str)
            # Second element is count
            assert isinstance(point[1], int)


class TestAccessHeatmap:
    """Tests for GET /api/dashboard/access-heatmap endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_dashboard_data):
        """Access heatmap endpoint should return 200 OK."""
        response = await test_client.get("/api/dashboard/access-heatmap")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_7x24_matrix(self, test_client, setup_dashboard_data):
        """Access heatmap should return 7x24 matrix."""
        response = await test_client.get("/api/dashboard/access-heatmap")
        assert response.status_code == 200
        data = response.json()

        assert "data" in data
        assert len(data["data"]) == 7  # 7 days
        for day in data["data"]:
            assert len(day) == 24  # 24 hours

    @pytest.mark.asyncio
    async def test_all_values_are_integers(self, test_client, setup_dashboard_data):
        """All heatmap values should be integers."""
        response = await test_client.get("/api/dashboard/access-heatmap")
        assert response.status_code == 200
        data = response.json()

        for day in data["data"]:
            for hour in day:
                assert isinstance(hour, int)

    @pytest.mark.asyncio
    async def test_returns_zeros_when_no_data(self, test_client, setup_dashboard_data):
        """Heatmap should return all zeros when no access events exist."""
        response = await test_client.get("/api/dashboard/access-heatmap")
        assert response.status_code == 200
        data = response.json()

        total = sum(sum(day) for day in data["data"])
        assert total == 0


class TestHeatmap:
    """Tests for GET /api/dashboard/heatmap endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_dashboard_data):
        """Heatmap endpoint should return 200 OK."""
        response = await test_client.get("/api/dashboard/heatmap")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_roots_array(self, test_client, setup_dashboard_data):
        """Heatmap response should have roots array."""
        response = await test_client.get("/api/dashboard/heatmap")
        assert response.status_code == 200
        data = response.json()

        assert "roots" in data
        assert isinstance(data["roots"], list)

    @pytest.mark.asyncio
    async def test_empty_roots_when_no_data(self, test_client, setup_dashboard_data):
        """Heatmap should return empty roots when no results exist."""
        response = await test_client.get("/api/dashboard/heatmap")
        assert response.status_code == 200
        data = response.json()

        assert data["roots"] == []

    @pytest.mark.asyncio
    async def test_builds_tree_from_file_paths(self, test_client, setup_dashboard_data):
        """Heatmap should build tree structure from file paths."""
        from openlabels.server.models import ScanJob, ScanResult

        session = setup_dashboard_data["session"]
        tenant = setup_dashboard_data["tenant"]
        target = setup_dashboard_data["target"]

        scan = ScanJob(
            id=uuid4(),
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        session.add(scan)
        await session.flush()

        # Add results with hierarchical paths
        result = ScanResult(
            id=uuid4(),
            tenant_id=tenant.id,
            job_id=scan.id,
            file_path="/documents/reports/annual.pdf",
            file_name="annual.pdf",
            risk_score=80,
            risk_tier="HIGH",
            entity_counts={"SSN": 5},
            total_entities=5,
        )
        session.add(result)
        await session.commit()

        response = await test_client.get("/api/dashboard/heatmap")
        assert response.status_code == 200
        data = response.json()

        assert len(data["roots"]) > 0

    @pytest.mark.asyncio
    async def test_filter_by_job_id(self, test_client, setup_dashboard_data):
        """Heatmap should filter by job_id when provided."""
        from openlabels.server.models import ScanJob, ScanResult

        session = setup_dashboard_data["session"]
        tenant = setup_dashboard_data["tenant"]
        target = setup_dashboard_data["target"]

        # Create two jobs
        job1 = ScanJob(
            id=uuid4(),
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        job2 = ScanJob(
            id=uuid4(),
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        # Add each job individually to avoid asyncpg sentinel matching issues
        session.add(job1)
        await session.flush()
        session.add(job2)
        await session.flush()

        # Add results to job1
        result1 = ScanResult(
            id=uuid4(),
            tenant_id=tenant.id,
            job_id=job1.id,
            file_path="/job1/file.txt",
            file_name="file.txt",
            risk_score=50,
            risk_tier="MEDIUM",
            entity_counts={},
            total_entities=1,
        )
        session.add(result1)
        await session.flush()

        # Add results to job2
        result2 = ScanResult(
            id=uuid4(),
            tenant_id=tenant.id,
            job_id=job2.id,
            file_path="/job2/file.txt",
            file_name="file.txt",
            risk_score=50,
            risk_tier="MEDIUM",
            entity_counts={},
            total_entities=1,
        )
        session.add(result2)
        await session.commit()

        # Request heatmap for job1 only
        response = await test_client.get(f"/api/dashboard/heatmap?job_id={job1.id}")
        assert response.status_code == 200
        data = response.json()

        # Should only have job1's files
        assert len(data["roots"]) == 1
        assert data["roots"][0]["name"] == "job1"

    @pytest.mark.asyncio
    async def test_node_structure(self, test_client, setup_dashboard_data):
        """Heatmap nodes should have required fields."""
        from openlabels.server.models import ScanJob, ScanResult

        session = setup_dashboard_data["session"]
        tenant = setup_dashboard_data["tenant"]
        target = setup_dashboard_data["target"]

        scan = ScanJob(
            id=uuid4(),
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        session.add(scan)
        await session.flush()

        result = ScanResult(
            id=uuid4(),
            tenant_id=tenant.id,
            job_id=scan.id,
            file_path="/test/file.txt",
            file_name="file.txt",
            risk_score=70,
            risk_tier="HIGH",
            entity_counts={"EMAIL": 3},
            total_entities=3,
        )
        session.add(result)
        await session.commit()

        response = await test_client.get("/api/dashboard/heatmap")
        assert response.status_code == 200
        data = response.json()

        # Check first root node
        root = data["roots"][0]
        assert "name" in root
        assert "path" in root
        assert "type" in root
        assert "risk_score" in root
        assert "entity_counts" in root


class TestDashboardContentType:
    """Tests for response content type."""

    @pytest.mark.asyncio
    async def test_stats_returns_json(self, test_client, setup_dashboard_data):
        """Stats endpoint should return JSON."""
        response = await test_client.get("/api/dashboard/stats")
        assert "application/json" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_trends_returns_json(self, test_client, setup_dashboard_data):
        """Trends endpoint should return JSON."""
        response = await test_client.get("/api/dashboard/trends")
        assert "application/json" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_heatmap_returns_json(self, test_client, setup_dashboard_data):
        """Heatmap endpoint should return JSON."""
        response = await test_client.get("/api/dashboard/heatmap")
        assert "application/json" in response.headers.get("content-type", "")
