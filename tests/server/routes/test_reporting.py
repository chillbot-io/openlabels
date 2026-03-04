"""
Tests for reporting API endpoints.

Tests focus on:
- Generate report
- List reports
- Get report details
- Download report
- Distribute report
- Schedule report
- Input validation
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest


@pytest.fixture
async def setup_reporting_data(test_db):
    """Set up test data for reporting endpoint tests."""
    from sqlalchemy import select

    from openlabels.server.models import Report, Tenant, User, generate_uuid

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    admin_user = result.scalar_one()

    # Create test reports
    reports = []
    for i, (report_type, status) in enumerate([
        ("executive_summary", "generated"),
        ("compliance_report", "generated"),
        ("scan_detail", "pending"),
        ("access_audit", "failed"),
    ]):
        report = Report(
            id=generate_uuid(),
            tenant_id=tenant.id,
            name=f"Test Report {i}",
            report_type=report_type,
            format="html",
            status=status,
            created_by=admin_user.id,
        )
        if status == "generated":
            report.generated_at = datetime.now(timezone.utc)
            report.result_path = f"/tmp/test_report_{i}.html"
            report.result_size_bytes = 1024 * (i + 1)
        if status == "failed":
            report.error = "Test generation failed (TestError)"
        test_db.add(report)
        await test_db.flush()
        reports.append(report)
    await test_db.commit()

    return {
        "tenant": tenant,
        "admin_user": admin_user,
        "reports": reports,
        "session": test_db,
    }


class TestGenerateReport:
    """Tests for POST /api/v1/reporting/generate endpoint."""

    async def test_rejects_invalid_report_type(self, test_client, setup_reporting_data):
        """Should return 400 for invalid report type."""
        response = await test_client.post(
            "/api/v1/reporting/generate",
            json={
                "report_type": "invalid_type",
                "format": "html",
            },
        )
        assert response.status_code == 400
        assert "Invalid report_type" in response.json()["message"]

    async def test_rejects_invalid_format(self, test_client, setup_reporting_data):
        """Should return 400 for invalid format."""
        response = await test_client.post(
            "/api/v1/reporting/generate",
            json={
                "report_type": "executive_summary",
                "format": "docx",
            },
        )
        assert response.status_code == 400
        assert "Invalid format" in response.json()["message"]

    async def test_creates_report_record(self, test_client, setup_reporting_data):
        """Should create a report record and return its details."""
        response = await test_client.post(
            "/api/v1/reporting/generate",
            json={
                "report_type": "executive_summary",
                "format": "html",
                "name": "My Test Report",
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert "id" in data
        assert data["name"] == "My Test Report"
        assert data["report_type"] == "executive_summary"
        assert data["format"] == "html"
        # Status could be generated or failed depending on engine availability
        assert data["status"] in ("generated", "failed", "pending")


class TestListReports:
    """Tests for GET /api/v1/reporting endpoint."""

    async def test_returns_paginated_structure(self, test_client, setup_reporting_data):
        """Response should have pagination structure."""
        response = await test_client.get("/api/v1/reporting")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "total_pages" in data

    async def test_returns_reports(self, test_client, setup_reporting_data):
        """Should return list of reports."""
        response = await test_client.get("/api/v1/reporting")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 4
        assert len(data["items"]) == 4

    async def test_filter_by_report_type(self, test_client, setup_reporting_data):
        """Should filter reports by type."""
        response = await test_client.get("/api/v1/reporting?report_type=executive_summary")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 1
        assert data["items"][0]["report_type"] == "executive_summary"

    async def test_report_response_structure(self, test_client, setup_reporting_data):
        """Report items should have expected fields."""
        response = await test_client.get("/api/v1/reporting")
        assert response.status_code == 200
        data = response.json()

        item = data["items"][0]
        assert "id" in item
        assert "name" in item
        assert "report_type" in item
        assert "format" in item
        assert "status" in item
        assert "created_at" in item


class TestGetReport:
    """Tests for GET /api/v1/reporting/{report_id} endpoint."""

    async def test_returns_report_details(self, test_client, setup_reporting_data):
        """Should return report details."""
        report = setup_reporting_data["reports"][0]
        response = await test_client.get(f"/api/v1/reporting/{report.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(report.id)
        assert data["name"] == report.name

    async def test_returns_404_for_nonexistent(self, test_client, setup_reporting_data):
        """Should return 404 for non-existent report."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/v1/reporting/{fake_id}")
        assert response.status_code == 404


class TestDownloadReport:
    """Tests for GET /api/v1/reporting/{report_id}/download endpoint."""

    async def test_returns_404_for_nonexistent(self, test_client, setup_reporting_data):
        """Should return 404 for non-existent report."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/v1/reporting/{fake_id}/download")
        assert response.status_code == 404

    async def test_returns_400_for_pending_report(self, test_client, setup_reporting_data):
        """Should return 400 for report that is not yet generated."""
        pending_report = setup_reporting_data["reports"][2]  # status=pending
        response = await test_client.get(f"/api/v1/reporting/{pending_report.id}/download")
        assert response.status_code == 400
        assert "not ready" in response.json()["message"]

    async def test_returns_404_for_missing_file(self, test_client, setup_reporting_data):
        """Should return 404 when report file doesn't exist on disk."""
        generated_report = setup_reporting_data["reports"][0]  # status=generated
        response = await test_client.get(f"/api/v1/reporting/{generated_report.id}/download")
        # File path /tmp/test_report_0.html doesn't exist, should 404
        assert response.status_code == 404


class TestDistributeReport:
    """Tests for POST /api/v1/reporting/{report_id}/distribute endpoint."""

    async def test_returns_404_for_nonexistent(self, test_client, setup_reporting_data):
        """Should return 404 for non-existent report."""
        fake_id = uuid4()
        response = await test_client.post(
            f"/api/v1/reporting/{fake_id}/distribute",
            json={"to": ["user@example.com"]},
        )
        assert response.status_code == 404

    async def test_returns_400_for_pending_report(self, test_client, setup_reporting_data):
        """Should return 400 when report is not generated."""
        pending_report = setup_reporting_data["reports"][2]
        response = await test_client.post(
            f"/api/v1/reporting/{pending_report.id}/distribute",
            json={"to": ["user@example.com"]},
        )
        assert response.status_code == 400
        assert "not ready" in response.json()["message"]

    async def test_returns_400_when_smtp_not_configured(self, test_client, setup_reporting_data):
        """Should return 400 when SMTP is not configured."""
        from unittest.mock import MagicMock, patch

        generated_report = setup_reporting_data["reports"][0]

        mock_settings = MagicMock()
        mock_settings.reporting.smtp_host = ""

        with patch("openlabels.server.routes.reporting.get_settings", return_value=mock_settings):
            response = await test_client.post(
                f"/api/v1/reporting/{generated_report.id}/distribute",
                json={"to": ["user@example.com"]},
            )
        assert response.status_code == 400
        assert "SMTP" in response.json()["message"]


class TestScheduleReport:
    """Tests for POST /api/v1/reporting/schedule endpoint."""

    async def test_schedules_report(self, test_client, setup_reporting_data):
        """Should create a scheduled report job."""
        response = await test_client.post(
            "/api/v1/reporting/schedule",
            json={
                "report_type": "executive_summary",
                "format": "html",
                "cron": "0 9 * * MON",
                "name": "Weekly Summary",
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["status"] == "scheduled"
        assert data["report_type"] == "executive_summary"
        assert data["cron"] == "0 9 * * MON"

    async def test_rejects_invalid_report_type(self, test_client, setup_reporting_data):
        """Should return 400 for invalid report type."""
        response = await test_client.post(
            "/api/v1/reporting/schedule",
            json={
                "report_type": "invalid_type",
                "format": "html",
                "cron": "0 9 * * MON",
            },
        )
        assert response.status_code == 400

    async def test_rejects_invalid_format(self, test_client, setup_reporting_data):
        """Should return 400 for invalid format."""
        response = await test_client.post(
            "/api/v1/reporting/schedule",
            json={
                "report_type": "executive_summary",
                "format": "docx",
                "cron": "0 9 * * MON",
            },
        )
        assert response.status_code == 400

    async def test_schedule_with_distribution(self, test_client, setup_reporting_data):
        """Should accept distribute_to email list."""
        response = await test_client.post(
            "/api/v1/reporting/schedule",
            json={
                "report_type": "compliance_report",
                "format": "pdf",
                "cron": "0 0 1 * *",
                "distribute_to": ["admin@example.com", "ciso@example.com"],
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["distribute_to"] == ["admin@example.com", "ciso@example.com"]


# ── Story 11: New Endpoint Tests ──────────────────────────────────────


class TestListReportTemplates:
    """Tests for GET /api/v1/reporting/templates endpoint."""

    async def test_returns_templates_list(self, test_client, setup_reporting_data):
        response = await test_client.get("/api/v1/reporting/templates")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 3

    async def test_templates_have_required_fields(self, test_client, setup_reporting_data):
        response = await test_client.get("/api/v1/reporting/templates")
        data = response.json()
        for template in data:
            assert "id" in template
            assert "name" in template
            assert "description" in template
            assert "report_type" in template
            assert "default_format" in template
            assert "category" in template

    async def test_includes_core_templates(self, test_client, setup_reporting_data):
        response = await test_client.get("/api/v1/reporting/templates")
        data = response.json()
        ids = {t["id"] for t in data}
        assert "risk_summary" in ids
        assert "label_coverage" in ids
        assert "exposure_report" in ids

    async def test_filter_by_category(self, test_client, setup_reporting_data):
        response = await test_client.get("/api/v1/reporting/templates?category=compliance")
        data = response.json()
        assert len(data) >= 1
        for t in data:
            assert t["category"] == "compliance"

    async def test_filter_by_nonexistent_category(self, test_client, setup_reporting_data):
        response = await test_client.get("/api/v1/reporting/templates?category=nonexistent")
        data = response.json()
        assert data == []


@pytest.fixture
async def setup_compliance_trend_data(test_db):
    """Set up scan results with policy violations for compliance trend testing."""
    from sqlalchemy import select

    from openlabels.server.models import (
        ScanJob,
        ScanResult,
        ScanTarget,
        Tenant,
        User,
        generate_uuid,
    )

    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    user = result.scalar_one()

    target = ScanTarget(
        id=generate_uuid(),
        tenant_id=tenant.id,
        name="Compliance Test Target",
        adapter="filesystem",
        config={"path": "/data/compliance"},
        enabled=True,
        created_by=user.id,
    )
    test_db.add(target)
    await test_db.flush()

    job = ScanJob(
        id=generate_uuid(),
        tenant_id=tenant.id,
        target_id=target.id,
        name="Compliance Test Scan",
        status="completed",
        files_scanned=100,
        files_with_pii=20,
        created_by=user.id,
    )
    test_db.add(job)
    await test_db.flush()

    now = datetime.now(timezone.utc)

    # Create results at different dates with and without violations
    for day_offset in range(5):
        scan_date = now - timedelta(days=day_offset)
        # Clean file
        sr_clean = ScanResult(
            id=generate_uuid(),
            tenant_id=tenant.id,
            job_id=job.id,
            file_path=f"/data/compliance/clean_{day_offset}.txt",
            file_name=f"clean_{day_offset}.txt",
            risk_score=10,
            risk_tier="LOW",
            total_entities=0,
            entity_counts={},
            scanned_at=scan_date,
        )
        # File with violations
        sr_violation = ScanResult(
            id=generate_uuid(),
            tenant_id=tenant.id,
            job_id=job.id,
            file_path=f"/data/compliance/violation_{day_offset}.xlsx",
            file_name=f"violation_{day_offset}.xlsx",
            risk_score=80,
            risk_tier="HIGH",
            total_entities=3,
            entity_counts={"SSN": 2, "EMAIL": 1},
            scanned_at=scan_date,
            policy_violations=[{"policy": "no_ssn_exposed", "severity": "high"}],
        )
        test_db.add_all([sr_clean, sr_violation])

    await test_db.commit()

    return {
        "tenant": tenant,
        "user": user,
        "target": target,
        "job": job,
    }


class TestComplianceTrend:
    """Tests for GET /api/v1/reporting/compliance-trend endpoint."""

    async def test_returns_trend_data(self, test_client, setup_compliance_trend_data):
        response = await test_client.get("/api/v1/reporting/compliance-trend")
        assert response.status_code == 200
        data = response.json()
        assert "points" in data
        assert "total_days" in data
        assert isinstance(data["points"], list)

    async def test_trend_points_have_fields(self, test_client, setup_compliance_trend_data):
        response = await test_client.get("/api/v1/reporting/compliance-trend?days=7")
        data = response.json()
        for point in data["points"]:
            assert "date" in point
            assert "total_files" in point
            assert "files_with_violations" in point
            assert "total_violations" in point
            assert "compliance_rate" in point

    async def test_trend_respects_days_param(self, test_client, setup_compliance_trend_data):
        response = await test_client.get("/api/v1/reporting/compliance-trend?days=7")
        data = response.json()
        assert data["total_days"] == 7
        # Should have 8 points (today + 7 days back)
        assert len(data["points"]) == 8

    async def test_compliance_rate_calculation(self, test_client, setup_compliance_trend_data):
        response = await test_client.get("/api/v1/reporting/compliance-trend?days=7")
        data = response.json()
        # On days with data, rate should reflect violations
        for point in data["points"]:
            if point["total_files"] > 0:
                assert 0 <= point["compliance_rate"] <= 100

    async def test_empty_days_have_defaults(self, test_client, setup_compliance_trend_data):
        response = await test_client.get("/api/v1/reporting/compliance-trend?days=30")
        data = response.json()
        # Most days should have 0 files and 100% compliance
        zero_days = [p for p in data["points"] if p["total_files"] == 0]
        for day in zero_days:
            assert day["compliance_rate"] == 100.0
            assert day["total_violations"] == 0


class TestDateRangeFiltering:
    """Tests for date range filtering in report listing."""

    async def test_filter_by_start_date(self, test_client, setup_reporting_data):
        response = await test_client.get(
            "/api/v1/reporting?start_date=2020-01-01T00:00:00Z"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 0

    async def test_filter_by_end_date(self, test_client, setup_reporting_data):
        response = await test_client.get(
            "/api/v1/reporting?end_date=2020-01-01T00:00:00Z"
        )
        assert response.status_code == 200
        data = response.json()
        # All test reports were created "now", so filtering to before 2020 should yield 0
        assert data["total"] == 0

    async def test_filter_by_date_range(self, test_client, setup_reporting_data):
        response = await test_client.get(
            "/api/v1/reporting?start_date=2020-01-01T00:00:00Z&end_date=2099-01-01T00:00:00Z"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 4


class TestReportingTenantIsolation:
    """Tests for tenant isolation in reporting endpoints."""

    async def test_cannot_access_other_tenant_reports(self, test_client, setup_reporting_data):
        """Should not be able to see reports from other tenants."""
        from openlabels.server.models import Report, Tenant, generate_uuid

        session = setup_reporting_data["session"]

        other_tenant = Tenant(
            name="Other Reporting Tenant",
            azure_tenant_id="other-reporting-tenant-id",
        )
        session.add(other_tenant)
        await session.flush()

        other_report = Report(
            id=generate_uuid(),
            tenant_id=other_tenant.id,
            name="Secret Other Report",
            report_type="executive_summary",
            format="html",
            status="generated",
        )
        session.add(other_report)
        await session.commit()

        response = await test_client.get("/api/v1/reporting")
        assert response.status_code == 200
        data = response.json()

        names = [r["name"] for r in data["items"]]
        assert "Secret Other Report" not in names
