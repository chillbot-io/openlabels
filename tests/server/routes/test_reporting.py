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

import pytest
from uuid import uuid4
from datetime import datetime, timezone


@pytest.fixture
async def setup_reporting_data(test_db):
    """Set up test data for reporting endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User, Report, generate_uuid

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
        from unittest.mock import patch, MagicMock

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


class TestReportingTenantIsolation:
    """Tests for tenant isolation in reporting endpoints."""

    async def test_cannot_access_other_tenant_reports(self, test_client, setup_reporting_data):
        """Should not be able to see reports from other tenants."""
        from openlabels.server.models import Tenant, Report, generate_uuid

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
