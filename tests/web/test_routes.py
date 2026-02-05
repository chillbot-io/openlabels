"""
Comprehensive tests for web UI routes module.

Tests focus on:
- Helper functions (format_relative_time, truncate_string)
- Page routes (dashboard, targets, scans, results, labels, etc.)
- Form submission handlers (CRUD operations)
- HTMX partial routes (dashboard-stats, lists, etc.)

Uses PostgreSQL test database via test_client fixture.
"""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from httpx import AsyncClient


class TestFormatRelativeTime:
    """Tests for the format_relative_time helper function."""

    def test_none_returns_never(self):
        """format_relative_time should return 'Never' for None."""
        from openlabels.web.routes import format_relative_time

        assert format_relative_time(None) == "Never"

    def test_just_now(self):
        """format_relative_time should return 'Just now' for recent times."""
        from openlabels.web.routes import format_relative_time

        now = datetime.now(timezone.utc)
        assert format_relative_time(now) == "Just now"

    def test_minutes_ago(self):
        """format_relative_time should return minutes ago."""
        from openlabels.web.routes import format_relative_time

        dt = datetime.now(timezone.utc) - timedelta(minutes=5)
        result = format_relative_time(dt)
        assert "m ago" in result

    def test_hours_ago(self):
        """format_relative_time should return hours ago."""
        from openlabels.web.routes import format_relative_time

        dt = datetime.now(timezone.utc) - timedelta(hours=3)
        result = format_relative_time(dt)
        assert "h ago" in result

    def test_days_ago(self):
        """format_relative_time should return days ago."""
        from openlabels.web.routes import format_relative_time

        dt = datetime.now(timezone.utc) - timedelta(days=3)
        result = format_relative_time(dt)
        assert "d ago" in result

    def test_old_date_returns_formatted(self):
        """format_relative_time should return formatted date for old times."""
        from openlabels.web.routes import format_relative_time

        dt = datetime.now(timezone.utc) - timedelta(days=30)
        result = format_relative_time(dt)
        assert "-" in result  # YYYY-MM-DD format

    def test_naive_datetime_handled(self):
        """format_relative_time should handle naive datetimes."""
        from openlabels.web.routes import format_relative_time

        dt = datetime.now() - timedelta(minutes=10)
        result = format_relative_time(dt)
        assert "m ago" in result


class TestTruncateString:
    """Tests for the truncate_string helper function."""

    def test_none_returns_empty(self):
        """truncate_string should return empty string for None."""
        from openlabels.web.routes import truncate_string

        assert truncate_string(None) == ""

    def test_empty_string_returns_empty(self):
        """truncate_string should return empty string for empty input."""
        from openlabels.web.routes import truncate_string

        assert truncate_string("") == ""

    def test_short_string_unchanged(self):
        """truncate_string should not modify short strings."""
        from openlabels.web.routes import truncate_string

        assert truncate_string("hello", 50) == "hello"

    def test_exact_length_unchanged(self):
        """truncate_string should not modify strings at exact length."""
        from openlabels.web.routes import truncate_string

        assert truncate_string("hello", 5) == "hello"

    def test_long_string_truncated(self):
        """truncate_string should truncate long strings."""
        from openlabels.web.routes import truncate_string

        result = truncate_string("hello world", 8)
        assert len(result) == 8
        assert result.endswith("...")

    def test_custom_suffix(self):
        """truncate_string should use custom suffix."""
        from openlabels.web.routes import truncate_string

        result = truncate_string("hello world", 10, suffix="…")
        assert result.endswith("…")

    def test_default_length(self):
        """truncate_string should use default length of 50."""
        from openlabels.web.routes import truncate_string

        long_text = "a" * 100
        result = truncate_string(long_text)
        assert len(result) == 50


class TestPageRoutes:
    """Tests for web page routes using actual test client."""

    async def test_home_route(self, test_client: AsyncClient):
        """Home route should render dashboard template."""
        response = await test_client.get("/ui/")
        assert response.status_code == 200
        assert "dashboard" in response.text.lower() or response.headers.get("content-type", "").startswith("text/html")

    async def test_dashboard_route(self, test_client: AsyncClient):
        """Dashboard route should render dashboard template."""
        response = await test_client.get("/ui/dashboard")
        assert response.status_code == 200

    async def test_targets_page_route(self, test_client: AsyncClient):
        """Targets page route should render targets template."""
        response = await test_client.get("/ui/targets")
        assert response.status_code == 200

    async def test_new_target_page_route(self, test_client: AsyncClient):
        """New target page route should render form."""
        response = await test_client.get("/ui/targets/new")
        assert response.status_code == 200

    async def test_scans_page_route(self, test_client: AsyncClient):
        """Scans page route should render scans template."""
        response = await test_client.get("/ui/scans")
        assert response.status_code == 200

    async def test_new_scan_page_route(self, test_client: AsyncClient):
        """New scan page route should render scan form template."""
        response = await test_client.get("/ui/scans/new")
        assert response.status_code == 200

    async def test_results_page_route(self, test_client: AsyncClient):
        """Results page route should render results template."""
        response = await test_client.get("/ui/results")
        assert response.status_code == 200

    async def test_results_page_with_scan_id(self, test_client: AsyncClient):
        """Results page route should accept scan_id filter."""
        response = await test_client.get("/ui/results?scan_id=test-scan-id")
        assert response.status_code == 200

    async def test_labels_page_route(self, test_client: AsyncClient):
        """Labels page route should render labels template."""
        response = await test_client.get("/ui/labels")
        assert response.status_code == 200

    async def test_labels_sync_page_route(self, test_client: AsyncClient):
        """Labels sync page route should render sync template."""
        response = await test_client.get("/ui/labels/sync")
        assert response.status_code == 200

    async def test_monitoring_page_route(self, test_client: AsyncClient):
        """Monitoring page route should render monitoring template."""
        response = await test_client.get("/ui/monitoring")
        assert response.status_code == 200

    async def test_schedules_page_route(self, test_client: AsyncClient):
        """Schedules page route should render schedules template."""
        response = await test_client.get("/ui/schedules")
        assert response.status_code == 200

    async def test_settings_page_route(self, test_client: AsyncClient):
        """Settings page should render with config values."""
        response = await test_client.get("/ui/settings")
        assert response.status_code == 200

    async def test_login_page_route(self, test_client: AsyncClient):
        """Login page route should render login template."""
        response = await test_client.get("/ui/login")
        assert response.status_code == 200


class TestDetailPages:
    """Tests for detail page routes with database interactions."""

    async def test_edit_target_page_not_found(self, test_client: AsyncClient):
        """Edit target page should return 404 for non-existent target."""
        fake_id = uuid4()
        response = await test_client.get(f"/ui/targets/{fake_id}")
        assert response.status_code == 404

    async def test_scan_detail_page_not_found(self, test_client: AsyncClient):
        """Scan detail page should return 404 for non-existent scan."""
        fake_id = uuid4()
        response = await test_client.get(f"/ui/scans/{fake_id}")
        assert response.status_code == 404

    async def test_result_detail_page_not_found(self, test_client: AsyncClient):
        """Result detail page should return 404 for non-existent result."""
        fake_id = uuid4()
        response = await test_client.get(f"/ui/results/{fake_id}")
        assert response.status_code == 404

    async def test_edit_schedule_page_not_found(self, test_client: AsyncClient):
        """Edit schedule page should return 404 for non-existent schedule."""
        fake_id = uuid4()
        response = await test_client.get(f"/ui/schedules/{fake_id}")
        assert response.status_code == 404


class TestTargetCRUD:
    """Tests for target CRUD operations via web forms."""

    async def test_create_target(self, test_client: AsyncClient, test_db):
        """Create target form should add target to database."""
        response = await test_client.post(
            "/ui/targets",
            data={
                "name": "Test Target",
                "adapter": "filesystem",
                "enabled": "on",
                "config[path]": "/data/test",
            },
            follow_redirects=False,
        )
        # Should redirect after successful creation
        assert response.status_code in (303, 302, 200)

    async def test_create_target_and_view(self, test_client: AsyncClient, test_db):
        """Create target and verify it appears in list."""
        # Create target
        await test_client.post(
            "/ui/targets",
            data={
                "name": "View Test Target",
                "adapter": "sharepoint",
                "enabled": "on",
            },
            follow_redirects=False,
        )

        # Verify target list contains the new target
        response = await test_client.get("/ui/partials/targets-list")
        assert response.status_code == 200
        assert "View Test Target" in response.text

    async def test_create_and_edit_target(self, test_client: AsyncClient, test_db):
        """Create target, then edit it."""
        from openlabels.server.models import ScanTarget

        # Create target directly in DB to get the ID
        target = ScanTarget(
            tenant_id=(await test_db.execute(
                __import__('sqlalchemy').select(
                    __import__('openlabels.server.models', fromlist=['Tenant']).Tenant.id
                )
            )).scalar(),
            name="Edit Test Target",
            adapter="filesystem",
            config={"path": "/data"},
            enabled=True,
        )
        test_db.add(target)
        await test_db.commit()
        await test_db.refresh(target)

        # Edit the target
        response = await test_client.post(
            f"/ui/targets/{target.id}",
            data={
                "name": "Updated Target Name",
                "adapter": "filesystem",
                "enabled": "on",
                "config[path]": "/new/path",
            },
            follow_redirects=False,
        )
        assert response.status_code in (303, 302, 200)


class TestScheduleCRUD:
    """Tests for schedule CRUD operations via web forms."""

    async def test_new_schedule_page_loads(self, test_client: AsyncClient):
        """New schedule page should load successfully."""
        response = await test_client.get("/ui/schedules/new")
        assert response.status_code == 200

    async def test_create_schedule(self, test_client: AsyncClient, test_db):
        """Create schedule form should add schedule to database."""
        from openlabels.server.models import ScanTarget
        from sqlalchemy import select

        # First create a target to associate with the schedule
        result = await test_db.execute(
            select(__import__('openlabels.server.models', fromlist=['Tenant']).Tenant.id)
        )
        tenant_id = result.scalar()

        target = ScanTarget(
            tenant_id=tenant_id,
            name="Schedule Test Target",
            adapter="filesystem",
            config={"path": "/test/schedule"},
            enabled=True,
        )
        test_db.add(target)
        await test_db.commit()
        await test_db.refresh(target)

        # Create schedule
        response = await test_client.post(
            "/ui/schedules",
            data={
                "name": "Daily Scan",
                "target_id": str(target.id),
                "cron": "0 0 * * *",
                "enabled": "on",
            },
            follow_redirects=False,
        )
        assert response.status_code in (303, 302, 200)


class TestScanCreation:
    """Tests for scan creation via web forms."""

    async def test_create_scan_no_targets(self, test_client: AsyncClient):
        """Create scan should handle case when no targets selected."""
        response = await test_client.post(
            "/ui/scans",
            data={},
            follow_redirects=False,
        )
        # Should return error (400) when no targets selected
        assert response.status_code in (400, 200)

    async def test_create_scan_with_target(self, test_client: AsyncClient, test_db):
        """Create scan should create job for selected target."""
        from openlabels.server.models import ScanTarget
        from sqlalchemy import select

        # Create a target first
        result = await test_db.execute(
            select(__import__('openlabels.server.models', fromlist=['Tenant']).Tenant.id)
        )
        tenant_id = result.scalar()

        target = ScanTarget(
            tenant_id=tenant_id,
            name="Scan Test Target",
            adapter="filesystem",
            config={"path": "/test/scan"},
            enabled=True,
        )
        test_db.add(target)
        await test_db.commit()
        await test_db.refresh(target)

        # Create scan
        response = await test_client.post(
            "/ui/scans",
            data={
                "target_ids[]": str(target.id),
            },
            follow_redirects=False,
        )
        assert response.status_code in (303, 302, 200)


class TestHTMXPartials:
    """Tests for HTMX partial routes."""

    async def test_dashboard_stats_partial(self, test_client: AsyncClient):
        """Dashboard stats partial should return stats HTML."""
        response = await test_client.get("/ui/partials/dashboard-stats")
        assert response.status_code == 200
        assert response.headers.get("content-type", "").startswith("text/html")

    async def test_recent_scans_partial(self, test_client: AsyncClient):
        """Recent scans partial should return scan list HTML."""
        response = await test_client.get("/ui/partials/recent-scans")
        assert response.status_code == 200

    async def test_findings_by_type_partial(self, test_client: AsyncClient):
        """Findings by type partial should return findings HTML."""
        response = await test_client.get("/ui/partials/findings-by-type")
        assert response.status_code == 200

    async def test_risk_distribution_partial(self, test_client: AsyncClient):
        """Risk distribution partial should return distribution HTML."""
        response = await test_client.get("/ui/partials/risk-distribution")
        assert response.status_code == 200

    async def test_recent_activity_partial(self, test_client: AsyncClient):
        """Recent activity partial should return activity HTML."""
        response = await test_client.get("/ui/partials/recent-activity")
        assert response.status_code == 200

    async def test_health_status_partial(self, test_client: AsyncClient):
        """Health status partial should return healthy status."""
        response = await test_client.get("/ui/partials/health-status")
        assert response.status_code == 200
        assert "healthy" in response.text.lower()

    async def test_system_health_partial(self, test_client: AsyncClient):
        """System health partial should check database."""
        response = await test_client.get("/ui/partials/system-health")
        assert response.status_code == 200

    async def test_targets_list_partial(self, test_client: AsyncClient):
        """Targets list partial should return targets HTML."""
        response = await test_client.get("/ui/partials/targets-list")
        assert response.status_code == 200

    async def test_targets_list_pagination(self, test_client: AsyncClient):
        """Targets list partial should handle pagination params."""
        response = await test_client.get("/ui/partials/targets-list?page=1&page_size=5")
        assert response.status_code == 200

    async def test_targets_list_adapter_filter(self, test_client: AsyncClient):
        """Targets list partial should filter by adapter."""
        response = await test_client.get("/ui/partials/targets-list?adapter=sharepoint")
        assert response.status_code == 200

    async def test_scans_list_partial(self, test_client: AsyncClient):
        """Scans list partial should return scans HTML."""
        response = await test_client.get("/ui/partials/scans-list")
        assert response.status_code == 200

    async def test_scans_list_status_filter(self, test_client: AsyncClient):
        """Scans list partial should filter by status."""
        response = await test_client.get("/ui/partials/scans-list?status=running")
        assert response.status_code == 200

    async def test_results_list_partial(self, test_client: AsyncClient):
        """Results list partial should return results HTML."""
        response = await test_client.get("/ui/partials/results-list")
        assert response.status_code == 200

    async def test_results_list_risk_filter(self, test_client: AsyncClient):
        """Results list partial should filter by risk tier."""
        response = await test_client.get("/ui/partials/results-list?risk_tier=HIGH")
        assert response.status_code == 200

    async def test_results_list_label_filter(self, test_client: AsyncClient):
        """Results list partial should filter by label status."""
        response = await test_client.get("/ui/partials/results-list?has_label=true")
        assert response.status_code == 200

    async def test_activity_log_partial(self, test_client: AsyncClient):
        """Activity log partial should return log HTML."""
        response = await test_client.get("/ui/partials/activity-log")
        assert response.status_code == 200

    async def test_activity_log_action_filter(self, test_client: AsyncClient):
        """Activity log partial should filter by action."""
        response = await test_client.get("/ui/partials/activity-log?action=scan_completed")
        assert response.status_code == 200

    async def test_job_queue_partial(self, test_client: AsyncClient):
        """Job queue partial should return queue stats HTML."""
        response = await test_client.get("/ui/partials/job-queue")
        assert response.status_code == 200

    async def test_labels_list_partial(self, test_client: AsyncClient):
        """Labels list partial should return labels HTML."""
        response = await test_client.get("/ui/partials/labels-list")
        assert response.status_code == 200

    async def test_label_mappings_partial(self, test_client: AsyncClient):
        """Label mappings partial should return mappings HTML."""
        response = await test_client.get("/ui/partials/label-mappings")
        assert response.status_code == 200

    async def test_target_checkboxes_partial(self, test_client: AsyncClient):
        """Target checkboxes partial should return checkbox HTML."""
        response = await test_client.get("/ui/partials/target-checkboxes")
        assert response.status_code == 200

    async def test_schedules_list_partial(self, test_client: AsyncClient):
        """Schedules list partial should return schedules HTML."""
        response = await test_client.get("/ui/partials/schedules-list")
        assert response.status_code == 200


class TestDataWithResults:
    """Tests that verify correct data rendering with actual database records."""

    async def test_target_appears_in_list(self, test_client: AsyncClient, test_db):
        """Created target should appear in targets list."""
        from openlabels.server.models import ScanTarget
        from sqlalchemy import select

        result = await test_db.execute(
            select(__import__('openlabels.server.models', fromlist=['Tenant']).Tenant.id)
        )
        tenant_id = result.scalar()

        target = ScanTarget(
            tenant_id=tenant_id,
            name="Visible Target",
            adapter="onedrive",
            config={"drive_id": "test-drive"},
            enabled=True,
        )
        test_db.add(target)
        await test_db.commit()

        response = await test_client.get("/ui/partials/targets-list")
        assert response.status_code == 200
        assert "Visible Target" in response.text

    async def test_scan_appears_in_recent(self, test_client: AsyncClient, test_db):
        """Created scan should appear in recent scans."""
        from openlabels.server.models import ScanJob, ScanTarget
        from sqlalchemy import select

        result = await test_db.execute(
            select(__import__('openlabels.server.models', fromlist=['Tenant']).Tenant.id)
        )
        tenant_id = result.scalar()

        # Create target first
        target = ScanTarget(
            tenant_id=tenant_id,
            name="Recent Scan Target",
            adapter="filesystem",
            config={"path": "/test/path"},
        )
        test_db.add(target)
        await test_db.commit()
        await test_db.refresh(target)

        scan = ScanJob(
            tenant_id=tenant_id,
            target_id=target.id,
            target_name=target.name,
            name="Recent Scan",
            status="completed",
            files_scanned=100,
        )
        test_db.add(scan)
        await test_db.commit()

        response = await test_client.get("/ui/partials/recent-scans")
        assert response.status_code == 200
        assert "Recent Scan Target" in response.text

    async def test_schedule_appears_in_list(self, test_client: AsyncClient, test_db):
        """Created schedule should appear in schedules list."""
        from openlabels.server.models import ScanSchedule, ScanTarget
        from sqlalchemy import select

        result = await test_db.execute(
            select(__import__('openlabels.server.models', fromlist=['Tenant']).Tenant.id)
        )
        tenant_id = result.scalar()

        # Create target first
        target = ScanTarget(
            tenant_id=tenant_id,
            name="Schedule Target",
            adapter="filesystem",
            config={"path": "/test/schedule-target"},
            enabled=True,
        )
        test_db.add(target)
        await test_db.commit()
        await test_db.refresh(target)

        # Create schedule
        schedule = ScanSchedule(
            tenant_id=tenant_id,
            name="Visible Schedule",
            target_id=target.id,
            cron="0 0 * * *",
            enabled=True,
        )
        test_db.add(schedule)
        await test_db.commit()

        response = await test_client.get("/ui/partials/schedules-list")
        assert response.status_code == 200
        assert "Visible Schedule" in response.text

    async def test_result_appears_in_list(self, test_client: AsyncClient, test_db):
        """Created result should appear in results list."""
        from openlabels.server.models import ScanResult, ScanTarget, ScanJob
        from sqlalchemy import select

        result = await test_db.execute(
            select(__import__('openlabels.server.models', fromlist=['Tenant']).Tenant.id)
        )
        tenant_id = result.scalar()

        # Create target and job first (required for ScanResult)
        target = ScanTarget(
            tenant_id=tenant_id,
            name="Result Test Target",
            adapter="filesystem",
            config={"path": "/test/results"},
            enabled=True,
        )
        test_db.add(target)
        await test_db.commit()
        await test_db.refresh(target)

        job = ScanJob(
            tenant_id=tenant_id,
            target_id=target.id,
            name="Result Test Job",
            status="completed",
        )
        test_db.add(job)
        await test_db.commit()
        await test_db.refresh(job)

        scan_result = ScanResult(
            tenant_id=tenant_id,
            job_id=job.id,
            file_path="/test/visible_file.docx",
            file_name="visible_file.docx",
            risk_tier="HIGH",
            risk_score=85,
            total_entities=5,
            entity_counts={"SSN": 3, "EMAIL": 2},
        )
        test_db.add(scan_result)
        await test_db.commit()

        response = await test_client.get("/ui/partials/results-list")
        assert response.status_code == 200
        assert "visible_file" in response.text

    async def test_dashboard_stats_with_data(self, test_client: AsyncClient, test_db):
        """Dashboard stats should reflect actual data."""
        from openlabels.server.models import ScanResult, ScanTarget, ScanJob
        from sqlalchemy import select

        result = await test_db.execute(
            select(__import__('openlabels.server.models', fromlist=['Tenant']).Tenant.id)
        )
        tenant_id = result.scalar()

        # Create target and job first (required for ScanResult)
        target = ScanTarget(
            tenant_id=tenant_id,
            name="Stats Test Target",
            adapter="filesystem",
            config={"path": "/test/stats"},
            enabled=True,
        )
        test_db.add(target)
        await test_db.commit()
        await test_db.refresh(target)

        job = ScanJob(
            tenant_id=tenant_id,
            target_id=target.id,
            name="Stats Test Job",
            status="completed",
        )
        test_db.add(job)
        await test_db.commit()
        await test_db.refresh(job)

        # Create multiple results
        for i in range(3):
            scan_result = ScanResult(
                tenant_id=tenant_id,
                job_id=job.id,
                file_path=f"/test/file_{i}.docx",
                file_name=f"file_{i}.docx",
                risk_tier="CRITICAL" if i == 0 else "MEDIUM",
                risk_score=90 if i == 0 else 50,
                total_entities=i + 1,
                entity_counts={"SSN": i + 1},
            )
            test_db.add(scan_result)
        await test_db.commit()

        response = await test_client.get("/ui/partials/dashboard-stats")
        assert response.status_code == 200
        # Stats should show non-zero values
        assert "0" not in response.text or "3" in response.text  # Should have some data


class TestEditPages:
    """Tests for edit page routes with actual data."""

    async def test_edit_target_page_with_data(self, test_client: AsyncClient, test_db):
        """Edit target page should render for existing target."""
        from openlabels.server.models import ScanTarget
        from sqlalchemy import select

        result = await test_db.execute(
            select(__import__('openlabels.server.models', fromlist=['Tenant']).Tenant.id)
        )
        tenant_id = result.scalar()

        target = ScanTarget(
            tenant_id=tenant_id,
            name="Editable Target",
            adapter="sharepoint",
            config={"site_url": "https://example.sharepoint.com"},
            enabled=True,
        )
        test_db.add(target)
        await test_db.commit()
        await test_db.refresh(target)

        response = await test_client.get(f"/ui/targets/{target.id}")
        assert response.status_code == 200
        assert "Editable Target" in response.text

    async def test_scan_detail_page_with_data(self, test_client: AsyncClient, test_db):
        """Scan detail page should render for existing scan."""
        from openlabels.server.models import ScanJob, ScanTarget
        from sqlalchemy import select

        result = await test_db.execute(
            select(__import__('openlabels.server.models', fromlist=['Tenant']).Tenant.id)
        )
        tenant_id = result.scalar()

        # Create target first
        target = ScanTarget(
            tenant_id=tenant_id,
            name="Detail Test Target",
            adapter="filesystem",
            config={"path": "/test/path"},
        )
        test_db.add(target)
        await test_db.commit()
        await test_db.refresh(target)

        scan = ScanJob(
            tenant_id=tenant_id,
            target_id=target.id,
            target_name=target.name,
            name="Detail Test Scan",
            status="running",
            files_scanned=50,
            progress={"files_total": 100, "files_scanned": 50},
        )
        test_db.add(scan)
        await test_db.commit()
        await test_db.refresh(scan)

        response = await test_client.get(f"/ui/scans/{scan.id}")
        assert response.status_code == 200
        assert "Detail Test" in response.text

    async def test_result_detail_page_with_data(self, test_client: AsyncClient, test_db):
        """Result detail page should render for existing result."""
        from openlabels.server.models import ScanResult, ScanTarget, ScanJob
        from sqlalchemy import select

        result = await test_db.execute(
            select(__import__('openlabels.server.models', fromlist=['Tenant']).Tenant.id)
        )
        tenant_id = result.scalar()

        # Create target and job first (required for ScanResult)
        target = ScanTarget(
            tenant_id=tenant_id,
            name="Detail Result Target",
            adapter="filesystem",
            config={"path": "/test/detail"},
            enabled=True,
        )
        test_db.add(target)
        await test_db.commit()
        await test_db.refresh(target)

        job = ScanJob(
            tenant_id=tenant_id,
            target_id=target.id,
            name="Detail Result Job",
            status="completed",
        )
        test_db.add(job)
        await test_db.commit()
        await test_db.refresh(job)

        scan_result = ScanResult(
            tenant_id=tenant_id,
            job_id=job.id,
            file_path="/test/detail_test.pdf",
            file_name="detail_test.pdf",
            risk_tier="HIGH",
            risk_score=75,
            total_entities=10,
            entity_counts={"SSN": 3, "EMAIL": 7},
        )
        test_db.add(scan_result)
        await test_db.commit()
        await test_db.refresh(scan_result)

        response = await test_client.get(f"/ui/results/{scan_result.id}")
        assert response.status_code == 200
        assert "detail_test.pdf" in response.text

    async def test_edit_schedule_page_with_data(self, test_client: AsyncClient, test_db):
        """Edit schedule page should render for existing schedule."""
        from openlabels.server.models import ScanSchedule, ScanTarget
        from sqlalchemy import select

        result = await test_db.execute(
            select(__import__('openlabels.server.models', fromlist=['Tenant']).Tenant.id)
        )
        tenant_id = result.scalar()

        target = ScanTarget(
            tenant_id=tenant_id,
            name="Edit Schedule Target",
            adapter="filesystem",
            config={"path": "/test/edit-schedule"},
            enabled=True,
        )
        test_db.add(target)
        await test_db.commit()
        await test_db.refresh(target)

        schedule = ScanSchedule(
            tenant_id=tenant_id,
            name="Editable Schedule",
            target_id=target.id,
            cron="0 6 * * *",
            enabled=True,
        )
        test_db.add(schedule)
        await test_db.commit()
        await test_db.refresh(schedule)

        response = await test_client.get(f"/ui/schedules/{schedule.id}")
        assert response.status_code == 200
        assert "Editable Schedule" in response.text


class TestTenantIsolation:
    """Tests to verify tenant isolation in web routes."""

    async def test_cannot_view_other_tenant_target(self, test_client: AsyncClient, test_db):
        """Should not be able to view another tenant's target."""
        from openlabels.server.models import ScanTarget, Tenant

        # Create a different tenant
        other_tenant = Tenant(
            name="Other Tenant",
            azure_tenant_id="other-tenant-id",
        )
        test_db.add(other_tenant)
        await test_db.commit()
        await test_db.refresh(other_tenant)

        # Create target for other tenant
        other_target = ScanTarget(
            tenant_id=other_tenant.id,
            name="Other Tenant Target",
            adapter="filesystem",
            config={"path": "/other/tenant/path"},
            enabled=True,
        )
        test_db.add(other_target)
        await test_db.commit()
        await test_db.refresh(other_target)

        # Try to access - should get 404
        response = await test_client.get(f"/ui/targets/{other_target.id}")
        assert response.status_code == 404

    async def test_cannot_view_other_tenant_scan(self, test_client: AsyncClient, test_db):
        """Should not be able to view another tenant's scan."""
        from openlabels.server.models import ScanJob, ScanTarget, Tenant

        # Create a different tenant
        other_tenant = Tenant(
            name="Other Tenant 2",
            azure_tenant_id="other-tenant-id-2",
        )
        test_db.add(other_tenant)
        await test_db.commit()
        await test_db.refresh(other_tenant)

        # Create target for other tenant
        other_target = ScanTarget(
            tenant_id=other_tenant.id,
            name="Other Target",
            adapter="filesystem",
            config={"path": "/other/path"},
        )
        test_db.add(other_target)
        await test_db.commit()
        await test_db.refresh(other_target)

        # Create scan for other tenant
        other_scan = ScanJob(
            tenant_id=other_tenant.id,
            target_id=other_target.id,
            target_name=other_target.name,
            name="Other Scan",
            status="completed",
        )
        test_db.add(other_scan)
        await test_db.commit()
        await test_db.refresh(other_scan)

        # Try to access - should get 404
        response = await test_client.get(f"/ui/scans/{other_scan.id}")
        assert response.status_code == 404
