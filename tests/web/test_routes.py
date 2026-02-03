"""
Comprehensive tests for web UI routes module.

Tests focus on:
- Helper functions (format_relative_time, truncate_string)
- Page routes (dashboard, targets, scans, results, labels, etc.)
- Form submission handlers (CRUD operations)
- HTMX partial routes (dashboard-stats, lists, etc.)
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi import Request
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport


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
    """Tests for web page routes."""

    @pytest.fixture
    def mock_templates(self):
        """Mock templates for testing."""
        with patch("openlabels.web.routes.templates") as mock:
            mock.TemplateResponse = MagicMock(return_value="mocked_response")
            yield mock

    @pytest.mark.asyncio
    async def test_home_route(self, mock_templates):
        """Home route should render dashboard template."""
        from openlabels.web.routes import home

        request = MagicMock(spec=Request)
        await home(request)

        mock_templates.TemplateResponse.assert_called_once()
        call_args = mock_templates.TemplateResponse.call_args
        assert call_args[0][0] == "dashboard.html"
        assert call_args[0][1]["active_page"] == "dashboard"

    @pytest.mark.asyncio
    async def test_dashboard_route(self, mock_templates):
        """Dashboard route should render dashboard template."""
        from openlabels.web.routes import dashboard

        request = MagicMock(spec=Request)
        await dashboard(request)

        mock_templates.TemplateResponse.assert_called_once()
        call_args = mock_templates.TemplateResponse.call_args
        assert call_args[0][0] == "dashboard.html"

    @pytest.mark.asyncio
    async def test_targets_page_route(self, mock_templates):
        """Targets page route should render targets template."""
        from openlabels.web.routes import targets_page

        request = MagicMock(spec=Request)
        await targets_page(request)

        mock_templates.TemplateResponse.assert_called_once()
        call_args = mock_templates.TemplateResponse.call_args
        assert call_args[0][0] == "targets.html"
        assert call_args[0][1]["active_page"] == "targets"

    @pytest.mark.asyncio
    async def test_new_target_page_route(self, mock_templates):
        """New target page route should render form with create mode."""
        from openlabels.web.routes import new_target_page

        request = MagicMock(spec=Request)
        await new_target_page(request)

        mock_templates.TemplateResponse.assert_called_once()
        call_args = mock_templates.TemplateResponse.call_args
        assert call_args[0][0] == "targets_form.html"
        assert call_args[0][1]["mode"] == "create"
        assert call_args[0][1]["target"] is None

    @pytest.mark.asyncio
    async def test_scans_page_route(self, mock_templates):
        """Scans page route should render scans template."""
        from openlabels.web.routes import scans_page

        request = MagicMock(spec=Request)
        await scans_page(request)

        mock_templates.TemplateResponse.assert_called_once()
        call_args = mock_templates.TemplateResponse.call_args
        assert call_args[0][0] == "scans.html"
        assert call_args[0][1]["active_page"] == "scans"

    @pytest.mark.asyncio
    async def test_new_scan_page_route(self, mock_templates):
        """New scan page route should render scan form template."""
        from openlabels.web.routes import new_scan_page

        request = MagicMock(spec=Request)
        await new_scan_page(request)

        mock_templates.TemplateResponse.assert_called_once()
        call_args = mock_templates.TemplateResponse.call_args
        assert call_args[0][0] == "scans_form.html"

    @pytest.mark.asyncio
    async def test_results_page_route(self, mock_templates):
        """Results page route should render results template."""
        from openlabels.web.routes import results_page

        request = MagicMock(spec=Request)
        await results_page(request, scan_id=None)

        mock_templates.TemplateResponse.assert_called_once()
        call_args = mock_templates.TemplateResponse.call_args
        assert call_args[0][0] == "results.html"
        assert call_args[0][1]["active_page"] == "results"

    @pytest.mark.asyncio
    async def test_results_page_with_scan_id(self, mock_templates):
        """Results page route should pass scan_id filter."""
        from openlabels.web.routes import results_page

        request = MagicMock(spec=Request)
        scan_id = "test-scan-id"
        await results_page(request, scan_id=scan_id)

        call_args = mock_templates.TemplateResponse.call_args
        assert call_args[0][1]["scan_id"] == scan_id

    @pytest.mark.asyncio
    async def test_labels_page_route(self, mock_templates):
        """Labels page route should render labels template."""
        from openlabels.web.routes import labels_page

        request = MagicMock(spec=Request)
        await labels_page(request)

        mock_templates.TemplateResponse.assert_called_once()
        call_args = mock_templates.TemplateResponse.call_args
        assert call_args[0][0] == "labels.html"
        assert call_args[0][1]["active_page"] == "labels"

    @pytest.mark.asyncio
    async def test_labels_sync_page_route(self, mock_templates):
        """Labels sync page route should render sync template."""
        from openlabels.web.routes import labels_sync_page

        request = MagicMock(spec=Request)
        await labels_sync_page(request)

        mock_templates.TemplateResponse.assert_called_once()
        call_args = mock_templates.TemplateResponse.call_args
        assert call_args[0][0] == "labels_sync.html"

    @pytest.mark.asyncio
    async def test_monitoring_page_route(self, mock_templates):
        """Monitoring page route should render monitoring template."""
        from openlabels.web.routes import monitoring_page

        request = MagicMock(spec=Request)
        await monitoring_page(request)

        mock_templates.TemplateResponse.assert_called_once()
        call_args = mock_templates.TemplateResponse.call_args
        assert call_args[0][0] == "monitoring.html"
        assert call_args[0][1]["active_page"] == "monitoring"

    @pytest.mark.asyncio
    async def test_schedules_page_route(self, mock_templates):
        """Schedules page route should render schedules template."""
        from openlabels.web.routes import schedules_page

        request = MagicMock(spec=Request)
        await schedules_page(request)

        mock_templates.TemplateResponse.assert_called_once()
        call_args = mock_templates.TemplateResponse.call_args
        assert call_args[0][0] == "schedules.html"
        assert call_args[0][1]["active_page"] == "schedules"

    @pytest.mark.asyncio
    async def test_login_page_route(self, mock_templates):
        """Login page route should render login template."""
        from openlabels.web.routes import login_page

        request = MagicMock(spec=Request)
        await login_page(request)

        mock_templates.TemplateResponse.assert_called_once()
        call_args = mock_templates.TemplateResponse.call_args
        assert call_args[0][0] == "login.html"


class TestSettingsPage:
    """Tests for settings page with config integration."""

    @pytest.fixture
    def mock_settings(self):
        """Mock settings configuration."""
        mock_config = MagicMock()
        mock_config.auth.tenant_id = "test-tenant-id"
        mock_config.auth.client_id = "test-client-id"
        mock_config.detection.max_file_size_mb = 100
        mock_config.detection.enable_ocr = True
        return mock_config

    @pytest.mark.asyncio
    async def test_settings_page_route(self, mock_settings):
        """Settings page should render with config values."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            with patch("openlabels.server.config.get_settings", return_value=mock_settings):
                from openlabels.web.routes import settings_page

                request = MagicMock(spec=Request)
                await settings_page(request)

                call_args = mock_templates.TemplateResponse.call_args
                assert call_args[0][0] == "settings.html"
                settings = call_args[0][1]["settings"]
                assert settings["azure"]["tenant_id"] == "test-tenant-id"
                assert settings["scan"]["max_file_size_mb"] == 100


class TestDetailPages:
    """Tests for detail page routes with database dependencies."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        user.id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_edit_target_page_not_found(self, mock_session, mock_user):
        """Edit target page should return 404 for non-existent target."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")
            mock_session.get = AsyncMock(return_value=None)

            from openlabels.web.routes import edit_target_page

            request = MagicMock(spec=Request)
            result = await edit_target_page(
                request=request,
                target_id=uuid4(),
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "error.html"
            assert call_args[1]["status_code"] == 404

    @pytest.mark.asyncio
    async def test_edit_target_page_found(self, mock_session, mock_user):
        """Edit target page should render form for existing target."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            target = MagicMock()
            target.id = uuid4()
            target.tenant_id = mock_user.tenant_id
            target.name = "Test Target"
            target.adapter = "sharepoint"
            target.config = {"site_url": "https://example.com"}
            target.enabled = True
            mock_session.get = AsyncMock(return_value=target)

            from openlabels.web.routes import edit_target_page

            request = MagicMock(spec=Request)
            await edit_target_page(
                request=request,
                target_id=target.id,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "targets_form.html"
            assert call_args[0][1]["mode"] == "edit"
            assert call_args[0][1]["target"]["name"] == "Test Target"

    @pytest.mark.asyncio
    async def test_edit_target_tenant_isolation(self, mock_session, mock_user):
        """Edit target page should return 404 for other tenant's target."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            target = MagicMock()
            target.id = uuid4()
            target.tenant_id = uuid4()  # Different tenant
            mock_session.get = AsyncMock(return_value=target)

            from openlabels.web.routes import edit_target_page

            request = MagicMock(spec=Request)
            await edit_target_page(
                request=request,
                target_id=target.id,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "error.html"
            assert call_args[1]["status_code"] == 404

    @pytest.mark.asyncio
    async def test_scan_detail_page_not_found(self, mock_session, mock_user):
        """Scan detail page should return 404 for non-existent scan."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")
            mock_session.get = AsyncMock(return_value=None)

            from openlabels.web.routes import scan_detail_page

            request = MagicMock(spec=Request)
            await scan_detail_page(
                request=request,
                scan_id=uuid4(),
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "error.html"
            assert call_args[1]["status_code"] == 404

    @pytest.mark.asyncio
    async def test_scan_detail_page_progress_calculation(self, mock_session, mock_user):
        """Scan detail page should calculate progress correctly."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            scan = MagicMock()
            scan.id = uuid4()
            scan.tenant_id = mock_user.tenant_id
            scan.target_name = "Test Target"
            scan.status = "running"
            scan.files_scanned = 50
            scan.total_files = 100
            scan.error = None
            scan.created_at = datetime.now(timezone.utc)
            scan.started_at = datetime.now(timezone.utc)
            scan.completed_at = None
            mock_session.get = AsyncMock(return_value=scan)

            from openlabels.web.routes import scan_detail_page

            request = MagicMock(spec=Request)
            await scan_detail_page(
                request=request,
                scan_id=scan.id,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][1]["scan"]["progress"] == 50

    @pytest.mark.asyncio
    async def test_scan_detail_completed_progress(self, mock_session, mock_user):
        """Scan detail page should show 100% for completed scans."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            scan = MagicMock()
            scan.id = uuid4()
            scan.tenant_id = mock_user.tenant_id
            scan.target_name = "Test Target"
            scan.status = "completed"
            scan.files_scanned = 0
            scan.total_files = 0
            scan.error = None
            scan.created_at = datetime.now(timezone.utc)
            scan.started_at = datetime.now(timezone.utc)
            scan.completed_at = datetime.now(timezone.utc)
            mock_session.get = AsyncMock(return_value=scan)

            from openlabels.web.routes import scan_detail_page

            request = MagicMock(spec=Request)
            await scan_detail_page(
                request=request,
                scan_id=scan.id,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][1]["scan"]["progress"] == 100

    @pytest.mark.asyncio
    async def test_result_detail_page_not_found(self, mock_session, mock_user):
        """Result detail page should return 404 for non-existent result."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")
            mock_session.get = AsyncMock(return_value=None)

            from openlabels.web.routes import result_detail_page

            request = MagicMock(spec=Request)
            await result_detail_page(
                request=request,
                result_id=uuid4(),
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "error.html"
            assert call_args[1]["status_code"] == 404

    @pytest.mark.asyncio
    async def test_result_detail_page_found(self, mock_session, mock_user):
        """Result detail page should render result details."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            result = MagicMock()
            result.id = uuid4()
            result.tenant_id = mock_user.tenant_id
            result.file_path = "/path/to/file.docx"
            result.risk_tier = "HIGH"
            result.risk_score = 75.5
            result.entity_counts = {"SSN": 3, "EMAIL": 5}
            result.entities = []
            result.label_applied = True
            result.label_name = "Confidential"
            result.scanned_at = datetime.now(timezone.utc)
            result.file_size = 1024
            result.file_hash = "abc123"
            mock_session.get = AsyncMock(return_value=result)

            from openlabels.web.routes import result_detail_page

            request = MagicMock(spec=Request)
            await result_detail_page(
                request=request,
                result_id=result.id,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "result_detail.html"
            assert call_args[0][1]["result"]["file_name"] == "file.docx"
            assert call_args[0][1]["result"]["risk_tier"] == "HIGH"


class TestSchedulePages:
    """Tests for schedule page routes."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        session = AsyncMock()
        session.execute = AsyncMock()
        return session

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        user.id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_new_schedule_page_loads_targets(self, mock_session, mock_user):
        """New schedule page should load enabled targets."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            # Mock targets query result
            target1 = MagicMock()
            target1.id = uuid4()
            target1.name = "Target 1"
            target1.adapter = "sharepoint"

            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = [target1]
            mock_session.execute = AsyncMock(return_value=mock_result)

            from openlabels.web.routes import new_schedule_page

            request = MagicMock(spec=Request)
            await new_schedule_page(
                request=request,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "schedules_form.html"
            assert call_args[0][1]["schedule"] is None
            assert len(call_args[0][1]["targets"]) == 1

    @pytest.mark.asyncio
    async def test_edit_schedule_page_not_found(self, mock_session, mock_user):
        """Edit schedule page should return 404 for non-existent schedule."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")
            mock_session.get = AsyncMock(return_value=None)
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = []
            mock_session.execute = AsyncMock(return_value=mock_result)

            from openlabels.web.routes import edit_schedule_page

            request = MagicMock(spec=Request)
            await edit_schedule_page(
                request=request,
                schedule_id=uuid4(),
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "error.html"
            assert call_args[1]["status_code"] == 404


class TestFormHandlers:
    """Tests for form submission handlers."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        return session

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        user.id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_create_target_form(self, mock_session, mock_user):
        """Create target form should add target to database."""
        from openlabels.web.routes import create_target_form

        request = MagicMock(spec=Request)
        form_data = MagicMock()
        form_data.items.return_value = [
            ("name", "Test Target"),
            ("adapter", "sharepoint"),
            ("config[site_url]", "https://example.com"),
        ]
        request.form = AsyncMock(return_value=form_data)

        result = await create_target_form(
            request=request,
            name="Test Target",
            adapter="sharepoint",
            enabled="on",
            session=mock_session,
            user=mock_user,
        )

        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()
        assert result.status_code == 303

    @pytest.mark.asyncio
    async def test_update_target_form_not_found(self, mock_session, mock_user):
        """Update target form should return 404 for non-existent target."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")
            mock_session.get = AsyncMock(return_value=None)

            from openlabels.web.routes import update_target_form

            request = MagicMock(spec=Request)
            form_data = MagicMock()
            form_data.items.return_value = []
            request.form = AsyncMock(return_value=form_data)

            await update_target_form(
                request=request,
                target_id=uuid4(),
                name="Updated",
                adapter="local",
                enabled=None,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "error.html"

    @pytest.mark.asyncio
    async def test_update_target_form_success(self, mock_session, mock_user):
        """Update target form should update target."""
        target = MagicMock()
        target.id = uuid4()
        target.tenant_id = mock_user.tenant_id
        mock_session.get = AsyncMock(return_value=target)

        from openlabels.web.routes import update_target_form

        request = MagicMock(spec=Request)
        form_data = MagicMock()
        form_data.items.return_value = [("config[path]", "/data")]
        request.form = AsyncMock(return_value=form_data)

        result = await update_target_form(
            request=request,
            target_id=target.id,
            name="Updated Target",
            adapter="local",
            enabled="on",
            session=mock_session,
            user=mock_user,
        )

        assert target.name == "Updated Target"
        assert target.enabled is True
        assert result.status_code == 303


class TestHTMXPartials:
    """Tests for HTMX partial routes."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        session = AsyncMock()
        return session

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_dashboard_stats_partial_no_user(self, mock_session):
        """Dashboard stats should return zeros when no user."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            from openlabels.web.routes import dashboard_stats_partial

            request = MagicMock(spec=Request)
            await dashboard_stats_partial(
                request=request,
                session=mock_session,
                user=None,
            )

            call_args = mock_templates.TemplateResponse.call_args
            stats = call_args[0][1]["stats"]
            assert stats["total_files"] == 0
            assert stats["total_findings"] == 0

    @pytest.mark.asyncio
    async def test_dashboard_stats_partial_with_user(self, mock_session, mock_user):
        """Dashboard stats should fetch real data for authenticated user."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            # Mock file stats result
            file_row = MagicMock()
            file_row.total_files = 100
            file_row.total_findings = 250
            file_row.critical_files = 5

            # Mock active scans result
            active_result = MagicMock()
            active_result.scalar.return_value = 2

            mock_session.execute = AsyncMock(side_effect=[
                MagicMock(one=MagicMock(return_value=file_row)),
                active_result,
            ])

            from openlabels.web.routes import dashboard_stats_partial

            request = MagicMock(spec=Request)
            await dashboard_stats_partial(
                request=request,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            stats = call_args[0][1]["stats"]
            assert stats["total_files"] == 100
            assert stats["active_scans"] == 2

    @pytest.mark.asyncio
    async def test_health_status_partial(self):
        """Health status partial should return healthy status."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            from openlabels.web.routes import health_status_partial

            request = MagicMock(spec=Request)
            await health_status_partial(request)

            call_args = mock_templates.TemplateResponse.call_args
            health = call_args[0][1]["health"]
            assert health["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_system_health_partial_db_ok(self, mock_session):
        """System health partial should check database."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            mock_session.execute = AsyncMock(return_value=MagicMock())

            from openlabels.web.routes import system_health_partial

            request = MagicMock(spec=Request)
            await system_health_partial(request=request, session=mock_session)

            call_args = mock_templates.TemplateResponse.call_args
            health = call_args[0][1]["health"]
            assert health["status"] == "healthy"
            assert health["components"]["database"] == "ok"

    @pytest.mark.asyncio
    async def test_system_health_partial_db_error(self, mock_session):
        """System health partial should detect database errors."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            mock_session.execute = AsyncMock(side_effect=Exception("DB error"))

            from openlabels.web.routes import system_health_partial

            request = MagicMock(spec=Request)
            await system_health_partial(request=request, session=mock_session)

            call_args = mock_templates.TemplateResponse.call_args
            health = call_args[0][1]["health"]
            assert health["status"] == "unhealthy"
            assert health["components"]["database"] == "error"

    @pytest.mark.asyncio
    async def test_targets_list_partial_pagination(self, mock_session, mock_user):
        """Targets list partial should handle pagination."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            # Mock count query
            count_result = MagicMock()
            count_result.scalar.return_value = 25

            # Mock targets query
            target = MagicMock()
            target.id = uuid4()
            target.name = "Target 1"
            target.adapter = "sharepoint"
            target.enabled = True
            target.created_at = datetime.now(timezone.utc)

            targets_result = MagicMock()
            targets_result.scalars.return_value.all.return_value = [target]

            mock_session.execute = AsyncMock(side_effect=[count_result, targets_result])

            from openlabels.web.routes import targets_list_partial

            request = MagicMock(spec=Request)
            await targets_list_partial(
                request=request,
                page=2,
                page_size=10,
                adapter=None,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            context = call_args[0][1]
            assert context["total"] == 25
            assert context["page"] == 2
            assert context["total_pages"] == 3

    @pytest.mark.asyncio
    async def test_scans_list_partial_status_filter(self, mock_session, mock_user):
        """Scans list partial should filter by status."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            count_result = MagicMock()
            count_result.scalar.return_value = 5

            scan = MagicMock()
            scan.id = uuid4()
            scan.target_name = "Test Target"
            scan.status = "running"
            scan.files_scanned = 50
            scan.total_files = 100
            scan.created_at = datetime.now(timezone.utc)

            scans_result = MagicMock()
            scans_result.scalars.return_value.all.return_value = [scan]

            mock_session.execute = AsyncMock(side_effect=[count_result, scans_result])

            from openlabels.web.routes import scans_list_partial

            request = MagicMock(spec=Request)
            await scans_list_partial(
                request=request,
                page=1,
                page_size=10,
                status="running",
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            context = call_args[0][1]
            assert len(context["scans"]) == 1
            assert context["scans"][0]["progress"] == 50

    @pytest.mark.asyncio
    async def test_results_list_partial_filters(self, mock_session, mock_user):
        """Results list partial should handle multiple filters."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            count_result = MagicMock()
            count_result.scalar.return_value = 10

            result = MagicMock()
            result.id = uuid4()
            result.file_path = "/path/to/document.pdf"
            result.risk_tier = "HIGH"
            result.risk_score = 85
            result.entity_counts = {"SSN": 2}
            result.label_applied = False
            result.label_name = None
            result.scanned_at = datetime.now(timezone.utc)

            results_result = MagicMock()
            results_result.scalars.return_value.all.return_value = [result]

            mock_session.execute = AsyncMock(side_effect=[count_result, results_result])

            from openlabels.web.routes import results_list_partial

            request = MagicMock(spec=Request)
            await results_list_partial(
                request=request,
                page=1,
                page_size=20,
                risk_tier="HIGH",
                entity_type=None,
                has_label="false",
                scan_id=None,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            context = call_args[0][1]
            assert len(context["results"]) == 1
            assert context["results"][0]["file_type"] == "pdf"


class TestTargetCheckboxesPartial:
    """Tests for target checkboxes partial (returns raw HTML)."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_target_checkboxes_with_targets(self, mock_session, mock_user):
        """Target checkboxes should render checkboxes for targets."""
        target = MagicMock()
        target.id = uuid4()
        target.name = "Test Target"
        target.adapter = "sharepoint"

        result = MagicMock()
        result.scalars.return_value.all.return_value = [target]
        mock_session.execute = AsyncMock(return_value=result)

        from openlabels.web.routes import target_checkboxes_partial

        request = MagicMock(spec=Request)
        response = await target_checkboxes_partial(
            request=request,
            session=mock_session,
            user=mock_user,
        )

        assert "Test Target" in response.body.decode()
        assert "sharepoint" in response.body.decode()

    @pytest.mark.asyncio
    async def test_target_checkboxes_empty(self, mock_session, mock_user):
        """Target checkboxes should show message when no targets."""
        result = MagicMock()
        result.scalars.return_value.all.return_value = []
        mock_session.execute = AsyncMock(return_value=result)

        from openlabels.web.routes import target_checkboxes_partial

        request = MagicMock(spec=Request)
        response = await target_checkboxes_partial(
            request=request,
            session=mock_session,
            user=mock_user,
        )

        assert "No enabled targets found" in response.body.decode()


class TestCreateScanForm:
    """Tests for scan creation form handler."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        return session

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        user.id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_create_scan_no_targets(self, mock_session, mock_user):
        """Create scan should return error when no targets selected."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            from openlabels.web.routes import create_scan_form

            request = MagicMock(spec=Request)
            form_data = MagicMock()
            form_data.getlist.return_value = []
            request.form = AsyncMock(return_value=form_data)

            await create_scan_form(
                request=request,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "error.html"
            assert call_args[1]["status_code"] == 400

    @pytest.mark.asyncio
    async def test_create_scan_with_targets(self, mock_session, mock_user):
        """Create scan should create jobs for selected targets."""
        target = MagicMock()
        target.id = uuid4()
        target.tenant_id = mock_user.tenant_id
        target.name = "Test Target"
        mock_session.get = AsyncMock(return_value=target)

        with patch("openlabels.jobs.JobQueue") as mock_queue_class:
            mock_queue = AsyncMock()
            mock_queue_class.return_value = mock_queue

            from openlabels.web.routes import create_scan_form

            request = MagicMock(spec=Request)
            form_data = MagicMock()
            form_data.getlist.return_value = [str(target.id)]
            request.form = AsyncMock(return_value=form_data)

            result = await create_scan_form(
                request=request,
                session=mock_session,
                user=mock_user,
            )

            mock_session.add.assert_called()
            mock_queue.enqueue.assert_called_once()
            assert result.status_code == 303


class TestScheduleFormHandlers:
    """Tests for schedule form handlers."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        return session

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        user.id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_create_schedule_form(self, mock_session, mock_user):
        """Create schedule form should add schedule."""
        with patch("openlabels.jobs.parse_cron_expression") as mock_parse:
            mock_parse.return_value = datetime.now(timezone.utc)

            from openlabels.web.routes import create_schedule_form

            request = MagicMock(spec=Request)
            result = await create_schedule_form(
                request=request,
                name="Daily Scan",
                target_id=str(uuid4()),
                cron="0 0 * * *",
                enabled="on",
                session=mock_session,
                user=mock_user,
            )

            mock_session.add.assert_called_once()
            mock_session.flush.assert_called_once()
            assert result.status_code == 303

    @pytest.mark.asyncio
    async def test_update_schedule_form_not_found(self, mock_session, mock_user):
        """Update schedule form should return 404 for non-existent schedule."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")
            mock_session.get = AsyncMock(return_value=None)

            from openlabels.web.routes import update_schedule_form

            request = MagicMock(spec=Request)
            await update_schedule_form(
                request=request,
                schedule_id=uuid4(),
                name="Updated",
                target_id=str(uuid4()),
                cron="0 0 * * *",
                enabled=None,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "error.html"

    @pytest.mark.asyncio
    async def test_update_schedule_form_success(self, mock_session, mock_user):
        """Update schedule form should update schedule."""
        schedule = MagicMock()
        schedule.id = uuid4()
        schedule.tenant_id = mock_user.tenant_id
        mock_session.get = AsyncMock(return_value=schedule)

        with patch("openlabels.jobs.parse_cron_expression") as mock_parse:
            mock_parse.return_value = datetime.now(timezone.utc)

            from openlabels.web.routes import update_schedule_form

            request = MagicMock(spec=Request)
            target_id = uuid4()
            result = await update_schedule_form(
                request=request,
                schedule_id=schedule.id,
                name="Updated Schedule",
                target_id=str(target_id),
                cron="0 6 * * *",
                enabled="on",
                session=mock_session,
                user=mock_user,
            )

            assert schedule.name == "Updated Schedule"
            assert schedule.enabled is True
            assert result.status_code == 303


class TestRecentScansPartial:
    """Tests for recent scans partial."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_recent_scans_partial_no_user(self, mock_session):
        """Recent scans should return empty list when no user."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            from openlabels.web.routes import recent_scans_partial

            request = MagicMock(spec=Request)
            await recent_scans_partial(
                request=request,
                session=mock_session,
                user=None,
            )

            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][1]["recent_scans"] == []

    @pytest.mark.asyncio
    async def test_recent_scans_partial_with_data(self, mock_session, mock_user):
        """Recent scans should return scan data with findings count."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            scan = MagicMock()
            scan.id = uuid4()
            scan.target_name = "Test Target"
            scan.status = "completed"
            scan.files_scanned = 100
            scan.created_at = datetime.now(timezone.utc)
            scan.started_at = datetime.now(timezone.utc)
            scan.completed_at = datetime.now(timezone.utc)

            scans_result = MagicMock()
            scans_result.scalars.return_value.all.return_value = [scan]

            findings_result = MagicMock()
            findings_result.scalar.return_value = 50

            mock_session.execute = AsyncMock(side_effect=[scans_result, findings_result])

            from openlabels.web.routes import recent_scans_partial

            request = MagicMock(spec=Request)
            await recent_scans_partial(
                request=request,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            recent_scans = call_args[0][1]["recent_scans"]
            assert len(recent_scans) == 1
            assert recent_scans[0]["findings_count"] == 50


class TestFindingsByTypePartial:
    """Tests for findings by type partial."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_findings_by_type_aggregation(self, mock_session, mock_user):
        """Findings by type should aggregate entity counts."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            row1 = MagicMock()
            row1.entity_counts = {"SSN": 5, "EMAIL": 3}
            row1.risk_tier = "HIGH"

            row2 = MagicMock()
            row2.entity_counts = {"SSN": 2, "PHONE": 4}
            row2.risk_tier = "MEDIUM"

            result = MagicMock()
            result.all.return_value = [row1, row2]
            mock_session.execute = AsyncMock(return_value=result)

            from openlabels.web.routes import findings_by_type_partial

            request = MagicMock(spec=Request)
            await findings_by_type_partial(
                request=request,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            findings = call_args[0][1]["findings_by_type"]

            # Check aggregation
            ssn_finding = next((f for f in findings if f["entity_type"] == "SSN"), None)
            assert ssn_finding is not None
            assert ssn_finding["count"] == 7  # 5 + 2


class TestRiskDistributionPartial:
    """Tests for risk distribution partial."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_risk_distribution_calculation(self, mock_session, mock_user):
        """Risk distribution should calculate percentages."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            row1 = MagicMock()
            row1.risk_tier = "HIGH"
            row1.count = 25

            row2 = MagicMock()
            row2.risk_tier = "LOW"
            row2.count = 75

            result = MagicMock()
            result.all.return_value = [row1, row2]
            mock_session.execute = AsyncMock(return_value=result)

            from openlabels.web.routes import risk_distribution_partial

            request = MagicMock(spec=Request)
            await risk_distribution_partial(
                request=request,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            distribution = call_args[0][1]["risk_distribution"]

            high_risk = next((d for d in distribution if d["level"] == "HIGH"), None)
            assert high_risk is not None
            assert high_risk["percentage"] == 25.0


class TestActivityLogPartial:
    """Tests for activity log partial."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_activity_log_with_filter(self, mock_session, mock_user):
        """Activity log should support action filter."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            log = MagicMock()
            log.action = "scan_completed"
            log.resource_type = "scan"
            log.resource_id = uuid4()
            log.details = {"name": "Test Scan"}
            log.created_at = datetime.now(timezone.utc)

            result = MagicMock()
            result.scalars.return_value.all.return_value = [log]
            mock_session.execute = AsyncMock(return_value=result)

            from openlabels.web.routes import activity_log_partial

            request = MagicMock(spec=Request)
            await activity_log_partial(
                request=request,
                action="scan_completed",
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            logs = call_args[0][1]["activity_logs"]
            assert len(logs) == 1
            assert logs[0]["action"] == "scan_completed"


class TestRecentActivityPartial:
    """Tests for recent activity partial."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_recent_activity_format(self, mock_session, mock_user):
        """Recent activity should format action descriptions."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            log = MagicMock()
            log.action = "target_created"
            log.details = {"name": "New Target"}
            log.created_at = datetime.now(timezone.utc)

            result = MagicMock()
            result.scalars.return_value.all.return_value = [log]
            mock_session.execute = AsyncMock(return_value=result)

            from openlabels.web.routes import recent_activity_partial

            request = MagicMock(spec=Request)
            await recent_activity_partial(
                request=request,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            activity = call_args[0][1]["recent_activity"]
            assert len(activity) == 1
            assert activity[0]["description"] == "Target Created"
            assert activity[0]["details"] == "New Target"


class TestJobQueuePartial:
    """Tests for job queue partial."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_job_queue_stats(self, mock_session, mock_user):
        """Job queue should return status counts."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            # Mock stats query
            stat1 = MagicMock()
            stat1.status = "pending"
            stat1.count = 5

            stat2 = MagicMock()
            stat2.status = "running"
            stat2.count = 2

            stats_result = MagicMock()
            stats_result.all.return_value = [stat1, stat2]

            # Mock failed jobs query
            failed_result = MagicMock()
            failed_result.scalars.return_value.all.return_value = []

            mock_session.execute = AsyncMock(side_effect=[stats_result, failed_result])

            from openlabels.web.routes import job_queue_partial

            request = MagicMock(spec=Request)
            await job_queue_partial(
                request=request,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            stats = call_args[0][1]["stats"]
            assert stats["pending"] == 5
            assert stats["running"] == 2


class TestLabelsListPartial:
    """Tests for labels list partial."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_labels_list_partial(self, mock_session, mock_user):
        """Labels list should return label data."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            label = MagicMock()
            label.id = uuid4()
            label.name = "Confidential"
            label.description = "Confidential data"
            label.color = "#FF0000"
            label.priority = 1
            label.updated_at = datetime.now(timezone.utc)

            result = MagicMock()
            result.scalars.return_value.all.return_value = [label]
            mock_session.execute = AsyncMock(return_value=result)

            from openlabels.web.routes import labels_list_partial

            request = MagicMock(spec=Request)
            await labels_list_partial(
                request=request,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            labels = call_args[0][1]["labels"]
            assert len(labels) == 1
            assert labels[0]["name"] == "Confidential"


class TestSchedulesListPartial:
    """Tests for schedules list partial."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = MagicMock()
        user.tenant_id = uuid4()
        return user

    @pytest.mark.asyncio
    async def test_schedules_list_with_target_names(self, mock_session, mock_user):
        """Schedules list should include target names."""
        with patch("openlabels.web.routes.templates") as mock_templates:
            mock_templates.TemplateResponse = MagicMock(return_value="mocked_response")

            schedule = MagicMock()
            schedule.id = uuid4()
            schedule.name = "Daily Scan"
            schedule.target_id = uuid4()
            schedule.cron = "0 0 * * *"
            schedule.enabled = True
            schedule.last_run_at = None
            schedule.next_run_at = datetime.now(timezone.utc)

            target = MagicMock()
            target.name = "SharePoint Target"

            schedules_result = MagicMock()
            schedules_result.scalars.return_value.all.return_value = [schedule]

            # First call returns schedules, then get returns target
            mock_session.execute = AsyncMock(return_value=schedules_result)
            mock_session.get = AsyncMock(return_value=target)

            from openlabels.web.routes import schedules_list_partial

            request = MagicMock(spec=Request)
            await schedules_list_partial(
                request=request,
                session=mock_session,
                user=mock_user,
            )

            call_args = mock_templates.TemplateResponse.call_args
            schedules = call_args[0][1]["schedules"]
            assert len(schedules) == 1
            assert schedules[0]["target_name"] == "SharePoint Target"
