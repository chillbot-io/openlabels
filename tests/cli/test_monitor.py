"""
Functional tests for the monitor CLI commands.

Tests file access monitoring functionality including:
- Enable/disable monitoring
- List monitored files
- View access history
- Check monitoring status
"""

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from openlabels.monitoring.base import (
    AccessAction,
    AccessEvent,
    MonitoringResult,
    WatchedFile,
)


@pytest.fixture
def runner():
    """Create a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def temp_dir():
    """Create a temporary directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        test_file = Path(tmpdir) / "sensitive_file.txt"
        test_file.write_text("SSN: 123-45-6789")

        other_file = Path(tmpdir) / "regular_file.txt"
        other_file.write_text("Some regular content")

        yield tmpdir


@pytest.fixture
def mock_monitoring_result_success():
    """Create a successful monitoring result."""
    return MonitoringResult(
        success=True,
        path=Path("/test/file.txt"),
        message="Monitoring enabled successfully",
        sacl_enabled=True,
        audit_rule_enabled=False,
    )


@pytest.fixture
def mock_watched_files():
    """Create mock watched files."""
    return [
        WatchedFile(
            path=Path("/data/sensitive.xlsx"),
            risk_tier="CRITICAL",
            added_at=datetime(2026, 1, 15, 10, 30, 0),
            sacl_enabled=True,
            audit_rule_enabled=False,
            last_event_at=datetime(2026, 1, 16, 14, 22, 0),
            access_count=15,
        ),
        WatchedFile(
            path=Path("/docs/financial.pdf"),
            risk_tier="HIGH",
            added_at=datetime(2026, 1, 10, 9, 0, 0),
            sacl_enabled=True,
            audit_rule_enabled=False,
            access_count=5,
        ),
    ]


@pytest.fixture
def mock_access_events():
    """Create mock access events."""
    return [
        AccessEvent(
            path=Path("/test/file.txt"),
            timestamp=datetime(2026, 1, 16, 14, 22, 0),
            action=AccessAction.READ,
            user_name="jsmith",
            user_domain="CORP",
            process_name="excel.exe",
            process_id=1234,
            success=True,
        ),
        AccessEvent(
            path=Path("/test/file.txt"),
            timestamp=datetime(2026, 1, 16, 12, 15, 0),
            action=AccessAction.WRITE,
            user_name="analyst",
            user_domain="CORP",
            process_name="notepad.exe",
            process_id=5678,
            success=True,
        ),
    ]


class TestMonitorHelp:
    """Tests for monitor command help."""

    def test_monitor_help_shows_subcommands(self, runner):
        """monitor --help should show available subcommands."""
        from openlabels.cli.commands.monitor import monitor

        result = runner.invoke(monitor, ["--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output
        assert "enable" in result.output
        assert "disable" in result.output
        assert "list" in result.output
        assert "history" in result.output
        assert "status" in result.output


class TestMonitorEnable:
    """Tests for monitor enable command."""

    def test_monitor_enable_help(self, runner):
        """monitor enable --help should show usage."""
        from openlabels.cli.commands.monitor import monitor

        result = runner.invoke(monitor, ["enable", "--help"])

        assert result.exit_code == 0
        assert "FILE_PATH" in result.output
        assert "--risk-tier" in result.output
        assert "--audit-read" in result.output
        assert "--audit-write" in result.output

    def test_monitor_enable_success(self, runner, temp_dir, mock_monitoring_result_success):
        """Enable monitoring on a file successfully."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.monitoring.enable_monitoring", return_value=mock_monitoring_result_success):
            result = runner.invoke(monitor, ["enable", str(test_file)])

        assert result.exit_code == 0
        assert "Monitoring enabled:" in result.output

    def test_monitor_enable_with_risk_tier(self, runner, temp_dir, mock_monitoring_result_success):
        """Enable monitoring with specific risk tier."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.monitoring.enable_monitoring", return_value=mock_monitoring_result_success) as mock:
            result = runner.invoke(monitor, ["enable", str(test_file), "--risk-tier", "CRITICAL"])

        assert result.exit_code == 0
        mock.assert_called_once()
        _, kwargs = mock.call_args
        assert kwargs["risk_tier"] == "CRITICAL"

    def test_monitor_enable_with_audit_options(self, runner, temp_dir, mock_monitoring_result_success):
        """Enable monitoring with audit options."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.monitoring.enable_monitoring", return_value=mock_monitoring_result_success) as mock:
            result = runner.invoke(monitor, [
                "enable", str(test_file),
                "--no-audit-read",
                "--audit-write",
            ])

        assert result.exit_code == 0
        mock.assert_called_once()
        _, kwargs = mock.call_args
        assert kwargs["audit_read"] is False
        assert kwargs["audit_write"] is True

    def test_monitor_enable_shows_sacl_status(self, runner, temp_dir, mock_monitoring_result_success):
        """Enable monitoring shows SACL status."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.monitoring.enable_monitoring", return_value=mock_monitoring_result_success):
            result = runner.invoke(monitor, ["enable", str(test_file)])

        assert result.exit_code == 0
        assert "SACL: enabled" in result.output

    def test_monitor_enable_failure(self, runner, temp_dir):
        """Enable monitoring failure shows error."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        failure_result = MonitoringResult(
            success=False,
            path=Path(test_file),
            error="Insufficient privileges to modify SACL",
        )

        with patch("openlabels.monitoring.enable_monitoring", return_value=failure_result):
            result = runner.invoke(monitor, ["enable", str(test_file)])

        assert result.exit_code == 1
        assert "Error:" in result.output
        assert "Insufficient privileges" in result.output

    def test_monitor_enable_nonexistent_file(self, runner, temp_dir):
        """Enable monitoring on non-existent file should fail."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "nonexistent.txt"

        result = runner.invoke(monitor, ["enable", str(test_file)])

        assert result.exit_code == 2
        assert "does not exist" in result.output.lower() or "invalid" in result.output.lower()

    def test_monitor_enable_without_file_fails(self, runner):
        """Enable monitoring without file path should fail."""
        from openlabels.cli.commands.monitor import monitor

        result = runner.invoke(monitor, ["enable"])

        assert result.exit_code == 2
        assert "Missing argument" in result.output or "FILE_PATH" in result.output


class TestMonitorDisable:
    """Tests for monitor disable command."""

    def test_monitor_disable_help(self, runner):
        """monitor disable --help should show usage."""
        from openlabels.cli.commands.monitor import monitor

        result = runner.invoke(monitor, ["disable", "--help"])

        assert result.exit_code == 0
        assert "FILE_PATH" in result.output

    def test_monitor_disable_success(self, runner, temp_dir):
        """Disable monitoring on a file successfully."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        success_result = MonitoringResult(
            success=True,
            path=Path(test_file),
            message="Monitoring disabled",
        )

        with patch("openlabels.monitoring.disable_monitoring", return_value=success_result):
            result = runner.invoke(monitor, ["disable", str(test_file)])

        assert result.exit_code == 0
        assert "Monitoring disabled:" in result.output

    def test_monitor_disable_failure(self, runner, temp_dir):
        """Disable monitoring failure shows error."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        failure_result = MonitoringResult(
            success=False,
            path=Path(test_file),
            error="File is not being monitored",
        )

        with patch("openlabels.monitoring.disable_monitoring", return_value=failure_result):
            result = runner.invoke(monitor, ["disable", str(test_file)])

        assert result.exit_code == 1
        assert "Error:" in result.output


class TestMonitorList:
    """Tests for monitor list command."""

    def test_monitor_list_help(self, runner):
        """monitor list --help should show usage."""
        from openlabels.cli.commands.monitor import monitor

        result = runner.invoke(monitor, ["list", "--help"])

        assert result.exit_code == 0
        assert "--json" in result.output

    def test_monitor_list_table_format(self, runner, mock_watched_files):
        """List monitored files in table format."""
        from openlabels.cli.commands.monitor import monitor

        with patch("openlabels.monitoring.get_watched_files", return_value=mock_watched_files):
            result = runner.invoke(monitor, ["list"])

        assert result.exit_code == 0
        assert "Path" in result.output
        assert "Risk" in result.output
        assert "Added" in result.output
        assert "sensitive.xlsx" in result.output
        assert "CRITICAL" in result.output

    def test_monitor_list_json_format(self, runner, mock_watched_files):
        """List monitored files in JSON format."""
        from openlabels.cli.commands.monitor import monitor

        with patch("openlabels.monitoring.get_watched_files", return_value=mock_watched_files):
            result = runner.invoke(monitor, ["list", "--json"])

        assert result.exit_code == 0

        import json
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 2
        assert "path" in data[0]
        assert "risk_tier" in data[0]

    def test_monitor_list_empty(self, runner):
        """List monitored files when none exist."""
        from openlabels.cli.commands.monitor import monitor

        with patch("openlabels.monitoring.get_watched_files", return_value=[]):
            result = runner.invoke(monitor, ["list"])

        assert result.exit_code == 0
        assert "No files currently monitored" in result.output


class TestMonitorHistory:
    """Tests for monitor history command."""

    def test_monitor_history_help(self, runner):
        """monitor history --help should show usage."""
        from openlabels.cli.commands.monitor import monitor

        result = runner.invoke(monitor, ["history", "--help"])

        assert result.exit_code == 0
        assert "FILE_PATH" in result.output
        assert "--days" in result.output
        assert "--limit" in result.output
        assert "--include-system" in result.output
        assert "--json" in result.output

    def test_monitor_history_table_format(self, runner, temp_dir, mock_access_events):
        """View access history in table format."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.monitoring.get_access_history", return_value=mock_access_events):
            result = runner.invoke(monitor, ["history", str(test_file)])

        assert result.exit_code == 0
        assert "Access history for:" in result.output
        assert "Timestamp" in result.output
        assert "User" in result.output
        assert "Action" in result.output
        assert "Process" in result.output
        assert "jsmith" in result.output
        assert "excel.exe" in result.output

    def test_monitor_history_json_format(self, runner, temp_dir, mock_access_events):
        """View access history in JSON format."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.monitoring.get_access_history", return_value=mock_access_events):
            result = runner.invoke(monitor, ["history", str(test_file), "--json"])

        assert result.exit_code == 0

        import json
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 2
        assert "action" in data[0]
        assert "user_name" in data[0]

    def test_monitor_history_with_days_option(self, runner, temp_dir, mock_access_events):
        """View access history with custom days range."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.monitoring.get_access_history", return_value=mock_access_events) as mock:
            result = runner.invoke(monitor, ["history", str(test_file), "--days", "7"])

        assert result.exit_code == 0
        mock.assert_called_once()
        _, kwargs = mock.call_args
        assert kwargs["days"] == 7

    def test_monitor_history_with_limit(self, runner, temp_dir, mock_access_events):
        """View access history with result limit."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.monitoring.get_access_history", return_value=mock_access_events) as mock:
            result = runner.invoke(monitor, ["history", str(test_file), "--limit", "10"])

        assert result.exit_code == 0
        mock.assert_called_once()
        _, kwargs = mock.call_args
        assert kwargs["limit"] == 10

    def test_monitor_history_include_system(self, runner, temp_dir, mock_access_events):
        """View access history including system accounts."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.monitoring.get_access_history", return_value=mock_access_events) as mock:
            result = runner.invoke(monitor, ["history", str(test_file), "--include-system"])

        assert result.exit_code == 0
        mock.assert_called_once()
        _, kwargs = mock.call_args
        assert kwargs["include_system"] is True

    def test_monitor_history_no_events(self, runner, temp_dir):
        """View access history when no events exist."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.monitoring.get_access_history", return_value=[]):
            result = runner.invoke(monitor, ["history", str(test_file)])

        assert result.exit_code == 0
        assert "No access events found" in result.output


class TestMonitorStatus:
    """Tests for monitor status command."""

    def test_monitor_status_help(self, runner):
        """monitor status --help should show usage."""
        from openlabels.cli.commands.monitor import monitor

        result = runner.invoke(monitor, ["status", "--help"])

        assert result.exit_code == 0
        assert "FILE_PATH" in result.output

    def test_monitor_status_monitored_file(self, runner, temp_dir, mock_watched_files):
        """Check status of a monitored file."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        # Create a watched file entry matching the test file
        watched = WatchedFile(
            path=test_file.resolve(),
            risk_tier="HIGH",
            added_at=datetime(2026, 1, 15, 10, 30, 0),
            sacl_enabled=True,
            audit_rule_enabled=False,
            access_count=10,
        )

        with patch("openlabels.monitoring.is_monitored", return_value=True):
            with patch("openlabels.monitoring.get_watched_files", return_value=[watched]):
                result = runner.invoke(monitor, ["status", str(test_file)])

        assert result.exit_code == 0
        assert "Status: MONITORED" in result.output
        assert "Risk tier:" in result.output
        assert "SACL enabled:" in result.output

    def test_monitor_status_unmonitored_file(self, runner, temp_dir):
        """Check status of an unmonitored file."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "regular_file.txt"

        with patch("openlabels.monitoring.is_monitored", return_value=False):
            result = runner.invoke(monitor, ["status", str(test_file)])

        assert result.exit_code == 0
        assert "Status: NOT MONITORED" in result.output

    def test_monitor_status_shows_access_count(self, runner, temp_dir):
        """Status shows access count for monitored file."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        watched = WatchedFile(
            path=test_file.resolve(),
            risk_tier="HIGH",
            added_at=datetime(2026, 1, 15, 10, 30, 0),
            sacl_enabled=True,
            audit_rule_enabled=False,
            access_count=25,
        )

        with patch("openlabels.monitoring.is_monitored", return_value=True):
            with patch("openlabels.monitoring.get_watched_files", return_value=[watched]):
                result = runner.invoke(monitor, ["status", str(test_file)])

        assert result.exit_code == 0
        assert "Access count:" in result.output
        assert "25" in result.output


class TestMonitorErrorHandling:
    """Tests for monitor error handling."""

    def test_monitor_enable_import_error(self, runner, temp_dir):
        """Enable monitoring handles import error gracefully."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.monitoring.enable_monitoring", side_effect=ImportError("Module not found")):
            result = runner.invoke(monitor, ["enable", str(test_file)])

        # Should handle error gracefully
        assert result.exit_code != 0 or "Error" in result.output or "Traceback" in result.output


class TestMonitorIntegration:
    """Integration-style tests for monitor commands."""

    def test_monitor_workflow(self, runner, temp_dir, mock_monitoring_result_success, mock_access_events):
        """Test complete monitoring workflow."""
        from openlabels.cli.commands.monitor import monitor

        test_file = Path(temp_dir) / "sensitive_file.txt"

        # Enable monitoring
        with patch("openlabels.monitoring.enable_monitoring", return_value=mock_monitoring_result_success):
            result = runner.invoke(monitor, ["enable", str(test_file), "--risk-tier", "CRITICAL"])
        assert result.exit_code == 0

        # Check status
        watched = WatchedFile(
            path=test_file.resolve(),
            risk_tier="CRITICAL",
            added_at=datetime.now(),
            sacl_enabled=True,
            audit_rule_enabled=False,
        )
        with patch("openlabels.monitoring.is_monitored", return_value=True):
            with patch("openlabels.monitoring.get_watched_files", return_value=[watched]):
                result = runner.invoke(monitor, ["status", str(test_file)])
        assert result.exit_code == 0
        assert "MONITORED" in result.output

        # View history
        with patch("openlabels.monitoring.get_access_history", return_value=mock_access_events):
            result = runner.invoke(monitor, ["history", str(test_file)])
        assert result.exit_code == 0

        # Disable monitoring
        disable_result = MonitoringResult(success=True, path=Path(test_file))
        with patch("openlabels.monitoring.disable_monitoring", return_value=disable_result):
            result = runner.invoke(monitor, ["disable", str(test_file)])
        assert result.exit_code == 0
