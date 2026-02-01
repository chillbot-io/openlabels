"""
Tests for the health CLI command.

Tests system health check functionality.
"""

import argparse
import json
from unittest.mock import patch, MagicMock

import pytest

from openlabels.health import CheckStatus
from openlabels.cli.commands.health import (
    _status_icon,
    cmd_health,
    add_health_parser,
)


class TestStatusIcon:
    """Tests for _status_icon helper function."""

    def test_pass_icon(self):
        """PASS status should return green PASS."""
        result = _status_icon(CheckStatus.PASS)
        assert "PASS" in result
        assert "green" in result

    def test_fail_icon(self):
        """FAIL status should return red FAIL."""
        result = _status_icon(CheckStatus.FAIL)
        assert "FAIL" in result
        assert "red" in result

    def test_warn_icon(self):
        """WARN status should return yellow WARN."""
        result = _status_icon(CheckStatus.WARN)
        assert "WARN" in result
        assert "yellow" in result

    def test_skip_icon(self):
        """SKIP status should return dim SKIP."""
        result = _status_icon(CheckStatus.SKIP)
        assert "SKIP" in result
        assert "dim" in result

    def test_unknown_status(self):
        """Unknown status should return ???? placeholder."""
        result = _status_icon(MagicMock())
        assert "????" in result


class TestCmdHealthValidation:
    """Tests for cmd_health command."""

    @pytest.fixture
    def mock_args(self):
        """Create mock args object."""
        args = MagicMock()
        args.check = None
        args.json = False
        args.verbose = False
        return args

    @pytest.fixture
    def mock_check_result(self):
        """Create mock check result."""
        result = MagicMock()
        result.name = "test_check"
        result.status = CheckStatus.PASS
        result.message = "Check passed"
        result.passed = True
        result.error = None
        result.details = {}
        result.duration_ms = 10.5
        return result

    @pytest.fixture
    def mock_report(self, mock_check_result):
        """Create mock health report."""
        report = MagicMock()
        report.checks = [mock_check_result]
        report.healthy = True
        report.to_dict.return_value = {
            "healthy": True,
            "checks": [{"name": "test_check", "status": "PASS"}]
        }
        return report


class TestCmdHealthRunAllChecks:
    """Tests for running all health checks."""

    @pytest.fixture
    def mock_args(self):
        args = MagicMock()
        args.check = None
        args.json = False
        args.verbose = False
        return args

    def test_runs_all_checks_when_no_specific_check(self, mock_args):
        """Should run all checks when no specific check requested."""
        mock_report = MagicMock()
        mock_report.checks = []
        mock_report.healthy = True

        with patch("openlabels.cli.commands.health.HealthChecker") as MockChecker:
            MockChecker.return_value.run_all.return_value = mock_report
            with patch("openlabels.cli.commands.health.console"):
                with patch("openlabels.cli.commands.health.echo"):
                    with patch("openlabels.cli.commands.health.success"):
                        result = cmd_health(mock_args)

        MockChecker.return_value.run_all.assert_called_once()
        assert result == 0

    def test_returns_zero_when_healthy(self, mock_args):
        """Should return 0 when all checks pass."""
        mock_check = MagicMock()
        mock_check.status = CheckStatus.PASS
        mock_check.name = "test"
        mock_check.message = "OK"
        mock_check.error = None
        mock_check.details = {}
        mock_check.duration_ms = 5.0

        mock_report = MagicMock()
        mock_report.checks = [mock_check]
        mock_report.healthy = True

        with patch("openlabels.cli.commands.health.HealthChecker") as MockChecker:
            MockChecker.return_value.run_all.return_value = mock_report
            with patch("openlabels.cli.commands.health.console"):
                with patch("openlabels.cli.commands.health.echo"):
                    with patch("openlabels.cli.commands.health.success"):
                        with patch("openlabels.cli.commands.health.dim"):
                            result = cmd_health(mock_args)

        assert result == 0

    def test_returns_one_when_unhealthy(self, mock_args):
        """Should return 1 when checks fail."""
        mock_check = MagicMock()
        mock_check.status = CheckStatus.FAIL
        mock_check.name = "test"
        mock_check.message = "Failed"
        mock_check.error = "Error details"
        mock_check.details = {}
        mock_check.duration_ms = 5.0

        mock_report = MagicMock()
        mock_report.checks = [mock_check]
        mock_report.healthy = False

        with patch("openlabels.cli.commands.health.HealthChecker") as MockChecker:
            MockChecker.return_value.run_all.return_value = mock_report
            with patch("openlabels.cli.commands.health.console"):
                with patch("openlabels.cli.commands.health.echo"):
                    with patch("openlabels.cli.commands.health.error"):
                        with patch("openlabels.cli.commands.health.dim"):
                            result = cmd_health(mock_args)

        assert result == 1


class TestCmdHealthSpecificCheck:
    """Tests for running specific health checks."""

    @pytest.fixture
    def mock_args(self):
        args = MagicMock()
        args.check = "python_version"
        args.json = False
        args.verbose = False
        return args

    def test_runs_specific_check(self, mock_args):
        """Should run only the specified check."""
        mock_check = MagicMock()
        mock_check.status = CheckStatus.PASS
        mock_check.name = "python_version"
        mock_check.message = "Python 3.11"
        mock_check.passed = True
        mock_check.error = None
        mock_check.details = {}
        mock_check.duration_ms = 1.0

        with patch("openlabels.cli.commands.health.HealthChecker") as MockChecker:
            MockChecker.return_value.run_check.return_value = mock_check
            with patch("openlabels.cli.commands.health.console"):
                with patch("openlabels.cli.commands.health.echo"):
                    with patch("openlabels.cli.commands.health.success"):
                        with patch("openlabels.cli.commands.health.dim"):
                            result = cmd_health(mock_args)

        MockChecker.return_value.run_check.assert_called_once_with("python_version")
        assert result == 0

    def test_returns_error_for_unknown_check(self, mock_args):
        """Should return error for unknown check name."""
        mock_args.check = "nonexistent_check"

        with patch("openlabels.cli.commands.health.HealthChecker") as MockChecker:
            MockChecker.return_value.run_check.return_value = None
            with patch("openlabels.cli.commands.health.error"):
                result = cmd_health(mock_args)

        assert result == 1


class TestCmdHealthJsonOutput:
    """Tests for JSON output mode."""

    @pytest.fixture
    def mock_args(self):
        args = MagicMock()
        args.check = None
        args.json = True
        args.verbose = False
        return args

    def test_outputs_json(self, mock_args):
        """Should output JSON when --json flag set."""
        mock_report = MagicMock()
        mock_report.checks = []
        mock_report.healthy = True
        mock_report.to_dict.return_value = {
            "healthy": True,
            "checks": []
        }

        with patch("openlabels.cli.commands.health.HealthChecker") as MockChecker:
            MockChecker.return_value.run_all.return_value = mock_report
            with patch("openlabels.cli.commands.health.echo") as mock_echo:
                result = cmd_health(mock_args)

        # Should have called echo with JSON
        call_args = mock_echo.call_args[0][0]
        parsed = json.loads(call_args)
        assert parsed["healthy"] is True
        assert result == 0

    def test_json_returns_error_code_on_failure(self, mock_args):
        """JSON mode should return 1 when unhealthy."""
        mock_report = MagicMock()
        mock_report.checks = []
        mock_report.healthy = False
        mock_report.to_dict.return_value = {"healthy": False, "checks": []}

        with patch("openlabels.cli.commands.health.HealthChecker") as MockChecker:
            MockChecker.return_value.run_all.return_value = mock_report
            with patch("openlabels.cli.commands.health.echo"):
                result = cmd_health(mock_args)

        assert result == 1


class TestCmdHealthVerboseMode:
    """Tests for verbose output mode."""

    @pytest.fixture
    def mock_args(self):
        args = MagicMock()
        args.check = None
        args.json = False
        args.verbose = True
        return args

    def test_shows_details_in_verbose_mode(self, mock_args):
        """Should show check details in verbose mode."""
        mock_check = MagicMock()
        mock_check.status = CheckStatus.PASS
        mock_check.name = "test"
        mock_check.message = "OK"
        mock_check.error = None
        mock_check.details = {"version": "3.11", "path": "/usr/bin/python"}
        mock_check.duration_ms = 5.0

        mock_report = MagicMock()
        mock_report.checks = [mock_check]
        mock_report.healthy = True

        with patch("openlabels.cli.commands.health.HealthChecker") as MockChecker:
            MockChecker.return_value.run_all.return_value = mock_report
            with patch("openlabels.cli.commands.health.console"):
                with patch("openlabels.cli.commands.health.echo"):
                    with patch("openlabels.cli.commands.health.success"):
                        with patch("openlabels.cli.commands.health.dim") as mock_dim:
                            result = cmd_health(mock_args)

        # Should have called dim with details
        dim_calls = [str(call) for call in mock_dim.call_args_list]
        assert any("version" in str(call) for call in dim_calls)


class TestCmdHealthSummary:
    """Tests for health check summary."""

    @pytest.fixture
    def mock_args(self):
        args = MagicMock()
        args.check = None
        args.json = False
        args.verbose = False
        return args

    def test_shows_warning_count(self, mock_args):
        """Should show warning count in summary."""
        mock_checks = [
            MagicMock(status=CheckStatus.PASS, name="check1", message="OK",
                     error=None, details={}, duration_ms=1.0),
            MagicMock(status=CheckStatus.WARN, name="check2", message="Warning",
                     error=None, details={}, duration_ms=1.0),
        ]

        mock_report = MagicMock()
        mock_report.checks = mock_checks
        mock_report.healthy = True

        with patch("openlabels.cli.commands.health.HealthChecker") as MockChecker:
            MockChecker.return_value.run_all.return_value = mock_report
            with patch("openlabels.cli.commands.health.console"):
                with patch("openlabels.cli.commands.health.echo"):
                    with patch("openlabels.cli.commands.health.success") as mock_success:
                        with patch("openlabels.cli.commands.health.dim"):
                            result = cmd_health(mock_args)

        # Should mention warning
        success_call = str(mock_success.call_args)
        assert "warning" in success_call.lower()


class TestAddHealthParser:
    """Tests for add_health_parser function."""

    def test_adds_parser(self):
        """Should add health parser to subparsers."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        result = add_health_parser(subparsers)

        assert result is not None

    def test_parser_has_check_arg(self):
        """Parser should have --check argument."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_health_parser(subparsers)

        args = parser.parse_args(["health", "--check", "python_version"])
        assert args.check == "python_version"

    def test_parser_has_json_arg(self):
        """Parser should have --json argument."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_health_parser(subparsers)

        args = parser.parse_args(["health", "--json"])
        assert args.json is True

    def test_parser_has_verbose_arg(self):
        """Parser should have --verbose argument."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_health_parser(subparsers)

        args = parser.parse_args(["health", "--verbose"])
        assert args.verbose is True

    def test_parser_defaults(self):
        """Parser should have correct defaults."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_health_parser(subparsers)

        args = parser.parse_args(["health"])
        assert args.check is None
        assert args.json is False
        assert args.verbose is False

    def test_short_flags(self):
        """Parser should support short flags."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_health_parser(subparsers)

        args = parser.parse_args(["health", "-c", "detector", "-j", "-v"])
        assert args.check == "detector"
        assert args.json is True
        assert args.verbose is True
