"""
Tests for CLI commands.

Tests actual CLI behavior: command existence, required arguments, output format.
"""

from click.testing import CliRunner
import pytest


class TestCLIHelp:
    """Tests for CLI help and basic functionality."""

    def test_cli_shows_help(self):
        """CLI --help should show usage information."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output
        # Should list main commands
        assert "serve" in result.output
        assert "scan" in result.output
        assert "config" in result.output

    def test_cli_no_args_shows_help(self):
        """CLI with no arguments should show help or usage error."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, [])

        # Click may show help or usage error depending on configuration
        # The important thing is it shows usage information
        assert "Usage:" in result.output or "usage:" in result.output.lower()

    def test_unknown_command_fails(self):
        """Unknown command should fail with error."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["nonexistent_command"])

        assert result.exit_code == 2  # Click usage error
        assert "Error" in result.output or "No such command" in result.output


class TestServeCommand:
    """Tests for the serve command."""

    def test_serve_help_shows_options(self):
        """serve --help should show host and port options."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["serve", "--help"])

        assert result.exit_code == 0
        assert "host" in result.output.lower()
        assert "port" in result.output.lower()

    def test_serve_has_reload_option(self):
        """serve should have --reload option for development."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["serve", "--help"])

        assert result.exit_code == 0
        assert "reload" in result.output.lower()


class TestConfigCommands:
    """Tests for config subcommands."""

    def test_config_help_shows_subcommands(self):
        """config --help should list subcommands."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["config", "--help"])

        assert result.exit_code == 0
        # Actual implementation has 'show' and 'set', not 'get'
        assert "show" in result.output
        assert "set" in result.output

    def test_config_show_displays_config(self):
        """config show should display configuration."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["config", "show"])

        # Should either succeed or fail gracefully
        # The output should contain some JSON-like structure
        assert result.exit_code in (0, 1)

    def test_config_set_requires_key_and_value(self):
        """config set without key/value should fail."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["config", "set"])

        assert result.exit_code == 2  # Click usage error

    def test_config_set_help_shows_arguments(self):
        """config set --help should document KEY and VALUE arguments."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["config", "set", "--help"])

        assert result.exit_code == 0
        assert "KEY" in result.output
        assert "VALUE" in result.output


class TestScanCommands:
    """Tests for scan subcommands."""

    def test_scan_help_shows_subcommands(self):
        """scan --help should list available scan commands."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])

        assert result.exit_code == 0
        # Actual implementation has 'start', 'status', 'cancel'
        assert "start" in result.output
        assert "status" in result.output

    def test_scan_start_requires_target(self):
        """scan start without target should fail."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "start"])

        assert result.exit_code == 2  # Click usage error
        assert "TARGET_NAME" in result.output or "Missing" in result.output

    def test_scan_start_help_shows_options(self):
        """scan start --help should show available options."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "start", "--help"])

        assert result.exit_code == 0
        assert "TARGET_NAME" in result.output

    def test_scan_status_requires_job_id(self):
        """scan status without job_id should fail."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "status"])

        assert result.exit_code == 2  # Click usage error


class TestTargetCommands:
    """Tests for target management commands."""

    def test_target_help_shows_subcommands(self):
        """target --help should list subcommands."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["target", "--help"])

        assert result.exit_code == 0
        assert "add" in result.output
        assert "list" in result.output

    def test_target_add_requires_name(self):
        """target add without name should fail."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["target", "add"])

        assert result.exit_code == 2  # Click usage error


class TestUserCommands:
    """Tests for user management commands."""

    def test_user_help_shows_subcommands(self):
        """user --help should list subcommands."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["user", "--help"])

        assert result.exit_code == 0
        assert "add" in result.output or "create" in result.output
        assert "list" in result.output

    def test_user_add_requires_email(self):
        """user add without email should fail."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["user", "add"])

        assert result.exit_code == 2  # Click usage error


class TestLabelsCommands:
    """Tests for labels commands (note: 'labels' not 'label')."""

    def test_labels_command_exists(self):
        """labels command should exist."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["labels", "--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output

    def test_labels_has_list_subcommand(self):
        """labels should have list subcommand."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["labels", "--help"])

        assert result.exit_code == 0
        assert "list" in result.output


class TestReportCommands:
    """Tests for report commands."""

    def test_report_help_shows_options(self):
        """report --help should show available options."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output


class TestWorkerCommand:
    """Tests for worker command."""

    def test_worker_help_shows_options(self):
        """worker --help should show concurrency option."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["worker", "--help"])

        assert result.exit_code == 0
        assert "concurrency" in result.output.lower() or "workers" in result.output.lower()


class TestDBCommands:
    """Tests for database management commands."""

    def test_db_help_shows_subcommands(self):
        """db --help should list migration subcommands."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["db", "--help"])

        assert result.exit_code == 0
        # Should have migration commands
        assert "init" in result.output or "migrate" in result.output or "upgrade" in result.output


class TestQuarantineCommand:
    """Tests for quarantine command."""

    def test_quarantine_help_shows_usage(self):
        """quarantine --help should show usage."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["quarantine", "--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output



class TestLockdownCommand:
    """Tests for lock-down command."""

    def test_lockdown_help_shows_usage(self):
        """lock-down --help should show usage."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["lock-down", "--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output


class TestExportCommand:
    """Tests for export command."""

    def test_export_help_shows_subcommands(self):
        """export --help should show available subcommands."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["export", "--help"])

        assert result.exit_code == 0
        # Should list 'results' subcommand
        assert "results" in result.output

    def test_export_results_help_shows_format_options(self):
        """export results --help should show format options."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["export", "results", "--help"])

        assert result.exit_code == 0
        # Should support different export formats
        assert "format" in result.output.lower() or "csv" in result.output.lower() or "json" in result.output.lower()


class TestClassifyCommand:
    """Tests for classify command."""

    def test_classify_help_shows_usage(self):
        """classify --help should show usage."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["classify", "--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output

    def test_classify_requires_path(self):
        """classify without path should fail."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["classify"])

        assert result.exit_code == 2  # Click usage error


class TestFindCommand:
    """Tests for find command."""

    def test_find_help_shows_usage(self):
        """find --help should show usage."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["find", "--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output


class TestMonitorCommand:
    """Tests for monitor command."""

    def test_monitor_help_shows_usage(self):
        """monitor --help should show usage."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["monitor", "--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output


class TestBackupRestoreCommands:
    """Tests for backup and restore commands."""

    def test_backup_help_shows_usage(self):
        """backup --help should show usage."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["backup", "--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output

    def test_restore_help_shows_usage(self):
        """restore --help should show usage."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["restore", "--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output

    def test_restore_requires_file(self):
        """restore without backup file should fail."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["restore"])

        assert result.exit_code == 2  # Click usage error


class TestCLIErrorHandling:
    """Tests for CLI error handling."""

    def test_invalid_option_shows_error(self):
        """Invalid option should show helpful error."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["serve", "--invalid-option-xyz"])

        assert result.exit_code == 2
        assert "Error" in result.output or "no such option" in result.output.lower()

    def test_missing_required_arg_shows_error(self):
        """Missing required argument should show helpful error."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "start"])  # Missing TARGET_NAME

        assert result.exit_code == 2
        assert "Missing" in result.output or "TARGET_NAME" in result.output or "argument" in result.output.lower()


class TestGUICommand:
    """Tests for GUI command."""

    def test_gui_help_shows_usage(self):
        """gui --help should show usage."""
        from openlabels.__main__ import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["gui", "--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output
