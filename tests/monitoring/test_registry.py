"""Tests for monitoring registry operations."""

import platform
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from openlabels.monitoring.registry import (
    enable_monitoring,
    disable_monitoring,
    is_monitored,
    get_watched_files,
    get_watched_file,
    _watched_files,
)
from openlabels.exceptions import MonitoringError


@pytest.fixture(autouse=True)
def clear_registry():
    """Clear the watched files registry before each test."""
    _watched_files.clear()
    yield
    _watched_files.clear()


class TestEnableMonitoringValidation:
    """Tests for enable_monitoring input validation."""

    def test_file_not_found_raises(self):
        """Raises MonitoringError if file doesn't exist."""
        with pytest.raises(MonitoringError, match="File not found"):
            enable_monitoring(Path("/nonexistent/file.txt"))


class TestEnableMonitoringBasic:
    """Basic tests for enable_monitoring."""

    def test_returns_monitoring_result(self, tmp_path):
        """Returns a MonitoringResult."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MagicMock(
                success=True,
                path=test_file,
                sacl_enabled=True,
                audit_rule_enabled=False,
            )

            result = enable_monitoring(test_file)

            # Verify result has expected structure and values
            assert result.success is True
            assert result.path == test_file

    def test_adds_to_registry_on_success(self, tmp_path):
        """Adds file to registry on successful enable."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MagicMock(
                success=True,
                path=test_file,
                sacl_enabled=True,
                audit_rule_enabled=False,
            )

            enable_monitoring(test_file, risk_tier="CRITICAL")

            assert is_monitored(test_file)
            wf = get_watched_file(test_file)
            assert wf.risk_tier == "CRITICAL"

    def test_idempotent_enable(self, tmp_path):
        """Enabling already-monitored file is idempotent."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MagicMock(
                success=True,
                path=test_file,
                sacl_enabled=True,
                audit_rule_enabled=False,
            )

            enable_monitoring(test_file)
            result = enable_monitoring(test_file)

            assert result.success is True
            assert result.message == "Already monitored"
            # Platform function should only be called once
            assert mock_enable.call_count == 1


class TestDisableMonitoring:
    """Tests for disable_monitoring."""

    def test_disable_unmonitored_file(self, tmp_path):
        """Disabling unmonitored file succeeds (no-op)."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        result = disable_monitoring(test_file)

        assert result.success is True
        assert "not currently monitored" in result.message.lower()

    def test_removes_from_registry(self, tmp_path):
        """Removes file from registry on disable."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        # First enable
        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MagicMock(
                success=True,
                path=test_file,
                sacl_enabled=True,
                audit_rule_enabled=False,
            )
            enable_monitoring(test_file)

        assert is_monitored(test_file)

        # Then disable
        with patch("openlabels.monitoring.registry._disable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._disable_monitoring_linux") as mock_disable:
            mock_disable.return_value = MagicMock(success=True, path=test_file)

            disable_monitoring(test_file)

        assert not is_monitored(test_file)


class TestRegistryQueries:
    """Tests for registry query functions."""

    def test_is_monitored_false_initially(self, tmp_path):
        """is_monitored returns False for unmonitored files."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        assert is_monitored(test_file) is False

    def test_get_watched_files_empty(self):
        """get_watched_files returns empty list initially."""
        files = get_watched_files()
        assert files == []

    def test_get_watched_files_returns_all(self, tmp_path):
        """get_watched_files returns all monitored files."""
        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"
        file1.write_text("test1")
        file2.write_text("test2")

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MagicMock(
                success=True,
                sacl_enabled=True,
                audit_rule_enabled=False,
            )
            mock_enable.return_value.path = file1

            enable_monitoring(file1)

            mock_enable.return_value.path = file2
            enable_monitoring(file2)

        files = get_watched_files()
        assert len(files) == 2

    def test_get_watched_file_not_found(self, tmp_path):
        """get_watched_file returns None for unmonitored file."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        wf = get_watched_file(test_file)
        assert wf is None


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
class TestEnableMonitoringWindows:
    """Windows-specific enable_monitoring tests."""

    def test_uses_powershell(self, tmp_path):
        """Uses PowerShell to add SACL on Windows."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            enable_monitoring(test_file)

            mock_run.assert_called()
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "powershell"


@pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
class TestEnableMonitoringLinux:
    """Linux-specific enable_monitoring tests."""

    def test_uses_auditctl(self, tmp_path):
        """Uses auditctl to add audit rule on Linux."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value="/sbin/auditctl"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

                enable_monitoring(test_file)

                mock_run.assert_called()
                cmd = mock_run.call_args[0][0]
                assert cmd[0] == "auditctl"

    def test_auditctl_not_found(self, tmp_path):
        """Returns error if auditctl not found."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value=None):
            result = enable_monitoring(test_file)

            assert result.success is False
            assert "auditctl not found" in result.error
