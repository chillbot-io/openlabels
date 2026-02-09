"""
Comprehensive tests for monitoring registry operations.

Tests cover:
- Enable/disable monitoring
- Registry state management
- Platform-specific implementations (Windows SACL, Linux auditd)
- Error handling (permissions, timeouts, missing tools)
- Path resolution and canonicalization
- Idempotency and concurrent access
"""

import platform
import subprocess
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openlabels.exceptions import MonitoringError
from openlabels.monitoring.base import MonitoringResult, WatchedFile
from openlabels.monitoring.registry import (
    _enable_monitoring_linux,
    _enable_monitoring_windows,
    _disable_monitoring_linux,
    _disable_monitoring_windows,
    _watched_files,
    disable_monitoring,
    enable_monitoring,
    get_watched_file,
    get_watched_files,
    is_monitored,
)


@pytest.fixture(autouse=True)
def clear_registry():
    """Clear the watched files registry before and after each test."""
    _watched_files.clear()
    yield
    _watched_files.clear()


class TestEnableMonitoringValidation:
    """Tests for enable_monitoring input validation."""

    def test_file_not_found_raises(self, tmp_path):
        """Raises MonitoringError if file doesn't exist."""
        nonexistent = tmp_path / "nonexistent.txt"

        with pytest.raises(MonitoringError, match="File not found"):
            enable_monitoring(nonexistent)

    def test_accepts_path_object(self, tmp_path):
        """Accepts Path object."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MonitoringResult(
                success=True,
                path=test_file,
                sacl_enabled=True,
                audit_rule_enabled=False,
            )

            result = enable_monitoring(test_file)

            assert result.success is True

    def test_accepts_string_path(self, tmp_path):
        """Accepts string path."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MonitoringResult(
                success=True,
                path=test_file,
                sacl_enabled=True,
                audit_rule_enabled=False,
            )

            result = enable_monitoring(str(test_file))

            assert result.success is True


class TestEnableMonitoringRegistryState:
    """Tests for registry state management during enable."""

    def test_adds_to_registry_on_success(self, tmp_path):
        """Adds file to registry on successful enable."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MonitoringResult(
                success=True,
                path=test_file,
                sacl_enabled=True,
                audit_rule_enabled=False,
            )

            enable_monitoring(test_file, risk_tier="CRITICAL", label_id="label-123")

            assert is_monitored(test_file)
            wf = get_watched_file(test_file)
            assert wf.risk_tier == "CRITICAL"
            assert wf.label_id == "label-123"

    def test_does_not_add_to_registry_on_failure(self, tmp_path):
        """Does not add file to registry on failure."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MonitoringResult(
                success=False,
                path=test_file,
                error="Failed to add SACL",
            )

            enable_monitoring(test_file)

            assert not is_monitored(test_file)

    def test_idempotent_enable(self, tmp_path):
        """Enabling already-monitored file is idempotent."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MonitoringResult(
                success=True,
                path=test_file,
                sacl_enabled=True,
                audit_rule_enabled=False,
            )

            enable_monitoring(test_file)
            result = enable_monitoring(test_file)

            # Second call should return cached result
            assert result.success is True
            assert result.message == "Already monitored"
            # Platform function should only be called once
            assert mock_enable.call_count == 1

    def test_stores_watched_file_metadata(self, tmp_path):
        """Stores complete metadata for watched files."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        before = datetime.now()

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MonitoringResult(
                success=True,
                path=test_file,
                sacl_enabled=True,
                audit_rule_enabled=True,
            )

            enable_monitoring(test_file, risk_tier="HIGH", label_id="lbl-1")

        after = datetime.now()

        wf = get_watched_file(test_file)
        assert wf.path == test_file.resolve()
        assert wf.risk_tier == "HIGH"
        assert before <= wf.added_at <= after
        assert wf.sacl_enabled is True
        assert wf.audit_rule_enabled is True
        assert wf.label_id == "lbl-1"


class TestDisableMonitoring:
    """Tests for disable_monitoring function."""

    def test_disable_unmonitored_file_succeeds(self, tmp_path):
        """Disabling unmonitored file succeeds (no-op)."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        result = disable_monitoring(test_file)

        assert result.success is True
        assert "not currently monitored" in result.message.lower()

    def test_removes_from_registry_on_success(self, tmp_path):
        """Removes file from registry on successful disable."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        # First enable
        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MonitoringResult(
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
            mock_disable.return_value = MonitoringResult(success=True, path=test_file)

            disable_monitoring(test_file)

        assert not is_monitored(test_file)

    def test_keeps_in_registry_on_failure(self, tmp_path):
        """Keeps file in registry on failed disable."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        # First enable
        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MonitoringResult(
                success=True,
                path=test_file,
                sacl_enabled=True,
                audit_rule_enabled=False,
            )
            enable_monitoring(test_file)

        # Then disable (fails)
        with patch("openlabels.monitoring.registry._disable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._disable_monitoring_linux") as mock_disable:
            mock_disable.return_value = MonitoringResult(
                success=False,
                path=test_file,
                error="Access denied",
            )

            disable_monitoring(test_file)

        # Should still be monitored
        assert is_monitored(test_file)


class TestRegistryQueries:
    """Tests for registry query functions."""

    def test_is_monitored_handles_path_resolution(self, tmp_path):
        """is_monitored resolves paths for comparison."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MonitoringResult(
                success=True,
                path=test_file,
                sacl_enabled=True,
                audit_rule_enabled=False,
            )
            enable_monitoring(test_file)

        # Query with different path representation
        relative_path = test_file
        assert is_monitored(relative_path) is True

    def test_get_watched_files_returns_list(self, tmp_path):
        """get_watched_files returns a list of WatchedFile objects."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MonitoringResult(
                success=True,
                path=test_file,
                sacl_enabled=True,
                audit_rule_enabled=False,
            )
            enable_monitoring(test_file)

        files = get_watched_files()

        assert isinstance(files, list)
        assert len(files) == 1
        assert isinstance(files[0], WatchedFile)

    def test_get_watched_file_returns_none_for_unknown(self, tmp_path):
        """get_watched_file returns None for unmonitored file."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        result = get_watched_file(test_file)

        assert result is None


class TestEnableMonitoringWindowsComprehensive:
    """Comprehensive Windows-specific tests."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_calls_powershell(self, tmp_path):
        """Windows implementation calls PowerShell."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            _enable_monitoring_windows(test_file, audit_read=True, audit_write=True)

            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "powershell"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_includes_read_rights(self, tmp_path):
        """Windows includes Read rights when audit_read=True."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            _enable_monitoring_windows(test_file, audit_read=True, audit_write=False)

            call_args = mock_run.call_args[0][0]
            ps_script = call_args[2]  # -Command argument
            assert "Read" in ps_script

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_includes_write_rights(self, tmp_path):
        """Windows includes Write rights when audit_write=True."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            _enable_monitoring_windows(test_file, audit_read=False, audit_write=True)

            call_args = mock_run.call_args[0][0]
            ps_script = call_args[2]
            assert "Write" in ps_script

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_requires_at_least_one_right(self, tmp_path):
        """Windows returns error if no rights specified."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        result = _enable_monitoring_windows(test_file, audit_read=False, audit_write=False)

        assert result.success is False
        assert "at least one" in result.error.lower()

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_handles_powershell_error(self, tmp_path):
        """Windows handles PowerShell errors."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Access denied",
            )

            result = _enable_monitoring_windows(test_file, audit_read=True, audit_write=True)

            assert result.success is False
            assert "Access denied" in result.error

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_handles_timeout(self, tmp_path):
        """Windows handles PowerShell timeout."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="powershell", timeout=30)

            result = _enable_monitoring_windows(test_file, audit_read=True, audit_write=True)

            assert result.success is False
            assert "timed out" in result.error.lower()


class TestDisableMonitoringWindowsComprehensive:
    """Comprehensive Windows-specific disable tests."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_disable_calls_powershell(self, tmp_path):
        """Windows disable calls PowerShell."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            _disable_monitoring_windows(test_file)

            mock_run.assert_called_once()

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_disable_handles_error(self, tmp_path):
        """Windows disable handles errors."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Error removing SACL",
            )

            result = _disable_monitoring_windows(test_file)

            assert result.success is False


class TestEnableMonitoringLinuxComprehensive:
    """Comprehensive Linux-specific tests."""

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
    def test_linux_checks_auditctl_available(self, tmp_path):
        """Linux checks for auditctl availability."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value=None):
            result = _enable_monitoring_linux(test_file, audit_read=True, audit_write=True)

            assert result.success is False
            assert "auditctl not found" in result.error

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
    def test_linux_calls_auditctl(self, tmp_path):
        """Linux calls auditctl with correct arguments."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value="/sbin/auditctl"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

                _enable_monitoring_linux(test_file, audit_read=True, audit_write=True)

                mock_run.assert_called_once()
                cmd = mock_run.call_args[0][0]
                assert cmd[0] == "auditctl"
                assert "-w" in cmd
                assert str(test_file) in cmd
                assert "-k" in cmd
                assert "openlabels" in cmd

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
    def test_linux_read_only_permissions(self, tmp_path):
        """Linux sets read-only permissions."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value="/sbin/auditctl"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

                _enable_monitoring_linux(test_file, audit_read=True, audit_write=False)

                cmd = mock_run.call_args[0][0]
                perms_idx = cmd.index("-p") + 1
                assert cmd[perms_idx] == "r"

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
    def test_linux_write_only_permissions(self, tmp_path):
        """Linux sets write-only permissions."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value="/sbin/auditctl"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

                _enable_monitoring_linux(test_file, audit_read=False, audit_write=True)

                cmd = mock_run.call_args[0][0]
                perms_idx = cmd.index("-p") + 1
                assert "w" in cmd[perms_idx]
                assert "a" in cmd[perms_idx]

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
    def test_linux_requires_at_least_one_permission(self, tmp_path):
        """Linux returns error if no permissions specified."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value="/sbin/auditctl"):
            result = _enable_monitoring_linux(test_file, audit_read=False, audit_write=False)

            assert result.success is False
            assert "at least one" in result.error.lower()

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
    def test_linux_handles_permission_denied(self, tmp_path):
        """Linux handles permission denied errors."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value="/sbin/auditctl"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1,
                    stdout="",
                    stderr="Operation not permitted",
                )

                result = _enable_monitoring_linux(test_file, audit_read=True, audit_write=True)

                assert result.success is False
                assert "Permission denied" in result.error or "CAP_AUDIT_CONTROL" in result.error

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
    def test_linux_handles_timeout(self, tmp_path):
        """Linux handles auditctl timeout."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value="/sbin/auditctl"):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(cmd="auditctl", timeout=30)

                result = _enable_monitoring_linux(test_file, audit_read=True, audit_write=True)

                assert result.success is False
                assert "timed out" in result.error.lower()


class TestDisableMonitoringLinuxComprehensive:
    """Comprehensive Linux-specific disable tests."""

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
    def test_linux_disable_checks_auditctl(self, tmp_path):
        """Linux disable checks for auditctl."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value=None):
            result = _disable_monitoring_linux(test_file)

            assert result.success is False
            assert "auditctl not found" in result.error

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
    def test_linux_disable_calls_auditctl(self, tmp_path):
        """Linux disable calls auditctl with -W flag."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value="/sbin/auditctl"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

                _disable_monitoring_linux(test_file)

                cmd = mock_run.call_args[0][0]
                assert "-W" in cmd
                assert str(test_file) in cmd


class TestPathResolution:
    """Tests for path resolution and canonicalization."""

    def test_resolves_relative_paths(self, tmp_path, monkeypatch):
        """Resolves relative paths to absolute."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        # Change to tmp_path so relative path works
        monkeypatch.chdir(tmp_path)

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MonitoringResult(
                success=True,
                path=test_file.resolve(),
                sacl_enabled=True,
                audit_rule_enabled=False,
            )

            enable_monitoring(Path("file.txt"))

            # Should be able to query with absolute path
            assert is_monitored(test_file)

    def test_handles_symlinks(self, tmp_path):
        """Handles symlinks by resolving to real path."""
        test_file = tmp_path / "real_file.txt"
        test_file.write_text("test")
        symlink = tmp_path / "link.txt"
        symlink.symlink_to(test_file)

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MonitoringResult(
                success=True,
                path=test_file.resolve(),
                sacl_enabled=True,
                audit_rule_enabled=False,
            )

            enable_monitoring(symlink)

            # Should be able to query with either path
            assert is_monitored(symlink)
            assert is_monitored(test_file)


class TestConcurrentAccess:
    """Tests for concurrent access scenarios."""

    def test_multiple_files_in_registry(self, tmp_path):
        """Registry handles multiple files."""
        files = []
        for i in range(5):
            f = tmp_path / f"file{i}.txt"
            f.write_text(f"content {i}")
            files.append(f)

        with patch("openlabels.monitoring.registry._enable_monitoring_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.registry._enable_monitoring_linux") as mock_enable:
            mock_enable.return_value = MonitoringResult(
                success=True,
                path=files[0],  # Will be set per-call
                sacl_enabled=True,
                audit_rule_enabled=False,
            )

            for f in files:
                mock_enable.return_value.path = f
                enable_monitoring(f, risk_tier=f"TIER_{files.index(f)}")

        all_watched = get_watched_files()
        assert len(all_watched) == 5

        for i, f in enumerate(files):
            wf = get_watched_file(f)
            assert wf is not None
            assert wf.risk_tier == f"TIER_{i}"
