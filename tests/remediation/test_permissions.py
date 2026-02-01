"""Tests for permission lockdown operations."""

import platform
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from openlabels.remediation.permissions import (
    lock_down,
    get_current_acl,
    DEFAULT_WINDOWS_PRINCIPALS,
    DEFAULT_UNIX_PRINCIPALS,
)
from openlabels.remediation.base import RemediationAction


class TestLockDownValidation:
    """Tests for lock_down input validation."""

    def test_file_not_found_raises(self):
        """Raises FileNotFoundError if file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            lock_down(Path("/nonexistent/file.txt"))


class TestLockDownDefaults:
    """Tests for lock_down default values."""

    def test_default_windows_principals(self):
        """Default Windows principals includes Administrators."""
        assert "BUILTIN\\Administrators" in DEFAULT_WINDOWS_PRINCIPALS

    def test_default_unix_principals(self):
        """Default Unix principals includes root."""
        assert "root" in DEFAULT_UNIX_PRINCIPALS


class TestLockDownDryRun:
    """Tests for lock_down dry run mode."""

    def test_dry_run_returns_success(self, tmp_path):
        """Dry run returns success without changing permissions."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test content")

        result = lock_down(test_file, dry_run=True)

        assert result.success is True
        assert result.action == RemediationAction.LOCKDOWN

    def test_dry_run_sets_principals(self, tmp_path):
        """Dry run sets correct principals."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test content")

        result = lock_down(
            test_file,
            allowed_principals=["TestGroup"],
            dry_run=True,
        )

        assert result.principals == ["TestGroup"]

    def test_dry_run_captures_previous_acl(self, tmp_path):
        """Dry run captures previous ACL."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test content")

        result = lock_down(test_file, backup_acl=True, dry_run=True)

        # previous_acl should be set (base64 encoded)
        assert result.previous_acl is not None


class TestGetCurrentAcl:
    """Tests for get_current_acl function."""

    def test_file_not_found_raises(self):
        """Raises FileNotFoundError if file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            get_current_acl(Path("/nonexistent/file.txt"))

    def test_returns_dict(self, tmp_path):
        """Returns a dictionary with ACL info."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test content")

        acl = get_current_acl(test_file)

        assert isinstance(acl, dict)
        assert "path" in acl

    @pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific")
    def test_unix_acl_includes_mode(self, tmp_path):
        """Unix ACL includes file mode."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test content")

        acl = get_current_acl(test_file)

        assert "mode" in acl
        assert "uid" in acl
        assert "gid" in acl


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
class TestLockDownWindows:
    """Windows-specific lock_down tests."""

    def test_uses_icacls(self, tmp_path):
        """Lock down uses icacls on Windows."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test content")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            lock_down(test_file)

            # Check icacls was called
            calls = mock_run.call_args_list
            commands = [call[0][0][0] for call in calls]
            assert "icacls" in commands

    def test_resets_permissions(self, tmp_path):
        """Lock down resets existing permissions."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test content")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            lock_down(test_file)

            # Check /reset was called
            all_args = [str(arg) for call in mock_run.call_args_list for arg in call[0][0]]
            assert "/reset" in all_args

    def test_grants_to_specified_principals(self, tmp_path):
        """Lock down grants access to specified principals."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test content")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            lock_down(test_file, allowed_principals=["BUILTIN\\Administrators"])

            # Check /grant:r was called with the principal
            all_args = " ".join(str(arg) for call in mock_run.call_args_list for arg in call[0][0])
            assert "/grant:r" in all_args
            assert "Administrators" in all_args

    def test_disables_inheritance(self, tmp_path):
        """Lock down disables inheritance when requested."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test content")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            lock_down(test_file, remove_inheritance=True)

            # Check /inheritance:d was called
            all_args = " ".join(str(arg) for call in mock_run.call_args_list for arg in call[0][0])
            assert "/inheritance:d" in all_args


@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test")
class TestLockDownUnix:
    """Unix-specific lock_down tests."""

    def test_sets_restrictive_mode(self, tmp_path):
        """Lock down sets restrictive file mode."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test content")
        test_file.chmod(0o644)  # Start with permissive

        result = lock_down(test_file)

        assert result.success is True
        # File should now be owner-only
        import stat
        mode = test_file.stat().st_mode
        assert not (mode & stat.S_IROTH)  # Not world-readable
        assert not (mode & stat.S_IRGRP)  # Not group-readable

    def test_uses_setfacl_if_available(self, tmp_path):
        """Uses setfacl for ACL manipulation if available."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test content")

        with patch("shutil.which", return_value="/usr/bin/setfacl"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

                lock_down(test_file, allowed_principals=["testuser"])

                # Check setfacl was called
                commands = [call[0][0][0] for call in mock_run.call_args_list]
                assert "setfacl" in commands


class TestLockDownResult:
    """Tests for lock_down result structure."""

    def test_success_result_structure(self, tmp_path):
        """Successful lock_down has correct result structure."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        result = lock_down(test_file, dry_run=True)

        assert result.success is True
        assert result.action == RemediationAction.LOCKDOWN
        assert result.source_path == test_file
        assert result.principals is not None
        assert result.timestamp is not None

    def test_captures_previous_acl(self, tmp_path):
        """Lock down captures previous ACL for rollback."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        result = lock_down(test_file, backup_acl=True, dry_run=True)

        assert result.previous_acl is not None
        # Should be base64 encoded
        import base64
        decoded = base64.b64decode(result.previous_acl)
        assert len(decoded) > 0

    def test_result_to_dict(self, tmp_path):
        """Lock down result can be serialized to dict."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        result = lock_down(test_file, dry_run=True)
        d = result.to_dict()

        assert isinstance(d, dict)
        assert d["success"] is True
        assert d["action"] == "lockdown"
