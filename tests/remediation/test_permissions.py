"""Tests for permission lockdown operations."""

import platform
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openlabels.exceptions import RemediationPermissionError
from openlabels.remediation.base import RemediationAction
from openlabels.remediation.permissions import (
    DEFAULT_UNIX_PRINCIPALS,
    DEFAULT_WINDOWS_PRINCIPALS,
    get_current_acl,
    lock_down,
    validate_principal_name,
)


class TestLockDownValidation:
    """Tests for lock_down input validation."""

    def test_file_not_found_raises(self):
        """Raises RemediationPermissionError if file doesn't exist."""
        with pytest.raises(RemediationPermissionError, match="File not found"):
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
        """Dry run captures previous ACL as base64."""
        import base64
        test_file = tmp_path / "file.txt"
        test_file.write_text("test content")

        result = lock_down(test_file, backup_acl=True, dry_run=True)

        # previous_acl should be set and valid base64
        assert result.previous_acl is not None
        decoded = base64.b64decode(result.previous_acl)
        assert len(decoded) > 0


class TestGetCurrentAcl:
    """Tests for get_current_acl function."""

    def test_file_not_found_raises(self):
        """Raises RemediationPermissionError if file doesn't exist."""
        with pytest.raises(RemediationPermissionError, match="File not found"):
            get_current_acl(Path("/nonexistent/file.txt"))

    def test_returns_dict(self, tmp_path):
        """Returns a dictionary with ACL info including the file path."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test content")

        acl = get_current_acl(test_file)

        assert acl["path"] == str(test_file)

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
        assert len(result.principals) > 0
        assert result.error is None

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


# ============================================================================
# Command injection prevention tests
# ============================================================================


class TestValidatePrincipalName:
    """Tests for validate_principal_name input validation."""

    # --- Valid principals ---

    def test_simple_username(self):
        """Simple alphanumeric username passes."""
        assert validate_principal_name("admin") == "admin"

    def test_domain_backslash_user(self):
        """DOMAIN\\user format passes."""
        assert validate_principal_name("BUILTIN\\Administrators") == "BUILTIN\\Administrators"

    def test_email_format(self):
        """user@domain.com format passes."""
        assert validate_principal_name("user@domain.com") == "user@domain.com"

    def test_username_with_dot(self):
        """Username with dots passes."""
        assert validate_principal_name("john.doe") == "john.doe"

    def test_username_with_hyphen(self):
        """Username with hyphens passes."""
        assert validate_principal_name("john-doe") == "john-doe"

    def test_username_with_underscore(self):
        """Username with underscores passes."""
        assert validate_principal_name("john_doe") == "john_doe"

    def test_root_principal(self):
        """Root principal passes."""
        assert validate_principal_name("root") == "root"

    def test_windows_builtin_users(self):
        """BUILTIN\\Users format passes."""
        assert validate_principal_name("BUILTIN\\Users") == "BUILTIN\\Users"

    def test_principal_with_space(self):
        """Principal name with spaces passes (e.g., 'Authenticated Users')."""
        assert validate_principal_name("Authenticated Users") == "Authenticated Users"

    def test_principal_with_forward_slash(self):
        """Forward slash in principal passes (e.g., group paths)."""
        assert validate_principal_name("domain/group") == "domain/group"

    def test_strips_whitespace(self):
        """Leading/trailing whitespace is stripped."""
        assert validate_principal_name("  admin  ") == "admin"

    # --- Command injection attempts ---

    def test_semicolon_injection_rejected(self):
        """Semicolon command separator is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("admin; rm -rf /")

    def test_pipe_injection_rejected(self):
        """Pipe operator is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("admin | cat /etc/passwd")

    def test_backtick_injection_rejected(self):
        """Backtick command substitution is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("`whoami`")

    def test_dollar_paren_injection_rejected(self):
        """$() command substitution is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("$(cat /etc/passwd)")

    def test_ampersand_injection_rejected(self):
        """Ampersand background operator is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("admin & rm -rf /")

    def test_newline_injection_rejected(self):
        """Newline character is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("admin\nrm -rf /")

    def test_tab_injection_rejected(self):
        """Tab character is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("admin\trm")

    def test_greater_than_redirect_rejected(self):
        """Output redirect > is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("admin > /tmp/evil")

    def test_less_than_redirect_rejected(self):
        """Input redirect < is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("admin < /etc/passwd")

    def test_dollar_sign_rejected(self):
        """Dollar sign (variable expansion) is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("$USER")

    def test_single_quote_rejected(self):
        """Single quote is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("admin'--")

    def test_double_quote_rejected(self):
        """Double quote is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name('admin"--')

    def test_hash_comment_rejected(self):
        """Hash (shell comment) is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("admin #comment")

    def test_exclamation_mark_rejected(self):
        """Exclamation mark (history expansion) is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("admin!!")

    # --- Edge cases ---

    def test_empty_string_rejected(self):
        """Empty string is rejected."""
        with pytest.raises(RemediationPermissionError, match="empty"):
            validate_principal_name("")

    def test_whitespace_only_rejected(self):
        """Whitespace-only string is rejected."""
        with pytest.raises(RemediationPermissionError, match="empty"):
            validate_principal_name("   ")

    def test_null_byte_rejected(self):
        """Null byte is rejected."""
        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            validate_principal_name("admin\x00evil")

    def test_very_long_name_rejected(self):
        """Extremely long principal name is rejected."""
        with pytest.raises(RemediationPermissionError, match="maximum length"):
            validate_principal_name("a" * 300)

    def test_max_length_accepted(self):
        """Principal name at exactly max length passes."""
        name = "a" * 256
        assert validate_principal_name(name) == name

    def test_one_over_max_length_rejected(self):
        """Principal name one char over max length is rejected."""
        with pytest.raises(RemediationPermissionError, match="maximum length"):
            validate_principal_name("a" * 257)


class TestLockDownCommandInjectionPrevention:
    """Tests that lock_down rejects malicious principal names."""

    def test_lock_down_rejects_semicolon_principal(self, tmp_path):
        """lock_down rejects principal with command injection via semicolon."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            lock_down(
                test_file,
                allowed_principals=["admin; rm -rf /"],
                dry_run=True,
            )

    def test_lock_down_rejects_backtick_principal(self, tmp_path):
        """lock_down rejects principal with backtick injection."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            lock_down(
                test_file,
                allowed_principals=["`cat /etc/shadow`"],
                dry_run=True,
            )

    def test_lock_down_rejects_pipe_principal(self, tmp_path):
        """lock_down rejects principal with pipe injection."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            lock_down(
                test_file,
                allowed_principals=["user | cat /etc/passwd"],
                dry_run=True,
            )

    def test_lock_down_accepts_valid_principal(self, tmp_path):
        """lock_down accepts valid principal names."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        result = lock_down(
            test_file,
            allowed_principals=["BUILTIN\\Administrators"],
            dry_run=True,
        )
        assert result.success is True

    def test_lock_down_validates_all_principals_in_list(self, tmp_path):
        """lock_down validates every principal in the list, not just the first."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with pytest.raises(RemediationPermissionError, match="invalid characters"):
            lock_down(
                test_file,
                allowed_principals=["ValidUser", "evil;rm -rf /"],
                dry_run=True,
            )

    def test_lock_down_default_principals_are_valid(self, tmp_path):
        """Default principals pass validation (no injection risk)."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        # Should not raise - default principals are safe
        result = lock_down(test_file, dry_run=True)
        assert result.success is True
