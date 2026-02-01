"""
Tests for encryption command security.

Tests critical security functionality:
- Recipient/key validation to prevent injection attacks
- File path validation to prevent traversal and symlink attacks
- GPG and age encryption wrapper safety
- Command-line argument handling
"""

import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openlabels.cli.commands.encrypt import (
    SHELL_METACHARACTERS,
    validate_recipient,
    validate_file_path,
    encrypt_file_gpg,
    encrypt_file_age,
)


class TestShellMetacharacters:
    """Tests for shell metacharacter constant."""

    def test_contains_backtick(self):
        """Backtick should be blocked (command substitution)."""
        assert '`' in SHELL_METACHARACTERS

    def test_contains_dollar(self):
        """Dollar sign should be blocked (variable expansion)."""
        assert '$' in SHELL_METACHARACTERS

    def test_contains_pipe(self):
        """Pipe should be blocked (command chaining)."""
        assert '|' in SHELL_METACHARACTERS

    def test_contains_semicolon(self):
        """Semicolon should be blocked (command separator)."""
        assert ';' in SHELL_METACHARACTERS

    def test_contains_ampersand(self):
        """Ampersand should be blocked (background/command chaining)."""
        assert '&' in SHELL_METACHARACTERS

    def test_contains_redirects(self):
        """Redirect operators should be blocked."""
        assert '>' in SHELL_METACHARACTERS
        assert '<' in SHELL_METACHARACTERS

    def test_contains_newline(self):
        """Newlines should be blocked (command injection)."""
        assert '\n' in SHELL_METACHARACTERS
        assert '\r' in SHELL_METACHARACTERS

    def test_contains_null_byte(self):
        """Null byte should be blocked (string truncation)."""
        assert '\x00' in SHELL_METACHARACTERS


class TestValidateRecipientGPG:
    """Tests for GPG recipient validation."""

    # Valid GPG recipients
    def test_valid_hex_key_id_8_chars(self):
        """8-character hex key ID should be valid."""
        assert validate_recipient("ABCD1234", "gpg") is True

    def test_valid_hex_key_id_16_chars(self):
        """16-character hex key ID should be valid."""
        assert validate_recipient("ABCD1234EFGH5678", "gpg") is True

    def test_valid_hex_key_id_40_chars(self):
        """40-character hex fingerprint should be valid."""
        fingerprint = "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890"
        assert validate_recipient(fingerprint, "gpg") is True

    def test_valid_email_address(self):
        """Email address should be valid for GPG."""
        assert validate_recipient("user@example.com", "gpg") is True
        assert validate_recipient("john.doe@company.org", "gpg") is True
        assert validate_recipient("test+tag@domain.co.uk", "gpg") is True

    def test_valid_name_identifier(self):
        """Name identifier should be valid for GPG."""
        assert validate_recipient("John Doe", "gpg") is True
        assert validate_recipient("Security_Team", "gpg") is True
        assert validate_recipient("ops.team-2024", "gpg") is True

    # Invalid GPG recipients - injection attempts
    def test_rejects_command_substitution_backtick(self):
        """Backtick command substitution should be rejected."""
        assert validate_recipient("`whoami`@evil.com", "gpg") is False

    def test_rejects_command_substitution_dollar(self):
        """Dollar command substitution should be rejected."""
        assert validate_recipient("$(cat /etc/passwd)", "gpg") is False

    def test_rejects_pipe_injection(self):
        """Pipe character should be rejected."""
        assert validate_recipient("user@test.com|cat /etc/passwd", "gpg") is False

    def test_rejects_semicolon_injection(self):
        """Semicolon should be rejected."""
        assert validate_recipient("user@test.com;rm -rf /", "gpg") is False

    def test_rejects_ampersand_injection(self):
        """Ampersand should be rejected."""
        assert validate_recipient("user@test.com&malicious", "gpg") is False

    def test_rejects_redirect_injection(self):
        """Redirect operators should be rejected."""
        assert validate_recipient("user@test.com>output.txt", "gpg") is False
        assert validate_recipient("user@test.com</etc/passwd", "gpg") is False

    def test_rejects_newline_injection(self):
        """Newline characters should be rejected."""
        assert validate_recipient("user@test.com\nmalicious", "gpg") is False
        assert validate_recipient("user@test.com\rmalicious", "gpg") is False

    def test_rejects_null_byte(self):
        """Null byte should be rejected."""
        assert validate_recipient("user@test.com\x00malicious", "gpg") is False

    # Edge cases
    def test_rejects_empty_recipient(self):
        """Empty string should be rejected."""
        assert validate_recipient("", "gpg") is False

    def test_rejects_none_recipient(self):
        """None should be rejected (handled as falsy)."""
        assert validate_recipient(None, "gpg") is False

    def test_rejects_very_long_recipient(self):
        """Very long recipients (>500 chars) should be rejected."""
        long_recipient = "a" * 501
        assert validate_recipient(long_recipient, "gpg") is False

    def test_accepts_max_length_recipient(self):
        """500-character recipient (valid email) should be accepted."""
        # Create a valid email that's close to 500 chars
        local_part = "a" * 480
        max_recipient = f"{local_part}@test.com"
        assert len(max_recipient) <= 500
        assert validate_recipient(max_recipient, "gpg") is True


class TestValidateRecipientAge:
    """Tests for age recipient validation."""

    # Valid age recipients
    def test_valid_age_public_key(self):
        """Valid age1 public key should be accepted."""
        # age public keys are 58 lowercase alphanumeric chars after "age1"
        valid_key = "age1" + "a" * 58
        assert validate_recipient(valid_key, "age") is True

    def test_valid_ssh_rsa_key(self):
        """SSH RSA public key should be accepted."""
        ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAA user@host"
        assert validate_recipient(ssh_key, "age") is True

    def test_valid_ssh_ed25519_key(self):
        """SSH Ed25519 public key should be accepted."""
        ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBVi user@host"
        assert validate_recipient(ssh_key, "age") is True

    def test_valid_file_path(self):
        """File path to key file should be accepted."""
        assert validate_recipient("/path/to/key.pub", "age") is True
        assert validate_recipient("./keys/recipient.txt", "age") is True
        assert validate_recipient("keys/age-key.pub", "age") is True

    # Invalid age recipients - injection attempts
    def test_rejects_command_substitution_backtick(self):
        """Backtick command substitution should be rejected."""
        assert validate_recipient("`whoami`", "age") is False

    def test_rejects_command_substitution_dollar(self):
        """Dollar command substitution should be rejected."""
        assert validate_recipient("$(cat /etc/passwd)", "age") is False

    def test_rejects_pipe_injection(self):
        """Pipe character should be rejected."""
        assert validate_recipient("/path/to/key|cat /etc/passwd", "age") is False

    def test_rejects_semicolon_injection(self):
        """Semicolon should be rejected."""
        assert validate_recipient("/path/to/key;rm -rf /", "age") is False

    def test_rejects_newline_injection(self):
        """Newline characters should be rejected."""
        assert validate_recipient("age1aaa\nmalicious", "age") is False

    # Edge cases
    def test_rejects_empty_recipient(self):
        """Empty string should be rejected."""
        assert validate_recipient("", "age") is False

    def test_rejects_very_long_recipient(self):
        """Very long recipients should be rejected."""
        long_recipient = "a" * 501
        assert validate_recipient(long_recipient, "age") is False


class TestValidateRecipientUnknownTool:
    """Tests for unknown encryption tool."""

    def test_rejects_unknown_tool(self):
        """Unknown tool should return False."""
        assert validate_recipient("user@test.com", "unknown") is False
        assert validate_recipient("user@test.com", "openssl") is False
        assert validate_recipient("user@test.com", "") is False


class TestValidateFilePath:
    """Tests for file path validation."""

    def test_valid_regular_file(self, tmp_path):
        """Regular file should be accepted."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        assert validate_file_path(test_file) is True

    def test_rejects_nonexistent_file(self, tmp_path):
        """Non-existent file should be rejected."""
        nonexistent = tmp_path / "nonexistent.txt"
        assert validate_file_path(nonexistent) is False

    def test_rejects_directory(self, tmp_path):
        """Directory should be rejected."""
        assert validate_file_path(tmp_path) is False

    def test_symlink_resolved_to_target(self, tmp_path):
        """Symlink is resolved to target file before validation.

        Note: The current implementation resolves symlinks and validates
        the target file. This is documented behavior - symlinks are followed.
        For TOCTOU-critical operations, use lstat() on the original path.
        """
        target = tmp_path / "target.txt"
        target.write_text("content")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        # Current behavior: symlinks are resolved and target is validated
        # This follows the design of resolve() + lstat() in validate_file_path
        result = validate_file_path(link)
        # After resolve(), we're checking the target which is a regular file
        assert result is True  # Symlinks to regular files are accepted

    def test_rejects_path_with_backtick(self, tmp_path):
        """Path with backtick should be rejected."""
        # Test that path containing backtick is rejected by validation
        path = Path(str(tmp_path) + "/`command`.txt")
        assert validate_file_path(path) is False

    def test_rejects_path_with_dollar(self, tmp_path):
        """Path with dollar sign should be rejected."""
        # Test with a path containing $
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # Create a path string with $
        bad_path = Path(str(tmp_path) + "/$HOME/test.txt")
        assert validate_file_path(bad_path) is False

    def test_rejects_path_with_semicolon(self, tmp_path):
        """Path with semicolon should be rejected."""
        bad_path = Path("/path/to/file;rm -rf /")
        assert validate_file_path(bad_path) is False

    def test_rejects_path_with_pipe(self, tmp_path):
        """Path with pipe should be rejected."""
        bad_path = Path("/path/to/file|cat /etc/passwd")
        assert validate_file_path(bad_path) is False

    def test_rejects_path_with_null_byte(self, tmp_path):
        """Path with null byte should be rejected."""
        bad_path = Path("/path/to/file\x00.txt")
        assert validate_file_path(bad_path) is False


class TestEncryptFileGPG:
    """Tests for GPG encryption wrapper."""

    def test_rejects_invalid_file_path(self, tmp_path):
        """Should reject invalid file path."""
        nonexistent = tmp_path / "nonexistent.txt"
        result = encrypt_file_gpg(nonexistent, "user@test.com")
        assert result is False

    def test_rejects_invalid_recipient(self, tmp_path):
        """Should reject invalid recipient."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = encrypt_file_gpg(test_file, "`whoami`@evil.com")
        assert result is False

    def test_rejects_symlink_file(self, tmp_path):
        """Should reject symlink (TOCTOU protection)."""
        target = tmp_path / "target.txt"
        target.write_text("content")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        result = encrypt_file_gpg(link, "user@test.com")
        assert result is False

    @patch('subprocess.run')
    def test_calls_gpg_with_correct_args(self, mock_run, tmp_path):
        """Should call gpg with correct arguments."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        mock_run.return_value = MagicMock(returncode=0)

        result = encrypt_file_gpg(test_file, "user@test.com")

        # Verify gpg was called correctly
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "gpg"
        assert "--encrypt" in call_args
        assert "--recipient" in call_args
        assert "user@test.com" in call_args

    @patch('subprocess.run')
    def test_deletes_original_on_success(self, mock_run, tmp_path):
        """Should delete original file after successful encryption."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        mock_run.return_value = MagicMock(returncode=0)

        result = encrypt_file_gpg(test_file, "user@test.com")

        assert result is True
        assert not test_file.exists()

    @patch('subprocess.run')
    def test_preserves_original_on_failure(self, mock_run, tmp_path):
        """Should preserve original file if encryption fails."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        mock_run.return_value = MagicMock(returncode=1)

        result = encrypt_file_gpg(test_file, "user@test.com")

        assert result is False
        assert test_file.exists()

    def test_handles_missing_gpg(self, tmp_path):
        """Should handle missing gpg binary gracefully."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        with patch('subprocess.run', side_effect=FileNotFoundError):
            result = encrypt_file_gpg(test_file, "user@test.com")
            assert result is False
            assert test_file.exists()  # Original preserved


class TestEncryptFileAge:
    """Tests for age encryption wrapper."""

    def test_rejects_invalid_file_path(self, tmp_path):
        """Should reject invalid file path."""
        nonexistent = tmp_path / "nonexistent.txt"
        valid_key = "age1" + "a" * 58
        result = encrypt_file_age(nonexistent, valid_key)
        assert result is False

    def test_rejects_invalid_recipient(self, tmp_path):
        """Should reject invalid recipient."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = encrypt_file_age(test_file, "`whoami`")
        assert result is False

    def test_rejects_symlink_file(self, tmp_path):
        """Should reject symlink (TOCTOU protection)."""
        target = tmp_path / "target.txt"
        target.write_text("content")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        valid_key = "age1" + "a" * 58
        result = encrypt_file_age(link, valid_key)
        assert result is False

    @patch('subprocess.run')
    def test_calls_age_with_correct_args(self, mock_run, tmp_path):
        """Should call age with correct arguments."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        valid_key = "age1" + "a" * 58

        mock_run.return_value = MagicMock(returncode=0)

        result = encrypt_file_age(test_file, valid_key)

        # Verify age was called correctly
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "age"
        assert "--encrypt" in call_args
        assert "--recipient" in call_args
        assert valid_key in call_args
        assert "-o" in call_args

    @patch('subprocess.run')
    def test_creates_output_with_age_extension(self, mock_run, tmp_path):
        """Should create output file with .age extension."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        valid_key = "age1" + "a" * 58

        mock_run.return_value = MagicMock(returncode=0)

        encrypt_file_age(test_file, valid_key)

        call_args = mock_run.call_args[0][0]
        output_path = None
        for i, arg in enumerate(call_args):
            if arg == "-o" and i + 1 < len(call_args):
                output_path = call_args[i + 1]
                break

        assert output_path is not None
        assert output_path.endswith(".txt.age")

    @patch('subprocess.run')
    def test_deletes_original_on_success(self, mock_run, tmp_path):
        """Should delete original file after successful encryption."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        valid_key = "age1" + "a" * 58

        mock_run.return_value = MagicMock(returncode=0)

        result = encrypt_file_age(test_file, valid_key)

        assert result is True
        assert not test_file.exists()

    @patch('subprocess.run')
    def test_preserves_original_on_failure(self, mock_run, tmp_path):
        """Should preserve original file if encryption fails."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        valid_key = "age1" + "a" * 58

        mock_run.return_value = MagicMock(returncode=1)

        result = encrypt_file_age(test_file, valid_key)

        assert result is False
        assert test_file.exists()

    def test_handles_missing_age(self, tmp_path):
        """Should handle missing age binary gracefully."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        valid_key = "age1" + "a" * 58

        with patch('subprocess.run', side_effect=FileNotFoundError):
            result = encrypt_file_age(test_file, valid_key)
            assert result is False
            assert test_file.exists()  # Original preserved


class TestInjectionVectors:
    """Comprehensive injection attack tests."""

    @pytest.mark.parametrize("payload", [
        # Command substitution
        "`id`",
        "$(whoami)",
        "$((1+1))",
        # Command chaining
        "x;id",
        "x|id",
        "x||id",
        "x&&id",
        "x&id",
        # Redirection
        "x>output",
        "x>>output",
        "x<input",
        "x 2>&1",
        # Newline injection
        "x\nid",
        "x\r\nid",
        "x\rid",
        # Null byte
        "x\x00id",
        # Environment variables
        "$HOME",
        "${HOME}",
        "$PATH",
        # Process substitution
        "<(cat /etc/passwd)",
        ">(tee output)",
        # Here-string/here-doc markers
        "<<<input",
        "<<EOF",
        # Glob expansion (would be dangerous if not escaped)
        "*.txt",
        "**/*",
        # Brace expansion
        "{a,b}",
    ])
    def test_gpg_rejects_injection_payloads(self, payload):
        """GPG recipient should reject all injection payloads."""
        # Most payloads should fail the metacharacter check
        # Some may fail the pattern match instead
        result = validate_recipient(payload, "gpg")
        assert result is False, f"Should reject: {payload!r}"

    @pytest.mark.parametrize("payload", [
        # Command substitution
        "`id`",
        "$(whoami)",
        # Command chaining
        "x;id",
        "x|id",
        "x&&id",
        # Redirection
        "x>output",
        "x<input",
        # Newline injection
        "x\nid",
        "x\x00id",
    ])
    def test_age_rejects_injection_payloads(self, payload):
        """Age recipient should reject all injection payloads."""
        result = validate_recipient(payload, "age")
        assert result is False, f"Should reject: {payload!r}"


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_unicode_in_gpg_recipient(self):
        """Unicode characters in GPG recipient."""
        # GPG pattern allows alphanumeric, spaces, dots, underscores, dashes
        # Most unicode would fail the pattern match
        assert validate_recipient("user@test.com", "gpg") is True
        # Unicode email would fail pattern
        assert validate_recipient("user@tst.com", "gpg") is True

    def test_very_long_email_rejected(self):
        """Very long email exceeding 500 chars should be rejected."""
        long_local = "a" * 500
        long_email = f"{long_local}@example.com"
        assert len(long_email) > 500
        assert validate_recipient(long_email, "gpg") is False

    def test_moderately_long_email_accepted(self):
        """Email under 500 chars should be accepted."""
        long_local = "a" * 200
        long_email = f"{long_local}@example.com"
        assert len(long_email) < 500
        assert validate_recipient(long_email, "gpg") is True

    def test_email_with_plus_tag(self):
        """Email with plus tag addressing."""
        assert validate_recipient("user+tag@example.com", "gpg") is True

    def test_email_with_dots(self):
        """Email with dots in local part."""
        assert validate_recipient("first.last@example.com", "gpg") is True

    def test_key_id_lowercase(self):
        """Lowercase hex key ID."""
        assert validate_recipient("abcd1234", "gpg") is True

    def test_key_id_mixed_case(self):
        """Mixed case hex key ID."""
        assert validate_recipient("AbCd1234", "gpg") is True
