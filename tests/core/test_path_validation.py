"""Tests for path validation security module.

Covers:
- Path traversal attack vectors (../../, symlinks, encoded slashes)
- Null byte injection prevention
- System directory blocking
- Sensitive file pattern blocking
- Edge cases (empty paths, Unicode, whitespace)
"""

import os
import pytest
from pathlib import Path

from openlabels.core.path_validation import (
    PathValidationError,
    validate_path,
    validate_output_path,
    _check_blocked_paths,
    _check_blocked_patterns,
    BLOCKED_PATH_PREFIXES,
    BLOCKED_FILE_PATTERNS,
)


class TestValidatePathBasic:
    """Basic validation tests for validate_path."""

    def test_empty_path_raises(self):
        """Empty string is rejected."""
        with pytest.raises(PathValidationError, match="File path is required"):
            validate_path("")

    def test_none_path_raises(self):
        """None is rejected (not a string)."""
        with pytest.raises(PathValidationError):
            validate_path(None)

    def test_non_string_raises(self):
        """Non-string types are rejected."""
        with pytest.raises(PathValidationError, match="must be a string"):
            validate_path(12345)

    def test_valid_absolute_path(self, tmp_path):
        """Valid absolute path passes validation."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        result = validate_path(str(test_file))
        assert result == str(test_file.resolve())

    def test_valid_relative_path(self, tmp_path, monkeypatch):
        """Valid relative path is converted to absolute when allowed."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        monkeypatch.chdir(tmp_path)
        result = validate_path("test.txt", allow_relative=True)
        assert os.path.isabs(result)

    def test_relative_path_rejected_when_disallowed(self):
        """Relative path raises when allow_relative=False."""
        with pytest.raises(PathValidationError, match="must be absolute"):
            validate_path("relative/path.txt", allow_relative=False)

    def test_require_exists_raises_for_missing(self):
        """require_exists=True raises for nonexistent file."""
        with pytest.raises(PathValidationError, match="does not exist"):
            validate_path("/tmp/nonexistent_file_xyz.txt", require_exists=True)

    def test_require_exists_passes_for_existing(self, tmp_path):
        """require_exists=True passes for an existing file."""
        test_file = tmp_path / "exists.txt"
        test_file.write_text("hello")
        result = validate_path(str(test_file), require_exists=True)
        assert result == str(test_file.resolve())

    def test_require_parent_exists_raises(self):
        """require_parent_exists=True raises when parent doesn't exist."""
        with pytest.raises(PathValidationError, match="Parent directory does not exist"):
            validate_path(
                "/tmp/nonexistent_parent_xyz/child.txt",
                require_parent_exists=True,
            )

    def test_require_parent_exists_passes(self, tmp_path):
        """require_parent_exists=True passes when parent exists."""
        result = validate_path(
            str(tmp_path / "new_file.txt"),
            require_parent_exists=True,
        )
        assert os.path.dirname(result) == str(tmp_path.resolve())


class TestNullByteInjection:
    """Tests for null byte injection prevention."""

    def test_null_byte_in_path_raises(self):
        """Path containing null byte is rejected."""
        with pytest.raises(PathValidationError, match="null bytes"):
            validate_path("/tmp/file.pdf\x00.txt")

    def test_null_byte_at_start_raises(self):
        """Null byte at start of path is rejected."""
        with pytest.raises(PathValidationError, match="null bytes"):
            validate_path("\x00/tmp/file.txt")

    def test_null_byte_at_end_raises(self):
        """Null byte at end of path is rejected."""
        with pytest.raises(PathValidationError, match="null bytes"):
            validate_path("/tmp/file.txt\x00")

    def test_embedded_null_byte_raises(self):
        """Null byte embedded in directory name is rejected."""
        with pytest.raises(PathValidationError, match="null bytes"):
            validate_path("/tmp/dir\x00name/file.txt")


class TestPathTraversalAttacks:
    """Tests for path traversal attack prevention."""

    def test_dot_dot_slash_raises(self):
        """Simple ../../../etc/passwd is rejected."""
        with pytest.raises(PathValidationError, match="traversal"):
            validate_path("/tmp/../../../etc/passwd")

    def test_dot_dot_in_middle_raises(self):
        """Path with .. in the middle is rejected."""
        with pytest.raises(PathValidationError, match="traversal"):
            validate_path("/home/user/../admin/secret.txt")

    def test_multiple_dot_dot_raises(self):
        """Multiple .. components are rejected."""
        with pytest.raises(PathValidationError, match="traversal"):
            validate_path("/data/files/../../etc/shadow")

    def test_dot_dot_backslash_raises(self):
        """Windows-style traversal with backslash and .. is rejected."""
        with pytest.raises(PathValidationError, match="traversal"):
            validate_path("C:\\data\\..\\..\\Windows\\System32")

    def test_encoded_dot_dot_in_literal_path(self):
        """Literal %2e%2e in path (not URL-decoded) is treated as-is.

        Path validation works on filesystem paths, not URLs. The literal
        string '%2e%2e' does NOT contain '..' so it would not trigger the
        traversal check directly. The important thing is that the resolved
        path is still checked against blocked prefixes.
        """
        # This is a literal filename, not URL-encoded traversal
        # validate_path should not crash
        try:
            result = validate_path("/tmp/%2e%2e/file.txt")
            # If it returns, the path was considered safe (it's literally /tmp/%2e%2e/file.txt)
            assert ".." not in result  # resolved path should not have ..
        except PathValidationError:
            # Also acceptable - it might be blocked for other reasons
            pass

    def test_single_dot_does_not_raise(self, tmp_path, monkeypatch):
        """Single dot (current directory) should not trigger traversal."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("content")
        monkeypatch.chdir(tmp_path)
        # Single dots are fine, only ".." is path traversal
        result = validate_path(str(tmp_path / "." / "file.txt"))
        assert os.path.isabs(result)


class TestBlockedSystemDirectories:
    """Tests for system directory blocking."""

    @pytest.mark.parametrize("blocked_path", [
        "/etc/passwd",
        "/etc/shadow",
        "/var/log/auth.log",
        "/usr/bin/python3",
        "/bin/sh",
        "/sbin/init",
        "/root/.bashrc",
        "/proc/1/environ",
        "/sys/kernel/debug",
        "/dev/sda",
        "/boot/vmlinuz",
    ])
    def test_unix_system_paths_blocked(self, blocked_path):
        """Unix system directories are blocked."""
        with pytest.raises(PathValidationError, match="system directories"):
            validate_path(blocked_path)

    @pytest.mark.parametrize("blocked_path", [
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Program Files\\app.exe",
        "C:\\Program Files (x86)\\app.exe",
        "C:\\ProgramData\\secrets",
    ])
    def test_windows_system_paths_blocked(self, blocked_path):
        """Windows system directories are blocked."""
        with pytest.raises(PathValidationError, match="system directories"):
            validate_path(blocked_path)

    def test_case_insensitive_blocking(self):
        """System path blocking is case-insensitive."""
        with pytest.raises(PathValidationError, match="system directories"):
            validate_path("/ETC/passwd")

    def test_non_system_path_allowed(self, tmp_path):
        """Non-system paths pass validation."""
        test_file = tmp_path / "safe_file.txt"
        test_file.write_text("safe")
        result = validate_path(str(test_file))
        assert result == str(test_file.resolve())


class TestBlockedFilePatterns:
    """Tests for sensitive file pattern blocking."""

    @pytest.mark.parametrize("sensitive_path", [
        "/home/user/.env",
        "/home/user/project/.env",
        "/home/user/.git/config",
        "/home/user/.ssh/id_rsa",
        "/home/user/.ssh/id_ed25519",
        "/home/user/.htpasswd",
    ])
    def test_sensitive_files_blocked(self, sensitive_path):
        """Known sensitive file patterns are blocked."""
        with pytest.raises(PathValidationError, match="file type is not allowed"):
            validate_path(sensitive_path)

    def test_credentials_pattern_blocked(self):
        """Files with 'credentials' in path are blocked."""
        with pytest.raises(PathValidationError, match="file type is not allowed"):
            validate_path("/home/user/credentials.json")

    def test_normal_file_allowed(self, tmp_path):
        """Normal files pass pattern checks."""
        test_file = tmp_path / "report.pdf"
        test_file.write_text("content")
        result = validate_path(str(test_file))
        assert "report.pdf" in result


class TestCheckBlockedPaths:
    """Direct tests for _check_blocked_paths helper."""

    def test_all_prefixes_are_blocked(self):
        """Every prefix in BLOCKED_PATH_PREFIXES blocks matching paths."""
        for prefix in BLOCKED_PATH_PREFIXES:
            test_path = prefix + "testfile"
            with pytest.raises(PathValidationError):
                _check_blocked_paths(test_path)

    def test_non_blocked_path_passes(self):
        """Paths not matching blocked prefixes pass."""
        _check_blocked_paths("/home/user/documents/file.txt")
        # Should not raise

    def test_case_insensitive(self):
        """Blocking is case-insensitive."""
        with pytest.raises(PathValidationError):
            _check_blocked_paths("/ETC/PASSWD")


class TestCheckBlockedPatterns:
    """Direct tests for _check_blocked_patterns helper."""

    def test_all_patterns_are_blocked(self):
        """Every pattern in BLOCKED_FILE_PATTERNS blocks matching paths."""
        for pattern in BLOCKED_FILE_PATTERNS:
            test_path = f"/home/user/{pattern}"
            with pytest.raises(PathValidationError):
                _check_blocked_patterns(test_path)

    def test_backslash_normalization(self):
        """Windows-style backslashes are normalized for pattern matching."""
        with pytest.raises(PathValidationError):
            _check_blocked_patterns("C:\\Users\\admin\\.git\\config")


class TestValidateOutputPath:
    """Tests for validate_output_path."""

    def test_valid_output_path(self, tmp_path):
        """Valid output path passes validation."""
        result = validate_output_path(str(tmp_path / "output.csv"))
        assert "output.csv" in result

    def test_directory_as_output_raises(self, tmp_path):
        """Directory path as output raises error."""
        with pytest.raises(PathValidationError, match="is a directory"):
            validate_output_path(str(tmp_path))

    def test_nonexistent_parent_raises(self):
        """Output with nonexistent parent raises by default."""
        with pytest.raises(PathValidationError, match="does not exist"):
            validate_output_path("/tmp/nonexistent_parent_xyz/output.txt")

    def test_create_parent_creates_dir(self, tmp_path):
        """create_parent=True creates the parent directory."""
        new_dir = tmp_path / "new_subdir"
        result = validate_output_path(
            str(new_dir / "output.txt"),
            create_parent=True,
        )
        assert new_dir.exists()
        assert "output.txt" in result

    def test_existing_file_passes_with_warning(self, tmp_path):
        """Existing file path passes (will be overwritten)."""
        existing = tmp_path / "existing.txt"
        existing.write_text("old content")
        result = validate_output_path(str(existing))
        assert result == str(existing.resolve())

    def test_output_path_blocked_for_system_dirs(self):
        """Output paths to system directories are blocked."""
        with pytest.raises(PathValidationError, match="system directories"):
            validate_output_path("/etc/malicious_output.txt")

    def test_output_path_traversal_blocked(self):
        """Path traversal in output path is blocked."""
        with pytest.raises(PathValidationError, match="traversal"):
            validate_output_path("/tmp/../etc/malicious.txt")


class TestEdgeCases:
    """Edge cases and unusual inputs."""

    def test_unicode_path(self, tmp_path):
        """Unicode characters in path are handled."""
        unicode_file = tmp_path / "file_\u00e9\u00e8\u00ea.txt"
        unicode_file.write_text("content")
        result = validate_path(str(unicode_file))
        assert os.path.isabs(result)

    def test_very_long_path(self, tmp_path):
        """Very long paths are handled gracefully."""
        # Build a long path (most OSes limit to ~4096 chars)
        long_name = "a" * 200
        long_path = str(tmp_path / long_name / "file.txt")
        # Should not crash - may raise PathValidationError or return
        try:
            validate_path(long_path)
        except PathValidationError:
            pass  # Expected for nonexistent deep paths

    def test_whitespace_only_path(self):
        """Whitespace-only path is handled."""
        # Whitespace paths can be valid filesystem names in some OS
        # but they should at least not crash the validator
        try:
            result = validate_path("   ")
            # If it returns, it was normalized to some valid path
            assert isinstance(result, str)
        except PathValidationError:
            pass  # Also acceptable

    def test_symlink_resolution(self, tmp_path):
        """Symlinks are resolved to their real targets."""
        real_file = tmp_path / "real.txt"
        real_file.write_text("content")
        link_path = tmp_path / "link.txt"
        link_path.symlink_to(real_file)

        result = validate_path(str(link_path))
        # Should resolve to the real file
        assert result == str(real_file.resolve())

    def test_path_with_spaces(self, tmp_path):
        """Paths with spaces are handled."""
        spaced_dir = tmp_path / "my documents"
        spaced_dir.mkdir()
        spaced_file = spaced_dir / "my file.txt"
        spaced_file.write_text("content")

        result = validate_path(str(spaced_file))
        assert result == str(spaced_file.resolve())

    def test_returns_canonicalized_path(self, tmp_path):
        """Returned path is fully canonicalized (no symlinks, no ./)."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        # Use a path with redundant ./
        input_path = str(tmp_path / "." / "test.txt")
        result = validate_path(input_path)
        assert "/." not in result
        assert result == str(test_file.resolve())
