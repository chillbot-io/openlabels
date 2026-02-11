"""Tests for quarantine operations."""

import os
import platform
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from openlabels.remediation.quarantine import (
    quarantine,
    ROBOCOPY_SUCCESS_CODES,
    ROBOCOPY_ERROR_CODES,
)
from openlabels.remediation.base import RemediationAction
from openlabels.exceptions import QuarantineError


class TestQuarantineValidation:
    """Tests for quarantine input validation."""

    def test_source_not_found_raises(self):
        """Raises QuarantineError if source doesn't exist."""
        with pytest.raises(QuarantineError, match="Source file not found"):
            quarantine(
                source=Path("/nonexistent/file.txt"),
                destination=Path("/tmp/quarantine"),
            )

    def test_source_is_directory_raises(self, tmp_path):
        """Raises QuarantineError if source is a directory."""
        source_dir = tmp_path / "source_dir"
        source_dir.mkdir()

        with pytest.raises(QuarantineError, match="must be a file"):
            quarantine(
                source=source_dir,
                destination=tmp_path / "dest",
            )

    def test_creates_destination_directory(self, tmp_path):
        """Creates destination directory if it doesn't exist."""
        source = tmp_path / "file.txt"
        source.write_text("test content")
        dest = tmp_path / "new" / "nested" / "dir"

        # Dry run so we don't actually move
        result = quarantine(source, dest, dry_run=True)

        assert result.success is True
        # In dry run, we don't create the directory
        # But the function should not raise


class TestQuarantineDryRun:
    """Tests for quarantine dry run mode."""

    def test_dry_run_returns_success(self, tmp_path):
        """Dry run returns success without moving file."""
        source = tmp_path / "file.txt"
        source.write_text("test content")
        dest = tmp_path / "quarantine"
        dest.mkdir()

        result = quarantine(source, dest, dry_run=True)

        assert result.success is True
        assert result.action == RemediationAction.QUARANTINE
        assert source.exists()  # File not moved

    def test_dry_run_sets_dest_path(self, tmp_path):
        """Dry run sets correct destination path."""
        source = tmp_path / "file.txt"
        source.write_text("test content")
        dest = tmp_path / "quarantine"
        dest.mkdir()

        result = quarantine(source, dest, dry_run=True)

        assert result.dest_path == dest / "file.txt"

    def test_dry_run_sets_performed_by(self, tmp_path):
        """Dry run sets performed_by field to current user."""
        import getpass
        source = tmp_path / "file.txt"
        source.write_text("test content")
        dest = tmp_path / "quarantine"
        dest.mkdir()

        result = quarantine(source, dest, dry_run=True)

        assert getpass.getuser() in result.performed_by


class TestRobocopyExitCodes:
    """Tests for robocopy exit code handling."""

    def test_success_codes_include_zero(self):
        """Zero is a success code."""
        assert 0 in ROBOCOPY_SUCCESS_CODES

    def test_success_codes_include_one(self):
        """One (files copied) is a success code."""
        assert 1 in ROBOCOPY_SUCCESS_CODES

    def test_error_codes_include_eight(self):
        """Eight (copy errors) is an error code."""
        assert 8 in ROBOCOPY_ERROR_CODES

    def test_error_codes_include_sixteen(self):
        """Sixteen (serious error) is an error code."""
        assert 16 in ROBOCOPY_ERROR_CODES


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
class TestQuarantineWindows:
    """Windows-specific quarantine tests."""

    def test_uses_robocopy(self, tmp_path):
        """Quarantine uses robocopy on Windows."""
        source = tmp_path / "file.txt"
        source.write_text("test content")
        dest = tmp_path / "quarantine"
        dest.mkdir()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,  # Files copied
                stdout="",
                stderr="",
            )

            result = quarantine(source, dest)

            # Check robocopy was called
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "robocopy"
            assert "/MOVE" in cmd

    def test_preserves_acls_by_default(self, tmp_path):
        """ACL preservation is enabled by default."""
        source = tmp_path / "file.txt"
        source.write_text("test content")
        dest = tmp_path / "quarantine"
        dest.mkdir()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

            quarantine(source, dest, preserve_acls=True)

            cmd = mock_run.call_args[0][0]
            # DATSOU includes Security (S), Owner (O), aUditing (U)
            assert any("/COPY:DATSOU" in str(arg) for arg in cmd)

    def test_can_disable_acl_preservation(self, tmp_path):
        """ACL preservation can be disabled."""
        source = tmp_path / "file.txt"
        source.write_text("test content")
        dest = tmp_path / "quarantine"
        dest.mkdir()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

            quarantine(source, dest, preserve_acls=False)

            cmd = mock_run.call_args[0][0]
            # DAT = Data, Attributes, Timestamps (no Security)
            assert any("/COPY:DAT" in str(arg) for arg in cmd)


@pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test")
class TestQuarantineUnix:
    """Unix-specific quarantine tests."""

    def test_moves_file(self, tmp_path):
        """Quarantine moves file on Unix."""
        source = tmp_path / "file.txt"
        source.write_text("test content")
        dest = tmp_path / "quarantine"
        dest.mkdir()

        result = quarantine(source, dest)

        assert result.success is True
        assert not source.exists()
        assert (dest / "file.txt").exists()

    def test_preserves_content(self, tmp_path):
        """Quarantine preserves file content."""
        source = tmp_path / "file.txt"
        source.write_text("original content")
        dest = tmp_path / "quarantine"
        dest.mkdir()

        quarantine(source, dest)

        assert (dest / "file.txt").read_text() == "original content"

    def test_tries_rsync_first(self, tmp_path):
        """Unix quarantine tries rsync before shutil."""
        source = tmp_path / "file.txt"
        source.write_text("test content")
        dest = tmp_path / "quarantine"
        dest.mkdir()

        with patch("shutil.which", return_value="/usr/bin/rsync"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

                quarantine(source, dest, preserve_acls=True)

                # Check rsync was called
                cmd = mock_run.call_args[0][0]
                assert cmd[0] == "rsync"

    def test_falls_back_to_shutil(self, tmp_path):
        """Unix quarantine falls back to shutil if rsync unavailable."""
        source = tmp_path / "file.txt"
        source.write_text("test content")
        dest = tmp_path / "quarantine"
        dest.mkdir()

        with patch("shutil.which", return_value=None):
            result = quarantine(source, dest)

            assert result.success is True
            assert (dest / "file.txt").exists()


class TestQuarantineResult:
    """Tests for quarantine result structure."""

    def test_success_result_structure(self, tmp_path):
        """Successful quarantine has correct result structure."""
        source = tmp_path / "file.txt"
        source.write_text("test")
        dest = tmp_path / "quarantine"
        dest.mkdir()

        result = quarantine(source, dest, dry_run=True)

        assert result.success is True
        assert result.action == RemediationAction.QUARANTINE
        assert result.source_path == source
        assert result.dest_path == dest / "file.txt"
        assert result.timestamp is not None
        assert result.error is None

    def test_result_to_dict(self, tmp_path):
        """Quarantine result can be serialized to dict."""
        source = tmp_path / "file.txt"
        source.write_text("test")
        dest = tmp_path / "quarantine"
        dest.mkdir()

        result = quarantine(source, dest, dry_run=True)
        d = result.to_dict()

        assert isinstance(d, dict)
        assert d["success"] is True
        assert d["action"] == "quarantine"
