"""Tests for quarantine operations."""

import json
import os
import platform
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from openlabels.remediation.quarantine import (
    quarantine,
    restore_from_quarantine,
    ROBOCOPY_SUCCESS_CODES,
    ROBOCOPY_ERROR_CODES,
)
from openlabels.remediation.base import RemediationAction
from openlabels.remediation.manifest import QuarantineEntry, QuarantineManifest
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


# ============================================================================
# Path traversal prevention tests for restore_from_quarantine
# ============================================================================


class TestRestoreFromQuarantinePathTraversal:
    """Tests for path traversal prevention in restore_from_quarantine."""

    def _make_manifest(self, tmp_path, entries=None, allowed_bases=None):
        """Helper to create a QuarantineManifest with given entries."""
        manifest_path = tmp_path / "manifest.json"
        if entries:
            data = {"entries": entries}
            manifest_path.write_text(json.dumps(data))
        if allowed_bases is None:
            allowed_bases = [tmp_path]
        return QuarantineManifest(manifest_path, allowed_bases=allowed_bases)

    def test_valid_restore_succeeds(self, tmp_path):
        """Restore with valid paths within expected directories succeeds."""
        # Set up quarantine directory structure
        quarantine_dir = tmp_path / "quarantine"
        quarantine_dir.mkdir()
        quarantined_file = quarantine_dir / "file.txt"
        quarantined_file.write_text("quarantined content")

        original_dir = tmp_path / "data"
        original_dir.mkdir()

        entry_data = {
            "id": "test-entry-1",
            "original_path": str(original_dir / "file.txt"),
            "quarantine_path": str(quarantined_file),
            "quarantined_at": "2025-01-01T00:00:00",
            "reason": "test",
            "risk_tier": "HIGH",
            "triggered_by": "test",
            "file_hash": None,
        }

        manifest = self._make_manifest(tmp_path, entries=[entry_data])
        result = restore_from_quarantine(
            "test-entry-1",
            manifest,
            verify_hash=False,
            quarantine_base=quarantine_dir,
        )
        assert result.success is True

    def test_quarantine_path_traversal_rejected(self, tmp_path):
        """Quarantine path outside quarantine base is rejected."""
        quarantine_dir = tmp_path / "quarantine"
        quarantine_dir.mkdir()

        # Attacker tries to reference a file outside quarantine directory
        evil_file = tmp_path / "evil.txt"
        evil_file.write_text("evil content")

        entry_data = {
            "id": "evil-entry",
            "original_path": str(tmp_path / "data" / "file.txt"),
            "quarantine_path": str(tmp_path / "quarantine" / ".." / "evil.txt"),
            "quarantined_at": "2025-01-01T00:00:00",
            "reason": "test",
            "risk_tier": "HIGH",
            "triggered_by": "test",
            "file_hash": None,
        }

        manifest = self._make_manifest(tmp_path, entries=[entry_data])
        result = restore_from_quarantine(
            "evil-entry",
            manifest,
            verify_hash=False,
            quarantine_base=quarantine_dir,
        )
        assert result.success is False
        assert "Security error" in result.error
        assert "quarantine path" in result.error

    def test_original_path_traversal_rejected(self, tmp_path):
        """Original path outside allowed bases is rejected at restore time.

        The manifest uses a broad allowed_bases (root /) to load the entry,
        but restore_from_quarantine uses a narrower manifest validation that
        we simulate by providing a manifest with restricted allowed_bases.
        """
        quarantine_dir = tmp_path / "quarantine"
        quarantine_dir.mkdir()
        quarantined_file = quarantine_dir / "file.txt"
        quarantined_file.write_text("quarantined content")

        # The original_path targets a location outside the expected data dir.
        # Use a path under tmp_path so the manifest loads the entry (allowed_bases
        # includes tmp_path), then reconfigure the manifest's allowed_bases to be
        # stricter for the restore validation.
        evil_original = str(tmp_path / "outside" / "evil.txt")
        entry_data = {
            "id": "evil-entry-2",
            "original_path": evil_original,
            "quarantine_path": str(quarantined_file),
            "quarantined_at": "2025-01-01T00:00:00",
            "reason": "test",
            "risk_tier": "HIGH",
            "triggered_by": "test",
            "file_hash": None,
        }

        # Load with broad allowed_bases so entry is accepted
        manifest = self._make_manifest(
            tmp_path, entries=[entry_data], allowed_bases=[tmp_path],
        )
        assert manifest.get("evil-entry-2") is not None

        # Now restrict allowed_bases so the original path is no longer valid
        manifest._allowed_bases = [(tmp_path / "data").resolve()]
        (tmp_path / "data").mkdir(exist_ok=True)

        result = restore_from_quarantine(
            "evil-entry-2",
            manifest,
            verify_hash=False,
            quarantine_base=quarantine_dir,
        )
        assert result.success is False
        assert "Security error" in result.error
        assert "original path" in result.error

    def test_dot_dot_in_quarantine_path(self, tmp_path):
        """Path with ../../ in quarantine_path is blocked."""
        quarantine_dir = tmp_path / "quarantine"
        quarantine_dir.mkdir()

        entry_data = {
            "id": "traversal-entry",
            "original_path": str(tmp_path / "safe" / "file.txt"),
            "quarantine_path": str(quarantine_dir / ".." / ".." / "etc" / "passwd"),
            "quarantined_at": "2025-01-01T00:00:00",
            "reason": "test",
            "risk_tier": "HIGH",
            "triggered_by": "test",
        }

        manifest = self._make_manifest(tmp_path, entries=[entry_data])
        result = restore_from_quarantine(
            "traversal-entry",
            manifest,
            verify_hash=False,
            quarantine_base=quarantine_dir,
        )
        assert result.success is False
        assert "quarantine path" in result.error

    def test_entry_not_found_returns_failure(self, tmp_path):
        """Non-existent entry ID returns failure result."""
        manifest = self._make_manifest(tmp_path)
        result = restore_from_quarantine("nonexistent-id", manifest)
        assert result.success is False
        assert "not found" in result.error

    def test_quarantine_file_missing_returns_failure(self, tmp_path):
        """Missing quarantine file returns failure result."""
        quarantine_dir = tmp_path / "quarantine"
        quarantine_dir.mkdir()

        entry_data = {
            "id": "missing-file",
            "original_path": str(tmp_path / "data" / "file.txt"),
            "quarantine_path": str(quarantine_dir / "deleted.txt"),
            "quarantined_at": "2025-01-01T00:00:00",
            "reason": "test",
            "risk_tier": "HIGH",
            "triggered_by": "test",
        }

        manifest = self._make_manifest(tmp_path, entries=[entry_data])
        result = restore_from_quarantine(
            "missing-file",
            manifest,
            verify_hash=False,
            quarantine_base=quarantine_dir,
        )
        assert result.success is False
        assert "no longer exists" in result.error

    def test_symlink_escape_quarantine_base(self, tmp_path):
        """Symlink that escapes quarantine base is caught by resolve()."""
        quarantine_dir = tmp_path / "quarantine"
        quarantine_dir.mkdir()
        outside_file = tmp_path / "outside" / "secret.txt"
        outside_file.parent.mkdir()
        outside_file.write_text("secret")

        # Create a symlink inside quarantine that points outside
        link_path = quarantine_dir / "link.txt"
        link_path.symlink_to(outside_file)

        entry_data = {
            "id": "symlink-escape",
            "original_path": str(tmp_path / "data" / "file.txt"),
            "quarantine_path": str(link_path),
            "quarantined_at": "2025-01-01T00:00:00",
            "reason": "test",
            "risk_tier": "HIGH",
            "triggered_by": "test",
        }

        manifest = self._make_manifest(tmp_path, entries=[entry_data])
        result = restore_from_quarantine(
            "symlink-escape",
            manifest,
            verify_hash=False,
            quarantine_base=quarantine_dir,
        )
        # The symlink resolves to outside the quarantine base
        assert result.success is False
        assert "quarantine path" in result.error

    def test_dry_run_with_valid_paths(self, tmp_path):
        """Dry run with valid paths succeeds without moving files."""
        quarantine_dir = tmp_path / "quarantine"
        quarantine_dir.mkdir()
        quarantined_file = quarantine_dir / "file.txt"
        quarantined_file.write_text("content")

        original_dir = tmp_path / "data"
        original_dir.mkdir()

        entry_data = {
            "id": "dry-run-entry",
            "original_path": str(original_dir / "file.txt"),
            "quarantine_path": str(quarantined_file),
            "quarantined_at": "2025-01-01T00:00:00",
            "reason": "test",
            "risk_tier": "HIGH",
            "triggered_by": "test",
            "file_hash": None,
        }

        manifest = self._make_manifest(tmp_path, entries=[entry_data])
        result = restore_from_quarantine(
            "dry-run-entry",
            manifest,
            verify_hash=False,
            dry_run=True,
            quarantine_base=quarantine_dir,
        )
        assert result.success is True
        # File should not have been moved
        assert quarantined_file.exists()
