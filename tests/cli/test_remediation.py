"""
Functional tests for the remediation CLI commands (quarantine and lock-down).

Tests remediation functionality including:
- Quarantine command
- Lock-down command
- Dry-run mode
- Filter-based batch operations
- Error handling
"""

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from openlabels.core.types import RiskTier
from openlabels.remediation.base import RemediationAction, RemediationResult


@pytest.fixture
def runner():
    """Create a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def temp_dir():
    """Create a temporary directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        test_file = Path(tmpdir) / "sensitive_file.txt"
        test_file.write_text("SSN: 123-45-6789")

        other_file = Path(tmpdir) / "other_file.txt"
        other_file.write_text("Some regular content")

        # Create quarantine destination
        quarantine_dir = Path(tmpdir) / "quarantine"
        quarantine_dir.mkdir()

        yield tmpdir


@pytest.fixture
def mock_file_classification():
    """Create a mock FileClassification result."""
    from openlabels.core.processor import FileClassification

    return FileClassification(
        file_path="/test/file.txt",
        file_name="file.txt",
        file_size=100,
        mime_type="text/plain",
        exposure_level="PRIVATE",
        entity_counts={"SSN": 2},
        risk_score=75,
        risk_tier=RiskTier.HIGH,
    )


@pytest.fixture
def mock_quarantine_success():
    """Create a successful quarantine result."""
    return RemediationResult(
        success=True,
        action=RemediationAction.QUARANTINE,
        source_path=Path("/test/source.txt"),
        dest_path=Path("/quarantine/source.txt"),
        performed_by="test_user",
    )


@pytest.fixture
def mock_lockdown_success():
    """Create a successful lockdown result."""
    return RemediationResult(
        success=True,
        action=RemediationAction.LOCKDOWN,
        source_path=Path("/test/file.txt"),
        principals=["BUILTIN\\Administrators"],
        previous_acl="base64_encoded_acl_data",
        performed_by="test_user",
    )


class TestQuarantineHelp:
    """Tests for quarantine command help."""

    def test_quarantine_help_shows_usage(self, runner):
        """quarantine --help should show usage information."""
        from openlabels.cli.commands.remediation import quarantine

        result = runner.invoke(quarantine, ["--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output
        assert "--where" in result.output
        assert "--scan-path" in result.output
        assert "--dry-run" in result.output
        assert "--preserve-acls" in result.output


class TestQuarantineSingleFile:
    """Tests for single file quarantine."""

    def test_quarantine_single_file_success(self, runner, temp_dir, mock_quarantine_success):
        """Quarantine a single file successfully."""
        from openlabels.cli.commands.remediation import quarantine

        source = Path(temp_dir) / "sensitive_file.txt"
        dest = Path(temp_dir) / "quarantine"

        with patch("openlabels.remediation.quarantine", return_value=mock_quarantine_success):
            result = runner.invoke(quarantine, [str(source), str(dest)])

        assert result.exit_code == 0
        assert "Quarantined:" in result.output

    def test_quarantine_single_file_dry_run(self, runner, temp_dir):
        """Quarantine with dry-run should not move file."""
        from openlabels.cli.commands.remediation import quarantine

        source = Path(temp_dir) / "sensitive_file.txt"
        dest = Path(temp_dir) / "quarantine"

        result = runner.invoke(quarantine, [str(source), str(dest), "--dry-run"])

        assert result.exit_code == 0
        assert "DRY RUN" in result.output
        # File should still exist at source
        assert source.exists()

    def test_quarantine_without_destination_fails(self, runner, temp_dir):
        """Quarantine without destination should fail."""
        from openlabels.cli.commands.remediation import quarantine

        source = Path(temp_dir) / "sensitive_file.txt"

        result = runner.invoke(quarantine, [str(source)])

        assert result.exit_code == 1
        assert "Error" in result.output or "required" in result.output.lower()

    def test_quarantine_preserve_acls_option(self, runner, temp_dir, mock_quarantine_success):
        """Quarantine with preserve-acls option."""
        from openlabels.cli.commands.remediation import quarantine

        source = Path(temp_dir) / "sensitive_file.txt"
        dest = Path(temp_dir) / "quarantine"

        with patch("openlabels.remediation.quarantine", return_value=mock_quarantine_success) as mock:
            result = runner.invoke(quarantine, [str(source), str(dest), "--preserve-acls"])

        assert result.exit_code == 0
        mock.assert_called_once()
        _, kwargs = mock.call_args
        assert kwargs["preserve_acls"] is True

    def test_quarantine_no_preserve_acls_option(self, runner, temp_dir, mock_quarantine_success):
        """Quarantine with --no-preserve-acls option."""
        from openlabels.cli.commands.remediation import quarantine

        source = Path(temp_dir) / "sensitive_file.txt"
        dest = Path(temp_dir) / "quarantine"

        with patch("openlabels.remediation.quarantine", return_value=mock_quarantine_success) as mock:
            result = runner.invoke(quarantine, [str(source), str(dest), "--no-preserve-acls"])

        assert result.exit_code == 0
        mock.assert_called_once()
        _, kwargs = mock.call_args
        assert kwargs["preserve_acls"] is False


class TestQuarantineBatchMode:
    """Tests for batch quarantine with --where filter."""

    def test_quarantine_batch_with_filter(self, runner, temp_dir, mock_file_classification, mock_quarantine_success):
        """Quarantine files matching filter."""
        from openlabels.cli.commands.remediation import quarantine

        dest = Path(temp_dir) / "quarantine"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            with patch("openlabels.remediation.quarantine", return_value=mock_quarantine_success):
                result = runner.invoke(quarantine, [
                    "--where", "score > 50",
                    "--scan-path", temp_dir,
                    str(dest),
                ])

        assert result.exit_code == 0
        assert "Found" in result.output
        assert "Quarantined" in result.output

    def test_quarantine_batch_dry_run(self, runner, temp_dir, mock_file_classification):
        """Batch quarantine dry-run shows files that would be moved."""
        from openlabels.cli.commands.remediation import quarantine

        dest = Path(temp_dir) / "quarantine"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(quarantine, [
                "--where", "score > 50",
                "--scan-path", temp_dir,
                str(dest),
                "--dry-run",
            ])

        assert result.exit_code == 0
        assert "DRY RUN" in result.output
        assert "would be quarantined" in result.output

    def test_quarantine_batch_requires_scan_path(self, runner, temp_dir):
        """Batch quarantine requires --scan-path when using --where."""
        from openlabels.cli.commands.remediation import quarantine

        dest = Path(temp_dir) / "quarantine"

        result = runner.invoke(quarantine, [
            "--where", "score > 50",
            str(dest),
        ])

        assert result.exit_code == 1
        assert "--scan-path required" in result.output

    def test_quarantine_batch_recursive(self, runner, temp_dir, mock_file_classification, mock_quarantine_success):
        """Batch quarantine with recursive scan."""
        from openlabels.cli.commands.remediation import quarantine

        # Create subdirectory with file
        subdir = Path(temp_dir) / "subdir"
        subdir.mkdir(exist_ok=True)
        (subdir / "nested.txt").write_text("SSN: 111-22-3333")

        dest = Path(temp_dir) / "quarantine"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            with patch("openlabels.remediation.quarantine", return_value=mock_quarantine_success):
                result = runner.invoke(quarantine, [
                    "--where", "score > 50",
                    "--scan-path", temp_dir,
                    "-r",
                    str(dest),
                ])

        assert result.exit_code == 0


class TestQuarantineErrorHandling:
    """Tests for quarantine error handling."""

    def test_quarantine_failure(self, runner, temp_dir):
        """Quarantine failure should show error."""
        from openlabels.cli.commands.remediation import quarantine

        source = Path(temp_dir) / "sensitive_file.txt"
        dest = Path(temp_dir) / "quarantine"

        failure_result = RemediationResult(
            success=False,
            action=RemediationAction.QUARANTINE,
            source_path=source,
            error="Permission denied",
        )

        with patch("openlabels.remediation.quarantine", return_value=failure_result):
            result = runner.invoke(quarantine, [str(source), str(dest)])

        assert result.exit_code == 1
        assert "Error" in result.output
        assert "Permission denied" in result.output

    def test_quarantine_nonexistent_source(self, runner, temp_dir):
        """Quarantine with non-existent source should fail."""
        from openlabels.cli.commands.remediation import quarantine

        source = Path(temp_dir) / "nonexistent.txt"
        dest = Path(temp_dir) / "quarantine"

        result = runner.invoke(quarantine, [str(source), str(dest)])

        assert result.exit_code == 2
        assert "does not exist" in result.output.lower() or "invalid" in result.output.lower()


class TestLockdownHelp:
    """Tests for lock-down command help."""

    def test_lockdown_help_shows_usage(self, runner):
        """lock-down --help should show usage information."""
        from openlabels.cli.commands.remediation import lock_down_cmd

        result = runner.invoke(lock_down_cmd, ["--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output
        assert "--where" in result.output
        assert "--principals" in result.output
        assert "--keep-inheritance" in result.output
        assert "--backup-acl" in result.output
        assert "--dry-run" in result.output


class TestLockdownSingleFile:
    """Tests for single file lock-down."""

    def test_lockdown_single_file_success(self, runner, temp_dir, mock_lockdown_success):
        """Lock down a single file successfully."""
        from openlabels.cli.commands.remediation import lock_down_cmd

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.remediation.lock_down", return_value=mock_lockdown_success):
            result = runner.invoke(lock_down_cmd, [str(test_file)])

        assert result.exit_code == 0
        assert "Locked down:" in result.output

    def test_lockdown_single_file_dry_run(self, runner, temp_dir):
        """Lock down with dry-run should not modify permissions."""
        from openlabels.cli.commands.remediation import lock_down_cmd

        test_file = Path(temp_dir) / "sensitive_file.txt"

        result = runner.invoke(lock_down_cmd, [str(test_file), "--dry-run"])

        assert result.exit_code == 0
        assert "DRY RUN" in result.output

    def test_lockdown_with_principals(self, runner, temp_dir, mock_lockdown_success):
        """Lock down with specific principals."""
        from openlabels.cli.commands.remediation import lock_down_cmd

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.remediation.lock_down", return_value=mock_lockdown_success) as mock:
            result = runner.invoke(lock_down_cmd, [
                str(test_file),
                "--principals", "admin",
                "--principals", "security_team",
            ])

        assert result.exit_code == 0
        mock.assert_called_once()
        _, kwargs = mock.call_args
        assert kwargs["allowed_principals"] == ["admin", "security_team"]

    def test_lockdown_keep_inheritance(self, runner, temp_dir, mock_lockdown_success):
        """Lock down with --keep-inheritance option."""
        from openlabels.cli.commands.remediation import lock_down_cmd

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.remediation.lock_down", return_value=mock_lockdown_success) as mock:
            result = runner.invoke(lock_down_cmd, [str(test_file), "--keep-inheritance"])

        assert result.exit_code == 0
        mock.assert_called_once()
        _, kwargs = mock.call_args
        assert kwargs["remove_inheritance"] is False

    def test_lockdown_backup_acl(self, runner, temp_dir, mock_lockdown_success):
        """Lock down with --backup-acl option."""
        from openlabels.cli.commands.remediation import lock_down_cmd

        test_file = Path(temp_dir) / "sensitive_file.txt"

        with patch("openlabels.remediation.lock_down", return_value=mock_lockdown_success) as mock:
            result = runner.invoke(lock_down_cmd, [str(test_file), "--backup-acl"])

        assert result.exit_code == 0
        mock.assert_called_once()
        _, kwargs = mock.call_args
        assert kwargs["backup_acl"] is True


class TestLockdownBatchMode:
    """Tests for batch lock-down with --where filter."""

    def test_lockdown_batch_with_filter(self, runner, temp_dir, mock_file_classification, mock_lockdown_success):
        """Lock down files matching filter."""
        from openlabels.cli.commands.remediation import lock_down_cmd

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            with patch("openlabels.remediation.lock_down", return_value=mock_lockdown_success):
                result = runner.invoke(lock_down_cmd, [
                    "--where", "tier = HIGH",
                    "--scan-path", temp_dir,
                ])

        assert result.exit_code == 0
        assert "Found" in result.output
        assert "Locked down" in result.output

    def test_lockdown_batch_dry_run(self, runner, temp_dir, mock_file_classification):
        """Batch lock-down dry-run shows files that would be locked."""
        from openlabels.cli.commands.remediation import lock_down_cmd

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(lock_down_cmd, [
                "--where", "tier = HIGH",
                "--scan-path", temp_dir,
                "--dry-run",
            ])

        assert result.exit_code == 0
        assert "DRY RUN" in result.output
        assert "would be locked down" in result.output

    def test_lockdown_batch_requires_scan_path(self, runner, temp_dir):
        """Batch lock-down requires --scan-path when using --where."""
        from openlabels.cli.commands.remediation import lock_down_cmd

        result = runner.invoke(lock_down_cmd, [
            "--where", "score > 50",
        ])

        assert result.exit_code == 1
        assert "--scan-path required" in result.output

    def test_lockdown_batch_with_principals_in_dry_run(self, runner, temp_dir, mock_file_classification):
        """Batch lock-down dry-run should show principals."""
        from openlabels.cli.commands.remediation import lock_down_cmd

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(lock_down_cmd, [
                "--where", "tier = HIGH",
                "--scan-path", temp_dir,
                "--principals", "admin",
                "--dry-run",
            ])

        assert result.exit_code == 0
        assert "DRY RUN" in result.output
        assert "admin" in result.output


class TestLockdownErrorHandling:
    """Tests for lock-down error handling."""

    def test_lockdown_failure(self, runner, temp_dir):
        """Lock-down failure should show error."""
        from openlabels.cli.commands.remediation import lock_down_cmd

        test_file = Path(temp_dir) / "sensitive_file.txt"

        failure_result = RemediationResult(
            success=False,
            action=RemediationAction.LOCKDOWN,
            source_path=test_file,
            error="Insufficient privileges",
        )

        with patch("openlabels.remediation.lock_down", return_value=failure_result):
            result = runner.invoke(lock_down_cmd, [str(test_file)])

        assert result.exit_code == 1
        assert "Error" in result.output
        assert "Insufficient privileges" in result.output

    def test_lockdown_nonexistent_file(self, runner, temp_dir):
        """Lock-down with non-existent file should fail."""
        from openlabels.cli.commands.remediation import lock_down_cmd

        test_file = Path(temp_dir) / "nonexistent.txt"

        result = runner.invoke(lock_down_cmd, [str(test_file)])

        assert result.exit_code == 2
        assert "does not exist" in result.output.lower() or "invalid" in result.output.lower()

    def test_lockdown_without_file_or_filter(self, runner):
        """Lock-down without file or filter should show error."""
        from openlabels.cli.commands.remediation import lock_down_cmd

        result = runner.invoke(lock_down_cmd, [])

        assert result.exit_code == 1
        assert "FILE_PATH required" in result.output or "Error" in result.output


class TestRemediationNoMatches:
    """Tests for remediation with no matching files."""

    def test_quarantine_no_matches(self, runner, temp_dir):
        """Quarantine with filter that matches nothing."""
        from openlabels.cli.commands.remediation import quarantine
        from openlabels.core.processor import FileClassification

        low_risk = FileClassification(
            file_path="/test/file.txt",
            file_name="file.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            entity_counts={},
            risk_score=5,
            risk_tier=RiskTier.MINIMAL,
        )

        dest = Path(temp_dir) / "quarantine"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=low_risk)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(quarantine, [
                "--where", "tier = CRITICAL",
                "--scan-path", temp_dir,
                str(dest),
            ])

        assert result.exit_code == 0
        assert "No files match" in result.output

    def test_lockdown_no_matches(self, runner, temp_dir):
        """Lock-down with filter that matches nothing."""
        from openlabels.cli.commands.remediation import lock_down_cmd
        from openlabels.core.processor import FileClassification

        low_risk = FileClassification(
            file_path="/test/file.txt",
            file_name="file.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            entity_counts={},
            risk_score=5,
            risk_tier=RiskTier.MINIMAL,
        )

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=low_risk)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(lock_down_cmd, [
                "--where", "tier = CRITICAL",
                "--scan-path", temp_dir,
            ])

        assert result.exit_code == 0
        assert "No files match" in result.output
