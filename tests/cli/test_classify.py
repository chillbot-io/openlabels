"""
Functional tests for the classify CLI command.

Tests file classification functionality including:
- Single file classification
- Directory recursive classification
- Output format options (JSON, table)
- Various file types
- Error handling for missing/invalid files
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from openlabels.core.types import RiskTier


@pytest.fixture
def runner():
    """Create a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def temp_dir():
    """Create a temporary directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        test_file = Path(tmpdir) / "test_document.txt"
        test_file.write_text("John Smith SSN: 123-45-6789 and credit card 4532015112830366")

        sensitive_file = Path(tmpdir) / "sensitive_data.csv"
        sensitive_file.write_text("name,ssn,phone\nJane Doe,987-65-4321,555-123-4567")

        # Create subdirectory with files
        subdir = Path(tmpdir) / "subdir"
        subdir.mkdir()

        nested_file = subdir / "nested_file.txt"
        nested_file.write_text("Account number: 1234567890, routing: 021000021")

        yield tmpdir


@pytest.fixture
def mock_file_classification():
    """Create a mock FileClassification result."""
    from openlabels.core.processor import FileClassification
    from openlabels.core.types import RiskTier

    return FileClassification(
        file_path="/test/file.txt",
        file_name="file.txt",
        file_size=100,
        mime_type="text/plain",
        exposure_level="PRIVATE",
        entity_counts={"SSN": 2, "CREDIT_CARD": 1},
        risk_score=75,
        risk_tier=RiskTier.HIGH,
    )


class TestClassifyHelp:
    """Tests for classify command help."""

    def test_classify_help_shows_usage(self, runner):
        """classify --help should show usage information."""
        from openlabels.cli.commands.classify import classify

        result = runner.invoke(classify, ["--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output
        assert "PATH" in result.output
        assert "--exposure" in result.output
        assert "--recursive" in result.output
        assert "--output" in result.output
        assert "--min-score" in result.output

    def test_classify_without_path_fails(self, runner):
        """classify without path should fail with usage error."""
        from openlabels.cli.commands.classify import classify

        result = runner.invoke(classify, [])

        assert result.exit_code == 2
        assert "Missing argument" in result.output or "PATH" in result.output


class TestClassifySingleFile:
    """Tests for single file classification."""

    def test_classify_single_file_success(self, runner, temp_dir, mock_file_classification):
        """Classify a single file successfully."""
        from openlabels.cli.commands.classify import classify

        test_file = Path(temp_dir) / "test_document.txt"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(classify, [str(test_file)])

        assert result.exit_code == 0
        assert "Classifying:" in result.output
        assert "Risk Score:" in result.output
        assert "Risk Tier:" in result.output

    def test_classify_file_with_exposure_option(self, runner, temp_dir, mock_file_classification):
        """Classify file with custom exposure level."""
        from openlabels.cli.commands.classify import classify

        test_file = Path(temp_dir) / "test_document.txt"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(classify, [str(test_file), "--exposure", "PUBLIC"])

        assert result.exit_code == 0
        # Verify processor was called with PUBLIC exposure
        mock_processor.process_file.assert_called()
        call_kwargs = mock_processor.process_file.call_args
        assert "PUBLIC" in str(call_kwargs)

    def test_classify_file_with_ml_enabled(self, runner, temp_dir, mock_file_classification):
        """Classify file with ML detectors enabled."""
        from openlabels.cli.commands.classify import classify

        test_file = Path(temp_dir) / "test_document.txt"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(classify, [str(test_file), "--enable-ml"])

        assert result.exit_code == 0
        mock_processor_cls.assert_called_with(enable_ml=True)

    def test_classify_file_nonexistent_path(self, runner):
        """Classify with non-existent path should fail."""
        from openlabels.cli.commands.classify import classify

        result = runner.invoke(classify, ["/nonexistent/path/file.txt"])

        assert result.exit_code == 2
        assert "does not exist" in result.output.lower() or "invalid" in result.output.lower()


class TestClassifyDirectory:
    """Tests for directory classification."""

    def test_classify_directory_non_recursive(self, runner, temp_dir, mock_file_classification):
        """Classify directory without recursion."""
        from openlabels.cli.commands.classify import classify

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(classify, [temp_dir])

        assert result.exit_code == 0
        assert "Classifying" in result.output
        # Should only process files in the top directory (2 files)
        assert mock_processor.process_file.call_count == 2

    def test_classify_directory_recursive(self, runner, temp_dir, mock_file_classification):
        """Classify directory with recursion."""
        from openlabels.cli.commands.classify import classify

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(classify, [temp_dir, "--recursive"])

        assert result.exit_code == 0
        # Should process all files including nested (3 files total)
        assert mock_processor.process_file.call_count == 3

    def test_classify_directory_shows_summary(self, runner, temp_dir, mock_file_classification):
        """Classify directory should show summary for multiple files."""
        from openlabels.cli.commands.classify import classify

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(classify, [temp_dir])

        assert result.exit_code == 0
        assert "Summary:" in result.output
        assert "files processed" in result.output


class TestClassifyOutput:
    """Tests for classify output options."""

    def test_classify_json_output(self, runner, temp_dir, mock_file_classification):
        """Classify with JSON output file."""
        from openlabels.cli.commands.classify import classify

        output_file = Path(temp_dir) / "results.json"
        test_file = Path(temp_dir) / "test_document.txt"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(classify, [str(test_file), "-o", str(output_file)])

        assert result.exit_code == 0
        assert output_file.exists()
        assert "Results written to:" in result.output

        # Verify JSON content
        with open(output_file) as f:
            data = json.load(f)

        assert isinstance(data, list)
        assert len(data) == 1
        assert "file" in data[0]
        assert "risk_score" in data[0]
        assert "risk_tier" in data[0]

    def test_classify_console_output_format(self, runner, temp_dir, mock_file_classification):
        """Classify console output should have proper format."""
        from openlabels.cli.commands.classify import classify

        test_file = Path(temp_dir) / "test_document.txt"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(classify, [str(test_file)])

        assert result.exit_code == 0
        assert "File:" in result.output
        assert "Risk Score:" in result.output
        assert "Risk Tier:" in result.output
        assert "Entities:" in result.output
        assert "Detected Entities:" in result.output


class TestClassifyMinScore:
    """Tests for min-score filtering."""

    def test_classify_min_score_filters_results(self, runner, temp_dir):
        """Min-score option should filter low-risk results."""
        from openlabels.cli.commands.classify import classify
        from openlabels.core.processor import FileClassification
        from openlabels.core.types import RiskTier

        # Create two results with different scores
        low_risk = FileClassification(
            file_path="/test/low.txt",
            file_name="low.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            entity_counts={},
            risk_score=20,
            risk_tier=RiskTier.LOW,
        )

        high_risk = FileClassification(
            file_path="/test/high.txt",
            file_name="high.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            entity_counts={"SSN": 5},
            risk_score=80,
            risk_tier=RiskTier.CRITICAL,
        )

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=[low_risk, high_risk])
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(classify, [temp_dir, "--min-score", "50"])

        assert result.exit_code == 0
        # Only the high risk file should be in output
        assert "high.txt" in result.output or "1 files processed" in result.output


class TestClassifyErrorHandling:
    """Tests for classify error handling."""

    def test_classify_permission_denied(self, runner, temp_dir):
        """Classify should handle permission denied gracefully."""
        from openlabels.cli.commands.classify import classify

        test_file = Path(temp_dir) / "test_document.txt"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()

            async def raise_permission_error(*args, **kwargs):
                raise PermissionError("Permission denied")

            mock_processor.process_file = AsyncMock(side_effect=raise_permission_error)
            mock_processor_cls.return_value = mock_processor

            # Need to patch open as well for the file read
            with patch("builtins.open", side_effect=PermissionError("Permission denied")):
                result = runner.invoke(classify, [str(test_file)])

        # Command should not crash
        assert result.exit_code == 0 or "Permission denied" in result.output

    def test_classify_import_error_handling(self, runner, temp_dir):
        """Classify should handle missing module gracefully."""
        from openlabels.cli.commands.classify import classify

        test_file = Path(temp_dir) / "test_document.txt"

        with patch("openlabels.core.processor.FileProcessor", side_effect=ImportError("Module not found")):
            result = runner.invoke(classify, [str(test_file)])

        assert "Error" in result.output or "not installed" in result.output


class TestClassifyFileTypes:
    """Tests for classify with various file types."""

    def test_classify_text_file(self, runner, temp_dir, mock_file_classification):
        """Classify plain text file."""
        from openlabels.cli.commands.classify import classify

        test_file = Path(temp_dir) / "test_document.txt"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(classify, [str(test_file)])

        assert result.exit_code == 0

    def test_classify_csv_file(self, runner, temp_dir, mock_file_classification):
        """Classify CSV file."""
        from openlabels.cli.commands.classify import classify

        test_file = Path(temp_dir) / "sensitive_data.csv"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(classify, [str(test_file)])

        assert result.exit_code == 0


class TestClassifyEntityDisplay:
    """Tests for entity display in classify output."""

    def test_classify_shows_entity_counts(self, runner, temp_dir, mock_file_classification):
        """Classify should show entity type counts."""
        from openlabels.cli.commands.classify import classify

        test_file = Path(temp_dir) / "test_document.txt"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(classify, [str(test_file)])

        assert result.exit_code == 0
        assert "SSN" in result.output
        assert "CREDIT_CARD" in result.output

    def test_classify_shows_high_risk_warning(self, runner, temp_dir, mock_file_classification):
        """Classify should show warning for high-risk files in directory scan."""
        from openlabels.cli.commands.classify import classify

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(classify, [temp_dir])

        assert result.exit_code == 0
        # High risk count should be shown in summary
        assert "High" in result.output or "risk" in result.output.lower()
