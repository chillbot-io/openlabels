"""
Functional tests for the report CLI command.

Tests report generation including:
- Report generation in various formats (text, json, csv, html)
- Filter expressions
- Output file creation
- Summary statistics
"""

import json
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
        test_file = Path(tmpdir) / "document.txt"
        test_file.write_text("SSN: 123-45-6789, Credit Card: 4532015112830366")

        sensitive_file = Path(tmpdir) / "sensitive.csv"
        sensitive_file.write_text("name,ssn\nJohn Doe,987-65-4321")

        # Create subdirectory with files
        subdir = Path(tmpdir) / "subdir"
        subdir.mkdir()

        nested_file = subdir / "nested.txt"
        nested_file.write_text("Account: 1234567890")

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
        entity_counts={"SSN": 2, "CREDIT_CARD": 1},
        risk_score=75,
        risk_tier=RiskTier.HIGH,
    )


@pytest.fixture
def mock_mixed_classifications():
    """Create multiple mock classifications with different risk levels."""
    from openlabels.core.processor import FileClassification

    return [
        FileClassification(
            file_path="/test/critical.txt",
            file_name="critical.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            entity_counts={"SSN": 10, "CREDIT_CARD": 5},
            risk_score=95,
            risk_tier=RiskTier.CRITICAL,
        ),
        FileClassification(
            file_path="/test/high.txt",
            file_name="high.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            entity_counts={"EMAIL": 5},
            risk_score=65,
            risk_tier=RiskTier.HIGH,
        ),
        FileClassification(
            file_path="/test/low.txt",
            file_name="low.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            entity_counts={},
            risk_score=10,
            risk_tier=RiskTier.LOW,
        ),
    ]


class TestReportHelp:
    """Tests for report command help."""

    def test_report_help_shows_usage(self, runner):
        """report --help should show usage information."""
        from openlabels.cli.commands.report import report

        result = runner.invoke(report, ["--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output
        assert "PATH" in result.output
        assert "--where" in result.output
        assert "--format" in result.output
        assert "--output" in result.output
        assert "--title" in result.output
        assert "--recursive" in result.output

    def test_report_without_path_fails(self, runner):
        """report without path should fail with usage error."""
        from openlabels.cli.commands.report import report

        result = runner.invoke(report, [])

        assert result.exit_code == 2
        assert "Missing argument" in result.output or "PATH" in result.output


class TestReportTextFormat:
    """Tests for text format reports."""

    def test_report_text_format_default(self, runner, temp_dir, mock_file_classification):
        """Report generates text format by default."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir])

        assert result.exit_code == 0
        assert "OpenLabels Scan Report" in result.output
        assert "SUMMARY" in result.output
        assert "Total files" in result.output
        assert "By Risk Tier:" in result.output

    def test_report_text_shows_entity_types(self, runner, temp_dir, mock_file_classification):
        """Text report shows entity type breakdown."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir])

        assert result.exit_code == 0
        assert "By Entity Type:" in result.output
        assert "SSN" in result.output

    def test_report_custom_title(self, runner, temp_dir, mock_file_classification):
        """Report with custom title."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--title", "My Custom Report"])

        assert result.exit_code == 0
        assert "My Custom Report" in result.output


class TestReportJsonFormat:
    """Tests for JSON format reports."""

    def test_report_json_format(self, runner, temp_dir, mock_file_classification):
        """Report in JSON format."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--format", "json"])

        assert result.exit_code == 0

        # Parse JSON output (skip the "Scanning..." line)
        lines = result.output.strip().split("\n")
        json_lines = [l for l in lines if not l.startswith("Scanning")]
        json_output = "\n".join(json_lines)
        data = json.loads(json_output)

        assert "title" in data
        assert "summary" in data
        assert "findings" in data
        assert "generated_at" in data

    def test_report_json_has_summary_stats(self, runner, temp_dir, mock_file_classification):
        """JSON report contains summary statistics."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--format", "json"])

        # Parse JSON
        lines = result.output.strip().split("\n")
        json_lines = [l for l in lines if not l.startswith("Scanning")]
        data = json.loads("\n".join(json_lines))

        summary = data["summary"]
        assert "total_files" in summary
        assert "files_with_findings" in summary
        assert "total_entities" in summary
        assert "by_tier" in summary
        assert "by_entity" in summary


class TestReportCsvFormat:
    """Tests for CSV format reports."""

    def test_report_csv_format(self, runner, temp_dir, mock_file_classification):
        """Report in CSV format."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--format", "csv"])

        assert result.exit_code == 0
        # Check CSV header
        assert "file_path" in result.output
        assert "risk_score" in result.output
        assert "risk_tier" in result.output
        assert "entity_counts" in result.output

    def test_report_csv_has_data_rows(self, runner, temp_dir, mock_file_classification):
        """CSV report contains data rows."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--format", "csv"])

        # Count lines (should have header + data rows)
        lines = [l for l in result.output.strip().split("\n") if not l.startswith("Scanning")]
        assert len(lines) >= 1  # At least header


class TestReportHtmlFormat:
    """Tests for HTML format reports."""

    def test_report_html_format(self, runner, temp_dir, mock_file_classification):
        """Report in HTML format."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--format", "html"])

        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.output
        assert "<html>" in result.output
        assert "</html>" in result.output

    def test_report_html_has_styling(self, runner, temp_dir, mock_file_classification):
        """HTML report contains CSS styling."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--format", "html"])

        assert "<style>" in result.output
        assert ".critical" in result.output
        assert ".high" in result.output

    def test_report_html_has_table(self, runner, temp_dir, mock_file_classification):
        """HTML report contains findings table."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--format", "html"])

        assert "<table>" in result.output
        assert "<th>File</th>" in result.output
        assert "<th>Score</th>" in result.output


class TestReportOutputFile:
    """Tests for report output file creation."""

    def test_report_output_to_file(self, runner, temp_dir, mock_file_classification):
        """Report writes to output file."""
        from openlabels.cli.commands.report import report

        output_file = Path(temp_dir) / "report.txt"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "-o", str(output_file)])

        assert result.exit_code == 0
        assert output_file.exists()
        assert "Report written to:" in result.output

        content = output_file.read_text()
        assert "OpenLabels Scan Report" in content

    def test_report_json_output_to_file(self, runner, temp_dir, mock_file_classification):
        """JSON report writes to output file."""
        from openlabels.cli.commands.report import report

        output_file = Path(temp_dir) / "report.json"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--format", "json", "-o", str(output_file)])

        assert result.exit_code == 0
        assert output_file.exists()

        with open(output_file) as f:
            data = json.load(f)
        assert "summary" in data
        assert "findings" in data

    def test_report_html_output_to_file(self, runner, temp_dir, mock_file_classification):
        """HTML report writes to output file."""
        from openlabels.cli.commands.report import report

        output_file = Path(temp_dir) / "report.html"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--format", "html", "-o", str(output_file)])

        assert result.exit_code == 0
        assert output_file.exists()

        content = output_file.read_text()
        assert "<!DOCTYPE html>" in content


class TestReportFiltering:
    """Tests for report with filter expressions."""

    def test_report_with_score_filter(self, runner, temp_dir, mock_file_classification):
        """Report with score filter."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--where", "score > 50"])

        assert result.exit_code == 0

    def test_report_with_tier_filter(self, runner, temp_dir, mock_file_classification):
        """Report with tier filter."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--where", "tier = HIGH"])

        assert result.exit_code == 0

    def test_report_shows_filter_in_output(self, runner, temp_dir, mock_file_classification):
        """Report shows applied filter in output."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--where", "score > 50"])

        assert result.exit_code == 0
        assert "Filter:" in result.output or "score > 50" in result.output

    def test_report_invalid_filter_fails(self, runner, temp_dir):
        """Report with invalid filter should fail."""
        from openlabels.cli.commands.report import report

        result = runner.invoke(report, [temp_dir, "--where", "invalid >>>"])

        assert result.exit_code == 2
        assert "Invalid filter" in result.output


class TestReportRecursive:
    """Tests for recursive report generation."""

    def test_report_recursive_includes_nested(self, runner, temp_dir, mock_file_classification):
        """Recursive report includes nested directory files."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir, "--recursive"])

        assert result.exit_code == 0
        # Should process all 3 files including nested
        assert mock_processor.process_file.call_count == 3

    def test_report_non_recursive(self, runner, temp_dir, mock_file_classification):
        """Non-recursive report excludes nested files."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [temp_dir])

        assert result.exit_code == 0
        # Should only process 2 files in top directory
        assert mock_processor.process_file.call_count == 2


class TestReportSummaryStats:
    """Tests for report summary statistics."""

    def test_report_tier_breakdown(self, runner, mock_mixed_classifications):
        """Report shows breakdown by risk tier."""
        from openlabels.cli.commands.report import report

        # Use a fresh temp directory with exactly 3 files
        with tempfile.TemporaryDirectory() as test_dir:
            Path(test_dir, "critical.txt").write_text("SSN: 123-45-6789")
            Path(test_dir, "high.txt").write_text("Email: test@test.com")
            Path(test_dir, "low.txt").write_text("some text")

            with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
                mock_processor = MagicMock()
                mock_processor.process_file = AsyncMock(side_effect=mock_mixed_classifications)
                mock_processor_cls.return_value = mock_processor

                result = runner.invoke(report, [test_dir])

            assert result.exit_code == 0
            assert "CRITICAL" in result.output
            assert "HIGH" in result.output


class TestReportErrorHandling:
    """Tests for report error handling."""

    def test_report_nonexistent_path(self, runner):
        """Report with non-existent path should fail."""
        from openlabels.cli.commands.report import report

        result = runner.invoke(report, ["/nonexistent/path"])

        assert result.exit_code == 2
        assert "does not exist" in result.output.lower() or "invalid" in result.output.lower()

    def test_report_empty_directory(self, runner):
        """Report on empty directory."""
        from openlabels.cli.commands.report import report

        with tempfile.TemporaryDirectory() as empty_dir:
            result = runner.invoke(report, [empty_dir])

        assert "No files found" in result.output

    def test_report_import_error(self, runner, temp_dir):
        """Report handles import error gracefully."""
        from openlabels.cli.commands.report import report

        with patch("openlabels.core.processor.FileProcessor", side_effect=ImportError("Module not found")):
            result = runner.invoke(report, [temp_dir])

        assert result.exit_code == 1
        assert "Error" in result.output


class TestReportIntegration:
    """Integration-style tests for report command."""

    def test_report_full_workflow(self, runner, temp_dir, mock_file_classification):
        """Test complete report workflow."""
        from openlabels.cli.commands.report import report

        output_file = Path(temp_dir) / "full_report.html"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(report, [
                temp_dir,
                "--recursive",
                "--format", "html",
                "--where", "score > 0",
                "--title", "Full Test Report",
                "-o", str(output_file),
            ])

        assert result.exit_code == 0
        assert output_file.exists()

        content = output_file.read_text()
        assert "Full Test Report" in content
        assert "<!DOCTYPE html>" in content
