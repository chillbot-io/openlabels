"""
Functional tests for the find CLI command.

Tests file search functionality including:
- Search by pattern
- Search with entity type filters
- Recursive search
- Output formatting (table, json, csv, paths)
- No-results case
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
        test_file = Path(tmpdir) / "test_document.txt"
        test_file.write_text("John Smith SSN: 123-45-6789")

        sensitive_file = Path(tmpdir) / "sensitive_data.csv"
        sensitive_file.write_text("name,ssn\nJane Doe,987-65-4321")

        # Create subdirectory with files
        subdir = Path(tmpdir) / "subdir"
        subdir.mkdir()

        nested_file = subdir / "nested_file.txt"
        nested_file.write_text("Credit card: 4532015112830366")

        yield tmpdir


@pytest.fixture
def mock_scan_results():
    """Create mock scan results for testing."""
    return [
        {
            "file_path": "/test/file1.txt",
            "file_name": "file1.txt",
            "risk_score": 85,
            "risk_tier": "CRITICAL",
            "entity_counts": {"SSN": 3, "CREDIT_CARD": 2},
            "total_entities": 5,
            "exposure_level": "PRIVATE",
            "owner": None,
        },
        {
            "file_path": "/test/file2.txt",
            "file_name": "file2.txt",
            "risk_score": 45,
            "risk_tier": "MEDIUM",
            "entity_counts": {"EMAIL": 2},
            "total_entities": 2,
            "exposure_level": "PRIVATE",
            "owner": None,
        },
        {
            "file_path": "/test/file3.txt",
            "file_name": "file3.txt",
            "risk_score": 15,
            "risk_tier": "LOW",
            "entity_counts": {},
            "total_entities": 0,
            "exposure_level": "PRIVATE",
            "owner": None,
        },
    ]


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


class TestFindHelp:
    """Tests for find command help."""

    def test_find_help_shows_usage(self, runner):
        """find --help should show usage information."""
        from openlabels.cli.commands.find import find

        result = runner.invoke(find, ["--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output
        assert "PATH" in result.output
        assert "--where" in result.output
        assert "--recursive" in result.output
        assert "--format" in result.output
        assert "--limit" in result.output
        assert "--sort" in result.output

    def test_find_without_path_fails(self, runner):
        """find without path should fail with usage error."""
        from openlabels.cli.commands.find import find

        result = runner.invoke(find, [])

        assert result.exit_code == 2
        assert "Missing argument" in result.output or "PATH" in result.output

    def test_find_help_shows_filter_grammar(self, runner):
        """find --help should document filter grammar."""
        from openlabels.cli.commands.find import find

        result = runner.invoke(find, ["--help"])

        assert result.exit_code == 0
        assert "score" in result.output
        assert "tier" in result.output
        assert "has(" in result.output
        assert "count(" in result.output
        assert "AND" in result.output
        assert "OR" in result.output


class TestFindBasicSearch:
    """Tests for basic find functionality."""

    def test_find_directory_default(self, runner, temp_dir, mock_file_classification):
        """Find in directory with default options."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir])

        assert result.exit_code == 0
        assert "Scanning" in result.output

    def test_find_single_file(self, runner, temp_dir, mock_file_classification):
        """Find on a single file."""
        from openlabels.cli.commands.find import find

        test_file = Path(temp_dir) / "test_document.txt"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [str(test_file)])

        assert result.exit_code == 0
        assert "Found" in result.output or "matching" in result.output

    def test_find_recursive(self, runner, temp_dir, mock_file_classification):
        """Find with recursive option includes nested files."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir, "--recursive"])

        assert result.exit_code == 0
        # Should process all 3 files including nested
        assert mock_processor.process_file.call_count == 3


class TestFindWithFilter:
    """Tests for find with filter expressions."""

    def test_find_score_filter(self, runner, temp_dir, mock_file_classification):
        """Find with score filter."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir, "--where", "score > 50"])

        assert result.exit_code == 0

    def test_find_tier_filter(self, runner, temp_dir, mock_file_classification):
        """Find with tier filter."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir, "--where", "tier = HIGH"])

        assert result.exit_code == 0

    def test_find_has_entity_filter(self, runner, temp_dir, mock_file_classification):
        """Find with has() entity filter."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir, "--where", "has(SSN)"])

        assert result.exit_code == 0

    def test_find_count_entity_filter(self, runner, temp_dir, mock_file_classification):
        """Find with count() entity filter."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir, "--where", "count(SSN) >= 2"])

        assert result.exit_code == 0

    def test_find_compound_filter(self, runner, temp_dir, mock_file_classification):
        """Find with compound AND/OR filter."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir, "--where", "score > 50 AND has(SSN)"])

        assert result.exit_code == 0

    def test_find_invalid_filter_shows_error(self, runner, temp_dir):
        """Find with invalid filter should show error."""
        from openlabels.cli.commands.find import find

        result = runner.invoke(find, [temp_dir, "--where", "invalid filter syntax !!!"])

        # Should fail due to bad parameter
        assert result.exit_code == 2
        assert "Invalid filter" in result.output or "Error" in result.output


class TestFindOutputFormats:
    """Tests for find output format options."""

    def test_find_table_format(self, runner, temp_dir, mock_file_classification):
        """Find with table format (default)."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir, "--format", "table"])

        assert result.exit_code == 0
        assert "Path" in result.output
        assert "Score" in result.output
        assert "Tier" in result.output

    def test_find_json_format(self, runner, temp_dir, mock_file_classification):
        """Find with JSON format."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir, "--format", "json"])

        assert result.exit_code == 0
        # Output contains JSON - find the JSON array in the output
        # The output may include "Scanning..." before the JSON
        output = result.output
        # Find the start of the JSON array
        json_start = output.find("[")
        if json_start >= 0:
            json_output = output[json_start:]
            data = json.loads(json_output)
            assert isinstance(data, list)
        else:
            # No JSON array found - should not happen for a successful result
            raise AssertionError(f"No JSON array in output: {output}")

    def test_find_csv_format(self, runner, temp_dir, mock_file_classification):
        """Find with CSV format."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir, "--format", "csv"])

        assert result.exit_code == 0
        assert "file_path" in result.output
        assert "risk_score" in result.output
        assert "risk_tier" in result.output

    def test_find_paths_format(self, runner, temp_dir, mock_file_classification):
        """Find with paths-only format."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir, "--format", "paths"])

        assert result.exit_code == 0


class TestFindSorting:
    """Tests for find sorting options."""

    def test_find_sort_by_score(self, runner, temp_dir, mock_file_classification):
        """Find sorted by score."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir, "--sort", "score", "--desc"])

        assert result.exit_code == 0

    def test_find_sort_by_path(self, runner, temp_dir, mock_file_classification):
        """Find sorted by path."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir, "--sort", "path", "--asc"])

        assert result.exit_code == 0

    def test_find_sort_by_tier(self, runner, temp_dir, mock_file_classification):
        """Find sorted by tier."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [temp_dir, "--sort", "tier"])

        assert result.exit_code == 0


class TestFindNoResults:
    """Tests for find with no matching results."""

    def test_find_no_matching_files(self, runner, temp_dir):
        """Find with filter that matches nothing."""
        from openlabels.cli.commands.find import find
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

            result = runner.invoke(find, [temp_dir, "--where", "score > 90"])

        assert result.exit_code == 0
        assert "No matching files" in result.output

    def test_find_empty_directory(self, runner):
        """Find in empty directory."""
        from openlabels.cli.commands.find import find

        with tempfile.TemporaryDirectory() as empty_dir:
            result = runner.invoke(find, [empty_dir])

        assert result.exit_code == 0
        assert "No files found" in result.output or "No matching" in result.output


class TestFindErrorHandling:
    """Tests for find error handling."""

    def test_find_nonexistent_path(self, runner):
        """Find with non-existent path should fail."""
        from openlabels.cli.commands.find import find

        result = runner.invoke(find, ["/nonexistent/path"])

        assert result.exit_code == 2
        assert "does not exist" in result.output.lower() or "invalid" in result.output.lower()

    def test_find_import_error_handling(self, runner, temp_dir):
        """Find should handle missing module gracefully."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor", side_effect=ImportError("Module not found")):
            result = runner.invoke(find, [temp_dir])

        assert result.exit_code == 1
        assert "Error" in result.output or "not installed" in result.output


class TestFindIntegration:
    """Integration-style tests for find command."""

    def test_find_full_workflow(self, runner, temp_dir, mock_file_classification):
        """Test complete find workflow with all options."""
        from openlabels.cli.commands.find import find

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(find, [
                temp_dir,
                "--recursive",
                "--where", "score > 50",
                "--format", "json",
                "--limit", "10",
                "--sort", "score",
                "--desc",
            ])

        assert result.exit_code == 0
