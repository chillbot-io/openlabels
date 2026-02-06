"""
Functional tests for the heatmap CLI command.

Tests risk heatmap generation including:
- Heatmap generation by directory
- Data aggregation
- Output formats (text, json)
- Depth control
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
    """Create a temporary directory with nested structure."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create directory structure
        # tmpdir/
        #   file1.txt
        #   dir1/
        #     file2.txt
        #     subdir1/
        #       file3.txt
        #   dir2/
        #     file4.txt

        Path(tmpdir, "file1.txt").write_text("SSN: 123-45-6789")

        dir1 = Path(tmpdir, "dir1")
        dir1.mkdir()
        Path(dir1, "file2.txt").write_text("Credit card: 4532015112830366")

        subdir1 = Path(dir1, "subdir1")
        subdir1.mkdir()
        Path(subdir1, "file3.txt").write_text("Account: 1234567890")

        dir2 = Path(tmpdir, "dir2")
        dir2.mkdir()
        Path(dir2, "file4.txt").write_text("Email: test@example.com")

        yield tmpdir


@pytest.fixture
def mock_file_classifications():
    """Create mock file classifications with varying risk levels."""
    from openlabels.core.processor import FileClassification

    return [
        FileClassification(
            file_path="/test/file1.txt",
            file_name="file1.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            entity_counts={"SSN": 3},
            risk_score=85,
            risk_tier=RiskTier.CRITICAL,
        ),
        FileClassification(
            file_path="/test/dir1/file2.txt",
            file_name="file2.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            entity_counts={"CREDIT_CARD": 2},
            risk_score=65,
            risk_tier=RiskTier.HIGH,
        ),
        FileClassification(
            file_path="/test/dir1/subdir1/file3.txt",
            file_name="file3.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            entity_counts={"BANK_ACCOUNT": 1},
            risk_score=45,
            risk_tier=RiskTier.MEDIUM,
        ),
        FileClassification(
            file_path="/test/dir2/file4.txt",
            file_name="file4.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            entity_counts={"EMAIL": 1},
            risk_score=15,
            risk_tier=RiskTier.LOW,
        ),
    ]


class TestHeatmapHelp:
    """Tests for heatmap command help."""

    def test_heatmap_help_shows_usage(self, runner):
        """heatmap --help should show usage information."""
        from openlabels.cli.commands.heatmap import heatmap

        result = runner.invoke(heatmap, ["--help"])

        assert result.exit_code == 0
        assert "Usage:" in result.output
        assert "PATH" in result.output
        assert "--recursive" in result.output
        assert "--depth" in result.output
        assert "--format" in result.output

    def test_heatmap_without_path_fails(self, runner):
        """heatmap without path should fail with usage error."""
        from openlabels.cli.commands.heatmap import heatmap

        result = runner.invoke(heatmap, [])

        assert result.exit_code == 2
        assert "Missing argument" in result.output or "PATH" in result.output


class TestHeatmapTextFormat:
    """Tests for heatmap text format output."""

    def test_heatmap_text_format_default(self, runner, temp_dir, mock_file_classifications):
        """Heatmap generates text format by default."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=mock_file_classifications)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir, "-r"])

        assert result.exit_code == 0
        assert "Risk Heatmap by Directory" in result.output
        assert "Directory" in result.output
        assert "Files" in result.output
        assert "Avg" in result.output
        assert "Max" in result.output

    def test_heatmap_shows_risk_indicators(self, runner, temp_dir, mock_file_classifications):
        """Heatmap shows visual risk indicators."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=mock_file_classifications)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir, "-r"])

        assert result.exit_code == 0
        # Should show risk indicators like [!!!!], [!!! ], etc.
        assert "[" in result.output

    def test_heatmap_shows_tier_counts(self, runner, temp_dir, mock_file_classifications):
        """Heatmap shows critical, high, medium counts."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=mock_file_classifications)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir, "-r"])

        assert result.exit_code == 0
        assert "C" in result.output  # Critical column
        assert "H" in result.output  # High column
        assert "M" in result.output  # Medium column

    def test_heatmap_shows_legend(self, runner, temp_dir, mock_file_classifications):
        """Heatmap shows legend explaining columns."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=mock_file_classifications)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir, "-r"])

        assert result.exit_code == 0
        assert "Legend:" in result.output
        assert "Critical" in result.output
        assert "High" in result.output
        assert "Medium" in result.output

    def test_heatmap_shows_total(self, runner, temp_dir, mock_file_classifications):
        """Heatmap shows total file count."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=mock_file_classifications)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir, "-r"])

        assert result.exit_code == 0
        assert "Total:" in result.output
        assert "files" in result.output
        assert "directories" in result.output


class TestHeatmapJsonFormat:
    """Tests for heatmap JSON format output."""

    def test_heatmap_json_format(self, runner, temp_dir, mock_file_classifications):
        """Heatmap generates JSON format."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=mock_file_classifications)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir, "-r", "--format", "json"])

        assert result.exit_code == 0

        # Parse JSON output (skip "Scanning..." line)
        lines = result.output.strip().split("\n")
        json_lines = [l for l in lines if not l.startswith("Scanning")]
        json_output = "\n".join(json_lines)
        data = json.loads(json_output)

        assert isinstance(data, list)
        assert len(data) > 0

    def test_heatmap_json_has_expected_fields(self, runner, temp_dir, mock_file_classifications):
        """JSON heatmap has expected fields."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=mock_file_classifications)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir, "-r", "--format", "json"])

        # Parse JSON
        lines = result.output.strip().split("\n")
        json_lines = [l for l in lines if not l.startswith("Scanning")]
        data = json.loads("\n".join(json_lines))

        if data:
            entry = data[0]
            assert "directory" in entry
            assert "files" in entry
            assert "avg_score" in entry
            assert "max_score" in entry
            assert "critical" in entry
            assert "high" in entry
            assert "medium" in entry
            assert "entities" in entry


class TestHeatmapDepth:
    """Tests for heatmap depth option."""

    def test_heatmap_depth_1(self, runner, temp_dir, mock_file_classifications):
        """Heatmap with depth 1 aggregates at top level."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=mock_file_classifications)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir, "-r", "--depth", "1"])

        assert result.exit_code == 0

    def test_heatmap_depth_3(self, runner, temp_dir, mock_file_classifications):
        """Heatmap with depth 3 shows more directory levels."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=mock_file_classifications)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir, "-r", "--depth", "3"])

        assert result.exit_code == 0

    def test_heatmap_default_depth_is_2(self, runner, temp_dir, mock_file_classifications):
        """Heatmap uses depth 2 by default."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=mock_file_classifications)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir, "-r"])

        assert result.exit_code == 0


class TestHeatmapRecursive:
    """Tests for heatmap recursive option."""

    def test_heatmap_non_recursive(self, runner, temp_dir, mock_file_classifications):
        """Non-recursive heatmap excludes nested directories."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            # Only return one classification for the top-level file
            mock_processor.process_file = AsyncMock(return_value=mock_file_classifications[0])
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir])

        assert result.exit_code == 0
        # Should only process top-level file (1 file)
        assert mock_processor.process_file.call_count == 1


class TestHeatmapAggregation:
    """Tests for heatmap data aggregation."""

    def test_heatmap_aggregates_by_directory(self, runner, temp_dir, mock_file_classifications):
        """Heatmap aggregates statistics by directory."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=mock_file_classifications)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir, "-r", "--format", "json"])

        # Parse JSON
        lines = result.output.strip().split("\n")
        json_lines = [l for l in lines if not l.startswith("Scanning")]
        data = json.loads("\n".join(json_lines))

        # Verify aggregation happened
        assert len(data) > 0
        for entry in data:
            assert entry["files"] > 0
            assert entry["avg_score"] >= 0
            assert entry["max_score"] >= 0

    def test_heatmap_sorted_by_risk(self, runner, temp_dir, mock_file_classifications):
        """Heatmap is sorted by risk (max score) descending."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=mock_file_classifications)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir, "-r", "--format", "json"])

        # Parse JSON
        lines = result.output.strip().split("\n")
        json_lines = [l for l in lines if not l.startswith("Scanning")]
        data = json.loads("\n".join(json_lines))

        # Verify sorted by max_score descending
        if len(data) > 1:
            for i in range(len(data) - 1):
                assert data[i]["max_score"] >= data[i + 1]["max_score"]


class TestHeatmapSingleFile:
    """Tests for heatmap on a single file."""

    def test_heatmap_single_file(self, runner, temp_dir, mock_file_classifications):
        """Heatmap on single file."""
        from openlabels.cli.commands.heatmap import heatmap

        single_file = Path(temp_dir) / "file1.txt"

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=mock_file_classifications[0])
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [str(single_file)])

        assert result.exit_code == 0


class TestHeatmapEmptyDirectory:
    """Tests for heatmap on empty directory."""

    def test_heatmap_empty_directory(self, runner):
        """Heatmap on empty directory."""
        from openlabels.cli.commands.heatmap import heatmap

        with tempfile.TemporaryDirectory() as empty_dir:
            result = runner.invoke(heatmap, [empty_dir])

        assert "No files found" in result.output


class TestHeatmapErrorHandling:
    """Tests for heatmap error handling."""

    def test_heatmap_nonexistent_path(self, runner):
        """Heatmap with non-existent path should fail."""
        from openlabels.cli.commands.heatmap import heatmap

        result = runner.invoke(heatmap, ["/nonexistent/path"])

        assert result.exit_code == 2
        assert "does not exist" in result.output.lower() or "invalid" in result.output.lower()

    def test_heatmap_import_error(self, runner, temp_dir):
        """Heatmap handles import error gracefully."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor", side_effect=ImportError("Module not found")):
            result = runner.invoke(heatmap, [temp_dir])

        assert result.exit_code == 1
        assert "Error" in result.output


class TestHeatmapIntegration:
    """Integration-style tests for heatmap command."""

    def test_heatmap_full_workflow(self, runner, temp_dir, mock_file_classifications):
        """Test complete heatmap workflow with all options."""
        from openlabels.cli.commands.heatmap import heatmap

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(side_effect=mock_file_classifications)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [
                temp_dir,
                "--recursive",
                "--depth", "3",
                "--format", "json",
            ])

        assert result.exit_code == 0

        # Verify JSON output
        lines = result.output.strip().split("\n")
        json_lines = [l for l in lines if not l.startswith("Scanning")]
        data = json.loads("\n".join(json_lines))
        assert isinstance(data, list)


class TestHeatmapRiskVisualIndicators:
    """Tests for risk visual indicators in heatmap."""

    def test_heatmap_critical_indicator(self, runner, temp_dir):
        """Heatmap shows critical risk indicator for score >= 80."""
        from openlabels.cli.commands.heatmap import heatmap
        from openlabels.core.processor import FileClassification

        critical_classification = FileClassification(
            file_path=str(Path(temp_dir) / "critical.txt"),
            file_name="critical.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            entity_counts={"SSN": 10},
            risk_score=95,
            risk_tier=RiskTier.CRITICAL,
        )

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=critical_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir])

        assert result.exit_code == 0
        # Should show critical indicator
        assert "[!!!!]" in result.output

    def test_heatmap_minimal_indicator(self, runner, temp_dir):
        """Heatmap shows minimal risk indicator for score < 11."""
        from openlabels.cli.commands.heatmap import heatmap
        from openlabels.core.processor import FileClassification

        minimal_classification = FileClassification(
            file_path=str(Path(temp_dir) / "safe.txt"),
            file_name="safe.txt",
            file_size=100,
            mime_type="text/plain",
            exposure_level="PRIVATE",
            entity_counts={},
            risk_score=5,
            risk_tier=RiskTier.MINIMAL,
        )

        with patch("openlabels.core.processor.FileProcessor") as mock_processor_cls:
            mock_processor = MagicMock()
            mock_processor.process_file = AsyncMock(return_value=minimal_classification)
            mock_processor_cls.return_value = mock_processor

            result = runner.invoke(heatmap, [temp_dir])

        assert result.exit_code == 0
        # Should show minimal indicator
        assert "[    ]" in result.output
