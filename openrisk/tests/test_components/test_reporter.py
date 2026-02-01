"""
Tests for openlabels.components.reporter module.

Tests report generation in various formats.
"""

import pytest
import tempfile
import os
import json
import csv
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime


@pytest.fixture
def mock_context():
    """Create a mock context."""
    return Mock()


@pytest.fixture
def mock_scanner():
    """Create a mock scanner."""
    scanner = Mock()
    scanner.scan.return_value = []
    return scanner


@pytest.fixture
def reporter(mock_context, mock_scanner):
    """Create a Reporter instance."""
    from openlabels.components.reporter import Reporter
    return Reporter(mock_context, mock_scanner)


@pytest.fixture
def sample_scan_results():
    """Create sample scan results."""
    from openlabels.core.types import ScanResult, Entity

    results = [
        ScanResult(
            path="/data/file1.txt",
            score=85,
            tier="HIGH",
            size_bytes=1024,
            file_type="text/plain",
            entities=[
                Entity(type="SSN", count=2, confidence=0.95, source="scanner"),
                Entity(type="EMAIL", count=1, confidence=0.9, source="scanner"),
            ],
            error=None,
        ),
        ScanResult(
            path="/data/file2.csv",
            score=45,
            tier="MEDIUM",
            size_bytes=2048,
            file_type="text/csv",
            entities=[
                Entity(type="PHONE", count=5, confidence=0.8, source="scanner"),
            ],
            error=None,
        ),
        ScanResult(
            path="/data/file3.json",
            score=15,
            tier="LOW",
            size_bytes=512,
            file_type="application/json",
            entities=[],
            error=None,
        ),
    ]
    return results


class TestReporterInit:
    """Tests for Reporter initialization."""

    def test_init_stores_context(self, mock_context, mock_scanner):
        """Should store context reference."""
        from openlabels.components.reporter import Reporter

        reporter = Reporter(mock_context, mock_scanner)
        assert reporter._ctx is mock_context

    def test_init_stores_scanner(self, mock_context, mock_scanner):
        """Should store scanner reference."""
        from openlabels.components.reporter import Reporter

        reporter = Reporter(mock_context, mock_scanner)
        assert reporter._scanner is mock_scanner


class TestBuildReport:
    """Tests for _build_report method."""

    def test_build_report_summary_total_files(self, reporter, sample_scan_results):
        """Should count total files."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON)
        report = reporter._build_report(sample_scan_results, config)

        assert report["summary"]["total_files"] == 3

    def test_build_report_summary_total_size(self, reporter, sample_scan_results):
        """Should sum file sizes."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON)
        report = reporter._build_report(sample_scan_results, config)

        expected_size = 1024 + 2048 + 512
        assert report["summary"]["total_size_bytes"] == expected_size

    def test_build_report_summary_average_score(self, reporter, sample_scan_results):
        """Should calculate average score."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON)
        report = reporter._build_report(sample_scan_results, config)

        expected_avg = (85 + 45 + 15) / 3
        assert abs(report["summary"]["average_score"] - expected_avg) < 0.01

    def test_build_report_summary_max_score(self, reporter, sample_scan_results):
        """Should find max score."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON)
        report = reporter._build_report(sample_scan_results, config)

        assert report["summary"]["max_score"] == 85

    def test_build_report_summary_min_score(self, reporter, sample_scan_results):
        """Should find min score."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON)
        report = reporter._build_report(sample_scan_results, config)

        assert report["summary"]["min_score"] == 15

    def test_build_report_tier_distribution(self, reporter, sample_scan_results):
        """Should count files per tier."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON)
        report = reporter._build_report(sample_scan_results, config)

        dist = report["summary"]["tier_distribution"]
        assert dist["HIGH"] == 1
        assert dist["MEDIUM"] == 1
        assert dist["LOW"] == 1
        assert dist["CRITICAL"] == 0
        assert dist["MINIMAL"] == 0

    def test_build_report_files_list(self, reporter, sample_scan_results):
        """Should include file entries."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON)
        report = reporter._build_report(sample_scan_results, config)

        assert len(report["files"]) == 3
        assert report["files"][0]["path"] == "/data/file1.txt"
        assert report["files"][0]["score"] == 85

    def test_build_report_includes_entities_when_configured(self, reporter, sample_scan_results):
        """Should include entities when include_entities=True."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON, include_entities=True)
        report = reporter._build_report(sample_scan_results, config)

        # First file has entities
        assert "entities" in report["files"][0]
        assert len(report["files"][0]["entities"]) == 2

    def test_build_report_excludes_entities_by_default(self, reporter, sample_scan_results):
        """Should exclude entities by default."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON, include_entities=False)
        report = reporter._build_report(sample_scan_results, config)

        assert "entities" not in report["files"][0]

    def test_build_report_empty_results(self, reporter):
        """Should handle empty results."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON)
        report = reporter._build_report([], config)

        assert report["summary"]["total_files"] == 0
        assert report["summary"]["average_score"] == 0
        assert report["summary"]["max_score"] == 0
        assert report["files"] == []

    def test_build_report_includes_title(self, reporter, sample_scan_results):
        """Should include config title."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON, title="Test Report")
        report = reporter._build_report(sample_scan_results, config)

        assert report["title"] == "Test Report"

    def test_build_report_includes_timestamp(self, reporter, sample_scan_results):
        """Should include generation timestamp."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON)
        report = reporter._build_report(sample_scan_results, config)

        assert "generated_at" in report
        # Should be valid ISO format
        datetime.fromisoformat(report["generated_at"])


class TestWriteReport:
    """Tests for _write_report method."""

    def test_write_json_report(self, reporter, sample_scan_results):
        """Should write valid JSON."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON)
        report = reporter._build_report(sample_scan_results, config)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            reporter._write_report(report, output_path, config)

            with open(output_path) as f:
                loaded = json.load(f)

            assert loaded["summary"]["total_files"] == 3
        finally:
            os.unlink(output_path)

    def test_write_jsonl_report(self, reporter, sample_scan_results):
        """Should write valid JSONL."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSONL)
        report = reporter._build_report(sample_scan_results, config)

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            output_path = f.name

        try:
            reporter._write_report(report, output_path, config)

            with open(output_path) as f:
                lines = f.readlines()

            assert len(lines) == 3
            for line in lines:
                json.loads(line)  # Should be valid JSON
        finally:
            os.unlink(output_path)

    def test_write_csv_report(self, reporter, sample_scan_results):
        """Should write valid CSV."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.CSV)
        report = reporter._build_report(sample_scan_results, config)

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_path = f.name

        try:
            reporter._write_report(report, output_path, config)

            with open(output_path, newline='') as f:
                reader = csv.reader(f)
                rows = list(reader)

            # Header + 3 data rows
            assert len(rows) == 4
            assert rows[0] == ["path", "score", "tier", "size_bytes", "file_type"]
        finally:
            os.unlink(output_path)

    def test_write_markdown_report(self, reporter, sample_scan_results):
        """Should write valid Markdown."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.MARKDOWN, title="Test")
        report = reporter._build_report(sample_scan_results, config)

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            output_path = f.name

        try:
            reporter._write_report(report, output_path, config)

            with open(output_path) as f:
                content = f.read()

            assert "# Test" in content
            assert "## Summary" in content
            assert "## Files" in content
            assert "| Path | Score | Tier |" in content
        finally:
            os.unlink(output_path)

    def test_write_html_report(self, reporter, sample_scan_results):
        """Should write valid HTML."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.HTML, title="Test Report")
        report = reporter._build_report(sample_scan_results, config)

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            output_path = f.name

        try:
            reporter._write_report(report, output_path, config)

            with open(output_path) as f:
                content = f.read()

            assert "<!DOCTYPE html>" in content
            assert "<title>Test Report</title>" in content
            assert "<table>" in content
        finally:
            os.unlink(output_path)

    def test_write_creates_parent_directories(self, reporter, sample_scan_results):
        """Should create parent directories if needed."""
        from openlabels.core.types import ReportConfig, ReportFormat

        config = ReportConfig(format=ReportFormat.JSON)
        report = reporter._build_report(sample_scan_results, config)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "nested", "dir", "report.json")
            reporter._write_report(report, output_path, config)

            assert os.path.exists(output_path)


class TestGenerateHtmlReport:
    """Tests for _generate_html_report method."""

    def test_html_escapes_title(self, reporter):
        """Should escape XSS in title."""
        report = {
            "title": "<script>alert('xss')</script>",
            "generated_at": "2024-01-01T00:00:00",
            "summary": {
                "total_files": 0,
                "average_score": 0,
                "max_score": 0,
                "tier_distribution": {},
            },
            "files": [],
        }

        html = reporter._generate_html_report(report)

        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_html_escapes_file_paths(self, reporter):
        """Should escape XSS in file paths."""
        report = {
            "title": "Test",
            "generated_at": "2024-01-01T00:00:00",
            "summary": {
                "total_files": 1,
                "average_score": 50,
                "max_score": 50,
                "tier_distribution": {},
            },
            "files": [
                {
                    "path": "<script>alert('xss')</script>",
                    "score": 50,
                    "tier": "MEDIUM",
                    "size_bytes": 100,
                }
            ],
        }

        html = reporter._generate_html_report(report)

        # Check that script tag is escaped in output
        assert "&lt;script&gt;" in html or "alert" not in html.split("<td>")[1].split("</td>")[0]

    def test_html_tier_colors(self, reporter):
        """Should apply correct tier colors."""
        report = {
            "title": "Test",
            "generated_at": "2024-01-01T00:00:00",
            "summary": {
                "total_files": 1,
                "average_score": 50,
                "max_score": 50,
                "tier_distribution": {},
            },
            "files": [
                {"path": "/test", "score": 90, "tier": "CRITICAL", "size_bytes": 100},
            ],
        }

        html = reporter._generate_html_report(report)

        # CRITICAL color should be red (#dc3545)
        assert "#dc3545" in html


class TestReport:
    """Tests for report method."""

    def test_report_calls_scanner(self, reporter, mock_scanner):
        """Should call scanner.scan."""
        from openlabels.core.types import ReportFormat

        mock_scanner.scan.return_value = []
        reporter.report("/test/path", format=ReportFormat.JSON)

        mock_scanner.scan.assert_called_once()

    def test_report_filters_errors(self, reporter, mock_scanner):
        """Should filter out results with errors."""
        from openlabels.core.types import ScanResult, ReportFormat

        mock_scanner.scan.return_value = [
            ScanResult(path="/good", score=50, tier="MEDIUM", size_bytes=100,
                      file_type="text", entities=[], error=None),
            ScanResult(path="/bad", score=0, tier="LOW", size_bytes=0,
                      file_type="", entities=[], error="Failed to read"),
        ]

        report = reporter.report("/test", format=ReportFormat.JSON)

        assert report["summary"]["total_files"] == 1

    def test_report_sorts_by_score(self, reporter, mock_scanner):
        """Should sort by score when configured."""
        from openlabels.core.types import ScanResult, ReportFormat, ReportConfig

        mock_scanner.scan.return_value = [
            ScanResult(path="/low", score=10, tier="LOW", size_bytes=100,
                      file_type="text", entities=[], error=None),
            ScanResult(path="/high", score=90, tier="HIGH", size_bytes=100,
                      file_type="text", entities=[], error=None),
        ]

        config = ReportConfig(format=ReportFormat.JSON, sort_by="score", sort_descending=True)
        report = reporter.report("/test", config=config)

        assert report["files"][0]["path"] == "/high"

    def test_report_sorts_by_path(self, reporter, mock_scanner):
        """Should sort by path when configured."""
        from openlabels.core.types import ScanResult, ReportFormat, ReportConfig

        mock_scanner.scan.return_value = [
            ScanResult(path="/z_file", score=50, tier="MEDIUM", size_bytes=100,
                      file_type="text", entities=[], error=None),
            ScanResult(path="/a_file", score=50, tier="MEDIUM", size_bytes=100,
                      file_type="text", entities=[], error=None),
        ]

        config = ReportConfig(format=ReportFormat.JSON, sort_by="path", sort_descending=False)
        report = reporter.report("/test", config=config)

        assert report["files"][0]["path"] == "/a_file"

    def test_report_sorts_by_tier(self, reporter, mock_scanner):
        """Should sort by tier when configured."""
        from openlabels.core.types import ScanResult, ReportFormat, ReportConfig

        mock_scanner.scan.return_value = [
            ScanResult(path="/low", score=10, tier="LOW", size_bytes=100,
                      file_type="text", entities=[], error=None),
            ScanResult(path="/critical", score=95, tier="CRITICAL", size_bytes=100,
                      file_type="text", entities=[], error=None),
        ]

        config = ReportConfig(format=ReportFormat.JSON, sort_by="tier", sort_descending=True)
        report = reporter.report("/test", config=config)

        assert report["files"][0]["path"] == "/critical"

    def test_report_respects_limit(self, reporter, mock_scanner):
        """Should limit results when configured."""
        from openlabels.core.types import ScanResult, ReportFormat, ReportConfig

        mock_scanner.scan.return_value = [
            ScanResult(path=f"/file{i}", score=50, tier="MEDIUM", size_bytes=100,
                      file_type="text", entities=[], error=None)
            for i in range(10)
        ]

        config = ReportConfig(format=ReportFormat.JSON, limit=5)
        report = reporter.report("/test", config=config)

        assert len(report["files"]) == 5

    def test_report_writes_to_output(self, reporter, mock_scanner):
        """Should write to output file when specified."""
        from openlabels.core.types import ScanResult, ReportFormat

        mock_scanner.scan.return_value = [
            ScanResult(path="/test", score=50, tier="MEDIUM", size_bytes=100,
                      file_type="text", entities=[], error=None),
        ]

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            reporter.report("/test", output=output_path, format=ReportFormat.JSON)

            assert os.path.exists(output_path)
            with open(output_path) as f:
                data = json.load(f)
            assert data["summary"]["total_files"] == 1
        finally:
            os.unlink(output_path)

    def test_report_returns_data_without_output(self, reporter, mock_scanner):
        """Should return report data even without output file."""
        from openlabels.core.types import ScanResult, ReportFormat

        mock_scanner.scan.return_value = [
            ScanResult(path="/test", score=50, tier="MEDIUM", size_bytes=100,
                      file_type="text", entities=[], error=None),
        ]

        report = reporter.report("/test", format=ReportFormat.JSON)

        assert report is not None
        assert "summary" in report
        assert "files" in report

    def test_report_default_config(self, reporter, mock_scanner):
        """Should use default config when not specified."""
        from openlabels.core.types import ScanResult, ReportFormat

        mock_scanner.scan.return_value = []
        report = reporter.report("/test", format=ReportFormat.JSON)

        assert report is not None

    def test_report_recursive_default(self, reporter, mock_scanner):
        """Should recurse by default."""
        from openlabels.core.types import ReportFormat

        mock_scanner.scan.return_value = []
        reporter.report("/test", format=ReportFormat.JSON)

        mock_scanner.scan.assert_called_with("/test", recursive=True)

    def test_report_non_recursive(self, reporter, mock_scanner):
        """Should not recurse when recursive=False."""
        from openlabels.core.types import ReportFormat

        mock_scanner.scan.return_value = []
        reporter.report("/test", format=ReportFormat.JSON, recursive=False)

        mock_scanner.scan.assert_called_with("/test", recursive=False)


class TestEdgeCases:
    """Tests for edge cases."""

    def test_report_with_zero_size_files(self, reporter, mock_scanner):
        """Should handle zero-size files."""
        from openlabels.core.types import ScanResult, ReportFormat

        mock_scanner.scan.return_value = [
            ScanResult(path="/empty", score=0, tier="MINIMAL", size_bytes=0,
                      file_type="text", entities=[], error=None),
        ]

        report = reporter.report("/test", format=ReportFormat.JSON)

        assert report["summary"]["total_size_bytes"] == 0

    def test_report_with_special_characters_in_path(self, reporter, mock_scanner):
        """Should handle special characters in paths."""
        from openlabels.core.types import ScanResult, ReportFormat

        mock_scanner.scan.return_value = [
            ScanResult(path="/path with spaces/file (1).txt", score=50,
                      tier="MEDIUM", size_bytes=100, file_type="text",
                      entities=[], error=None),
        ]

        report = reporter.report("/test", format=ReportFormat.JSON)

        assert "/path with spaces/file (1).txt" in report["files"][0]["path"]

    def test_report_with_unicode_in_path(self, reporter, mock_scanner):
        """Should handle unicode in paths."""
        from openlabels.core.types import ScanResult, ReportFormat

        mock_scanner.scan.return_value = [
            ScanResult(path="/数据/文件.txt", score=50, tier="MEDIUM",
                      size_bytes=100, file_type="text", entities=[], error=None),
        ]

        report = reporter.report("/test", format=ReportFormat.JSON)

        assert "/数据/文件.txt" in report["files"][0]["path"]
