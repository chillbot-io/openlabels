"""
Tests for openlabels/output/report.py

Tests the report generation functionality across all formats:
JSON, CSV, HTML, Markdown, and JSONL.
"""

import json
import tempfile
from pathlib import Path

import pytest

from openlabels.adapters.base import Entity
from openlabels.core.types import ScanResult, ReportConfig, ReportFormat
from openlabels.output.report import (
    ReportGenerator,
    ReportSummary,
    results_to_json,
    results_to_csv,
    results_to_html,
    results_to_markdown,
    generate_report,
)


# --- Test Fixtures ---

@pytest.fixture
def sample_results():
    """Sample scan results for testing."""
    return [
        ScanResult(
            path="/data/patient_records.csv",
            size_bytes=1024000,
            file_type=".csv",
            score=85,
            tier="CRITICAL",
            entities=[
                Entity(type="SSN", count=10, confidence=0.95, source="scanner"),
                Entity(type="NAME", count=25, confidence=0.9, source="scanner"),
            ],
        ),
        ScanResult(
            path="/data/internal_memo.docx",
            size_bytes=51200,
            file_type=".docx",
            score=45,
            tier="MEDIUM",
            entities=[
                Entity(type="EMAIL", count=5, confidence=0.85, source="scanner"),
            ],
        ),
        ScanResult(
            path="/data/public_info.txt",
            size_bytes=2048,
            file_type=".txt",
            score=5,
            tier="MINIMAL",
            entities=[],
        ),
    ]


@pytest.fixture
def sample_results_dicts():
    """Sample results as dictionaries."""
    return [
        {
            "path": "/data/file1.csv",
            "size_bytes": 1000,
            "file_type": ".csv",
            "score": 75,
            "tier": "HIGH",
            "entities": [{"type": "PHONE", "count": 3}],
        },
        {
            "path": "/data/file2.txt",
            "size_bytes": 500,
            "score": 25,
            "tier": "LOW",
            "entities": [],
        },
    ]


@pytest.fixture
def empty_results():
    """Empty results list."""
    return []


@pytest.fixture
def results_with_errors():
    """Results including error entries."""
    return [
        ScanResult(path="/data/good.csv", score=50, tier="MEDIUM", size_bytes=1000),
        ScanResult(path="/data/bad.csv", error="Permission denied"),
        ScanResult(path="/data/missing.csv", error="File not found"),
    ]


# --- ReportSummary Tests ---

class TestReportSummary:
    """Tests for ReportSummary dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        summary = ReportSummary(
            total_files=10,
            total_size_bytes=1024000,
            average_score=55.5,
            median_score=50.0,
            max_score=95,
            min_score=5,
            tier_distribution={"HIGH": 3, "MEDIUM": 5, "LOW": 2},
            entity_types_found=["SSN", "NAME", "EMAIL"],
            total_entities=50,
            entity_distribution={"SSN": 20, "NAME": 25, "EMAIL": 5},
            error_count=2,
        )

        d = summary.to_dict()

        assert d["total_files"] == 10
        assert d["total_size_bytes"] == 1024000
        assert d["average_score"] == 55.5
        assert d["max_score"] == 95
        assert d["tier_distribution"] == {"HIGH": 3, "MEDIUM": 5, "LOW": 2}
        assert d["total_entities"] == 50


# --- ReportGenerator Tests ---

class TestReportGenerator:
    """Tests for ReportGenerator class."""

    def test_init_with_scan_results(self, sample_results):
        """Test initialization with ScanResult objects."""
        gen = ReportGenerator(sample_results)

        assert gen.summary.total_files == 3
        assert gen.summary.max_score == 85
        assert gen.summary.min_score == 5

    def test_init_with_dicts(self, sample_results_dicts):
        """Test initialization with dictionaries."""
        gen = ReportGenerator(sample_results_dicts)

        assert gen.summary.total_files == 2
        assert gen.summary.max_score == 75

    def test_init_empty_results(self, empty_results):
        """Test initialization with empty results."""
        gen = ReportGenerator(empty_results)

        assert gen.summary.total_files == 0
        assert gen.summary.average_score == 0.0
        assert gen.summary.max_score == 0

    def test_summary_with_errors(self, results_with_errors):
        """Test that errors are tracked but excluded from score stats."""
        gen = ReportGenerator(results_with_errors)

        assert gen.summary.total_files == 3
        assert gen.summary.error_count == 2
        # Only the non-error file contributes to scores
        assert gen.summary.average_score == 50.0
        assert gen.summary.max_score == 50

    def test_tier_distribution(self, sample_results):
        """Test tier distribution counting."""
        gen = ReportGenerator(sample_results)

        assert gen.summary.tier_distribution.get("CRITICAL") == 1
        assert gen.summary.tier_distribution.get("MEDIUM") == 1
        assert gen.summary.tier_distribution.get("MINIMAL") == 1

    def test_entity_distribution(self, sample_results):
        """Test entity type aggregation."""
        gen = ReportGenerator(sample_results)

        assert gen.summary.entity_distribution.get("SSN") == 10
        assert gen.summary.entity_distribution.get("NAME") == 25
        assert gen.summary.entity_distribution.get("EMAIL") == 5
        assert gen.summary.total_entities == 40

    def test_median_score_odd(self):
        """Test median calculation with odd number of results."""
        results = [
            {"path": "/a", "score": 10, "tier": "LOW"},
            {"path": "/b", "score": 50, "tier": "MEDIUM"},
            {"path": "/c", "score": 90, "tier": "CRITICAL"},
        ]
        gen = ReportGenerator(results)

        assert gen.summary.median_score == 50

    def test_median_score_even(self):
        """Test median calculation with even number of results."""
        results = [
            {"path": "/a", "score": 10, "tier": "LOW"},
            {"path": "/b", "score": 40, "tier": "MEDIUM"},
            {"path": "/c", "score": 60, "tier": "HIGH"},
            {"path": "/d", "score": 90, "tier": "CRITICAL"},
        ]
        gen = ReportGenerator(results)

        assert gen.summary.median_score == 50  # (40 + 60) / 2


# --- JSON Format Tests ---

class TestJsonFormat:
    """Tests for JSON report generation."""

    def test_to_json_structure(self, sample_results):
        """Test JSON output has correct structure."""
        gen = ReportGenerator(sample_results)
        output = gen.to_json()

        data = json.loads(output)

        assert "title" in data
        assert "generated_at" in data
        assert "summary" in data
        assert "files" in data

    def test_to_json_summary(self, sample_results):
        """Test JSON summary section."""
        gen = ReportGenerator(sample_results)
        output = gen.to_json()

        data = json.loads(output)
        summary = data["summary"]

        assert summary["total_files"] == 3
        assert summary["max_score"] == 85

    def test_to_json_files(self, sample_results):
        """Test JSON files section."""
        gen = ReportGenerator(sample_results)
        output = gen.to_json()

        data = json.loads(output)
        files = data["files"]

        assert len(files) == 3
        # Should be sorted by score descending by default
        assert files[0]["score"] == 85
        assert files[1]["score"] == 45
        assert files[2]["score"] == 5

    def test_to_json_indent(self, sample_results):
        """Test JSON indentation."""
        gen = ReportGenerator(sample_results)

        output_default = gen.to_json()
        output_compact = gen.to_json(indent=0)

        assert len(output_default) > len(output_compact)


# --- JSONL Format Tests ---

class TestJsonlFormat:
    """Tests for JSONL report generation."""

    def test_to_jsonl_lines(self, sample_results):
        """Test JSONL has one object per line."""
        gen = ReportGenerator(sample_results)
        output = gen.to_jsonl()

        lines = output.strip().split('\n')
        assert len(lines) == 3

        # Each line should be valid JSON
        for line in lines:
            data = json.loads(line)
            assert "path" in data
            assert "score" in data

    def test_to_jsonl_order(self, sample_results):
        """Test JSONL respects sort order."""
        gen = ReportGenerator(sample_results)
        output = gen.to_jsonl()

        lines = output.strip().split('\n')
        scores = [json.loads(line)["score"] for line in lines]

        # Default is descending by score
        assert scores == sorted(scores, reverse=True)


# --- CSV Format Tests ---

class TestCsvFormat:
    """Tests for CSV report generation."""

    def test_to_csv_header(self, sample_results):
        """Test CSV has correct header."""
        gen = ReportGenerator(sample_results)
        output = gen.to_csv()

        lines = output.strip().split('\n')
        header = lines[0]

        assert "path" in header
        assert "score" in header
        assert "tier" in header
        assert "size_bytes" in header

    def test_to_csv_rows(self, sample_results):
        """Test CSV has correct number of data rows."""
        gen = ReportGenerator(sample_results)
        output = gen.to_csv()

        lines = output.strip().split('\n')
        # 1 header + 3 data rows
        assert len(lines) == 4

    def test_to_csv_with_entities(self, sample_results):
        """Test CSV includes entities when configured."""
        config = ReportConfig(include_entities=True)
        gen = ReportGenerator(sample_results, config)
        output = gen.to_csv()

        assert "entities" in output.split('\n')[0]
        assert "SSN:10" in output

    def test_to_csv_without_entities(self, sample_results):
        """Test CSV excludes entities when not configured."""
        config = ReportConfig(include_entities=False)
        gen = ReportGenerator(sample_results, config)
        output = gen.to_csv()

        header = output.split('\n')[0]
        assert "entities" not in header


# --- HTML Format Tests ---

class TestHtmlFormat:
    """Tests for HTML report generation."""

    def test_to_html_structure(self, sample_results):
        """Test HTML has valid structure."""
        gen = ReportGenerator(sample_results)
        output = gen.to_html()

        assert output.startswith("<!DOCTYPE html>")
        assert "<html" in output
        assert "</html>" in output
        assert "<head>" in output
        assert "<body>" in output

    def test_to_html_title(self, sample_results):
        """Test HTML includes title."""
        config = ReportConfig(title="Test Report")
        gen = ReportGenerator(sample_results, config)
        output = gen.to_html()

        assert "<title>Test Report</title>" in output
        assert "<h1>Test Report</h1>" in output

    def test_to_html_xss_prevention(self):
        """Test HTML escapes user-controlled data."""
        malicious_results = [
            {
                "path": "/data/<script>alert('xss')</script>.txt",
                "score": 50,
                "tier": "MEDIUM",
                "size_bytes": 100,
            }
        ]
        gen = ReportGenerator(malicious_results)
        output = gen.to_html()

        # Script tags should be escaped
        assert "<script>" not in output
        assert "&lt;script&gt;" in output

    def test_to_html_tier_badges(self, sample_results):
        """Test HTML includes tier badges."""
        gen = ReportGenerator(sample_results)
        output = gen.to_html()

        assert "tier-badge" in output
        assert "tier-CRITICAL" in output
        assert "tier-MEDIUM" in output

    def test_to_html_summary_stats(self, sample_results):
        """Test HTML includes summary statistics."""
        gen = ReportGenerator(sample_results)
        output = gen.to_html()

        assert "Total Files" in output
        assert "Average Score" in output
        assert "Max Score" in output


# --- Markdown Format Tests ---

class TestMarkdownFormat:
    """Tests for Markdown report generation."""

    def test_to_markdown_structure(self, sample_results):
        """Test Markdown has correct structure."""
        gen = ReportGenerator(sample_results)
        output = gen.to_markdown()

        assert output.startswith("#")
        assert "## Summary" in output
        assert "## Files" in output

    def test_to_markdown_title(self, sample_results):
        """Test Markdown includes custom title."""
        config = ReportConfig(title="Custom Title")
        gen = ReportGenerator(sample_results, config)
        output = gen.to_markdown()

        assert "# Custom Title" in output

    def test_to_markdown_table(self, sample_results):
        """Test Markdown includes file table."""
        gen = ReportGenerator(sample_results)
        output = gen.to_markdown()

        assert "| Path | Score | Tier | Size |" in output
        assert "|------|-------|------|------|" in output

    def test_to_markdown_tier_distribution(self, sample_results):
        """Test Markdown includes tier distribution."""
        gen = ReportGenerator(sample_results)
        output = gen.to_markdown()

        assert "### Risk Distribution" in output
        assert "**CRITICAL:**" in output


# --- Sorting and Limiting Tests ---

class TestSortingAndLimiting:
    """Tests for result sorting and limiting."""

    def test_sort_by_score_descending(self, sample_results):
        """Test sorting by score descending (default)."""
        gen = ReportGenerator(sample_results)
        output = gen.to_json()

        files = json.loads(output)["files"]
        scores = [f["score"] for f in files]

        assert scores == sorted(scores, reverse=True)

    def test_sort_by_score_ascending(self, sample_results):
        """Test sorting by score ascending."""
        config = ReportConfig(sort_by="score", sort_descending=False)
        gen = ReportGenerator(sample_results, config)
        output = gen.to_json()

        files = json.loads(output)["files"]
        scores = [f["score"] for f in files]

        assert scores == sorted(scores)

    def test_sort_by_path(self, sample_results):
        """Test sorting by path."""
        config = ReportConfig(sort_by="path", sort_descending=False)
        gen = ReportGenerator(sample_results, config)
        output = gen.to_json()

        files = json.loads(output)["files"]
        paths = [f["path"] for f in files]

        assert paths == sorted(paths)

    def test_limit_results(self, sample_results):
        """Test limiting number of results."""
        config = ReportConfig(limit=2)
        gen = ReportGenerator(sample_results, config)
        output = gen.to_json()

        files = json.loads(output)["files"]
        assert len(files) == 2

    def test_limit_larger_than_results(self, sample_results):
        """Test limit larger than result count."""
        config = ReportConfig(limit=100)
        gen = ReportGenerator(sample_results, config)
        output = gen.to_json()

        files = json.loads(output)["files"]
        assert len(files) == 3


# --- Save to File Tests ---

class TestSaveToFile:
    """Tests for saving reports to files."""

    def test_save_json(self, sample_results):
        """Test saving JSON report to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.json"
            gen = ReportGenerator(sample_results)
            gen.save(path)

            assert path.exists()
            content = path.read_text()
            data = json.loads(content)
            assert "files" in data

    def test_save_csv(self, sample_results):
        """Test saving CSV report to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.csv"
            gen = ReportGenerator(sample_results)
            gen.save(path)

            assert path.exists()
            content = path.read_text()
            assert "path,score,tier" in content

    def test_save_html(self, sample_results):
        """Test saving HTML report to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.html"
            gen = ReportGenerator(sample_results)
            gen.save(path)

            assert path.exists()
            content = path.read_text()
            assert "<!DOCTYPE html>" in content

    def test_save_markdown(self, sample_results):
        """Test saving Markdown report to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.md"
            gen = ReportGenerator(sample_results)
            gen.save(path)

            assert path.exists()
            content = path.read_text()
            assert "# " in content

    def test_save_creates_parent_dirs(self, sample_results):
        """Test save creates parent directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nested" / "dir" / "report.json"
            gen = ReportGenerator(sample_results)
            gen.save(path)

            assert path.exists()


# --- Convenience Function Tests ---

class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_results_to_json(self, sample_results):
        """Test results_to_json function."""
        output = results_to_json(sample_results)

        data = json.loads(output)
        assert "files" in data
        assert len(data["files"]) == 3

    def test_results_to_csv(self, sample_results):
        """Test results_to_csv function."""
        output = results_to_csv(sample_results)

        assert "path,score,tier" in output
        lines = output.strip().split('\n')
        assert len(lines) == 4

    def test_results_to_html(self, sample_results):
        """Test results_to_html function."""
        output = results_to_html(sample_results)

        assert "<!DOCTYPE html>" in output
        assert "<table>" in output

    def test_results_to_markdown(self, sample_results):
        """Test results_to_markdown function."""
        output = results_to_markdown(sample_results)

        assert "## Summary" in output
        assert "| Path |" in output

    def test_generate_report_function(self, sample_results):
        """Test generate_report convenience function."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.json"
            generate_report(sample_results, path)

            assert path.exists()
            data = json.loads(path.read_text())
            assert "files" in data


# --- Size Formatting Tests ---

class TestSizeFormatting:
    """Tests for file size formatting."""

    def test_format_bytes(self, sample_results):
        """Test bytes formatting."""
        gen = ReportGenerator([{"path": "/a", "size_bytes": 500, "score": 0, "tier": "MINIMAL"}])
        output = gen.to_html()

        assert "500 B" in output

    def test_format_kilobytes(self, sample_results):
        """Test KB formatting."""
        gen = ReportGenerator([{"path": "/a", "size_bytes": 2048, "score": 0, "tier": "MINIMAL"}])
        output = gen.to_html()

        assert "KB" in output

    def test_format_megabytes(self, sample_results):
        """Test MB formatting."""
        gen = ReportGenerator([{"path": "/a", "size_bytes": 1048576, "score": 0, "tier": "MINIMAL"}])
        output = gen.to_html()

        assert "MB" in output

    def test_format_gigabytes(self, sample_results):
        """Test GB formatting."""
        gen = ReportGenerator([{"path": "/a", "size_bytes": 1073741824, "score": 0, "tier": "MINIMAL"}])
        output = gen.to_html()

        assert "GB" in output
