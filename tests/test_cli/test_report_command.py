"""
Tests for the report CLI command.

Tests CLI argument parsing, report generation, output formats,
and template rendering.
"""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from openlabels.cli.commands.report import add_report_parser


class TestSetupParser:
    """Test CLI argument parser setup."""

    def test_parser_creation(self):
        """Test parser is created correctly."""
        subparsers = MagicMock()
        parser_mock = MagicMock()
        subparsers.add_parser.return_value = parser_mock

        result = add_report_parser(subparsers)

        subparsers.add_parser.assert_called_once()
        assert result == parser_mock

    def test_parser_has_required_arguments(self):
        """Test parser accepts required arguments."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        report_parser = add_report_parser(subparsers)

        # Should accept path argument
        with tempfile.TemporaryDirectory() as temp:
            args = report_parser.parse_args([temp])
            assert hasattr(args, 'path')

    def test_parser_has_format_argument(self):
        """Test parser accepts format argument."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        report_parser = add_report_parser(subparsers)

        with tempfile.TemporaryDirectory() as temp:
            args = report_parser.parse_args([temp, "--format", "json"])
            assert args.format == "json"


class TestReportFormats:
    """Test different report output formats."""

    def test_json_format(self):
        """Test results_to_json produces valid JSON with summary and results."""
        from openlabels.cli.commands.report import generate_summary, results_to_json
        from openlabels.cli.commands.scan import ScanResult

        results = [
            ScanResult(path="/a.txt", score=95, tier="CRITICAL", entities={"SSN": 2}, exposure="PRIVATE"),
            ScanResult(path="/b.txt", score=50, tier="MEDIUM", entities={"EMAIL": 5}, exposure="PRIVATE"),
        ]

        summary = generate_summary(results)
        json_output = results_to_json(results, summary)
        parsed = json.loads(json_output)

        assert parsed["summary"]["total_files"] == 2
        assert len(parsed["results"]) == 2
        assert parsed["results"][0]["path"] == "/a.txt"
        assert parsed["results"][0]["score"] == 95

    def test_csv_format(self):
        """Test results_to_csv produces valid CSV with all fields."""
        import csv
        from io import StringIO
        from openlabels.cli.commands.report import results_to_csv
        from openlabels.cli.commands.scan import ScanResult

        results = [
            ScanResult(path="/a.txt", score=95, tier="CRITICAL", entities={"SSN": 2}, exposure="PRIVATE"),
            ScanResult(path="/b.txt", score=50, tier="MEDIUM", entities={"EMAIL": 5}, exposure="INTERNAL"),
        ]

        csv_output = results_to_csv(results)
        reader = csv.DictReader(StringIO(csv_output))
        rows = list(reader)

        assert len(rows) == 2
        assert rows[0]["path"] == "/a.txt"
        assert rows[0]["score"] == "95"
        assert rows[0]["tier"] == "CRITICAL"
        assert rows[1]["tier"] == "MEDIUM"

    def test_html_format(self):
        """Test results_to_html produces valid HTML structure."""
        from openlabels.cli.commands.report import generate_summary, results_to_html
        from openlabels.cli.commands.scan import ScanResult

        results = [
            ScanResult(path="/test.txt", score=80, tier="HIGH", entities={"SSN": 1}, exposure="PRIVATE"),
        ]

        summary = generate_summary(results)
        html_output = results_to_html(results, summary)

        assert "<!DOCTYPE html>" in html_output
        assert "/test.txt" in html_output
        assert "HIGH" in html_output


class TestReportContent:
    """Test report content generation."""

    def test_generate_summary_counts_files(self):
        """Test generate_summary correctly counts files."""
        from openlabels.cli.commands.report import generate_summary
        from openlabels.cli.commands.scan import ScanResult

        results = [
            ScanResult(path="/a.txt", score=95, tier="CRITICAL", entities={"SSN": 2}, exposure="PRIVATE"),
            ScanResult(path="/b.txt", score=50, tier="MEDIUM", entities={"EMAIL": 5}, exposure="PRIVATE"),
            ScanResult(path="/c.txt", score=0, tier="MINIMAL", entities={}, exposure="PRIVATE"),
        ]

        summary = generate_summary(results)

        assert summary["total_files"] == 3
        assert summary["files_at_risk"] == 2  # files with score > 0
        assert "CRITICAL" in summary["by_tier"]
        assert summary["by_tier"]["CRITICAL"] == 1

    def test_generate_summary_tracks_entities(self):
        """Test generate_summary aggregates entity counts correctly."""
        from openlabels.cli.commands.report import generate_summary
        from openlabels.cli.commands.scan import ScanResult

        results = [
            ScanResult(path="/a.txt", score=95, tier="CRITICAL", entities={"SSN": 2, "EMAIL": 1}, exposure="PRIVATE"),
            ScanResult(path="/b.txt", score=50, tier="MEDIUM", entities={"EMAIL": 5}, exposure="PRIVATE"),
        ]

        summary = generate_summary(results)

        assert "SSN" in summary["by_entity"]
        assert "EMAIL" in summary["by_entity"]
        assert summary["by_entity"]["SSN"] == 2
        assert summary["by_entity"]["EMAIL"] == 6  # 1 + 5

    def test_generate_summary_tier_distribution(self):
        """Test generate_summary produces accurate tier distribution."""
        from openlabels.cli.commands.report import generate_summary
        from openlabels.cli.commands.scan import ScanResult

        results = [
            ScanResult(path="/a.txt", score=95, tier="CRITICAL", entities={}, exposure="PRIVATE"),
            ScanResult(path="/b.txt", score=85, tier="HIGH", entities={}, exposure="PRIVATE"),
            ScanResult(path="/c.txt", score=80, tier="HIGH", entities={}, exposure="PRIVATE"),
            ScanResult(path="/d.txt", score=50, tier="MEDIUM", entities={}, exposure="PRIVATE"),
        ]

        summary = generate_summary(results)

        assert summary["by_tier"]["CRITICAL"] == 1
        assert summary["by_tier"]["HIGH"] == 2
        assert summary["by_tier"]["MEDIUM"] == 1


class TestReportFilters:
    """Test report filtering options."""

    def test_filter_results_by_min_score(self):
        """Test filtering ScanResults by minimum score."""
        from openlabels.cli.commands.report import generate_summary
        from openlabels.cli.commands.scan import ScanResult

        all_results = [
            ScanResult(path="/a.txt", score=95, tier="CRITICAL", entities={}, exposure="PRIVATE"),
            ScanResult(path="/b.txt", score=50, tier="MEDIUM", entities={}, exposure="PRIVATE"),
            ScanResult(path="/c.txt", score=30, tier="LOW", entities={}, exposure="PRIVATE"),
        ]

        min_score = 50
        filtered = [r for r in all_results if r.score >= min_score]

        assert len(filtered) == 2
        assert all(r.score >= 50 for r in filtered)
        # Verify summary works with filtered results
        summary = generate_summary(filtered)
        assert summary["total_files"] == 2

    def test_filter_results_by_tier(self):
        """Test filtering ScanResults by tier."""
        from openlabels.cli.commands.report import generate_summary
        from openlabels.cli.commands.scan import ScanResult

        all_results = [
            ScanResult(path="/a.txt", score=95, tier="CRITICAL", entities={}, exposure="PRIVATE"),
            ScanResult(path="/b.txt", score=80, tier="HIGH", entities={}, exposure="PRIVATE"),
            ScanResult(path="/c.txt", score=20, tier="LOW", entities={}, exposure="PRIVATE"),
        ]

        high_risk_tiers = ("CRITICAL", "HIGH")
        filtered = [r for r in all_results if r.tier in high_risk_tiers]

        assert len(filtered) == 2
        assert all(r.tier in high_risk_tiers for r in filtered)


class TestReportOutput:
    """Test report output options."""

    def test_json_output_to_file(self):
        """Test writing JSON report to file."""
        from openlabels.cli.commands.report import generate_summary, results_to_json
        from openlabels.cli.commands.scan import ScanResult

        results = [
            ScanResult(path="/a.txt", score=75, tier="HIGH", entities={"SSN": 1}, exposure="PRIVATE"),
        ]
        summary = generate_summary(results)
        json_output = results_to_json(results, summary)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json_output)
            f.flush()

            # Read back and verify structure
            with open(f.name, 'r') as rf:
                loaded = json.load(rf)

            assert loaded["summary"]["total_files"] == 1
            assert loaded["results"][0]["path"] == "/a.txt"
            assert loaded["results"][0]["score"] == 75

            Path(f.name).unlink()

    def test_csv_output_has_header(self):
        """Test CSV output includes header row."""
        from openlabels.cli.commands.report import results_to_csv
        from openlabels.cli.commands.scan import ScanResult

        results = [
            ScanResult(path="/test.txt", score=50, tier="MEDIUM", entities={}, exposure="PRIVATE"),
        ]

        csv_output = results_to_csv(results)
        lines = csv_output.strip().split("\n")

        assert len(lines) >= 2  # header + at least one data row
        header = lines[0].lower()
        assert "path" in header
        assert "score" in header
        assert "tier" in header


class TestReportErrorHandling:
    """Test error handling in report command."""

    def test_empty_directory(self):
        """Test report on empty directory produces valid report with zero files."""
        from openlabels.cli.commands.report import generate_summary, results_to_json

        with tempfile.TemporaryDirectory() as temp:
            # Empty results list (no files in directory)
            results = []

            # Summary should handle empty results gracefully
            summary = generate_summary(results)

            assert summary["total_files"] == 0
            assert summary["files_at_risk"] == 0
            assert summary["by_tier"] == {}
            assert summary["by_entity"] == {}

            # JSON output should also work
            json_output = results_to_json(results, summary)
            parsed = json.loads(json_output)

            assert parsed["summary"]["total_files"] == 0
            assert parsed["results"] == []

    def test_no_matching_files(self):
        """Test report when filter matches no files."""
        from openlabels.cli.commands.report import generate_summary
        from openlabels.cli.commands.scan import ScanResult

        # Create results where none match a high score filter
        results = [
            ScanResult(path="/a.txt", score=10, tier="LOW", entities={}, exposure="PRIVATE"),
            ScanResult(path="/b.txt", score=5, tier="MINIMAL", entities={}, exposure="PRIVATE"),
            ScanResult(path="/c.txt", score=0, tier="MINIMAL", entities={}, exposure="PRIVATE"),
        ]

        # Filter for high score (simulating filter that matches nothing)
        filtered_results = [r for r in results if r.score > 90]

        assert len(filtered_results) == 0

        # Summary should work with empty filtered results
        summary = generate_summary(filtered_results)
        assert summary["total_files"] == 0

    def test_partial_scan_failure(self):
        """Test report includes results with errors."""
        from openlabels.cli.commands.report import generate_summary, results_to_csv
        from openlabels.cli.commands.scan import ScanResult

        # Mix of successful scans and errors
        results = [
            ScanResult(path="/good1.txt", score=50, tier="MEDIUM", entities={"EMAIL": 2}, exposure="PRIVATE"),
            ScanResult(path="/error.txt", score=0, tier="UNKNOWN", entities={}, exposure="PRIVATE", error="Permission denied"),
            ScanResult(path="/good2.txt", score=80, tier="HIGH", entities={"SSN": 1}, exposure="PRIVATE"),
        ]

        # Summary should count all files including errors
        summary = generate_summary(results)
        assert summary["total_files"] == 3

        # CSV should include error column
        csv_output = results_to_csv(results)
        lines = csv_output.strip().split("\n")

        assert len(lines) == 4  # header + 3 results
        assert "error" in lines[0].lower()  # Header has error column
        assert "Permission denied" in csv_output  # Error is in output
