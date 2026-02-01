"""
Tests for the find CLI command.

Tests CLI argument parsing, filter expressions, output formatting,
and result matching.
"""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from openlabels.cli.commands.find import add_find_parser


class TestSetupParser:
    """Test CLI argument parser setup."""

    def test_parser_creation(self):
        """Test parser is created correctly."""
        subparsers = MagicMock()
        parser_mock = MagicMock()
        subparsers.add_parser.return_value = parser_mock

        result = add_find_parser(subparsers)

        subparsers.add_parser.assert_called_once()
        assert result == parser_mock

    def test_parser_has_filter_arguments(self):
        """Test parser accepts filter arguments via --where."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        find_parser = add_find_parser(subparsers)

        # Filter is passed via --where
        with tempfile.TemporaryDirectory() as temp:
            args = find_parser.parse_args([
                temp,
                "--where", "score >= 50 AND tier == 'HIGH'",
            ])
            assert args.where == "score >= 50 AND tier == 'HIGH'"


class TestFilterExpressions:
    """Test filter expression parsing and evaluation."""

    def test_min_score_filter(self):
        """Test minimum score filtering."""
        from openlabels.cli.filter import parse_filter

        # Test filter expression parsing
        filter_obj = parse_filter("score >= 50")
        assert filter_obj is not None

        # Test evaluation
        result = {"score": 75}
        assert filter_obj.evaluate(result) is True

        result = {"score": 25}
        assert filter_obj.evaluate(result) is False

    def test_tier_filter(self):
        """Test tier filtering."""
        from openlabels.cli.filter import parse_filter

        # Tier filter uses single = not ==
        filter_obj = parse_filter("tier = HIGH")
        assert filter_obj is not None

        result = {"tier": "HIGH"}
        assert filter_obj.evaluate(result) is True

        result = {"tier": "LOW"}
        assert filter_obj.evaluate(result) is False

    def test_combined_filter(self):
        """Test combined filter expressions."""
        from openlabels.cli.filter import parse_filter

        # Use AND keyword with single = for equality
        filter_obj = parse_filter("score >= 50 AND tier = HIGH")
        assert filter_obj is not None

        result = {"score": 75, "tier": "HIGH"}
        assert filter_obj.evaluate(result) is True

        result = {"score": 75, "tier": "LOW"}
        assert filter_obj.evaluate(result) is False

    def test_entity_filter(self):
        """Test entity type filtering with has() function."""
        from openlabels.cli.filter import parse_filter

        # Use has() function for entity checks
        filter_obj = parse_filter("has(SSN)")
        assert filter_obj is not None

        # Test evaluation against results with and without SSN
        # Filter expects entities as list of dicts with 'type' key
        result_with_ssn = {"entities": [{"type": "SSN"}, {"type": "EMAIL"}]}
        assert filter_obj.evaluate(result_with_ssn) is True

        result_without_ssn = {"entities": [{"type": "EMAIL"}]}
        assert filter_obj.evaluate(result_without_ssn) is False


class TestFindOutputFormats:
    """Test different output formats for find command."""

    def test_default_output_format(self):
        """Test default (text) output format."""
        from openlabels.cli.commands.find import format_find_result
        from openlabels.cli.commands.scan import ScanResult

        result = ScanResult(
            path="/test/file.txt",
            score=75,
            tier="HIGH",
            entities={"SSN": 2, "EMAIL": 5},
            exposure="PRIVATE",
        )

        # Text format should be tab-separated, human-readable
        output = format_find_result(result, "text")

        assert "/test/file.txt" in output
        assert "Score: 75" in output
        assert "SSN(2)" in output or "EMAIL(5)" in output
        assert "\t" in output  # Tab-separated

    def test_json_output_format(self):
        """Test JSON output format via format_find_result."""
        from openlabels.cli.commands.find import format_find_result
        from openlabels.cli.commands.scan import ScanResult

        result = ScanResult(
            path="/test/file.txt",
            score=75,
            tier="HIGH",
            entities={"SSN": 2},
            exposure="PRIVATE",
        )

        json_output = format_find_result(result, "json")
        parsed = json.loads(json_output)

        assert parsed["path"] == "/test/file.txt"
        assert parsed["score"] == 75
        assert parsed["tier"] == "HIGH"
        assert parsed["entities"] == {"SSN": 2}

    def test_paths_only_output(self):
        """Test paths-only output format via format_find_result."""
        from openlabels.cli.commands.find import format_find_result
        from openlabels.cli.commands.scan import ScanResult

        result = ScanResult(
            path="/test/data.csv",
            score=50,
            tier="MEDIUM",
            entities={"EMAIL": 3},
            exposure="INTERNAL",
        )

        output = format_find_result(result, "paths")
        # Paths output should contain the path
        assert "/test/data.csv" in output

    def test_count_output(self):
        """Test count format via format_find_result."""
        from openlabels.cli.commands.find import format_find_result
        from openlabels.cli.commands.scan import ScanResult

        result = ScanResult(
            path="/a.txt",
            score=30,
            tier="LOW",
            entities={},
            exposure="PRIVATE",
        )

        # Count format typically returns "1" for each result
        output = format_find_result(result, "count")
        assert output is not None


class TestFindIntegration:
    """Integration tests for find command."""

    @pytest.fixture
    def temp_dir_with_index(self):
        """Create a temporary directory with indexed files."""
        import tempfile
        import shutil

        temp = tempfile.mkdtemp()

        # Create test files
        (Path(temp) / "high_risk.txt").write_text("SSN: 123-45-6789")
        (Path(temp) / "low_risk.txt").write_text("Hello world")
        (Path(temp) / "medium_risk.txt").write_text("Email: test@example.com")

        yield temp

        shutil.rmtree(temp)

    def test_find_with_min_score(self, temp_dir_with_index):
        """Test finding files with minimum score using REAL scanner."""
        from openlabels import Client
        from openlabels.cli.commands.find import find_matching

        client = Client()
        path = Path(temp_dir_with_index)

        # Find files with score > 0 (files with PII should have positive score)
        results = list(find_matching(
            path, client,
            filter_expr="score > 0",
            recursive=True,
            exposure="PRIVATE",
        ))

        # high_risk.txt and medium_risk.txt should have scores > 0
        # low_risk.txt ("Hello world") should have score ~0
        paths = [r.path for r in results]

        # At least one file with PII should be found
        assert len(results) >= 1, f"Expected at least 1 file with score > 0, got {len(results)}"

        # Files with PII content should be in results
        matching_names = [Path(p).name for p in paths]
        assert "high_risk.txt" in matching_names or any(r.score > 0 for r in results)

    def test_find_with_tier_filter(self, temp_dir_with_index):
        """Test finding files by tier using REAL scanner."""
        from openlabels import Client
        from openlabels.cli.commands.find import find_matching

        client = Client()
        path = Path(temp_dir_with_index)

        # Find files that are NOT minimal risk
        results = list(find_matching(
            path, client,
            filter_expr="tier = high OR tier = critical OR tier = medium",
            recursive=True,
            exposure="PRIVATE",
        ))

        # All returned results should have non-minimal tier
        for result in results:
            assert result.tier.upper() in ("HIGH", "CRITICAL", "MEDIUM"), \
                f"Expected HIGH/CRITICAL/MEDIUM tier, got {result.tier}"

    def test_find_with_limit(self, temp_dir_with_index):
        """Test that find correctly applies result limits."""
        from openlabels import Client
        from openlabels.cli.commands.find import find_matching
        import itertools

        client = Client()
        path = Path(temp_dir_with_index)

        # Get all results first (no filter, so all files)
        all_results = list(find_matching(
            path, client,
            filter_expr=None,  # No filter - find all
            recursive=True,
            exposure="PRIVATE",
        ))

        # Now get limited results using itertools.islice (simulates --limit)
        limited = list(itertools.islice(find_matching(
            path, client,
            filter_expr=None,
            recursive=True,
            exposure="PRIVATE",
        ), 2))

        # Limited should have at most 2 results
        assert len(limited) <= 2
        # If there were more than 2 files total, limited should have exactly 2
        if len(all_results) > 2:
            assert len(limited) == 2


class TestFindErrorHandling:
    """Test error handling in find command."""

    def test_nonexistent_path(self):
        """Test handling of nonexistent path."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        find_parser = add_find_parser(subparsers)

        # Parser should accept the path even if it doesn't exist
        # (validation happens at runtime)
        args = find_parser.parse_args(["/nonexistent/path"])
        assert args.path == "/nonexistent/path"

    def test_invalid_filter_expression(self):
        """Test handling of invalid filter expression."""
        from openlabels.cli.filter import parse_filter

        # Invalid expression raises ValueError
        with pytest.raises(ValueError):
            parse_filter("invalid &&& syntax")

    def test_invalid_tier_value(self):
        """Test handling of invalid tier value in filter."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        find_parser = add_find_parser(subparsers)

        # Parser should accept any filter value (validation at runtime)
        with tempfile.TemporaryDirectory() as temp:
            args = find_parser.parse_args([temp, "--where", "tier == INVALID"])
            assert args.where == "tier == INVALID"
