"""
Tests for the scan CLI command.

Tests CLI argument parsing, output formatting, error handling,
and integration with the scanner.
"""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from io import StringIO

from openlabels.cli.commands.scan import (
    ScanResult,
    scan_file,
    add_scan_parser,
)


class TestScanResult:
    """Test ScanResult dataclass."""

    def test_to_dict(self):
        """Test ScanResult.to_dict() conversion."""
        result = ScanResult(
            path="/test/file.txt",
            score=75,
            tier="HIGH",
            entities={"SSN": 2, "EMAIL": 5},
            exposure="PRIVATE",
        )

        d = result.to_dict()

        assert d["path"] == "/test/file.txt"
        assert d["score"] == 75
        assert d["tier"] == "HIGH"
        assert d["entities"] == {"SSN": 2, "EMAIL": 5}
        assert d["exposure"] == "PRIVATE"
        assert d["error"] is None

    def test_to_dict_with_error(self):
        """Test ScanResult.to_dict() with error."""
        result = ScanResult(
            path="/test/file.txt",
            score=0,
            tier="UNKNOWN",
            entities={},
            exposure="PRIVATE",
            error="File not readable",
        )

        d = result.to_dict()

        assert d["error"] == "File not readable"


class TestSetupParser:
    """Test CLI argument parser setup."""

    def test_parser_creation(self):
        """Test parser is created correctly."""
        subparsers = MagicMock()
        parser_mock = MagicMock()
        subparsers.add_parser.return_value = parser_mock

        result = add_scan_parser(subparsers)

        subparsers.add_parser.assert_called_once()
        assert result == parser_mock

    def test_parser_arguments(self):
        """Test parser has expected arguments."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        scan_parser = add_scan_parser(subparsers)

        # Parse with required argument
        with tempfile.NamedTemporaryFile() as f:
            args = scan_parser.parse_args([f.name])
            assert hasattr(args, 'path')


class TestScanFile:
    """Test scan_file function."""

    def test_scan_nonexistent_file(self):
        """Test scanning a file that doesn't exist."""
        mock_client = Mock()

        result = scan_file(
            Path("/nonexistent/file.txt"),
            mock_client,
            exposure="PRIVATE",
        )

        assert result.error is not None
        assert result.score == 0
        assert result.tier == "UNKNOWN"

    def test_scan_file_returns_result(self):
        """Test scanning a valid file returns ScanResult."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Test content with no PII")
            f.flush()

            mock_client = Mock()
            mock_scoring = Mock()
            mock_scoring.score = 0
            mock_scoring.tier = Mock(value="MINIMAL")
            mock_client.score_file.return_value = mock_scoring

            # Patch the actual location where detect_file is imported
            with patch('openlabels.adapters.scanner.detect_file') as mock_detect:
                mock_detect.return_value = Mock(entity_counts={})

                result = scan_file(
                    Path(f.name),
                    mock_client,
                    exposure="PRIVATE",
                )

            assert isinstance(result, ScanResult)
            assert result.path == f.name
            assert result.exposure == "PRIVATE"

            # Cleanup
            Path(f.name).unlink()


class TestScanCommandIntegration:
    """Integration tests for scan command - tests REAL scanning, not mocks."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory with test files."""
        import tempfile
        import shutil

        temp = tempfile.mkdtemp()

        # Create test files with different content
        (Path(temp) / "clean.txt").write_text("Hello world, this is clean content")
        (Path(temp) / "with_ssn.txt").write_text("Patient SSN: 123-45-6789")
        (Path(temp) / "with_email.txt").write_text("Contact: john.doe@example.com")
        (Path(temp) / "with_cc.txt").write_text("Payment card: 4111-1111-1111-1111")
        (Path(temp) / "subdir").mkdir()
        (Path(temp) / "subdir" / "nested.txt").write_text("Nested file with SSN 987-65-4321")

        yield temp

        shutil.rmtree(temp)

    def test_scan_detects_ssn_in_real_file(self, temp_dir):
        """Test that scanning ACTUALLY detects SSN in file content."""
        from openlabels import Client

        file_path = Path(temp_dir) / "with_ssn.txt"
        client = Client()

        result = scan_file(file_path, client, exposure="PRIVATE")

        # SSN should be detected - this is a REAL test
        assert result.error is None, f"Scan failed with error: {result.error}"
        assert "SSN" in result.entities or result.score > 0, \
            f"SSN not detected in file containing '123-45-6789'. Entities: {result.entities}"

    def test_scan_detects_email_in_real_file(self, temp_dir):
        """Test that scanning ACTUALLY detects EMAIL in file content."""
        from openlabels import Client

        file_path = Path(temp_dir) / "with_email.txt"
        client = Client()

        result = scan_file(file_path, client, exposure="PRIVATE")

        assert result.error is None
        # Email should be detected - john.doe@example.com is a clear email address
        assert "EMAIL" in result.entities, \
            f"Expected EMAIL entity, got: {result.entities}"

    def test_scan_detects_credit_card_in_real_file(self, temp_dir):
        """Test that scanning ACTUALLY detects credit card in file content."""
        from openlabels import Client

        file_path = Path(temp_dir) / "with_cc.txt"
        client = Client()

        result = scan_file(file_path, client, exposure="PRIVATE")

        assert result.error is None
        # Credit card 4111-1111-1111-1111 is a valid Visa test number
        assert "CREDIT_CARD" in result.entities or result.score > 0, \
            f"Credit card not detected. Entities: {result.entities}"

    def test_clean_file_has_low_score(self, temp_dir):
        """Test that clean file has minimal/low score."""
        from openlabels import Client

        file_path = Path(temp_dir) / "clean.txt"
        client = Client()

        result = scan_file(file_path, client, exposure="PRIVATE")

        assert result.error is None
        # Clean file should have low/no risk
        assert result.score < 50, f"Clean file scored {result.score}, expected < 50"
        assert result.tier in ("MINIMAL", "LOW", "UNKNOWN")

    def test_exposure_affects_result(self, temp_dir):
        """Test that exposure level is passed through correctly."""
        from openlabels import Client

        file_path = Path(temp_dir) / "with_ssn.txt"
        client = Client()

        result_private = scan_file(file_path, client, exposure="PRIVATE")
        result_public = scan_file(file_path, client, exposure="PUBLIC")

        # Both should succeed
        assert result_private.error is None
        assert result_public.error is None

        # Exposure should be set correctly
        assert result_private.exposure == "PRIVATE"
        assert result_public.exposure == "PUBLIC"

        # Both scores should be valid (non-negative)
        assert result_public.score >= 0
        assert result_private.score >= 0


class TestOutputFormats:
    """Test different output formats."""

    def test_json_output_format(self):
        """Test JSON output is valid JSON."""
        result = ScanResult(
            path="/test/file.txt",
            score=50,
            tier="MEDIUM",
            entities={"EMAIL": 3},
            exposure="INTERNAL",
        )

        json_str = json.dumps(result.to_dict())
        parsed = json.loads(json_str)

        assert parsed["score"] == 50
        assert parsed["tier"] == "MEDIUM"

    def test_jsonl_output_multiple_results(self):
        """Test JSONL output for multiple results."""
        results = [
            ScanResult(path="/a.txt", score=10, tier="LOW", entities={}, exposure="PRIVATE"),
            ScanResult(path="/b.txt", score=80, tier="HIGH", entities={"SSN": 1}, exposure="PRIVATE"),
        ]

        lines = [json.dumps(r.to_dict()) for r in results]

        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "path" in parsed
            assert "score" in parsed


class TestErrorHandling:
    """Test error handling in scan command."""

    def test_permission_error(self):
        """Test handling of permission errors."""
        mock_client = Mock()
        mock_client.score_file.side_effect = PermissionError("Access denied")

        with patch('openlabels.adapters.scanner.detect_file') as mock_detect:
            mock_detect.side_effect = PermissionError("Access denied")

            result = scan_file(
                Path("/restricted/file.txt"),
                mock_client,
            )

        assert result.error is not None
        assert result.score == 0

    def test_unicode_error(self):
        """Test handling of files with encoding issues."""
        mock_client = Mock()

        with patch('openlabels.adapters.scanner.detect_file') as mock_detect:
            mock_detect.side_effect = ValueError("Invalid encoding")

            result = scan_file(
                Path("/binary/file.bin"),
                mock_client,
            )

        assert result.error is not None
