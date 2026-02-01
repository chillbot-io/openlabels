"""
CLI Integration Tests.

Tests for the OpenLabels command-line interface.
These tests verify CLI commands work end-to-end.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files with PII-like content
        pii_file = Path(tmpdir) / "pii_data.txt"
        pii_file.write_text(
            "Customer: John Smith\n"
            "SSN: 123-45-6789\n"
            "Email: john.smith@example.com\n"
            "Phone: (555) 123-4567\n"
        )

        # Create clean file
        clean_file = Path(tmpdir) / "clean.txt"
        clean_file.write_text("This is just regular text without any sensitive data.")

        # Create nested structure
        subdir = Path(tmpdir) / "data"
        subdir.mkdir()
        (subdir / "nested.txt").write_text("Nested file content")

        yield Path(tmpdir)


def run_cli(*args, input_text=None):
    """Run the CLI command and return result."""
    cmd = [sys.executable, "-m", "openlabels.cli.main"] + list(args)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=30,
    )
    return result


# =============================================================================
# Version Tests
# =============================================================================

class TestVersion:
    """Tests for --version flag."""

    def test_version_shows_version(self):
        """Test that --version displays version info."""
        result = run_cli("--version")

        # Should exit successfully and show version
        assert result.returncode == 0
        assert "openlabels" in result.stdout.lower() or "openrisk" in result.stdout.lower()


# =============================================================================
# Help Tests
# =============================================================================

class TestHelp:
    """Tests for --help flag."""

    def test_help_shows_usage(self):
        """Test that --help shows usage information."""
        result = run_cli("--help")

        assert result.returncode == 0
        assert "usage" in result.stdout.lower() or "Usage" in result.stdout

    def test_scan_help(self):
        """Test that scan --help shows scan options."""
        result = run_cli("scan", "--help")

        assert result.returncode == 0
        # Should mention path argument
        assert "path" in result.stdout.lower()


# =============================================================================
# Scan Command Tests
# =============================================================================

class TestScanCommand:
    """Tests for the scan command."""

    def test_scan_file(self, temp_dir):
        """Test scanning a single file."""
        pii_file = temp_dir / "pii_data.txt"
        result = run_cli("scan", str(pii_file))

        assert result.returncode == 0

    def test_scan_file_with_pii(self, temp_dir):
        """Test detecting PII in a file."""
        pii_file = temp_dir / "pii_data.txt"
        result = run_cli("scan", str(pii_file))

        assert result.returncode == 0
        # Should find entities - check stdout or stderr
        output = result.stdout + result.stderr
        assert "SSN" in output or "entities" in output.lower() or "score" in output.lower()

    def test_scan_file_clean(self, temp_dir):
        """Test scanning a clean file."""
        clean_file = temp_dir / "clean.txt"
        result = run_cli("scan", str(clean_file))

        assert result.returncode == 0

    def test_scan_directory(self, temp_dir):
        """Test scanning a directory."""
        result = run_cli("scan", str(temp_dir))

        assert result.returncode == 0

    def test_scan_directory_recursive(self, temp_dir):
        """Test recursive directory scanning."""
        result = run_cli("scan", str(temp_dir), "--recursive")

        assert result.returncode == 0

    def test_scan_with_json_output(self, temp_dir):
        """Test scan with JSON output (single JSON object, not JSONL)."""
        result = run_cli("scan", str(temp_dir), "--format", "json")

        assert result.returncode == 0
        # --format json outputs a single JSON object with summary and results
        output = json.loads(result.stdout)
        assert "summary" in output
        assert "results" in output
        assert isinstance(output["results"], list)

    def test_scan_with_jsonl_output(self, temp_dir):
        """Test scan with JSONL output (one JSON object per line)."""
        result = run_cli("scan", str(temp_dir), "--format", "jsonl")

        assert result.returncode == 0
        # --format jsonl outputs one JSON object per line
        # Verify any JSON lines present are valid
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line and line.startswith('{') and line.endswith('}'):
                parsed = json.loads(line)
                assert "path" in parsed

    def test_scan_nonexistent_path(self):
        """Test error handling for nonexistent path."""
        result = run_cli("scan", "/nonexistent/path")

        assert result.returncode != 0

    def test_scan_file_json_output(self, temp_dir):
        """Test JSON output for file scanning."""
        pii_file = temp_dir / "pii_data.txt"
        result = run_cli("scan", str(pii_file), "--format", "json")

        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, dict)


# =============================================================================
# Find Command Tests
# =============================================================================

class TestFindCommand:
    """Tests for the find command."""

    def test_find_basic(self, temp_dir):
        """Test basic find command."""
        result = run_cli("find", str(temp_dir))

        assert result.returncode == 0

    def test_find_with_limit(self, temp_dir):
        """Test find with --limit option."""
        result = run_cli("find", str(temp_dir), "--limit", "1")

        assert result.returncode == 0


# =============================================================================
# Health Command Tests
# =============================================================================

class TestHealthCommand:
    """Tests for the health command."""

    def test_health_runs(self):
        """Test that health command runs."""
        result = run_cli("health")

        # Health check should run (may pass or warn)
        assert result.returncode in [0, 1]  # 0=pass, 1=warn/fail


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_file(self, temp_dir):
        """Test scanning an empty file."""
        empty_file = temp_dir / "empty.txt"
        empty_file.write_text("")
        result = run_cli("scan", str(empty_file))

        # Should handle gracefully
        assert result.returncode == 0

    def test_unicode_file(self, temp_dir):
        """Test scanning file with unicode text."""
        unicode_file = temp_dir / "unicode.txt"
        unicode_file.write_text("Naïve café résumé: test@example.com")
        result = run_cli("scan", str(unicode_file))

        # Should handle unicode without crashing
        assert result.returncode == 0

    def test_large_file(self, temp_dir):
        """Test scanning a large file."""
        large_file = temp_dir / "large.txt"
        # Generate large text with some PII
        large_text = "Regular text. " * 1000 + " SSN: 123-45-6789 " + " More text. " * 1000
        large_file.write_text(large_text)
        result = run_cli("scan", str(large_file))

        assert result.returncode == 0

    def test_special_characters_in_path(self, temp_dir):
        """Test file with special characters in name."""
        special_file = temp_dir / "file with spaces.txt"
        special_file.write_text("SSN: 123-45-6789")

        result = run_cli("scan", str(special_file))

        assert result.returncode == 0


# =============================================================================
# Output Format Tests
# =============================================================================

class TestOutputFormats:
    """Tests for different output formats."""

    def test_text_format(self, temp_dir):
        """Test default text format."""
        pii_file = temp_dir / "pii_data.txt"
        result = run_cli("scan", str(pii_file), "--format", "text")

        assert result.returncode == 0

    def test_json_format_is_valid(self, temp_dir):
        """Test that JSON format produces valid JSON."""
        pii_file = temp_dir / "pii_data.txt"
        result = run_cli("scan", str(pii_file), "--format", "json")

        assert result.returncode == 0
        # Should parse as JSON
        data = json.loads(result.stdout)
        assert isinstance(data, dict)

    def test_jsonl_format(self, temp_dir):
        """Test JSONL (line-delimited JSON) format."""
        pii_file = temp_dir / "pii_data.txt"
        result = run_cli("scan", str(pii_file), "--format", "jsonl")

        assert result.returncode == 0
        # Should be valid JSON lines
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line and line.startswith('{'):
                data = json.loads(line)
                assert isinstance(data, dict)
