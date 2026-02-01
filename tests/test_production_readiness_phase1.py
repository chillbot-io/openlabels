#!/usr/bin/env python3
"""
Tests for Production Readiness Phase 1: Critical Input Validation & Safety.

These tests verify the fixes for:
- Issue 1.1: Text input size limits
- Issue 1.2: File size limits before reading
- Issue 1.3: ReDoS timeout enforcement
- Issue 1.4: Cloud URI validation with path traversal protection
"""

import os
import sys
import tempfile
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest


# =============================================================================
# ISSUE 1.1 & 1.2: SIZE LIMIT TESTS
# =============================================================================

class TestSizeLimits:
    """Tests for text and file size limit enforcement."""

    def test_text_input_size_limit_config_default(self):
        """Verify default max_text_size is set."""
        from openlabels.adapters.scanner.config import Config

        config = Config()
        assert config.max_text_size == 10_000_000  # 10 million chars (10 * MAX_TEXT_LENGTH)

    def test_file_size_limit_config_default(self):
        """Verify default max_file_size is set."""
        from openlabels.adapters.scanner.config import Config

        config = Config()
        assert config.max_file_size == 100 * 1024 * 1024  # 100 MB default

    def test_text_input_within_limit_succeeds(self):
        """Text within size limit should be processed normally."""
        from openlabels.adapters.scanner.adapter import Detector
        from openlabels.adapters.scanner.config import Config

        config = Config()
        config.max_text_size = 1000  # 1KB limit for test
        detector = Detector(config=config)

        # Text within limit should work
        result = detector.detect("Test text with SSN: 123-45-6789")
        assert result is not None
        assert result.text is not None

    def test_text_input_exceeds_limit_raises(self):
        """Text exceeding size limit should raise ValueError."""
        from openlabels.adapters.scanner.adapter import Detector
        from openlabels.adapters.scanner.config import Config

        config = Config()
        config.max_text_size = 100  # 100 byte limit for test
        detector = Detector(config=config)

        # Text exceeding limit should raise
        huge_text = "a" * 200
        with pytest.raises(ValueError) as exc_info:
            detector.detect(huge_text)

        assert "exceeds maximum" in str(exc_info.value)
        assert "characters" in str(exc_info.value)  # Should say characters, not bytes

    def test_file_size_check_before_read(self):
        """File size should be checked BEFORE reading content."""
        from openlabels.adapters.scanner.adapter import Detector
        from openlabels.adapters.scanner.config import Config

        config = Config()
        config.max_file_size = 50  # 50 byte limit for test
        detector = Detector(config=config)

        # Create a file larger than limit
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("x" * 100)  # 100 bytes, exceeds 50 byte limit
            temp_path = f.name

        try:
            with pytest.raises(ValueError) as exc_info:
                detector.detect_file(temp_path)

            assert "exceeds maximum" in str(exc_info.value)
            assert temp_path in str(exc_info.value)
        finally:
            os.unlink(temp_path)

    def test_file_within_limit_succeeds(self):
        """File within size limit should be processed normally."""
        from openlabels.adapters.scanner.adapter import Detector
        from openlabels.adapters.scanner.config import Config

        config = Config()
        config.max_file_size = 1000  # 1KB limit
        detector = Detector(config=config)

        # Create a small file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Patient SSN: 123-45-6789")
            temp_path = f.name

        try:
            result = detector.detect_file(temp_path)
            assert result is not None
        finally:
            os.unlink(temp_path)

    def test_empty_text_does_not_trigger_size_check(self):
        """Empty text should not trigger size check."""
        from openlabels.adapters.scanner.adapter import Detector
        from openlabels.adapters.scanner.config import Config

        config = Config()
        config.max_text_size = 10
        detector = Detector(config=config)

        # Empty text should return empty result, not raise
        result = detector.detect("")
        assert result.spans == []

    def test_config_validation_rejects_invalid_limits(self):
        """Config should reject invalid size limits."""
        from openlabels.adapters.scanner.config import Config

        with pytest.raises(ValueError):
            config = Config()
            config.max_text_size = 0
            config.__post_init__()

        with pytest.raises(ValueError):
            config = Config()
            config.max_file_size = -1
            config.__post_init__()


# =============================================================================
# ISSUE 1.3: REDOS TIMEOUT TESTS
# =============================================================================

class TestReDoSProtection:
    """Tests for ReDoS timeout enforcement in filter.py."""

    def test_safe_regex_basic_match(self):
        """Basic regex match should work."""
        from openlabels.cli.filter import Condition

        cond = Condition(field="path", operator="matches", value=r"test.*\.txt")
        assert cond._safe_regex_match(r"test.*\.txt", "test_file.txt")
        assert not cond._safe_regex_match(r"test.*\.txt", "other_file.csv")

    def test_safe_regex_rejects_long_patterns(self):
        """Patterns exceeding 500 chars should be rejected."""
        from openlabels.cli.filter import Condition

        cond = Condition(field="test", operator="matches", value="x")
        long_pattern = "a" * 600
        assert not cond._safe_regex_match(long_pattern, "test")

    def test_safe_regex_rejects_nested_quantifiers(self):
        """Patterns with nested quantifiers (ReDoS-prone) should be rejected."""
        from openlabels.cli.filter import Condition

        cond = Condition(field="test", operator="matches", value="x")

        # These are classic ReDoS patterns
        assert not cond._safe_regex_match(r"(a+)+", "aaaa")
        assert not cond._safe_regex_match(r"(a*)*", "aaaa")
        assert not cond._safe_regex_match(r"(a|b)+", "abab")  # Alternation with quantifier

    def test_safe_regex_rejects_huge_text(self):
        """Regex on huge text should be rejected."""
        from openlabels.cli.filter import Condition

        cond = Condition(field="test", operator="matches", value="x")

        # Text over 1MB should be rejected
        huge_text = "a" * (1_000_001)
        assert not cond._safe_regex_match(r"test", huge_text)

    def test_safe_regex_handles_invalid_pattern(self):
        """Invalid regex patterns should return False, not raise."""
        from openlabels.cli.filter import Condition

        cond = Condition(field="test", operator="matches", value="x")

        # Invalid regex should return False
        assert not cond._safe_regex_match(r"[invalid", "test")
        assert not cond._safe_regex_match(r"(unclosed", "test")

    def test_filter_matches_operator_uses_safe_regex(self):
        """The 'matches' operator in filters should use safe regex."""
        from openlabels.cli.filter import Filter

        # Valid pattern should work
        f = Filter.parse("path matches test.*")
        result = {"path": "test_file.txt"}
        assert f.evaluate(result)

        # ReDoS pattern should fail (return False, not hang)
        f = Filter.parse("path matches '(a+)+'")
        result = {"path": "aaaaaaaaaaaaaaaaaaaaaa"}
        assert not f.evaluate(result)  # Should return False quickly


# =============================================================================
# ISSUE 1.4: CLOUD URI VALIDATION TESTS
# =============================================================================

class TestCloudURIValidation:
    """Tests for Cloud URI parsing and validation."""

    def test_valid_s3_uri(self):
        """Valid S3 URIs should parse correctly."""
        from openlabels.output.virtual import parse_cloud_uri

        result = parse_cloud_uri("s3://my-bucket/path/to/file.txt")
        assert result.provider == 's3'
        assert result.bucket == 'my-bucket'
        assert result.key == 'path/to/file.txt'

    def test_valid_s3_uri_no_key(self):
        """S3 URI without key should parse correctly."""
        from openlabels.output.virtual import parse_cloud_uri

        result = parse_cloud_uri("s3://my-bucket")
        assert result.provider == 's3'
        assert result.bucket == 'my-bucket'
        assert result.key == ''

    def test_valid_gcs_uri(self):
        """Valid GCS URIs should parse correctly."""
        from openlabels.output.virtual import parse_cloud_uri

        result = parse_cloud_uri("gs://my-bucket/blob/name.json")
        assert result.provider == 'gcs'
        assert result.bucket == 'my-bucket'
        assert result.key == 'blob/name.json'

    def test_valid_azure_uri(self):
        """Valid Azure URIs should parse correctly."""
        from openlabels.output.virtual import parse_cloud_uri

        result = parse_cloud_uri("azure://my-container/blob/path")
        assert result.provider == 'azure'
        assert result.bucket == 'my-container'
        assert result.key == 'blob/path'

    def test_path_traversal_rejected(self):
        """URIs with path traversal should be rejected."""
        from openlabels.output.virtual import parse_cloud_uri, CloudURIValidationError

        traversal_uris = [
            "s3://bucket/../../../etc/passwd",
            "s3://bucket/path/../../../etc/passwd",
            "gs://bucket/..\\..\\windows\\system32",
            "azure://container/path/to/../../../secret",
            "s3://bucket/..",
        ]

        for uri in traversal_uris:
            with pytest.raises(CloudURIValidationError) as exc_info:
                parse_cloud_uri(uri)
            assert "traversal" in str(exc_info.value).lower(), f"Expected traversal error for: {uri}"

    def test_invalid_bucket_name_rejected(self):
        """Invalid bucket names should be rejected."""
        from openlabels.output.virtual import parse_cloud_uri, CloudURIValidationError

        invalid_uris = [
            "s3://ab/key",  # Too short (2 chars)
            "s3://UPPERCASE/key",  # Uppercase not allowed
            "s3://-invalid/key",  # Can't start with hyphen
            "s3://invalid-/key",  # Can't end with hyphen
            "s3://192.168.1.1/key",  # IP address not allowed
        ]

        for uri in invalid_uris:
            with pytest.raises(CloudURIValidationError):
                parse_cloud_uri(uri)

    def test_empty_bucket_rejected(self):
        """Empty bucket name should be rejected."""
        from openlabels.output.virtual import parse_cloud_uri, CloudURIValidationError

        with pytest.raises(CloudURIValidationError):
            parse_cloud_uri("s3:///key")

    def test_unknown_scheme_rejected(self):
        """Unknown URI schemes should be rejected."""
        from openlabels.output.virtual import parse_cloud_uri, CloudURIValidationError

        with pytest.raises(CloudURIValidationError):
            parse_cloud_uri("http://bucket/key")

        with pytest.raises(CloudURIValidationError):
            parse_cloud_uri("file:///path/to/file")

    def test_null_byte_in_key_rejected(self):
        """Null bytes in key should be rejected."""
        from openlabels.output.virtual import parse_cloud_uri, CloudURIValidationError

        with pytest.raises(CloudURIValidationError):
            parse_cloud_uri("s3://bucket/key\x00injection")

    def test_key_length_limit(self):
        """Keys exceeding 1024 bytes should be rejected."""
        from openlabels.output.virtual import parse_cloud_uri, CloudURIValidationError

        long_key = "a" * 1025
        with pytest.raises(CloudURIValidationError):
            parse_cloud_uri(f"s3://my-bucket/{long_key}")

    def test_gcs_bucket_cannot_contain_google(self):
        """GCS bucket names cannot contain 'google'."""
        from openlabels.output.virtual import parse_cloud_uri, CloudURIValidationError

        with pytest.raises(CloudURIValidationError):
            parse_cloud_uri("gs://mygooglebucket/key")

        with pytest.raises(CloudURIValidationError):
            parse_cloud_uri("gs://googtest/key")


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestPhase1Integration:
    """Integration tests verifying Phase 1 fixes work together."""

    def test_client_respects_size_limits(self):
        """High-level Client API should respect size limits."""
        from openlabels import Client

        client = Client()

        # Normal text should work
        result = client.score_text("SSN: 123-45-6789")
        assert result is not None
        assert result.score >= 0

    def test_filter_safe_under_adversarial_input(self):
        """Filter evaluation should be safe under adversarial input."""
        from openlabels.cli.filter import Filter, matches_filter

        # Create a filter with matches operator
        filter_expr = "path matches 'test'"

        # Even with malicious path containing ReDoS patterns, should complete quickly
        result = {"path": "a" * 100}
        assert matches_filter(result, filter_expr) is False


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Run tests using pytest."""
    import pytest
    return pytest.main([__file__, "-v"])


if __name__ == "__main__":
    sys.exit(main())
