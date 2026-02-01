"""
Tests for the Secrets Detector.

Tests detection of API keys, tokens, private keys, JWTs, connection strings,
and other sensitive credentials.

Adapted from openrisk/tests/test_scanner/test_secrets_detector.py
"""

import pytest
from openlabels.core.detectors.secrets import SecretsDetector


class TestSecretsDetector:
    """Test the SecretsDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a SecretsDetector instance."""
        return SecretsDetector()

    def test_detector_name(self, detector):
        """Test detector has correct name."""
        assert detector.name == "secrets"


class TestAWSCredentials:
    """Test detection of AWS credentials."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_aws_access_key(self, detector):
        """Test AWS access key ID detection."""
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) >= 1
        for span in aws_spans:
            assert span.text.startswith("AKIA")


class TestGitHubTokens:
    """Test detection of GitHub tokens."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_github_pat_format(self, detector):
        """Test GitHub Personal Access Token format detection."""
        text = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) >= 1
        assert any(s.text.startswith("ghp_") for s in gh_spans)


class TestPrivateKeys:
    """Test detection of private keys."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_rsa_private_key(self, detector):
        """Test RSA private key detection."""
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
-----END RSA PRIVATE KEY-----"""
        spans = detector.detect(text)

        key_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(key_spans) >= 1

    def test_detect_generic_private_key(self, detector):
        """Test generic private key detection."""
        text = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEA...
-----END PRIVATE KEY-----"""
        spans = detector.detect(text)

        key_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(key_spans) >= 1


class TestJWT:
    """Test detection of JSON Web Tokens."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_jwt_format(self, detector):
        """Test JWT detection (header.payload.signature format)."""
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        spans = detector.detect(text)

        jwt_spans = [s for s in spans if s.entity_type == "JWT"]
        assert len(jwt_spans) >= 1


class TestEdgeCases:
    """Test edge cases and false positive prevention."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_no_false_positive_normal_text(self, detector):
        """Test normal text isn't flagged."""
        text = "The quick brown fox jumps over the lazy dog."
        spans = detector.detect(text)
        assert len(spans) == 0

    def test_no_false_positive_placeholder(self, detector):
        """Test placeholder tokens aren't flagged."""
        text = "GITHUB_TOKEN=<your-token-here>"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) == 0

    def test_confidence_scores_valid(self, detector):
        """Test that detected spans have valid confidence scores."""
        text = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        spans = detector.detect(text)

        for span in spans:
            assert 0.0 <= span.confidence <= 1.0

    def test_span_positions_valid(self, detector):
        """Test that span positions are correct."""
        text = "key: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        spans = detector.detect(text)

        for span in spans:
            assert span.start >= 0
            assert span.end > span.start
            assert span.end <= len(text)

    def test_empty_string(self, detector):
        """Test empty string input."""
        spans = detector.detect("")
        assert spans == []

    def test_multiple_secrets(self, detector):
        """Test detection of multiple secrets in one text."""
        # GitHub PAT tokens have 36 chars after prefix
        text = """
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234
        """
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]

        assert len(aws_spans) >= 1
        assert len(gh_spans) >= 1
