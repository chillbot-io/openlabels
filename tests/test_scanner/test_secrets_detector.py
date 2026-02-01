"""
Tests for the Secrets Detector.

Tests detection of API keys, tokens, private keys, JWTs, connection strings,
and other sensitive credentials.

Note: Many specific token tests are omitted to avoid triggering secret scanning.
The detector's pattern matching is tested using clearly invalid test patterns
or by verifying detector properties rather than specific secret formats.
"""

import pytest
from openlabels.adapters.scanner.detectors.secrets import SecretsDetector


class TestSecretsDetector:
    """Test the SecretsDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a SecretsDetector instance."""
        return SecretsDetector()

    def test_detector_name(self, detector):
        """Test detector has correct name."""
        assert detector.name == "secrets"

    def test_detector_available(self, detector):
        """Test detector is available."""
        assert detector.is_available() is True


class TestAWSCredentials:
    """Test detection of AWS credentials."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_aws_access_key(self, detector):
        """Test AWS access key ID detection."""
        # AKIA prefix with 16 alphanumeric chars is the pattern
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) >= 1
        # Verify the pattern matches expected format
        for span in aws_spans:
            assert span.text.startswith("AKIA")

    def test_detect_aws_secret_key_with_context(self, detector):
        """Test AWS secret access key detection requires context."""
        # Secret keys need context like 'aws_secret_access_key' and 40 chars
        text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"'
        spans = detector.detect(text)

        # Should detect based on context pattern
        secret_spans = [s for s in spans if s.entity_type == "AWS_SECRET_KEY"]
        assert len(secret_spans) >= 1


class TestGitHubTokens:
    """Test detection of GitHub tokens."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_github_pat_format(self, detector):
        """Test GitHub Personal Access Token format detection."""
        # ghp_ prefix with exactly 36 alphanumeric chars
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
        # JWT with three base64 parts separated by dots
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        spans = detector.detect(text)

        jwt_spans = [s for s in spans if s.entity_type == "JWT"]
        assert len(jwt_spans) >= 1


class TestDatabaseURLs:
    """Test detection of database connection strings."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_postgres_url(self, detector):
        """Test PostgreSQL connection string detection."""
        text = "DATABASE_URL=postgres://user:password123@localhost:5432/mydb"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) >= 1

    def test_detect_mysql_url(self, detector):
        """Test MySQL connection string detection."""
        text = "mysql://admin:secretpass@db.example.com:3306/production"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) >= 1


class TestGenericSecrets:
    """Test detection of generic secret patterns."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_password_assignment(self, detector):
        """Test password assignment detection."""
        text = 'password = "SuperSecret123!"'
        spans = detector.detect(text)

        # Should detect as some form of secret pattern
        secret_spans = [s for s in spans if any(x in s.entity_type.upper() for x in ["SECRET", "PASSWORD", "GENERIC"])]
        assert len(secret_spans) >= 1


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

        # Placeholders shouldn't match real token patterns
        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) == 0

    def test_confidence_scores_valid(self, detector):
        """Test that detected spans have valid confidence scores."""
        text = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd1234"
        spans = detector.detect(text)

        for span in spans:
            assert 0.0 <= span.confidence <= 1.0

    def test_span_positions_valid(self, detector):
        """Test that span positions are correct."""
        text = "key: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd1234"
        spans = detector.detect(text)

        for span in spans:
            assert span.start >= 0
            assert span.end > span.start
            assert span.end <= len(text)

    def test_high_confidence_for_known_patterns(self, detector):
        """Test that known patterns have high confidence."""
        text = "AKIAIOSFODNN7EXAMPLE1"  # AWS Access Key format
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        for span in aws_spans:
            assert span.confidence >= 0.90
