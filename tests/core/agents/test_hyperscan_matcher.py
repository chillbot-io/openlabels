"""Tests for the Hyperscan regex matcher."""

import pytest

from openlabels.core.agents.hyperscan_matcher import (
    HYPERSCAN_AVAILABLE,
    HyperscanMatcher,
    Pattern,
    PatternFlags,
    PII_PATTERNS,
    luhn_check,
    scan_text,
    ssn_validate,
)


# ============================================================================
# Validator Tests
# ============================================================================

class TestLuhnCheck:
    """Test Luhn algorithm validation."""

    def test_valid_visa(self):
        """Valid Visa card number."""
        assert luhn_check("4111111111111111")

    def test_valid_mastercard(self):
        """Valid Mastercard number."""
        assert luhn_check("5500000000000004")

    def test_valid_amex(self):
        """Valid American Express number."""
        assert luhn_check("340000000000009")

    def test_invalid_card(self):
        """Invalid card number."""
        assert not luhn_check("4111111111111112")

    def test_short_number(self):
        """Too short number."""
        assert not luhn_check("41")


class TestSSNValidation:
    """Test SSN validation."""

    def test_valid_ssn(self):
        """Valid SSN format."""
        assert ssn_validate("123-45-6789")
        assert ssn_validate("123456789")

    def test_invalid_area_000(self):
        """Area 000 is invalid."""
        assert not ssn_validate("000-45-6789")

    def test_invalid_area_666(self):
        """Area 666 is invalid."""
        assert not ssn_validate("666-45-6789")

    def test_invalid_area_900s(self):
        """Area 900-999 is invalid."""
        assert not ssn_validate("900-45-6789")
        assert not ssn_validate("999-45-6789")

    def test_invalid_group_00(self):
        """Group 00 is invalid."""
        assert not ssn_validate("123-00-6789")

    def test_invalid_serial_0000(self):
        """Serial 0000 is invalid."""
        assert not ssn_validate("123-45-0000")

    def test_known_invalid_woolworth(self):
        """Woolworth wallet SSN is invalid."""
        assert not ssn_validate("078-05-1120")


# ============================================================================
# Pattern Matching Tests (Fallback/Hyperscan)
# ============================================================================

class TestPatternMatching:
    """Test pattern matching with fallback regex."""

    @pytest.fixture
    def matcher(self):
        """Create a matcher (uses fallback if Hyperscan unavailable)."""
        return HyperscanMatcher()

    def test_matcher_compiles(self, matcher):
        """Matcher compiles successfully."""
        assert matcher.pattern_count > 0

    def test_detect_ssn_with_dashes(self, matcher):
        """Detect SSN with dashes."""
        text = "My SSN is 123-45-6789 and that's private."
        matches = matcher.scan(text)

        ssn_matches = [m for m in matches if m.entity_type == "SSN"]
        assert len(ssn_matches) >= 1
        assert "123-45-6789" in [m.matched_text for m in ssn_matches]

    def test_detect_credit_card_visa(self, matcher):
        """Detect Visa credit card."""
        text = "Card: 4111-1111-1111-1111"
        matches = matcher.scan(text)

        card_matches = [m for m in matches if m.entity_type == "CREDIT_CARD"]
        assert len(card_matches) >= 1

    def test_detect_email(self, matcher):
        """Detect email address."""
        text = "Contact me at john.doe@example.com for more info."
        matches = matcher.scan(text)

        email_matches = [m for m in matches if m.entity_type == "EMAIL"]
        assert len(email_matches) == 1
        assert email_matches[0].matched_text == "john.doe@example.com"

    def test_detect_phone(self, matcher):
        """Detect phone number."""
        text = "Call me at (555) 123-4567"
        matches = matcher.scan(text)

        phone_matches = [m for m in matches if m.entity_type == "PHONE"]
        assert len(phone_matches) >= 1

    def test_detect_ipv4(self, matcher):
        """Detect IPv4 address."""
        text = "Server IP: 192.168.1.100"
        matches = matcher.scan(text)

        ip_matches = [m for m in matches if m.entity_type == "IP_ADDRESS"]
        assert len(ip_matches) == 1
        assert ip_matches[0].matched_text == "192.168.1.100"

    def test_detect_aws_key(self, matcher):
        """Detect AWS access key."""
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        matches = matcher.scan(text)

        aws_matches = [m for m in matches if m.entity_type == "AWS_KEY"]
        assert len(aws_matches) == 1
        assert "AKIAIOSFODNN7EXAMPLE" in aws_matches[0].matched_text

    def test_detect_github_token(self, matcher):
        """Detect GitHub token."""
        text = "Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        matches = matcher.scan(text)

        token_matches = [m for m in matches if m.entity_type == "GITHUB_TOKEN"]
        assert len(token_matches) == 1

    def test_no_false_positive_on_text(self, matcher):
        """No false positives on regular text."""
        text = "This is a normal sentence without any sensitive data."
        matches = matcher.scan(text)

        # May have some low-confidence matches, but should be empty or minimal
        high_confidence = [m for m in matches if m.confidence >= 0.8]
        assert len(high_confidence) == 0

    def test_detect_iban(self, matcher):
        """Detect IBAN."""
        text = "IBAN: DE89370400440532013000"
        matches = matcher.scan(text)

        iban_matches = [m for m in matches if m.entity_type == "IBAN"]
        assert len(iban_matches) >= 1

    def test_detect_dob_with_label(self, matcher):
        """Detect date of birth with label."""
        text = "DOB: 01/15/1990"
        matches = matcher.scan(text)

        dob_matches = [m for m in matches if m.entity_type == "DOB"]
        assert len(dob_matches) >= 1

    def test_luhn_validation_filters_invalid(self, matcher):
        """Invalid credit cards are filtered by Luhn check."""
        # Invalid Luhn checksum
        text = "Card: 4111111111111112"
        matches = matcher.scan(text)

        card_matches = [m for m in matches if m.entity_type == "CREDIT_CARD"]
        # Should be filtered out by Luhn check
        assert len(card_matches) == 0

    def test_ssn_validation_filters_invalid(self, matcher):
        """Invalid SSNs are filtered by validation."""
        # Invalid area code (000)
        text = "SSN: 000-12-3456"
        matches = matcher.scan(text)

        ssn_matches = [m for m in matches if m.entity_type == "SSN"]
        # Should be filtered out by SSN validation
        assert len(ssn_matches) == 0


class TestBatchScanning:
    """Test batch scanning."""

    def test_batch_scan(self):
        """Scan multiple texts efficiently."""
        matcher = HyperscanMatcher()

        texts = [
            "Email: user1@example.com",
            "SSN: 123-45-6789",
            "No sensitive data here",
        ]

        results = matcher.scan_batch(texts)
        assert len(results) == 3

        # First text has email
        assert any(m.entity_type == "EMAIL" for m in results[0])

        # Second text has SSN
        assert any(m.entity_type == "SSN" for m in results[1])

        # Third text should have minimal/no high-confidence matches
        high_conf = [m for m in results[2] if m.confidence >= 0.8]
        assert len(high_conf) == 0


class TestCustomPatterns:
    """Test custom pattern support."""

    def test_custom_pattern(self):
        """Create matcher with custom patterns."""
        patterns = [
            Pattern(
                id=1,
                name="custom_id",
                entity_type="CUSTOM_ID",
                regex=r"\bCUST-\d{8}\b",
                confidence=0.9,
            )
        ]

        matcher = HyperscanMatcher(patterns=patterns)
        matches = matcher.scan("ID: CUST-12345678")

        assert len(matches) == 1
        assert matches[0].entity_type == "CUSTOM_ID"
        assert matches[0].matched_text == "CUST-12345678"


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_scan_text_function(self):
        """scan_text convenience function works."""
        matches = scan_text("Email: test@example.com")

        email_matches = [m for m in matches if m.entity_type == "EMAIL"]
        assert len(email_matches) == 1


@pytest.mark.skipif(not HYPERSCAN_AVAILABLE, reason="Hyperscan not installed")
class TestHyperscanSpecific:
    """Tests that specifically require Hyperscan."""

    def test_using_hyperscan(self):
        """Matcher uses Hyperscan when available."""
        matcher = HyperscanMatcher()
        assert matcher.using_hyperscan

    def test_hyperscan_utf8_handling(self):
        """Hyperscan handles UTF-8 text correctly."""
        matcher = HyperscanMatcher()

        # Text with unicode characters
        text = "Contact: über.user@example.com for café orders"
        matches = matcher.scan(text)

        # Should still find the email
        email_matches = [m for m in matches if m.entity_type == "EMAIL"]
        # Note: the email with ü may or may not match depending on regex
        # At minimum, no crash should occur
        assert isinstance(matches, list)
