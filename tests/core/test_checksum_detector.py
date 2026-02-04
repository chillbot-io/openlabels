"""
Tests for checksum-validated detectors.

Tests validators (Luhn, SSN, Credit Card, NPI, IBAN)
and the ChecksumDetector class.

Adapted from openrisk/tests/test_scanner/test_checksum_detector.py
"""

import pytest
from openlabels.core.detectors.checksum import (
    luhn_check,
    validate_ssn,
    validate_credit_card,
    validate_npi,
    validate_iban,
    ChecksumDetector,
)


class TestLuhnCheck:
    """Tests for Luhn algorithm validation."""

    def test_valid_luhn_numbers(self):
        """Test valid Luhn numbers."""
        assert luhn_check("79927398713") is True
        assert luhn_check("4539578763621486") is True  # Valid Visa
        assert luhn_check("4111111111111111") is True  # Test Visa
        assert luhn_check("5500000000000004") is True  # Test Mastercard

    def test_invalid_luhn_numbers(self):
        """Test invalid Luhn numbers."""
        assert luhn_check("79927398710") is False
        assert luhn_check("1234567890123456") is False
        assert luhn_check("1111111111111111") is False

    def test_too_few_digits(self):
        """Test numbers with too few digits."""
        assert luhn_check("1") is False
        assert luhn_check("") is False
        assert luhn_check("a") is False

    def test_with_non_digit_characters(self):
        """Test Luhn handles non-digit characters (strips them)."""
        assert luhn_check("4111-1111-1111-1111") is True
        assert luhn_check("4111 1111 1111 1111") is True


class TestValidateSSN:
    """Tests for SSN validation."""

    def test_valid_ssn_hyphenated(self):
        """Test valid SSN with hyphens."""
        is_valid, conf = validate_ssn("123-45-6789")
        assert is_valid is True
        assert conf >= 0.95

    def test_valid_ssn_spaces(self):
        """Test valid SSN with spaces."""
        is_valid, conf = validate_ssn("123 45 6789")
        assert is_valid is True
        assert conf >= 0.95

    def test_invalid_area_000(self):
        """Test SSN with invalid area code 000."""
        is_valid, conf = validate_ssn("000-45-6789")
        assert is_valid is True  # Still detected
        assert conf < 0.90  # Lower confidence

    def test_invalid_area_666(self):
        """Test SSN with invalid area code 666."""
        is_valid, conf = validate_ssn("666-45-6789")
        assert is_valid is True
        assert conf < 0.90

    def test_invalid_area_9xx(self):
        """Test SSN with invalid area code starting with 9."""
        is_valid, conf = validate_ssn("900-45-6789")
        assert is_valid is True
        assert conf < 0.90

    def test_invalid_group_00(self):
        """Test SSN with invalid group 00."""
        is_valid, conf = validate_ssn("123-00-6789")
        assert is_valid is True
        assert conf < 0.85

    def test_invalid_serial_0000(self):
        """Test SSN with invalid serial 0000."""
        is_valid, conf = validate_ssn("123-45-0000")
        assert is_valid is True
        assert conf < 0.85

    def test_wrong_length(self):
        """Test SSN with wrong number of digits."""
        is_valid, _ = validate_ssn("12-34-5678")
        assert is_valid is False

        is_valid, _ = validate_ssn("1234-56-7890")
        assert is_valid is False

    def test_whitespace_trimmed(self):
        """Test leading/trailing whitespace is trimmed."""
        is_valid, conf = validate_ssn("  123-45-6789  ")
        assert is_valid is True
        assert conf >= 0.95


class TestValidateCreditCard:
    """Tests for credit card validation."""

    def test_valid_visa(self):
        """Test valid Visa card."""
        is_valid, conf = validate_credit_card("4111111111111111")
        assert is_valid is True
        assert conf >= 0.95

    def test_valid_mastercard(self):
        """Test valid Mastercard."""
        is_valid, conf = validate_credit_card("5500000000000004")
        assert is_valid is True
        assert conf >= 0.95

    def test_valid_amex(self):
        """Test valid American Express."""
        is_valid, conf = validate_credit_card("374245455400126")
        assert is_valid is True
        assert conf >= 0.95

    def test_valid_with_spaces(self):
        """Test valid card with spaces."""
        is_valid, conf = validate_credit_card("4111 1111 1111 1111")
        assert is_valid is True
        assert conf >= 0.95

    def test_valid_with_dashes(self):
        """Test valid card with dashes."""
        is_valid, conf = validate_credit_card("4111-1111-1111-1111")
        assert is_valid is True
        assert conf >= 0.95

    def test_invalid_luhn(self):
        """Test card that fails Luhn check should have low confidence."""
        is_valid, conf = validate_credit_card("4111111111111112")
        # Invalid Luhn MUST result in either low confidence OR explicit rejection
        # Using AND ensures we catch bugs where invalid cards get high confidence
        assert conf < 0.90, f"Invalid Luhn card should have confidence < 0.90, got {conf}"

    def test_too_short(self):
        """Test card number too short."""
        is_valid, _ = validate_credit_card("411111111111")  # 12 digits
        assert is_valid is False

    def test_too_long(self):
        """Test card number too long."""
        is_valid, _ = validate_credit_card("41111111111111111111")  # 20 digits
        assert is_valid is False


class TestValidateNPI:
    """Tests for NPI (National Provider Identifier) validation."""

    def test_valid_npi(self):
        """Test valid NPI number."""
        # Valid NPI: 1234567893 (Luhn check with 80840 prefix)
        is_valid, conf = validate_npi("1234567893")
        assert is_valid is True
        assert conf >= 0.95

    def test_invalid_npi_luhn(self):
        """Test NPI that fails Luhn check should have low confidence."""
        is_valid, conf = validate_npi("1234567890")
        # Invalid Luhn MUST result in low confidence
        assert conf < 0.90, f"Invalid NPI Luhn should have confidence < 0.90, got {conf}"

    def test_invalid_npi_length(self):
        """Test NPI with wrong length."""
        is_valid, _ = validate_npi("123456789")  # 9 digits
        assert is_valid is False

        is_valid, _ = validate_npi("12345678901")  # 11 digits
        assert is_valid is False

    def test_npi_with_formatting(self):
        """Test NPI with formatting characters."""
        is_valid, conf = validate_npi("1234-567-893")
        assert is_valid is True


class TestValidateIBAN:
    """Tests for IBAN validation."""

    def test_valid_iban_gb(self):
        """Test valid UK IBAN."""
        is_valid, conf = validate_iban("GB82WEST12345698765432")
        assert is_valid is True
        assert conf >= 0.95

    def test_valid_iban_de(self):
        """Test valid German IBAN."""
        is_valid, conf = validate_iban("DE89370400440532013000")
        assert is_valid is True
        assert conf >= 0.95

    def test_valid_iban_with_spaces(self):
        """Test valid IBAN with spaces."""
        is_valid, conf = validate_iban("GB82 WEST 1234 5698 7654 32")
        assert is_valid is True

    def test_invalid_iban_checksum(self):
        """Test IBAN with invalid checksum should have low confidence."""
        is_valid, conf = validate_iban("GB82WEST12345698765433")  # Changed last digit
        # Invalid checksum MUST result in low confidence - catch false positives
        assert conf < 0.90, f"Invalid IBAN checksum should have confidence < 0.90, got {conf}"

    def test_invalid_iban_country(self):
        """Test IBAN with invalid country code."""
        is_valid, _ = validate_iban("XX00BANK00000000000000")
        assert is_valid is False

    def test_invalid_iban_too_short(self):
        """Test IBAN that is too short."""
        is_valid, _ = validate_iban("GB82WEST")
        assert is_valid is False


class TestChecksumDetector:
    """Integration tests for ChecksumDetector class."""

    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return ChecksumDetector()

    def test_detect_ssn_in_text(self, detector):
        """Test detecting SSN in text."""
        text = "My SSN is 123-45-6789 for your records."
        spans = detector.detect(text)

        assert len(spans) >= 1
        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) == 1
        assert ssn_spans[0].text == "123-45-6789"
        assert ssn_spans[0].confidence >= 0.95

    def test_detect_credit_card_in_text(self, detector):
        """Test detecting credit card in text."""
        text = "Please charge card 4111-1111-1111-1111 for the order."
        spans = detector.detect(text)

        cc_spans = [s for s in spans if s.entity_type == "CREDIT_CARD"]
        assert len(cc_spans) == 1
        assert "4111" in cc_spans[0].text

    def test_detect_multiple_entities(self, detector):
        """Test detecting multiple entities in text."""
        text = """
        SSN: 123-45-6789
        Card: 4111-1111-1111-1111
        NPI: 1234567893
        """
        spans = detector.detect(text)

        entity_types = {s.entity_type for s in spans}
        assert "SSN" in entity_types
        assert "CREDIT_CARD" in entity_types

    def test_no_false_positives_on_plain_text(self, detector):
        """Test that plain text doesn't trigger false positives."""
        text = "This is a normal sentence without any sensitive data."
        spans = detector.detect(text)

        # Should not find anything
        assert len(spans) == 0

    def test_overlapping_patterns_resolved(self, detector):
        """Test that overlapping detections are resolved."""
        # A number that could match multiple patterns
        text = "Account 4111111111111111"  # Looks like CC
        spans = detector.detect(text)

        # Should not have overlapping spans
        for i, s1 in enumerate(spans):
            for s2 in spans[i + 1:]:
                assert not s1.overlaps(s2), f"Overlapping spans: {s1} and {s2}"

    def test_detector_name(self, detector):
        """Test detector name is set correctly."""
        assert detector.name == "checksum"

    def test_detector_tier(self, detector):
        """Test detector tier is highest (Tier 4)."""
        from openlabels.core.types import Tier
        text = "SSN: 123-45-6789"
        spans = detector.detect(text)

        if spans:
            assert spans[0].tier == Tier.CHECKSUM


class TestEdgeCases:
    """Edge case and security tests."""

    @pytest.fixture
    def detector(self):
        return ChecksumDetector()

    def test_empty_string(self, detector):
        """Test empty string input."""
        spans = detector.detect("")
        assert spans == []

    def test_very_long_string(self, detector):
        """Test very long string doesn't cause issues."""
        text = "a" * 100000 + " 123-45-6789 " + "b" * 100000
        spans = detector.detect(text)
        # Should still find the SSN
        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) == 1

    def test_unicode_text(self, detector):
        """Test Unicode text handling."""
        text = "Patient: \u00c9ric, SSN: 123-45-6789"
        spans = detector.detect(text)
        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) == 1

    def test_special_characters(self, detector):
        """Test special characters don't break detection."""
        text = "SSN: 123-45-6789 <script>alert('xss')</script>"
        spans = detector.detect(text)
        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) == 1
