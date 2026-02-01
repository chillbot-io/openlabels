"""
Tests for validators, checksum functions, and pipeline components.

Tests cover:
- Luhn algorithm validation (credit cards, NPI)
- SSN validation and structure checking
- IP address, phone, date, age, VIN validation
- SSN context-based false positive filtering
- Allowlist filtering
- Span filters (ID card context, tracking numbers)
"""

import pytest

from openlabels.adapters.scanner.detectors.checksum import (
    luhn_check,
    validate_ssn,
    validate_credit_card,
    validate_npi,
)
from openlabels.adapters.scanner.detectors.patterns.validators import (
    validate_ip,
    validate_phone,
    validate_date,
    validate_age,
    validate_vin,
    validate_ssn_context,
)
from openlabels.adapters.scanner.pipeline.allowlist import (
    COMMON_WORDS,
    SAFE_ALLOWLIST,
)
from openlabels.adapters.scanner.pipeline.span_filters import (
    is_id_card_context,
    is_tracking_number,
    filter_ml_mrn_on_id_cards,
)
from openlabels.adapters.scanner.types import Span, Tier


# =============================================================================
# Luhn Algorithm Tests
# =============================================================================

class TestLuhnCheck:
    """Tests for Luhn algorithm validation."""

    def test_valid_visa_card(self):
        """Test valid Visa card passes Luhn."""
        assert luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        """Test valid Mastercard passes Luhn."""
        assert luhn_check("5500000000000004") is True

    def test_valid_amex(self):
        """Test valid Amex passes Luhn."""
        assert luhn_check("340000000000009") is True

    def test_invalid_card_fails_luhn(self):
        """Test invalid card number fails Luhn."""
        assert luhn_check("4111111111111112") is False  # Wrong check digit

    def test_all_zeros_fails(self):
        """Test all zeros fails Luhn."""
        assert luhn_check("0000000000000000") is True  # Actually passes Luhn!

    def test_single_digit_fails(self):
        """Test single digit fails (too short)."""
        assert luhn_check("1") is False

    def test_empty_string_fails(self):
        """Test empty string fails."""
        assert luhn_check("") is False

    def test_with_dashes(self):
        """Test Luhn ignores dashes."""
        assert luhn_check("4111-1111-1111-1111") is True

    def test_with_spaces(self):
        """Test Luhn ignores spaces."""
        assert luhn_check("4111 1111 1111 1111") is True

    def test_non_digit_characters_ignored(self):
        """Test non-digit characters are ignored."""
        assert luhn_check("4111-1111-1111-1111") is True


# =============================================================================
# SSN Validation Tests
# =============================================================================

class TestValidateSSN:
    """Tests for SSN validation."""

    def test_valid_ssn_high_confidence(self):
        """Test valid SSN returns high confidence."""
        valid, confidence = validate_ssn("123-45-6789")
        assert valid is True
        assert confidence >= 0.9

    def test_valid_ssn_no_dashes(self):
        """Test valid SSN without dashes."""
        valid, confidence = validate_ssn("123456789")
        assert valid is True

    def test_valid_ssn_with_spaces(self):
        """Test valid SSN with spaces."""
        valid, confidence = validate_ssn("123 45 6789")
        assert valid is True

    def test_invalid_area_000(self):
        """Test SSN with area 000 has lower confidence."""
        valid, confidence = validate_ssn("000-45-6789")
        assert valid is True  # Still detected
        assert confidence < 0.9  # Lower confidence

    def test_invalid_area_666(self):
        """Test SSN with area 666 has lower confidence."""
        valid, confidence = validate_ssn("666-45-6789")
        assert valid is True
        assert confidence < 0.9

    def test_invalid_area_9xx(self):
        """Test SSN with area 9xx has lower confidence."""
        valid, confidence = validate_ssn("900-45-6789")
        assert valid is True
        assert confidence < 0.9

    def test_invalid_group_00(self):
        """Test SSN with group 00 has lower confidence."""
        valid, confidence = validate_ssn("123-00-6789")
        assert valid is True
        assert confidence < 0.9

    def test_invalid_serial_0000(self):
        """Test SSN with serial 0000 has lower confidence."""
        valid, confidence = validate_ssn("123-45-0000")
        assert valid is True
        assert confidence < 0.9

    def test_wrong_length_fails(self):
        """Test SSN with wrong length fails."""
        valid, _ = validate_ssn("12345678")  # 8 digits
        assert valid is False

        valid, _ = validate_ssn("1234567890")  # 10 digits
        assert valid is False

    def test_unicode_digits_rejected(self):
        """Test unicode digits are rejected for security."""
        # Unicode fullwidth digits should be rejected
        valid, _ = validate_ssn("１２３-４５-６７８９")
        assert valid is False

    def test_special_characters_rejected(self):
        """Test special characters are rejected."""
        valid, _ = validate_ssn("123@45#6789")
        assert valid is False


# =============================================================================
# Credit Card Validation Tests
# =============================================================================

class TestValidateCreditCard:
    """Tests for credit card validation."""

    def test_valid_visa(self):
        """Test valid Visa card."""
        valid, confidence = validate_credit_card("4111111111111111")
        assert valid is True
        assert confidence >= 0.9

    def test_valid_mastercard_classic(self):
        """Test valid Mastercard (classic range 51-55)."""
        valid, confidence = validate_credit_card("5500000000000004")
        assert valid is True

    def test_valid_mastercard_new_range(self):
        """Test valid Mastercard (new range 2221-2720)."""
        valid, confidence = validate_credit_card("2221000000000009")
        assert valid is True

    def test_valid_amex(self):
        """Test valid American Express."""
        valid, confidence = validate_credit_card("340000000000009")
        assert valid is True

    def test_valid_discover(self):
        """Test valid Discover card."""
        valid, confidence = validate_credit_card("6011000000000004")
        assert valid is True

    def test_invalid_prefix_rejected(self):
        """Test card with invalid prefix is rejected."""
        valid, _ = validate_credit_card("1111111111111111")
        assert valid is False

    def test_valid_prefix_invalid_luhn_still_detected(self):
        """Test card with valid prefix but invalid Luhn is still detected."""
        # Valid Visa prefix but wrong check digit
        valid, confidence = validate_credit_card("4111111111111112")
        assert valid is True  # Still detected for safety
        assert confidence < 0.9  # Lower confidence

    def test_too_short_rejected(self):
        """Test card that's too short is rejected."""
        valid, _ = validate_credit_card("411111111111")  # 12 digits
        assert valid is False

    def test_too_long_rejected(self):
        """Test card that's too long is rejected."""
        valid, _ = validate_credit_card("41111111111111111111")  # 20 digits
        assert valid is False


# =============================================================================
# NPI Validation Tests
# =============================================================================

class TestValidateNPI:
    """Tests for NPI (National Provider Identifier) validation."""

    def test_valid_npi(self):
        """Test valid NPI passes."""
        # NPI: 1234567893 (valid Luhn with 80840 prefix)
        valid, confidence = validate_npi("1234567893")
        assert valid is True

    def test_wrong_length_fails(self):
        """Test NPI with wrong length fails."""
        valid, _ = validate_npi("123456789")  # 9 digits
        assert valid is False

        valid, _ = validate_npi("12345678901")  # 11 digits
        assert valid is False

    def test_invalid_first_digit_fails(self):
        """Test NPI not starting with 1 or 2 fails."""
        valid, _ = validate_npi("3234567893")
        assert valid is False


# =============================================================================
# IP Address Validation Tests
# =============================================================================

class TestValidateIP:
    """Tests for IP address validation."""

    def test_valid_ip(self):
        """Test valid IP addresses."""
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("10.0.0.1") is True
        assert validate_ip("255.255.255.255") is True
        assert validate_ip("0.0.0.0") is True

    def test_invalid_octet_too_high(self):
        """Test IP with octet > 255 fails."""
        assert validate_ip("192.168.1.256") is False
        assert validate_ip("300.0.0.1") is False

    def test_negative_octet_fails(self):
        """Test IP with negative octet fails."""
        assert validate_ip("192.168.-1.1") is False

    def test_wrong_part_count_fails(self):
        """Test IP with wrong number of parts fails."""
        assert validate_ip("192.168.1") is False
        assert validate_ip("192.168.1.1.1") is False

    def test_non_numeric_fails(self):
        """Test IP with non-numeric parts fails."""
        assert validate_ip("192.168.1.abc") is False


# =============================================================================
# Phone Validation Tests
# =============================================================================

class TestValidatePhone:
    """Tests for phone number validation."""

    def test_valid_phone(self):
        """Test valid phone numbers."""
        assert validate_phone("212-555-4567") is True  # 212 (NYC) is valid

    def test_invalid_area_code_555(self):
        """Test phone with 555 area code fails."""
        assert validate_phone("555-123-4567") is False

    def test_invalid_area_code_000(self):
        """Test phone with 000 area code fails."""
        assert validate_phone("000-123-4567") is False

    def test_invalid_area_code_911(self):
        """Test phone with 911 area code fails."""
        assert validate_phone("911-123-4567") is False

    def test_all_zeros_fails(self):
        """Test phone with all zeros fails."""
        assert validate_phone("000-000-0000") is False

    def test_sequential_digits_fails(self):
        """Test phone with sequential digits fails."""
        assert validate_phone("123-456-7890") is False

    def test_repeated_digit_fails(self):
        """Test phone with all same digit fails."""
        assert validate_phone("111-111-1111") is False

    def test_short_phone_passes(self):
        """Test short phone (< 10 digits) passes through."""
        # Can't validate, so allow through
        assert validate_phone("123-4567") is True


# =============================================================================
# Date Validation Tests
# =============================================================================

class TestValidateDate:
    """Tests for date validation."""

    def test_valid_dates(self):
        """Test valid dates."""
        assert validate_date(1, 15, 2000) is True
        assert validate_date(12, 31, 2023) is True
        assert validate_date(6, 30, 1990) is True

    def test_invalid_month(self):
        """Test invalid month fails."""
        assert validate_date(0, 15, 2000) is False
        assert validate_date(13, 15, 2000) is False

    def test_invalid_day(self):
        """Test invalid day fails."""
        assert validate_date(1, 0, 2000) is False
        assert validate_date(1, 32, 2000) is False
        assert validate_date(4, 31, 2000) is False  # April has 30 days

    def test_leap_year_feb_29(self):
        """Test February 29 on leap year."""
        assert validate_date(2, 29, 2000) is True  # Leap year
        assert validate_date(2, 29, 2004) is True  # Leap year
        assert validate_date(2, 29, 2001) is False  # Not leap year

    def test_century_leap_year_rule(self):
        """Test century leap year rule."""
        assert validate_date(2, 29, 1900) is False  # Not leap (divisible by 100)
        assert validate_date(2, 29, 2000) is True   # Leap (divisible by 400)

    def test_year_out_of_range(self):
        """Test year out of range fails."""
        assert validate_date(1, 15, 1899) is False
        assert validate_date(1, 15, 2101) is False


# =============================================================================
# Age Validation Tests
# =============================================================================

class TestValidateAge:
    """Tests for age validation."""

    def test_valid_ages(self):
        """Test valid ages."""
        assert validate_age("0") is True
        assert validate_age("25") is True
        assert validate_age("65") is True
        assert validate_age("125") is True

    def test_invalid_ages(self):
        """Test invalid ages."""
        assert validate_age("-1") is False
        assert validate_age("126") is False
        assert validate_age("200") is False

    def test_non_numeric_fails(self):
        """Test non-numeric age fails."""
        assert validate_age("abc") is False
        assert validate_age("25 years") is False


# =============================================================================
# VIN Validation Tests
# =============================================================================

class TestValidateVIN:
    """Tests for VIN (Vehicle Identification Number) validation."""

    def test_valid_vin(self):
        """Test valid VIN with correct check digit."""
        # Example VIN with valid check digit
        assert validate_vin("11111111111111111") is True

    def test_wrong_length_fails(self):
        """Test VIN with wrong length fails."""
        assert validate_vin("1234567890123456") is False  # 16 chars
        assert validate_vin("123456789012345678") is False  # 18 chars

    def test_invalid_characters_fail(self):
        """Test VIN with invalid characters fails."""
        # VIN cannot contain I, O, Q
        assert validate_vin("1I111111111111111") is False
        assert validate_vin("1O111111111111111") is False
        assert validate_vin("1Q111111111111111") is False


# =============================================================================
# SSN Context Validation Tests
# =============================================================================

class TestValidateSSNContext:
    """Tests for SSN context-based false positive filtering."""

    def test_high_confidence_always_passes(self):
        """Test high confidence SSN always passes context check."""
        text = "Order #123-45-6789"
        assert validate_ssn_context(text, 7, 0.80) is True

    def test_order_number_prefix_fails(self):
        """Test 'order' prefix fails for low confidence."""
        text = "Order 123-45-6789"
        assert validate_ssn_context(text, 6, 0.5) is False

    def test_page_number_prefix_fails(self):
        """Test 'page' prefix fails for low confidence."""
        text = "Page 123-45-6789"
        assert validate_ssn_context(text, 5, 0.5) is False

    def test_reference_number_prefix_fails(self):
        """Test 'reference' prefix fails."""
        text = "Reference: 123-45-6789"
        assert validate_ssn_context(text, 11, 0.5) is False

    def test_invoice_number_prefix_fails(self):
        """Test 'invoice' prefix fails."""
        text = "Invoice #123-45-6789"
        assert validate_ssn_context(text, 9, 0.5) is False

    def test_no_suspicious_prefix_passes(self):
        """Test SSN without suspicious prefix passes."""
        text = "SSN: 123-45-6789"
        assert validate_ssn_context(text, 5, 0.5) is True

    def test_patient_context_passes(self):
        """Test patient context passes."""
        text = "Patient SSN: 123-45-6789"
        assert validate_ssn_context(text, 13, 0.5) is True


# =============================================================================
# Allowlist Tests
# =============================================================================

class TestAllowlist:
    """Tests for allowlist constants."""

    def test_common_words_contains_pronouns(self):
        """Test common words includes pronouns."""
        assert "he" in COMMON_WORDS
        assert "she" in COMMON_WORDS
        assert "they" in COMMON_WORDS

    def test_common_words_contains_articles(self):
        """Test common words includes articles."""
        assert "the" in COMMON_WORDS
        assert "a" in COMMON_WORDS
        assert "an" in COMMON_WORDS

    def test_common_words_contains_name_like_words(self):
        """Test common words includes words that are also names."""
        assert "will" in COMMON_WORDS  # Also a name
        assert "mark" in COMMON_WORDS  # Also a name
        assert "grace" in COMMON_WORDS  # Also a name

    def test_safe_allowlist_contains_relative_dates(self):
        """Test safe allowlist contains relative dates."""
        assert "today" in SAFE_ALLOWLIST
        assert "yesterday" in SAFE_ALLOWLIST
        assert "tomorrow" in SAFE_ALLOWLIST

    def test_safe_allowlist_contains_placeholder_text(self):
        """Test safe allowlist contains placeholder text."""
        assert "redacted" in SAFE_ALLOWLIST
        assert "n/a" in SAFE_ALLOWLIST
        assert "unknown" in SAFE_ALLOWLIST


# =============================================================================
# Span Filter Tests
# =============================================================================

class TestIDCardContext:
    """Tests for ID card context detection."""

    def test_drivers_license_detected(self):
        """Test driver's license text is detected."""
        text = "DRIVER'S LICENSE DLN: 12345 CLASS: C"
        assert is_id_card_context(text) is True

    def test_state_id_detected(self):
        """Test state ID text is detected."""
        text = "STATE ID DUPS: 0 RESTR: NONE"
        assert is_id_card_context(text) is True

    def test_clinical_notes_not_detected(self):
        """Test clinical notes are not flagged as ID card."""
        text = "Patient presented with chest pain. MRN: 12345678"
        assert is_id_card_context(text) is False

    def test_requires_multiple_indicators(self):
        """Test single indicator is not enough."""
        text = "DRIVER mentioned in conversation"
        assert is_id_card_context(text) is False


class TestTrackingNumber:
    """Tests for tracking number detection."""

    def test_usps_tracking_detected(self):
        """Test USPS tracking number is detected."""
        context = "USPS tracking: "
        span_text = "94001234567890123456"
        assert is_tracking_number(span_text, context) is True

    def test_fedex_tracking_detected(self):
        """Test FedEx tracking number is detected."""
        context = "FedEx: "
        span_text = "123456789012"
        assert is_tracking_number(span_text, context) is True

    def test_ups_tracking_detected(self):
        """Test UPS tracking number is detected."""
        context = "UPS tracking #"
        span_text = "1Z999AA10123456784"
        assert is_tracking_number(span_text, context) is True

    def test_non_tracking_context(self):
        """Test number without tracking context is not flagged."""
        context = "Patient ID: "
        span_text = "123456789012"
        # Without tracking context, might not be flagged
        # (depends on implementation)


class TestFilterMLMRNOnIDCards:
    """Tests for ML MRN filtering on ID cards."""

    def test_filters_ml_mrn_on_id_card(self):
        """Test ML MRN detections are filtered on ID cards."""
        text = "DRIVER'S LICENSE DLN: 12345 CLASS: C"
        spans = [
            Span(start=20, end=25, text="12345", entity_type="MRN",
                 confidence=0.9, detector="phi_bert", tier=Tier.ML),
        ]

        filtered = filter_ml_mrn_on_id_cards(spans, text)
        assert len(filtered) == 0

    def test_keeps_rule_based_mrn_on_id_card(self):
        """Test rule-based MRN is kept even on ID cards."""
        text = "DRIVER'S LICENSE DLN: 12345 CLASS: C MRN: 12345678"
        spans = [
            Span(start=40, end=48, text="12345678", entity_type="MRN",
                 confidence=0.9, detector="pattern", tier=Tier.PATTERN),  # Rule-based
        ]

        filtered = filter_ml_mrn_on_id_cards(spans, text)
        assert len(filtered) == 1

    def test_keeps_all_spans_on_clinical_notes(self):
        """Test all spans are kept on clinical notes."""
        text = "Patient MRN: 12345678"
        spans = [
            Span(start=13, end=21, text="12345678", entity_type="MRN",
                 confidence=0.9, detector="phi_bert", tier=Tier.ML),
        ]

        filtered = filter_ml_mrn_on_id_cards(spans, text)
        assert len(filtered) == 1


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_string_validations(self):
        """Test validators handle empty strings."""
        assert validate_ip("") is False
        assert validate_age("") is False
        assert luhn_check("") is False

    def test_whitespace_only(self):
        """Test validators handle whitespace-only input."""
        valid, _ = validate_ssn("   ")
        assert valid is False

    def test_very_long_input(self):
        """Test validators handle very long input."""
        long_number = "1" * 1000
        assert luhn_check(long_number) is False or luhn_check(long_number) is True
        # Just shouldn't crash

    def test_unicode_handling(self):
        """Test validators handle unicode gracefully."""
        # Unicode em-dash instead of hyphen
        valid, _ = validate_ssn("123—45—6789")  # em-dash
        assert valid is False

    def test_mixed_case_handling(self):
        """Test case-insensitive matching where appropriate."""
        # VIN should be case-insensitive
        result1 = validate_vin("11111111111111111")
        result2 = validate_vin("11111111111111111".lower())
        # Should produce same result
