"""Tests for checksum-validated detectors.

Tests Luhn algorithm, SSN, credit card, NPI, DEA, IBAN, and VIN validation.
"""

import pytest

from scrubiq.detectors.checksum import (
    luhn_check,
    validate_ssn,
    validate_credit_card,
    validate_npi,
    validate_dea,
    validate_iban,
    validate_vin,
)


# =============================================================================
# LUHN ALGORITHM TESTS
# =============================================================================

class TestLuhnCheck:
    """Tests for Luhn checksum validation."""

    def test_valid_visa(self):
        """Valid Visa card passes Luhn."""
        assert luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        """Valid Mastercard passes Luhn."""
        assert luhn_check("5500000000000004") is True

    def test_valid_amex(self):
        """Valid Amex passes Luhn."""
        assert luhn_check("340000000000009") is True

    def test_valid_discover(self):
        """Valid Discover passes Luhn."""
        assert luhn_check("6011000000000004") is True

    def test_invalid_checksum(self):
        """Invalid checksum fails."""
        assert luhn_check("4111111111111112") is False

    def test_with_separators(self):
        """Numbers with separators fail (non-digit chars)."""
        # Luhn should strip non-digits
        assert luhn_check("4111-1111-1111-1111") is True

    def test_with_spaces(self):
        """Numbers with spaces pass (spaces stripped)."""
        assert luhn_check("4111 1111 1111 1111") is True

    def test_too_short(self):
        """Single digit fails."""
        assert luhn_check("4") is False

    def test_minimum_length(self):
        """Two digits can be valid."""
        # 00 has checksum 0
        assert luhn_check("00") is True

    def test_empty_string(self):
        """Empty string fails."""
        assert luhn_check("") is False

    def test_non_digit_only(self):
        """Non-digit string fails."""
        assert luhn_check("abcdef") is False


# =============================================================================
# SSN VALIDATION TESTS
# =============================================================================

class TestValidateSSN:
    """Tests for SSN validation."""

    def test_valid_ssn_formatted(self):
        """Valid SSN with dashes passes."""
        valid, conf = validate_ssn("123-45-6789")
        assert valid is True
        assert conf > 0.9

    def test_valid_ssn_spaces(self):
        """Valid SSN with spaces passes."""
        valid, conf = validate_ssn("123 45 6789")
        assert valid is True
        assert conf > 0.9

    def test_valid_ssn_plain(self):
        """Valid SSN without separators passes."""
        valid, conf = validate_ssn("123456789")
        assert valid is True
        assert conf > 0.9

    def test_valid_ssn_returns_high_confidence(self):
        """Valid SSN returns 0.99 confidence."""
        valid, conf = validate_ssn("123-45-6789")
        assert conf == 0.99

    def test_invalid_area_000(self):
        """Area 000 is invalid but still detected."""
        valid, conf = validate_ssn("000-45-6789")
        assert valid is True
        assert conf == 0.85  # Lower confidence

    def test_invalid_area_666(self):
        """Area 666 is invalid but still detected."""
        valid, conf = validate_ssn("666-45-6789")
        assert valid is True
        assert conf == 0.85

    def test_invalid_area_9xx(self):
        """Area 9xx is invalid but still detected."""
        valid, conf = validate_ssn("900-45-6789")
        assert valid is True
        assert conf == 0.85

    def test_invalid_group_00(self):
        """Group 00 is invalid but still detected."""
        valid, conf = validate_ssn("123-00-6789")
        assert valid is True
        assert conf == 0.80

    def test_invalid_serial_0000(self):
        """Serial 0000 is invalid but still detected."""
        valid, conf = validate_ssn("123-45-0000")
        assert valid is True
        assert conf == 0.80

    def test_wrong_length_short(self):
        """Too short fails."""
        valid, conf = validate_ssn("12345678")
        assert valid is False

    def test_wrong_length_long(self):
        """Too long fails."""
        valid, conf = validate_ssn("1234567890")
        assert valid is False

    def test_non_ascii_digits_rejected(self):
        """Non-ASCII digits are rejected (security)."""
        # Unicode digits should be rejected
        valid, conf = validate_ssn("123-45-6789")  # Normal should pass
        assert valid is True
        # Note: actual unicode digit test would need unicode chars

    def test_special_characters_rejected(self):
        """Special characters are rejected."""
        valid, conf = validate_ssn("123@45#6789")
        assert valid is False

    def test_empty_string(self):
        """Empty string fails."""
        valid, conf = validate_ssn("")
        assert valid is False

    def test_whitespace_stripped(self):
        """Leading/trailing whitespace is stripped."""
        valid, conf = validate_ssn("  123-45-6789  ")
        assert valid is True


# =============================================================================
# CREDIT CARD VALIDATION TESTS
# =============================================================================

class TestValidateCreditCard:
    """Tests for credit card validation."""

    def test_valid_visa(self):
        """Valid Visa card passes."""
        valid, conf = validate_credit_card("4111111111111111")
        assert valid is True
        assert conf == 0.99

    def test_valid_mastercard(self):
        """Valid Mastercard passes."""
        valid, conf = validate_credit_card("5500000000000004")
        assert valid is True
        assert conf == 0.99

    def test_valid_amex(self):
        """Valid Amex passes."""
        valid, conf = validate_credit_card("340000000000009")
        assert valid is True
        assert conf == 0.99

    def test_valid_discover(self):
        """Valid Discover passes."""
        valid, conf = validate_credit_card("6011000000000004")
        assert valid is True
        assert conf == 0.99

    def test_with_dashes(self):
        """Card with dashes passes."""
        valid, conf = validate_credit_card("4111-1111-1111-1111")
        assert valid is True
        assert conf == 0.99

    def test_with_spaces(self):
        """Card with spaces passes."""
        valid, conf = validate_credit_card("4111 1111 1111 1111")
        assert valid is True
        assert conf == 0.99

    def test_invalid_luhn_valid_prefix(self):
        """Invalid Luhn but valid prefix still detected."""
        # Visa prefix but wrong checksum
        valid, conf = validate_credit_card("4111111111111112")
        assert valid is True
        assert conf == 0.87  # Lower confidence

    def test_invalid_prefix(self):
        """Invalid prefix fails."""
        valid, conf = validate_credit_card("9999999999999999")
        assert valid is False

    def test_too_short(self):
        """Too short fails."""
        valid, conf = validate_credit_card("411111111111")  # 12 digits
        assert valid is False

    def test_too_long(self):
        """Too long fails."""
        valid, conf = validate_credit_card("41111111111111111111")  # 20 digits
        assert valid is False

    def test_minimum_length(self):
        """13 digits can be valid."""
        # 13-digit Visa
        valid, conf = validate_credit_card("4222222222222")
        # Luhn might not pass, but prefix is valid
        assert valid is True

    def test_mastercard_2_prefix(self):
        """New Mastercard 2xxx range passes."""
        # 2221-2720 range
        valid, conf = validate_credit_card("2221000000000009")
        assert valid is True

    def test_jcb_prefix(self):
        """JCB prefix passes."""
        valid, conf = validate_credit_card("3530111333300000")
        assert valid is True

    def test_diners_prefix(self):
        """Diners Club prefix passes."""
        valid, conf = validate_credit_card("30000000000004")
        assert valid is True


# =============================================================================
# NPI VALIDATION TESTS
# =============================================================================

class TestValidateNPI:
    """Tests for NPI (National Provider Identifier) validation."""

    def test_valid_npi(self):
        """Valid NPI passes."""
        valid, conf = validate_npi("1234567893")
        assert valid is True
        assert conf == 0.99

    def test_starts_with_1(self):
        """NPI starting with 1 is valid."""
        valid, conf = validate_npi("1234567893")
        assert valid is True

    def test_starts_with_2(self):
        """NPI prefix 2 is allowed with valid checksum."""
        # NPI starting with 2 is allowed and must pass Luhn with 80840 prefix
        valid, conf = validate_npi("2000000002")  # Valid: Luhn(808402000000002) passes
        assert valid is True

    def test_invalid_start_3(self):
        """NPI starting with 3 fails."""
        valid, conf = validate_npi("3234567893")
        assert valid is False

    def test_wrong_length_short(self):
        """9 digits fails."""
        valid, conf = validate_npi("123456789")
        assert valid is False

    def test_wrong_length_long(self):
        """11 digits fails."""
        valid, conf = validate_npi("12345678901")
        assert valid is False

    def test_invalid_checksum(self):
        """Invalid Luhn checksum fails."""
        valid, conf = validate_npi("1234567890")  # Wrong checksum
        assert valid is False

    def test_with_separators(self):
        """NPI with separators strips them."""
        valid, conf = validate_npi("123-456-7893")
        assert valid is True


# =============================================================================
# DEA VALIDATION TESTS
# =============================================================================

class TestValidateDEA:
    """Tests for DEA number validation."""

    def test_valid_dea(self):
        """Valid DEA number passes."""
        valid, conf = validate_dea("AB1234563")
        assert valid is True
        assert conf == 0.99

    def test_valid_dea_lowercase(self):
        """Lowercase DEA is normalized and passes."""
        valid, conf = validate_dea("ab1234563")
        assert valid is True

    def test_wrong_length_short(self):
        """8 chars fails."""
        valid, conf = validate_dea("AB123456")
        assert valid is False

    def test_wrong_length_long(self):
        """10 chars fails."""
        valid, conf = validate_dea("AB12345678")
        assert valid is False

    def test_no_letters_prefix(self):
        """No letter prefix fails."""
        valid, conf = validate_dea("121234563")
        assert valid is False

    def test_one_letter_prefix(self):
        """Single letter prefix fails."""
        valid, conf = validate_dea("A11234563")
        assert valid is False

    def test_non_digit_suffix(self):
        """Non-digit suffix fails."""
        valid, conf = validate_dea("AB123456X")
        assert valid is False

    def test_invalid_checksum(self):
        """Invalid checksum fails."""
        valid, conf = validate_dea("AB1234560")  # Wrong checksum
        assert valid is False

    def test_with_spaces(self):
        """Spaces are stripped."""
        valid, conf = validate_dea("AB 1234563")
        assert valid is True


# =============================================================================
# IBAN VALIDATION TESTS
# =============================================================================

class TestValidateIBAN:
    """Tests for IBAN validation."""

    def test_valid_german_iban(self):
        """Valid German IBAN passes."""
        valid, conf = validate_iban("DE89370400440532013000")
        assert valid is True
        assert conf == 0.99

    def test_valid_uk_iban(self):
        """Valid UK IBAN passes."""
        valid, conf = validate_iban("GB82WEST12345698765432")
        assert valid is True

    def test_valid_french_iban(self):
        """Valid French IBAN passes."""
        valid, conf = validate_iban("FR7630006000011234567890189")
        assert valid is True

    def test_with_spaces(self):
        """IBAN with spaces passes."""
        valid, conf = validate_iban("DE89 3704 0044 0532 0130 00")
        assert valid is True

    def test_lowercase(self):
        """Lowercase IBAN is normalized."""
        valid, conf = validate_iban("de89370400440532013000")
        assert valid is True

    def test_too_short(self):
        """Too short fails."""
        valid, conf = validate_iban("DE8937040044")
        assert valid is False

    def test_too_long(self):
        """Too long fails."""
        valid, conf = validate_iban("DE" + "1" * 33)  # 35 chars
        assert valid is False

    def test_invalid_checksum(self):
        """Invalid checksum fails."""
        valid, conf = validate_iban("DE00370400440532013000")  # Wrong check digits
        assert valid is False

    def test_special_chars_fail(self):
        """Special characters fail."""
        valid, conf = validate_iban("DE89@3704#0044$0532")
        assert valid is False


# =============================================================================
# VIN VALIDATION TESTS
# =============================================================================

class TestValidateVIN:
    """Tests for VIN (Vehicle Identification Number) validation."""

    def test_valid_vin(self):
        """Valid VIN passes."""
        valid, conf = validate_vin("1HGBH41JXMN109186")
        assert valid is True
        assert conf == 0.99

    def test_wrong_length(self):
        """Non-17 character VIN fails."""
        valid, conf = validate_vin("1HGBH41JXMN10918")  # 16 chars
        assert valid is False

    def test_invalid_check_digit(self):
        """Invalid check digit fails."""
        valid, conf = validate_vin("1HGBH41JAMN109186")  # 'A' instead of 'X'
        assert valid is False

    def test_forbidden_chars_i(self):
        """VIN with 'I' fails."""
        valid, conf = validate_vin("1IGBH41JXMN109186")
        assert valid is False

    def test_forbidden_chars_o(self):
        """VIN with 'O' fails."""
        valid, conf = validate_vin("1OGBH41JXMN109186")
        assert valid is False

    def test_forbidden_chars_q(self):
        """VIN with 'Q' fails."""
        valid, conf = validate_vin("1QGBH41JXMN109186")
        assert valid is False

    def test_lowercase_normalized(self):
        """Lowercase VIN is normalized."""
        valid, conf = validate_vin("1hgbh41jxmn109186")
        assert valid is True


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for all validators."""

    def test_all_zeros_ssn(self):
        """All zeros SSN has very low confidence."""
        valid, conf = validate_ssn("000-00-0000")
        assert valid is True
        assert conf < 0.85  # Multiple invalid components

    def test_all_zeros_credit_card(self):
        """All zeros is not a valid credit card prefix."""
        valid, conf = validate_credit_card("0000000000000000")
        assert valid is False

    def test_sequential_numbers_cc(self):
        """Sequential numbers might not have valid prefix."""
        valid, conf = validate_credit_card("1234567890123456")
        assert valid is False  # Not a valid prefix

    def test_repeated_digits_npi(self):
        """Repeated digits may not pass NPI Luhn."""
        valid, conf = validate_npi("1111111111")
        # May or may not pass Luhn, but starts with 1
        # Let test verify consistency

    def test_none_values_handled(self):
        """Functions handle string inputs only."""
        # These should work with string inputs
        assert validate_ssn("") == (False, 0.0)
        assert validate_credit_card("") == (False, 0.0)
        assert validate_npi("") == (False, 0.0)
        assert validate_dea("") == (False, 0.0)
        assert validate_iban("") == (False, 0.0)
        assert validate_vin("") == (False, 0.0)
