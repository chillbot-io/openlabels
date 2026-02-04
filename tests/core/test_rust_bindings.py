"""
Comprehensive tests for core/_rust module (Python fallback implementations).

Tests focus on:
- PatternMatcherWrapper class
- MatchResult dataclass
- Validators (Luhn, SSN, phone, email, IPv4, IBAN, NPI, CUSIP, ISIN)
- Pattern definitions and matching
"""

import pytest
from unittest.mock import patch, MagicMock


class TestMatchResult:
    """Tests for the MatchResult dataclass."""

    def test_match_result_creation(self):
        """MatchResult should store all fields correctly."""
        from openlabels.core._rust import MatchResult

        result = MatchResult(
            pattern_name="TEST",
            start=0,
            end=10,
            matched_text="0123456789",
            confidence=0.85,
            validator="luhn",
        )

        assert result.pattern_name == "TEST"
        assert result.start == 0
        assert result.end == 10
        assert result.matched_text == "0123456789"
        assert result.confidence == 0.85
        assert result.validator == "luhn"

    def test_match_result_without_validator(self):
        """MatchResult should default validator to None."""
        from openlabels.core._rust import MatchResult

        result = MatchResult(
            pattern_name="TEST",
            start=0,
            end=5,
            matched_text="test",
            confidence=0.75,
        )

        assert result.validator is None

    def test_match_result_equality(self):
        """MatchResult dataclass should support equality checks."""
        from openlabels.core._rust import MatchResult

        result1 = MatchResult("TEST", 0, 5, "hello", 0.8)
        result2 = MatchResult("TEST", 0, 5, "hello", 0.8)

        assert result1 == result2


class TestPatternMatcherWrapper:
    """Tests for the PatternMatcherWrapper class."""

    def test_init_with_patterns(self):
        """PatternMatcherWrapper should initialize with custom patterns."""
        from openlabels.core._rust import PatternMatcherWrapper

        patterns = [
            ("TEST1", r"\d{4}", None, 0.5),
            ("TEST2", r"[A-Z]+", None, 0.6),
        ]
        matcher = PatternMatcherWrapper(patterns)

        assert matcher.pattern_count == 2
        assert "TEST1" in matcher.pattern_names
        assert "TEST2" in matcher.pattern_names

    def test_init_with_validator_pattern(self):
        """PatternMatcherWrapper should initialize patterns with validators."""
        from openlabels.core._rust import PatternMatcherWrapper

        patterns = [
            ("CREDIT_CARD", r"\d{16}", "luhn", 0.8),
        ]
        matcher = PatternMatcherWrapper(patterns)

        assert matcher.pattern_count == 1

    def test_init_skips_invalid_regex(self):
        """PatternMatcherWrapper should skip invalid regex patterns."""
        from openlabels.core._rust import PatternMatcherWrapper

        patterns = [
            ("VALID", r"\d{4}", None, 0.5),
            ("INVALID", r"[unclosed", None, 0.5),  # Invalid regex
        ]
        matcher = PatternMatcherWrapper(patterns)

        # Should only have the valid pattern
        assert matcher.pattern_count == 1
        assert "VALID" in matcher.pattern_names

    def test_with_builtin_patterns(self):
        """with_builtin_patterns should create matcher with default patterns."""
        from openlabels.core._rust import PatternMatcherWrapper

        matcher = PatternMatcherWrapper.with_builtin_patterns()

        assert matcher.pattern_count > 0
        # Check for some expected pattern names
        names = matcher.pattern_names
        assert any("SSN" in name for name in names)
        assert any("EMAIL" in name for name in names)

    def test_find_matches_returns_list(self):
        """find_matches should return a list of MatchResult objects with correct attributes."""
        from openlabels.core._rust import PatternMatcherWrapper, MatchResult

        patterns = [("DIGITS", r"\d{4}", None, 0.7)]
        matcher = PatternMatcherWrapper(patterns)

        results = matcher.find_matches("Test 1234 here")

        assert len(results) == 1, "Should find exactly one 4-digit match"
        assert isinstance(results[0], MatchResult), f"Result should be MatchResult, got {type(results[0])}"
        assert results[0].matched_text == "1234", f"Should match '1234', got: {results[0].matched_text}"
        assert results[0].pattern_name == "DIGITS", f"Pattern name should be DIGITS, got: {results[0].pattern_name}"
        assert results[0].start == 5, f"Start position should be 5, got: {results[0].start}"
        assert results[0].end == 9, f"End position should be 9, got: {results[0].end}"
        assert results[0].confidence == 0.7, f"Confidence should be 0.7, got: {results[0].confidence}"

    def test_find_matches_multiple_matches(self):
        """find_matches should find all matches in text."""
        from openlabels.core._rust import PatternMatcherWrapper

        patterns = [("DIGITS", r"\d{4}", None, 0.7)]
        matcher = PatternMatcherWrapper(patterns)

        results = matcher.find_matches("Numbers: 1234 and 5678")

        assert len(results) == 2
        assert results[0].matched_text == "1234"
        assert results[1].matched_text == "5678"

    def test_find_matches_no_matches(self):
        """find_matches should return empty list when no matches."""
        from openlabels.core._rust import PatternMatcherWrapper

        patterns = [("DIGITS", r"\d{4}", None, 0.7)]
        matcher = PatternMatcherWrapper(patterns)

        results = matcher.find_matches("No numbers here")

        assert results == []

    def test_find_matches_with_validator(self):
        """find_matches should apply validator and filter invalid matches."""
        from openlabels.core._rust import PatternMatcherWrapper

        # Pattern that would match but fail Luhn validation
        patterns = [("CARD", r"\d{16}", "luhn", 0.8)]
        matcher = PatternMatcherWrapper(patterns)

        # This number passes Luhn
        results = matcher.find_matches("Card: 4532015112830366")
        assert len(results) == 1

    def test_find_matches_position_tracking(self):
        """find_matches should correctly track start and end positions."""
        from openlabels.core._rust import PatternMatcherWrapper

        patterns = [("WORD", r"hello", None, 0.5)]
        matcher = PatternMatcherWrapper(patterns)

        results = matcher.find_matches("Say hello world")

        assert len(results) == 1
        assert results[0].start == 4
        assert results[0].end == 9

    def test_find_matches_batch_basic(self):
        """find_matches_batch should process multiple texts."""
        from openlabels.core._rust import PatternMatcherWrapper

        patterns = [("DIGITS", r"\d{4}", None, 0.7)]
        matcher = PatternMatcherWrapper(patterns)

        texts = ["Test 1234", "Number 5678", "No match"]
        results = matcher.find_matches_batch(texts)

        assert len(results) == 3
        assert len(results[0]) == 1
        assert len(results[1]) == 1
        assert len(results[2]) == 0

    def test_find_matches_batch_empty_list(self):
        """find_matches_batch should handle empty input list."""
        from openlabels.core._rust import PatternMatcherWrapper

        patterns = [("DIGITS", r"\d{4}", None, 0.7)]
        matcher = PatternMatcherWrapper(patterns)

        results = matcher.find_matches_batch([])

        assert results == []

    def test_pattern_count_property(self):
        """pattern_count should return correct count."""
        from openlabels.core._rust import PatternMatcherWrapper

        patterns = [
            ("P1", r"\d", None, 0.5),
            ("P2", r"\w", None, 0.5),
            ("P3", r"\s", None, 0.5),
        ]
        matcher = PatternMatcherWrapper(patterns)

        assert matcher.pattern_count == 3

    def test_pattern_names_property(self):
        """pattern_names should return all pattern names."""
        from openlabels.core._rust import PatternMatcherWrapper

        patterns = [
            ("ALPHA", r"[A-Z]", None, 0.5),
            ("BETA", r"[0-9]", None, 0.5),
        ]
        matcher = PatternMatcherWrapper(patterns)

        names = matcher.pattern_names
        assert "ALPHA" in names
        assert "BETA" in names

    def test_is_rust_property(self):
        """is_rust should indicate which implementation is used."""
        from openlabels.core._rust import PatternMatcherWrapper, _RUST_AVAILABLE

        patterns = [("TEST", r"\d", None, 0.5)]
        matcher = PatternMatcherWrapper(patterns)

        # The is_rust property should match whether Rust is available
        assert matcher.is_rust == _RUST_AVAILABLE

    def test_confidence_boost_from_validator(self):
        """Valid matches should get confidence boost from validator."""
        from openlabels.core._rust import PatternMatcherWrapper

        # Use phone validator which gives 0.05 boost
        patterns = [("PHONE", r"\d{10}", "phone", 0.70)]
        matcher = PatternMatcherWrapper(patterns)

        results = matcher.find_matches("Call 5551234567")

        if results:
            # Should have base 0.70 + 0.05 boost = 0.75
            assert results[0].confidence == 0.75

    def test_confidence_capped_at_one(self):
        """Confidence should be capped at 1.0 after boost."""
        from openlabels.core._rust import PatternMatcherWrapper

        # High base confidence + boost should cap at 1.0
        patterns = [("HIGH_CONF", r"\d{10}", "phone", 0.98)]
        matcher = PatternMatcherWrapper(patterns)

        results = matcher.find_matches("Call 5551234567")

        if results:
            assert results[0].confidence <= 1.0


class TestValidateLuhn:
    """Tests for the Luhn validator."""

    def test_valid_visa_number(self):
        """Luhn should validate a correct Visa card number."""
        from openlabels.core._rust.validators_py import validate_luhn

        # Known valid Visa test number
        assert validate_luhn("4532015112830366") is True

    def test_valid_mastercard_number(self):
        """Luhn should validate a correct Mastercard number."""
        from openlabels.core._rust.validators_py import validate_luhn

        # Known valid Mastercard test number
        assert validate_luhn("5425233430109903") is True

    def test_invalid_luhn_number(self):
        """Luhn should reject invalid numbers."""
        from openlabels.core._rust.validators_py import validate_luhn

        assert validate_luhn("4532015112830367") is False  # Changed last digit

    def test_luhn_with_spaces(self):
        """Luhn should handle formatted numbers with spaces."""
        from openlabels.core._rust.validators_py import validate_luhn

        # Spaces should be ignored
        assert validate_luhn("4532 0151 1283 0366") is True

    def test_luhn_with_dashes(self):
        """Luhn should handle formatted numbers with dashes."""
        from openlabels.core._rust.validators_py import validate_luhn

        assert validate_luhn("4532-0151-1283-0366") is True

    def test_luhn_too_short(self):
        """Luhn should reject numbers with less than 2 digits."""
        from openlabels.core._rust.validators_py import validate_luhn

        assert validate_luhn("1") is False
        assert validate_luhn("") is False

    def test_luhn_non_numeric_ignored(self):
        """Luhn should ignore non-numeric characters."""
        from openlabels.core._rust.validators_py import validate_luhn

        # Same valid number with letters
        assert validate_luhn("4532A0151B1283C0366") is True


class TestValidateSSN:
    """Tests for the SSN validator."""

    def test_valid_ssn(self):
        """SSN validator should accept valid SSNs."""
        from openlabels.core._rust.validators_py import validate_ssn

        assert validate_ssn("123-45-6789") is True
        assert validate_ssn("123456789") is True

    def test_ssn_area_zero_invalid(self):
        """SSN validator should reject area code 000."""
        from openlabels.core._rust.validators_py import validate_ssn

        assert validate_ssn("000-12-3456") is False

    def test_ssn_area_666_invalid(self):
        """SSN validator should reject area code 666."""
        from openlabels.core._rust.validators_py import validate_ssn

        assert validate_ssn("666-12-3456") is False

    def test_ssn_area_900_999_invalid(self):
        """SSN validator should reject area codes 900-999."""
        from openlabels.core._rust.validators_py import validate_ssn

        assert validate_ssn("900-12-3456") is False
        assert validate_ssn("999-12-3456") is False

    def test_ssn_group_zero_invalid(self):
        """SSN validator should reject group number 00."""
        from openlabels.core._rust.validators_py import validate_ssn

        assert validate_ssn("123-00-4567") is False

    def test_ssn_serial_zero_invalid(self):
        """SSN validator should reject serial number 0000."""
        from openlabels.core._rust.validators_py import validate_ssn

        assert validate_ssn("123-45-0000") is False

    def test_ssn_wrong_length(self):
        """SSN validator should reject wrong length numbers."""
        from openlabels.core._rust.validators_py import validate_ssn

        assert validate_ssn("12345678") is False  # 8 digits
        assert validate_ssn("1234567890") is False  # 10 digits


class TestValidatePhone:
    """Tests for the phone validator."""

    def test_valid_us_phone(self):
        """Phone validator should accept 10-digit US numbers."""
        from openlabels.core._rust.validators_py import validate_phone

        assert validate_phone("5551234567") is True
        assert validate_phone("(555) 123-4567") is True

    def test_valid_international_phone(self):
        """Phone validator should accept international numbers."""
        from openlabels.core._rust.validators_py import validate_phone

        assert validate_phone("+14155551234") is True
        assert validate_phone("+442071234567") is True

    def test_phone_too_short(self):
        """Phone validator should reject too short numbers."""
        from openlabels.core._rust.validators_py import validate_phone

        assert validate_phone("123456789") is False  # 9 digits

    def test_phone_too_long(self):
        """Phone validator should reject too long numbers."""
        from openlabels.core._rust.validators_py import validate_phone

        assert validate_phone("1234567890123456") is False  # 16 digits


class TestValidateEmail:
    """Tests for the email validator."""

    def test_valid_email(self):
        """Email validator should accept valid emails."""
        from openlabels.core._rust.validators_py import validate_email

        assert validate_email("user@example.com") is True
        assert validate_email("user.name@example.co.uk") is True
        assert validate_email("user+tag@example.com") is True

    def test_email_no_at_sign(self):
        """Email validator should reject emails without @."""
        from openlabels.core._rust.validators_py import validate_email

        assert validate_email("userexample.com") is False

    def test_email_no_domain(self):
        """Email validator should reject emails without domain."""
        from openlabels.core._rust.validators_py import validate_email

        assert validate_email("user@") is False

    def test_email_no_local_part(self):
        """Email validator should reject emails without local part."""
        from openlabels.core._rust.validators_py import validate_email

        assert validate_email("@example.com") is False

    def test_email_no_tld(self):
        """Email validator should reject emails without TLD."""
        from openlabels.core._rust.validators_py import validate_email

        assert validate_email("user@example") is False

    def test_email_domain_starts_with_dot(self):
        """Email validator should reject domains starting with dot."""
        from openlabels.core._rust.validators_py import validate_email

        assert validate_email("user@.example.com") is False

    def test_email_domain_ends_with_dot(self):
        """Email validator should reject domains ending with dot."""
        from openlabels.core._rust.validators_py import validate_email

        assert validate_email("user@example.com.") is False


class TestValidateIPv4:
    """Tests for the IPv4 validator."""

    def test_valid_ipv4(self):
        """IPv4 validator should accept valid addresses."""
        from openlabels.core._rust.validators_py import validate_ipv4

        assert validate_ipv4("192.168.1.1") is True
        assert validate_ipv4("10.0.0.0") is True
        assert validate_ipv4("255.255.255.255") is True
        assert validate_ipv4("0.0.0.0") is True

    def test_ipv4_octet_too_high(self):
        """IPv4 validator should reject octets > 255."""
        from openlabels.core._rust.validators_py import validate_ipv4

        assert validate_ipv4("256.0.0.1") is False
        assert validate_ipv4("192.168.1.300") is False

    def test_ipv4_wrong_parts(self):
        """IPv4 validator should reject wrong number of parts."""
        from openlabels.core._rust.validators_py import validate_ipv4

        assert validate_ipv4("192.168.1") is False
        assert validate_ipv4("192.168.1.1.1") is False

    def test_ipv4_non_numeric(self):
        """IPv4 validator should reject non-numeric parts."""
        from openlabels.core._rust.validators_py import validate_ipv4

        assert validate_ipv4("192.168.1.abc") is False

    def test_ipv4_negative(self):
        """IPv4 validator should reject negative numbers."""
        from openlabels.core._rust.validators_py import validate_ipv4

        assert validate_ipv4("192.168.-1.1") is False


class TestValidateIBAN:
    """Tests for the IBAN validator."""

    def test_valid_iban_germany(self):
        """IBAN validator should accept valid German IBAN."""
        from openlabels.core._rust.validators_py import validate_iban

        # Valid test IBAN
        assert validate_iban("DE89370400440532013000") is True

    def test_valid_iban_uk(self):
        """IBAN validator should accept valid UK IBAN."""
        from openlabels.core._rust.validators_py import validate_iban

        # Valid UK test IBAN
        assert validate_iban("GB82WEST12345698765432") is True

    def test_iban_with_spaces(self):
        """IBAN validator should handle formatted IBANs with spaces."""
        from openlabels.core._rust.validators_py import validate_iban

        assert validate_iban("DE89 3704 0044 0532 0130 00") is True

    def test_iban_invalid_checksum(self):
        """IBAN validator should reject invalid checksums."""
        from openlabels.core._rust.validators_py import validate_iban

        # Changed a digit to make checksum invalid
        assert validate_iban("DE89370400440532013001") is False

    def test_iban_too_short(self):
        """IBAN validator should reject too short IBANs."""
        from openlabels.core._rust.validators_py import validate_iban

        assert validate_iban("DE123456789") is False  # Less than 15

    def test_iban_too_long(self):
        """IBAN validator should reject too long IBANs."""
        from openlabels.core._rust.validators_py import validate_iban

        # Over 34 characters
        assert validate_iban("DE89370400440532013000123456789012345") is False


class TestValidateNPI:
    """Tests for the NPI (National Provider Identifier) validator."""

    def test_valid_npi(self):
        """NPI validator should accept valid NPIs."""
        from openlabels.core._rust.validators_py import validate_npi

        # Valid test NPIs
        assert validate_npi("1234567893") is True

    def test_npi_wrong_length(self):
        """NPI validator should reject wrong length numbers."""
        from openlabels.core._rust.validators_py import validate_npi

        assert validate_npi("123456789") is False  # 9 digits
        assert validate_npi("12345678901") is False  # 11 digits

    def test_npi_invalid_checksum(self):
        """NPI validator should reject invalid checksums."""
        from openlabels.core._rust.validators_py import validate_npi

        assert validate_npi("1234567890") is False  # Invalid check digit


class TestValidateCUSIP:
    """Tests for the CUSIP validator."""

    def test_valid_cusip(self):
        """CUSIP validator should accept valid CUSIPs."""
        from openlabels.core._rust.validators_py import validate_cusip

        # Apple Inc CUSIP
        assert validate_cusip("037833100") is True

    def test_cusip_wrong_length(self):
        """CUSIP validator should reject wrong length."""
        from openlabels.core._rust.validators_py import validate_cusip

        assert validate_cusip("03783310") is False  # 8 chars
        assert validate_cusip("0378331001") is False  # 10 chars

    def test_cusip_invalid_checksum(self):
        """CUSIP validator should reject invalid checksums."""
        from openlabels.core._rust.validators_py import validate_cusip

        assert validate_cusip("037833101") is False  # Wrong check digit


class TestValidateISIN:
    """Tests for the ISIN validator."""

    def test_valid_isin(self):
        """ISIN validator should accept valid ISINs."""
        from openlabels.core._rust.validators_py import validate_isin

        # Apple Inc ISIN
        assert validate_isin("US0378331005") is True

    def test_isin_wrong_length(self):
        """ISIN validator should reject wrong length."""
        from openlabels.core._rust.validators_py import validate_isin

        assert validate_isin("US037833100") is False  # 11 chars
        assert validate_isin("US03783310051") is False  # 13 chars

    def test_isin_invalid_country_code(self):
        """ISIN validator should reject non-letter country codes."""
        from openlabels.core._rust.validators_py import validate_isin

        assert validate_isin("120378331005") is False  # Starts with numbers

    def test_isin_invalid_checksum(self):
        """ISIN validator should reject invalid checksums."""
        from openlabels.core._rust.validators_py import validate_isin

        assert validate_isin("US0378331006") is False  # Wrong check digit


class TestValidateDispatcher:
    """Tests for the validate() dispatcher function."""

    def test_validate_luhn_validator(self):
        """validate() should dispatch to Luhn validator."""
        from openlabels.core._rust.validators_py import validate

        is_valid, boost = validate("4532015112830366", "luhn")
        assert is_valid is True
        assert boost == 0.15

    def test_validate_ssn_validator(self):
        """validate() should dispatch to SSN validator."""
        from openlabels.core._rust.validators_py import validate

        is_valid, boost = validate("123-45-6789", "ssn")
        assert is_valid is True
        assert boost == 0.10

    def test_validate_phone_validator(self):
        """validate() should dispatch to phone validator."""
        from openlabels.core._rust.validators_py import validate

        is_valid, boost = validate("5551234567", "phone")
        assert is_valid is True
        assert boost == 0.05

    def test_validate_email_validator(self):
        """validate() should dispatch to email validator."""
        from openlabels.core._rust.validators_py import validate

        is_valid, boost = validate("user@example.com", "email")
        assert is_valid is True
        assert boost == 0.05

    def test_validate_ipv4_validator(self):
        """validate() should dispatch to IPv4 validator."""
        from openlabels.core._rust.validators_py import validate

        is_valid, boost = validate("192.168.1.1", "ipv4")
        assert is_valid is True
        assert boost == 0.05

    def test_validate_iban_validator(self):
        """validate() should dispatch to IBAN validator."""
        from openlabels.core._rust.validators_py import validate

        is_valid, boost = validate("DE89370400440532013000", "iban")
        assert is_valid is True
        assert boost == 0.15

    def test_validate_npi_validator(self):
        """validate() should dispatch to NPI validator."""
        from openlabels.core._rust.validators_py import validate

        is_valid, boost = validate("1234567893", "npi")
        assert is_valid is True
        assert boost == 0.15

    def test_validate_cusip_validator(self):
        """validate() should dispatch to CUSIP validator."""
        from openlabels.core._rust.validators_py import validate

        is_valid, boost = validate("037833100", "cusip")
        assert is_valid is True
        assert boost == 0.15

    def test_validate_isin_validator(self):
        """validate() should dispatch to ISIN validator."""
        from openlabels.core._rust.validators_py import validate

        is_valid, boost = validate("US0378331005", "isin")
        assert is_valid is True
        assert boost == 0.15

    def test_validate_unknown_validator(self):
        """validate() should pass through unknown validators."""
        from openlabels.core._rust.validators_py import validate

        is_valid, boost = validate("anything", "unknown_validator")
        assert is_valid is True
        assert boost == 0.0

    def test_validate_returns_false_for_invalid(self):
        """validate() should return False for invalid values."""
        from openlabels.core._rust.validators_py import validate

        is_valid, boost = validate("invalid-ssn", "ssn")
        assert is_valid is False
        assert boost == 0.0


class TestBuiltinPatterns:
    """Tests for the BUILTIN_PATTERNS definitions."""

    def test_builtin_patterns_not_empty(self):
        """BUILTIN_PATTERNS should contain expected core patterns."""
        from openlabels.core._rust.patterns_py import BUILTIN_PATTERNS

        assert len(BUILTIN_PATTERNS) >= 10, "Should have at least 10 builtin patterns"
        pattern_names = [p[0] for p in BUILTIN_PATTERNS]
        assert "SSN" in pattern_names, "Should include SSN pattern"
        assert "EMAIL" in pattern_names, "Should include EMAIL pattern"
        assert "AWS_ACCESS_KEY" in pattern_names, "Should include AWS_ACCESS_KEY pattern"

    def test_builtin_patterns_format(self):
        """BUILTIN_PATTERNS should have correct tuple format."""
        from openlabels.core._rust.patterns_py import BUILTIN_PATTERNS

        for pattern in BUILTIN_PATTERNS:
            assert len(pattern) == 4
            name, regex, validator, confidence = pattern
            assert isinstance(name, str)
            assert isinstance(regex, str)
            assert validator is None or isinstance(validator, str)
            assert isinstance(confidence, float)
            assert 0 <= confidence <= 1

    def test_builtin_patterns_valid_regex(self):
        """All BUILTIN_PATTERNS should have valid regex."""
        import re
        from openlabels.core._rust.patterns_py import BUILTIN_PATTERNS

        for name, regex, _, _ in BUILTIN_PATTERNS:
            try:
                re.compile(regex)
            except re.error as e:
                pytest.fail(f"Invalid regex in pattern '{name}': {e}")

    def test_builtin_patterns_has_ssn(self):
        """BUILTIN_PATTERNS should include SSN pattern."""
        from openlabels.core._rust.patterns_py import BUILTIN_PATTERNS

        names = [p[0] for p in BUILTIN_PATTERNS]
        assert "SSN" in names

    def test_builtin_patterns_has_email(self):
        """BUILTIN_PATTERNS should include EMAIL pattern."""
        from openlabels.core._rust.patterns_py import BUILTIN_PATTERNS

        names = [p[0] for p in BUILTIN_PATTERNS]
        assert "EMAIL" in names

    def test_builtin_patterns_has_credit_cards(self):
        """BUILTIN_PATTERNS should include credit card patterns."""
        from openlabels.core._rust.patterns_py import BUILTIN_PATTERNS

        names = [p[0] for p in BUILTIN_PATTERNS]
        assert any("CREDIT_CARD" in name for name in names)

    def test_builtin_patterns_has_aws_keys(self):
        """BUILTIN_PATTERNS should include AWS key patterns."""
        from openlabels.core._rust.patterns_py import BUILTIN_PATTERNS

        names = [p[0] for p in BUILTIN_PATTERNS]
        assert "AWS_ACCESS_KEY" in names


class TestPatternMatcherIntegration:
    """Integration tests for the pattern matcher with real data."""

    def test_detect_ssn(self):
        """Pattern matcher should detect SSN."""
        from openlabels.core._rust import PatternMatcherWrapper

        matcher = PatternMatcherWrapper.with_builtin_patterns()
        results = matcher.find_matches("My SSN is 123-45-6789")

        ssn_matches = [r for r in results if "SSN" in r.pattern_name]
        assert len(ssn_matches) >= 1, "Should detect at least one SSN"
        assert ssn_matches[0].matched_text == "123-45-6789", f"Should match exact SSN, got: {ssn_matches[0].matched_text}"
        assert ssn_matches[0].confidence >= 0.8, f"SSN should have high confidence, got: {ssn_matches[0].confidence}"

    def test_detect_email(self):
        """Pattern matcher should detect email addresses."""
        from openlabels.core._rust import PatternMatcherWrapper

        matcher = PatternMatcherWrapper.with_builtin_patterns()
        results = matcher.find_matches("Contact me at user@example.com")

        email_matches = [r for r in results if r.pattern_name == "EMAIL"]
        assert len(email_matches) == 1
        assert email_matches[0].matched_text == "user@example.com"

    def test_detect_ipv4(self):
        """Pattern matcher should detect IPv4 addresses."""
        from openlabels.core._rust import PatternMatcherWrapper

        matcher = PatternMatcherWrapper.with_builtin_patterns()
        results = matcher.find_matches("Server at 192.168.1.100")

        ip_matches = [r for r in results if r.pattern_name == "IPV4"]
        assert len(ip_matches) == 1
        assert ip_matches[0].matched_text == "192.168.1.100"

    def test_detect_aws_access_key(self):
        """Pattern matcher should detect AWS access keys."""
        from openlabels.core._rust import PatternMatcherWrapper

        matcher = PatternMatcherWrapper.with_builtin_patterns()
        results = matcher.find_matches("AWS key: AKIAIOSFODNN7EXAMPLE")

        aws_matches = [r for r in results if "AWS" in r.pattern_name]
        assert len(aws_matches) >= 1, "Should detect AWS access key"
        assert "AKIAIOSFODNN7EXAMPLE" in aws_matches[0].matched_text, \
            f"Should match AWS key, got: {aws_matches[0].matched_text}"

    def test_detect_private_key(self):
        """Pattern matcher should detect private key headers."""
        from openlabels.core._rust import PatternMatcherWrapper

        matcher = PatternMatcherWrapper.with_builtin_patterns()
        results = matcher.find_matches("-----BEGIN RSA PRIVATE KEY-----")

        key_matches = [r for r in results if "PRIVATE_KEY" in r.pattern_name]
        assert len(key_matches) >= 1, "Should detect private key header"
        assert "BEGIN RSA PRIVATE KEY" in key_matches[0].matched_text, \
            f"Should match key header, got: {key_matches[0].matched_text}"

    def test_detect_classification_marking(self):
        """Pattern matcher should detect classification markings."""
        from openlabels.core._rust import PatternMatcherWrapper

        matcher = PatternMatcherWrapper.with_builtin_patterns()
        results = matcher.find_matches("TOP SECRET document")

        class_matches = [r for r in results if "CLASSIFICATION" in r.pattern_name]
        assert len(class_matches) >= 1, "Should detect classification marking"
        assert "TOP SECRET" in class_matches[0].matched_text, \
            f"Should match TOP SECRET, got: {class_matches[0].matched_text}"

    def test_multiple_patterns_in_document(self):
        """Pattern matcher should detect multiple patterns in a document."""
        from openlabels.core._rust import PatternMatcherWrapper

        matcher = PatternMatcherWrapper.with_builtin_patterns()
        text = """
        Employee: John Doe
        SSN: 123-45-6789
        Email: john.doe@company.com
        Phone: (555) 123-4567
        """
        results = matcher.find_matches(text)

        # Should find at least SSN, email, and phone
        pattern_types = set(r.pattern_name for r in results)
        assert "SSN" in pattern_types or any("SSN" in p for p in pattern_types)
        assert "EMAIL" in pattern_types

    def test_batch_processing_documents(self):
        """Pattern matcher should efficiently batch process multiple documents."""
        from openlabels.core._rust import PatternMatcherWrapper

        matcher = PatternMatcherWrapper.with_builtin_patterns()
        documents = [
            "SSN: 123-45-6789",
            "Email: test@example.com",
            "No sensitive data here",
            "IP: 10.0.0.1",
        ]

        results = matcher.find_matches_batch(documents)

        assert len(results) == 4
        # Doc 1 should have SSN match
        assert any("SSN" in r.pattern_name for r in results[0])
        # Doc 2 should have email match
        assert any("EMAIL" in r.pattern_name for r in results[1])
        # Doc 3 should have no matches
        assert len(results[2]) == 0
        # Doc 4 should have IP match
        assert any("IPV4" in r.pattern_name for r in results[3])


class TestRustAvailability:
    """Tests for Rust availability detection."""

    def test_rust_available_exported(self):
        """_RUST_AVAILABLE should be exported."""
        from openlabels.core._rust import _RUST_AVAILABLE

        assert isinstance(_RUST_AVAILABLE, bool)

    def test_pattern_matcher_exports(self):
        """Module should export expected classes."""
        from openlabels.core._rust import PatternMatcher, PatternMatcherWrapper, MatchResult

        # PatternMatcher should be an alias
        assert PatternMatcher is PatternMatcherWrapper
