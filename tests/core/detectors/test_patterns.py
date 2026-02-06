"""
Comprehensive tests for the Pattern Detector.

Tests detection of PHI/PII entities using regex patterns:
- Phone numbers (various formats)
- Email addresses
- Dates (various formats)
- Names (patients, providers, relatives)
- SSN (Social Security Numbers)
- Addresses (street, city, state, ZIP)
- Medical identifiers (MRN, NPI, DEA)
- Driver's licenses (state-specific)
- Credit cards
- VIN (Vehicle Identification Numbers)
- And many more pattern types

Also tests:
- Custom pattern registration
- Pattern validation functions
- False positive rejection
- Edge cases and boundary conditions
"""

import pytest
from openlabels.core.detectors.patterns import (
    PatternDetector,
    _validate_ip,
    _validate_phone,
    _validate_date,
    _validate_age,
    _validate_luhn,
    _validate_vin,
    _validate_ssn_context,
    _is_false_positive_name,
    PATTERNS,
    add_pattern,
)
from openlabels.core.types import Tier


# =============================================================================
# DETECTOR INITIALIZATION TESTS
# =============================================================================

# =============================================================================
# PHONE NUMBER TESTS
# =============================================================================

class TestPhoneDetection:
    """Test phone number detection."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_phone_parentheses_format(self, detector):
        """Test phone with parentheses: (212) 123-4567."""
        # Using 212 (New York) - valid area code. 555 is reserved/invalid.
        text = "Call me at (212) 123-4567"
        spans = detector.detect(text)

        phone_spans = [s for s in spans if s.entity_type == "PHONE"]
        assert len(phone_spans) >= 1

    def test_detect_phone_dashes_format(self, detector):
        """Test phone with dashes: 212-123-4567."""
        text = "Phone: 212-123-4567"
        spans = detector.detect(text)

        phone_spans = [s for s in spans if s.entity_type == "PHONE"]
        assert len(phone_spans) >= 1

    def test_detect_phone_dots_format(self, detector):
        """Test phone with dots: 212.123.4567."""
        text = "Contact: 212.123.4567"
        spans = detector.detect(text)

        phone_spans = [s for s in spans if s.entity_type == "PHONE"]
        assert len(phone_spans) >= 1

    def test_detect_phone_international_plus1(self, detector):
        """Test international phone: +1-555-123-4567."""
        text = "International: +1-555-123-4567"
        spans = detector.detect(text)

        phone_spans = [s for s in spans if s.entity_type == "PHONE"]
        assert len(phone_spans) >= 1

    def test_detect_phone_labeled(self, detector):
        """Test labeled phone: phone: (212) 123-4567."""
        text = "phone: (212) 123-4567"
        spans = detector.detect(text)

        phone_spans = [s for s in spans if s.entity_type == "PHONE"]
        assert len(phone_spans) >= 1

    def test_detect_fax_labeled(self, detector):
        """Test labeled fax number."""
        text = "fax: (212) 123-4567"
        spans = detector.detect(text)

        fax_spans = [s for s in spans if s.entity_type in ("FAX", "PHONE")]
        assert len(fax_spans) >= 1

    def test_reject_invalid_area_code(self, detector):
        """Test invalid area codes are rejected."""
        # 555 is reserved for fictional use
        text = "Phone: 555-555-5555"
        spans = detector.detect(text)

        phone_spans = [s for s in spans if s.entity_type == "PHONE"]
        # Should be rejected or have lower confidence
        assert len(phone_spans) == 0

    def test_reject_all_zeros(self, detector):
        """Test all zeros phone is rejected."""
        text = "Phone: 000-000-0000"
        spans = detector.detect(text)

        phone_spans = [s for s in spans if s.entity_type == "PHONE"]
        assert len(phone_spans) == 0


# =============================================================================
# EMAIL TESTS
# =============================================================================

class TestEmailDetection:
    """Test email address detection."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_basic_email(self, detector):
        """Test basic email detection."""
        text = "Contact: john.doe@example.com"
        spans = detector.detect(text)

        email_spans = [s for s in spans if s.entity_type == "EMAIL"]
        assert len(email_spans) >= 1
        assert any("john.doe@example.com" in s.text for s in email_spans)

    def test_detect_email_with_plus(self, detector):
        """Test email with plus addressing."""
        text = "Send to: john+newsletter@example.com"
        spans = detector.detect(text)

        email_spans = [s for s in spans if s.entity_type == "EMAIL"]
        assert len(email_spans) >= 1

    def test_detect_email_with_subdomain(self, detector):
        """Test email with subdomain."""
        text = "Email: user@mail.company.co.uk"
        spans = detector.detect(text)

        email_spans = [s for s in spans if s.entity_type == "EMAIL"]
        assert len(email_spans) >= 1

    def test_detect_labeled_email(self, detector):
        """Test labeled email detection."""
        text = "email: patient@hospital.org"
        spans = detector.detect(text)

        email_spans = [s for s in spans if s.entity_type == "EMAIL"]
        assert len(email_spans) >= 1


# =============================================================================
# DATE TESTS
# =============================================================================

class TestDateDetection:
    """Test date detection in various formats."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_date_slash_format(self, detector):
        """Test date: MM/DD/YYYY."""
        text = "DOB: 01/15/1985"
        spans = detector.detect(text)

        date_spans = [s for s in spans if "DATE" in s.entity_type]
        assert len(date_spans) >= 1

    def test_detect_date_dash_format(self, detector):
        """Test date: MM-DD-YYYY."""
        text = "Date: 01-15-1985"
        spans = detector.detect(text)

        date_spans = [s for s in spans if "DATE" in s.entity_type]
        assert len(date_spans) >= 1

    def test_detect_date_iso_format(self, detector):
        """Test date: YYYY-MM-DD (ISO format)."""
        text = "Date: 1985-01-15"
        spans = detector.detect(text)

        date_spans = [s for s in spans if "DATE" in s.entity_type]
        assert len(date_spans) >= 1

    def test_detect_date_written_month(self, detector):
        """Test date: January 15, 1985."""
        text = "Born on January 15, 1985"
        spans = detector.detect(text)

        date_spans = [s for s in spans if "DATE" in s.entity_type]
        assert len(date_spans) >= 1

    def test_detect_date_abbreviated_month(self, detector):
        """Test date: Jan 15, 1985."""
        text = "Date: Jan 15, 1985"
        spans = detector.detect(text)

        date_spans = [s for s in spans if "DATE" in s.entity_type]
        assert len(date_spans) >= 1

    def test_detect_dob_labeled(self, detector):
        """Test labeled DOB detection."""
        text = "DOB: 01/15/1985"
        spans = detector.detect(text)

        dob_spans = [s for s in spans if "DOB" in s.entity_type or "DATE" in s.entity_type]
        assert len(dob_spans) >= 1

    def test_detect_admission_date(self, detector):
        """Test admission date detection."""
        text = "admission: 03/15/2023"
        spans = detector.detect(text)

        date_spans = [s for s in spans if "DATE" in s.entity_type]
        assert len(date_spans) >= 1


# =============================================================================
# AGE TESTS
# =============================================================================

class TestAgeDetection:
    """Test age detection in various formats."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_age_years_old(self, detector):
        """Test age: X years old."""
        text = "Patient is 45 years old"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1
        assert any("45" in s.text for s in age_spans)

    def test_detect_age_year_old_hyphen(self, detector):
        """Test age: X-year-old."""
        text = "A 67-year-old male patient"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1

    def test_detect_age_yo_abbreviation(self, detector):
        """Test age: X y/o."""
        text = "Pt is a 52 y/o female"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1

    def test_detect_age_labeled(self, detector):
        """Test labeled age detection."""
        text = "age: 73"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1

    def test_reject_unreasonable_age(self, detector):
        """Test unreasonable ages are rejected."""
        text = "The building is 500 years old"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        # Should not detect 500 as a valid human age
        assert not any("500" in s.text for s in age_spans)

    def test_accept_elderly_age(self, detector):
        """Test elderly ages are accepted."""
        text = "Patient is 98 years old"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1


# =============================================================================
# NAME TESTS
# =============================================================================

class TestNameDetection:
    """Test name detection patterns."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_patient_name_labeled(self, detector):
        """Test labeled patient name."""
        text = "Patient: John Smith"
        spans = detector.detect(text)

        name_spans = [s for s in spans if "NAME" in s.entity_type]
        assert len(name_spans) >= 1

    def test_detect_provider_dr_prefix(self, detector):
        """Test provider name with Dr. prefix."""
        text = "Seen by Dr. Jane Wilson"
        spans = detector.detect(text)

        name_spans = [s for s in spans if "NAME" in s.entity_type]
        assert len(name_spans) >= 1

    def test_detect_provider_credentials(self, detector):
        """Test provider name with credentials."""
        text = "Treated by John Smith, MD"
        spans = detector.detect(text)

        name_spans = [s for s in spans if "NAME" in s.entity_type]
        assert len(name_spans) >= 1

    def test_detect_name_mr_mrs(self, detector):
        """Test name with Mr./Mrs. prefix."""
        text = "Mr. Robert Johnson arrived"
        spans = detector.detect(text)

        name_spans = [s for s in spans if "NAME" in s.entity_type]
        assert len(name_spans) >= 1

    def test_detect_name_international_prefix(self, detector):
        """Test name with international prefix."""
        text = "Herr Mueller was examined"
        spans = detector.detect(text)

        name_spans = [s for s in spans if "NAME" in s.entity_type]
        assert len(name_spans) >= 1

    def test_false_positive_name_document_headers(self):
        """Test document headers are rejected as names."""
        assert _is_false_positive_name("LABORATORY REPORT") is True
        assert _is_false_positive_name("DISCHARGE SUMMARY") is True

    def test_false_positive_name_state_abbreviations(self):
        """Test state abbreviations alone are rejected."""
        assert _is_false_positive_name("MD") is True
        assert _is_false_positive_name("PA") is True

    def test_valid_name_not_false_positive(self):
        """Test valid names are not rejected."""
        assert _is_false_positive_name("John Smith") is False
        assert _is_false_positive_name("Mary Jane Watson") is False


# =============================================================================
# SSN TESTS
# =============================================================================

class TestSSNDetection:
    """Test Social Security Number detection."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_ssn_labeled_dashes(self, detector):
        """Test labeled SSN with dashes."""
        text = "SSN: 123-45-6789"
        spans = detector.detect(text)

        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1

    def test_detect_ssn_labeled_spaces(self, detector):
        """Test labeled SSN with spaces."""
        text = "SSN: 123 45 6789"
        spans = detector.detect(text)

        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1

    def test_detect_ssn_social_security_label(self, detector):
        """Test SSN with full label."""
        text = "Social Security Number: 123-45-6789"
        spans = detector.detect(text)

        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1

    def test_detect_ssn_partial_last4(self, detector):
        """Test partial SSN (last 4 digits)."""
        text = "last 4: 6789"
        spans = detector.detect(text)

        ssn_spans = [s for s in spans if "SSN" in s.entity_type]
        assert len(ssn_spans) >= 1


# =============================================================================
# ADDRESS TESTS
# =============================================================================

class TestAddressDetection:
    """Test address detection patterns."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_full_address(self, detector):
        """Test full address with street, city, state, ZIP."""
        text = "Address: 123 Main Street, Springfield, IL 62701"
        spans = detector.detect(text)

        addr_spans = [s for s in spans if s.entity_type == "ADDRESS"]
        assert len(addr_spans) >= 1

    def test_detect_address_with_apt(self, detector):
        """Test address with apartment number."""
        text = "123 Oak Avenue, Apt 4B, Chicago, IL 60601"
        spans = detector.detect(text)

        addr_spans = [s for s in spans if s.entity_type == "ADDRESS"]
        assert len(addr_spans) >= 1

    def test_detect_street_address_only(self, detector):
        """Test street address without city/state."""
        text = "Located at 456 Elm Street"
        spans = detector.detect(text)

        addr_spans = [s for s in spans if s.entity_type == "ADDRESS"]
        assert len(addr_spans) >= 1

    def test_detect_city_state_zip(self, detector):
        """Test city, state, ZIP."""
        text = "Born in Springfield, IL 62701"
        spans = detector.detect(text)

        addr_spans = [s for s in spans if s.entity_type == "ADDRESS"]
        assert len(addr_spans) >= 1

    def test_detect_po_box(self, detector):
        """Test P.O. Box address."""
        text = "Mail to: P.O. Box 1234"
        spans = detector.detect(text)

        addr_spans = [s for s in spans if s.entity_type == "ADDRESS"]
        assert len(addr_spans) >= 1


# =============================================================================
# ZIP CODE TESTS
# =============================================================================

class TestZipCodeDetection:
    """Test ZIP code detection, especially HIPAA restricted prefixes."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_zip_labeled(self, detector):
        """Test labeled ZIP code."""
        text = "ZIP: 62701"
        spans = detector.detect(text)

        zip_spans = [s for s in spans if s.entity_type == "ZIP"]
        assert len(zip_spans) >= 1

    def test_detect_zip_plus4(self, detector):
        """Test ZIP+4 format."""
        # Pattern expects "ZIP" or "Postal" followed by colon/space
        text = "ZIP: 62701-1234"
        spans = detector.detect(text)

        zip_spans = [s for s in spans if s.entity_type == "ZIP"]
        assert len(zip_spans) >= 1

    def test_detect_hipaa_restricted_zip_036(self, detector):
        """Test HIPAA restricted ZIP prefix 036 (Vermont)."""
        text = "Resident of 03601 area"
        spans = detector.detect(text)

        zip_spans = [s for s in spans if s.entity_type == "ZIP"]
        assert len(zip_spans) >= 1


# =============================================================================
# MEDICAL IDENTIFIER TESTS
# =============================================================================

class TestMedicalIdentifierDetection:
    """Test medical identifier detection (MRN, NPI, DEA)."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_mrn_labeled(self, detector):
        """Test labeled MRN detection."""
        text = "MRN: 12345678"
        spans = detector.detect(text)

        mrn_spans = [s for s in spans if s.entity_type == "MRN"]
        assert len(mrn_spans) >= 1

    def test_detect_mrn_full_label(self, detector):
        """Test MRN with full label."""
        text = "Medical Record Number: 12345678"
        spans = detector.detect(text)

        mrn_spans = [s for s in spans if s.entity_type == "MRN"]
        assert len(mrn_spans) >= 1

    def test_detect_npi(self, detector):
        """Test NPI (National Provider Identifier) detection."""
        text = "NPI: 1234567890"
        spans = detector.detect(text)

        npi_spans = [s for s in spans if s.entity_type == "NPI"]
        assert len(npi_spans) >= 1

    def test_detect_dea(self, detector):
        """Test DEA number detection."""
        text = "DEA: AB1234567"
        spans = detector.detect(text)

        dea_spans = [s for s in spans if s.entity_type == "DEA"]
        assert len(dea_spans) >= 1


# =============================================================================
# DRIVER'S LICENSE TESTS
# =============================================================================

class TestDriversLicenseDetection:
    """Test driver's license detection across state formats."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_dl_labeled(self, detector):
        """Test labeled driver's license."""
        text = "Driver's License: A1234567"
        spans = detector.detect(text)

        dl_spans = [s for s in spans if s.entity_type == "DRIVER_LICENSE"]
        assert len(dl_spans) >= 1

    def test_detect_dl_florida_format(self, detector):
        """Test Florida DL format: Letter + dashes."""
        text = "FL DL: W426-545-30-761-0"
        spans = detector.detect(text)

        dl_spans = [s for s in spans if s.entity_type == "DRIVER_LICENSE"]
        assert len(dl_spans) >= 1

    def test_detect_dl_california_format(self, detector):
        """Test California DL format: Letter + 7 digits."""
        text = "License: A1234567"
        spans = detector.detect(text)

        dl_spans = [s for s in spans if s.entity_type == "DRIVER_LICENSE"]
        assert len(dl_spans) >= 1


# =============================================================================
# CREDIT CARD TESTS
# =============================================================================

class TestCreditCardDetection:
    """Test credit card number detection."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_credit_card_labeled(self, detector):
        """Test labeled credit card number."""
        text = "Card: 4111-1111-1111-1111"
        spans = detector.detect(text)

        cc_spans = [s for s in spans if s.entity_type == "CREDIT_CARD"]
        assert len(cc_spans) >= 1

    def test_detect_credit_card_spaces(self, detector):
        """Test credit card with spaces."""
        text = "Payment: 4111 1111 1111 1111"
        spans = detector.detect(text)

        cc_spans = [s for s in spans if s.entity_type == "CREDIT_CARD"]
        assert len(cc_spans) >= 1

    def test_detect_credit_card_partial(self, detector):
        """Test partial credit card (last 4 digits)."""
        text = "ending in 1111"
        spans = detector.detect(text)

        cc_spans = [s for s in spans if "CREDIT_CARD" in s.entity_type]
        assert len(cc_spans) >= 1


# =============================================================================
# VIN TESTS
# =============================================================================

class TestVINDetection:
    """Test Vehicle Identification Number detection."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_vin_labeled(self, detector):
        """Test labeled VIN detection."""
        text = "VIN: 1HGBH41JXMN109186"
        spans = detector.detect(text)

        vin_spans = [s for s in spans if s.entity_type == "VIN"]
        assert len(vin_spans) >= 1


# =============================================================================
# VALIDATION FUNCTION TESTS
# =============================================================================

class TestValidationFunctions:
    """Test pattern validation functions."""

    def test_validate_ip_valid(self):
        """Test valid IP addresses."""
        assert _validate_ip("192.168.1.1") is True
        assert _validate_ip("10.0.0.1") is True
        assert _validate_ip("0.0.0.0") is True
        assert _validate_ip("255.255.255.255") is True

    def test_validate_ip_invalid(self):
        """Test invalid IP addresses."""
        assert _validate_ip("256.1.1.1") is False
        assert _validate_ip("192.168.1") is False
        assert _validate_ip("192.168.1.1.1") is False

    def test_validate_phone_valid(self):
        """Test valid phone numbers."""
        assert _validate_phone("(800) 555-1234") is True
        assert _validate_phone("212-555-1234") is True

    def test_validate_phone_invalid_area_code(self):
        """Test invalid area codes are rejected."""
        assert _validate_phone("555-555-5555") is False  # 555 is reserved
        assert _validate_phone("000-000-0000") is False  # All zeros

    def test_validate_date_valid(self):
        """Test valid dates."""
        assert _validate_date(1, 15, 1985) is True  # Jan 15, 1985
        assert _validate_date(12, 31, 2020) is True  # Dec 31, 2020
        assert _validate_date(2, 29, 2020) is True  # Leap year

    def test_validate_date_invalid(self):
        """Test invalid dates."""
        assert _validate_date(2, 30, 2020) is False  # Feb 30
        assert _validate_date(13, 1, 2020) is False  # Month 13
        assert _validate_date(2, 29, 2021) is False  # Not leap year

    def test_validate_age_valid(self):
        """Test valid ages."""
        assert _validate_age("0") is True
        assert _validate_age("45") is True
        assert _validate_age("100") is True
        assert _validate_age("125") is True

    def test_validate_age_invalid(self):
        """Test invalid ages."""
        assert _validate_age("126") is False
        assert _validate_age("-5") is False
        assert _validate_age("500") is False

    def test_validate_luhn_valid(self):
        """Test valid Luhn checksums."""
        # Test credit card
        assert _validate_luhn("4111111111111111") is True
        # Test with spaces
        assert _validate_luhn("4111 1111 1111 1111") is True

    def test_validate_luhn_invalid(self):
        """Test invalid Luhn checksums."""
        assert _validate_luhn("4111111111111112") is False

    def test_validate_vin_valid(self):
        """Test valid VIN check digit."""
        # Valid VIN with correct check digit in position 9
        assert _validate_vin("1HGBH41JXMN109186") is True

    def test_validate_vin_invalid_length(self):
        """Test VIN with wrong length."""
        assert _validate_vin("1HGBH41JXMN10918") is False  # 16 chars
        assert _validate_vin("1HGBH41JXMN1091866") is False  # 18 chars


# =============================================================================
# FALSE POSITIVE TESTS
# =============================================================================

class TestPatternFalsePositives:
    """Test false positive prevention."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_no_false_positive_normal_text(self, detector):
        """Test normal text is not flagged excessively."""
        text = "The quick brown fox jumps over the lazy dog."
        spans = detector.detect(text)

        # Should have minimal matches for normal prose
        assert len(spans) <= 2

    def test_ssn_context_validation(self):
        """Test SSN context validation rejects non-SSN contexts."""
        # Test that page numbers aren't flagged as SSN
        assert _validate_ssn_context("Page 123456789", 5, 0.70) is False
        assert _validate_ssn_context("Reference #: 123456789", 12, 0.70) is False

    def test_ssn_context_allows_labeled(self):
        """Test SSN context allows labeled SSNs."""
        # High confidence (labeled) SSNs should pass
        assert _validate_ssn_context("SSN: 123456789", 5, 0.96) is True


# =============================================================================
# EDGE CASES
# =============================================================================

class TestPatternEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_empty_string(self, detector):
        """Test empty string input."""
        spans = detector.detect("")
        assert spans == []

    def test_whitespace_only(self, detector):
        """Test whitespace-only input."""
        spans = detector.detect("   \n\t  ")
        assert spans == []

    def test_multiple_entities_in_text(self, detector):
        """Test detecting multiple entity types."""
        text = """
        Patient: John Smith
        DOB: 01/15/1985
        Phone: (555) 123-4567
        Email: john@example.com
        """
        spans = detector.detect(text)

        entity_types = {s.entity_type for s in spans}
        # Should detect multiple types
        assert len(entity_types) >= 2

    def test_span_positions_valid(self, detector):
        """Test that span positions are correct."""
        text = "DOB: 01/15/1985"
        spans = detector.detect(text)

        for span in spans:
            assert span.start >= 0
            assert span.end > span.start
            assert span.end <= len(text)
            assert text[span.start:span.end] == span.text


# =============================================================================
# SPAN VALIDATION TESTS
# =============================================================================

class TestPatternSpanValidation:
    """Test span properties and validation."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_span_has_correct_detector_name(self, detector):
        """Test spans have correct detector name."""
        text = "Phone: (555) 123-4567"
        spans = detector.detect(text)

        for span in spans:
            assert span.detector == "pattern"

    def test_span_has_correct_tier(self, detector):
        """Test spans have correct tier."""
        text = "Phone: (555) 123-4567"
        spans = detector.detect(text)

        for span in spans:
            assert span.tier == Tier.PATTERN

    def test_span_text_matches_position(self, detector):
        """Test span text matches extracted position."""
        text = "prefix Phone: (800) 555-1234 suffix"
        spans = detector.detect(text)

        for span in spans:
            extracted = text[span.start:span.end]
            assert extracted == span.text


# =============================================================================
# PATTERN REGISTRATION TESTS
# =============================================================================

class TestPatternRegistration:
    """Test pattern registration functionality."""

    def test_pattern_tuple_structure(self):
        """Test each pattern has correct tuple structure."""
        for pattern, entity_type, confidence, group_idx in PATTERNS:
            # Pattern should be compiled regex
            assert hasattr(pattern, 'finditer')
            # Entity type should be non-empty string
            assert isinstance(entity_type, str)
            assert len(entity_type) > 0
            # Confidence should be float 0-1
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
            # Group index should be non-negative int
            assert isinstance(group_idx, int)
            assert group_idx >= 0


# =============================================================================
# INTERNATIONAL FORMAT TESTS
# =============================================================================

class TestInternationalFormats:
    """Test international pattern formats."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_international_phone(self, detector):
        """Test international phone format."""
        text = "Call +44 20 7946 0958"
        spans = detector.detect(text)

        phone_spans = [s for s in spans if s.entity_type == "PHONE"]
        assert len(phone_spans) >= 1

    def test_detect_international_name_prefix_german(self, detector):
        """Test German name prefix."""
        text = "Patient Herr Schmidt reported symptoms"
        spans = detector.detect(text)

        name_spans = [s for s in spans if "NAME" in s.entity_type]
        assert len(name_spans) >= 1

    def test_detect_international_name_prefix_french(self, detector):
        """Test French name prefix."""
        text = "Monsieur Dupont arrived at clinic"
        spans = detector.detect(text)

        name_spans = [s for s in spans if "NAME" in s.entity_type]
        assert len(name_spans) >= 1


# =============================================================================
# TIME DETECTION TESTS
# =============================================================================

class TestTimeDetection:
    """Test time detection patterns."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_time_12_hour(self, detector):
        """Test 12-hour time format."""
        text = "Appointment at 3:30 PM"
        spans = detector.detect(text)

        time_spans = [s for s in spans if s.entity_type == "TIME"]
        assert len(time_spans) >= 1

    def test_detect_time_24_hour(self, detector):
        """Test 24-hour time format."""
        text = "Surgery began 14:30:00"
        spans = detector.detect(text)

        time_spans = [s for s in spans if s.entity_type == "TIME"]
        assert len(time_spans) >= 1

    def test_detect_iso_datetime(self, detector):
        """Test ISO 8601 datetime format."""
        text = "Timestamp: 2024-03-15T14:30:00Z"
        spans = detector.detect(text)

        dt_spans = [s for s in spans if "TIME" in s.entity_type or "DATE" in s.entity_type]
        assert len(dt_spans) >= 1


# =============================================================================
# FACILITY DETECTION TESTS
# =============================================================================

class TestFacilityDetection:
    """Test healthcare facility detection."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_hospital(self, detector):
        """Test hospital name detection."""
        text = "Admitted to General Hospital for treatment"
        spans = detector.detect(text)

        facility_spans = [s for s in spans if s.entity_type == "FACILITY"]
        assert len(facility_spans) >= 1

    def test_detect_medical_center(self, detector):
        """Test medical center detection."""
        text = "Transferred to University Medical Center"
        spans = detector.detect(text)

        facility_spans = [s for s in spans if s.entity_type == "FACILITY"]
        assert len(facility_spans) >= 1

    def test_detect_st_hospital(self, detector):
        """Test St. hospital names."""
        text = "Seen at St. Mary's Hospital"
        spans = detector.detect(text)

        facility_spans = [s for s in spans if s.entity_type == "FACILITY"]
        assert len(facility_spans) >= 1


# =============================================================================
# NETWORK/DEVICE IDENTIFIER TESTS
# =============================================================================

class TestNetworkDeviceIdentifiers:
    """Test network and device identifier detection."""

    @pytest.fixture
    def detector(self):
        return PatternDetector()

    def test_detect_ip_address(self, detector):
        """Test IP address detection."""
        text = "Server IP: 192.168.1.100"
        spans = detector.detect(text)

        ip_spans = [s for s in spans if s.entity_type == "IP_ADDRESS"]
        assert len(ip_spans) >= 1

    def test_detect_mac_address(self, detector):
        """Test MAC address detection."""
        text = "Device MAC: 00:1A:2B:3C:4D:5E"
        spans = detector.detect(text)

        mac_spans = [s for s in spans if s.entity_type == "MAC_ADDRESS"]
        assert len(mac_spans) >= 1

    def test_detect_url(self, detector):
        """Test URL detection."""
        text = "Visit https://example.com/patient/portal"
        spans = detector.detect(text)

        url_spans = [s for s in spans if s.entity_type == "URL"]
        assert len(url_spans) >= 1

    def test_detect_username(self, detector):
        """Test username detection."""
        text = "username: jsmith123"
        spans = detector.detect(text)

        user_spans = [s for s in spans if s.entity_type == "USERNAME"]
        assert len(user_spans) >= 1
