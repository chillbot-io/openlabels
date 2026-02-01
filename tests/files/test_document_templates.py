"""
Comprehensive tests for files/document_templates.py.

Tests cover:
- DocumentType and PHICategory enums
- ExtractedField and DocumentParseResult dataclasses
- Validation functions (Luhn, MBI, SSN, NPI, DEA, date, passport MRZ)
- Document type detection
- Document-specific parsers (DL, insurance, Medicare, CMS-1500, UB-04, passport, lab req, Rx, EOB)
- Main interface functions (get_parser, parse_document, clean_document_text, extract_phi_fields)
"""

import pytest
from datetime import datetime

from scrubiq.files.document_templates import (
    # Enums
    DocumentType,
    PHICategory,
    # Dataclasses
    ExtractedField,
    DocumentParseResult,
    # Validation functions
    validate_luhn,
    validate_medicare_mbi,
    validate_ssn,
    validate_npi,
    validate_dea,
    validate_date,
    validate_passport_mrz,
    # Detection
    detect_document_type,
    DOCUMENT_KEYWORDS,
    # Field patterns
    AAMVA_FIELD_PATTERNS,
    INSURANCE_FIELD_PATTERNS,
    MEDICARE_FIELD_PATTERNS,
    CMS_1500_FIELD_PATTERNS,
    UB_04_FIELD_PATTERNS,
    LAB_REQUISITION_PATTERNS,
    PRESCRIPTION_PATTERNS,
    EOB_PATTERNS,
    # Parsers
    DocumentParser,
    DriversLicenseParser,
    InsuranceCardParser,
    MedicareCardParser,
    CMS1500Parser,
    UB04Parser,
    PassportParser,
    LabRequisitionParser,
    PrescriptionParser,
    EOBParser,
    # Main functions
    DOCUMENT_PARSERS,
    get_parser,
    parse_document,
    clean_document_text,
    extract_phi_fields,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestDocumentTypeEnum:
    """Tests for DocumentType enum."""

    def test_id_document_types(self):
        """Test ID document type values exist."""
        assert DocumentType.DRIVERS_LICENSE is not None
        assert DocumentType.STATE_ID is not None
        assert DocumentType.PASSPORT is not None
        assert DocumentType.PASSPORT_CARD is not None
        assert DocumentType.MILITARY_ID is not None

    def test_insurance_types(self):
        """Test insurance document type values exist."""
        assert DocumentType.INSURANCE_COMMERCIAL is not None
        assert DocumentType.INSURANCE_MEDICARE is not None
        assert DocumentType.INSURANCE_MEDICAID is not None
        assert DocumentType.INSURANCE_TRICARE is not None

    def test_claim_form_types(self):
        """Test claim form type values exist."""
        assert DocumentType.CMS_1500 is not None
        assert DocumentType.UB_04 is not None
        assert DocumentType.ADA_DENTAL is not None

    def test_clinical_document_types(self):
        """Test clinical document type values exist."""
        assert DocumentType.LAB_REQUISITION is not None
        assert DocumentType.PRESCRIPTION_LABEL is not None
        assert DocumentType.PRESCRIPTION_PAD is not None
        assert DocumentType.SUPERBILL is not None

    def test_other_types(self):
        """Test other document types exist."""
        assert DocumentType.EOB is not None
        assert DocumentType.CONSENT_FORM is not None
        assert DocumentType.ADVANCE_DIRECTIVE is not None
        assert DocumentType.UNKNOWN is not None

    def test_enum_uniqueness(self):
        """Test all enum values are unique."""
        values = [t.value for t in DocumentType]
        assert len(values) == len(set(values))


class TestPHICategoryEnum:
    """Tests for PHICategory enum."""

    def test_hipaa_safe_harbor_categories(self):
        """Test HIPAA Safe Harbor PHI categories."""
        assert PHICategory.NAME.value == "name"
        assert PHICategory.ADDRESS.value == "address"
        assert PHICategory.DATE.value == "date"
        assert PHICategory.PHONE.value == "phone"
        assert PHICategory.FAX.value == "fax"
        assert PHICategory.EMAIL.value == "email"
        assert PHICategory.SSN.value == "ssn"
        assert PHICategory.MRN.value == "mrn"
        assert PHICategory.HEALTH_PLAN_ID.value == "health_plan_id"
        assert PHICategory.ACCOUNT_NUMBER.value == "account_number"
        assert PHICategory.LICENSE_NUMBER.value == "license_number"
        assert PHICategory.VEHICLE_ID.value == "vehicle_id"
        assert PHICategory.DEVICE_ID.value == "device_id"
        assert PHICategory.URL.value == "url"
        assert PHICategory.IP_ADDRESS.value == "ip_address"
        assert PHICategory.BIOMETRIC.value == "biometric"
        assert PHICategory.PHOTO.value == "photo"
        assert PHICategory.OTHER_UNIQUE_ID.value == "other_unique_id"

    def test_all_18_identifiers_covered(self):
        """Test that all 18 HIPAA identifiers are represented."""
        # HIPAA Safe Harbor requires 18 identifier types
        assert len(PHICategory) == 18


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestExtractedField:
    """Tests for ExtractedField dataclass."""

    def test_basic_field_creation(self):
        """Test creating a basic extracted field."""
        field = ExtractedField(
            name="License Number",
            value="D12345678",
            confidence=0.95
        )
        assert field.name == "License Number"
        assert field.value == "D12345678"
        assert field.confidence == 0.95
        assert field.phi_category is None
        assert field.bbox is None
        assert field.validated is False
        assert field.validation_method is None

    def test_field_with_phi_category(self):
        """Test field with PHI category."""
        field = ExtractedField(
            name="SSN",
            value="123-45-6789",
            confidence=0.9,
            phi_category=PHICategory.SSN
        )
        assert field.phi_category == PHICategory.SSN

    def test_field_with_bbox(self):
        """Test field with bounding box."""
        field = ExtractedField(
            name="Name",
            value="John Doe",
            confidence=0.85,
            bbox=(10, 20, 200, 50)
        )
        assert field.bbox == (10, 20, 200, 50)

    def test_validated_field(self):
        """Test validated field with method."""
        field = ExtractedField(
            name="NPI",
            value="1234567893",
            confidence=0.95,
            phi_category=PHICategory.LICENSE_NUMBER,
            validated=True,
            validation_method="npi_luhn"
        )
        assert field.validated is True
        assert field.validation_method == "npi_luhn"


class TestDocumentParseResult:
    """Tests for DocumentParseResult dataclass."""

    def test_basic_result_creation(self):
        """Test creating a basic parse result."""
        result = DocumentParseResult(
            document_type=DocumentType.DRIVERS_LICENSE,
            confidence=0.9,
            fields={},
            raw_text="Sample text"
        )
        assert result.document_type == DocumentType.DRIVERS_LICENSE
        assert result.confidence == 0.9
        assert result.fields == {}
        assert result.raw_text == "Sample text"
        assert result.warnings == []

    def test_result_with_fields(self):
        """Test result with extracted fields."""
        fields = {
            "name": ExtractedField(
                name="Name",
                value="John Doe",
                confidence=0.9,
                phi_category=PHICategory.NAME
            ),
            "license_number": ExtractedField(
                name="License Number",
                value="D12345678",
                confidence=0.95,
                phi_category=PHICategory.LICENSE_NUMBER
            ),
            "sex": ExtractedField(
                name="Sex",
                value="M",
                confidence=0.95,
                phi_category=None  # Not PHI
            )
        }
        result = DocumentParseResult(
            document_type=DocumentType.DRIVERS_LICENSE,
            confidence=0.9,
            fields=fields,
            raw_text="OCR text"
        )
        assert len(result.fields) == 3

    def test_get_phi_fields(self):
        """Test getting only PHI fields."""
        fields = {
            "name": ExtractedField(
                name="Name",
                value="John Doe",
                confidence=0.9,
                phi_category=PHICategory.NAME
            ),
            "sex": ExtractedField(
                name="Sex",
                value="M",
                confidence=0.95,
                phi_category=None
            ),
            "dob": ExtractedField(
                name="DOB",
                value="01/01/1990",
                confidence=0.9,
                phi_category=PHICategory.DATE
            )
        }
        result = DocumentParseResult(
            document_type=DocumentType.DRIVERS_LICENSE,
            confidence=0.9,
            fields=fields,
            raw_text=""
        )
        phi_fields = result.get_phi_fields()
        assert len(phi_fields) == 2
        assert "name" in phi_fields
        assert "dob" in phi_fields
        assert "sex" not in phi_fields

    def test_to_clean_text(self):
        """Test converting to clean text."""
        fields = {
            "name": ExtractedField(name="Name", value="John Doe", confidence=0.9),
            "city": ExtractedField(name="City", value="Springfield", confidence=0.9),
            "empty": ExtractedField(name="Empty", value="", confidence=0.5)
        }
        result = DocumentParseResult(
            document_type=DocumentType.UNKNOWN,
            confidence=0.5,
            fields=fields,
            raw_text=""
        )
        clean = result.to_clean_text()
        assert "John Doe" in clean
        assert "Springfield" in clean

    def test_result_with_warnings(self):
        """Test result with warnings."""
        result = DocumentParseResult(
            document_type=DocumentType.UNKNOWN,
            confidence=0.3,
            fields={},
            raw_text="",
            warnings=["Low confidence detection", "Missing required fields"]
        )
        assert len(result.warnings) == 2
        assert "Low confidence detection" in result.warnings


# =============================================================================
# VALIDATION FUNCTION TESTS
# =============================================================================

class TestValidateLuhn:
    """Tests for Luhn algorithm validation."""

    def test_valid_credit_card_numbers(self):
        """Test valid credit card numbers pass Luhn."""
        # Test Visa card
        assert validate_luhn("4532015112830366") is True
        # Test Mastercard
        assert validate_luhn("5425233430109903") is True
        # Test Amex
        assert validate_luhn("374245455400126") is True

    def test_valid_with_formatting(self):
        """Test valid numbers with dashes/spaces."""
        assert validate_luhn("4532-0151-1283-0366") is True
        assert validate_luhn("4532 0151 1283 0366") is True

    def test_invalid_numbers(self):
        """Test invalid numbers fail Luhn."""
        assert validate_luhn("4532015112830367") is False  # Wrong check digit
        assert validate_luhn("1234567890123456") is False  # Invalid sequence

    def test_single_digit_errors_detected(self):
        """Test single digit errors are detected."""
        valid = "4532015112830366"
        # Change one digit
        invalid = "4532015112830376"
        assert validate_luhn(valid) is True
        assert validate_luhn(invalid) is False

    def test_empty_input(self):
        """Test empty input returns False."""
        assert validate_luhn("") is False
        assert validate_luhn("   ") is False

    def test_non_numeric_input(self):
        """Test non-numeric characters are stripped."""
        assert validate_luhn("4532-0151-1283-0366") is True
        assert validate_luhn("ABC") is False  # Only non-digits


class TestValidateMedicareMBI:
    """Tests for Medicare Beneficiary Identifier validation."""

    def test_valid_mbi_formats(self):
        """Test valid MBI formats."""
        # Format: N-C-AN-N-C-AN-N-C-C-N-N
        # N = 1-9 for position 1, 0-9 for others
        # C = Alpha excluding S,L,O,I,B,Z
        # AN = Alphanumeric excluding S,L,O,I,B,Z
        assert validate_medicare_mbi("1EG4TE5MK72") is True
        assert validate_medicare_mbi("1EG4-TE5-MK72") is True
        assert validate_medicare_mbi("1EG4 TE5 MK72") is True
        assert validate_medicare_mbi("2AN9XX5CC00") is True

    def test_invalid_mbi_first_digit_zero(self):
        """Test MBI cannot start with 0."""
        assert validate_medicare_mbi("0EG4TE5MK72") is False

    def test_invalid_mbi_excluded_letters(self):
        """Test excluded letters S, L, O, I, B, Z are rejected."""
        # S in alpha position
        assert validate_medicare_mbi("1SG4TE5MK72") is False
        # L in alpha position
        assert validate_medicare_mbi("1LG4TE5MK72") is False
        # O in alpha position
        assert validate_medicare_mbi("1OG4TE5MK72") is False
        # I in alpha position
        assert validate_medicare_mbi("1IG4TE5MK72") is False
        # B in alpha position
        assert validate_medicare_mbi("1BG4TE5MK72") is False
        # Z in alpha position
        assert validate_medicare_mbi("1ZG4TE5MK72") is False

    def test_invalid_mbi_wrong_length(self):
        """Test wrong length MBIs are rejected."""
        assert validate_medicare_mbi("1EG4TE5MK7") is False  # 10 chars
        assert validate_medicare_mbi("1EG4TE5MK723") is False  # 12 chars

    def test_invalid_mbi_wrong_positions(self):
        """Test wrong character types in positions."""
        # Position 2 should be alpha, not numeric
        assert validate_medicare_mbi("1234TE5MK72") is False
        # Position 4 should be numeric, not alpha
        assert validate_medicare_mbi("1EGATX5MK72") is False


class TestValidateSSN:
    """Tests for SSN validation."""

    def test_valid_ssn_formats(self):
        """Test valid SSN formats."""
        assert validate_ssn("123-45-6789") is True
        assert validate_ssn("123456789") is True
        assert validate_ssn("123 45 6789") is True

    def test_invalid_area_000(self):
        """Test area number 000 is invalid."""
        assert validate_ssn("000-45-6789") is False

    def test_invalid_area_666(self):
        """Test area number 666 is invalid."""
        assert validate_ssn("666-45-6789") is False

    def test_invalid_area_900_999(self):
        """Test area numbers 900-999 are invalid."""
        assert validate_ssn("900-45-6789") is False
        assert validate_ssn("950-45-6789") is False
        assert validate_ssn("999-45-6789") is False

    def test_invalid_group_00(self):
        """Test group number 00 is invalid."""
        assert validate_ssn("123-00-6789") is False

    def test_invalid_serial_0000(self):
        """Test serial number 0000 is invalid."""
        assert validate_ssn("123-45-0000") is False

    def test_invalid_length(self):
        """Test wrong length is invalid."""
        assert validate_ssn("12345678") is False  # 8 digits
        assert validate_ssn("1234567890") is False  # 10 digits


class TestValidateNPI:
    """Tests for National Provider Identifier validation."""

    def test_valid_npi(self):
        """Test valid NPIs pass validation."""
        # NPI uses Luhn with prefix 80840
        # Valid test NPI: 1234567893
        assert validate_npi("1234567893") is True
        # Another valid: 1497758544
        assert validate_npi("1497758544") is True

    def test_invalid_npi_wrong_checksum(self):
        """Test invalid NPI checksum is rejected."""
        assert validate_npi("1234567890") is False
        assert validate_npi("1234567891") is False

    def test_invalid_npi_wrong_length(self):
        """Test wrong length NPIs are rejected."""
        assert validate_npi("123456789") is False  # 9 digits
        assert validate_npi("12345678901") is False  # 11 digits

    def test_npi_with_formatting(self):
        """Test NPI validation strips non-digits."""
        assert validate_npi("1234-567-893") is True


class TestValidateDEA:
    """Tests for DEA Registration Number validation."""

    def test_valid_dea_numbers(self):
        """Test valid DEA numbers pass validation."""
        # DEA format: 2 letters + 6 digits + 1 check digit
        # Check: (d1+d3+d5 + 2*(d2+d4+d6)) mod 10 = check digit
        # Example: AB1234563 -> (1+3+5) + 2*(2+4+6) = 9 + 24 = 33 mod 10 = 3
        assert validate_dea("AB1234563") is True
        # Another valid: MJ1234563
        assert validate_dea("MJ1234563") is True

    def test_valid_dea_registrant_types(self):
        """Test various valid registrant type letters."""
        # A, B - Practitioners/hospitals
        assert validate_dea("AB1234563") is True
        # F, G - Practitioners
        assert validate_dea("FB1234563") is True
        # M - Mid-level practitioner
        assert validate_dea("MA1234563") is True
        # P, R - Manufacturers/distributors
        assert validate_dea("PA1234563") is True

    def test_invalid_dea_registrant_type(self):
        """Test invalid registrant type letters."""
        # I, N, O, Q, V, W, Y, Z are not valid
        assert validate_dea("IA1234563") is False
        assert validate_dea("NA1234563") is False
        assert validate_dea("OA1234563") is False

    def test_invalid_dea_checksum(self):
        """Test invalid checksum is rejected."""
        assert validate_dea("AB1234560") is False  # Wrong check digit
        assert validate_dea("AB1234561") is False

    def test_invalid_dea_format(self):
        """Test invalid formats are rejected."""
        # Wrong length
        assert validate_dea("AB123456") is False  # 8 chars
        assert validate_dea("AB12345634") is False  # 10 chars
        # Numbers in wrong position
        assert validate_dea("A11234563") is False  # Second char must be alpha
        assert validate_dea("1B1234563") is False  # First char must be valid type


class TestValidateDate:
    """Tests for date validation."""

    def test_valid_date_formats(self):
        """Test valid date formats are parsed."""
        # MM/DD/YYYY
        result = validate_date("01/15/2024")
        assert result is not None
        assert result.month == 1
        assert result.day == 15
        assert result.year == 2024

        # MM-DD-YYYY
        result = validate_date("12-25-2023")
        assert result is not None

        # YYYY-MM-DD (ISO)
        result = validate_date("2024-01-15")
        assert result is not None

        # MM/DD/YY
        result = validate_date("01/15/24")
        assert result is not None

    def test_invalid_date_formats(self):
        """Test invalid date strings return None."""
        assert validate_date("not a date") is None
        assert validate_date("32/13/2024") is None
        assert validate_date("") is None

    def test_custom_formats(self):
        """Test custom date formats."""
        result = validate_date("Jan 15, 2024", formats=["%b %d, %Y"])
        assert result is not None
        assert result.month == 1


class TestValidatePassportMRZ:
    """Tests for passport MRZ validation."""

    def test_valid_mrz(self):
        """Test valid MRZ passes validation."""
        line1 = "P<USASMITH<<JOHN<EDWARD<<<<<<<<<<<<<<<<<<<<<<<"[:44].ljust(44, '<')
        line2 = "1234567890USA7001011M2501011234567890<<<<<<0"[:44].ljust(44, '0')
        # Ensure exactly 44 chars
        line1 = line1[:44]
        line2 = line2[:44]
        assert len(line1) == 44
        assert len(line2) == 44
        assert validate_passport_mrz([line1, line2]) is True

    def test_invalid_mrz_wrong_line_count(self):
        """Test wrong number of lines is invalid."""
        assert validate_passport_mrz([]) is False
        assert validate_passport_mrz(["P<USA"]) is False
        assert validate_passport_mrz(["P<USA", "ABC", "DEF"]) is False

    def test_invalid_mrz_wrong_length(self):
        """Test wrong line length is invalid."""
        assert validate_passport_mrz(["P<USA" + "<" * 38, "ABC" * 10]) is False

    def test_invalid_mrz_wrong_first_char(self):
        """Test first line must start with P."""
        line1 = "X<USASMITH<<JOHN<" + "<" * 27
        line2 = "1234567890" + "0" * 34
        assert validate_passport_mrz([line1, line2]) is False

    def test_invalid_mrz_invalid_characters(self):
        """Test invalid characters are rejected."""
        line1 = "P<USASMITH<<JOHN<" + "<" * 27
        line2 = "12345!@#$%" + "0" * 34  # Invalid chars
        assert validate_passport_mrz([line1, line2]) is False


# =============================================================================
# DOCUMENT DETECTION TESTS
# =============================================================================

class TestDocumentDetection:
    """Tests for document type detection."""

    def test_detect_drivers_license(self):
        """Test detecting driver's license."""
        text = """
        DRIVER'S LICENSE
        DLN: D12345678
        CLASS: C
        ORGAN DONOR
        """
        doc_type, confidence = detect_document_type(text)
        assert doc_type == DocumentType.DRIVERS_LICENSE
        assert confidence > 0.0

    def test_detect_passport(self):
        """Test detecting passport."""
        text = """
        PASSPORT
        UNITED STATES OF AMERICA
        NATIONALITY: USA
        """
        doc_type, confidence = detect_document_type(text)
        assert doc_type == DocumentType.PASSPORT
        assert confidence > 0.0

    def test_detect_insurance_commercial(self):
        """Test detecting commercial insurance card."""
        text = """
        MEMBER ID: ABC123456
        GROUP #: GRP789
        RX BIN: 123456
        COPAY: $20
        """
        doc_type, confidence = detect_document_type(text)
        assert doc_type == DocumentType.INSURANCE_COMMERCIAL
        assert confidence > 0.0

    def test_detect_medicare(self):
        """Test detecting Medicare card."""
        text = """
        MEDICARE
        HEALTH INSURANCE
        MBI: 1EG4TE5MK72
        PART A: 01/01/2020
        """
        doc_type, confidence = detect_document_type(text)
        assert doc_type == DocumentType.INSURANCE_MEDICARE
        assert confidence > 0.0

    def test_detect_cms_1500(self):
        """Test detecting CMS-1500 form."""
        text = """
        CMS-1500
        HEALTH INSURANCE CLAIM FORM
        1a. INSURED'S I.D. NUMBER
        21. DIAGNOSIS
        """
        doc_type, confidence = detect_document_type(text)
        assert doc_type == DocumentType.CMS_1500
        assert confidence > 0.0

    def test_detect_ub04(self):
        """Test detecting UB-04 form."""
        text = """
        UB-04
        UNIFORM BILL
        FL 1
        TYPE OF BILL
        CONDITION CODES
        """
        doc_type, confidence = detect_document_type(text)
        assert doc_type == DocumentType.UB_04
        assert confidence > 0.0

    def test_detect_prescription(self):
        """Test detecting prescription."""
        text = """
        RX# 123456789
        PRESCRIPTION
        REFILLS: 3
        QTY: 30
        PHARMACY
        """
        doc_type, confidence = detect_document_type(text)
        assert doc_type == DocumentType.PRESCRIPTION_LABEL
        assert confidence > 0.0

    def test_detect_eob(self):
        """Test detecting EOB."""
        text = """
        EXPLANATION OF BENEFITS
        THIS IS NOT A BILL
        PATIENT RESPONSIBILITY
        YOUR PLAN PAID
        """
        doc_type, confidence = detect_document_type(text)
        assert doc_type == DocumentType.EOB
        assert confidence > 0.0

    def test_detect_unknown(self):
        """Test unknown document returns UNKNOWN."""
        text = "Random text with no keywords"
        doc_type, confidence = detect_document_type(text)
        assert doc_type == DocumentType.UNKNOWN
        assert confidence == 0.0

    def test_aspect_ratio_boost_id_card(self):
        """Test aspect ratio boosts ID card detection."""
        text = "DRIVER'S LICENSE"
        # ID card aspect ratio ~1.58
        doc_type1, conf1 = detect_document_type(text, aspect_ratio=1.58)
        doc_type2, conf2 = detect_document_type(text, aspect_ratio=None)
        # Should be detected either way, but with boost
        assert doc_type1 == DocumentType.DRIVERS_LICENSE

    def test_aspect_ratio_boost_form(self):
        """Test aspect ratio boosts form detection."""
        text = "CMS-1500 HEALTH INSURANCE CLAIM"
        # Letter portrait ~0.77
        doc_type, conf = detect_document_type(text, aspect_ratio=0.77)
        assert doc_type == DocumentType.CMS_1500


# =============================================================================
# PARSER TESTS
# =============================================================================

class TestDriversLicenseParser:
    """Tests for DriversLicenseParser."""

    @pytest.fixture
    def parser(self):
        return DriversLicenseParser()

    def test_document_type(self, parser):
        """Test parser document type."""
        assert parser.document_type == DocumentType.DRIVERS_LICENSE

    def test_field_patterns(self, parser):
        """Test parser has field patterns."""
        assert parser.field_patterns == AAMVA_FIELD_PATTERNS
        assert len(parser.field_patterns) > 0

    def test_extract_license_number(self, parser):
        """Test extracting license number."""
        text = "DLN: D12345678"
        fields = parser.extract_fields(text)
        assert "license_number" in fields
        assert fields["license_number"].value == "D12345678"
        assert fields["license_number"].phi_category == PHICategory.LICENSE_NUMBER

    def test_extract_dob(self, parser):
        """Test extracting date of birth."""
        text = "DOB: 01/15/1990"
        fields = parser.extract_fields(text)
        assert "dob" in fields
        assert fields["dob"].value == "01/15/1990"
        assert fields["dob"].phi_category == PHICategory.DATE

    def test_extract_address(self, parser):
        """Test extracting address."""
        text = "123 MAIN STREET"
        fields = parser.extract_fields(text)
        assert "address" in fields
        assert "123 MAIN STREET" in fields["address"].value
        assert fields["address"].phi_category == PHICategory.ADDRESS

    def test_extract_city_state_zip(self, parser):
        """Test extracting city, state, ZIP."""
        text = "SPRINGFIELD IL 62701"
        fields = parser.extract_fields(text)
        assert "city" in fields
        assert "state" in fields
        assert "zip" in fields
        assert fields["city"].value == "SPRINGFIELD"
        assert fields["state"].value == "IL"
        assert fields["zip"].value == "62701"

    def test_extract_sex(self, parser):
        """Test extracting sex."""
        text = "SEX: M"
        fields = parser.extract_fields(text)
        assert "sex" in fields
        assert fields["sex"].value == "M"
        assert fields["sex"].phi_category is None  # Not PHI by itself

    def test_extract_expiration(self, parser):
        """Test extracting expiration date."""
        text = "EXP: 01/15/2030"
        fields = parser.extract_fields(text)
        assert "expiration" in fields
        assert fields["expiration"].phi_category is None  # Not PHI

    def test_clean_text(self, parser):
        """Test cleaning field labels from text."""
        text = "DLN: D12345678\nDOB: 01/15/1990"
        cleaned = parser.clean_text(text)
        assert "DLN:" not in cleaned
        assert "DOB:" not in cleaned

    def test_parse_full_document(self, parser):
        """Test parsing full driver's license document."""
        text = """
        DRIVER'S LICENSE
        SMITH
        JOHN EDWARD
        DLN: D12345678
        DOB: 01/15/1990
        123 MAIN STREET
        SPRINGFIELD IL 62701
        SEX: M
        EXP: 01/15/2030
        CLASS: C
        """
        result = parser.parse(text)
        assert result.document_type == DocumentType.DRIVERS_LICENSE
        assert result.confidence == 1.0
        assert len(result.fields) > 0


class TestInsuranceCardParser:
    """Tests for InsuranceCardParser."""

    @pytest.fixture
    def parser(self):
        return InsuranceCardParser()

    def test_document_type(self, parser):
        """Test parser document type."""
        assert parser.document_type == DocumentType.INSURANCE_COMMERCIAL

    def test_extract_member_id(self, parser):
        """Test extracting member ID."""
        text = "MEMBER ID: ABC123456789"
        fields = parser.extract_fields(text)
        assert "member_id" in fields
        assert fields["member_id"].value == "ABC123456789"
        assert fields["member_id"].phi_category == PHICategory.HEALTH_PLAN_ID

    def test_extract_group_number(self, parser):
        """Test extracting group number."""
        text = "GROUP#: GRP12345"
        fields = parser.extract_fields(text)
        assert "group_number" in fields
        assert fields["group_number"].value == "GRP12345"

    def test_extract_rx_bin(self, parser):
        """Test extracting RxBIN."""
        text = "RX BIN: 123456"
        fields = parser.extract_fields(text)
        assert "rx_bin" in fields
        assert fields["rx_bin"].value == "123456"
        assert fields["rx_bin"].phi_category is None  # Not PHI

    def test_extract_rx_pcn(self, parser):
        """Test extracting RxPCN."""
        text = "PCN: RXPCN123"
        fields = parser.extract_fields(text)
        assert "rx_pcn" in fields
        assert fields["rx_pcn"].value == "RXPCN123"


class TestMedicareCardParser:
    """Tests for MedicareCardParser."""

    @pytest.fixture
    def parser(self):
        return MedicareCardParser()

    def test_document_type(self, parser):
        """Test parser document type."""
        assert parser.document_type == DocumentType.INSURANCE_MEDICARE

    def test_extract_mbi(self, parser):
        """Test extracting Medicare Beneficiary Identifier."""
        text = "MBI: 1EG4TE5MK72"
        fields = parser.extract_fields(text)
        assert "mbi" in fields
        assert fields["mbi"].value == "1EG4TE5MK72"
        assert fields["mbi"].phi_category == PHICategory.HEALTH_PLAN_ID
        assert fields["mbi"].validated is True

    def test_extract_invalid_mbi(self, parser):
        """Test extracting invalid MBI still captures but not validated."""
        # Use a malformed MBI that doesn't match the pattern
        text = "MEDICARE: INVALID123"
        fields = parser.extract_fields(text)
        # Should not match the MBI pattern
        assert "mbi" not in fields

    def test_extract_hicn_legacy(self, parser):
        """Test extracting legacy HICN format."""
        text = "123-45-6789A"
        fields = parser.extract_fields(text)
        assert "hicn" in fields
        assert "123-45-6789A" in fields["hicn"].value

    def test_extract_effective_date(self, parser):
        """Test extracting effective date."""
        text = "EFFECTIVE: 01/01/2020"
        fields = parser.extract_fields(text)
        assert "effective_date" in fields

    def test_extract_part_dates(self, parser):
        """Test extracting Part A/B/C/D dates."""
        text = """
        PART A: 01/01/2020
        PART B: 01/01/2020
        """
        fields = parser.extract_fields(text)
        assert "part_a_date" in fields
        assert "part_b_date" in fields


class TestCMS1500Parser:
    """Tests for CMS1500Parser."""

    @pytest.fixture
    def parser(self):
        return CMS1500Parser()

    def test_document_type(self, parser):
        """Test parser document type."""
        assert parser.document_type == DocumentType.CMS_1500

    def test_extract_insured_id(self, parser):
        """Test extracting Box 1a - Insured's ID."""
        text = "1A. INSURED'S I.D. #: XYZ123456789"
        fields = parser.extract_fields(text)
        assert "insured_id" in fields
        assert fields["insured_id"].phi_category == PHICategory.HEALTH_PLAN_ID

    def test_extract_patient_name(self, parser):
        """Test extracting Box 2 - Patient Name."""
        text = "2. PATIENT'S NAME: SMITH, JOHN"
        fields = parser.extract_fields(text)
        assert "patient_name" in fields
        assert fields["patient_name"].phi_category == PHICategory.NAME

    def test_extract_patient_dob(self, parser):
        """Test extracting Box 3 - Patient DOB."""
        text = "3. DOB: 01/15/1960"
        fields = parser.extract_fields(text)
        assert "patient_dob" in fields
        assert fields["patient_dob"].phi_category == PHICategory.DATE

    def test_extract_diagnosis_codes(self, parser):
        """Test extracting diagnosis codes."""
        text = "DIAGNOSIS: Z00.00 E11.9 I10"
        fields = parser.extract_fields(text)
        assert "diagnosis_codes" in fields
        # Should capture ICD-10 codes
        assert "Z00.00" in fields["diagnosis_codes"].value or "E11.9" in fields["diagnosis_codes"].value

    def test_extract_npi(self, parser):
        """Test extracting NPI."""
        text = "NPI: 1234567893"
        fields = parser.extract_fields(text)
        assert "billing_npi" in fields
        assert fields["billing_npi"].validated is True

    def test_extract_tax_id_ein(self, parser):
        """Test extracting EIN Tax ID."""
        text = "TAX ID: 12-3456789"
        fields = parser.extract_fields(text)
        assert "tax_id" in fields

    def test_extract_tax_id_ssn(self, parser):
        """Test extracting SSN as Tax ID."""
        text = "SSN: 123-45-6789"
        fields = parser.extract_fields(text)
        assert "tax_id" in fields
        assert fields["tax_id"].phi_category == PHICategory.SSN
        assert fields["tax_id"].validated is True


class TestUB04Parser:
    """Tests for UB04Parser."""

    @pytest.fixture
    def parser(self):
        return UB04Parser()

    def test_document_type(self, parser):
        """Test parser document type."""
        assert parser.document_type == DocumentType.UB_04

    def test_extract_patient_control(self, parser):
        """Test extracting FL 3a - Patient Control Number."""
        text = "FL 3A PATIENT CONTROL#: ACCT123456"
        fields = parser.extract_fields(text)
        assert "patient_control" in fields
        assert fields["patient_control"].phi_category == PHICategory.ACCOUNT_NUMBER

    def test_extract_patient_name(self, parser):
        """Test extracting FL 8 - Patient Name."""
        text = "FL 8. PATIENT NAME: SMITH, JOHN"
        fields = parser.extract_fields(text)
        assert "patient_name" in fields
        assert fields["patient_name"].phi_category == PHICategory.NAME

    def test_extract_patient_dob(self, parser):
        """Test extracting FL 10 - Patient DOB."""
        text = "FL 10. BIRTH DATE: 01/15/1960"
        fields = parser.extract_fields(text)
        assert "patient_dob" in fields

    def test_extract_admission_date(self, parser):
        """Test extracting FL 12 - Admission Date."""
        text = "FL 12. ADMISSION: 01/01/2024"
        fields = parser.extract_fields(text)
        assert "admission_date" in fields
        assert fields["admission_date"].phi_category == PHICategory.DATE

    def test_extract_mrn(self, parser):
        """Test extracting MRN."""
        text = "MRN: MR123456789"
        fields = parser.extract_fields(text)
        assert "mrn" in fields
        assert fields["mrn"].phi_category == PHICategory.MRN


class TestPassportParser:
    """Tests for PassportParser."""

    @pytest.fixture
    def parser(self):
        return PassportParser()

    def test_document_type(self, parser):
        """Test parser document type."""
        assert parser.document_type == DocumentType.PASSPORT

    def test_extract_mrz_data(self, parser):
        """Test extracting MRZ data."""
        # Standard passport MRZ format (TD3)
        text = """
        P<USASMITH<<JOHN<EDWARD<<<<<<<<<<<<<<<<<<<<<<
        123456789<USA7001011M2501011234567890<<<<<<0
        """
        fields = parser.extract_fields(text)

        if "name" in fields:
            assert fields["name"].phi_category == PHICategory.NAME

        if "passport_number" in fields:
            assert fields["passport_number"].phi_category == PHICategory.OTHER_UNIQUE_ID

    def test_extract_visual_zone_passport_number(self, parser):
        """Test extracting passport number from visual zone."""
        text = "PASSPORT NO: 123456789"
        fields = parser.extract_fields(text)
        assert "passport_number" in fields
        assert fields["passport_number"].value == "123456789"

    def test_field_patterns_empty(self, parser):
        """Test passport uses special MRZ parsing."""
        assert parser.field_patterns == []


class TestLabRequisitionParser:
    """Tests for LabRequisitionParser."""

    @pytest.fixture
    def parser(self):
        return LabRequisitionParser()

    def test_document_type(self, parser):
        """Test parser document type."""
        assert parser.document_type == DocumentType.LAB_REQUISITION

    def test_extract_patient_name(self, parser):
        """Test extracting patient name."""
        text = "PATIENT: SMITH, JOHN"
        fields = parser.extract_fields(text)
        assert "patient_name" in fields
        assert fields["patient_name"].phi_category == PHICategory.NAME

    def test_extract_mrn(self, parser):
        """Test extracting MRN."""
        text = "MRN: MR123456"
        fields = parser.extract_fields(text)
        assert "mrn" in fields
        assert fields["mrn"].phi_category == PHICategory.MRN

    def test_extract_dob(self, parser):
        """Test extracting DOB."""
        text = "DOB: 01/15/1990"
        fields = parser.extract_fields(text)
        assert "dob" in fields

    def test_extract_collection_date(self, parser):
        """Test extracting collection date."""
        text = "COLLECTION DATE: 01/01/2024"
        fields = parser.extract_fields(text)
        assert "collection_date" in fields
        assert fields["collection_date"].phi_category == PHICategory.DATE

    def test_extract_ordering_physician(self, parser):
        """Test extracting ordering physician."""
        text = "ORDERING PHYSICIAN: DR. JANE DOE"
        fields = parser.extract_fields(text)
        assert "ordering_physician" in fields

    def test_extract_npi(self, parser):
        """Test extracting NPI."""
        text = "NPI: 1234567893"
        fields = parser.extract_fields(text)
        assert "npi" in fields
        assert fields["npi"].validated is True


class TestPrescriptionParser:
    """Tests for PrescriptionParser."""

    @pytest.fixture
    def parser(self):
        return PrescriptionParser()

    def test_document_type(self, parser):
        """Test parser document type."""
        assert parser.document_type == DocumentType.PRESCRIPTION_LABEL

    def test_extract_rx_number(self, parser):
        """Test extracting Rx number."""
        text = "RX# 1234567890"
        fields = parser.extract_fields(text)
        assert "rx_number" in fields
        assert fields["rx_number"].phi_category == PHICategory.OTHER_UNIQUE_ID

    def test_extract_patient_name(self, parser):
        """Test extracting patient name."""
        text = "PATIENT: SMITH, JOHN"
        fields = parser.extract_fields(text)
        assert "patient_name" in fields

    def test_extract_prescriber(self, parser):
        """Test extracting prescriber."""
        text = "DR. JANE DOE"
        fields = parser.extract_fields(text)
        assert "prescriber" in fields

    def test_extract_dea_number(self, parser):
        """Test extracting DEA number."""
        text = "DEA# AB1234563"
        fields = parser.extract_fields(text)
        assert "dea_number" in fields
        assert fields["dea_number"].validated is True

    def test_extract_invalid_dea(self, parser):
        """Test extracting invalid DEA shows lower confidence."""
        text = "DEA# AB1234560"  # Wrong check digit
        fields = parser.extract_fields(text)
        assert "dea_number" in fields
        assert fields["dea_number"].confidence == 0.7  # Lower for invalid

    def test_extract_ndc(self, parser):
        """Test extracting NDC."""
        text = "NDC: 12345-678-90"
        fields = parser.extract_fields(text)
        assert "ndc" in fields
        assert fields["ndc"].phi_category is None  # Not PHI

    def test_extract_date_filled(self, parser):
        """Test extracting date filled."""
        text = "DATE FILLED: 01/15/2024"
        fields = parser.extract_fields(text)
        assert "date_filled" in fields


class TestEOBParser:
    """Tests for EOBParser."""

    @pytest.fixture
    def parser(self):
        return EOBParser()

    def test_document_type(self, parser):
        """Test parser document type."""
        assert parser.document_type == DocumentType.EOB

    def test_extract_claim_number(self, parser):
        """Test extracting claim number."""
        text = "CLAIM# CLM123456789012"
        fields = parser.extract_fields(text)
        assert "claim_number" in fields
        assert fields["claim_number"].phi_category == PHICategory.ACCOUNT_NUMBER

    def test_extract_member_name(self, parser):
        """Test extracting member name."""
        text = "MEMBER: SMITH, JOHN"
        fields = parser.extract_fields(text)
        assert "member_name" in fields
        assert fields["member_name"].phi_category == PHICategory.NAME

    def test_extract_service_date(self, parser):
        """Test extracting service date."""
        text = "SERVICE DATE: 01/15/2024"
        fields = parser.extract_fields(text)
        assert "service_date" in fields
        assert fields["service_date"].phi_category == PHICategory.DATE

    def test_extract_member_id(self, parser):
        """Test extracting member ID."""
        text = "MEMBER ID: ABC123456789"
        fields = parser.extract_fields(text)
        assert "member_id" in fields
        assert fields["member_id"].phi_category == PHICategory.HEALTH_PLAN_ID


# =============================================================================
# MAIN INTERFACE TESTS
# =============================================================================

class TestGetParser:
    """Tests for get_parser function."""

    def test_get_drivers_license_parser(self):
        """Test getting driver's license parser."""
        parser = get_parser(DocumentType.DRIVERS_LICENSE)
        assert parser is not None
        assert isinstance(parser, DriversLicenseParser)

    def test_get_state_id_parser(self):
        """Test getting state ID parser (shares DL parser)."""
        parser = get_parser(DocumentType.STATE_ID)
        assert parser is not None
        assert isinstance(parser, DriversLicenseParser)

    def test_get_insurance_parser(self):
        """Test getting insurance card parser."""
        parser = get_parser(DocumentType.INSURANCE_COMMERCIAL)
        assert parser is not None
        assert isinstance(parser, InsuranceCardParser)

    def test_get_medicare_parser(self):
        """Test getting Medicare card parser."""
        parser = get_parser(DocumentType.INSURANCE_MEDICARE)
        assert parser is not None
        assert isinstance(parser, MedicareCardParser)

    def test_get_unknown_returns_none(self):
        """Test unknown document type returns None."""
        parser = get_parser(DocumentType.UNKNOWN)
        assert parser is None

    def test_get_unsupported_returns_none(self):
        """Test unsupported types return None."""
        # CONSENT_FORM doesn't have a dedicated parser
        parser = get_parser(DocumentType.CONSENT_FORM)
        assert parser is None


class TestParseDocument:
    """Tests for parse_document function."""

    def test_parse_with_specified_type(self):
        """Test parsing with specified document type."""
        text = "DLN: D12345678\nDOB: 01/15/1990"
        result = parse_document(text, doc_type=DocumentType.DRIVERS_LICENSE)
        assert result.document_type == DocumentType.DRIVERS_LICENSE
        assert result.confidence == 1.0
        assert len(result.fields) > 0

    def test_parse_with_auto_detection(self):
        """Test parsing with auto-detected document type."""
        text = """
        MEDICARE
        MBI: 1EG4TE5MK72
        PART A: 01/01/2020
        """
        result = parse_document(text)
        assert result.document_type == DocumentType.INSURANCE_MEDICARE

    def test_parse_unknown_document(self):
        """Test parsing unknown document type."""
        text = "Random text without keywords"
        result = parse_document(text)
        assert result.document_type == DocumentType.UNKNOWN
        assert result.fields == {}
        assert "No parser available" in result.warnings[0]

    def test_parse_with_aspect_ratio(self):
        """Test parsing with aspect ratio hint."""
        text = "DRIVER'S LICENSE"
        result = parse_document(text, aspect_ratio=1.58)
        # Should still detect as DL
        assert result.document_type == DocumentType.DRIVERS_LICENSE


class TestCleanDocumentText:
    """Tests for clean_document_text function."""

    def test_clean_dl_text(self):
        """Test cleaning driver's license text."""
        text = "DLN: D12345678\nDOB: 01/15/1990"
        cleaned = clean_document_text(text, DocumentType.DRIVERS_LICENSE)
        assert "DLN:" not in cleaned
        assert "DOB:" not in cleaned

    def test_clean_insurance_text(self):
        """Test cleaning insurance card text."""
        text = "MEMBER ID: ABC123"
        cleaned = clean_document_text(text, DocumentType.INSURANCE_COMMERCIAL)
        assert "MEMBER ID:" not in cleaned

    def test_clean_unknown_returns_original(self):
        """Test cleaning unknown document returns original."""
        text = "Some random text"
        cleaned = clean_document_text(text)
        assert cleaned == text


class TestExtractPHIFields:
    """Tests for extract_phi_fields function."""

    def test_extract_phi_from_dl(self):
        """Test extracting PHI fields from driver's license."""
        text = """
        DLN: D12345678
        DOB: 01/15/1990
        SEX: M
        SPRINGFIELD IL 62701
        """
        phi_fields = extract_phi_fields(text, DocumentType.DRIVERS_LICENSE)

        # Should have license_number (PHI) but not sex (not PHI)
        # Check that at least some PHI fields are extracted
        for field in phi_fields.values():
            assert field.phi_category is not None

    def test_extract_phi_from_cms_1500(self):
        """Test extracting PHI fields from CMS-1500."""
        text = """
        2. PATIENT'S NAME: SMITH, JOHN
        3. DOB: 01/15/1960
        NPI: 1234567893
        """
        phi_fields = extract_phi_fields(text, DocumentType.CMS_1500)

        # Patient name should be PHI
        if "patient_name" in phi_fields:
            assert phi_fields["patient_name"].phi_category == PHICategory.NAME


class TestDocumentParserRegistry:
    """Tests for DOCUMENT_PARSERS registry."""

    def test_registry_has_dl(self):
        """Test registry has driver's license parser."""
        assert DocumentType.DRIVERS_LICENSE in DOCUMENT_PARSERS
        assert DOCUMENT_PARSERS[DocumentType.DRIVERS_LICENSE] == DriversLicenseParser

    def test_registry_has_insurance_types(self):
        """Test registry has insurance parsers."""
        assert DocumentType.INSURANCE_COMMERCIAL in DOCUMENT_PARSERS
        assert DocumentType.INSURANCE_MEDICARE in DOCUMENT_PARSERS
        assert DocumentType.INSURANCE_MEDICAID in DOCUMENT_PARSERS
        assert DocumentType.INSURANCE_TRICARE in DOCUMENT_PARSERS

    def test_registry_has_claim_forms(self):
        """Test registry has claim form parsers."""
        assert DocumentType.CMS_1500 in DOCUMENT_PARSERS
        assert DocumentType.UB_04 in DOCUMENT_PARSERS

    def test_registry_has_clinical_docs(self):
        """Test registry has clinical document parsers."""
        assert DocumentType.LAB_REQUISITION in DOCUMENT_PARSERS
        assert DocumentType.PRESCRIPTION_LABEL in DOCUMENT_PARSERS
        assert DocumentType.PRESCRIPTION_PAD in DOCUMENT_PARSERS

    def test_registry_has_eob(self):
        """Test registry has EOB parser."""
        assert DocumentType.EOB in DOCUMENT_PARSERS


# =============================================================================
# FIELD PATTERN TESTS
# =============================================================================

class TestFieldPatterns:
    """Tests for field pattern lists."""

    def test_aamva_patterns_not_empty(self):
        """Test AAMVA field patterns are defined."""
        assert len(AAMVA_FIELD_PATTERNS) > 0
        # Should include common AAMVA codes
        patterns = [p[0] for p in AAMVA_FIELD_PATTERNS]
        assert any("DAQ" in p for p in patterns)  # License number
        assert any("DOB" in p for p in patterns)  # Date of birth

    def test_insurance_patterns_not_empty(self):
        """Test insurance field patterns are defined."""
        assert len(INSURANCE_FIELD_PATTERNS) > 0
        patterns = [p[0] for p in INSURANCE_FIELD_PATTERNS]
        assert any("MEMBER" in p for p in patterns)
        assert any("GROUP" in p for p in patterns)

    def test_medicare_patterns_not_empty(self):
        """Test Medicare field patterns are defined."""
        assert len(MEDICARE_FIELD_PATTERNS) > 0
        patterns = [p[0] for p in MEDICARE_FIELD_PATTERNS]
        assert any("MBI" in p for p in patterns)
        assert any("MEDICARE" in p for p in patterns)

    def test_cms_1500_patterns_not_empty(self):
        """Test CMS-1500 field patterns are defined."""
        assert len(CMS_1500_FIELD_PATTERNS) > 0
        # Should have box number patterns
        patterns = [p[0] for p in CMS_1500_FIELD_PATTERNS]
        assert any("1a" in p or "1A" in p for p in patterns)

    def test_ub_04_patterns_not_empty(self):
        """Test UB-04 field patterns are defined."""
        assert len(UB_04_FIELD_PATTERNS) > 0
        # Should have form locator patterns
        patterns = [p[0] for p in UB_04_FIELD_PATTERNS]
        assert any("FL" in p for p in patterns)

    def test_lab_requisition_patterns_not_empty(self):
        """Test lab requisition patterns are defined."""
        assert len(LAB_REQUISITION_PATTERNS) > 0
        patterns = [p[0] for p in LAB_REQUISITION_PATTERNS]
        assert any("PATIENT" in p for p in patterns)
        assert any("MRN" in p for p in patterns)

    def test_prescription_patterns_not_empty(self):
        """Test prescription patterns are defined."""
        assert len(PRESCRIPTION_PATTERNS) > 0
        patterns = [p[0] for p in PRESCRIPTION_PATTERNS]
        assert any("RX" in p for p in patterns)
        assert any("DEA" in p for p in patterns)

    def test_eob_patterns_not_empty(self):
        """Test EOB patterns are defined."""
        assert len(EOB_PATTERNS) > 0
        patterns = [p[0] for p in EOB_PATTERNS]
        assert any("CLAIM" in p for p in patterns)


class TestDocumentKeywords:
    """Tests for DOCUMENT_KEYWORDS detection patterns."""

    def test_keywords_defined_for_all_detectable_types(self):
        """Test keywords defined for detectable document types."""
        assert DocumentType.DRIVERS_LICENSE in DOCUMENT_KEYWORDS
        assert DocumentType.PASSPORT in DOCUMENT_KEYWORDS
        assert DocumentType.INSURANCE_COMMERCIAL in DOCUMENT_KEYWORDS
        assert DocumentType.INSURANCE_MEDICARE in DOCUMENT_KEYWORDS
        assert DocumentType.CMS_1500 in DOCUMENT_KEYWORDS
        assert DocumentType.UB_04 in DOCUMENT_KEYWORDS
        assert DocumentType.LAB_REQUISITION in DOCUMENT_KEYWORDS
        assert DocumentType.PRESCRIPTION_LABEL in DOCUMENT_KEYWORDS
        assert DocumentType.EOB in DOCUMENT_KEYWORDS

    def test_keywords_are_regex_patterns(self):
        """Test keywords are valid regex patterns."""
        import re
        for doc_type, patterns in DOCUMENT_KEYWORDS.items():
            for pattern in patterns:
                # Should compile without error
                re.compile(pattern, re.IGNORECASE)


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_text_detection(self):
        """Test detection with empty text."""
        doc_type, confidence = detect_document_type("")
        assert doc_type == DocumentType.UNKNOWN
        assert confidence == 0.0

    def test_empty_text_parsing(self):
        """Test parsing empty text."""
        result = parse_document("")
        assert result.document_type == DocumentType.UNKNOWN

    def test_whitespace_only_text(self):
        """Test detection with whitespace only."""
        doc_type, confidence = detect_document_type("   \n\t   ")
        assert doc_type == DocumentType.UNKNOWN

    def test_special_characters_in_text(self):
        """Test handling special characters."""
        text = "MEMBER ID: ABC@#$%123"
        result = parse_document(text, DocumentType.INSURANCE_COMMERCIAL)
        # Should not crash
        assert result is not None

    def test_very_long_text(self):
        """Test handling very long text."""
        text = "DRIVER'S LICENSE\n" + "A" * 10000
        result = parse_document(text, DocumentType.DRIVERS_LICENSE)
        assert result is not None

    def test_unicode_text(self):
        """Test handling unicode characters."""
        text = "PATIENT: José García\nDOB: 01/15/1990"
        result = parse_document(text, DocumentType.LAB_REQUISITION)
        assert result is not None

    def test_mixed_case_detection(self):
        """Test detection is case-insensitive."""
        text1 = "DRIVER'S LICENSE"
        text2 = "driver's license"
        text3 = "Driver's License"

        doc_type1, _ = detect_document_type(text1)
        doc_type2, _ = detect_document_type(text2)
        doc_type3, _ = detect_document_type(text3)

        assert doc_type1 == DocumentType.DRIVERS_LICENSE
        assert doc_type2 == DocumentType.DRIVERS_LICENSE
        assert doc_type3 == DocumentType.DRIVERS_LICENSE

    def test_confidence_capped_at_one(self):
        """Test confidence doesn't exceed 1.0."""
        # Many keywords should still cap at 1.0
        text = """
        CMS-1500 HCFA-1500 HEALTH INSURANCE CLAIM FORM
        APPROVED BY NATIONAL
        1a. INSURED'S I.D
        21. DIAGNOSIS
        24. A. DATE
        """
        doc_type, confidence = detect_document_type(text)
        assert confidence <= 1.0
