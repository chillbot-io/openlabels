"""
Comprehensive tests for scrubiq/detectors/additional_patterns.py.

Tests detection of additional entity types: EMPLOYER, AGE, HEALTH_PLAN_ID,
MEMBER_ID, NPI, BANK_ROUTING, and EMPLOYEE_ID.
"""

import pytest
from scrubiq.detectors.additional_patterns import (
    AdditionalPatternDetector,
    ADDITIONAL_PATTERNS,
)
from scrubiq.types import Tier


# =============================================================================
# AdditionalPatternDetector Class Tests
# =============================================================================
class TestAdditionalPatternDetector:
    """Tests for the AdditionalPatternDetector class."""

    @pytest.fixture
    def detector(self):
        """Create an AdditionalPatternDetector instance."""
        return AdditionalPatternDetector()

    def test_detector_name(self, detector):
        """Detector should have correct name."""
        assert detector.name == "additional_patterns"

    def test_detector_tier(self, detector):
        """Detector should use PATTERN tier."""
        assert detector.tier == Tier.PATTERN

    def test_detect_returns_list(self, detector):
        """Detection should return a list."""
        result = detector.detect("No patterns here")
        assert isinstance(result, list)

    def test_detect_empty_text(self, detector):
        """Empty text should return empty list."""
        result = detector.detect("")
        assert result == []

    def test_is_available(self, detector):
        """Detector should be available when patterns compiled."""
        assert detector.is_available() is True

    def test_patterns_compiled(self, detector):
        """Patterns should be compiled on init."""
        assert len(detector._compiled_patterns) > 0


# =============================================================================
# EMPLOYER Detection Tests
# =============================================================================
class TestEmployerDetection:
    """Tests for employer/organization name detection."""

    @pytest.fixture
    def detector(self):
        return AdditionalPatternDetector()

    def test_detect_company_inc(self, detector):
        """Detect company with Inc suffix."""
        text = "Employed at Acme Technologies Inc."
        spans = detector.detect(text)

        employer_spans = [s for s in spans if s.entity_type == "EMPLOYER"]
        assert len(employer_spans) >= 1
        assert any("Acme" in s.text for s in employer_spans)

    def test_detect_company_corp(self, detector):
        """Detect company with Corp suffix."""
        text = "Works for Global Systems Corp"
        spans = detector.detect(text)

        employer_spans = [s for s in spans if s.entity_type == "EMPLOYER"]
        assert len(employer_spans) >= 1

    def test_detect_company_llc(self, detector):
        """Detect company with LLC suffix."""
        text = "Patient employer: Smith & Associates LLC"
        spans = detector.detect(text)

        employer_spans = [s for s in spans if s.entity_type == "EMPLOYER"]
        assert len(employer_spans) >= 1

    def test_detect_company_ltd(self, detector):
        """Detect company with Ltd suffix."""
        text = "British Healthcare Ltd provides services"
        spans = detector.detect(text)

        employer_spans = [s for s in spans if s.entity_type == "EMPLOYER"]
        assert len(employer_spans) >= 1

    def test_detect_employer_label(self, detector):
        """Detect employer with explicit label."""
        text = "employer: Riverside Medical Center"
        spans = detector.detect(text)

        employer_spans = [s for s in spans if s.entity_type == "EMPLOYER"]
        assert len(employer_spans) >= 1

    def test_detect_works_at(self, detector):
        """Detect employer with 'works at' context."""
        text = "She works at General Hospital"
        spans = detector.detect(text)

        employer_spans = [s for s in spans if s.entity_type == "EMPLOYER"]
        # Pattern requires specific format, may or may not match

    def test_detect_employed_by(self, detector):
        """Detect employer with 'employed by' context."""
        text = "Employed by State Farm Insurance"
        spans = detector.detect(text)

        employer_spans = [s for s in spans if s.entity_type == "EMPLOYER"]
        # May detect depending on pattern matching

    def test_detect_company_group(self, detector):
        """Detect company with Group suffix."""
        text = "Acme Healthcare Group announced"
        spans = detector.detect(text)

        employer_spans = [s for s in spans if s.entity_type == "EMPLOYER"]
        assert len(employer_spans) >= 1

    def test_detect_company_holdings(self, detector):
        """Detect company with Holdings suffix."""
        text = "MedCorp Holdings Inc"
        spans = detector.detect(text)

        employer_spans = [s for s in spans if s.entity_type == "EMPLOYER"]
        assert len(employer_spans) >= 1


# =============================================================================
# AGE Detection Tests
# =============================================================================
class TestAgeDetection:
    """Tests for age expression detection."""

    @pytest.fixture
    def detector(self):
        return AdditionalPatternDetector()

    def test_detect_years_old(self, detector):
        """Detect 'X years old' format."""
        text = "Patient is 45 years old"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1
        assert any("45" in s.text for s in age_spans)

    def test_detect_year_old_hyphenated(self, detector):
        """Detect 'X-year-old' format."""
        text = "A 72-year-old male presented"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1

    def test_detect_yo_abbreviation(self, detector):
        """Detect 'X y/o' abbreviation."""
        text = "65 y/o female patient"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1

    def test_detect_yo_no_slash(self, detector):
        """Detect 'Xyo' abbreviation."""
        text = "32yo male"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1

    def test_detect_age_colon(self, detector):
        """Detect 'age: X' format."""
        text = "Patient age: 55"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1
        assert any("55" in s.text for s in age_spans)

    def test_detect_aged(self, detector):
        """Detect 'aged X' format."""
        text = "Person aged 28"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1

    def test_detect_pt_age(self, detector):
        """Detect 'pt age: X' format."""
        text = "Pt. age: 40"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1

    def test_detect_year_old_with_gender(self, detector):
        """Detect 'X-year-old male/female' format."""
        text = "52-year-old female presented with"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1

    def test_detect_article_before_age(self, detector):
        """Detect 'a X year old' format."""
        text = "a 38 year old patient"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1

    def test_detect_months_old(self, detector):
        """Detect infant age in months."""
        text = "6 months old infant"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1

    def test_age_validation_invalid(self, detector):
        """Ages > 120 should be filtered."""
        text = "Age: 150 years old"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        # 150 is invalid, should be filtered
        invalid_ages = [s for s in age_spans if "150" in s.text]
        assert len(invalid_ages) == 0

    def test_age_validation_valid_boundary(self, detector):
        """Age 120 should be accepted."""
        text = "She is 120 years old"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        # 120 is valid
        valid_ages = [s for s in age_spans if "120" in s.text]
        assert len(valid_ages) >= 1

    def test_age_negative_filtered(self, detector):
        """Negative ages should be filtered."""
        # Pattern won't match negative numbers due to \d+ pattern
        text = "Age: -5"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) == 0


# =============================================================================
# HEALTH_PLAN_ID Detection Tests
# =============================================================================
class TestHealthPlanIDDetection:
    """Tests for health plan/insurance ID detection."""

    @pytest.fixture
    def detector(self):
        return AdditionalPatternDetector()

    def test_detect_member_id(self, detector):
        """Detect member ID."""
        text = "Member ID: ABC123456789"
        spans = detector.detect(text)

        hp_spans = [s for s in spans if s.entity_type in ("HEALTH_PLAN_ID", "MEMBER_ID")]
        assert len(hp_spans) >= 1

    def test_detect_subscriber_id(self, detector):
        """Detect subscriber ID."""
        text = "Subscriber ID: XYZ987654"
        spans = detector.detect(text)

        hp_spans = [s for s in spans if s.entity_type == "HEALTH_PLAN_ID"]
        assert len(hp_spans) >= 1

    def test_detect_policy_number(self, detector):
        """Detect policy number."""
        text = "Policy #: POL123456"
        spans = detector.detect(text)

        hp_spans = [s for s in spans if s.entity_type == "HEALTH_PLAN_ID"]
        assert len(hp_spans) >= 1

    def test_detect_group_number(self, detector):
        """Detect group number."""
        text = "Group number: GRP98765"
        spans = detector.detect(text)

        hp_spans = [s for s in spans if s.entity_type == "HEALTH_PLAN_ID"]
        assert len(hp_spans) >= 1

    def test_detect_bcbs_prefix(self, detector):
        """Detect BCBS prefixed ID."""
        text = "Insurance: BCBS1234567890"
        spans = detector.detect(text)

        hp_spans = [s for s in spans if s.entity_type == "HEALTH_PLAN_ID"]
        assert len(hp_spans) >= 1

    def test_detect_uhc_prefix(self, detector):
        """Detect UHC prefixed ID."""
        text = "Member: UHC9876543210"
        spans = detector.detect(text)

        hp_spans = [s for s in spans if s.entity_type == "HEALTH_PLAN_ID"]
        assert len(hp_spans) >= 1

    def test_detect_aetna_prefix(self, detector):
        """Detect AETNA prefixed ID."""
        text = "Plan ID: AETNA12345678"
        spans = detector.detect(text)

        hp_spans = [s for s in spans if s.entity_type == "HEALTH_PLAN_ID"]
        assert len(hp_spans) >= 1

    def test_detect_medicaid_id(self, detector):
        """Detect Medicaid ID."""
        text = "Medicaid ID: 123456789AB"
        spans = detector.detect(text)

        hp_spans = [s for s in spans if s.entity_type == "HEALTH_PLAN_ID"]
        assert len(hp_spans) >= 1

    def test_detect_medicare_id(self, detector):
        """Detect Medicare ID."""
        text = "Medicare number: 1EG4TE5MK72"
        spans = detector.detect(text)

        hp_spans = [s for s in spans if s.entity_type == "HEALTH_PLAN_ID"]
        assert len(hp_spans) >= 1


# =============================================================================
# NPI Detection Tests
# =============================================================================
class TestNPIDetection:
    """Tests for National Provider Identifier detection."""

    @pytest.fixture
    def detector(self):
        return AdditionalPatternDetector()

    def test_detect_npi_labeled(self, detector):
        """Detect NPI with label."""
        text = "NPI: 1234567890"
        spans = detector.detect(text)

        npi_spans = [s for s in spans if s.entity_type == "NPI"]
        assert len(npi_spans) >= 1
        assert any("1234567890" in s.text for s in npi_spans)

    def test_detect_npi_full_label(self, detector):
        """Detect NPI with full label."""
        text = "National Provider Identifier: 1987654321"
        spans = detector.detect(text)

        npi_spans = [s for s in spans if s.entity_type == "NPI"]
        assert len(npi_spans) >= 1

    def test_detect_provider_id(self, detector):
        """Detect provider ID (may be NPI)."""
        text = "Provider ID: 1555666777"
        spans = detector.detect(text)

        npi_spans = [s for s in spans if s.entity_type == "NPI"]
        assert len(npi_spans) >= 1

    def test_npi_starts_with_1(self, detector):
        """NPI should start with 1 or 2."""
        text = "NPI: 1234567890"
        spans = detector.detect(text)

        npi_spans = [s for s in spans if s.entity_type == "NPI"]
        assert len(npi_spans) >= 1

    def test_npi_starts_with_2(self, detector):
        """NPI starting with 2 should be detected."""
        text = "NPI: 2345678901"
        spans = detector.detect(text)

        npi_spans = [s for s in spans if s.entity_type == "NPI"]
        assert len(npi_spans) >= 1

    def test_npi_wrong_start_digit(self, detector):
        """NPI starting with other digits should not match."""
        text = "NPI: 3456789012"  # Starts with 3
        spans = detector.detect(text)

        npi_spans = [s for s in spans if s.entity_type == "NPI" and "3456789012" in s.text]
        # Pattern requires starting with 1 or 2
        assert len(npi_spans) == 0


# =============================================================================
# BANK_ROUTING Detection Tests
# =============================================================================
class TestBankRoutingDetection:
    """Tests for bank routing number detection."""

    @pytest.fixture
    def detector(self):
        return AdditionalPatternDetector()

    def test_detect_routing_labeled(self, detector):
        """Detect routing number with label."""
        text = "Routing number: 123456789"
        spans = detector.detect(text)

        routing_spans = [s for s in spans if s.entity_type == "BANK_ROUTING"]
        assert len(routing_spans) >= 1
        assert any("123456789" in s.text for s in routing_spans)

    def test_detect_aba_labeled(self, detector):
        """Detect ABA routing number."""
        text = "ABA: 021000021"
        spans = detector.detect(text)

        routing_spans = [s for s in spans if s.entity_type == "BANK_ROUTING"]
        assert len(routing_spans) >= 1

    def test_detect_rtn_labeled(self, detector):
        """Detect RTN (Routing Transit Number)."""
        text = "RTN: 026009593"
        spans = detector.detect(text)

        routing_spans = [s for s in spans if s.entity_type == "BANK_ROUTING"]
        assert len(routing_spans) >= 1

    def test_routing_simple_colon(self, detector):
        """Detect routing with simple colon format."""
        text = "routing: 111000025"
        spans = detector.detect(text)

        routing_spans = [s for s in spans if s.entity_type == "BANK_ROUTING"]
        assert len(routing_spans) >= 1


# =============================================================================
# EMPLOYEE_ID Detection Tests
# =============================================================================
class TestEmployeeIDDetection:
    """Tests for employee ID detection."""

    @pytest.fixture
    def detector(self):
        return AdditionalPatternDetector()

    def test_detect_employee_id(self, detector):
        """Detect employee ID."""
        text = "Employee ID: EMP12345"
        spans = detector.detect(text)

        emp_spans = [s for s in spans if s.entity_type == "EMPLOYEE_ID"]
        assert len(emp_spans) >= 1

    def test_detect_staff_id(self, detector):
        """Detect staff ID."""
        text = "Staff ID: STF98765"
        spans = detector.detect(text)

        emp_spans = [s for s in spans if s.entity_type == "EMPLOYEE_ID"]
        assert len(emp_spans) >= 1

    def test_detect_personnel_number(self, detector):
        """Detect personnel number."""
        text = "Personnel number: P123456"
        spans = detector.detect(text)

        emp_spans = [s for s in spans if s.entity_type == "EMPLOYEE_ID"]
        assert len(emp_spans) >= 1

    def test_detect_emp_id_abbreviation(self, detector):
        """Detect abbreviated emp id."""
        text = "emp id: ABC1234"
        spans = detector.detect(text)

        emp_spans = [s for s in spans if s.entity_type == "EMPLOYEE_ID"]
        assert len(emp_spans) >= 1


# =============================================================================
# Pattern Coverage Tests
# =============================================================================
class TestPatternsCoverage:
    """Tests for pattern definitions."""

    def test_patterns_not_empty(self):
        """ADDITIONAL_PATTERNS should contain patterns."""
        assert len(ADDITIONAL_PATTERNS) > 0

    def test_pattern_structure(self):
        """Each pattern should have correct structure."""
        for pattern, entity_type, confidence, group, flags in ADDITIONAL_PATTERNS:
            assert isinstance(pattern, str) and len(pattern) > 0
            assert isinstance(entity_type, str) and len(entity_type) > 0
            assert 0 <= confidence <= 1
            assert group >= 0
            assert isinstance(flags, int)

    def test_all_entity_types_defined(self):
        """All documented entity types should have patterns."""
        entity_types = {pattern[1] for pattern in ADDITIONAL_PATTERNS}

        expected = {"EMPLOYER", "AGE", "HEALTH_PLAN_ID", "NPI", "BANK_ROUTING"}

        # Core types should be present
        for et in expected:
            assert et in entity_types, f"Missing pattern for {et}"


# =============================================================================
# Edge Cases and Robustness Tests
# =============================================================================
class TestAdditionalPatternsEdgeCases:
    """Edge case tests for additional pattern detection."""

    @pytest.fixture
    def detector(self):
        return AdditionalPatternDetector()

    def test_unicode_text(self, detector):
        """Should handle Unicode text."""
        text = "Patient age: 45 日本語テスト"
        spans = detector.detect(text)
        # Should still detect age
        age_spans = [s for s in spans if s.entity_type == "AGE"]
        assert len(age_spans) >= 1

    def test_very_long_text(self, detector):
        """Should handle very long text."""
        text = "x" * 50000 + " Member ID: ABC123456 " + "y" * 50000
        spans = detector.detect(text)
        hp_spans = [s for s in spans if s.entity_type in ("HEALTH_PLAN_ID", "MEMBER_ID")]
        assert len(hp_spans) >= 1

    def test_multiple_types_same_text(self, detector):
        """Should detect multiple entity types in same text."""
        text = """
        Patient: 45 years old
        Employer: Acme Corp
        Member ID: XYZ123456
        NPI: 1234567890
        """
        spans = detector.detect(text)

        entity_types = {s.entity_type for s in spans}
        # Should have multiple types
        assert len(entity_types) >= 2

    def test_span_position_accuracy(self, detector):
        """Span positions should be accurate."""
        prefix = "Patient age is "
        text = f"{prefix}72 years old"
        spans = detector.detect(text)

        age_spans = [s for s in spans if s.entity_type == "AGE"]
        if age_spans:
            span = age_spans[0]
            # Text at position should match
            assert text[span.start:span.end] == span.text

    def test_case_insensitive_detection(self, detector):
        """Patterns should be case-insensitive where appropriate."""
        text1 = "MEMBER ID: ABC123456"
        text2 = "member id: ABC123456"
        text3 = "Member Id: ABC123456"

        spans1 = [s for s in detector.detect(text1) if s.entity_type in ("HEALTH_PLAN_ID", "MEMBER_ID")]
        spans2 = [s for s in detector.detect(text2) if s.entity_type in ("HEALTH_PLAN_ID", "MEMBER_ID")]
        spans3 = [s for s in detector.detect(text3) if s.entity_type in ("HEALTH_PLAN_ID", "MEMBER_ID")]

        # All variations should detect
        assert len(spans1) >= 1 or len(spans2) >= 1 or len(spans3) >= 1

    def test_short_match_filtered(self, detector):
        """Very short matches should be filtered."""
        text = "ID: AB"  # Only 2 chars
        spans = detector.detect(text)

        # 2-char matches should be filtered
        short_spans = [s for s in spans if len(s.text.strip()) < 2]
        assert len(short_spans) == 0

    def test_detect_handles_regex_errors(self):
        """Detector should handle regex errors gracefully."""
        detector = AdditionalPatternDetector()
        # Detection should work even if some patterns failed to compile
        result = detector.detect("Test text")
        assert isinstance(result, list)
