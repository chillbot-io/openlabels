"""Tests for context-aware filtering in merger.py.

Tests ID card detection, tracking number filtering, and healthcare facility validation.
"""

import pytest
from scrubiq.types import Span, Tier
from scrubiq.pipeline.merger import (
    is_id_card_context,
    filter_ml_mrn_on_id_cards,
    is_tracking_number,
    filter_tracking_numbers,
    is_valid_healthcare_facility,
)


def make_span(text, start=0, entity_type="NAME", confidence=0.9, detector="test", tier=2):
    """Helper to create spans with correct end position."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=Tier.from_value(tier),
    )


class TestIsIdCardContext:
    """Tests for is_id_card_context()."""

    def test_drivers_license_detected(self):
        """Text with DRIVER'S LICENSE pattern is detected."""
        text = """
        DRIVER'S LICENSE
        NAME: JOHN SMITH
        DLN: D123-4567-8901
        """
        assert is_id_card_context(text) is True

    def test_state_id_detected(self):
        """Text with STATE ID pattern is detected."""
        text = """
        STATE ID
        CLASS: C
        NAME: JANE DOE
        """
        assert is_id_card_context(text) is True

    def test_dln_pattern_detected(self):
        """Text with DLN: pattern is detected."""
        text = "DLN: D123456789 CLASS: C DUPS: 000"
        assert is_id_card_context(text) is True

    def test_multiple_indicators_required(self):
        """At least 2 ID card indicators are required."""
        # Only one indicator - not enough
        text = "DRIVER LICENSE number is 12345"
        assert is_id_card_context(text) is False

        # Two indicators - enough
        text = "DRIVER'S LICENSE CLASS: C"
        assert is_id_card_context(text) is True

    def test_clinical_note_not_id_card(self):
        """Regular clinical notes are not detected as ID cards."""
        text = """
        Patient: John Smith
        DOB: 01/15/1980
        MRN: 123456789
        Chief Complaint: Chest pain
        """
        assert is_id_card_context(text) is False

    def test_organ_donor_indicator(self):
        """ORGAN DONOR text is an ID card indicator."""
        text = "DRIVER'S LICENSE ORGAN DONOR: YES"
        assert is_id_card_context(text) is True


class TestFilterMlMrnOnIdCards:
    """Tests for filter_ml_mrn_on_id_cards()."""

    def test_ml_mrn_filtered_on_id_card(self):
        """ML-detected MRN on ID card is filtered."""
        text = """
        DRIVER'S LICENSE
        DLN: D123456789
        CLASS: C
        """
        spans = [
            make_span("D123456789", start=30, entity_type="MRN", detector="phi_bert"),
        ]
        result = filter_ml_mrn_on_id_cards(spans, text)

        assert len(result) == 0

    def test_rule_based_mrn_kept_on_id_card(self):
        """Rule-based MRN detection on ID card is kept."""
        text = """
        DRIVER'S LICENSE
        DLN: D123456789
        MRN: 987654321
        CLASS: C
        """
        spans = [
            make_span("987654321", start=60, entity_type="MRN", detector="pattern"),
        ]
        result = filter_ml_mrn_on_id_cards(spans, text)

        # Pattern detector kept
        assert len(result) == 1

    def test_non_id_card_context_unchanged(self):
        """MRN on non-ID-card text is kept."""
        text = "Patient MRN: 123456789"
        spans = [
            make_span("123456789", start=13, entity_type="MRN", detector="phi_bert"),
        ]
        result = filter_ml_mrn_on_id_cards(spans, text)

        assert len(result) == 1

    def test_pii_bert_also_filtered(self):
        """pii_bert detector is also filtered on ID cards."""
        text = "DRIVER'S LICENSE CLASS: C DLN: 123"
        spans = [
            make_span("123", start=31, entity_type="MRN", detector="pii_bert"),
        ]
        result = filter_ml_mrn_on_id_cards(spans, text)

        assert len(result) == 0

    def test_non_mrn_types_kept(self):
        """Non-MRN types are kept even on ID cards."""
        text = "DRIVER'S LICENSE CLASS: C NAME: JOHN"
        spans = [
            make_span("JOHN", start=32, entity_type="NAME", detector="phi_bert"),
        ]
        result = filter_ml_mrn_on_id_cards(spans, text)

        assert len(result) == 1


class TestIsTrackingNumber:
    """Tests for is_tracking_number()."""

    def test_usps_tracking_with_context(self):
        """USPS tracking number with carrier context is detected."""
        span_text = "9400111899223456789012"
        context = "USPS Tracking: "
        assert is_tracking_number(span_text, context) is True

    def test_fedex_tracking_with_context(self):
        """FedEx tracking number with carrier context is detected."""
        span_text = "123456789012"
        context = "FedEx: "
        assert is_tracking_number(span_text, context) is True

    def test_ups_1z_format(self):
        """UPS 1Z tracking format with context is detected."""
        span_text = "1Z999AA10123456784"
        context = "UPS tracking number: "
        assert is_tracking_number(span_text, context) is True

    def test_tracking_number_without_context(self):
        """Tracking number pattern without carrier context is not detected."""
        span_text = "9400111899223456789012"
        context = "The number is: "  # No carrier keywords
        assert is_tracking_number(span_text, context) is False

    def test_context_keywords_detected(self):
        """Various tracking context keywords are detected."""
        span_text = "123456789012"
        contexts = [
            "tracking: ",
            "shipment: ",
            "package: ",
            "delivery: ",
            "Track your package: ",
        ]
        for context in contexts:
            assert is_tracking_number(span_text, context) is True, f"Failed for context: {context}"

    def test_spaces_and_dashes_stripped(self):
        """Spaces and dashes in tracking numbers are handled."""
        span_text = "9400 1118 9922 3456 7890 12"
        context = "USPS: "
        assert is_tracking_number(span_text, context) is True

    def test_short_number_not_tracking(self):
        """Short numbers don't match tracking patterns."""
        span_text = "12345"
        context = "USPS: "
        assert is_tracking_number(span_text, context) is False


class TestFilterTrackingNumbers:
    """Tests for filter_tracking_numbers()."""

    def test_ml_mrn_filtered_when_tracking(self):
        """ML-detected MRN that looks like tracking number is filtered."""
        text = "Your USPS tracking: 9400111899223456789012 delivered"
        spans = [
            make_span("9400111899223456789012", start=20, entity_type="MRN", detector="phi_bert"),
        ]
        result = filter_tracking_numbers(spans, text)

        assert len(result) == 0

    def test_carrier_name_prefix_filtered(self):
        """Carrier name detected as MRN is filtered."""
        text = "Ship via USPS: 12345"
        spans = [
            make_span("USPS", start=9, entity_type="MRN", detector="phi_bert"),
        ]
        result = filter_tracking_numbers(spans, text)

        assert len(result) == 0

    def test_non_ml_mrn_kept(self):
        """Non-ML MRN detections are kept."""
        text = "USPS tracking: 9400111899223456789012"
        spans = [
            make_span("9400111899223456789012", start=15, entity_type="MRN", detector="pattern"),
        ]
        result = filter_tracking_numbers(spans, text)

        # Pattern detector kept
        assert len(result) == 1

    def test_mrn_without_tracking_context_kept(self):
        """MRN without tracking context is kept."""
        text = "Patient MRN: 9400111899223456789012"
        spans = [
            make_span("9400111899223456789012", start=13, entity_type="MRN", detector="phi_bert"),
        ]
        result = filter_tracking_numbers(spans, text)

        # No tracking context, kept
        assert len(result) == 1

    def test_onnx_detectors_filtered(self):
        """ONNX variants of ML detectors are also filtered."""
        text = "FedEx: 123456789012"
        spans = [
            make_span("123456789012", start=7, entity_type="MRN", detector="phi_bert_onnx"),
        ]
        result = filter_tracking_numbers(spans, text)

        assert len(result) == 0

    def test_non_mrn_types_kept(self):
        """Non-MRN types near tracking numbers are kept."""
        text = "USPS tracking: 9400111899223456789012 for John Smith"
        spans = [
            make_span("9400111899223456789012", start=15, entity_type="MRN", detector="phi_bert"),
            make_span("John Smith", start=42, entity_type="NAME", detector="phi_bert"),
        ]
        result = filter_tracking_numbers(spans, text)

        # MRN filtered, NAME kept
        assert len(result) == 1
        assert result[0].entity_type == "NAME"


class TestIsValidHealthcareFacility:
    """Tests for is_valid_healthcare_facility()."""

    def test_hospital_keyword_valid(self):
        """Text containing 'hospital' is valid."""
        assert is_valid_healthcare_facility("St. Mary Hospital") is True
        assert is_valid_healthcare_facility("Regional Medical Hospital") is True

    def test_clinic_keyword_valid(self):
        """Text containing 'clinic' is valid."""
        assert is_valid_healthcare_facility("Downtown Health Clinic") is True

    def test_medical_keyword_valid(self):
        """Text containing 'medical' is valid."""
        assert is_valid_healthcare_facility("ABC Medical Center") is True

    def test_known_health_system_valid(self):
        """Known health systems are valid."""
        known_systems = [
            "Kaiser Permanente",
            "Mayo Clinic",
            "Cleveland Clinic",
            "Johns Hopkins",
            "Mass General",
        ]
        for system in known_systems:
            assert is_valid_healthcare_facility(system) is True, f"{system} should be valid"

    def test_generic_company_invalid(self):
        """Generic company names are not valid."""
        invalid_names = [
            "Acme Corporation",
            "Tech Solutions Inc",
            "Global Industries",
            "ABC Company",
        ]
        for name in invalid_names:
            assert is_valid_healthcare_facility(name) is False, f"{name} should be invalid"

    def test_case_insensitive(self):
        """Keyword matching is case-insensitive."""
        assert is_valid_healthcare_facility("REGIONAL HOSPITAL") is True
        assert is_valid_healthcare_facility("kaiser permanente") is True

    def test_religious_hospital_names(self):
        """Religious hospital name patterns are valid."""
        religious_names = [
            "St. Mary's Hospital",
            "Sacred Heart Medical Center",
            "Baptist Hospital",
            "Methodist Healthcare",
            "Providence Health",
            "Mercy Hospital",
        ]
        for name in religious_names:
            assert is_valid_healthcare_facility(name) is True, f"{name} should be valid"

    def test_specialty_facilities(self):
        """Specialty facility types are valid."""
        specialty_names = [
            "Cancer Treatment Center",
            "Cardiac Care Institute",
            "Orthopedic Specialists",
            "Pediatric Hospital",
            "Rehabilitation Center",
        ]
        for name in specialty_names:
            assert is_valid_healthcare_facility(name) is True, f"{name} should be valid"

    def test_partial_matches_work(self):
        """Keywords can appear anywhere in the name."""
        assert is_valid_healthcare_facility("The Great Hospital of Springfield") is True
        assert is_valid_healthcare_facility("Springfield Community Health Center") is True


class TestHealthcareFacilityPerformance:
    """Performance tests for healthcare facility validation."""

    def test_many_validations_fast(self):
        """Many validations complete quickly (Aho-Corasick optimization)."""
        import time

        names = [
            "St. Mary Hospital",
            "Generic Company Inc",
            "Kaiser Permanente",
            "Tech Solutions",
            "Mayo Clinic",
        ] * 1000  # 5000 validations

        start = time.time()
        for name in names:
            is_valid_healthcare_facility(name)
        elapsed = time.time() - start

        # Should complete in well under 1 second with Aho-Corasick
        assert elapsed < 1.0, f"Validation too slow: {elapsed:.2f}s for 5000 calls"

    def test_long_text_handled(self):
        """Long facility names are handled correctly."""
        long_name = "The Very Long Named Regional Medical Center and Hospital of Greater Springfield Area"
        assert is_valid_healthcare_facility(long_name) is True


class TestContextFilterIntegration:
    """Integration tests for context filtering in merge_spans."""

    def test_id_card_mrn_filtered_in_merge(self):
        """ID card MRN filtering works through merge_spans."""
        from scrubiq.pipeline.merger import merge_spans

        text = """
        DRIVER'S LICENSE
        DLN: D123456789
        CLASS: C
        """
        spans = [
            make_span("D123456789", start=35, entity_type="MRN", detector="phi_bert"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)
        assert len(result) == 0

    def test_tracking_number_filtered_in_merge(self):
        """Tracking number filtering works through merge_spans."""
        from scrubiq.pipeline.merger import merge_spans

        text = "USPS: 9400111899223456789012"
        spans = [
            make_span("9400111899223456789012", start=6, entity_type="MRN", detector="phi_bert"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)
        assert len(result) == 0

    def test_invalid_facility_filtered_in_merge(self):
        """Invalid healthcare facility filtering works through merge_spans."""
        from scrubiq.pipeline.merger import merge_spans

        text = "Works at Acme Corporation"
        spans = [
            make_span("Acme Corporation", start=9, entity_type="FACILITY"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)
        assert len(result) == 0

    def test_valid_facility_kept_in_merge(self):
        """Valid healthcare facility is kept through merge_spans."""
        from scrubiq.pipeline.merger import merge_spans

        text = "Works at St. Mary Hospital"
        spans = [
            make_span("St. Mary Hospital", start=9, entity_type="FACILITY"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)
        assert len(result) == 1
        assert result[0].text == "St. Mary Hospital"
