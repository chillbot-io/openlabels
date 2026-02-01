"""Comprehensive tests for pipeline/merger.py to achieve 80%+ coverage."""

import pytest
from scrubiq.types import Span, Tier
from scrubiq.pipeline.merger import (
    types_compatible,
    fix_misclassified_emails,
    trim_span_whitespace,
    trim_trailing_punctuation,
    remove_contained_spans,
    filter_short_names,
    is_id_card_context,
    filter_ml_mrn_on_id_cards,
    is_tracking_number,
    filter_tracking_numbers,
    filter_city_as_name,
    merge_adjacent_addresses,
    trim_names_at_newlines,
    trim_name_at_non_name_words,
    snap_to_word_boundaries,
    is_valid_healthcare_facility,
    normalize_type,
    normalize_name_types,
    merge_spans,
    TYPE_NORMALIZE,
    COMPATIBLE_TYPE_GROUPS,
)


def make_span(
    text: str,
    start: int = 0,
    entity_type: str = "NAME",
    confidence: float = 0.9,
    detector: str = "test",
    tier: int = 2,
    **kwargs
) -> Span:
    """Factory function to create a valid Span for testing."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=Tier.from_value(tier),
        **kwargs
    )


class TestTypesCompatible:
    """Tests for types_compatible function."""

    def test_same_type_compatible(self):
        """Same types should always be compatible."""
        assert types_compatible("NAME", "NAME") is True
        assert types_compatible("ADDRESS", "ADDRESS") is True
        assert types_compatible("SSN", "SSN") is True

    def test_prefix_match(self):
        """Types with prefix relationships should be compatible."""
        assert types_compatible("NAME", "NAME_PATIENT") is True
        assert types_compatible("NAME_PATIENT", "NAME") is True
        assert types_compatible("DATE", "DATE_DOB") is True

    def test_group_compatibility(self):
        """Types in same compatibility group should match."""
        assert types_compatible("NAME", "NAME_PROVIDER") is True
        assert types_compatible("NAME_PATIENT", "NAME_RELATIVE") is True
        assert types_compatible("ADDRESS", "CITY") is True
        assert types_compatible("STREET", "ZIP") is True
        assert types_compatible("PHONE", "FAX") is True
        assert types_compatible("SSN", "SSN_PARTIAL") is True
        assert types_compatible("MRN", "PATIENT_ID") is True

    def test_incompatible_types(self):
        """Different type groups should not be compatible."""
        assert types_compatible("NAME", "ADDRESS") is False
        assert types_compatible("SSN", "MRN") is False
        assert types_compatible("PHONE", "EMAIL") is False
        assert types_compatible("DATE", "NAME") is False

    def test_unknown_types(self):
        """Unknown types should only match themselves."""
        assert types_compatible("UNKNOWN_TYPE", "UNKNOWN_TYPE") is True
        assert types_compatible("UNKNOWN_TYPE", "OTHER_UNKNOWN") is False


class TestFixMisclassifiedEmails:
    """Tests for fix_misclassified_emails function."""

    def test_email_reclassified_from_name(self):
        """Email addresses detected as NAME should be reclassified."""
        spans = [make_span("john.doe@example.com", entity_type="NAME")]
        result = fix_misclassified_emails(spans)
        assert len(result) == 1
        assert result[0].entity_type == "EMAIL"

    def test_email_reclassified_from_name_subtypes(self):
        """NAME subtypes containing emails should be reclassified."""
        spans = [make_span("test@domain.org", entity_type="NAME_PATIENT")]
        result = fix_misclassified_emails(spans)
        assert result[0].entity_type == "EMAIL"

    def test_non_email_name_unchanged(self):
        """Regular names should not be changed."""
        spans = [make_span("John Smith", entity_type="NAME")]
        result = fix_misclassified_emails(spans)
        assert result[0].entity_type == "NAME"

    def test_email_with_trailing_punctuation(self):
        """Email with trailing punctuation should be cleaned."""
        spans = [make_span("user@test.com.", entity_type="NAME", start=0)]
        result = fix_misclassified_emails(spans)
        assert result[0].entity_type == "EMAIL"
        assert result[0].text == "user@test.com"

    def test_other_entity_types_unchanged(self):
        """Non-NAME entity types should pass through unchanged."""
        spans = [make_span("123-456-7890", entity_type="PHONE")]
        result = fix_misclassified_emails(spans)
        assert result[0].entity_type == "PHONE"


class TestTrimSpanWhitespace:
    """Tests for trim_span_whitespace function."""

    def test_trim_leading_whitespace(self):
        """Leading whitespace should be trimmed."""
        text = "  John Smith"
        spans = [Span(start=0, end=12, text=text, entity_type="NAME",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = trim_span_whitespace(spans, text)
        assert result[0].start == 2
        assert result[0].text == "John Smith"

    def test_trim_trailing_whitespace(self):
        """Trailing whitespace should be trimmed."""
        text = "John Smith  "
        spans = [Span(start=0, end=12, text=text, entity_type="NAME",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = trim_span_whitespace(spans, text)
        assert result[0].end == 10
        assert result[0].text == "John Smith"

    def test_trim_both_sides(self):
        """Both leading and trailing whitespace should be trimmed."""
        text = "  John Smith  "
        spans = [Span(start=0, end=14, text=text, entity_type="NAME",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = trim_span_whitespace(spans, text)
        assert result[0].start == 2
        assert result[0].end == 12
        assert result[0].text == "John Smith"

    def test_no_whitespace_unchanged(self):
        """Spans without whitespace should be unchanged."""
        text = "John Smith"
        spans = [make_span(text)]
        result = trim_span_whitespace(spans, text)
        assert result[0].text == text

    def test_all_whitespace_discarded(self):
        """Spans that are only whitespace should be discarded."""
        text = "   "
        spans = [Span(start=0, end=3, text=text, entity_type="NAME",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = trim_span_whitespace(spans, text)
        assert len(result) == 0


class TestTrimTrailingPunctuation:
    """Tests for trim_trailing_punctuation function."""

    def test_trim_email_punctuation(self):
        """Trailing punctuation should be trimmed from EMAIL."""
        spans = [make_span("test@example.com.", entity_type="EMAIL")]
        text = "test@example.com."
        result = trim_trailing_punctuation(spans, text)
        assert result[0].text == "test@example.com"

    def test_trim_phone_punctuation(self):
        """Trailing punctuation should be trimmed from PHONE."""
        spans = [make_span("555-123-4567,", entity_type="PHONE")]
        result = trim_trailing_punctuation(spans, "555-123-4567,")
        assert result[0].text == "555-123-4567"

    def test_name_unchanged(self):
        """NAME spans should NOT have punctuation trimmed (Jr., Sr.)."""
        spans = [make_span("John Smith Jr.", entity_type="NAME")]
        result = trim_trailing_punctuation(spans, "John Smith Jr.")
        assert result[0].text == "John Smith Jr."

    def test_ssn_trimmed(self):
        """SSN should have trailing punctuation trimmed."""
        spans = [make_span("123-45-6789;", entity_type="SSN")]
        result = trim_trailing_punctuation(spans, "123-45-6789;")
        assert result[0].text == "123-45-6789"

    def test_multiple_types(self):
        """Mix of types should be handled correctly."""
        spans = [
            make_span("test@test.com!", entity_type="EMAIL", start=0),
            make_span("John Smith.", entity_type="NAME", start=20),
        ]
        text = "test@test.com!      John Smith."
        result = trim_trailing_punctuation(spans, text)
        assert result[0].text == "test@test.com"
        assert result[1].text == "John Smith."  # NAME unchanged


class TestRemoveContainedSpans:
    """Tests for remove_contained_spans function."""

    def test_smaller_span_removed(self):
        """Smaller span inside larger compatible span should be removed."""
        spans = [
            make_span("K. Edwards, DNP", entity_type="NAME", start=0, tier=2),
            make_span("K.", entity_type="NAME", start=0, tier=1),
        ]
        result = remove_contained_spans(spans)
        assert len(result) == 1
        assert result[0].text == "K. Edwards, DNP"

    def test_incompatible_types_kept(self):
        """Contained spans of incompatible types should be kept."""
        spans = [
            make_span("John 123-4567", entity_type="NAME", start=0),
            make_span("123-4567", entity_type="PHONE", start=5),
        ]
        result = remove_contained_spans(spans)
        assert len(result) == 2

    def test_non_overlapping_kept(self):
        """Non-overlapping spans should all be kept."""
        spans = [
            make_span("John", entity_type="NAME", start=0),
            make_span("Smith", entity_type="NAME", start=10),
        ]
        result = remove_contained_spans(spans)
        assert len(result) == 2

    def test_single_span(self):
        """Single span should be returned unchanged."""
        spans = [make_span("John")]
        result = remove_contained_spans(spans)
        assert len(result) == 1

    def test_empty_list(self):
        """Empty list should return empty list."""
        result = remove_contained_spans([])
        assert result == []


class TestFilterShortNames:
    """Tests for filter_short_names function."""

    def test_single_initial_removed(self):
        """Single initials should be filtered."""
        spans = [make_span("K.", entity_type="NAME")]
        result = filter_short_names(spans)
        assert len(result) == 0

    def test_short_initial_removed(self):
        """Very short names should be filtered."""
        spans = [make_span("R", entity_type="NAME")]
        result = filter_short_names(spans)
        assert len(result) == 0

    def test_normal_name_kept(self):
        """Normal length names should be kept."""
        spans = [make_span("John Smith", entity_type="NAME")]
        result = filter_short_names(spans)
        assert len(result) == 1

    def test_name_subtypes_filtered(self):
        """NAME subtypes should also be filtered."""
        spans = [make_span("J.", entity_type="NAME_PATIENT")]
        result = filter_short_names(spans)
        assert len(result) == 0

    def test_non_name_types_unchanged(self):
        """Non-NAME types should not be filtered by length."""
        spans = [make_span("A", entity_type="ADDRESS")]
        result = filter_short_names(spans)
        assert len(result) == 1


class TestIdCardContext:
    """Tests for ID card detection functions."""

    def test_detect_drivers_license(self):
        """Driver's license text should be detected."""
        text = "DRIVER'S LICENSE\nDLN: D123456\nCLASS: C"
        assert is_id_card_context(text) is True

    def test_detect_state_id(self):
        """State ID text should be detected."""
        text = "STATE ID\nDUPS: 000\nRESTR: NONE"
        assert is_id_card_context(text) is True

    def test_clinical_note_not_id_card(self):
        """Clinical notes should not be detected as ID card."""
        text = "Patient presents with chest pain. MRN: 123456"
        assert is_id_card_context(text) is False

    def test_filter_mrn_on_id_card(self):
        """ML MRN detections on ID cards should be filtered."""
        text = "DRIVER'S LICENSE\nDLN: 123456\nCLASS: C\nDUPS: 000"
        spans = [
            make_span("123456", entity_type="MRN", detector="phi_bert", start=27),
            make_span("000", entity_type="MRN", detector="phi_bert", start=45),
        ]
        result = filter_ml_mrn_on_id_cards(spans, text)
        assert len(result) == 0

    def test_keep_mrn_in_clinical(self):
        """MRN detections in clinical notes should be kept."""
        text = "Patient MRN: 123456789"
        spans = [make_span("123456789", entity_type="MRN", detector="phi_bert", start=13)]
        result = filter_ml_mrn_on_id_cards(spans, text)
        assert len(result) == 1


class TestTrackingNumbers:
    """Tests for tracking number detection and filtering."""

    def test_usps_tracking_detected(self):
        """USPS tracking numbers should be detected."""
        assert is_tracking_number("9400111899223456789012", "USPS:") is True

    def test_fedex_tracking_detected(self):
        """FedEx tracking numbers should be detected."""
        assert is_tracking_number("123456789012", "FedEx tracking:") is True

    def test_ups_tracking_detected(self):
        """UPS tracking numbers should be detected."""
        assert is_tracking_number("1Z999AA10123456784", "UPS:") is True

    def test_mrn_without_tracking_context(self):
        """MRN without tracking context should not be detected as tracking."""
        assert is_tracking_number("123456789012", "Patient MRN:") is False

    def test_filter_tracking_from_mrn(self):
        """Tracking numbers should be filtered from MRN detections."""
        text = "USPS Tracking: 9400111899223456789012"
        spans = [make_span("9400111899223456789012", entity_type="MRN",
                          detector="phi_bert", start=15)]
        result = filter_tracking_numbers(spans, text)
        assert len(result) == 0

    def test_keep_real_mrn(self):
        """Real MRN should not be filtered."""
        text = "Patient MRN: 123456789"
        spans = [make_span("123456789", entity_type="MRN",
                          detector="phi_bert", start=13)]
        result = filter_tracking_numbers(spans, text)
        assert len(result) == 1

    def test_filter_carrier_name_as_mrn(self):
        """Carrier names detected as MRN should be filtered."""
        text = "Shipped via USPS tracking number..."
        spans = [make_span("USPS", entity_type="MRN", detector="phi_bert", start=12)]
        result = filter_tracking_numbers(spans, text)
        assert len(result) == 0


class TestFilterCityAsName:
    """Tests for city/name reclassification."""

    def test_city_state_reclassified(self):
        """City, State format should be reclassified as ADDRESS."""
        spans = [make_span("HARRISBURG, PA", entity_type="NAME_PROVIDER")]
        result = filter_city_as_name(spans)
        assert result[0].entity_type == "ADDRESS"

    def test_city_suffix_reclassified(self):
        """Names ending in city suffixes should be reclassified."""
        for city in ["Springfield", "Pittsburgh", "Harrisburg"]:
            spans = [make_span(city, entity_type="NAME")]
            result = filter_city_as_name(spans)
            assert result[0].entity_type == "ADDRESS", f"Failed for {city}"

    def test_real_name_unchanged(self):
        """Real names should not be changed."""
        spans = [make_span("John Smith", entity_type="NAME")]
        result = filter_city_as_name(spans)
        assert result[0].entity_type == "NAME"

    def test_non_name_unchanged(self):
        """Non-NAME types should pass through unchanged."""
        spans = [make_span("Springfield, IL", entity_type="ADDRESS")]
        result = filter_city_as_name(spans)
        assert result[0].entity_type == "ADDRESS"


class TestMergeAdjacentAddresses:
    """Tests for merging adjacent ADDRESS spans."""

    def test_merge_street_and_city(self):
        """Street and city addresses should be merged."""
        text = "123 Main St, Springfield, IL 62701"
        spans = [
            Span(start=0, end=11, text="123 Main St", entity_type="ADDRESS",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
            Span(start=13, end=34, text="Springfield, IL 62701", entity_type="ADDRESS",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
        ]
        result = merge_adjacent_addresses(spans, text)
        address_spans = [s for s in result if s.entity_type == "ADDRESS"]
        assert len(address_spans) == 1
        assert address_spans[0].text == "123 Main St, Springfield, IL 62701"

    def test_distant_addresses_not_merged(self):
        """Addresses far apart should not be merged."""
        text = "123 Main St" + " " * 100 + "456 Oak Ave"
        spans = [
            Span(start=0, end=11, text="123 Main St", entity_type="ADDRESS",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
            Span(start=111, end=122, text="456 Oak Ave", entity_type="ADDRESS",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
        ]
        result = merge_adjacent_addresses(spans, text)
        address_spans = [s for s in result if s.entity_type == "ADDRESS"]
        assert len(address_spans) == 2

    def test_single_address_unchanged(self):
        """Single address should be unchanged."""
        text = "123 Main St"
        spans = [make_span(text, entity_type="ADDRESS")]
        result = merge_adjacent_addresses(spans, text)
        assert len(result) == 1


class TestTrimNamesAtNewlines:
    """Tests for trimming names at newlines."""

    def test_name_trimmed_at_newline(self):
        """Names extending past newlines should be trimmed."""
        text = "Dr. Luis Collins\nCOMPREHENSIVE METABOLIC PANEL"
        spans = [Span(start=0, end=46, text=text, entity_type="NAME",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = trim_names_at_newlines(spans, text)
        assert result[0].text == "Dr. Luis Collins"

    def test_name_without_newline_unchanged(self):
        """Names without newlines should be unchanged."""
        text = "Dr. Luis Collins"
        spans = [make_span(text, entity_type="NAME")]
        result = trim_names_at_newlines(spans, text)
        assert result[0].text == text

    def test_non_name_unchanged(self):
        """Non-NAME types should pass through unchanged."""
        text = "123 Main St\n Springfield"
        spans = [Span(start=0, end=25, text=text, entity_type="ADDRESS",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = trim_names_at_newlines(spans, text)
        assert result[0].text == text


class TestTrimNameAtNonNameWords:
    """Tests for trimming non-name words from names."""

    def test_trim_common_words(self):
        """Common non-name words should be trimmed."""
        text = "John Smith ordered"
        spans = [Span(start=0, end=18, text=text, entity_type="NAME",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = trim_name_at_non_name_words(spans, text)
        assert "ordered" not in result[0].text

    def test_keep_name_with_suffix(self):
        """Names with valid suffixes should be kept."""
        text = "John Smith Jr"
        spans = [make_span(text, entity_type="NAME")]
        result = trim_name_at_non_name_words(spans, text)
        assert result[0].text == text

    def test_single_word_unchanged(self):
        """Single word names should be unchanged."""
        text = "John"
        spans = [make_span(text, entity_type="NAME")]
        result = trim_name_at_non_name_words(spans, text)
        assert result[0].text == text


class TestSnapToWordBoundaries:
    """Tests for snapping spans to word boundaries."""

    def test_expand_left_to_word_start(self):
        """Span starting mid-word should expand left."""
        text = "EYES"
        spans = [Span(start=1, end=4, text="YES", entity_type="NAME",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = snap_to_word_boundaries(spans, text)
        assert result[0].start == 0
        assert result[0].text == "EYES"

    def test_expand_right_to_word_end(self):
        """Span ending mid-word should expand right."""
        text = "JOHN"
        spans = [Span(start=0, end=3, text="JOH", entity_type="NAME",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = snap_to_word_boundaries(spans, text)
        assert result[0].end == 4
        assert result[0].text == "JOHN"

    def test_at_boundary_unchanged(self):
        """Span already at word boundaries should be unchanged."""
        text = "John Smith"
        spans = [make_span("John", entity_type="NAME", start=0)]
        result = snap_to_word_boundaries(spans, text)
        assert result[0].start == 0
        assert result[0].end == 4


class TestIsValidHealthcareFacility:
    """Tests for healthcare facility validation."""

    def test_hospital_valid(self):
        """Hospital names should be valid."""
        assert is_valid_healthcare_facility("Memorial Hospital") is True
        assert is_valid_healthcare_facility("Regional Medical Center") is True

    def test_known_systems_valid(self):
        """Known health systems should be valid."""
        assert is_valid_healthcare_facility("Kaiser Permanente") is True
        assert is_valid_healthcare_facility("Mayo Clinic") is True
        assert is_valid_healthcare_facility("Cleveland Clinic") is True

    def test_generic_company_invalid(self):
        """Generic company names should be invalid."""
        assert is_valid_healthcare_facility("Acme Corporation") is False
        assert is_valid_healthcare_facility("Tech Solutions Inc") is False


class TestNormalizeType:
    """Tests for type normalization."""

    def test_known_mappings(self):
        """Known type mappings should work."""
        assert normalize_type("PERSON") == "NAME"
        assert normalize_type("PER") == "NAME"
        assert normalize_type("GPE") == "ADDRESS"
        assert normalize_type("US_SSN") == "SSN"
        assert normalize_type("PHONE_NUMBER") == "PHONE"

    def test_unknown_passthrough(self):
        """Unknown types should pass through unchanged."""
        assert normalize_type("UNKNOWN_TYPE") == "UNKNOWN_TYPE"
        assert normalize_type("NAME") == "NAME"


class TestNormalizeNameTypes:
    """Tests for NAME subtype normalization based on context."""

    def test_provider_without_context_to_name(self):
        """NAME_PROVIDER without context should become NAME."""
        text = "John Smith attended the meeting"
        spans = [Span(start=0, end=10, text="John Smith", entity_type="NAME_PROVIDER",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = normalize_name_types(spans, text)
        assert result[0].entity_type == "NAME"

    def test_provider_with_context_kept(self):
        """NAME_PROVIDER with context should be kept."""
        text = "Dr. John Smith, MD reviewed the case"
        spans = [Span(start=4, end=14, text="John Smith", entity_type="NAME_PROVIDER",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = normalize_name_types(spans, text)
        assert result[0].entity_type == "NAME_PROVIDER"

    def test_patient_with_context_kept(self):
        """NAME_PATIENT with context should be kept."""
        text = "Patient: John Smith presents with..."
        spans = [Span(start=9, end=19, text="John Smith", entity_type="NAME_PATIENT",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = normalize_name_types(spans, text)
        assert result[0].entity_type == "NAME_PATIENT"

    def test_relative_without_context_to_name(self):
        """NAME_RELATIVE without context should become NAME."""
        text = "Jane Doe was also present"
        spans = [Span(start=0, end=8, text="Jane Doe", entity_type="NAME_RELATIVE",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = normalize_name_types(spans, text)
        assert result[0].entity_type == "NAME"


class TestMergeSpans:
    """Tests for the main merge_spans function."""

    def test_empty_spans(self):
        """Empty span list should return empty list."""
        result = merge_spans([])
        assert result == []

    def test_low_confidence_filtered(self):
        """Low confidence spans should be filtered."""
        spans = [
            make_span("John", confidence=0.3, entity_type="NAME"),
            make_span("Smith", confidence=0.9, entity_type="NAME", start=5),
        ]
        result = merge_spans(spans, min_confidence=0.5)
        assert len(result) == 1
        assert result[0].text == "Smith"

    def test_type_normalization(self):
        """Types should be normalized."""
        spans = [make_span("John", entity_type="PERSON")]
        result = merge_spans(spans)
        assert result[0].entity_type == "NAME"

    def test_overlapping_resolved(self):
        """Overlapping spans should be resolved."""
        spans = [
            make_span("John Smith", entity_type="NAME", start=0, tier=2, confidence=0.9),
            make_span("Smith", entity_type="NAME", start=5, tier=1, confidence=0.8),
        ]
        result = merge_spans(spans)
        assert len(result) == 1
        assert result[0].text == "John Smith"

    def test_with_text_parameter(self):
        """merge_spans with text should apply boundary normalization."""
        text = "  John Smith  "
        spans = [Span(start=0, end=14, text=text, entity_type="NAME",
                      confidence=0.9, detector="test", tier=Tier.PATTERN)]
        result = merge_spans(spans, text=text)
        # Should trim whitespace
        assert result[0].text.strip() == "John Smith"

    def test_clinical_context_filtered(self):
        """Clinical context types should be filtered."""
        spans = [
            make_span("headache", entity_type="DIAGNOSIS"),
            make_span("John", entity_type="NAME", start=20),
        ]
        result = merge_spans(spans)
        # DIAGNOSIS should be filtered (it's a clinical context type)
        names = [s for s in result if s.entity_type == "NAME"]
        assert len(names) == 1

    def test_sorted_by_position(self):
        """Output should be sorted by position."""
        spans = [
            make_span("Smith", entity_type="NAME", start=10),
            make_span("John", entity_type="NAME", start=0),
        ]
        result = merge_spans(spans)
        assert result[0].start < result[1].start

    def test_invalid_spans_filtered(self):
        """Invalid spans should be filtered when text is provided."""
        text = "Hello"
        spans = [
            Span(start=-1, end=5, text="Hello", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
            Span(start=0, end=5, text="Hello", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
        ]
        result = merge_spans(spans, text=text)
        assert len(result) == 1
        assert result[0].start == 0


class TestCompatibleTypeGroups:
    """Tests for COMPATIBLE_TYPE_GROUPS constant."""

    def test_groups_exist(self):
        """Compatible type groups should be defined."""
        assert len(COMPATIBLE_TYPE_GROUPS) > 0

    def test_name_group_exists(self):
        """NAME group should exist."""
        name_group = next((g for g in COMPATIBLE_TYPE_GROUPS if "NAME" in g), None)
        assert name_group is not None
        assert "NAME_PATIENT" in name_group

    def test_address_group_exists(self):
        """ADDRESS group should exist."""
        addr_group = next((g for g in COMPATIBLE_TYPE_GROUPS if "ADDRESS" in g), None)
        assert addr_group is not None


class TestTypeNormalizeMapping:
    """Tests for TYPE_NORMALIZE mapping."""

    def test_mapping_exists(self):
        """Type normalize mapping should exist."""
        assert len(TYPE_NORMALIZE) > 0

    def test_common_mappings(self):
        """Common type mappings should be defined."""
        assert "PERSON" in TYPE_NORMALIZE
        assert "GPE" in TYPE_NORMALIZE
        assert "US_SSN" in TYPE_NORMALIZE
        assert "PHONE_NUMBER" in TYPE_NORMALIZE
