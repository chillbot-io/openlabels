"""Tests for detectors/structured.py - structured document extraction.

Tests cover:
- Prose detection (looks_like_prose)
- Field value cleaning (clean_field_value)
- OCR post-processing (post_process_ocr, OCR_FIXES)
- Character mapping (map_processed_to_original, map_span_to_original)
- Label detection (detect_labels, normalize_label)
- Value extraction (extract_value, validate_value)
- Unlabeled address detection
- Main extraction pipeline (extract_structured_phi)
"""

import pytest

from scrubiq.types import Span, Tier


# =============================================================================
# PROSE DETECTION TESTS
# =============================================================================

class TestLooksLikeProse:
    """Tests for looks_like_prose function."""

    def test_empty_string_not_prose(self):
        """Empty or very short strings are not prose."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("") is False
        assert looks_like_prose("AB") is False

    def test_long_value_is_prose(self):
        """Values longer than 60 characters are considered prose."""
        from scrubiq.detectors.structured import looks_like_prose

        long_text = "This is a very long sentence that goes on and on and describes something in great detail."
        assert looks_like_prose(long_text) is True

    def test_sentence_structure_is_prose(self):
        """Text with sentence structure (period + capital) is prose."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("First sentence. Second one.") is True

    def test_pipe_delimiter_is_prose(self):
        """Text with pipe delimiter is prose (field separator)."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("1979-11-07 | Age: 70") is True

    def test_pronouns_indicate_prose(self):
        """Text with pronouns indicates prose."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("He slept well today") is True
        assert looks_like_prose("She went home") is True
        assert looks_like_prose("They are here") is True

    def test_auxiliary_verbs_indicate_prose(self):
        """Text with auxiliary verbs indicates prose."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("Patient was seen today") is True
        assert looks_like_prose("He has been here") is True
        assert looks_like_prose("Results are normal") is True

    def test_clinical_verbs_indicate_prose(self):
        """Text with clinical prose verbs indicates prose."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("Patient reports pain") is True
        assert looks_like_prose("He denies symptoms") is True
        assert looks_like_prose("She sleeps poorly") is True

    def test_time_references_indicate_prose(self):
        """Text with time references indicates prose."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("Called today about it") is True
        assert looks_like_prose("Seen yesterday") is True

    def test_preposition_phrases_indicate_prose(self):
        """Text with 'at the', 'in the' etc. indicates prose."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("Met at the clinic") is True
        assert looks_like_prose("Seen in the office") is True

    def test_question_words_indicate_prose(self):
        """Text with question words indicates prose."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("Asked what happened") is True
        assert looks_like_prose("Unsure when started") is True

    def test_lowercase_flow_indicates_prose(self):
        """Multiple lowercase words indicate prose flow."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("John went to store") is True
        assert looks_like_prose("Called about the test") is True

    def test_prose_endings_indicate_prose(self):
        """Common prose pattern endings indicate prose."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("Feeling better well") is True
        assert looks_like_prose("Doing very much") is True

    def test_numbers_in_prose_context(self):
        """Numbers in prose context ('in 2 weeks') indicate prose."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("Follow up in 2 weeks") is True
        assert looks_like_prose("Return for 3 days") is True

    def test_preposition_start_indicates_prose(self):
        """Text starting with preposition indicates prose."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("at the hospital") is True
        assert looks_like_prose("to the clinic") is True
        assert looks_like_prose("in the office") is True

    def test_clinical_symptoms_indicate_prose(self):
        """Clinical symptom words indicate prose."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("Complains of weakness") is True
        assert looks_like_prose("Having palpitations") is True
        assert looks_like_prose("Reports chest pain") is True

    def test_valid_names_not_prose(self):
        """Valid field values are not prose."""
        from scrubiq.detectors.structured import looks_like_prose

        assert looks_like_prose("John Smith") is False
        assert looks_like_prose("123-45-6789") is False
        assert looks_like_prose("01/15/1980") is False
        assert looks_like_prose("Dr. Sarah Johnson") is False


# =============================================================================
# CLEAN FIELD VALUE TESTS
# =============================================================================

class TestCleanFieldValue:
    """Tests for clean_field_value function."""

    def test_removes_trailing_pipe(self):
        """Removes pipe and everything after it."""
        from scrubiq.detectors.structured import clean_field_value

        assert clean_field_value("1979-11-07 | Age: 70", "DATE") == "1979-11-07"

    def test_removes_trailing_colon(self):
        """Removes trailing colons."""
        from scrubiq.detectors.structured import clean_field_value

        assert clean_field_value("Value:", "NAME") == "Value"

    def test_removes_age_suffix_from_dates(self):
        """Removes 'Age: XX' suffix from dates."""
        from scrubiq.detectors.structured import clean_field_value

        assert clean_field_value("01/15/1980 Age: 45", "DATE") == "01/15/1980"
        assert clean_field_value("01/15/1980 | Age: 45", "DATE_DOB") == "01/15/1980"

    def test_removes_field_labels_from_dates(self):
        """Removes trailing field labels from dates."""
        from scrubiq.detectors.structured import clean_field_value

        assert clean_field_value("01/15/1980 MRN:", "DATE") == "01/15/1980"
        assert clean_field_value("01/15/1980 SSN:", "DATE_DOB") == "01/15/1980"

    def test_removes_dob_suffix_from_names(self):
        """Removes DOB/MRN suffix from names."""
        from scrubiq.detectors.structured import clean_field_value

        assert clean_field_value("John Smith DOB:", "NAME") == "John Smith"
        assert clean_field_value("Dr. Johnson MRN:", "NAME_PROVIDER") == "Dr. Johnson"

    def test_removes_trailing_parenthetical(self):
        """Removes trailing incomplete parenthetical from names."""
        from scrubiq.detectors.structured import clean_field_value

        assert clean_field_value("John Smith (", "NAME") == "John Smith"

    def test_strips_whitespace(self):
        """Strips leading/trailing whitespace."""
        from scrubiq.detectors.structured import clean_field_value

        assert clean_field_value("  John Smith  ", "NAME") == "John Smith"


# =============================================================================
# OCR POST-PROCESSING TESTS
# =============================================================================

class TestPostProcessOCR:
    """Tests for post_process_ocr function."""

    def test_normalizes_dln_format(self):
        """Normalizes driver's license number format."""
        from scrubiq.detectors.structured import post_process_ocr

        processed, char_map = post_process_ocr("4dDLN:99999999")
        assert "DLN:" in processed

    def test_splits_concatenated_addresses(self):
        """Splits concatenated street addresses."""
        from scrubiq.detectors.structured import post_process_ocr

        processed, char_map = post_process_ocr("8123MAINSTREET")
        assert "8123" in processed
        assert "MAIN" in processed

    def test_splits_city_state_zip(self):
        """Splits CITY,STZIP format."""
        from scrubiq.detectors.structured import post_process_ocr

        processed, char_map = post_process_ocr("HARRISBURG,PA17101")
        assert "HARRISBURG" in processed
        assert "PA" in processed
        assert "17101" in processed

    def test_splits_field_codes(self):
        """Splits field codes like 4aISS:."""
        from scrubiq.detectors.structured import post_process_ocr

        processed, char_map = post_process_ocr("4aISS: 01/01/2020")
        assert "4a" in processed
        assert "ISS:" in processed

    def test_fixes_zero_for_o_in_dob(self):
        """Fixes common OCR D0B -> DOB."""
        from scrubiq.detectors.structured import post_process_ocr

        processed, char_map = post_process_ocr("D0B: 01/15/1980")
        assert "DOB:" in processed

    def test_splits_document_discriminator(self):
        """Splits document discriminator (5DD:123)."""
        from scrubiq.detectors.structured import post_process_ocr

        processed, char_map = post_process_ocr("5DD:123456")
        assert "DD:" in processed

    def test_splits_field_code_from_name(self):
        """Splits field code from name (2ANDREW -> 2 ANDREW)."""
        from scrubiq.detectors.structured import post_process_ocr

        processed, char_map = post_process_ocr("2ANDREW SAMPLE")
        # Should have space between 2 and ANDREW
        assert " ANDREW" in processed or "2 ANDREW" in processed

    def test_returns_char_map(self):
        """Returns character map for position tracking."""
        from scrubiq.detectors.structured import post_process_ocr

        processed, char_map = post_process_ocr("Hello World")
        assert isinstance(char_map, list)
        assert len(char_map) == len(processed)

    def test_unchanged_text_identity_map(self):
        """Unchanged text has identity character map."""
        from scrubiq.detectors.structured import post_process_ocr

        text = "No changes needed here"
        processed, char_map = post_process_ocr(text)

        if processed == text:
            assert char_map == list(range(len(text)))


# =============================================================================
# CHARACTER MAPPING TESTS
# =============================================================================

class TestCharacterMapping:
    """Tests for character position mapping functions."""

    def test_map_processed_to_original_identity(self):
        """Identity mapping for unchanged text."""
        from scrubiq.detectors.structured import map_processed_to_original

        char_map = list(range(10))
        assert map_processed_to_original(5, char_map) == 5

    def test_map_processed_to_original_empty_map(self):
        """Empty char_map returns position unchanged."""
        from scrubiq.detectors.structured import map_processed_to_original

        assert map_processed_to_original(5, []) == 5

    def test_map_processed_to_original_negative(self):
        """Negative position returns 0 or raises."""
        from scrubiq.detectors.structured import map_processed_to_original

        char_map = list(range(10))
        result = map_processed_to_original(-1, char_map, strict=False)
        assert result == 0

    def test_map_processed_to_original_beyond_end(self):
        """Position beyond map length handled gracefully."""
        from scrubiq.detectors.structured import map_processed_to_original

        char_map = [0, 1, 2, 3, 4]
        result = map_processed_to_original(10, char_map, strict=False)
        # Should return last mapped + offset
        assert result >= char_map[-1]

    def test_map_processed_to_original_strict_raises(self):
        """Strict mode raises for out-of-bounds positions."""
        from scrubiq.detectors.structured import map_processed_to_original

        char_map = [0, 1, 2, 3, 4]

        with pytest.raises(ValueError):
            map_processed_to_original(-1, char_map, strict=True)

        with pytest.raises(ValueError):
            map_processed_to_original(10, char_map, strict=True)

    def test_map_span_to_original_identity(self):
        """Identity mapping for unchanged text."""
        from scrubiq.detectors.structured import map_span_to_original

        char_map = list(range(20))
        original_text = "Hello World Testing!"

        start, end = map_span_to_original(0, 5, "Hello", char_map, original_text)
        assert start == 0
        assert end == 5

    def test_map_span_to_original_empty_map(self):
        """Empty char_map returns positions unchanged."""
        from scrubiq.detectors.structured import map_span_to_original

        start, end = map_span_to_original(0, 5, "Hello", [], "Hello World")
        assert start == 0
        assert end == 5


# =============================================================================
# LABEL NORMALIZATION TESTS
# =============================================================================

class TestNormalizeLabel:
    """Tests for normalize_label function."""

    def test_uppercase(self):
        """Converts to uppercase."""
        from scrubiq.detectors.structured import normalize_label

        assert normalize_label("dob") == "DOB"
        assert normalize_label("name") == "NAME"

    def test_strips_whitespace(self):
        """Strips leading/trailing whitespace."""
        from scrubiq.detectors.structured import normalize_label

        assert normalize_label("  DOB  ") == "DOB"

    def test_removes_trailing_punctuation(self):
        """Removes trailing colons and dashes."""
        from scrubiq.detectors.structured import normalize_label

        assert normalize_label("DOB:") == "DOB"
        assert normalize_label("NAME-") == "NAME"
        assert normalize_label("MRN: ") == "MRN"

    def test_collapses_internal_whitespace(self):
        """Collapses multiple internal spaces."""
        from scrubiq.detectors.structured import normalize_label

        assert normalize_label("DATE  OF   BIRTH") == "DATE OF BIRTH"


# =============================================================================
# LABEL DETECTION TESTS
# =============================================================================

class TestDetectLabels:
    """Tests for detect_labels function."""

    def test_detects_standard_labels(self):
        """Detects standard LABEL: format."""
        from scrubiq.detectors.structured import detect_labels

        text = "DOB: 01/15/1980 MRN: 123456"
        labels = detect_labels(text)

        label_names = [l.label for l in labels]
        assert "DOB" in label_names
        assert "MRN" in label_names

    def test_detects_multi_word_labels(self):
        """Detects multi-word labels like DATE OF BIRTH."""
        from scrubiq.detectors.structured import detect_labels

        text = "DATE OF BIRTH: 01/15/1980"
        labels = detect_labels(text)

        assert len(labels) >= 1
        assert any("DOB" in l.label or "BIRTH" in l.label for l in labels)

    def test_detects_field_code_labels(self):
        """Detects field code + label format (16 HGT:)."""
        from scrubiq.detectors.structured import detect_labels

        text = "16 HGT: 5'10\" 18 EYES: BRO"
        labels = detect_labels(text)

        label_names = [l.label for l in labels]
        # Should detect HGT and EYES (physical descriptors)
        assert "HGT" in label_names or "HEIGHT" in label_names

    def test_returns_phi_type(self):
        """Labels include mapped PHI type."""
        from scrubiq.detectors.structured import detect_labels

        text = "SSN: 123-45-6789"
        labels = detect_labels(text)

        ssn_label = next((l for l in labels if l.label == "SSN"), None)
        assert ssn_label is not None
        assert ssn_label.phi_type == "SSN"

    def test_non_phi_labels_have_none_type(self):
        """Non-PHI labels have None phi_type."""
        from scrubiq.detectors.structured import detect_labels

        text = "CLASS: C RESTR: NONE"
        labels = detect_labels(text)

        class_label = next((l for l in labels if l.label == "CLASS"), None)
        if class_label:
            assert class_label.phi_type is None

    def test_sorted_by_position(self):
        """Labels are sorted by position."""
        from scrubiq.detectors.structured import detect_labels

        text = "MRN: 123 DOB: 01/01/2000 NAME: John"
        labels = detect_labels(text)

        positions = [l.label_start for l in labels]
        assert positions == sorted(positions)

    def test_skips_document_type_labels(self):
        """Skips document type labels like DRIVER'S LICENSE."""
        from scrubiq.detectors.structured import detect_labels

        text = "DRIVER'S LICENSE STATE OF CALIFORNIA"
        labels = detect_labels(text)

        # Should not include DRIVER'S LICENSE as a label
        label_names = [l.label for l in labels]
        assert "DRIVER'S LICENSE" not in label_names
        assert "DRIVER LICENSE" not in label_names


# =============================================================================
# VALUE VALIDATION TESTS
# =============================================================================

class TestValidateValue:
    """Tests for validate_value function."""

    def test_date_requires_digits(self):
        """Date values must contain digits."""
        from scrubiq.detectors.structured import validate_value

        assert validate_value("01/15/1980", "DATE") is True
        assert validate_value("January", "DATE") is False

    def test_ssn_validation(self):
        """SSN must have reasonable digit count."""
        from scrubiq.detectors.structured import validate_value

        assert validate_value("123-45-6789", "SSN") is True
        assert validate_value("12345", "SSN") is True
        assert validate_value("123", "SSN") is False  # Too short

    def test_phone_validation(self):
        """Phone must have 7-15 digits."""
        from scrubiq.detectors.structured import validate_value

        assert validate_value("555-123-4567", "PHONE") is True
        assert validate_value("1234567890", "PHONE") is True
        assert validate_value("123", "PHONE") is False  # Too short

    def test_email_requires_at_sign(self):
        """Email must contain @ symbol."""
        from scrubiq.detectors.structured import validate_value

        assert validate_value("test@example.com", "EMAIL") is True
        assert validate_value("test.example.com", "EMAIL") is False

    def test_zip_validation(self):
        """ZIP must be 5 or 9 digits."""
        from scrubiq.detectors.structured import validate_value

        assert validate_value("12345", "ZIP") is True
        assert validate_value("12345-6789", "ZIP") is True
        assert validate_value("123", "ZIP") is False

    def test_mrn_validation(self):
        """MRN must have alphanumeric content and minimum length."""
        from scrubiq.detectors.structured import validate_value

        assert validate_value("MRN123456", "MRN") is True
        assert validate_value("123456789", "MRN") is True
        assert validate_value("AB", "MRN") is False  # Too short

    def test_mrn_rejects_false_positives(self):
        """MRN rejects common false positive words."""
        from scrubiq.detectors.structured import validate_value

        assert validate_value("range", "MRN") is False
        assert validate_value("result", "MRN") is False
        assert validate_value("normal", "MRN") is False

    def test_name_validation(self):
        """Names must have letters and not be all digits."""
        from scrubiq.detectors.structured import validate_value

        assert validate_value("John Smith", "NAME") is True
        assert validate_value("Dr. Sarah Johnson", "NAME") is True
        assert validate_value("12345", "NAME") is False
        assert validate_value("a", "NAME") is False  # Too short

    def test_name_rejects_false_positives(self):
        """Names reject common false positive words."""
        from scrubiq.detectors.structured import validate_value

        assert validate_value("range", "NAME") is False
        assert validate_value("result", "NAME") is False
        assert validate_value("normal", "NAME") is False
        assert validate_value("report", "NAME") is False

    def test_address_minimum_length(self):
        """Address must have minimum length."""
        from scrubiq.detectors.structured import validate_value

        assert validate_value("123 Main Street", "ADDRESS") is True
        assert validate_value("123", "ADDRESS") is False

    def test_physical_desc_validation(self):
        """Physical descriptors have validation."""
        from scrubiq.detectors.structured import validate_value

        assert validate_value("5'10\"", "PHYSICAL_DESC") is True
        assert validate_value("BRO", "PHYSICAL_DESC") is True
        assert validate_value("a", "PHYSICAL_DESC") is False  # Too short
        assert validate_value("loss", "PHYSICAL_DESC") is False  # False positive


# =============================================================================
# VALUE EXTRACTION TESTS
# =============================================================================

class TestExtractValue:
    """Tests for extract_value function."""

    def test_extracts_date_after_label(self):
        """Extracts date value after DOB label."""
        from scrubiq.detectors.structured import extract_value, DetectedLabel

        text = "DOB: 01/15/1980 MRN: 123456"
        label = DetectedLabel(
            label="DOB",
            label_start=0,
            label_end=5,
            phi_type="DATE_DOB",
            raw_label="DOB",
        )
        next_label = DetectedLabel(
            label="MRN",
            label_start=16,
            label_end=21,
            phi_type="MRN",
            raw_label="MRN",
        )

        field = extract_value(text, label, next_label)

        assert field is not None
        assert field.value == "01/15/1980"
        assert field.phi_type == "DATE_DOB"

    def test_returns_none_for_non_phi_labels(self):
        """Returns None for labels with phi_type=None."""
        from scrubiq.detectors.structured import extract_value, DetectedLabel

        text = "CLASS: C"
        label = DetectedLabel(
            label="CLASS",
            label_start=0,
            label_end=7,
            phi_type=None,
            raw_label="CLASS",
        )

        field = extract_value(text, label, None)
        assert field is None

    def test_extracts_name_value(self):
        """Extracts name value correctly."""
        from scrubiq.detectors.structured import extract_value, DetectedLabel

        text = "NAME: John Smith DOB: 01/15/1980"
        label = DetectedLabel(
            label="NAME",
            label_start=0,
            label_end=6,
            phi_type="NAME",
            raw_label="NAME",
        )
        next_label = DetectedLabel(
            label="DOB",
            label_start=17,
            label_end=22,
            phi_type="DATE_DOB",
            raw_label="DOB",
        )

        field = extract_value(text, label, next_label)

        assert field is not None
        assert "John" in field.value

    def test_rejects_prose_values(self):
        """Rejects values that look like prose."""
        from scrubiq.detectors.structured import extract_value, DetectedLabel

        text = "NAME: Patient was seen today for chest pain"
        label = DetectedLabel(
            label="NAME",
            label_start=0,
            label_end=6,
            phi_type="NAME",
            raw_label="NAME",
        )

        field = extract_value(text, label, None)
        # Should reject because value looks like prose
        assert field is None

    def test_high_confidence_for_label_extraction(self):
        """Label-based extraction has high confidence."""
        from scrubiq.detectors.structured import extract_value, DetectedLabel

        text = "SSN: 123-45-6789"
        label = DetectedLabel(
            label="SSN",
            label_start=0,
            label_end=5,
            phi_type="SSN",
            raw_label="SSN",
        )

        field = extract_value(text, label, None)

        assert field is not None
        assert field.confidence == 0.92


# =============================================================================
# UNLABELED ADDRESS DETECTION TESTS
# =============================================================================

class TestDetectUnlabeledAddresses:
    """Tests for detect_unlabeled_addresses function."""

    def test_detects_street_address(self):
        """Detects street address pattern."""
        from scrubiq.detectors.structured import detect_unlabeled_addresses

        text = "Patient lives at 123 Main Street Springfield"
        spans = detect_unlabeled_addresses(text, [])

        # Should detect "123 Main Street"
        assert len(spans) >= 1
        assert any("Main" in s.text or "123" in s.text for s in spans)

    def test_detects_city_state_zip(self):
        """Detects city, state, zip pattern."""
        from scrubiq.detectors.structured import detect_unlabeled_addresses

        text = "Mailing to Springfield, IL 62701"
        spans = detect_unlabeled_addresses(text, [])

        # Should detect "Springfield, IL 62701"
        assert len(spans) >= 1
        address_span = next((s for s in spans if "Springfield" in s.text), None)
        assert address_span is not None

    def test_avoids_overlaps(self):
        """Does not detect addresses that overlap existing spans."""
        from scrubiq.detectors.structured import detect_unlabeled_addresses
        from scrubiq.types import Span, Tier

        text = "Patient at 123 Main Street"
        existing = [Span(
            start=11,
            end=26,
            text="123 Main Street",
            entity_type="ADDRESS",
            confidence=0.95,
            detector="other",
            tier=Tier.STRUCTURED,
        )]

        spans = detect_unlabeled_addresses(text, existing)

        # Should not duplicate the existing span
        assert len(spans) == 0

    def test_address_entity_type(self):
        """Detected addresses have ADDRESS entity type."""
        from scrubiq.detectors.structured import detect_unlabeled_addresses

        text = "Lives at 456 Oak Avenue"
        spans = detect_unlabeled_addresses(text, [])

        for span in spans:
            assert span.entity_type == "ADDRESS"

    def test_structured_tier(self):
        """Detected addresses have STRUCTURED tier."""
        from scrubiq.detectors.structured import detect_unlabeled_addresses

        text = "Address: 789 Pine Road"
        spans = detect_unlabeled_addresses(text, [])

        for span in spans:
            assert span.tier.value == 3  # STRUCTURED tier


# =============================================================================
# MAIN EXTRACTION PIPELINE TESTS
# =============================================================================

class TestExtractStructuredPHI:
    """Tests for extract_structured_phi main function."""

    def test_returns_structured_result(self):
        """Returns StructuredExtractionResult."""
        from scrubiq.detectors.structured import extract_structured_phi, StructuredExtractionResult

        text = "DOB: 01/15/1980"
        result = extract_structured_phi(text)

        assert isinstance(result, StructuredExtractionResult)
        assert hasattr(result, 'spans')
        assert hasattr(result, 'processed_text')
        assert hasattr(result, 'labels_found')
        assert hasattr(result, 'fields_extracted')

    def test_extracts_labeled_fields(self):
        """Extracts values from labeled fields."""
        from scrubiq.detectors.structured import extract_structured_phi

        text = "NAME: John Smith DOB: 01/15/1980 SSN: 123-45-6789"
        result = extract_structured_phi(text)

        # Should extract multiple fields
        assert result.labels_found >= 3
        assert result.fields_extracted >= 1

    def test_spans_in_original_coordinates(self):
        """Returned spans are in original text coordinates."""
        from scrubiq.detectors.structured import extract_structured_phi

        text = "DOB: 01/15/1980"
        result = extract_structured_phi(text)

        for span in result.spans:
            # Span text should match original text at those coordinates
            assert span.text == text[span.start:span.end]

    def test_includes_unlabeled_addresses(self):
        """Includes unlabeled address detection."""
        from scrubiq.detectors.structured import extract_structured_phi

        text = "Patient lives at 123 Main Street, Springfield, IL 62701"
        result = extract_structured_phi(text)

        # Should detect address even without label
        address_spans = [s for s in result.spans if s.entity_type == "ADDRESS"]
        assert len(address_spans) >= 1

    def test_handles_ocr_noise(self):
        """Handles OCR noise like concatenated text."""
        from scrubiq.detectors.structured import extract_structured_phi

        # OCR-like text with concatenated fields
        text = "DOB:01/15/1980MRN:123456"
        result = extract_structured_phi(text)

        # Should still extract fields despite noise
        assert result.processed_text is not None

    def test_empty_text_returns_empty(self):
        """Empty text returns empty result."""
        from scrubiq.detectors.structured import extract_structured_phi

        result = extract_structured_phi("")

        assert result.labels_found == 0
        assert result.fields_extracted == 0
        assert result.spans == []

    def test_structured_detector_tag(self):
        """All spans have 'structured' detector tag."""
        from scrubiq.detectors.structured import extract_structured_phi

        text = "DOB: 01/15/1980 NAME: John Smith"
        result = extract_structured_phi(text)

        for span in result.spans:
            assert span.detector == "structured"


# =============================================================================
# LABEL TAXONOMY TESTS
# =============================================================================

class TestLabelTaxonomy:
    """Tests for LABEL_TO_PHI_TYPE mapping."""

    def test_name_labels(self):
        """Name-related labels map correctly."""
        from scrubiq.detectors.structured import LABEL_TO_PHI_TYPE

        assert LABEL_TO_PHI_TYPE["NAME"] == "NAME"
        assert LABEL_TO_PHI_TYPE["PATIENT"] == "NAME_PATIENT"
        assert LABEL_TO_PHI_TYPE["PROVIDER"] == "NAME_PROVIDER"
        assert LABEL_TO_PHI_TYPE["PHYSICIAN"] == "NAME_PROVIDER"

    def test_date_labels(self):
        """Date-related labels map correctly."""
        from scrubiq.detectors.structured import LABEL_TO_PHI_TYPE

        assert LABEL_TO_PHI_TYPE["DOB"] == "DATE_DOB"
        assert LABEL_TO_PHI_TYPE["DATE OF BIRTH"] == "DATE_DOB"
        assert LABEL_TO_PHI_TYPE["EXP"] == "DATE"
        assert LABEL_TO_PHI_TYPE["ADMIT DATE"] == "DATE"

    def test_id_labels(self):
        """ID-related labels map correctly."""
        from scrubiq.detectors.structured import LABEL_TO_PHI_TYPE

        assert LABEL_TO_PHI_TYPE["SSN"] == "SSN"
        assert LABEL_TO_PHI_TYPE["MRN"] == "MRN"
        assert LABEL_TO_PHI_TYPE["MEMBER ID"] == "HEALTH_PLAN_ID"
        assert LABEL_TO_PHI_TYPE["NPI"] == "NPI"

    def test_contact_labels(self):
        """Contact-related labels map correctly."""
        from scrubiq.detectors.structured import LABEL_TO_PHI_TYPE

        assert LABEL_TO_PHI_TYPE["PHONE"] == "PHONE"
        assert LABEL_TO_PHI_TYPE["EMAIL"] == "EMAIL"
        assert LABEL_TO_PHI_TYPE["FAX"] == "FAX"
        assert LABEL_TO_PHI_TYPE["ADDRESS"] == "ADDRESS"

    def test_non_phi_labels(self):
        """Non-PHI labels map to None."""
        from scrubiq.detectors.structured import LABEL_TO_PHI_TYPE

        assert LABEL_TO_PHI_TYPE["CLASS"] is None
        assert LABEL_TO_PHI_TYPE["RESTRICTIONS"] is None
        assert LABEL_TO_PHI_TYPE["ORGAN DONOR"] is None
        assert LABEL_TO_PHI_TYPE["COPAY"] is None


# =============================================================================
# VALUE PATTERNS TESTS
# =============================================================================

class TestValuePatterns:
    """Tests for VALUE_PATTERNS regex patterns."""

    def test_date_pattern(self):
        """Date pattern matches common formats."""
        from scrubiq.detectors.structured import VALUE_PATTERNS

        pattern = VALUE_PATTERNS["DATE"]

        assert pattern.match("01/15/1980")
        assert pattern.match("1-15-80")
        assert pattern.match("12/31/2023")

    def test_ssn_pattern(self):
        """SSN pattern matches with/without dashes."""
        from scrubiq.detectors.structured import VALUE_PATTERNS

        pattern = VALUE_PATTERNS["SSN"]

        assert pattern.match("123-45-6789")
        assert pattern.match("123456789")
        assert pattern.match("123 45 6789")

    def test_phone_pattern(self):
        """Phone pattern matches various formats."""
        from scrubiq.detectors.structured import VALUE_PATTERNS

        pattern = VALUE_PATTERNS["PHONE"]

        assert pattern.match("555-123-4567")
        assert pattern.match("(555) 123-4567")
        assert pattern.match("555.123.4567")

    def test_email_pattern(self):
        """Email pattern matches standard format."""
        from scrubiq.detectors.structured import VALUE_PATTERNS

        pattern = VALUE_PATTERNS["EMAIL"]

        assert pattern.match("test@example.com")
        assert pattern.match("user.name@domain.org")

    def test_zip_pattern(self):
        """ZIP pattern matches 5 and 9 digit formats."""
        from scrubiq.detectors.structured import VALUE_PATTERNS

        pattern = VALUE_PATTERNS["ZIP"]

        assert pattern.match("12345")
        assert pattern.match("12345-6789")

    def test_name_pattern(self):
        """Name pattern matches various name formats."""
        from scrubiq.detectors.structured import VALUE_PATTERNS

        pattern = VALUE_PATTERNS["NAME"]

        assert pattern.match("John")
        assert pattern.match("John Smith")
        assert pattern.match("Dr. Sarah Johnson")
        assert pattern.match("Mary O'Brien")


# =============================================================================
# DETECTED LABEL DATACLASS TESTS
# =============================================================================

class TestDetectedLabel:
    """Tests for DetectedLabel dataclass."""

    def test_detected_label_creation(self):
        """DetectedLabel can be created with all fields."""
        from scrubiq.detectors.structured import DetectedLabel

        label = DetectedLabel(
            label="DOB",
            label_start=0,
            label_end=4,
            phi_type="DATE_DOB",
            raw_label="DOB",
        )

        assert label.label == "DOB"
        assert label.label_start == 0
        assert label.label_end == 4
        assert label.phi_type == "DATE_DOB"
        assert label.raw_label == "DOB"


# =============================================================================
# EXTRACTED FIELD DATACLASS TESTS
# =============================================================================

class TestExtractedField:
    """Tests for ExtractedField dataclass."""

    def test_extracted_field_creation(self):
        """ExtractedField can be created with all fields."""
        from scrubiq.detectors.structured import ExtractedField

        field = ExtractedField(
            label="DOB",
            phi_type="DATE_DOB",
            value="01/15/1980",
            value_start=5,
            value_end=15,
            confidence=0.92,
        )

        assert field.label == "DOB"
        assert field.phi_type == "DATE_DOB"
        assert field.value == "01/15/1980"
        assert field.value_start == 5
        assert field.value_end == 15
        assert field.confidence == 0.92


# =============================================================================
# STRUCTURED EXTRACTION RESULT TESTS
# =============================================================================

class TestStructuredExtractionResult:
    """Tests for StructuredExtractionResult dataclass."""

    def test_result_creation(self):
        """StructuredExtractionResult can be created."""
        from scrubiq.detectors.structured import StructuredExtractionResult

        result = StructuredExtractionResult(
            spans=[],
            processed_text="test",
            labels_found=5,
            fields_extracted=3,
        )

        assert result.spans == []
        assert result.processed_text == "test"
        assert result.labels_found == 5
        assert result.fields_extracted == 3
