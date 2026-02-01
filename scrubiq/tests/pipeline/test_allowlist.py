"""Tests for context-aware allowlist filtering in allowlist.py.

Tests false positive filtering for common words, drug names,
clinical labels, and context-based confidence adjustment.
"""

import pytest
from scrubiq.types import Span, Tier
from scrubiq.pipeline.allowlist import (
    apply_allowlist,
    _has_medication_context,
    _has_date_context,
    _has_number_context,
    COMMON_WORDS,
    SAFE_ALLOWLIST,
    FALSE_POSITIVE_PHRASES,
    CLINICAL_LABELS,
    MEDICATION_FALSE_POSITIVES,
    ADDRESS_FALSE_POSITIVES,
    FACILITY_FALSE_POSITIVES,
    ACCOUNT_FALSE_POSITIVES,
    DEVICE_ID_FALSE_POSITIVES,
    DRUG_NAMES,
    DATE_CONTEXT,
    NUMBER_CONTEXT,
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


# =============================================================================
# CONSTANTS TESTS
# =============================================================================

class TestConstants:
    """Tests for allowlist constants."""

    def test_common_words_has_stopwords(self):
        """COMMON_WORDS contains common stopwords."""
        assert "the" in COMMON_WORDS
        assert "is" in COMMON_WORDS
        assert "and" in COMMON_WORDS

    def test_common_words_has_pronouns(self):
        """COMMON_WORDS contains pronouns."""
        assert "he" in COMMON_WORDS
        assert "she" in COMMON_WORDS
        assert "they" in COMMON_WORDS

    def test_common_words_has_ambiguous_names(self):
        """COMMON_WORDS contains words that are also names."""
        assert "will" in COMMON_WORDS  # Will (name) vs will (verb)
        assert "mark" in COMMON_WORDS  # Mark (name) vs mark (verb)
        assert "april" in COMMON_WORDS  # April (name) vs April (month)

    def test_safe_allowlist_has_relative_dates(self):
        """SAFE_ALLOWLIST contains relative dates."""
        assert "today" in SAFE_ALLOWLIST
        assert "yesterday" in SAFE_ALLOWLIST
        assert "this week" in SAFE_ALLOWLIST

    def test_safe_allowlist_has_brand_names(self):
        """SAFE_ALLOWLIST contains brand names that look like names."""
        assert "dr. pepper" in SAFE_ALLOWLIST
        assert "mr. clean" in SAFE_ALLOWLIST

    def test_false_positive_phrases_has_job_titles(self):
        """FALSE_POSITIVE_PHRASES contains job titles with credentials."""
        assert "lab director, md" in FALSE_POSITIVE_PHRASES
        assert "nurse manager, rn" in FALSE_POSITIVE_PHRASES

    def test_clinical_labels_has_identifiers(self):
        """CLINICAL_LABELS contains identifier labels."""
        assert "ssn" in CLINICAL_LABELS
        assert "dob" in CLINICAL_LABELS
        assert "mrn" in CLINICAL_LABELS

    def test_drug_names_has_common_medications(self):
        """DRUG_NAMES contains common medications."""
        assert "lisinopril" in DRUG_NAMES
        assert "metformin" in DRUG_NAMES
        assert "aspirin" in DRUG_NAMES
        assert "allegra" in DRUG_NAMES  # Also a person's name


# =============================================================================
# MEDICATION CONTEXT TESTS
# =============================================================================

class TestHasMedicationContext:
    """Tests for _has_medication_context()."""

    def test_dosage_context_detected(self):
        """Dosage patterns trigger medication context."""
        text = "Patient takes Allegra 180 mg daily"
        span = make_span("Allegra", start=14, entity_type="NAME")

        assert _has_medication_context(text, span) is True

    def test_frequency_context_detected(self):
        """Frequency patterns trigger medication context."""
        text = "Take lisinopril b.i.d."
        span = make_span("lisinopril", start=5, entity_type="NAME")

        assert _has_medication_context(text, span) is True

    def test_route_context_detected(self):
        """Route patterns trigger medication context."""
        text = "Administer insulin IV daily"
        span = make_span("insulin", start=11, entity_type="NAME")

        assert _has_medication_context(text, span) is True

    def test_action_context_detected(self):
        """Action patterns trigger medication context."""
        text = "Patient was prescribed Allegra"
        span = make_span("Allegra", start=23, entity_type="NAME")

        assert _has_medication_context(text, span) is True

    def test_no_context_returns_false(self):
        """No medication context returns False."""
        text = "I met Allegra at the park"
        span = make_span("Allegra", start=6, entity_type="NAME")

        assert _has_medication_context(text, span) is False

    def test_form_context_detected(self):
        """Dosage form patterns trigger medication context."""
        text = "Metformin tablets twice daily"
        span = make_span("Metformin", start=0, entity_type="NAME")

        assert _has_medication_context(text, span) is True


# =============================================================================
# DATE CONTEXT TESTS
# =============================================================================

class TestHasDateContext:
    """Tests for _has_date_context()."""

    def test_published_context_detected(self):
        """'published' triggers date context."""
        text = "Guideline published 01/15/2023"
        span = make_span("01/15/2023", start=20, entity_type="DATE")

        assert _has_date_context(text, span) is True

    def test_copyright_context_detected(self):
        """'copyright' triggers date context."""
        text = "Copyright 2023"
        span = make_span("2023", start=10, entity_type="DATE")

        assert _has_date_context(text, span) is True

    def test_version_context_detected(self):
        """'version' triggers date context."""
        text = "Version updated 03/2023"
        span = make_span("03/2023", start=16, entity_type="DATE")

        assert _has_date_context(text, span) is True

    def test_patient_date_no_context(self):
        """Patient dates don't have publishing context."""
        text = "Patient DOB: 01/15/1980"
        span = make_span("01/15/1980", start=13, entity_type="DATE")

        assert _has_date_context(text, span) is False


# =============================================================================
# NUMBER CONTEXT TESTS
# =============================================================================

class TestHasNumberContext:
    """Tests for _has_number_context()."""

    def test_room_context_detected(self):
        """'room' triggers number context."""
        text = "Patient in room 203"
        span = make_span("203", start=16, entity_type="MRN")

        assert _has_number_context(text, span) is True

    def test_lot_context_detected(self):
        """'lot' triggers number context."""
        text = "Vaccine lot 12345"
        span = make_span("12345", start=12, entity_type="MRN")

        assert _has_number_context(text, span) is True

    def test_reference_context_detected(self):
        """'reference' triggers number context."""
        text = "Lab reference 90-100"
        span = make_span("90-100", start=14, entity_type="MRN")

        assert _has_number_context(text, span) is True

    def test_mrn_no_context(self):
        """Actual MRN doesn't have reference context."""
        text = "MRN: 12345678"
        span = make_span("12345678", start=5, entity_type="MRN")

        assert _has_number_context(text, span) is False


# =============================================================================
# SAFE ALLOWLIST FILTERING
# =============================================================================

class TestSafeAllowlistFiltering:
    """Tests for SAFE_ALLOWLIST filtering."""

    def test_relative_date_filtered(self):
        """Relative dates are filtered."""
        text = "Follow up today"
        spans = [make_span("today", start=10, entity_type="DATE")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_brand_name_filtered(self):
        """Brand names that look like names are filtered."""
        text = "Drink Dr. Pepper"
        spans = [make_span("Dr. Pepper", start=6, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_template_text_filtered(self):
        """Template/placeholder text is filtered."""
        text = "Name: [REDACTED]"
        spans = [make_span("REDACTED", start=7, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_punctuation_stripped_for_matching(self):
        """Punctuation is stripped for matching."""
        text = "See you tomorrow."
        spans = [make_span("tomorrow.", start=8, entity_type="DATE")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0


# =============================================================================
# COMMON WORDS FILTERING
# =============================================================================

class TestCommonWordsFiltering:
    """Tests for COMMON_WORDS filtering."""

    def test_stopword_as_name_filtered(self):
        """Common stopwords detected as NAME are filtered."""
        text = "The patient"
        spans = [make_span("The", start=0, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_pronoun_as_name_filtered(self):
        """Pronouns detected as NAME are filtered."""
        text = "He said hello"
        spans = [make_span("He", start=0, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_ambiguous_name_filtered(self):
        """Ambiguous words (name/common) detected as NAME are filtered."""
        text = "Will go tomorrow"
        spans = [make_span("Will", start=0, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_common_word_not_filtered_for_other_types(self):
        """Common words are NOT filtered for non-NAME types."""
        text = "Medication: Will"
        spans = [make_span("Will", start=12, entity_type="MEDICATION")]

        result = apply_allowlist(text, spans)

        # MEDICATION type is kept (COMMON_WORDS only filters NAME)
        assert len(result) == 1

    def test_multi_word_all_common_filtered(self):
        """Multi-word spans where ALL words are common are filtered."""
        text = "Provider recommends rest"
        spans = [make_span("recommends rest", start=9, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_multi_word_not_all_common_kept(self):
        """Multi-word spans where NOT all words are common are kept."""
        text = "April Jones called"
        spans = [make_span("April Jones", start=0, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        # "April" is common but "Jones" is not → keep span
        assert len(result) == 1


# =============================================================================
# FALSE POSITIVE PHRASES FILTERING
# =============================================================================

class TestFalsePositivePhrasesFiltering:
    """Tests for FALSE_POSITIVE_PHRASES filtering."""

    def test_job_title_with_credential_filtered(self):
        """Job titles with credentials are filtered."""
        text = "Signed by Lab Director, MD"
        spans = [make_span("Lab Director, MD", start=10, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_instruction_phrase_filtered(self):
        """Instructional phrases are filtered."""
        text = "Please call to schedule"
        spans = [make_span("call to schedule", start=7, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0


# =============================================================================
# CLINICAL LABELS FILTERING
# =============================================================================

class TestClinicalLabelsFiltering:
    """Tests for CLINICAL_LABELS filtering."""

    def test_ssn_label_filtered(self):
        """'SSN' as label detected as NAME is filtered."""
        text = "SSN: 123-45-6789"
        spans = [make_span("SSN", start=0, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_dob_label_filtered(self):
        """'DOB' as label detected as NAME is filtered."""
        text = "DOB: 01/15/1980"
        spans = [make_span("DOB", start=0, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_clinical_abbreviation_filtered(self):
        """Clinical abbreviations detected as NAME are filtered."""
        text = "HPI: Patient presents with..."
        spans = [make_span("HPI", start=0, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0


# =============================================================================
# MEDICATION FALSE POSITIVES FILTERING
# =============================================================================

class TestMedicationFalsePositivesFiltering:
    """Tests for MEDICATION_FALSE_POSITIVES filtering."""

    def test_dosage_form_filtered(self):
        """Dosage forms detected as MEDICATION are filtered."""
        text = "Take 2 tablets daily"
        spans = [make_span("tablets", start=7, entity_type="MEDICATION")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_unit_filtered(self):
        """Units detected as MEDICATION are filtered."""
        text = "Dosage: 50 mg"
        spans = [make_span("mg", start=11, entity_type="MEDICATION")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0


# =============================================================================
# ADDRESS FALSE POSITIVES FILTERING
# =============================================================================

class TestAddressFalsePositivesFiltering:
    """Tests for ADDRESS_FALSE_POSITIVES filtering."""

    def test_clinical_term_as_address_filtered(self):
        """Clinical terms detected as ADDRESS are filtered."""
        text = "Continue home monitoring."
        spans = [make_span("monitoring.", start=14, entity_type="ADDRESS")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0


# =============================================================================
# FACILITY FALSE POSITIVES FILTERING
# =============================================================================

class TestFacilityFalsePositivesFiltering:
    """Tests for FACILITY_FALSE_POSITIVES filtering."""

    def test_generic_facility_word_filtered(self):
        """Generic facility words detected as FACILITY are filtered."""
        text = "HOSPITAL ADMISSION RECORD"
        spans = [make_span("HOSPITAL", start=0, entity_type="FACILITY")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_specific_facility_name_kept(self):
        """Specific facility names are NOT filtered."""
        text = "Admitted to Johns Hopkins Hospital"
        spans = [make_span("Johns Hopkins Hospital", start=12, entity_type="FACILITY")]

        result = apply_allowlist(text, spans)

        # Specific name is kept
        assert len(result) == 1


# =============================================================================
# ACCOUNT FALSE POSITIVES FILTERING
# =============================================================================

class TestAccountFalsePositivesFiltering:
    """Tests for ACCOUNT_FALSE_POSITIVES filtering."""

    def test_label_word_as_account_filtered(self):
        """Label words after 'Account' detected as ACCOUNT_NUMBER are filtered."""
        text = "Account Created"
        spans = [make_span("Created", start=8, entity_type="ACCOUNT_NUMBER")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0


# =============================================================================
# ID NUMBER FALSE POSITIVES FILTERING
# =============================================================================

class TestIdNumberFalsePositivesFiltering:
    """Tests for ID_NUMBER_FALSE_POSITIVE_PATTERNS filtering."""

    def test_reference_range_filtered(self):
        """Lab reference ranges are filtered."""
        text = "Normal range: 70-100"
        spans = [make_span("70-100", start=14, entity_type="ID_NUMBER")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_percentage_filtered(self):
        """Percentage values are filtered."""
        text = "A1C should be <5.7%"
        spans = [make_span("5.7%", start=15, entity_type="ID_NUMBER")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_comparison_filtered(self):
        """Comparison values are filtered."""
        text = "Cholesterol <200"
        spans = [make_span("<200", start=12, entity_type="ID_NUMBER")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0


# =============================================================================
# DEVICE ID FALSE POSITIVES FILTERING
# =============================================================================

class TestDeviceIdFalsePositivesFiltering:
    """Tests for DEVICE_ID_FALSE_POSITIVES filtering."""

    def test_label_word_as_device_id_filtered(self):
        """Label words detected as DEVICE_ID are filtered."""
        text = "Serial Number: ABC123"
        spans = [make_span("Number", start=7, entity_type="DEVICE_ID")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0


# =============================================================================
# DRUG NAMES WITH CONTEXT FILTERING
# =============================================================================

class TestDrugNamesFiltering:
    """Tests for drug name filtering based on context."""

    def test_drug_name_with_med_context_filtered(self):
        """Drug name as NAME with medication context is filtered."""
        text = "Patient takes Allegra 180mg daily"
        spans = [make_span("Allegra", start=14, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        # "Allegra" with dosage context → filter (it's a drug, not a person)
        assert len(result) == 0

    def test_drug_name_without_context_kept(self):
        """Drug name as NAME without medication context is kept."""
        text = "I met Allegra at the store"
        spans = [make_span("Allegra", start=6, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        # "Allegra" without medication context → keep (could be a person)
        assert len(result) == 1

    def test_drug_name_as_medication_type_kept(self):
        """Drug names detected as MEDICATION type are kept."""
        text = "Prescribed metformin 500mg"
        spans = [make_span("metformin", start=11, entity_type="MEDICATION")]

        result = apply_allowlist(text, spans)

        # MEDICATION type → keep (we want to detect medications)
        assert len(result) == 1


# =============================================================================
# DATE CONTEXT CONFIDENCE ADJUSTMENT
# =============================================================================

class TestDateContextConfidenceAdjustment:
    """Tests for date context confidence downgrade."""

    def test_publishing_date_confidence_reduced(self):
        """Dates with publishing context have confidence reduced."""
        text = "Guideline published 01/15/2023"
        spans = [make_span("01/15/2023", start=20, entity_type="DATE", confidence=0.9)]

        result = apply_allowlist(text, spans)

        assert len(result) == 1
        assert result[0].confidence == pytest.approx(0.27)  # 0.9 * 0.3

    def test_patient_date_confidence_unchanged(self):
        """Patient dates without context have confidence unchanged."""
        text = "Patient DOB: 01/15/1980"
        spans = [make_span("01/15/1980", start=13, entity_type="DATE", confidence=0.9)]

        result = apply_allowlist(text, spans)

        assert len(result) == 1
        assert result[0].confidence == 0.9


# =============================================================================
# NUMBER CONTEXT CONFIDENCE ADJUSTMENT
# =============================================================================

class TestNumberContextConfidenceAdjustment:
    """Tests for number context confidence downgrade."""

    def test_room_number_confidence_reduced(self):
        """Numbers with room context have confidence reduced."""
        text = "Patient in room 203"
        spans = [make_span("203", start=16, entity_type="MRN", confidence=0.9)]

        result = apply_allowlist(text, spans)

        assert len(result) == 1
        assert result[0].confidence == pytest.approx(0.27)  # 0.9 * 0.3

    def test_actual_mrn_confidence_unchanged(self):
        """Actual MRN without context has confidence unchanged."""
        text = "MRN: 12345678"
        spans = [make_span("12345678", start=5, entity_type="MRN", confidence=0.9)]

        result = apply_allowlist(text, spans)

        assert len(result) == 1
        assert result[0].confidence == 0.9


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestAllowlistIntegration:
    """Integration tests for apply_allowlist()."""

    def test_empty_spans(self):
        """Empty span list returns empty."""
        result = apply_allowlist("Some text", [])
        assert result == []

    def test_real_phi_passes_through(self):
        """Real PHI that doesn't match allowlist passes through."""
        text = "Patient: John Smith, DOB: 01/15/1980, SSN: 123-45-6789"
        spans = [
            make_span("John Smith", start=9, entity_type="NAME"),
            make_span("01/15/1980", start=26, entity_type="DATE"),
            make_span("123-45-6789", start=43, entity_type="SSN"),
        ]

        result = apply_allowlist(text, spans)

        # All real PHI should pass through
        assert len(result) == 3

    def test_mixed_real_and_false_positives(self):
        """Mix of real PHI and false positives is correctly filtered."""
        text = "Patient John Smith takes Allegra 180mg daily. SSN: 123-45-6789"
        spans = [
            make_span("John Smith", start=8, entity_type="NAME"),  # Real name
            make_span("Allegra", start=25, entity_type="NAME"),  # Drug with context
            make_span("123-45-6789", start=52, entity_type="SSN"),  # Real SSN
        ]

        result = apply_allowlist(text, spans)

        # Allegra filtered (drug context), others kept
        assert len(result) == 2
        texts = [s.text for s in result]
        assert "John Smith" in texts
        assert "123-45-6789" in texts
        assert "Allegra" not in texts

    def test_preserves_span_metadata(self):
        """Allowlist preserves span metadata for kept spans."""
        text = "Patient John Smith"
        span = Span(
            start=8,
            end=18,
            text="John Smith",
            entity_type="NAME",
            confidence=0.95,
            detector="ml_bert",
            tier=Tier.ML,
            safe_harbor_value="REDACTED",
        )

        result = apply_allowlist(text, [span])

        assert len(result) == 1
        assert result[0].detector == "ml_bert"
        assert result[0].tier == Tier.ML
        assert result[0].safe_harbor_value == "REDACTED"


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for allowlist filtering."""

    def test_case_insensitive_matching(self):
        """Matching is case-insensitive."""
        text = "TODAY is the day"
        spans = [make_span("TODAY", start=0, entity_type="DATE")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0

    def test_unicode_text(self):
        """Unicode text is handled correctly."""
        text = "Patient: José García"
        spans = [make_span("José García", start=9, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        # Real name passes through
        assert len(result) == 1

    def test_span_at_text_boundary(self):
        """Spans at text boundaries work correctly."""
        text = "Dr. Pepper"
        spans = [make_span("Dr. Pepper", start=0, entity_type="NAME")]

        result = apply_allowlist(text, spans)

        assert len(result) == 0  # Brand name filtered

    def test_multiple_spans_same_text(self):
        """Multiple spans over same text are individually processed."""
        text = "Today Today"
        spans = [
            make_span("Today", start=0, entity_type="DATE"),
            make_span("Today", start=6, entity_type="DATE"),
        ]

        result = apply_allowlist(text, spans)

        assert len(result) == 0  # Both filtered
