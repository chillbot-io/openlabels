"""Tests for coreference resolution in coref.py.

Tests pronoun resolution, partial name linking, and the rule-based
fallback (ONNX model tests require the actual model files).
"""

import pytest
from unittest.mock import patch, MagicMock

from scrubiq.types import Span, Tier
import scrubiq.pipeline.coref as coref_module


def make_span(text, start=0, entity_type="NAME", confidence=0.9, detector="test",
              tier=2, coref_anchor_value=None):
    """Helper to create spans with correct end position."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=Tier.from_value(tier),
        coref_anchor_value=coref_anchor_value,
    )


@pytest.fixture(autouse=True)
def reset_coref_globals():
    """Reset global caches before each test."""
    coref_module._ONNX_SESSION = None
    coref_module._TOKENIZER = None
    coref_module._ONNX_AVAILABLE = None
    coref_module._MODELS_DIR = None
    yield


# =============================================================================
# CONSTANTS TESTS
# =============================================================================

class TestConstants:
    """Tests for module constants."""

    def test_name_types_includes_all_name_variants(self):
        """NAME_TYPES includes all NAME-family types."""
        assert "NAME" in coref_module.NAME_TYPES
        assert "NAME_PATIENT" in coref_module.NAME_TYPES
        assert "NAME_PROVIDER" in coref_module.NAME_TYPES
        assert "NAME_RELATIVE" in coref_module.NAME_TYPES

    def test_name_types_excludes_other_types(self):
        """NAME_TYPES doesn't include non-name types."""
        assert "SSN" not in coref_module.NAME_TYPES
        assert "PHONE" not in coref_module.NAME_TYPES
        assert "DATE" not in coref_module.NAME_TYPES

    def test_pronouns_includes_common(self):
        """PRONOUNS includes common pronouns."""
        assert "he" in coref_module.PRONOUNS
        assert "she" in coref_module.PRONOUNS
        assert "they" in coref_module.PRONOUNS
        assert "him" in coref_module.PRONOUNS
        assert "her" in coref_module.PRONOUNS
        assert "them" in coref_module.PRONOUNS

    def test_male_pronouns_set(self):
        """MALE_PRONOUNS contains male pronouns."""
        assert "he" in coref_module.MALE_PRONOUNS
        assert "him" in coref_module.MALE_PRONOUNS
        assert "his" in coref_module.MALE_PRONOUNS

    def test_female_pronouns_set(self):
        """FEMALE_PRONOUNS contains female pronouns."""
        assert "she" in coref_module.FEMALE_PRONOUNS
        assert "her" in coref_module.FEMALE_PRONOUNS
        assert "hers" in coref_module.FEMALE_PRONOUNS

    def test_neutral_pronouns_set(self):
        """NEUTRAL_PRONOUNS contains neutral pronouns."""
        assert "they" in coref_module.NEUTRAL_PRONOUNS
        assert "them" in coref_module.NEUTRAL_PRONOUNS
        assert "their" in coref_module.NEUTRAL_PRONOUNS


# =============================================================================
# SPLIT SENTENCES TESTS
# =============================================================================

class TestSplitSentences:
    """Tests for _split_sentences() function."""

    def test_splits_on_period(self):
        """Splits on period followed by space."""
        sentences = coref_module._split_sentences("First sentence. Second sentence.")
        assert len(sentences) >= 2

    def test_splits_on_question_mark(self):
        """Splits on question mark."""
        sentences = coref_module._split_sentences("Is this first? Yes this is second.")
        assert len(sentences) >= 2

    def test_splits_on_exclamation(self):
        """Splits on exclamation mark."""
        sentences = coref_module._split_sentences("Hello! How are you?")
        assert len(sentences) >= 2

    def test_preserves_abbreviations(self):
        """Doesn't split on abbreviations like Dr. Mr. etc."""
        sentences = coref_module._split_sentences("Dr. Smith arrived. He was early.")
        # Should be 2 sentences, not 3
        assert len(sentences) == 2

    def test_preserves_mrs(self):
        """Doesn't split on Mrs."""
        sentences = coref_module._split_sentences("Mrs. Jones called. She left a message.")
        assert len(sentences) == 2

    def test_single_sentence(self):
        """Single sentence without terminal punctuation."""
        sentences = coref_module._split_sentences("Just one sentence")
        assert len(sentences) == 1

    def test_returns_positions(self):
        """Returns start/end positions with text."""
        text = "First. Second."
        sentences = coref_module._split_sentences(text)
        for start, end, sent_text in sentences:
            assert text[start:end] == sent_text

    def test_empty_string(self):
        """Empty string returns empty list (no sentences to split)."""
        sentences = coref_module._split_sentences("")
        # Implementation returns [] for empty string
        # (no text after final position = no appending)
        assert len(sentences) == 0


class TestGetSentenceIndex:
    """Tests for _get_sentence_index() function."""

    def test_finds_correct_sentence(self):
        """Finds correct sentence index for position."""
        text = "First sentence. Second sentence. Third sentence."
        sentences = coref_module._split_sentences(text)

        # Position in first sentence
        assert coref_module._get_sentence_index(0, sentences) == 0
        # Position in second sentence
        assert coref_module._get_sentence_index(20, sentences) == 1

    def test_position_past_end(self):
        """Position past end returns last sentence index."""
        sentences = [(0, 10, "First."), (10, 20, "Second.")]
        idx = coref_module._get_sentence_index(100, sentences)
        assert idx == len(sentences) - 1


# =============================================================================
# GENDER INFERENCE TESTS
# =============================================================================

class TestInferGender:
    """Tests for _infer_gender() function."""

    def test_male_name_returns_m(self):
        """Male names return 'M'."""
        assert coref_module._infer_gender("John Smith") == "M"
        assert coref_module._infer_gender("James Wilson") == "M"
        assert coref_module._infer_gender("Michael Brown") == "M"

    def test_female_name_returns_f(self):
        """Female names return 'F'."""
        assert coref_module._infer_gender("Mary Johnson") == "F"
        assert coref_module._infer_gender("Jennifer Lee") == "F"
        assert coref_module._infer_gender("Sarah Miller") == "F"

    def test_unknown_name_returns_none(self):
        """Unknown names return None."""
        assert coref_module._infer_gender("Xyzzy Unknown") is None

    def test_uses_first_name_only(self):
        """Uses first name for gender inference."""
        assert coref_module._infer_gender("John Mary Smith") == "M"

    def test_handles_title_with_period(self):
        """Handles names with titles like Dr. Mr."""
        # "Dr." is stripped of period, "dr" not in name lists
        result = coref_module._infer_gender("Dr. Smith")
        # "dr" → None
        assert result is None


class TestPronounMatchesGender:
    """Tests for _pronoun_matches_gender() function."""

    def test_male_pronoun_matches_male(self):
        """Male pronouns match male gender."""
        assert coref_module._pronoun_matches_gender("he", "M") is True
        assert coref_module._pronoun_matches_gender("him", "M") is True
        assert coref_module._pronoun_matches_gender("his", "M") is True

    def test_male_pronoun_not_female(self):
        """Male pronouns don't match female gender."""
        assert coref_module._pronoun_matches_gender("he", "F") is False
        assert coref_module._pronoun_matches_gender("him", "F") is False

    def test_female_pronoun_matches_female(self):
        """Female pronouns match female gender."""
        assert coref_module._pronoun_matches_gender("she", "F") is True
        assert coref_module._pronoun_matches_gender("her", "F") is True
        assert coref_module._pronoun_matches_gender("hers", "F") is True

    def test_female_pronoun_not_male(self):
        """Female pronouns don't match male gender."""
        assert coref_module._pronoun_matches_gender("she", "M") is False
        assert coref_module._pronoun_matches_gender("her", "M") is False

    def test_neutral_matches_any(self):
        """Neutral pronouns match any gender."""
        assert coref_module._pronoun_matches_gender("they", "M") is True
        assert coref_module._pronoun_matches_gender("they", "F") is True
        assert coref_module._pronoun_matches_gender("them", "M") is True
        assert coref_module._pronoun_matches_gender("their", "F") is True

    def test_none_gender_matches_all(self):
        """None gender matches all pronouns."""
        assert coref_module._pronoun_matches_gender("he", None) is True
        assert coref_module._pronoun_matches_gender("she", None) is True
        assert coref_module._pronoun_matches_gender("they", None) is True


# =============================================================================
# RULE-BASED RESOLUTION TESTS
# =============================================================================

class TestResolveWithRules:
    """Tests for _resolve_with_rules() function."""

    def test_expands_pronouns(self):
        """Expands pronouns following name anchor."""
        text = "John Smith arrived. He was tired."
        spans = [make_span("John Smith", start=0, confidence=0.9)]

        result = coref_module._resolve_with_rules(
            text, spans,
            window_sentences=2,
            max_expansions_per_anchor=3,
            min_anchor_confidence=0.85,
            confidence_decay=0.90,
        )

        # Should have original + pronoun span
        assert len(result) >= 2
        pronoun_spans = [s for s in result if s.text.lower() == "he"]
        assert len(pronoun_spans) >= 1

    def test_pronoun_inherits_type(self):
        """Pronoun span inherits entity_type from anchor."""
        text = "John Smith arrived. He was tired."
        spans = [make_span("John Smith", start=0, entity_type="NAME_PATIENT", confidence=0.9)]

        result = coref_module._resolve_with_rules(
            text, spans, 2, 3, 0.85, 0.90
        )

        pronoun_spans = [s for s in result if s.text.lower() == "he"]
        assert pronoun_spans[0].entity_type == "NAME_PATIENT"

    def test_pronoun_has_coref_anchor(self):
        """Pronoun span has coref_anchor_value set."""
        text = "John Smith arrived. He was tired."
        spans = [make_span("John Smith", start=0, confidence=0.9)]

        result = coref_module._resolve_with_rules(
            text, spans, 2, 3, 0.85, 0.90
        )

        pronoun_spans = [s for s in result if s.text.lower() == "he"]
        assert pronoun_spans[0].coref_anchor_value == "John Smith"

    def test_respects_window_limit(self):
        """Respects sentence window limit."""
        # 4 sentences apart
        text = "John Smith arrived. Second sentence. Third sentence. Fourth sentence. He was there."
        spans = [make_span("John Smith", start=0, confidence=0.9)]

        result = coref_module._resolve_with_rules(
            text, spans,
            window_sentences=1,  # Only 1 sentence away
            max_expansions_per_anchor=3,
            min_anchor_confidence=0.85,
            confidence_decay=0.90,
        )

        # Pronoun should be too far
        pronoun_spans = [s for s in result if s.text.lower() == "he"]
        assert len(pronoun_spans) == 0

    def test_respects_expansion_cap(self):
        """Respects max_expansions_per_anchor."""
        text = "John Smith said he told him about his plan."
        spans = [make_span("John Smith", start=0, confidence=0.9)]

        result = coref_module._resolve_with_rules(
            text, spans,
            window_sentences=2,
            max_expansions_per_anchor=1,  # Only 1 expansion allowed
            min_anchor_confidence=0.85,
            confidence_decay=0.90,
        )

        # Should have max 1 expansion
        new_spans = [s for s in result if s not in spans]
        assert len(new_spans) <= 1

    def test_low_confidence_anchor_skipped(self):
        """Low confidence anchors are skipped."""
        text = "John Smith arrived. He was tired."
        spans = [make_span("John Smith", start=0, confidence=0.5)]  # Low confidence

        result = coref_module._resolve_with_rules(
            text, spans, 2, 3, 0.85, 0.90
        )

        # Only original span, no expansion
        assert len(result) == 1

    def test_non_name_types_skipped(self):
        """Non-NAME types are not used as anchors."""
        text = "SSN 123-45-6789 is valid. He was tired."
        spans = [make_span("123-45-6789", start=4, entity_type="SSN", confidence=0.9)]

        result = coref_module._resolve_with_rules(
            text, spans, 2, 3, 0.85, 0.90
        )

        # No pronoun expansion for SSN
        assert len(result) == 1

    def test_empty_spans_returns_empty(self):
        """Empty spans list returns empty."""
        result = coref_module._resolve_with_rules(
            "Some text", [], 2, 3, 0.85, 0.90
        )
        assert result == []

    def test_gender_matching(self):
        """Pronouns match anchor gender."""
        text = "Mary Smith arrived. She was tired."
        spans = [make_span("Mary Smith", start=0, confidence=0.9)]

        result = coref_module._resolve_with_rules(
            text, spans, 2, 3, 0.85, 0.90
        )

        # "she" should match female name
        pronoun_spans = [s for s in result if s.text.lower() == "she"]
        assert len(pronoun_spans) >= 1

    def test_gender_mismatch_skipped(self):
        """Gender mismatched pronouns are skipped."""
        text = "Mary Smith arrived. He was tired."
        spans = [make_span("Mary Smith", start=0, confidence=0.9)]

        result = coref_module._resolve_with_rules(
            text, spans, 2, 3, 0.85, 0.90
        )

        # "he" shouldn't match female Mary
        pronoun_spans = [s for s in result if s.text.lower() == "he"]
        assert len(pronoun_spans) == 0

    def test_results_sorted_by_position(self):
        """Results are sorted by start position."""
        text = "John Smith arrived. He was tired."
        spans = [make_span("John Smith", start=0, confidence=0.9)]

        result = coref_module._resolve_with_rules(
            text, spans, 2, 3, 0.85, 0.90
        )

        for i in range(len(result) - 1):
            assert result[i].start <= result[i + 1].start


# =============================================================================
# PARTIAL NAME LINKING TESTS
# =============================================================================

class TestNormalizeNameForMatching:
    """Tests for _normalize_name_for_matching() function."""

    def test_lowercases(self):
        """Lowercases name."""
        assert coref_module._normalize_name_for_matching("John Smith") == "john smith"

    def test_strips_whitespace(self):
        """Strips leading/trailing whitespace."""
        assert coref_module._normalize_name_for_matching("  John  ") == "john"


class TestGetNameWords:
    """Tests for _get_name_words() function."""

    def test_extracts_words(self):
        """Extracts words from name."""
        words = coref_module._get_name_words("John Smith")
        assert "john" in words
        assert "smith" in words

    def test_excludes_titles(self):
        """Excludes common titles."""
        words = coref_module._get_name_words("Dr. John Smith Jr.")
        assert "dr" not in words
        assert "jr" not in words
        assert "john" in words
        assert "smith" in words

    def test_handles_periods(self):
        """Handles periods in titles."""
        words = coref_module._get_name_words("Mr. Smith")
        assert "mr" not in words
        assert "smith" in words


class TestLinkPartialNames:
    """Tests for _link_partial_names() function."""

    def test_links_partial_to_full(self):
        """Links partial name to full name."""
        spans = [
            make_span("John Smith", start=0, confidence=0.9),
            make_span("Smith", start=50, confidence=0.9),
        ]

        result = coref_module._link_partial_names(spans)

        # Smith should link to John Smith
        smith_span = [s for s in result if s.text == "Smith"][0]
        assert smith_span.coref_anchor_value == "John Smith"

    def test_anchor_is_longest(self):
        """Anchor is the longest name in group."""
        spans = [
            make_span("Smith", start=0, confidence=0.9),
            make_span("John Smith", start=20, confidence=0.9),
            make_span("Smith", start=50, confidence=0.9),
        ]

        result = coref_module._link_partial_names(spans)

        # Both Smiths should link to John Smith
        for span in result:
            if span.text == "Smith":
                assert span.coref_anchor_value == "John Smith"

    def test_doesnt_overwrite_existing(self):
        """Doesn't overwrite existing coref_anchor_value."""
        spans = [
            make_span("John Smith", start=0, confidence=0.9),
            make_span("Smith", start=50, confidence=0.9, coref_anchor_value="Dr. Smith"),
        ]

        result = coref_module._link_partial_names(spans)

        # Smith should keep existing anchor
        smith_span = [s for s in result if s.text == "Smith"][0]
        assert smith_span.coref_anchor_value == "Dr. Smith"

    def test_needs_minimum_two_names(self):
        """Needs at least 2 names to link."""
        spans = [make_span("John Smith", start=0, confidence=0.9)]
        result = coref_module._link_partial_names(spans)
        assert len(result) == 1

    def test_respects_min_confidence(self):
        """Respects min_confidence parameter."""
        spans = [
            make_span("John Smith", start=0, confidence=0.5),  # Low confidence
            make_span("Smith", start=50, confidence=0.5),
        ]

        result = coref_module._link_partial_names(spans, min_confidence=0.85)

        # Neither should be linked due to low confidence
        for span in result:
            if span.text == "Smith":
                assert span.coref_anchor_value is None

    def test_only_name_types(self):
        """Only links NAME-type spans."""
        spans = [
            make_span("12345", start=0, entity_type="MRN", confidence=0.9),
            make_span("123", start=20, entity_type="MRN", confidence=0.9),
        ]

        result = coref_module._link_partial_names(spans)

        # Non-NAME types shouldn't be linked
        for span in result:
            assert span.coref_anchor_value is None

    def test_empty_returns_empty(self):
        """Empty list returns empty."""
        assert coref_module._link_partial_names([]) == []

    def test_groups_by_shared_words(self):
        """Groups names that share words."""
        spans = [
            make_span("John Smith", start=0, confidence=0.9),
            make_span("Jane Smith", start=20, confidence=0.9),
            make_span("Smith", start=50, confidence=0.9),
        ]

        result = coref_module._link_partial_names(spans)

        # Smith should link to one of the full names
        smith_span = [s for s in result if s.text == "Smith"][0]
        assert smith_span.coref_anchor_value in ["John Smith", "Jane Smith"]


# =============================================================================
# RESOLVE COREFERENCES (PUBLIC API) TESTS
# =============================================================================

class TestResolveCoreferences:
    """Tests for resolve_coreferences() public API."""

    def test_empty_text_returns_spans(self):
        """Empty text returns original spans."""
        spans = [make_span("John", start=0)]
        result = coref_module.resolve_coreferences("", spans)
        assert len(result) == 1

    def test_empty_spans_returns_empty(self):
        """Empty spans returns empty."""
        result = coref_module.resolve_coreferences("Some text", [])
        assert result == []

    def test_none_spans_returns_empty(self):
        """None spans returns empty."""
        result = coref_module.resolve_coreferences("Some text", None)
        assert result == []

    def test_uses_rules_when_onnx_unavailable(self):
        """Uses rule-based resolution when ONNX unavailable."""
        with patch.object(coref_module, '_check_onnx_available', return_value=False):
            text = "John Smith arrived. He was tired."
            spans = [make_span("John Smith", start=0, confidence=0.9)]

            result = coref_module.resolve_coreferences(text, spans)

            # Should still expand pronouns
            assert len(result) >= 2

    def test_force_rules_mode(self):
        """Can force rule-based mode."""
        text = "John Smith arrived. He was tired."
        spans = [make_span("John Smith", start=0, confidence=0.9)]

        result = coref_module.resolve_coreferences(text, spans, use_onnx=False)

        # Should expand pronouns using rules
        assert len(result) >= 2

    def test_combines_pronoun_and_partial_linking(self):
        """Combines pronoun resolution and partial name linking."""
        text = "John Smith arrived. He was tired. Smith left."
        spans = [
            make_span("John Smith", start=0, confidence=0.9),
            make_span("Smith", start=34, confidence=0.9),
        ]

        with patch.object(coref_module, '_check_onnx_available', return_value=False):
            result = coref_module.resolve_coreferences(text, spans)

        # Should have pronouns and Smith linked
        assert len(result) >= 3


# =============================================================================
# ONNX AVAILABILITY TESTS
# =============================================================================

class TestOnnxAvailability:
    """Tests for ONNX availability checking."""

    def test_is_onnx_available_function(self):
        """is_onnx_available() returns bool."""
        # Will likely return False in test env without models
        result = coref_module.is_onnx_available()
        assert isinstance(result, bool)

    def test_is_fastcoref_available_alias(self):
        """is_fastcoref_available() is alias for is_onnx_available()."""
        with patch.object(coref_module, '_check_onnx_available', return_value=True):
            assert coref_module.is_fastcoref_available() is True

        with patch.object(coref_module, '_check_onnx_available', return_value=False):
            assert coref_module.is_fastcoref_available() is False

    def test_set_models_dir(self):
        """set_models_dir() sets custom path."""
        from pathlib import Path
        test_path = Path("/custom/models")

        coref_module.set_models_dir(test_path)

        assert coref_module._MODELS_DIR == test_path
        # Should reset availability check
        assert coref_module._ONNX_AVAILABLE is None


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for coreference resolution."""

    def test_multiple_anchors_same_gender(self):
        """Multiple anchors of same gender uses closest."""
        text = "John Smith arrived. James Brown came. He was first."
        spans = [
            make_span("John Smith", start=0, confidence=0.9),
            make_span("James Brown", start=20, confidence=0.9),
        ]

        with patch.object(coref_module, '_check_onnx_available', return_value=False):
            result = coref_module.resolve_coreferences(text, spans)

        # Should have pronoun span
        pronoun_spans = [s for s in result if s.text.lower() == "he"]
        if pronoun_spans:
            # Should link to closer anchor (James Brown)
            assert pronoun_spans[0].coref_anchor_value == "James Brown"

    def test_pronoun_pattern_case_insensitive(self):
        """Pronoun pattern matches case-insensitively."""
        text = "John Smith arrived. HE was tired."
        spans = [make_span("John Smith", start=0, confidence=0.9)]

        with patch.object(coref_module, '_check_onnx_available', return_value=False):
            result = coref_module.resolve_coreferences(text, spans)

        # Should match "HE"
        pronoun_spans = [s for s in result if s.text.lower() == "he"]
        assert len(pronoun_spans) >= 1

    def test_existing_pronoun_span_not_duplicated(self):
        """Existing pronoun spans are not duplicated."""
        text = "John Smith arrived. He was tired."
        spans = [
            make_span("John Smith", start=0, confidence=0.9),
            make_span("He", start=20, confidence=0.9),  # Already detected
        ]

        with patch.object(coref_module, '_check_onnx_available', return_value=False):
            result = coref_module.resolve_coreferences(text, spans)

        # Should not duplicate "He"
        he_spans = [s for s in result if s.text.lower() == "he"]
        assert len(he_spans) == 1

    def test_no_pronouns_in_text(self):
        """Text without pronouns returns original spans."""
        text = "John Smith arrived at the office."
        spans = [make_span("John Smith", start=0, confidence=0.9)]

        with patch.object(coref_module, '_check_onnx_available', return_value=False):
            result = coref_module.resolve_coreferences(text, spans)

        # No pronouns to expand
        assert len(result) == 1
