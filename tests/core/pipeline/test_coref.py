"""Tests for coreference resolution (rule-based fallback path).

Covers:
- Basic coreference chain detection and pronoun resolution
- Gender-aware pronoun matching
- Window constraints (sentence distance)
- Expansion cap per anchor
- Partial name linking
- Edge cases: no pronouns, single entity, empty input, no anchors
"""


from openlabels.core.pipeline.coref import (
    PRONOUNS,
    _cluster_mentions,
    _get_name_words,
    _get_sentence_index,
    _infer_gender,
    _link_partial_names,
    _normalize_name_for_matching,
    _pronoun_matches_gender,
    _resolve_with_rules,
    _split_sentences,
    _token_spans_to_char_spans,
    resolve_coreferences,
)
from openlabels.core.types import Span, Tier

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_name_span(
    text: str,
    start: int,
    confidence: float = 0.90,
    entity_type: str = "NAME",
    detector: str = "test",
    tier: Tier = Tier.PATTERN,
    **kwargs,
) -> Span:
    """Create a NAME-family span positioned within a document."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=tier,
        **kwargs,
    )


# ===========================================================================
# _split_sentences
# ===========================================================================

class TestSplitSentences:
    def test_single_sentence(self):
        text = "John went home"
        sentences = _split_sentences(text)
        assert len(sentences) == 1
        assert sentences[0][2] == text

    def test_two_sentences(self):
        text = "John went home. He was tired."
        sentences = _split_sentences(text)
        assert len(sentences) == 2

    def test_abbreviation_not_split(self):
        text = "Dr. Smith went home. He rested."
        sentences = _split_sentences(text)
        # "Dr." should not cause a sentence split
        assert len(sentences) == 2

    def test_empty_string(self):
        sentences = _split_sentences("")
        # Empty string has no sentence-ending punctuation and pos==0
        # equals len(text)==0, so the trailing segment is empty and
        # not appended.  The result is an empty list.
        assert len(sentences) == 0

    def test_multiple_punctuation(self):
        text = "Really?! She said so. OK."
        sentences = _split_sentences(text)
        assert len(sentences) >= 2


class TestGetSentenceIndex:
    def test_first_sentence(self):
        text = "First sentence. Second sentence."
        sentences = _split_sentences(text)
        assert _get_sentence_index(0, sentences) == 0

    def test_second_sentence(self):
        text = "First sentence. Second sentence."
        sentences = _split_sentences(text)
        second_start = text.index("Second")
        assert _get_sentence_index(second_start, sentences) == 1

    def test_position_past_end(self):
        text = "Hello world."
        sentences = _split_sentences(text)
        # Position past end returns last sentence index
        result = _get_sentence_index(9999, sentences)
        assert result == len(sentences) - 1


# ===========================================================================
# Gender inference
# ===========================================================================

class TestInferGender:
    def test_male_name(self):
        assert _infer_gender("John Smith") == "M"

    def test_female_name(self):
        assert _infer_gender("Mary Johnson") == "F"

    def test_unknown_name(self):
        assert _infer_gender("Skyler White") is None

    def test_title_stripped(self):
        # "Dr" is stripped, so the first actual word matters
        # "Dr." -> first word is "Dr." -> rstrip('.') -> "Dr" not in lists -> None
        assert _infer_gender("Dr. Smith") is None


class TestPronounMatchesGender:
    def test_male_pronoun_male_gender(self):
        assert _pronoun_matches_gender("he", "M") is True

    def test_male_pronoun_female_gender(self):
        assert _pronoun_matches_gender("he", "F") is False

    def test_female_pronoun_female_gender(self):
        assert _pronoun_matches_gender("she", "F") is True

    def test_female_pronoun_male_gender(self):
        assert _pronoun_matches_gender("she", "M") is False

    def test_neutral_pronoun_any_gender(self):
        assert _pronoun_matches_gender("they", "M") is True
        assert _pronoun_matches_gender("they", "F") is True
        assert _pronoun_matches_gender("them", None) is True

    def test_any_pronoun_unknown_gender(self):
        assert _pronoun_matches_gender("he", None) is True
        assert _pronoun_matches_gender("she", None) is True


# ===========================================================================
# Name word utilities
# ===========================================================================

class TestNameWordUtils:
    def test_normalize_name(self):
        assert _normalize_name_for_matching("  John Smith  ") == "john smith"

    def test_get_name_words_strips_titles(self):
        words = _get_name_words("Dr. John Smith Jr.")
        assert "john" in words
        assert "smith" in words
        assert "dr" not in words
        assert "jr" not in words

    def test_get_name_words_simple(self):
        words = _get_name_words("Alice Bob")
        assert words == {"alice", "bob"}


# ===========================================================================
# Rule-based pronoun resolution
# ===========================================================================

class TestResolveWithRules:
    """Test the rule-based pronoun resolver."""

    def test_empty_spans(self):
        result = _resolve_with_rules("Hello world", [], 2, 3, 0.85, 0.90)
        assert result == []

    def test_no_pronouns_returns_original(self):
        text = "John Smith works at the company."
        spans = [_make_name_span("John Smith", start=0)]
        result = _resolve_with_rules(text, spans, 2, 3, 0.85, 0.90)
        assert len(result) == 1
        assert result[0].text == "John Smith"

    def test_basic_pronoun_resolution(self):
        text = "John Smith went home. He was tired."
        anchor = _make_name_span("John Smith", start=0, confidence=0.90)
        result = _resolve_with_rules(text, [anchor], 2, 3, 0.85, 0.90)
        # Should find "He" pronoun and link it
        assert len(result) > 1
        pronoun_spans = [s for s in result if s.text.lower() in PRONOUNS]
        assert len(pronoun_spans) >= 1
        # Pronoun should reference the anchor
        for ps in pronoun_spans:
            assert ps.coref_anchor_value == "John Smith"
            assert ps.entity_type == "NAME"
            assert ps.detector == "coref_rules"
            assert ps.tier == Tier.ML

    def test_confidence_decay(self):
        text = "Mary Jones is a doctor. She treats patients."
        anchor = _make_name_span("Mary Jones", start=0, confidence=0.95)
        result = _resolve_with_rules(text, [anchor], 2, 3, 0.85, 0.90)
        pronoun_spans = [s for s in result if s.detector == "coref_rules"]
        for ps in pronoun_spans:
            # Confidence should be decayed from anchor
            assert ps.confidence <= anchor.confidence * 0.90

    def test_anchor_below_threshold_skipped(self):
        text = "John Smith went home. He was tired."
        # Anchor confidence below threshold (0.85)
        anchor = _make_name_span("John Smith", start=0, confidence=0.70)
        result = _resolve_with_rules(text, [anchor], 2, 3, 0.85, 0.90)
        # No expansions because anchor is below confidence threshold
        assert len(result) == 1

    def test_expansion_cap_per_anchor(self):
        text = "John Smith went to the park. He saw a bird. He picked it up. He smiled. He left."
        anchor = _make_name_span("John Smith", start=0, confidence=0.90)
        # max_expansions=2 should cap at 2 pronoun expansions
        result = _resolve_with_rules(text, [anchor], 5, 2, 0.85, 0.90)
        pronoun_spans = [s for s in result if s.detector == "coref_rules"]
        assert len(pronoun_spans) <= 2

    def test_window_constraint(self):
        # Sentences far apart should not be linked
        text = (
            "John Smith works here. "
            "The weather is nice today. "
            "It is very sunny outside. "
            "The birds are singing loudly. "
            "He went home."
        )
        anchor = _make_name_span("John Smith", start=0, confidence=0.90)
        # window_sentences=1 means only 1 sentence away
        result = _resolve_with_rules(text, [anchor], 1, 3, 0.85, 0.90)
        pronoun_spans = [s for s in result if s.detector == "coref_rules"]
        # "He" is many sentences away, so with window=1 it should not be linked
        assert len(pronoun_spans) == 0

    def test_pronoun_before_anchor_skipped(self):
        text = "He said hello. John Smith arrived."
        anchor_start = text.index("John Smith")
        anchor = _make_name_span("John Smith", start=anchor_start, confidence=0.90)
        result = _resolve_with_rules(text, [anchor], 2, 3, 0.85, 0.90)
        # "He" appears before the anchor, so it should NOT be resolved
        pronoun_spans = [s for s in result if s.detector == "coref_rules"]
        assert len(pronoun_spans) == 0

    def test_gender_mismatch_skipped(self):
        text = "John Smith went home. She was tired."
        anchor = _make_name_span("John Smith", start=0, confidence=0.90)
        result = _resolve_with_rules(text, [anchor], 2, 3, 0.85, 0.90)
        pronoun_spans = [s for s in result if s.detector == "coref_rules"]
        # "She" does not match male name "John", so no expansion
        assert len(pronoun_spans) == 0

    def test_single_entity_no_pronouns(self):
        text = "The report was filed by the department."
        anchor = _make_name_span("The report", start=0, confidence=0.90, entity_type="NAME")
        # No pronouns in text that match
        result = _resolve_with_rules(text, [anchor], 2, 3, 0.85, 0.90)
        assert len(result) == 1

    def test_non_name_types_ignored(self):
        text = "SSN 123-45-6789 is his number. He called."
        ssn_span = Span(
            start=4, end=15, text="123-45-6789",
            entity_type="SSN", confidence=0.95,
            detector="pattern", tier=Tier.CHECKSUM,
        )
        result = _resolve_with_rules(text, [ssn_span], 2, 3, 0.85, 0.90)
        # SSN is not a NAME type, so no coreference expansion
        assert len(result) == 1

    def test_result_sorted_by_start(self):
        text = "Mary Jones is great. She is smart."
        anchor = _make_name_span("Mary Jones", start=0, confidence=0.90)
        result = _resolve_with_rules(text, [anchor], 2, 3, 0.85, 0.90)
        starts = [s.start for s in result]
        assert starts == sorted(starts)

    def test_multiple_anchors_closest_wins(self):
        text = "John Smith said hello. Mary Jones arrived. She smiled."
        john_anchor = _make_name_span("John Smith", start=0, confidence=0.90)
        mary_start = text.index("Mary Jones")
        mary_anchor = _make_name_span("Mary Jones", start=mary_start, confidence=0.90)
        result = _resolve_with_rules(
            text, [john_anchor, mary_anchor], 2, 3, 0.85, 0.90
        )
        pronoun_spans = [s for s in result if s.detector == "coref_rules"]
        # "She" should be linked to "Mary Jones" (closer + gender match)
        for ps in pronoun_spans:
            if ps.text.lower() == "she":
                assert ps.coref_anchor_value == "Mary Jones"


# ===========================================================================
# Partial name linking
# ===========================================================================

class TestLinkPartialNames:
    def test_empty_input(self):
        assert _link_partial_names([]) == []

    def test_single_span_no_linking(self):
        spans = [_make_name_span("John Smith", start=0)]
        result = _link_partial_names(spans)
        assert len(result) == 1
        assert result[0].coref_anchor_value is None

    def test_full_and_partial_linked(self):
        text = "John Smith is here. Smith left."
        full = _make_name_span("John Smith", start=0, confidence=0.90)
        partial_start = text.index("Smith left")
        partial = _make_name_span("Smith", start=partial_start, confidence=0.85)
        result = _link_partial_names([full, partial], min_confidence=0.70)
        # The partial name "Smith" should be linked to "John Smith"
        linked = [s for s in result if s.coref_anchor_value is not None]
        assert len(linked) >= 1
        assert linked[0].coref_anchor_value == "John Smith"

    def test_no_shared_words_no_linking(self):
        spans = [
            _make_name_span("John Smith", start=0, confidence=0.90),
            _make_name_span("Mary Jones", start=20, confidence=0.90),
        ]
        result = _link_partial_names(spans, min_confidence=0.70)
        linked = [s for s in result if s.coref_anchor_value is not None]
        assert len(linked) == 0

    def test_below_min_confidence_skipped(self):
        spans = [
            _make_name_span("John Smith", start=0, confidence=0.90),
            _make_name_span("Smith", start=20, confidence=0.50),
        ]
        result = _link_partial_names(spans, min_confidence=0.70)
        # "Smith" at 0.50 is below min_confidence, so no linking
        linked = [s for s in result if s.coref_anchor_value is not None]
        assert len(linked) == 0

    def test_already_linked_not_overwritten(self):
        spans = [
            _make_name_span("John Smith", start=0, confidence=0.90),
            _make_name_span(
                "Smith", start=20, confidence=0.85,
                coref_anchor_value="Existing Anchor",
            ),
        ]
        result = _link_partial_names(spans, min_confidence=0.70)
        smith = [s for s in result if s.text == "Smith"][0]
        assert smith.coref_anchor_value == "Existing Anchor"


# ===========================================================================
# Cluster mentions (internal utility)
# ===========================================================================

class TestClusterMentions:
    def test_empty_mentions(self):
        result = _cluster_mentions([], None, threshold=0.0)
        assert result == []

    def test_single_mention_no_cluster(self):
        import numpy as np
        mentions = [(0, 2, 1.0)]
        scores = np.zeros((1, 1))
        result = _cluster_mentions(mentions, scores, threshold=0.0)
        # Single mention can't form a multi-member cluster
        assert result == []

    def test_two_linked_mentions(self):
        import numpy as np
        mentions = [(0, 2, 1.0), (3, 5, 0.8)]
        scores = np.array([[0.0, 0.0], [1.0, 0.0]])
        result = _cluster_mentions(mentions, scores, threshold=0.0)
        assert len(result) == 1
        assert len(result[0]) == 2


# ===========================================================================
# Token-to-char span conversion
# ===========================================================================

class TestTokenSpansToCharSpans:
    def test_basic_conversion(self):
        offset_mapping = [(0, 4), (5, 9), (10, 15)]
        token_spans = [(0, 1)]
        result = _token_spans_to_char_spans(token_spans, offset_mapping)
        assert result == [(0, 9)]

    def test_out_of_range_skipped(self):
        offset_mapping = [(0, 4), (5, 9)]
        token_spans = [(0, 10)]  # End index out of range
        result = _token_spans_to_char_spans(token_spans, offset_mapping)
        assert result == []

    def test_empty_input(self):
        result = _token_spans_to_char_spans([], [(0, 5)])
        assert result == []


# ===========================================================================
# Public API: resolve_coreferences
# ===========================================================================

class TestResolveCoreferences:
    def test_empty_text(self):
        result = resolve_coreferences("", [], use_onnx=False)
        assert result == []

    def test_empty_spans(self):
        result = resolve_coreferences("Some text here.", [], use_onnx=False)
        assert result == []

    def test_none_spans(self):
        result = resolve_coreferences("Some text", None, use_onnx=False)
        assert result == []

    def test_no_names_returns_original(self):
        text = "The report was filed."
        ssn = Span(
            start=0, end=3, text="The",
            entity_type="SSN", confidence=0.95,
            detector="pattern", tier=Tier.CHECKSUM,
        )
        result = resolve_coreferences(text, [ssn], use_onnx=False)
        assert len(result) == 1

    def test_basic_resolution_rule_based(self):
        text = "John Smith went home. He was tired."
        anchor = _make_name_span("John Smith", start=0, confidence=0.90)
        result = resolve_coreferences(text, [anchor], use_onnx=False)
        assert len(result) >= 1
        # At minimum, the original anchor should be preserved
        assert any(s.text == "John Smith" for s in result)

    def test_preserves_original_spans(self):
        text = "Jane Doe is here. She likes coffee. SSN: 123-45-6789."
        name = _make_name_span("Jane Doe", start=0, confidence=0.90)
        ssn_start = text.index("123-45-6789")
        ssn = Span(
            start=ssn_start, end=ssn_start + 11, text="123-45-6789",
            entity_type="SSN", confidence=0.99,
            detector="checksum", tier=Tier.CHECKSUM,
        )
        result = resolve_coreferences(text, [name, ssn], use_onnx=False)
        # Both original spans should be preserved
        assert any(s.text == "Jane Doe" for s in result)
        assert any(s.text == "123-45-6789" for s in result)
