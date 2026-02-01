"""
Comprehensive tests for the repeat finder pipeline component.

Tests repeat value expansion, word boundary checking, name type unification,
expansion limits, and the IntervalSet data structure.
"""

import pytest
from openlabels.adapters.scanner.pipeline.repeats import (
    expand_repeated_values,
    _unify_name_types,
    _has_overlap,
    IntervalSet,
    REPEAT_ELIGIBLE_TYPES,
    MAX_EXPANSIONS_PER_VALUE,
    NAME_TYPE_PRIORITY,
)
from openlabels.adapters.scanner.types import Span, Tier


def make_span(
    start: int,
    end: int,
    text: str,
    entity_type: str = "NAME",
    confidence: float = 0.9,
    detector: str = "test",
    tier: Tier = Tier.PATTERN,
) -> Span:
    """Helper to create test spans."""
    return Span(
        start=start,
        end=end,
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=tier,
    )


class TestIntervalSet:
    """Tests for the IntervalSet data structure."""

    def test_add_and_check_overlap_exact(self):
        """Test adding interval and checking exact overlap."""
        iset = IntervalSet()
        iset.add(10, 20)

        assert iset.overlaps(10, 20) is True

    def test_no_overlap_before(self):
        """Test no overlap when interval is before."""
        iset = IntervalSet()
        iset.add(10, 20)

        assert iset.overlaps(0, 5) is False

    def test_no_overlap_after(self):
        """Test no overlap when interval is after."""
        iset = IntervalSet()
        iset.add(10, 20)

        assert iset.overlaps(25, 30) is False

    def test_overlap_partial_start(self):
        """Test overlap when new interval starts before and ends inside."""
        iset = IntervalSet()
        iset.add(10, 20)

        assert iset.overlaps(5, 15) is True

    def test_overlap_partial_end(self):
        """Test overlap when new interval starts inside and ends after."""
        iset = IntervalSet()
        iset.add(10, 20)

        assert iset.overlaps(15, 25) is True

    def test_overlap_contained(self):
        """Test overlap when new interval is fully contained."""
        iset = IntervalSet()
        iset.add(10, 20)

        assert iset.overlaps(12, 18) is True

    def test_overlap_containing(self):
        """Test overlap when new interval fully contains existing."""
        iset = IntervalSet()
        iset.add(10, 20)

        assert iset.overlaps(5, 25) is True

    def test_empty_set_no_overlap(self):
        """Test empty set has no overlaps."""
        iset = IntervalSet()

        assert iset.overlaps(10, 20) is False

    def test_add_duplicate_ignored(self):
        """Test adding duplicate interval is ignored."""
        iset = IntervalSet()
        iset.add(10, 20)
        iset.add(10, 20)  # Duplicate

        # Should still work correctly
        assert iset.overlaps(10, 20) is True
        assert len(iset._intervals) == 1

    def test_multiple_intervals(self):
        """Test multiple non-overlapping intervals."""
        iset = IntervalSet()
        iset.add(0, 10)
        iset.add(20, 30)
        iset.add(40, 50)

        assert iset.overlaps(5, 8) is True
        assert iset.overlaps(12, 18) is False
        assert iset.overlaps(25, 28) is True
        assert iset.overlaps(32, 38) is False
        assert iset.overlaps(45, 48) is True

    def test_overlaps_fast(self):
        """Test fast overlap checking."""
        iset = IntervalSet()
        iset.add(10, 20)
        iset.add(30, 40)

        assert iset.overlaps_fast(15, 25) is True
        assert iset.overlaps_fast(22, 28) is False


class TestHasOverlap:
    """Tests for the _has_overlap function."""

    def test_empty_list(self):
        """Test empty range list has no overlaps."""
        assert _has_overlap([], 0, 10) is False

    def test_no_overlap_before(self):
        """Test no overlap when query is before all ranges."""
        ranges = [(10, 20), (30, 40)]
        assert _has_overlap(ranges, 0, 5) is False

    def test_no_overlap_after(self):
        """Test no overlap when query is after all ranges."""
        ranges = [(10, 20), (30, 40)]
        assert _has_overlap(ranges, 50, 60) is False

    def test_no_overlap_between(self):
        """Test no overlap when query is between ranges."""
        ranges = [(10, 20), (30, 40)]
        assert _has_overlap(ranges, 22, 28) is False

    def test_overlap_with_first(self):
        """Test overlap with first range."""
        ranges = [(10, 20), (30, 40)]
        assert _has_overlap(ranges, 15, 25) is True

    def test_overlap_with_last(self):
        """Test overlap with last range."""
        ranges = [(10, 20), (30, 40)]
        assert _has_overlap(ranges, 35, 45) is True

    def test_overlap_contained(self):
        """Test query contained in a range."""
        ranges = [(10, 30)]
        assert _has_overlap(ranges, 15, 25) is True


class TestUnifyNameTypes:
    """Tests for name type unification."""

    def test_empty_spans(self):
        """Test empty span list."""
        result = _unify_name_types([])
        assert result == []

    def test_single_span_unchanged(self):
        """Test single span is unchanged."""
        spans = [make_span(0, 10, "John Smith", "NAME")]
        result = _unify_name_types(spans)

        assert len(result) == 1
        assert result[0].entity_type == "NAME"

    def test_unifies_to_more_specific_type(self):
        """Test same value unifies to most specific type."""
        spans = [
            make_span(0, 10, "John Smith", "NAME"),
            make_span(50, 60, "John Smith", "NAME_PATIENT"),
        ]
        result = _unify_name_types(spans)

        assert len(result) == 2
        assert result[0].entity_type == "NAME_PATIENT"
        assert result[1].entity_type == "NAME_PATIENT"

    def test_preserves_different_values(self):
        """Test different values keep their types."""
        spans = [
            make_span(0, 10, "John Smith", "NAME"),
            make_span(50, 58, "Jane Doe", "NAME_PATIENT"),
        ]
        result = _unify_name_types(spans)

        assert result[0].entity_type == "NAME"
        assert result[1].entity_type == "NAME_PATIENT"

    def test_non_name_types_unchanged(self):
        """Test non-NAME types are not affected."""
        spans = [
            make_span(0, 11, "123-45-6789", "SSN"),
            make_span(50, 61, "123-45-6789", "SSN"),
        ]
        result = _unify_name_types(spans)

        assert result[0].entity_type == "SSN"
        assert result[1].entity_type == "SSN"


class TestExpandRepeatedValues:
    """Tests for the main repeat expansion function."""

    def test_empty_text(self):
        """Test empty text returns empty list."""
        result = expand_repeated_values("", [])
        assert result == []

    def test_empty_spans(self):
        """Test empty spans returns empty list."""
        result = expand_repeated_values("some text", [])
        assert result == []

    def test_no_repeats_found(self):
        """Test no expansion when value doesn't repeat."""
        text = "John Smith went to the store."
        spans = [make_span(0, 10, "John Smith", "NAME", 0.9)]
        result = expand_repeated_values(text, spans)

        assert len(result) == 1

    def test_finds_repeat(self):
        """Test finding repeated value."""
        text = "John Smith called John Smith back."
        spans = [make_span(0, 10, "John Smith", "NAME", 0.9)]
        result = expand_repeated_values(text, spans)

        assert len(result) == 2
        # Original + expanded
        texts = [s.text for s in result]
        assert texts.count("John Smith") == 2

    def test_expanded_span_attributes(self):
        """Test expanded span has correct attributes."""
        text = "John Smith met John Smith."
        spans = [make_span(0, 10, "John Smith", "NAME", 0.9)]
        result = expand_repeated_values(text, spans)

        expanded = [s for s in result if s.detector == "repeat_finder"]
        assert len(expanded) == 1
        assert expanded[0].entity_type == "NAME"
        assert expanded[0].tier == Tier.ML
        assert expanded[0].coref_anchor_value == "John Smith"

    def test_confidence_decay(self):
        """Test expanded spans have decayed confidence."""
        text = "John Smith met John Smith."
        spans = [make_span(0, 10, "John Smith", "NAME", 0.9)]
        result = expand_repeated_values(text, spans, confidence_decay=0.95)

        expanded = [s for s in result if s.detector == "repeat_finder"]
        assert expanded[0].confidence == 0.9 * 0.95

    def test_respects_min_confidence(self):
        """Test low confidence anchors are not used."""
        text = "John Smith met John Smith."
        spans = [make_span(0, 10, "John Smith", "NAME", 0.5)]  # Below threshold
        result = expand_repeated_values(text, spans, min_confidence=0.7)

        # Should not expand (anchor below threshold)
        assert len(result) == 1

    def test_respects_word_boundaries(self):
        """Test doesn't match partial words."""
        text = "John went to Johnson City."
        spans = [make_span(0, 4, "John", "NAME", 0.9)]
        result = expand_repeated_values(text, spans)

        # Should NOT match "John" inside "Johnson"
        assert len(result) == 1

    def test_skips_very_short_values(self):
        """Test very short values (< 3 chars) are skipped."""
        text = "Mr. Smith and Mr. Jones"
        spans = [make_span(0, 2, "Mr", "NAME", 0.9)]  # Too short
        result = expand_repeated_values(text, spans)

        assert len(result) == 1  # No expansion

    def test_skips_ineligible_types(self):
        """Test non-eligible types are not expanded."""
        text = "diabetes patient has diabetes"
        spans = [make_span(0, 8, "diabetes", "DIAGNOSIS", 0.9)]
        result = expand_repeated_values(text, spans)

        # DIAGNOSIS not in REPEAT_ELIGIBLE_TYPES
        assert len(result) == 1

    def test_expands_eligible_types(self):
        """Test eligible types are expanded."""
        text = "SSN 123-45-6789 repeated 123-45-6789"
        spans = [make_span(4, 15, "123-45-6789", "SSN", 0.95)]
        result = expand_repeated_values(text, spans)

        assert len(result) == 2

    def test_respects_max_expansions(self):
        """Test expansion cap is respected."""
        # Create text with many repeats
        value = "test_value"
        text = " ".join([value] * 100)
        spans = [make_span(0, len(value), value, "NAME", 0.9)]

        result = expand_repeated_values(
            text, spans, max_expansions_per_value=10
        )

        # Should be capped
        assert len(result) <= 11  # 1 original + up to 10 expansions

    def test_does_not_duplicate_existing(self):
        """Test doesn't create duplicates of existing spans."""
        text = "John Smith met John Smith."
        spans = [
            make_span(0, 10, "John Smith", "NAME", 0.9),
            make_span(15, 25, "John Smith", "NAME", 0.85),
        ]
        result = expand_repeated_values(text, spans)

        # Should not add third occurrence (both already covered)
        assert len(result) == 2

    def test_does_not_overlap_existing(self):
        """Test doesn't create spans overlapping existing ones."""
        text = "John Smith and Johnny."
        spans = [
            make_span(0, 10, "John Smith", "NAME", 0.9),
            make_span(15, 21, "Johnny", "NAME", 0.85),  # Overlaps potential "John"
        ]
        result = expand_repeated_values(text, spans)

        assert len(result) == 2

    def test_sorted_by_position(self):
        """Test result is sorted by position."""
        text = "Zoe met Amy and Zoe again."
        spans = [make_span(8, 11, "Amy", "NAME", 0.9)]

        # Note: "Amy" won't repeat but test sorting anyway
        result = expand_repeated_values(text, spans)

        positions = [s.start for s in result]
        assert positions == sorted(positions)


class TestRepeatEligibleTypes:
    """Tests for the REPEAT_ELIGIBLE_TYPES set."""

    def test_contains_names(self):
        """Test NAME types are eligible."""
        assert "NAME" in REPEAT_ELIGIBLE_TYPES
        assert "NAME_PATIENT" in REPEAT_ELIGIBLE_TYPES
        assert "NAME_PROVIDER" in REPEAT_ELIGIBLE_TYPES

    def test_contains_contact_info(self):
        """Test contact types are eligible."""
        assert "PHONE" in REPEAT_ELIGIBLE_TYPES
        assert "EMAIL" in REPEAT_ELIGIBLE_TYPES
        assert "FAX" in REPEAT_ELIGIBLE_TYPES

    def test_contains_ids(self):
        """Test ID types are eligible."""
        assert "SSN" in REPEAT_ELIGIBLE_TYPES
        assert "MRN" in REPEAT_ELIGIBLE_TYPES
        assert "NPI" in REPEAT_ELIGIBLE_TYPES

    def test_contains_financial(self):
        """Test financial types are eligible."""
        assert "CREDIT_CARD" in REPEAT_ELIGIBLE_TYPES
        assert "IBAN" in REPEAT_ELIGIBLE_TYPES

    def test_is_frozenset(self):
        """Test REPEAT_ELIGIBLE_TYPES is immutable."""
        assert isinstance(REPEAT_ELIGIBLE_TYPES, frozenset)


class TestNameTypePriority:
    """Tests for NAME_TYPE_PRIORITY mapping."""

    def test_specific_types_higher_priority(self):
        """Test specific name types have higher priority."""
        assert NAME_TYPE_PRIORITY["NAME_PATIENT"] > NAME_TYPE_PRIORITY["NAME"]
        assert NAME_TYPE_PRIORITY["NAME_PROVIDER"] > NAME_TYPE_PRIORITY["NAME"]

    def test_generic_name_lowest(self):
        """Test generic NAME has lowest priority."""
        assert NAME_TYPE_PRIORITY["NAME"] == 1


class TestExpandIntegration:
    """Integration tests for repeat expansion."""

    def test_multiple_different_values(self):
        """Test expanding multiple different values."""
        text = "John Smith and Jane Doe. Later John Smith met Jane Doe."
        spans = [
            make_span(0, 10, "John Smith", "NAME", 0.9),
            make_span(15, 23, "Jane Doe", "NAME", 0.9),
        ]
        result = expand_repeated_values(text, spans)

        # Should find repeats of both
        john_spans = [s for s in result if s.text == "John Smith"]
        jane_spans = [s for s in result if s.text == "Jane Doe"]

        assert len(john_spans) == 2
        assert len(jane_spans) == 2

    def test_case_sensitive_matching(self):
        """Test matching is case sensitive."""
        text = "John Smith and john smith"
        spans = [make_span(0, 10, "John Smith", "NAME", 0.9)]
        result = expand_repeated_values(text, spans)

        # "john smith" (lowercase) should NOT match "John Smith"
        assert len(result) == 1

    def test_ssn_expansion(self):
        """Test SSN value expansion."""
        text = "SSN: 123-45-6789. Confirmed: 123-45-6789"
        spans = [make_span(5, 16, "123-45-6789", "SSN", 0.98)]
        result = expand_repeated_values(text, spans)

        assert len(result) == 2
        assert all(s.entity_type == "SSN" for s in result)
