"""Tests for repeat finder in repeats.py.

Tests propagation of detected PHI to identical strings, interval
overlap checking, name type unification, and expansion limits.
"""

import pytest
from scrubiq.types import Span, Tier
from scrubiq.pipeline.repeats import (
    IntervalSet,
    expand_repeated_values,
    _has_overlap,
    _unify_name_types,
    REPEAT_ELIGIBLE_TYPES,
    NAME_TYPE_PRIORITY,
    MAX_EXPANSIONS_PER_VALUE,
)


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


# =============================================================================
# CONSTANTS TESTS
# =============================================================================

class TestConstants:
    """Tests for module constants."""

    def test_repeat_eligible_types_includes_names(self):
        """NAME types are eligible for repeat expansion."""
        assert "NAME" in REPEAT_ELIGIBLE_TYPES
        assert "NAME_PATIENT" in REPEAT_ELIGIBLE_TYPES
        assert "NAME_PROVIDER" in REPEAT_ELIGIBLE_TYPES
        assert "NAME_RELATIVE" in REPEAT_ELIGIBLE_TYPES

    def test_repeat_eligible_types_includes_identifiers(self):
        """ID types are eligible for repeat expansion."""
        assert "SSN" in REPEAT_ELIGIBLE_TYPES
        assert "MRN" in REPEAT_ELIGIBLE_TYPES
        assert "PHONE" in REPEAT_ELIGIBLE_TYPES
        assert "EMAIL" in REPEAT_ELIGIBLE_TYPES

    def test_repeat_eligible_types_excludes_context(self):
        """Context-only types are NOT eligible."""
        assert "DRUG" not in REPEAT_ELIGIBLE_TYPES
        assert "DIAGNOSIS" not in REPEAT_ELIGIBLE_TYPES
        assert "DATE" not in REPEAT_ELIGIBLE_TYPES
        assert "AGE" not in REPEAT_ELIGIBLE_TYPES

    def test_repeat_eligible_types_is_frozenset(self):
        """REPEAT_ELIGIBLE_TYPES is immutable."""
        assert isinstance(REPEAT_ELIGIBLE_TYPES, frozenset)

    def test_name_type_priority_ranking(self):
        """Specific NAME types have higher priority than generic NAME."""
        assert NAME_TYPE_PRIORITY["NAME_PATIENT"] > NAME_TYPE_PRIORITY["NAME"]
        assert NAME_TYPE_PRIORITY["NAME_PROVIDER"] > NAME_TYPE_PRIORITY["NAME"]
        assert NAME_TYPE_PRIORITY["NAME_RELATIVE"] > NAME_TYPE_PRIORITY["NAME"]

    def test_max_expansions_per_value_is_reasonable(self):
        """MAX_EXPANSIONS_PER_VALUE is set to prevent O(n²)."""
        assert MAX_EXPANSIONS_PER_VALUE > 0
        assert MAX_EXPANSIONS_PER_VALUE <= 100


# =============================================================================
# INTERVAL SET TESTS
# =============================================================================

class TestIntervalSet:
    """Tests for IntervalSet class."""

    def test_empty_no_overlap(self):
        """Empty set has no overlaps."""
        iset = IntervalSet()
        assert not iset.overlaps(0, 10)

    def test_add_interval(self):
        """Can add intervals."""
        iset = IntervalSet()
        iset.add(0, 10)
        assert iset.overlaps(0, 10)

    def test_exact_match_overlaps(self):
        """Exact match is detected as overlap."""
        iset = IntervalSet()
        iset.add(5, 15)
        assert iset.overlaps(5, 15)

    def test_partial_overlap_detected(self):
        """Partial overlap is detected."""
        iset = IntervalSet()
        iset.add(5, 15)
        # Overlaps on left
        assert iset.overlaps(0, 10)
        # Overlaps on right
        assert iset.overlaps(10, 20)

    def test_contained_interval_overlaps(self):
        """Interval contained within existing overlaps."""
        iset = IntervalSet()
        iset.add(0, 20)
        assert iset.overlaps(5, 15)

    def test_containing_interval_overlaps(self):
        """Interval containing existing overlaps."""
        iset = IntervalSet()
        iset.add(5, 15)
        assert iset.overlaps(0, 20)

    def test_adjacent_no_overlap(self):
        """Adjacent intervals don't overlap ([5,10) and [10,15))."""
        iset = IntervalSet()
        iset.add(5, 10)
        assert not iset.overlaps(10, 15)

    def test_no_overlap_before(self):
        """Interval before existing doesn't overlap."""
        iset = IntervalSet()
        iset.add(20, 30)
        assert not iset.overlaps(5, 15)

    def test_no_overlap_after(self):
        """Interval after existing doesn't overlap."""
        iset = IntervalSet()
        iset.add(5, 15)
        assert not iset.overlaps(20, 30)

    def test_duplicate_add_no_error(self):
        """Adding same interval twice is idempotent."""
        iset = IntervalSet()
        iset.add(5, 15)
        iset.add(5, 15)
        assert iset.overlaps(5, 15)

    def test_multiple_intervals(self):
        """Multiple intervals tracked correctly."""
        iset = IntervalSet()
        iset.add(0, 10)
        iset.add(20, 30)
        iset.add(40, 50)

        # Should overlap
        assert iset.overlaps(5, 15)
        assert iset.overlaps(25, 35)
        assert iset.overlaps(35, 45)

        # Should not overlap
        assert not iset.overlaps(10, 20)
        assert not iset.overlaps(30, 40)
        assert not iset.overlaps(50, 60)


class TestIntervalSetFast:
    """Tests for IntervalSet.overlaps_fast() method."""

    def test_empty_no_overlap(self):
        """Empty set has no overlaps."""
        iset = IntervalSet()
        assert not iset.overlaps_fast(0, 10)

    def test_exact_match_overlaps(self):
        """Exact match is detected as overlap."""
        iset = IntervalSet()
        iset.add(5, 15)
        assert iset.overlaps_fast(5, 15)

    def test_partial_overlap_detected(self):
        """Partial overlap is detected."""
        iset = IntervalSet()
        iset.add(5, 15)
        assert iset.overlaps_fast(0, 10)
        assert iset.overlaps_fast(10, 20)

    def test_no_overlap_adjacent(self):
        """Adjacent intervals don't overlap."""
        iset = IntervalSet()
        iset.add(5, 10)
        assert not iset.overlaps_fast(10, 15)


# =============================================================================
# _HAS_OVERLAP TESTS
# =============================================================================

class TestHasOverlap:
    """Tests for _has_overlap() function."""

    def test_empty_list_no_overlap(self):
        """Empty list has no overlaps."""
        assert not _has_overlap([], 0, 10)

    def test_exact_match_overlaps(self):
        """Exact match is detected."""
        ranges = [(5, 15)]
        assert _has_overlap(ranges, 5, 15)

    def test_partial_overlap_left(self):
        """Overlap on left side detected."""
        ranges = [(5, 15)]
        assert _has_overlap(ranges, 0, 10)

    def test_partial_overlap_right(self):
        """Overlap on right side detected."""
        ranges = [(5, 15)]
        assert _has_overlap(ranges, 10, 20)

    def test_contained_overlaps(self):
        """Smaller interval inside larger is overlap."""
        ranges = [(0, 20)]
        assert _has_overlap(ranges, 5, 15)

    def test_containing_overlaps(self):
        """Larger interval containing smaller is overlap."""
        ranges = [(5, 15)]
        assert _has_overlap(ranges, 0, 20)

    def test_adjacent_no_overlap(self):
        """Adjacent intervals don't overlap."""
        ranges = [(5, 10)]
        assert not _has_overlap(ranges, 10, 15)

    def test_before_no_overlap(self):
        """Interval before existing doesn't overlap."""
        ranges = [(20, 30)]
        assert not _has_overlap(ranges, 5, 10)

    def test_after_no_overlap(self):
        """Interval after existing doesn't overlap."""
        ranges = [(5, 10)]
        assert not _has_overlap(ranges, 20, 30)

    def test_multiple_ranges_first_overlaps(self):
        """First of multiple ranges can overlap."""
        ranges = [(0, 10), (20, 30), (40, 50)]
        assert _has_overlap(ranges, 5, 15)

    def test_multiple_ranges_middle_overlaps(self):
        """Middle of multiple ranges can overlap."""
        ranges = [(0, 10), (20, 30), (40, 50)]
        assert _has_overlap(ranges, 15, 25)

    def test_multiple_ranges_last_overlaps(self):
        """Last of multiple ranges can overlap."""
        ranges = [(0, 10), (20, 30), (40, 50)]
        assert _has_overlap(ranges, 35, 45)

    def test_gap_no_overlap(self):
        """Gap between ranges doesn't overlap."""
        ranges = [(0, 10), (20, 30)]
        assert not _has_overlap(ranges, 12, 18)


# =============================================================================
# _UNIFY_NAME_TYPES TESTS
# =============================================================================

class TestUnifyNameTypes:
    """Tests for _unify_name_types() function."""

    def test_empty_list(self):
        """Empty list returns empty."""
        assert _unify_name_types([]) == []

    def test_single_span_unchanged(self):
        """Single span unchanged."""
        spans = [make_span("John", entity_type="NAME")]
        result = _unify_name_types(spans)
        assert len(result) == 1
        assert result[0].entity_type == "NAME"

    def test_same_type_unchanged(self):
        """Same value with same type unchanged."""
        spans = [
            make_span("John", start=0, entity_type="NAME"),
            make_span("John", start=10, entity_type="NAME"),
        ]
        result = _unify_name_types(spans)
        assert all(s.entity_type == "NAME" for s in result)

    def test_upgrades_to_specific_type(self):
        """Generic NAME upgraded to specific NAME_PATIENT."""
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("John Smith", start=20, entity_type="NAME_PATIENT"),
        ]
        result = _unify_name_types(spans)
        assert all(s.entity_type == "NAME_PATIENT" for s in result)

    def test_upgrades_to_provider_type(self):
        """Generic NAME upgraded to NAME_PROVIDER."""
        spans = [
            make_span("Dr. Brown", start=0, entity_type="NAME"),
            make_span("Dr. Brown", start=20, entity_type="NAME_PROVIDER"),
        ]
        result = _unify_name_types(spans)
        assert all(s.entity_type == "NAME_PROVIDER" for s in result)

    def test_upgrades_to_relative_type(self):
        """Generic NAME upgraded to NAME_RELATIVE."""
        spans = [
            make_span("Jane Smith", start=0, entity_type="NAME_RELATIVE"),
            make_span("Jane Smith", start=20, entity_type="NAME"),
        ]
        result = _unify_name_types(spans)
        assert all(s.entity_type == "NAME_RELATIVE" for s in result)

    def test_non_name_types_unchanged(self):
        """Non-NAME types are not unified."""
        spans = [
            make_span("12345", start=0, entity_type="MRN"),
            make_span("12345", start=20, entity_type="ENCOUNTER_ID"),
        ]
        result = _unify_name_types(spans)
        assert result[0].entity_type == "MRN"
        assert result[1].entity_type == "ENCOUNTER_ID"

    def test_preserves_other_fields(self):
        """Unification preserves other span fields."""
        spans = [
            Span(
                start=0, end=10, text="John Smith",
                entity_type="NAME", confidence=0.85,
                detector="bert", tier=Tier.ML,
            ),
            Span(
                start=20, end=30, text="John Smith",
                entity_type="NAME_PATIENT", confidence=0.95,
                detector="structured", tier=Tier.STRUCTURED,
            ),
        ]
        result = _unify_name_types(spans)

        # First span should be upgraded but keep original metadata
        assert result[0].entity_type == "NAME_PATIENT"
        assert result[0].confidence == 0.85
        assert result[0].detector == "bert"
        assert result[0].tier == Tier.ML

    def test_different_values_not_unified(self):
        """Different values are not unified."""
        spans = [
            make_span("John", start=0, entity_type="NAME"),
            make_span("Jane", start=10, entity_type="NAME_PATIENT"),
        ]
        result = _unify_name_types(spans)
        assert result[0].entity_type == "NAME"
        assert result[1].entity_type == "NAME_PATIENT"


# =============================================================================
# EXPAND_REPEATED_VALUES TESTS
# =============================================================================

class TestExpandRepeatedValues:
    """Tests for expand_repeated_values() function."""

    def test_empty_text_returns_empty(self):
        """Empty text returns empty list."""
        result = expand_repeated_values("", [])
        assert result == []

    def test_no_spans_returns_empty(self):
        """No spans returns empty list."""
        result = expand_repeated_values("Some text", [])
        assert result == []

    def test_single_occurrence_unchanged(self):
        """Single occurrence returns original span only."""
        text = "Hello John Smith how are you"
        spans = [make_span("John Smith", start=6)]
        result = expand_repeated_values(text, spans)

        assert len(result) == 1
        assert result[0].start == 6

    def test_finds_second_occurrence(self):
        """Finds second occurrence of same value."""
        text = "John Smith met John Smith at lunch"
        spans = [make_span("John Smith", start=0)]
        result = expand_repeated_values(text, spans)

        assert len(result) == 2
        assert result[0].start == 0
        assert result[1].start == 15

    def test_expanded_span_has_correct_properties(self):
        """Expanded span inherits entity_type from anchor."""
        text = "John Smith met John Smith at lunch"
        spans = [make_span("John Smith", start=0, entity_type="NAME_PATIENT")]
        result = expand_repeated_values(text, spans)

        expanded = result[1]
        assert expanded.entity_type == "NAME_PATIENT"
        assert expanded.text == "John Smith"
        assert expanded.detector == "repeat_finder"
        assert expanded.coref_anchor_value == "John Smith"

    def test_confidence_decays(self):
        """Expanded spans have decayed confidence."""
        text = "John Smith met John Smith at lunch"
        spans = [make_span("John Smith", start=0, confidence=0.9)]
        result = expand_repeated_values(text, spans, confidence_decay=0.95)

        expanded = result[1]
        assert expanded.confidence == pytest.approx(0.9 * 0.95)

    def test_low_confidence_anchor_skipped(self):
        """Low confidence anchors are not used for expansion."""
        text = "John Smith met John Smith at lunch"
        spans = [make_span("John Smith", start=0, confidence=0.5)]
        result = expand_repeated_values(text, spans, min_confidence=0.7)

        # Only original span, no expansion
        assert len(result) == 1

    def test_ineligible_type_not_expanded(self):
        """Ineligible entity types are not expanded."""
        text = "aspirin then aspirin"
        spans = [make_span("aspirin", start=0, entity_type="DRUG")]
        result = expand_repeated_values(text, spans)

        # No expansion for DRUG type
        assert len(result) == 1

    def test_short_values_not_expanded(self):
        """Values shorter than 3 chars are not expanded."""
        text = "JD met JD today"
        spans = [make_span("JD", start=0)]
        result = expand_repeated_values(text, spans)

        assert len(result) == 1

    def test_respects_word_boundaries(self):
        """Doesn't match partial words (e.g., 'John' in 'Johnson')."""
        text = "John met Johnson yesterday"
        spans = [make_span("John", start=0)]
        result = expand_repeated_values(text, spans)

        # Should NOT match 'John' in 'Johnson'
        assert len(result) == 1

    def test_finds_phone_repeats(self):
        """Finds repeated phone numbers."""
        text = "Call 555-1234 or call 555-1234"
        spans = [make_span("555-1234", start=5, entity_type="PHONE")]
        result = expand_repeated_values(text, spans)

        assert len(result) == 2
        assert result[1].entity_type == "PHONE"

    def test_finds_ssn_repeats(self):
        """Finds repeated SSNs."""
        text = "SSN: 123-45-6789. Verify SSN: 123-45-6789"
        spans = [make_span("123-45-6789", start=5, entity_type="SSN")]
        result = expand_repeated_values(text, spans)

        assert len(result) == 2

    def test_multiple_different_values(self):
        """Finds repeats for multiple different values."""
        text = "John Smith has SSN 123-45-6789. John Smith SSN is 123-45-6789"
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("123-45-6789", start=19, entity_type="SSN"),
        ]
        result = expand_repeated_values(text, spans)

        # Should find both repeated
        assert len(result) == 4

    def test_already_covered_not_duplicated(self):
        """Already detected spans are not duplicated."""
        text = "John Smith met John Smith"
        spans = [
            make_span("John Smith", start=0),
            make_span("John Smith", start=15),
        ]
        result = expand_repeated_values(text, spans)

        # Should not create duplicates
        assert len(result) == 2

    def test_overlapping_span_not_created(self):
        """Don't create span that overlaps existing."""
        text = "John Smith is here"
        spans = [
            make_span("John Smith", start=0),
            make_span("Smith", start=5),  # Overlaps
        ]
        result = expand_repeated_values(text, spans)

        # No new overlapping spans created
        assert len(result) == 2

    def test_results_sorted_by_position(self):
        """Results are sorted by start position."""
        text = "John Smith then Jane Doe then John Smith"
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("Jane Doe", start=16, entity_type="NAME"),
        ]
        result = expand_repeated_values(text, spans)

        # Verify sorted order
        for i in range(len(result) - 1):
            assert result[i].start <= result[i + 1].start

    def test_unifies_name_types_after_expansion(self):
        """Name types are unified after expansion."""
        text = "John Smith is a patient. John Smith"
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
        ]
        result = expand_repeated_values(text, spans)

        # Both should have same entity_type
        assert result[0].entity_type == result[1].entity_type

    def test_max_expansions_cap(self):
        """Expansion is capped at max_expansions_per_value."""
        # Create text with 100 occurrences
        value = "John Smith"
        text = " ".join([value] * 100)
        spans = [make_span(value, start=0)]

        result = expand_repeated_values(text, spans, max_expansions_per_value=5)

        # Should be capped: 1 original + 5 expansions = 6
        assert len(result) <= 6

    def test_case_sensitive_matching(self):
        """Matching is case-sensitive."""
        text = "John Smith and john smith"
        spans = [make_span("John Smith", start=0)]
        result = expand_repeated_values(text, spans)

        # Should NOT match lowercase version
        assert len(result) == 1

    def test_finds_at_text_end(self):
        """Finds occurrences at end of text."""
        text = "Hello John Smith"
        spans = [make_span("John Smith", start=6)]
        result = expand_repeated_values(text, spans)

        # Just the one occurrence
        assert len(result) == 1

    def test_finds_at_text_start(self):
        """Finds occurrences at start of text."""
        text = "John Smith is here and later John Smith"
        spans = [make_span("John Smith", start=30)]
        result = expand_repeated_values(text, spans)

        assert len(result) == 2
        assert result[0].start == 0  # Found at start

    def test_preserves_original_spans(self):
        """Original spans are preserved unchanged."""
        text = "John Smith met John Smith"
        original = make_span("John Smith", start=0, confidence=0.95, detector="bert")
        result = expand_repeated_values(text, [original])

        # First span should be original
        assert result[0].detector == "bert"
        assert result[0].confidence == 0.95


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for repeat finder."""

    def test_none_text_handled(self):
        """None text returns original spans (via falsy check)."""
        # The function checks "if not text" which covers None
        spans = [make_span("John", start=0)]
        result = expand_repeated_values(None, spans)
        # When text is falsy, returns original spans as-is
        assert len(result) == 1
        assert result[0].text == "John"

    def test_none_spans_handled(self):
        """None spans returns empty list."""
        result = expand_repeated_values("text", None)
        assert result == []

    def test_whitespace_only_text(self):
        """Whitespace text returns original spans."""
        spans = [make_span("John", start=0)]
        result = expand_repeated_values("   ", spans)
        assert len(result) == 1

    def test_special_characters_in_value(self):
        """Values with special chars are matched literally."""
        text = "user@email.com and user@email.com"
        spans = [make_span("user@email.com", start=0, entity_type="EMAIL")]
        result = expand_repeated_values(text, spans)

        assert len(result) == 2

    def test_longer_matches_first(self):
        """Longer values are matched before shorter ones."""
        text = "John Smith Jr. called. John Smith Jr. is here. John Smith also"
        spans = [
            make_span("John Smith Jr.", start=0, entity_type="NAME"),
            make_span("John Smith", start=47, entity_type="NAME"),
        ]
        result = expand_repeated_values(text, spans)

        # "John Smith Jr." should be found twice
        jr_spans = [s for s in result if "Jr." in s.text]
        assert len(jr_spans) == 2

    def test_adjacent_occurrences(self):
        """Adjacent occurrences with separator are found."""
        text = "John,John,John"
        spans = [make_span("John", start=0)]
        result = expand_repeated_values(text, spans)

        assert len(result) == 3

    def test_exact_boundary_match(self):
        """Match at exact word boundary."""
        text = "(John Smith)"
        spans = [make_span("John Smith", start=1)]
        result = expand_repeated_values(text, spans)

        assert len(result) == 1

    def test_numeric_identifiers(self):
        """Numeric identifiers like MRN are expanded."""
        text = "MRN: 12345678 and MRN: 12345678"
        spans = [make_span("12345678", start=5, entity_type="MRN")]
        result = expand_repeated_values(text, spans)

        assert len(result) == 2


# =============================================================================
# PERFORMANCE / SAFETY TESTS
# =============================================================================

class TestPerformanceSafety:
    """Tests for performance and safety features."""

    def test_expansion_cap_prevents_explosion(self):
        """Expansion cap prevents pathological O(n²) cases."""
        # A name repeated 1000 times
        value = "Test Name"
        text = " ".join([value] * 1000)
        spans = [make_span(value, start=0)]

        # Should complete quickly due to cap
        result = expand_repeated_values(text, spans)

        # Should be capped
        assert len(result) <= MAX_EXPANSIONS_PER_VALUE + 1

    def test_multiple_values_each_capped(self):
        """Each unique value has its own expansion cap."""
        name1 = "John Smith"
        name2 = "Jane Doe"
        text = " ".join([name1, name2] * 100)
        spans = [
            make_span(name1, start=0),
            make_span(name2, start=11),
        ]

        result = expand_repeated_values(text, spans, max_expansions_per_value=5)

        # Each value capped separately
        name1_count = sum(1 for s in result if s.text == name1)
        name2_count = sum(1 for s in result if s.text == name2)
        assert name1_count <= 6  # 1 original + 5 expansions
        assert name2_count <= 6

    def test_binary_search_overlap_efficiency(self):
        """Overlap checking uses efficient binary search."""
        # Many non-overlapping spans
        text = "x" * 10000
        spans = [make_span("test", start=i * 20) for i in range(100)]

        # Should complete quickly
        result = expand_repeated_values(text, spans)

        # Original spans returned
        assert len(result) >= 100
