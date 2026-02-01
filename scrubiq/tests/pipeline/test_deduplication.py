"""Tests for span deduplication in merger.py.

Tests containment removal and exact deduplication logic.
"""

import pytest
from scrubiq.types import Span, Tier
from scrubiq.pipeline.merger import remove_contained_spans, types_compatible


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


class TestRemoveContainedSpans:
    """Tests for remove_contained_spans()."""

    def test_smaller_span_inside_larger_removed(self):
        """Smaller span fully contained in larger compatible span is removed."""
        # "K." is contained in "K. Edwards, DNP"
        spans = [
            make_span("K. Edwards, DNP", start=0, entity_type="NAME", tier=2),
            make_span("K.", start=0, entity_type="NAME", tier=1),
        ]
        result = remove_contained_spans(spans)

        assert len(result) == 1
        assert result[0].text == "K. Edwards, DNP"

    def test_non_contained_spans_kept(self):
        """Non-overlapping spans are all kept."""
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("Jane Doe", start=20, entity_type="NAME"),
        ]
        result = remove_contained_spans(spans)

        assert len(result) == 2

    def test_overlapping_but_not_contained_kept(self):
        """Overlapping but not fully contained spans are both kept."""
        # "John Smi" and "Smith" overlap but neither contains the other
        spans = [
            make_span("John Smi", start=0, entity_type="NAME"),
            make_span("Smith", start=5, entity_type="NAME"),
        ]
        result = remove_contained_spans(spans)

        assert len(result) == 2

    def test_incompatible_types_both_kept(self):
        """Contained span with incompatible type is kept."""
        # "123" is contained in "MRN: 123456" but different types
        spans = [
            make_span("MRN: 123456", start=0, entity_type="MRN"),
            make_span("123", start=5, entity_type="SSN"),  # Incompatible type
        ]
        result = remove_contained_spans(spans)

        # SSN is not compatible with MRN, so both kept
        assert len(result) == 2

    def test_compatible_types_deduplicated(self):
        """Contained span with compatible type is removed."""
        # "John" is contained in "John Smith", both NAME types
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("John", start=0, entity_type="NAME_PATIENT"),  # Compatible
        ]
        result = remove_contained_spans(spans)

        assert len(result) == 1
        assert result[0].text == "John Smith"

    def test_higher_tier_wins_for_equal_length(self):
        """For equal length spans, higher tier is preferred."""
        spans = [
            make_span("John Smith", start=0, entity_type="NAME", tier=1),  # ML
            make_span("John Smith", start=0, entity_type="NAME", tier=3),  # STRUCTURED
        ]
        result = remove_contained_spans(spans)

        assert len(result) == 1
        assert result[0].tier == Tier.STRUCTURED

    def test_higher_confidence_wins_for_equal_tier(self):
        """For equal tier, higher confidence is preferred."""
        spans = [
            make_span("John Smith", start=0, entity_type="NAME", tier=2, confidence=0.7),
            make_span("John Smith", start=0, entity_type="NAME", tier=2, confidence=0.95),
        ]
        result = remove_contained_spans(spans)

        assert len(result) == 1
        assert result[0].confidence == 0.95

    def test_nested_containment(self):
        """Multiple levels of containment are handled."""
        # "K." inside "K. Smith" inside "Dr. K. Smith, MD"
        spans = [
            make_span("Dr. K. Smith, MD", start=0, entity_type="NAME"),
            make_span("K. Smith", start=4, entity_type="NAME"),
            make_span("K.", start=4, entity_type="NAME"),
        ]
        result = remove_contained_spans(spans)

        assert len(result) == 1
        assert result[0].text == "Dr. K. Smith, MD"

    def test_single_span_unchanged(self):
        """Single span is returned unchanged."""
        spans = [make_span("John Smith", start=0)]
        result = remove_contained_spans(spans)

        assert len(result) == 1
        assert result[0].text == "John Smith"

    def test_empty_list_returns_empty(self):
        """Empty input returns empty output."""
        result = remove_contained_spans([])
        assert result == []

    def test_exact_same_boundaries_keeps_one(self):
        """Spans with exact same boundaries keeps higher authority."""
        spans = [
            make_span("John Smith", start=0, entity_type="NAME", tier=1, confidence=0.8),
            make_span("John Smith", start=0, entity_type="NAME", tier=2, confidence=0.9),
        ]
        result = remove_contained_spans(spans)

        assert len(result) == 1
        assert result[0].tier == Tier.PATTERN
        assert result[0].confidence == 0.9


class TestContainmentWithIntervalTree:
    """Tests that verify behavior regardless of IntervalTree availability."""

    def test_large_span_count_handled(self):
        """Large numbers of spans are handled correctly."""
        # Create 200 non-overlapping spans
        spans = [
            make_span(f"Name{i}", start=i * 20, entity_type="NAME")
            for i in range(200)
        ]
        result = remove_contained_spans(spans)

        # All should be kept (no containment)
        assert len(result) == 200

    def test_many_contained_spans(self):
        """Many contained spans within one large span."""
        # One large span containing many small ones
        large_span = make_span("A" * 100, start=0, entity_type="NAME", tier=3)
        small_spans = [
            make_span("A" * 5, start=i * 10, entity_type="NAME", tier=1)
            for i in range(10)
        ]

        result = remove_contained_spans([large_span] + small_spans)

        # Only the large span should remain
        assert len(result) == 1
        assert result[0].text == "A" * 100


class TestExactDeduplication:
    """Tests for exact deduplication (same start, end, type).

    This tests the deduplication logic in merge_spans() step 7.
    We test it indirectly through the merge_spans function.
    """

    def test_exact_duplicates_deduplicated(self):
        """Exact same position and type keeps highest tier."""
        from scrubiq.pipeline.merger import merge_spans

        text = "John Smith is here"
        spans = [
            make_span("John Smith", start=0, entity_type="NAME", tier=1, confidence=0.7),
            make_span("John Smith", start=0, entity_type="NAME", tier=2, confidence=0.9),
            make_span("John Smith", start=0, entity_type="NAME", tier=1, confidence=0.8),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 1
        assert result[0].tier == Tier.PATTERN  # tier 2
        assert result[0].confidence == 0.9

    def test_different_types_not_deduplicated(self):
        """Same position but different types are NOT deduplicated."""
        from scrubiq.pipeline.merger import merge_spans

        text = "123456789 is the number"
        spans = [
            make_span("123456789", start=0, entity_type="SSN", tier=2, confidence=0.9),
            make_span("123456789", start=0, entity_type="MRN", tier=2, confidence=0.85),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        # Both should survive exact dedup (different types)
        # But greedy selection will pick one (first by authority)
        assert len(result) == 1

    def test_different_positions_not_deduplicated(self):
        """Same type but different positions are NOT deduplicated."""
        from scrubiq.pipeline.merger import merge_spans

        text = "John Smith and John Smith"
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("John Smith", start=15, entity_type="NAME"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 2


class TestGreedySelection:
    """Tests for greedy non-overlapping selection (merge_spans step 14)."""

    def test_overlapping_spans_highest_authority_wins(self):
        """Overlapping spans: highest authority wins."""
        from scrubiq.pipeline.merger import merge_spans

        text = "Dr. John Smith, MD is here"
        spans = [
            make_span("John Smith", start=4, entity_type="NAME", tier=1, confidence=0.7),
            make_span("Dr. John Smith, MD", start=0, entity_type="NAME", tier=2, confidence=0.9),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 1
        assert result[0].text == "Dr. John Smith, MD"

    def test_non_overlapping_all_kept(self):
        """Non-overlapping spans are all kept."""
        from scrubiq.pipeline.merger import merge_spans

        text = "John Smith lives at 123 Main St"
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("123 Main St", start=20, entity_type="ADDRESS"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 2

    def test_authority_order_tier_confidence_length(self):
        """Authority ranking: tier > confidence > length for overlapping spans.

        Note: Contained spans are removed regardless of tier (larger span wins).
        For tier comparison, use overlapping incompatible-type spans that won't merge.
        """
        from scrubiq.pipeline.merger import merge_spans

        text = "John Smith123456 here"
        # Overlapping spans with incompatible types (NAME vs MRN won't merge)
        spans = [
            make_span("John Smith", start=0, entity_type="NAME", tier=2, confidence=0.95),
            make_span("Smith12345", start=5, entity_type="MRN", tier=3, confidence=0.7),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        # Tier 3 (STRUCTURED) wins in greedy selection over tier 2 (PATTERN)
        # even though PATTERN has higher confidence
        assert len(result) == 1
        assert result[0].tier == Tier.STRUCTURED


class TestOutputOrdering:
    """Tests for output ordering (merge_spans step 15)."""

    def test_output_sorted_by_position(self):
        """Output spans are sorted by start position."""
        from scrubiq.pipeline.merger import merge_spans

        text = "End name John and Start name Alice"
        # Input in reverse order
        spans = [
            make_span("Alice", start=29, entity_type="NAME"),
            make_span("John", start=9, entity_type="NAME"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 2
        assert result[0].text == "John"  # First by position
        assert result[1].text == "Alice"  # Second by position
        assert result[0].start < result[1].start
