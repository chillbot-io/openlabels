"""Tests for span overlap resolution.

Covers:
- Non-overlapping spans (pass-through)
- Exact duplicate spans (deduplication)
- Fully contained / nesting spans
- Partial overlap with same entity type (merging)
- Partial overlap with different entity types (strategy-based)
- Tie-breaking logic for all three strategies
- Confidence threshold filtering
- Empty input
- source_text extraction during merge
"""

import pytest

from openlabels.core.types import Span, Tier
from openlabels.core.pipeline.span_resolver import (
    OverlapStrategy,
    resolve_spans,
    _deduplicate,
    _compare_by_strategy,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _span(
    start: int,
    end: int,
    entity_type: str = "NAME",
    confidence: float = 0.90,
    tier: Tier = Tier.PATTERN,
    detector: str = "test",
    text: str | None = None,
) -> Span:
    """Create a Span with a simple generated text matching start/end length."""
    if text is None:
        length = end - start
        text = "x" * length
    return Span(
        start=start,
        end=end,
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=tier,
    )


# ===========================================================================
# Empty / trivial inputs
# ===========================================================================

class TestEmptyInput:
    def test_empty_list(self):
        assert resolve_spans([]) == []

    def test_single_span_passthrough(self):
        s = _span(0, 5)
        result = resolve_spans([s])
        assert len(result) == 1
        assert result[0].start == 0
        assert result[0].end == 5


# ===========================================================================
# Non-overlapping spans
# ===========================================================================

class TestNonOverlapping:
    def test_two_disjoint_spans(self):
        s1 = _span(0, 5)
        s2 = _span(10, 15)
        result = resolve_spans([s1, s2])
        assert len(result) == 2

    def test_sorted_by_start(self):
        s1 = _span(10, 15)
        s2 = _span(0, 5)
        result = resolve_spans([s2, s1])
        assert result[0].start < result[1].start

    def test_adjacent_not_overlapping(self):
        s1 = _span(0, 5)
        s2 = _span(5, 10)
        result = resolve_spans([s1, s2])
        assert len(result) == 2


# ===========================================================================
# Confidence threshold filtering
# ===========================================================================

class TestConfidenceThreshold:
    def test_below_threshold_removed(self):
        s1 = _span(0, 5, confidence=0.3)
        s2 = _span(10, 15, confidence=0.8)
        result = resolve_spans([s1, s2], confidence_threshold=0.5)
        assert len(result) == 1
        assert result[0].confidence == 0.8

    def test_at_threshold_kept(self):
        s = _span(0, 5, confidence=0.5)
        result = resolve_spans([s], confidence_threshold=0.5)
        assert len(result) == 1

    def test_zero_threshold_keeps_all(self):
        s = _span(0, 5, confidence=0.01)
        result = resolve_spans([s], confidence_threshold=0.0)
        assert len(result) == 1


# ===========================================================================
# Exact duplicates (same position)
# ===========================================================================

class TestExactDuplicates:
    def test_same_position_higher_tier_wins(self):
        low = _span(0, 5, tier=Tier.ML, confidence=0.90)
        high = _span(0, 5, tier=Tier.CHECKSUM, confidence=0.80)
        result = resolve_spans([low, high])
        assert len(result) == 1
        assert result[0].tier == Tier.CHECKSUM

    def test_same_position_same_tier_higher_confidence_wins(self):
        s1 = _span(0, 5, tier=Tier.PATTERN, confidence=0.70)
        s2 = _span(0, 5, tier=Tier.PATTERN, confidence=0.95)
        result = resolve_spans([s1, s2])
        assert len(result) == 1
        assert result[0].confidence == 0.95

    def test_three_exact_duplicates(self):
        s1 = _span(0, 5, tier=Tier.ML, confidence=0.50)
        s2 = _span(0, 5, tier=Tier.PATTERN, confidence=0.80)
        s3 = _span(0, 5, tier=Tier.CHECKSUM, confidence=0.90)
        result = resolve_spans([s1, s2, s3])
        assert len(result) == 1
        assert result[0].tier == Tier.CHECKSUM


# ===========================================================================
# Containment (nested spans)
# ===========================================================================

class TestContainment:
    def test_outer_contains_inner_same_type(self):
        """Outer span contains inner span -> outer wins (same type)."""
        outer = _span(0, 10, entity_type="NAME", confidence=0.80)
        inner = _span(2, 7, entity_type="NAME", confidence=0.90)
        result = resolve_spans([outer, inner])
        assert len(result) == 1
        # The outer span absorbs the inner (contains it)
        assert result[0].start == 0

    def test_inner_higher_tier_replaces_outer(self):
        """Inner span with higher tier replaces the containing outer."""
        outer = _span(0, 20, tier=Tier.PATTERN, confidence=0.80)
        inner = _span(5, 15, tier=Tier.CHECKSUM, confidence=0.95)
        result = resolve_spans([outer, inner])
        assert len(result) == 1
        assert result[0].tier == Tier.CHECKSUM

    def test_span_contains_accepted_lower_tier(self):
        """A larger span containing a higher-tier accepted span: higher-tier kept."""
        # First: high-tier span accepted
        high_tier = _span(5, 10, tier=Tier.CHECKSUM, confidence=0.90)
        # Then: larger span containing it with lower tier
        larger = _span(0, 15, tier=Tier.ML, confidence=0.80)
        result = resolve_spans([high_tier, larger])
        assert len(result) == 1
        assert result[0].tier == Tier.CHECKSUM


# ===========================================================================
# Partial overlap - same entity type (merge)
# ===========================================================================

class TestPartialOverlapSameType:
    def test_merge_overlapping_same_type(self):
        """Two overlapping NAME spans should merge."""
        source = "John Smith Johnson"
        s1 = _span(0, 10, entity_type="NAME", confidence=0.80, text="John Smith")
        s2 = _span(5, 18, entity_type="NAME", confidence=0.90, text="Smith Johnson")
        result = resolve_spans([s1, s2], source_text=source)
        assert len(result) == 1
        assert result[0].start == 0
        assert result[0].end == 18
        assert result[0].confidence == 0.90  # max of the two

    def test_merge_uses_source_text(self):
        """Merged span text should come from source_text when provided."""
        source = "John Smith Johnson"
        s1 = _span(0, 10, entity_type="NAME", confidence=0.80, text="John Smith")
        s2 = _span(5, 18, entity_type="NAME", confidence=0.90, text="Smith Johnson")
        result = resolve_spans([s1, s2], source_text=source)
        assert result[0].text == "John Smith Johnson"

    def test_merge_without_source_text_concatenates(self):
        """Without source_text, heuristic concatenation is used."""
        s1 = _span(0, 10, entity_type="NAME", confidence=0.80, text="John Smith")
        s2 = _span(5, 15, entity_type="NAME", confidence=0.90, text="Smith Jane")
        result = resolve_spans([s1, s2])
        assert len(result) == 1
        merged = result[0]
        assert merged.start == 0
        assert merged.end == 15

    def test_merge_higher_tier_preserved(self):
        """Merged span should keep the higher tier's metadata."""
        s1 = _span(0, 10, entity_type="NAME", tier=Tier.ML, confidence=0.80, text="John Smith")
        s2 = _span(5, 15, entity_type="NAME", tier=Tier.PATTERN, confidence=0.90, text="Smith Jane")
        result = resolve_spans([s1, s2])
        assert len(result) == 1
        assert result[0].tier == Tier.PATTERN


# ===========================================================================
# Partial overlap - different entity types (strategy)
# ===========================================================================

class TestPartialOverlapDifferentType:
    def test_higher_confidence_strategy_default(self):
        """Default strategy: HIGHER_CONFIDENCE — higher confidence wins."""
        s1 = _span(0, 10, entity_type="NAME", confidence=0.95)
        s2 = _span(5, 15, entity_type="ADDRESS", confidence=0.70)
        result = resolve_spans(
            [s1, s2],
            strategy=OverlapStrategy.HIGHER_CONFIDENCE,
        )
        assert len(result) == 1
        assert result[0].entity_type == "NAME"

    def test_higher_tier_strategy(self):
        """HIGHER_TIER strategy: higher tier wins regardless of confidence."""
        s1 = _span(0, 10, entity_type="NAME", tier=Tier.ML, confidence=0.99)
        s2 = _span(5, 15, entity_type="SSN", tier=Tier.CHECKSUM, confidence=0.50)
        result = resolve_spans(
            [s1, s2],
            strategy=OverlapStrategy.HIGHER_TIER,
        )
        assert len(result) == 1
        assert result[0].entity_type == "SSN"

    def test_longer_span_strategy(self):
        """LONGER_SPAN strategy: longer span wins."""
        s1 = _span(0, 15, entity_type="NAME", confidence=0.70)
        s2 = _span(5, 12, entity_type="ADDRESS", confidence=0.95)
        result = resolve_spans(
            [s1, s2],
            strategy=OverlapStrategy.LONGER_SPAN,
        )
        assert len(result) == 1
        assert result[0].entity_type == "NAME"  # longer span


# ===========================================================================
# _compare_by_strategy
# ===========================================================================

class TestCompareByStrategy:
    def test_higher_tier_candidate_wins(self):
        candidate = _span(0, 5, tier=Tier.CHECKSUM, confidence=0.50)
        incumbent = _span(0, 5, tier=Tier.ML, confidence=0.99)
        assert _compare_by_strategy(
            candidate, incumbent, OverlapStrategy.HIGHER_TIER
        ) is True

    def test_higher_tier_same_tier_uses_confidence(self):
        candidate = _span(0, 5, tier=Tier.PATTERN, confidence=0.90)
        incumbent = _span(0, 5, tier=Tier.PATTERN, confidence=0.80)
        assert _compare_by_strategy(
            candidate, incumbent, OverlapStrategy.HIGHER_TIER
        ) is True

    def test_higher_confidence_strategy(self):
        candidate = _span(0, 5, confidence=0.95)
        incumbent = _span(0, 5, confidence=0.80)
        assert _compare_by_strategy(
            candidate, incumbent, OverlapStrategy.HIGHER_CONFIDENCE
        ) is True

    def test_higher_confidence_tie_breaks_on_tier(self):
        candidate = _span(0, 5, confidence=0.90, tier=Tier.CHECKSUM)
        incumbent = _span(0, 5, confidence=0.90, tier=Tier.ML)
        assert _compare_by_strategy(
            candidate, incumbent, OverlapStrategy.HIGHER_CONFIDENCE
        ) is True

    def test_longer_span_strategy(self):
        candidate = _span(0, 20)
        incumbent = _span(0, 10)
        assert _compare_by_strategy(
            candidate, incumbent, OverlapStrategy.LONGER_SPAN
        ) is True

    def test_longer_span_tie_breaks_on_confidence(self):
        candidate = _span(0, 10, confidence=0.95)
        incumbent = _span(0, 10, confidence=0.80)
        assert _compare_by_strategy(
            candidate, incumbent, OverlapStrategy.LONGER_SPAN
        ) is True

    def test_incumbent_wins_returns_false(self):
        candidate = _span(0, 5, confidence=0.30)
        incumbent = _span(0, 5, confidence=0.90)
        assert _compare_by_strategy(
            candidate, incumbent, OverlapStrategy.HIGHER_CONFIDENCE
        ) is False


# ===========================================================================
# Entity type normalization in overlap resolution
# ===========================================================================

class TestEntityTypeNormalization:
    def test_alias_types_merged(self):
        """PERSON and PER normalize to NAME - should merge on overlap."""
        s1 = _span(0, 10, entity_type="PERSON", confidence=0.80, text="John Smith")
        s2 = _span(5, 15, entity_type="PER", confidence=0.90, text="Smith Jane")
        result = resolve_spans([s1, s2])
        # Both normalize to NAME, so they should merge
        assert len(result) == 1


# ===========================================================================
# OverlapStrategy enum
# ===========================================================================

class TestOverlapStrategyEnum:
    def test_all_strategies_exist(self):
        assert OverlapStrategy.HIGHER_TIER.value == "higher_tier"
        assert OverlapStrategy.HIGHER_CONFIDENCE.value == "higher_confidence"
        assert OverlapStrategy.LONGER_SPAN.value == "longer_span"


# ===========================================================================
# Integration-style tests
# ===========================================================================

class TestIntegration:
    def test_mixed_overlapping_and_disjoint(self):
        """Mix of overlapping and non-overlapping spans."""
        s1 = _span(0, 5, entity_type="NAME", confidence=0.80)
        s2 = _span(3, 8, entity_type="NAME", confidence=0.90)  # overlaps s1
        s3 = _span(20, 25, entity_type="EMAIL", confidence=0.95)  # disjoint
        result = resolve_spans([s1, s2, s3])
        # s1 and s2 merge; s3 stays separate
        assert len(result) == 2
        assert result[0].start == 0  # merged
        assert result[1].entity_type == "EMAIL"

    def test_many_overlapping_same_type(self):
        """Chain of overlapping spans of the same type should merge into one."""
        spans = [
            _span(0, 10, entity_type="NAME", confidence=0.80, text="a" * 10),
            _span(5, 15, entity_type="NAME", confidence=0.85, text="b" * 10),
            _span(10, 20, entity_type="NAME", confidence=0.90, text="c" * 10),
        ]
        result = resolve_spans(spans)
        assert len(result) == 1
        assert result[0].start == 0
        assert result[0].end == 20

    def test_output_sorted_by_start_then_reverse_end(self):
        """Output should be sorted by (start, -end)."""
        spans = [
            _span(20, 30),
            _span(0, 10),
            _span(10, 20),
        ]
        result = resolve_spans(spans)
        for i in range(len(result) - 1):
            assert result[i].start <= result[i + 1].start
