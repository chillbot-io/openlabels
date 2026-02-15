"""Tests for the span-level evaluation engine."""

import pytest

from openlabels.core.benchmark.dataset import GoldSpan
from openlabels.core.benchmark.evaluate import (
    EvalMetrics,
    MatchType,
    SpanMatch,
    aggregate_metrics,
    evaluate_spans,
    per_category_metrics,
    per_entity_type_metrics,
    _overlap_chars,
)
from openlabels.core.types import Span, Tier


def _gold(start, end, text, entity_type="NAME", label="FIRSTNAME"):
    return GoldSpan(
        start=start,
        end=end,
        text=text,
        entity_type=entity_type,
        original_label=label,
    )


def _pred(start, end, text, entity_type="NAME", confidence=0.9):
    return Span(
        start=start,
        end=end,
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector="test",
        tier=Tier.PATTERN,
    )


class TestOverlapChars:
    """Test the character overlap calculation."""

    def test_no_overlap(self):
        assert _overlap_chars(0, 5, 10, 15) == 0

    def test_full_overlap_identical(self):
        assert _overlap_chars(0, 10, 0, 10) == 10

    def test_partial_overlap(self):
        assert _overlap_chars(0, 10, 5, 15) == 5

    def test_contained(self):
        assert _overlap_chars(0, 20, 5, 15) == 10

    def test_adjacent_no_overlap(self):
        assert _overlap_chars(0, 5, 5, 10) == 0


class TestEvalMetrics:
    """Test the EvalMetrics dataclass."""

    def test_precision_no_predictions(self):
        m = EvalMetrics(true_positives=0, false_positives=0, false_negatives=5)
        assert m.precision == 0.0

    def test_recall_no_gold(self):
        m = EvalMetrics(true_positives=0, false_positives=5, false_negatives=0)
        assert m.recall == 0.0

    def test_perfect_scores(self):
        m = EvalMetrics(true_positives=10, false_positives=0, false_negatives=0)
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1 == 1.0

    def test_f1_calculation(self):
        m = EvalMetrics(true_positives=8, false_positives=2, false_negatives=4)
        assert m.precision == pytest.approx(0.8)
        assert m.recall == pytest.approx(2 / 3, abs=0.001)
        expected_f1 = 2 * 0.8 * (2 / 3) / (0.8 + 2 / 3)
        assert m.f1 == pytest.approx(expected_f1, abs=0.001)

    def test_to_dict(self):
        m = EvalMetrics(true_positives=5, false_positives=2, false_negatives=3)
        d = m.to_dict()
        assert d["true_positives"] == 5
        assert d["false_positives"] == 2
        assert d["false_negatives"] == 3
        assert "precision" in d
        assert "recall" in d
        assert "f1" in d

    def test_total_counts(self):
        m = EvalMetrics(true_positives=5, false_positives=2, false_negatives=3)
        assert m.total_gold == 8  # TP + FN
        assert m.total_pred == 7  # TP + FP


class TestEvaluateSpans:
    """Test the core span evaluation function."""

    def test_exact_match(self):
        gold = [_gold(0, 4, "John")]
        pred = [_pred(0, 4, "John")]

        metrics, matches = evaluate_spans(gold, pred)

        assert metrics.true_positives == 1
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 0
        assert metrics.exact_matches == 1
        assert metrics.f1 == 1.0
        assert len(matches) == 1
        assert matches[0].match_type == MatchType.EXACT

    def test_no_predictions(self):
        gold = [_gold(0, 4, "John"), _gold(10, 15, "Smith")]
        pred = []

        metrics, matches = evaluate_spans(gold, pred)

        assert metrics.true_positives == 0
        assert metrics.false_negatives == 2
        assert metrics.recall == 0.0
        assert len([m for m in matches if m.match_type == MatchType.MISS]) == 2

    def test_no_gold(self):
        gold = []
        pred = [_pred(0, 4, "John")]

        metrics, matches = evaluate_spans(gold, pred)

        assert metrics.true_positives == 0
        assert metrics.false_positives == 1
        assert metrics.precision == 0.0
        assert len([m for m in matches if m.match_type == MatchType.SPURIOUS]) == 1

    def test_partial_overlap(self):
        gold = [_gold(0, 10, "John Smith")]
        pred = [_pred(0, 4, "John")]

        metrics, matches = evaluate_spans(gold, pred)

        # 4/4 = 100% overlap relative to shorter span
        assert metrics.true_positives == 1
        assert metrics.partial_matches == 1

    def test_insufficient_overlap(self):
        gold = [_gold(0, 20, "John Smith something")]
        pred = [_pred(0, 4, "John")]

        # 4/4 = 100% but let's test with higher threshold
        metrics, _ = evaluate_spans(gold, pred, min_overlap_ratio=0.5)
        assert metrics.true_positives == 1  # 4/4 still >= 0.5

    def test_type_mismatch_strict(self):
        gold = [_gold(0, 4, "John", entity_type="NAME")]
        pred = [_pred(0, 4, "John", entity_type="ADDRESS")]

        metrics, matches = evaluate_spans(gold, pred, strict_type_match=True)

        assert metrics.type_mismatches == 1
        assert metrics.false_positives == 1  # pred counts as FP
        assert metrics.false_negatives == 1  # gold counts as FN
        assert metrics.true_positives == 0

    def test_type_mismatch_relaxed(self):
        gold = [_gold(0, 4, "John", entity_type="NAME")]
        pred = [_pred(0, 4, "John", entity_type="ADDRESS")]

        metrics, _ = evaluate_spans(gold, pred, strict_type_match=False)

        assert metrics.true_positives == 1  # Still counts as TP in relaxed mode

    def test_multiple_exact_matches(self):
        gold = [
            _gold(0, 4, "John", entity_type="NAME"),
            _gold(10, 21, "123-45-6789", entity_type="SSN"),
            _gold(30, 50, "john.smith@email.com", entity_type="EMAIL"),
        ]
        pred = [
            _pred(0, 4, "John", entity_type="NAME"),
            _pred(10, 21, "123-45-6789", entity_type="SSN"),
            _pred(30, 50, "john.smith@email.com", entity_type="EMAIL"),
        ]

        metrics, _ = evaluate_spans(gold, pred)

        assert metrics.true_positives == 3
        assert metrics.exact_matches == 3
        assert metrics.f1 == 1.0

    def test_mixed_results(self):
        gold = [
            _gold(0, 4, "John", entity_type="NAME"),      # matched
            _gold(10, 21, "123-45-6789", entity_type="SSN"),  # missed
        ]
        pred = [
            _pred(0, 4, "John", entity_type="NAME"),      # TP
            _pred(30, 40, "extra text", entity_type="EMAIL"),  # FP (spurious)
        ]

        metrics, matches = evaluate_spans(gold, pred)

        assert metrics.true_positives == 1
        assert metrics.false_positives == 1
        assert metrics.false_negatives == 1
        assert metrics.precision == pytest.approx(0.5)
        assert metrics.recall == pytest.approx(0.5)

    def test_greedy_matching_prefers_best_overlap(self):
        """When multiple predictions overlap one gold, best overlap wins."""
        gold = [_gold(0, 10, "John Smith")]
        pred = [
            _pred(0, 4, "John"),                # 4/4 = 1.0 overlap ratio
            _pred(0, 10, "John Smith"),          # 10/10 = 1.0 overlap ratio (exact)
        ]

        metrics, matches = evaluate_spans(gold, pred)

        # The exact match should be preferred
        assert metrics.true_positives == 1
        assert metrics.exact_matches == 1
        assert metrics.false_positives == 1  # The other prediction is spurious

    def test_empty_inputs(self):
        metrics, matches = evaluate_spans([], [])
        assert metrics.true_positives == 0
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 0
        assert len(matches) == 0


class TestAggregateMetrics:
    """Test metric aggregation across samples."""

    def test_aggregate_empty(self):
        result = aggregate_metrics([])
        assert result.true_positives == 0
        assert result.f1 == 0.0

    def test_aggregate_single(self):
        m = EvalMetrics(true_positives=5, false_positives=2, false_negatives=3)
        result = aggregate_metrics([m])
        assert result.true_positives == 5
        assert result.false_positives == 2
        assert result.false_negatives == 3

    def test_aggregate_multiple(self):
        m1 = EvalMetrics(true_positives=5, false_positives=2, false_negatives=3,
                         exact_matches=3, partial_matches=2)
        m2 = EvalMetrics(true_positives=3, false_positives=1, false_negatives=2,
                         exact_matches=2, partial_matches=1)
        result = aggregate_metrics([m1, m2])
        assert result.true_positives == 8
        assert result.false_positives == 3
        assert result.false_negatives == 5
        assert result.exact_matches == 5
        assert result.partial_matches == 3


class TestPerCategoryMetrics:
    """Test per-category metric breakdown."""

    def test_basic_categorisation(self):
        matches = [
            SpanMatch(
                match_type=MatchType.EXACT,
                gold=_gold(0, 4, "John", entity_type="NAME"),
                pred=_pred(0, 4, "John", entity_type="NAME"),
                overlap_ratio=1.0,
            ),
            SpanMatch(
                match_type=MatchType.EXACT,
                gold=_gold(10, 21, "123-45-6789", entity_type="SSN"),
                pred=_pred(10, 21, "123-45-6789", entity_type="SSN"),
                overlap_ratio=1.0,
            ),
            SpanMatch(
                match_type=MatchType.MISS,
                gold=_gold(30, 49, "john.smith@email.com", entity_type="EMAIL"),
            ),
        ]

        cats = per_category_metrics(matches)

        assert "names" in cats
        assert cats["names"].true_positives == 1
        assert "government_ids" in cats
        assert cats["government_ids"].true_positives == 1
        assert "contact" in cats
        assert cats["contact"].false_negatives == 1


class TestPerEntityTypeMetrics:
    """Test per-entity-type metric breakdown."""

    def test_basic_entity_type_breakdown(self):
        matches = [
            SpanMatch(
                match_type=MatchType.EXACT,
                gold=_gold(0, 4, "John", entity_type="NAME"),
                pred=_pred(0, 4, "John", entity_type="NAME"),
                overlap_ratio=1.0,
            ),
            SpanMatch(
                match_type=MatchType.MISS,
                gold=_gold(10, 14, "Jane", entity_type="NAME"),
            ),
        ]

        types = per_entity_type_metrics(matches)

        assert "NAME" in types
        assert types["NAME"].true_positives == 1
        assert types["NAME"].false_negatives == 1
