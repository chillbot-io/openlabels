"""Span-level evaluation metrics for PII detection benchmarking.

Computes precision, recall, and F1 using span-overlap matching between
predicted spans (from the detection pipeline) and gold-standard spans
(from the ai4privacy dataset).

Matching strategy
-----------------
A predicted span matches a gold span when:

1. **Overlap**: The character ranges overlap by at least ``min_overlap_ratio``
   (default 0.5 = 50 %).
2. **Type match** (optional): The entity types match after normalisation.
   Disabled by ``strict_type_match=False`` for type-agnostic recall.

Each gold span can match at most one prediction and vice-versa (greedy
matching by overlap ratio, largest first).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from openlabels.core.types import Span, normalize_entity_type

from .dataset import GoldSpan
from .entity_mapping import get_eval_category

logger = logging.getLogger(__name__)


class MatchType(Enum):
    """Classification of a match between predicted and gold spans."""

    EXACT = "exact"         # Same start, end, and entity type
    PARTIAL = "partial"     # Overlapping ranges, same type
    TYPE_MISMATCH = "type_mismatch"  # Overlapping ranges, different type
    MISS = "miss"           # Gold span with no prediction
    SPURIOUS = "spurious"   # Prediction with no gold span


@dataclass
class SpanMatch:
    """A single match (or miss) between a prediction and gold span."""

    match_type: MatchType
    gold: GoldSpan | None = None
    pred: Span | None = None
    overlap_ratio: float = 0.0


@dataclass
class EvalMetrics:
    """Aggregate evaluation metrics."""

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    exact_matches: int = 0
    partial_matches: int = 0
    type_mismatches: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def total_gold(self) -> int:
        return self.true_positives + self.false_negatives

    @property
    def total_pred(self) -> int:
        return self.true_positives + self.false_positives

    def to_dict(self) -> dict[str, object]:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "exact_matches": self.exact_matches,
            "partial_matches": self.partial_matches,
            "type_mismatches": self.type_mismatches,
            "total_gold": self.total_gold,
            "total_pred": self.total_pred,
        }


def evaluate_spans(
    gold_spans: list[GoldSpan],
    pred_spans: list[Span],
    *,
    min_overlap_ratio: float = 0.5,
    strict_type_match: bool = True,
    count_type_mismatch_as_tp: bool = False,
) -> tuple[EvalMetrics, list[SpanMatch]]:
    """Evaluate predicted spans against gold-standard spans.

    Args:
        gold_spans: Ground-truth annotations.
        pred_spans: Predicted spans from the detection pipeline.
        min_overlap_ratio: Minimum fraction of the smaller span that must
            overlap for a match to be considered.
        strict_type_match: If ``True``, overlapping spans with different
            entity types count as type mismatches (FP + FN).
            If ``False``, any sufficient overlap counts as a TP.
        count_type_mismatch_as_tp: If ``True``, type mismatches still
            count as true positives (useful for location-accuracy-only
            evaluation).

    Returns:
        Tuple of (metrics, matches) where *matches* is a list of
        ``SpanMatch`` objects for detailed analysis.
    """
    matches: list[SpanMatch] = []
    metrics = EvalMetrics()

    # Track which spans have been matched
    gold_matched = [False] * len(gold_spans)
    pred_matched = [False] * len(pred_spans)

    # Build overlap matrix and sort by overlap ratio (greedy best-first)
    candidates: list[tuple[float, int, int, MatchType]] = []

    for gi, gold in enumerate(gold_spans):
        for pi, pred in enumerate(pred_spans):
            overlap = _overlap_chars(gold.start, gold.end, pred.start, pred.end)
            if overlap <= 0:
                continue

            # Ratio relative to the smaller span
            min_len = min(gold.end - gold.start, pred.end - pred.start)
            ratio = overlap / min_len if min_len > 0 else 0.0

            if ratio < min_overlap_ratio:
                continue

            # Determine match type
            gold_type = normalize_entity_type(gold.entity_type)
            pred_type = normalize_entity_type(pred.entity_type)

            if gold.start == pred.start and gold.end == pred.end and gold_type == pred_type:
                mtype = MatchType.EXACT
            elif gold_type == pred_type:
                mtype = MatchType.PARTIAL
            else:
                mtype = MatchType.TYPE_MISMATCH

            candidates.append((ratio, gi, pi, mtype))

    # Greedy matching: best overlap first, then exact > partial > mismatch
    candidates.sort(key=lambda c: (-c[0], c[3].value))

    for ratio, gi, pi, mtype in candidates:
        if gold_matched[gi] or pred_matched[pi]:
            continue

        gold_matched[gi] = True
        pred_matched[pi] = True

        matches.append(SpanMatch(
            match_type=mtype,
            gold=gold_spans[gi],
            pred=pred_spans[pi],
            overlap_ratio=ratio,
        ))

        if mtype in (MatchType.EXACT, MatchType.PARTIAL):
            metrics.true_positives += 1
            if mtype == MatchType.EXACT:
                metrics.exact_matches += 1
            else:
                metrics.partial_matches += 1
        elif mtype == MatchType.TYPE_MISMATCH:
            metrics.type_mismatches += 1
            if count_type_mismatch_as_tp or not strict_type_match:
                metrics.true_positives += 1
            else:
                metrics.false_positives += 1
                metrics.false_negatives += 1

    # Unmatched gold = false negatives
    for gi, matched in enumerate(gold_matched):
        if not matched:
            metrics.false_negatives += 1
            matches.append(SpanMatch(
                match_type=MatchType.MISS,
                gold=gold_spans[gi],
            ))

    # Unmatched predictions = false positives
    for pi, matched in enumerate(pred_matched):
        if not matched:
            metrics.false_positives += 1
            matches.append(SpanMatch(
                match_type=MatchType.SPURIOUS,
                pred=pred_spans[pi],
            ))

    return metrics, matches


def aggregate_metrics(
    per_sample: list[EvalMetrics],
) -> EvalMetrics:
    """Aggregate per-sample metrics into a single micro-averaged result."""
    total = EvalMetrics()
    for m in per_sample:
        total.true_positives += m.true_positives
        total.false_positives += m.false_positives
        total.false_negatives += m.false_negatives
        total.exact_matches += m.exact_matches
        total.partial_matches += m.partial_matches
        total.type_mismatches += m.type_mismatches
    return total


def per_category_metrics(
    all_matches: list[SpanMatch],
) -> dict[str, EvalMetrics]:
    """Compute metrics broken down by entity category.

    Uses ``get_eval_category`` to group entity types into categories
    like "names", "government_ids", "financial", etc.
    """
    buckets: dict[str, EvalMetrics] = {}

    for m in all_matches:
        # Determine category from gold or pred
        if m.gold is not None:
            cat = get_eval_category(m.gold.entity_type)
        elif m.pred is not None:
            cat = get_eval_category(
                normalize_entity_type(m.pred.entity_type)
            )
        else:
            continue

        if cat not in buckets:
            buckets[cat] = EvalMetrics()
        metrics = buckets[cat]

        if m.match_type == MatchType.EXACT:
            metrics.true_positives += 1
            metrics.exact_matches += 1
        elif m.match_type == MatchType.PARTIAL:
            metrics.true_positives += 1
            metrics.partial_matches += 1
        elif m.match_type == MatchType.TYPE_MISMATCH:
            metrics.type_mismatches += 1
            metrics.false_positives += 1
            metrics.false_negatives += 1
        elif m.match_type == MatchType.MISS:
            metrics.false_negatives += 1
        elif m.match_type == MatchType.SPURIOUS:
            metrics.false_positives += 1

    return buckets


def per_entity_type_metrics(
    all_matches: list[SpanMatch],
) -> dict[str, EvalMetrics]:
    """Compute metrics broken down by individual entity type."""
    buckets: dict[str, EvalMetrics] = {}

    for m in all_matches:
        if m.gold is not None:
            etype = m.gold.entity_type
        elif m.pred is not None:
            etype = normalize_entity_type(m.pred.entity_type)
        else:
            continue

        if etype not in buckets:
            buckets[etype] = EvalMetrics()
        metrics = buckets[etype]

        if m.match_type == MatchType.EXACT:
            metrics.true_positives += 1
            metrics.exact_matches += 1
        elif m.match_type == MatchType.PARTIAL:
            metrics.true_positives += 1
            metrics.partial_matches += 1
        elif m.match_type == MatchType.TYPE_MISMATCH:
            metrics.type_mismatches += 1
            metrics.false_positives += 1
            metrics.false_negatives += 1
        elif m.match_type == MatchType.MISS:
            metrics.false_negatives += 1
        elif m.match_type == MatchType.SPURIOUS:
            metrics.false_positives += 1

    return buckets


def _overlap_chars(s1: int, e1: int, s2: int, e2: int) -> int:
    """Return number of overlapping characters between two ranges."""
    return max(0, min(e1, e2) - max(s1, s2))
