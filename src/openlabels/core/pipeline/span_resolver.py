"""Span overlap resolution.

Standalone, strategy-configurable resolver extracted from the orchestrator.
Handles deduplication and merging of overlapping detection spans.
"""

from __future__ import annotations

from enum import Enum
from typing import List

from ..types import Span, normalize_entity_type


class OverlapStrategy(Enum):
    """How to resolve partial overlaps between different entity types."""
    HIGHER_TIER = "higher_tier"
    HIGHER_CONFIDENCE = "higher_confidence"
    LONGER_SPAN = "longer_span"


def resolve_spans(
    spans: list[Span],
    *,
    confidence_threshold: float = 0.0,
    strategy: OverlapStrategy = OverlapStrategy.HIGHER_CONFIDENCE,
) -> list[Span]:
    """Deduplicate, filter, and sort spans.

    Args:
        spans: Raw spans from all detectors.
        confidence_threshold: Discard spans below this threshold.
        strategy: How to break ties on partial overlap between
                  different entity types.

    Returns:
        Deduplicated, sorted spans.
    """
    if not spans:
        return []

    filtered = [s for s in spans if s.confidence >= confidence_threshold]
    deduped = _deduplicate(filtered, strategy)
    deduped.sort(key=lambda s: (s.start, -s.end))
    return deduped


def _deduplicate(
    spans: list[Span],
    strategy: OverlapStrategy = OverlapStrategy.HIGHER_CONFIDENCE,
) -> list[Span]:
    """Remove duplicate/overlapping detections.

    Uses a sort + single-pass merge algorithm — O(n log n) for the sort
    plus O(n) amortised for the merge.

    Overlap handling:
    - Exact same position: higher tier wins, then higher confidence
    - One span fully contains the other: the containing span is kept
    - Partial overlap, same entity_type: merge into one span covering
      the union of both character ranges
    - Partial overlap, different entity_types: resolved by *strategy*
    """
    if not spans:
        return []

    sorted_spans = sorted(
        spans,
        key=lambda s: (s.start, -s.tier.value, -s.confidence),
    )

    result: List[Span] = []

    for span in sorted_spans:
        absorbed = False
        i = len(result) - 1

        while i >= 0:
            accepted = result[i]

            if accepted.end <= span.start:
                break

            if not accepted.overlaps(span):
                i -= 1
                continue

            # exact same position
            if span.start == accepted.start and span.end == accepted.end:
                if (span.tier.value > accepted.tier.value
                        or (span.tier.value == accepted.tier.value
                            and span.confidence > accepted.confidence)):
                    result[i] = span
                absorbed = True
                break

            # accepted fully contains span
            if accepted.contains(span):
                absorbed = True
                break

            # span fully contains accepted
            if span.contains(accepted):
                result.pop(i)
                i -= 1
                continue

            # partial overlap
            accepted_norm = normalize_entity_type(accepted.entity_type)
            span_norm = normalize_entity_type(span.entity_type)

            if accepted_norm == span_norm:
                # Same entity type: merge
                new_start = min(accepted.start, span.start)
                new_end = max(accepted.end, span.end)

                if accepted.start <= span.start:
                    left, right = accepted, span
                else:
                    left, right = span, accepted
                overlap_chars = left.end - right.start
                merged_text = left.text + right.text[overlap_chars:]

                if (span.tier.value > accepted.tier.value
                        or (span.tier.value == accepted.tier.value
                            and span.confidence > accepted.confidence)):
                    base = span
                else:
                    base = accepted

                span = Span(
                    start=new_start,
                    end=new_end,
                    text=merged_text,
                    entity_type=base.entity_type,
                    confidence=max(accepted.confidence, span.confidence),
                    detector=base.detector,
                    tier=base.tier,
                )
                result.pop(i)
                i -= 1
                continue

            else:
                # Different entity types — use strategy
                span_wins = _compare_by_strategy(span, accepted, strategy)
                if span_wins:
                    result.pop(i)
                    i -= 1
                    continue
                else:
                    absorbed = True
                    break

        if not absorbed:
            result.append(span)

    return result


def _compare_by_strategy(
    candidate: Span,
    incumbent: Span,
    strategy: OverlapStrategy,
) -> bool:
    """Return True if candidate should replace incumbent."""
    if strategy == OverlapStrategy.HIGHER_TIER:
        return (
            candidate.tier.value > incumbent.tier.value
            or (candidate.tier.value == incumbent.tier.value
                and candidate.confidence > incumbent.confidence)
        )
    elif strategy == OverlapStrategy.LONGER_SPAN:
        cand_len = candidate.end - candidate.start
        inc_len = incumbent.end - incumbent.start
        return (
            cand_len > inc_len
            or (cand_len == inc_len
                and candidate.confidence > incumbent.confidence)
        )
    else:  # HIGHER_CONFIDENCE (default)
        return (
            candidate.confidence > incumbent.confidence
            or (candidate.confidence == incumbent.confidence
                and candidate.tier.value > incumbent.tier.value)
        )
