"""
Span deduplication and overlap resolution.

Handles exact deduplication, containment removal, and greedy non-overlapping
selection using interval trees when available.
"""

import logging
from typing import Dict, List

from ..types import Span
from ..constants import INTERVALTREE_THRESHOLD
from .type_normalization import types_compatible

logger = logging.getLogger(__name__)

# Try to import intervaltree for O(n log n) overlap detection
try:
    from intervaltree import IntervalTree
    _INTERVALTREE_AVAILABLE = True
except ImportError:
    _INTERVALTREE_AVAILABLE = False


def remove_contained_spans(spans: List[Span]) -> List[Span]:
    """
    Remove spans that are fully contained within larger compatible spans.

    Fixes issues like:
    - pii_bert detects "K." while pattern detects "K. Edwards, DNP"
    - Both survive exact dedup (different positions), but "K." should be dropped

    Uses IntervalTree for O(n log n) performance instead of O(n²).
    """
    if len(spans) < 2:
        return spans

    # Sort by span length descending, then by tier and confidence
    sorted_spans = sorted(
        spans,
        key=lambda s: (s.end - s.start, s.tier, s.confidence),
        reverse=True
    )

    if _INTERVALTREE_AVAILABLE:
        # O(n log n) approach using IntervalTree
        tree = IntervalTree()
        result = []

        for span in sorted_spans:
            overlaps = tree[span.start:span.end]

            is_contained = False
            for interval in overlaps:
                accepted = interval.data
                if (span.start >= accepted.start and
                    span.end <= accepted.end and
                    types_compatible(span.entity_type, accepted.entity_type)):
                    is_contained = True
                    break

            if not is_contained:
                result.append(span)
                tree.addi(span.start, max(span.end, span.start + 1), span)

        return result
    else:
        # Fallback to O(n²) approach
        result = []
        for span in sorted_spans:
            is_contained = False
            for accepted in result:
                if (span.start >= accepted.start and
                    span.end <= accepted.end and
                    types_compatible(span.entity_type, accepted.entity_type)):
                    is_contained = True
                    break

            if not is_contained:
                result.append(span)

        return result


def dedup_by_position_type(spans: List[Span]) -> List[Span]:
    """
    Deduplicate spans with same (start, end, type) keeping highest tier.

    When multiple detectors find the same span with the same type,
    keep only the one with highest authority (tier, then confidence).
    """
    groups: Dict[tuple, List[Span]] = {}
    for span in spans:
        key = (span.start, span.end, span.entity_type)
        if key not in groups:
            groups[key] = []
        groups[key].append(span)

    return [
        max(group, key=lambda s: (s.tier, s.confidence))
        for group in groups.values()
    ]


def select_non_overlapping(spans: List[Span]) -> List[Span]:
    """
    Greedy select non-overlapping spans from authority-sorted input.

    Uses interval tree for O(n log n) when available and span count exceeds
    threshold, otherwise falls back to O(n²) pairwise comparison.

    Args:
        spans: Spans sorted by authority (tier desc, confidence desc, length desc)

    Returns:
        Non-overlapping spans (highest authority wins conflicts)
    """
    selected = []

    if _INTERVALTREE_AVAILABLE and len(spans) > INTERVALTREE_THRESHOLD:
        # O(n log n) with interval tree for large span counts
        tree = IntervalTree()
        for span in spans:
            if not tree.overlaps(span.start, span.end):
                selected.append(span)
                tree.addi(span.start, max(span.end, span.start + 1), span)
    else:
        # O(n²) fallback - fine for small span counts
        for span in spans:
            if not any(span.overlaps(s) for s in selected):
                selected.append(span)

    return selected
