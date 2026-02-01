"""
Authority-based span merging.

Orchestrates the span processing pipeline:
1. Type normalization
2. Confidence filtering
3. Boundary cleanup
4. False positive filtering
5. Deduplication
6. Non-overlapping selection

Each step is implemented in focused modules for maintainability.
"""

import logging
from typing import List

from ..types import Span, CLINICAL_CONTEXT_TYPES
from .type_normalization import normalize_type, types_compatible, TYPE_NORMALIZE
from .healthcare_vocabulary import is_valid_healthcare_facility
from .span_cleanup import (
    fix_misclassified_emails,
    trim_span_whitespace,
    trim_trailing_punctuation,
    snap_to_word_boundaries,
)
from .span_filters import (
    filter_short_names,
    filter_ml_mrn_on_id_cards,
    filter_tracking_numbers,
    filter_city_as_name,
)
from .name_processing import (
    trim_names_at_newlines,
    trim_name_at_non_name_words,
    normalize_name_types,
)
from .address_processing import merge_adjacent_addresses
from .deduplication import (
    remove_contained_spans,
    dedup_by_position_type,
    select_non_overlapping,
)

logger = logging.getLogger(__name__)

# Re-export for backwards compatibility
__all__ = [
    "merge_spans",
    "normalize_type",
    "types_compatible",
    "TYPE_NORMALIZE",
    "normalize_name_types",
]


def _normalize_span_types(spans: List[Span]) -> List[Span]:
    """
    Normalize entity types in spans (immutable - creates new spans when needed).
    """
    return [
        Span(
            start=span.start,
            end=span.end,
            text=span.text,
            entity_type=normalize_type(span.entity_type),
            confidence=span.confidence,
            detector=span.detector,
            tier=span.tier,
            safe_harbor_value=span.safe_harbor_value,
            needs_review=span.needs_review,
            review_reason=span.review_reason,
            coref_anchor_value=span.coref_anchor_value,
            token=span.token,
        ) if normalize_type(span.entity_type) != span.entity_type else span
        for span in spans
    ]


def merge_spans(
    spans: List[Span],
    min_confidence: float = 0.50,
    text: str = None
) -> List[Span]:
    """
    Merge overlapping spans using authority ranking.

    This function follows immutable patterns - input spans are not modified.
    New spans are created when modifications are needed.

    Pipeline:
    1. Normalize entity types to canonical forms
    2. Filter low confidence spans
    3. Filter clinical context types (LAB_TEST, DIAGNOSIS, etc.)
    4. Filter invalid healthcare facility spans
    5. Normalize span boundaries (if text provided):
       - Trim whitespace from boundaries
       - Snap to word boundaries
       - Trim NAME spans at newlines
       - Trim NAME spans at non-name words
       - Merge adjacent ADDRESS spans
       - Trim trailing punctuation from ID-type spans
    6. Fix misclassified emails (NAME → EMAIL)
    7. Exact dedup (same position + type → keep highest tier)
    8. Remove contained spans ("K." inside "K. Edwards, DNP")
    9. Filter short NAME spans (isolated initials)
    10. Reclassify city names (NAME → ADDRESS)
    11. Filter ML-based MRN on ID cards (if text provided)
    12. Filter tracking numbers misclassified as MRN (if text provided)
    13. Sort by authority (tier desc, confidence desc, length desc)
    14. Greedy select non-overlapping (O(n log n) with IntervalTree when available)
    15. Sort output by position

    Args:
        spans: Raw spans from detectors (not modified, new spans created)
        min_confidence: Minimum confidence threshold
        text: Original text (optional, enables boundary normalization)

    Returns:
        Non-overlapping spans sorted by position
    """
    if not spans:
        return []

    # Input validation: filter spans with invalid positions
    if text is not None:
        text_len = len(text)
        valid_spans = []
        for span in spans:
            if span.start < 0 or span.end > text_len or span.start >= span.end:
                logger.warning(
                    f"Filtering invalid span: start={span.start}, end={span.end}, "
                    f"text_len={text_len}, type={span.entity_type}"
                )
                continue
            valid_spans.append(span)
        spans = valid_spans
        if not spans:
            return []

    # Step 1: Normalize types
    spans = _normalize_span_types(spans)

    # Step 2: Filter low confidence
    spans = [s for s in spans if s.confidence >= min_confidence]

    # Step 3: Filter clinical context types
    spans = [s for s in spans if s.entity_type.upper() not in CLINICAL_CONTEXT_TYPES]

    # Step 4: Filter FACILITY spans without healthcare keywords
    spans = [
        s for s in spans
        if s.entity_type != "FACILITY" or is_valid_healthcare_facility(s.text)
    ]

    if not spans:
        return []

    # Step 5: Normalize span boundaries (requires text)
    if text:
        spans = trim_span_whitespace(spans, text)
        spans = snap_to_word_boundaries(spans, text)
        spans = trim_names_at_newlines(spans, text)
        spans = trim_name_at_non_name_words(spans, text)
        spans = merge_adjacent_addresses(spans, text)
        spans = trim_trailing_punctuation(spans)

    # Step 6: Fix misclassified emails
    spans = fix_misclassified_emails(spans)

    # Step 7: Exact dedup
    deduped = dedup_by_position_type(spans)

    # Step 8: Remove contained spans
    deduped = remove_contained_spans(deduped)

    # Step 9: Filter short NAME spans
    deduped = filter_short_names(deduped)

    # Step 10: Reclassify city names
    deduped = filter_city_as_name(deduped)

    # Steps 11-12: Context-aware ML filtering (requires text)
    if text:
        deduped = filter_ml_mrn_on_id_cards(deduped, text)
        deduped = filter_tracking_numbers(deduped, text)

    # Step 13: Sort by authority
    deduped.sort(key=lambda s: (s.tier, s.confidence, len(s)), reverse=True)

    # Step 14: Greedy select non-overlapping
    selected = select_non_overlapping(deduped)

    # Step 15: Sort by position
    selected.sort(key=lambda s: s.start)

    return selected
