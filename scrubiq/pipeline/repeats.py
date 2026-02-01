"""Repeat finder: propagate detected PHI to identical strings.

If we detect "John Smith" at position 0, find all other exact matches
in the text and create spans for them. This handles cases where ML models
miss repeated mentions of the same entity.

Runs AFTER merge, BEFORE coref. That way coref can expand pronouns
for both original and newly-found repeated names.

Works for ALL entity types, not just names - if the same phone number
or SSN appears twice, both get detected.
"""

import bisect
import logging
from typing import List, Set, Tuple, Dict

from ..types import Span, Tier


logger = logging.getLogger(__name__)

# Maximum expansions per unique value (prevents O(n²) on pathological input)
MAX_EXPANSIONS_PER_VALUE = 50

# Entity types eligible for repeat expansion
# Excludes context-only types (DRUG, DIAGNOSIS, etc.) and dates (which get shifted)
REPEAT_ELIGIBLE_TYPES = frozenset([
    # Names
    "NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
    # Contact
    "PHONE", "FAX", "EMAIL", "PAGER",
    # IDs
    "SSN", "SSN_PARTIAL", "MRN", "ENCOUNTER_ID", "ACCESSION_ID",
    "MEMBER_ID", "MEDICARE_ID", "HEALTH_PLAN_ID", "PHARMACY_ID",
    "NPI", "DEA", "MEDICAL_LICENSE",
    "DRIVER_LICENSE", "PASSPORT",
    # Financial
    "CREDIT_CARD", "ACCOUNT_NUMBER", "IBAN", "ABA_ROUTING",
    # Device/Network
    "IP_ADDRESS", "MAC_ADDRESS", "IMEI", "DEVICE_ID",
    # Other
    "URL", "USERNAME",
])

# NAME type specificity ranking (higher = more specific)
# When same value has multiple types, use the most specific
NAME_TYPE_PRIORITY = {
    "NAME_PATIENT": 3,
    "NAME_PROVIDER": 3,
    "NAME_RELATIVE": 3,
    "NAME": 1,
}


class IntervalSet:
    """
    Efficient interval overlap checking using sorted endpoints.
    
    O(log n) insertion and overlap checking instead of O(n).
    """
    
    def __init__(self):
        self._starts: List[int] = []
        self._ends: List[int] = []
        self._intervals: Set[Tuple[int, int]] = set()
    
    def add(self, start: int, end: int) -> None:
        """Add an interval."""
        if (start, end) in self._intervals:
            return
        self._intervals.add((start, end))
        bisect.insort(self._starts, start)
        bisect.insort(self._ends, end)
    
    def overlaps(self, start: int, end: int) -> bool:
        """Check if interval overlaps any existing interval. O(log n)."""
        if not self._intervals:
            return False
        
        # Quick check against exact match
        if (start, end) in self._intervals:
            return True
        
        # Check each existing interval for overlap
        # An interval [s, e) overlaps [start, end) if s < end and e > start
        for (s, e) in self._intervals:
            if s < end and e > start:
                return True
        
        return False
    
    def overlaps_fast(self, start: int, end: int) -> bool:
        """
        Fast overlap check using the fact that intervals don't overlap each other.
        
        For non-overlapping intervals, we can use binary search.
        """
        if not self._intervals:
            return False
        
        if (start, end) in self._intervals:
            return True
        
        # Find intervals that could possibly overlap
        # An interval [s, e) overlaps [start, end) if s < end and e > start
        
        # Find first interval that ends after our start
        idx = bisect.bisect_right(self._ends, start)
        
        # Check intervals from idx onwards until start >= end
        sorted_intervals = sorted(self._intervals)
        for i in range(len(sorted_intervals)):
            s, e = sorted_intervals[i]
            if s >= end:
                break
            if e > start:
                return True
        
        return False


def _unify_name_types(spans: List[Span]) -> List[Span]:
    """
    Ensure same-value NAME spans get the same entity_type.
    
    If "John Smith" is detected as NAME_PATIENT at one position and NAME
    at another, unify them to the most specific type (NAME_PATIENT).
    This ensures the tokenizer assigns the same token to all occurrences.
    """
    if not spans:
        return []
    
    # Group spans by normalized text value (case-sensitive for names)
    value_to_spans: Dict[str, List[int]] = {}
    for i, span in enumerate(spans):
        if span.entity_type in NAME_TYPE_PRIORITY:
            value = span.text
            if value not in value_to_spans:
                value_to_spans[value] = []
            value_to_spans[value].append(i)
    
    # For each value, find the most specific type and apply to all
    result = list(spans)
    for value, indices in value_to_spans.items():
        if len(indices) <= 1:
            continue
        
        # Find highest priority type among these spans
        best_type = None
        best_priority = -1
        for idx in indices:
            span = spans[idx]
            priority = NAME_TYPE_PRIORITY.get(span.entity_type, 0)
            if priority > best_priority:
                best_priority = priority
                best_type = span.entity_type
        
        # Apply best type to all spans with this value
        for idx in indices:
            old_span = result[idx]
            if old_span.entity_type != best_type:
                logger.debug(
                    f"Unifying type for '{value}': {old_span.entity_type} -> {best_type}"
                )
                result[idx] = Span(
                    start=old_span.start,
                    end=old_span.end,
                    text=old_span.text,
                    entity_type=best_type,
                    confidence=old_span.confidence,
                    detector=old_span.detector,
                    tier=old_span.tier,
                    coref_anchor_value=old_span.coref_anchor_value,
                )
    
    return result


def expand_repeated_values(
    text: str,
    spans: List[Span],
    min_confidence: float = 0.70,
    confidence_decay: float = 0.95,
    max_expansions_per_value: int = MAX_EXPANSIONS_PER_VALUE,
) -> List[Span]:
    """
    Find repeated occurrences of detected PHI values.
    
    For each detected span, search the text for other exact matches
    and create new spans for them. New spans inherit entity_type from
    the original detection.
    
    Args:
        text: Original text
        spans: Detected spans (non-overlapping, from merger)
        min_confidence: Minimum confidence to use span as anchor
        confidence_decay: Multiplier for expanded spans (default 0.95)
        max_expansions_per_value: Cap on expansions per unique value (prevents O(n²))
    
    Returns:
        Original spans + expanded repeat spans, sorted by position
    """
    if not text or not spans:
        return list(spans) if spans else []
    
    # Find eligible anchors (high confidence, eligible type)
    anchors = []
    for s in spans:
        if s.entity_type in REPEAT_ELIGIBLE_TYPES and s.confidence >= min_confidence:
            anchors.append(s)
    
    if not anchors:
        return list(spans)
    
    # Track what's already covered - use set for O(1) exact lookups
    covered_exact: Set[Tuple[int, int]] = {(s.start, s.end) for s in spans}
    
    # Also track covered ranges for overlap detection
    # Use sorted list of (start, end) tuples for efficient overlap checking
    covered_ranges: List[Tuple[int, int]] = sorted((s.start, s.end) for s in spans)
    
    new_spans = []
    
    # Sort anchors by length descending - find longer matches first
    # This prevents "John" matching inside "John Smith"
    anchors_sorted = sorted(anchors, key=lambda s: len(s.text), reverse=True)
    
    # Track how many expansions per value (prevent pathological cases)
    value_expansion_count: Dict[str, int] = {}
    
    for anchor in anchors_sorted:
        value = anchor.text
        
        # Skip very short values (too likely to false positive)
        if len(value) < 3:
            continue
        
        # Check if we've hit the cap for this value
        current_count = value_expansion_count.get(value, 0)
        if current_count >= max_expansions_per_value:
            continue
        
        # Search for all occurrences
        start_pos = 0
        while True:
            pos = text.find(value, start_pos)
            if pos == -1:
                break
            
            # Check expansion cap
            if value_expansion_count.get(value, 0) >= max_expansions_per_value:
                break
            
            end_pos = pos + len(value)
            
            # Quick check: exact match already covered?
            if (pos, end_pos) in covered_exact:
                start_pos = pos + 1
                continue
            
            # Check for overlap using binary search
            already_covered = _has_overlap(covered_ranges, pos, end_pos)
            
            if not already_covered:
                # Check word boundaries
                # Don't match "Johnson" when looking for "John"
                valid_start = (pos == 0 or not text[pos - 1].isalnum())
                valid_end = (end_pos == len(text) or not text[end_pos].isalnum())
                
                if valid_start and valid_end:
                    new_span = Span(
                        start=pos,
                        end=end_pos,
                        text=value,
                        entity_type=anchor.entity_type,
                        confidence=anchor.confidence * confidence_decay,
                        detector="repeat_finder",
                        tier=Tier.ML,
                        # Link to anchor so tokenizer assigns same token
                        coref_anchor_value=anchor.text,
                    )
                    new_spans.append(new_span)
                    covered_exact.add((pos, end_pos))
                    
                    # Insert into sorted list maintaining order
                    bisect.insort(covered_ranges, (pos, end_pos))
                    
                    # Track expansion count
                    value_expansion_count[value] = value_expansion_count.get(value, 0) + 1
                    
                    logger.debug(
                        f"Repeat found: '{value}' at {pos}-{end_pos} "
                        f"(anchor at {anchor.start}-{anchor.end})"
                    )
            
            start_pos = pos + 1
    
    if new_spans:
        logger.info(f"Repeat finder: {len(new_spans)} additional spans from {len(anchors)} anchors")
        if any(c >= max_expansions_per_value for c in value_expansion_count.values()):
            capped = [v for v, c in value_expansion_count.items() if c >= max_expansions_per_value]
            logger.warning(
                f"Repeat finder: {len(capped)} value(s) hit expansion cap of {max_expansions_per_value}"
            )
    
    result = list(spans) + new_spans
    result.sort(key=lambda s: s.start)
    
    # Unify NAME types so same value gets same token
    result = _unify_name_types(result)
    
    return result


def _has_overlap(sorted_ranges: List[Tuple[int, int]], start: int, end: int) -> bool:
    """
    Check if [start, end) overlaps any range in sorted list.
    
    Uses binary search for O(log n) performance.
    """
    if not sorted_ranges:
        return False
    
    # Find insertion point for start
    # All ranges with range_start < end could potentially overlap
    idx = bisect.bisect_left(sorted_ranges, (start, 0))
    
    # Check range at idx (if exists) - its start >= our start
    if idx < len(sorted_ranges):
        range_start, range_end = sorted_ranges[idx]
        if range_start < end:  # Overlap: our end > their start, their start >= our start
            return True
    
    # Check range before idx - its start < our start
    if idx > 0:
        range_start, range_end = sorted_ranges[idx - 1]
        if range_end > start:  # Overlap: their end > our start
            return True
    
    return False
