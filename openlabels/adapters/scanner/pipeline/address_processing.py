"""
Address span processing.

Handles merging adjacent ADDRESS spans that represent parts of a single address.
"""

import re
from typing import List

from ..types import Span
from ..constants import ADDRESS_GAP_THRESHOLD


def merge_adjacent_addresses(spans: List[Span], text: str) -> List[Span]:
    """
    Merge adjacent ADDRESS spans into single spans.

    Clinical documents often have addresses split across detectors:
    - "5734 Mill Highway" (street)
    - "Apt 773" (unit)
    - "Springfield, IL 62701" (city/state/zip)

    These should be merged into one ADDRESS span.

    Args:
        spans: All spans (will separate ADDRESS from others)
        text: Original text for gap content checking

    Returns:
        Spans with adjacent ADDRESS spans merged
    """
    # Separate ADDRESS spans from others
    address_spans = [s for s in spans if s.entity_type == "ADDRESS"]
    other_spans = [s for s in spans if s.entity_type != "ADDRESS"]

    if len(address_spans) < 2:
        return spans

    # Sort addresses by position
    address_spans.sort(key=lambda s: s.start)

    merged = []
    current = address_spans[0]

    for next_span in address_spans[1:]:
        # Calculate gap between current and next
        gap = next_span.start - current.end

        # Check if should merge:
        # - Gap is small (allows ", Apt 123, " between address parts)
        # - Gap contains only whitespace, commas, hyphens, or "Apt/Unit/Suite"
        should_merge = False
        if 0 <= gap <= ADDRESS_GAP_THRESHOLD:
            gap_text = text[current.end:next_span.start]
            # Allow: whitespace, commas, newlines, and address connectors
            if re.match(r'^[\s,\-\n]*(?:Apt\.?|Unit|Suite|Ste\.?|#)?[\s,\-\n]*$', gap_text, re.I):
                should_merge = True

        if should_merge:
            # Merge: extend current to include next
            merged_text = text[current.start:next_span.end]
            current = Span(
                start=current.start,
                end=next_span.end,
                text=merged_text,
                entity_type="ADDRESS",
                confidence=min(current.confidence, next_span.confidence),
                detector=current.detector,
                tier=max(current.tier, next_span.tier),
            )
        else:
            # Not adjacent, save current and start new
            merged.append(current)
            current = next_span

    # Don't forget the last one
    merged.append(current)

    return other_spans + merged
