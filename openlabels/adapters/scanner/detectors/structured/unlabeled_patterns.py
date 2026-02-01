"""
Unlabeled pattern detection.

Detects structured data patterns (addresses, etc.) that appear without
explicit labels in documents.
"""

import re
from typing import List

from ...types import Span
from ..constants import (CONFIDENCE_MEDIUM_LOW)


# Pattern for street addresses (without labels)
STREET_PATTERN = re.compile(
    r'\b(\d{1,5}[ \t]+[A-Z][A-Za-z]+(?:[ \t]+[A-Z][A-Za-z]+)*[ \t]+'
    r'(?:STREET|ST|AVENUE|AVE|ROAD|RD|DRIVE|DR|LANE|LN|BLVD|BOULEVARD|'
    r'WAY|COURT|CT|CIRCLE|CIR|PLACE|PL|TERRACE|TER|TRAIL|TRL|PIKE|HWY|HIGHWAY)'
    r'(?:[ \t]+(?:APT|UNIT|STE|SUITE|#)[ \t]*\.?[ \t]*[A-Z0-9]*)?)\b',
    re.IGNORECASE
)

# Pattern for city, state zip (without labels)
CITY_STATE_ZIP_PATTERN = re.compile(
    r'\b([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)\b',
    re.IGNORECASE
)


def detect_unlabeled_addresses(text: str, existing_spans: List[Span]) -> List[Span]:
    """
    Detect addresses that don't have labels (common on ID documents).

    Args:
        text: Processed text
        existing_spans: Already detected spans (to avoid overlap)

    Returns:
        List of address spans
    """
    spans = []

    def overlaps_existing(start: int, end: int) -> bool:
        for s in existing_spans:
            if not (end <= s.start or start >= s.end):
                return True
        return False

    # Detect street addresses
    for match in STREET_PATTERN.finditer(text):
        if not overlaps_existing(match.start(), match.end()):
            value = match.group(1)
            spans.append(Span(
                start=match.start(),
                end=match.start() + len(value),
                text=value,
                entity_type="ADDRESS",
                confidence=CONFIDENCE_MEDIUM_LOW,
                detector="structured",
                tier=3,
            ))

    # Detect city, state, zip
    for match in CITY_STATE_ZIP_PATTERN.finditer(text):
        if not overlaps_existing(match.start(), match.end()):
            spans.append(Span(
                start=match.start(),
                end=match.end(),
                text=match.group(1),
                entity_type="ADDRESS",
                confidence=CONFIDENCE_MEDIUM_LOW,
                detector="structured",
                tier=3,
            ))

    return spans
