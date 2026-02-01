"""
Span boundary cleanup and normalization.

Handles whitespace trimming, punctuation trimming, word boundary snapping,
and email reclassification for detected spans.
"""

import logging
import re
from typing import List

from ..types import Span
from ..constants import WORD_BOUNDARY_EXPANSION_LIMIT

logger = logging.getLogger(__name__)

# Email pattern for reclassification
_EMAIL_PATTERN = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')

# Word boundary pattern for snap_to_word_boundaries
# Includes ASCII punctuation, Unicode dashes, curly quotes, and various whitespace
_WORD_BOUNDARY = re.compile(
    r'['
    r'\s'                    # All Unicode whitespace (includes non-breaking space)
    r'\-\.,;:!?\(\)\[\]{}'   # ASCII punctuation
    r'"\'/\\|<>'             # ASCII quotes and symbols
    r'\u2010-\u2015'         # Unicode dashes (hyphen, en-dash, em-dash, etc.)
    r'\u2018-\u201F'         # Unicode quotation marks (curly quotes)
    r'\u2026'                # Horizontal ellipsis
    r'\u00A0'                # Non-breaking space (explicit)
    r'\u3000'                # Ideographic space (CJK)
    r']'
)


def fix_misclassified_emails(spans: List[Span]) -> List[Span]:
    """
    Reclassify NAME spans that are actually email addresses.

    ML models sometimes tag emails as NAME. If the text matches email format,
    reclassify to EMAIL.
    """
    result = []
    for span in spans:
        if span.entity_type == "NAME" or span.entity_type.startswith("NAME_"):
            # Strip trailing punctuation for the check
            text = span.text.rstrip('.,;:!?')
            if _EMAIL_PATTERN.match(text):
                # Reclassify as EMAIL and fix the text
                result.append(Span(
                    start=span.start,
                    end=span.start + len(text),  # Exclude trailing punctuation
                    text=text,
                    entity_type="EMAIL",
                    confidence=span.confidence,
                    detector=span.detector,
                    tier=span.tier,
                ))
                continue
        result.append(span)
    return result


def trim_span_whitespace(spans: List[Span], text: str) -> List[Span]:
    """
    Trim leading and trailing whitespace from span boundaries.

    Whitespace shouldn't be included in spans as it causes formatting issues:
    - " John Smith" → "[NAME_1]" leaves orphan leading space
    - "John Smith " → "[NAME_1]" leaves orphan trailing space

    This normalizes span boundaries to exclude surrounding whitespace.
    """
    result = []
    for span in spans:
        span_text = text[span.start:span.end]

        # Count leading whitespace
        leading = len(span_text) - len(span_text.lstrip())
        # Count trailing whitespace
        trailing = len(span_text) - len(span_text.rstrip())

        if leading > 0 or trailing > 0:
            new_start = span.start + leading
            new_end = span.end - trailing if trailing > 0 else span.end
            new_text = text[new_start:new_end]

            # Only adjust if we still have meaningful content
            if new_text and new_start < new_end:
                result.append(Span(
                    start=new_start,
                    end=new_end,
                    text=new_text,
                    entity_type=span.entity_type,
                    confidence=span.confidence,
                    detector=span.detector,
                    tier=span.tier,
                    safe_harbor_value=span.safe_harbor_value,
                    needs_review=span.needs_review,
                    review_reason=span.review_reason,
                    coref_anchor_value=span.coref_anchor_value,
                    token=span.token,
                ))
            # else: span was only whitespace, discard
        else:
            result.append(span)

    return result


def trim_trailing_punctuation(spans: List[Span]) -> List[Span]:
    """
    Trim trailing punctuation from spans where it doesn't belong.

    Applies to: EMAIL, PHONE, SSN, MRN, and ID-type spans.
    Does NOT apply to: NAME (could end in Jr., Sr., etc.), ADDRESS, DATE.
    """
    TRIM_TYPES = {
        "EMAIL", "PHONE", "FAX", "SSN", "MRN", "NPI", "DEA",
        "HEALTH_PLAN_ID", "MEMBER_ID", "ACCOUNT_NUMBER", "ID_NUMBER",
        "CREDIT_CARD", "DRIVER_LICENSE", "PASSPORT"
    }

    result = []
    for span in spans:
        if span.entity_type in TRIM_TYPES:
            # Trim trailing punctuation
            new_text = span.text.rstrip('.,;:!?')
            if new_text != span.text:
                result.append(Span(
                    start=span.start,
                    end=span.start + len(new_text),
                    text=new_text,
                    entity_type=span.entity_type,
                    confidence=span.confidence,
                    detector=span.detector,
                    tier=span.tier,
                ))
                continue
        result.append(span)
    return result


def _is_word_char(c: str) -> bool:
    """Check if character is part of a word (not a boundary)."""
    return bool(c) and not _WORD_BOUNDARY.match(c)


def _find_word_start(text: str, pos: int) -> int:
    """Find the start of the word containing position."""
    while pos > 0 and _is_word_char(text[pos - 1]):
        pos -= 1
    return pos


def _find_word_end(text: str, pos: int) -> int:
    """Find the end of the word containing position."""
    while pos < len(text) and _is_word_char(text[pos]):
        pos += 1
    return pos


def snap_to_word_boundaries(spans: List[Span], text: str) -> List[Span]:
    """
    Snap span boundaries to word edges to prevent partial word tokenization.

    Fixes issues like:
    - "[PHYS_1]YES" → "EYES" should be fully captured or not at all
    - "r[NAME_4]" → end of "our" shouldn't be tokenized
    - "5D[NAME_3]23" → partial document ID
    """
    adjusted = []
    for span in spans:
        new_start = span.start
        new_end = span.end

        # Safety: skip invalid spans (don't pass them through)
        if span.start < 0 or span.end > len(text) or span.start >= span.end:
            logger.warning(
                f"Skipping invalid span: start={span.start}, end={span.end}, "
                f"text_len={len(text)}"
            )
            continue

        # Check if we're starting mid-word
        if (span.start > 0 and
            span.start < len(text) and
            _is_word_char(text[span.start - 1]) and
            _is_word_char(text[span.start])):
            # We're in the middle of a word - expand to word start
            new_start = _find_word_start(text, span.start)

        # Check if we're ending mid-word
        if (span.end > 0 and
            span.end < len(text) and
            _is_word_char(text[span.end]) and
            _is_word_char(text[span.end - 1])):
            # We're in the middle of a word - expand to word end
            new_end = _find_word_end(text, span.end)

        # Only adjust if boundaries changed and the expansion is reasonable
        if new_start != span.start or new_end != span.end:
            start_delta = span.start - new_start
            end_delta = new_end - span.end

            if (start_delta <= WORD_BOUNDARY_EXPANSION_LIMIT and
                    end_delta <= WORD_BOUNDARY_EXPANSION_LIMIT):
                # Create new span with adjusted boundaries
                new_text = text[new_start:new_end]
                adjusted.append(Span(
                    start=new_start,
                    end=new_end,
                    text=new_text,
                    entity_type=span.entity_type,
                    confidence=span.confidence * 0.95,  # Slight confidence reduction
                    detector=span.detector,
                    tier=span.tier,
                ))
            else:
                # Expansion too large - likely a bad detection, keep original
                adjusted.append(span)
        else:
            adjusted.append(span)

    return adjusted
