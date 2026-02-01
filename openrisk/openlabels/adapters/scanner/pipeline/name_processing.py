"""
Name-specific span processing.

Handles NAME span boundary corrections and subtype normalization
based on contextual evidence.
"""

import re
from typing import List

from ..types import Span
from ..constants import NON_NAME_WORDS, NAME_CONNECTORS, NAME_CONTEXT_WINDOW


# Pre-compiled patterns for NAME type normalization

# Provider context patterns (look before the name)
_PROVIDER_BEFORE_PATTERNS = [
    re.compile(r'\bdr\.?\s*$', re.IGNORECASE),
    re.compile(r'\bdoctor\s*$', re.IGNORECASE),
    re.compile(r'\bphysician\s*$', re.IGNORECASE),
    re.compile(r'\bnurse\s*$', re.IGNORECASE),
    re.compile(r'\bordered\s+by\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\breviewed\s+by\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\bsigned\s+by\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\bdictated\s+by\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\btranscribed\s+by\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\bverified\s+by\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\bapproved\s+by\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\battending\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\bprovider\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\bcc\s*:\s*$', re.IGNORECASE),
]

# Provider context patterns (look after the name)
_PROVIDER_AFTER_PATTERNS = [
    re.compile(r'^\s*,?\s*(?:md|do|rn|np|pa|lpn|cna|phd|pharmd|dpm|dds|dmd)\b', re.IGNORECASE),
    re.compile(r'^\s*,?\s*m\.?d\.?\b', re.IGNORECASE),
]

# Patient context patterns (look before the name)
_PATIENT_BEFORE_PATTERNS = [
    re.compile(r'\bpatient\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\bpt\.?\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\bpatient\s+name\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\bname\s*:\s*$', re.IGNORECASE),
    re.compile(r'\bsubject\s*:\s*$', re.IGNORECASE),
    re.compile(r'\bclient\s*:\s*$', re.IGNORECASE),
]

# Patient context patterns (look after the name)
_PATIENT_AFTER_PATTERNS = [
    re.compile(r'^\s+(?:has|had|have|is|was|were|presents?|complains?|reports?|denies?|states?)\s+', re.IGNORECASE),
    re.compile(r'^\s+(?:was\s+)?admitted', re.IGNORECASE),
    re.compile(r'^\s+(?:is\s+)?diagnosed', re.IGNORECASE),
    re.compile(r'^\s+(?:has\s+)?history\s+of', re.IGNORECASE),
    re.compile(r'^\s*,?\s*(?:age|aged|\d+\s*(?:y/?o|year))', re.IGNORECASE),
    re.compile(r'^\s*,?\s*(?:a|an)\s+\d+\s*(?:year|y/?o)', re.IGNORECASE),
]

# Relative context patterns (look before the name only)
_RELATIVE_BEFORE_PATTERNS = [
    re.compile(r'\b(?:mother|father|mom|dad|parent|spouse|wife|husband|son|daughter|brother|sister|sibling|child|guardian)\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\bemergency\s+contact\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\bnext\s+of\s+kin\s*:?\s*$', re.IGNORECASE),
    re.compile(r'\bfamily\s+member\s*:?\s*$', re.IGNORECASE),
]


def trim_names_at_newlines(spans: List[Span], text: str) -> List[Span]:
    """
    Trim NAME spans at newlines to prevent over-extension.

    ML models sometimes extend NAME spans past line breaks into headers/labels.
    Example: "Dr. Luis Collins\nCOMPREHENSIVE METABOLIC PANEL" should be just
    "Dr. Luis Collins".
    """
    adjusted = []
    for span in spans:
        # Only trim NAME-type spans
        if not (span.entity_type == "NAME" or span.entity_type.startswith("NAME_")):
            adjusted.append(span)
            continue

        # Check for newline within span
        span_text = text[span.start:span.end]
        newline_pos = span_text.find('\n')

        if newline_pos == -1:
            adjusted.append(span)
            continue

        # Trim at newline
        new_end = span.start + newline_pos
        new_text = text[span.start:new_end].rstrip()

        # Only keep if we have meaningful content left (at least 2 chars)
        if len(new_text) >= 2:
            adjusted.append(Span(
                start=span.start,
                end=span.start + len(new_text),
                text=new_text,
                entity_type=span.entity_type,
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
            ))

    return adjusted


def trim_name_at_non_name_words(spans: List[Span], text: str) -> List[Span]:
    """
    Trim NAME spans that end with non-name words.

    Defense in depth: catches NAME spans that extended past the actual name
    due to ML model boundary detection issues.

    A trailing word is trimmed if:
    1. It's in NON_NAME_WORDS (case-insensitive), OR
    2. It's lowercase, not a name connector, and > 5 chars
    """
    result = []
    for span in spans:
        if not (span.entity_type == "NAME" or span.entity_type.startswith("NAME_")):
            result.append(span)
            continue

        span_text = text[span.start:span.end]
        words = span_text.split()

        if len(words) <= 1:
            result.append(span)
            continue

        # Work backwards, trimming non-name words
        original_word_count = len(words)
        while len(words) > 1:
            last_word = words[-1].rstrip('.,;:!?')
            last_lower = last_word.lower()

            should_trim = False
            # Rule 1: Explicit non-name words
            if last_lower in NON_NAME_WORDS:
                should_trim = True
            # Rule 2: Lowercase, not a connector, and > 5 chars
            elif (last_word.islower() and
                  last_lower not in NAME_CONNECTORS and
                  len(last_word) > 5):
                should_trim = True

            if should_trim:
                words.pop()
            else:
                break

        if len(words) == original_word_count:
            result.append(span)
        else:
            # Create trimmed span - find actual end position in original text
            span_text = text[span.start:span.end]
            last_word = words[-1]

            # Search forward through kept words to find the last one's position
            search_start = 0
            for w in words[:-1]:
                pos = span_text.find(w, search_start)
                if pos != -1:
                    search_start = pos + len(w)

            last_word_pos = span_text.find(last_word, search_start)
            if last_word_pos == -1:
                last_word_pos = span_text.rfind(last_word)

            if last_word_pos != -1:
                new_end = span.start + last_word_pos + len(last_word)
                new_text = text[span.start:new_end]
            else:
                # Fallback: reconstruct from words
                new_text = ' '.join(words)
                new_end = span.start + len(new_text)

            result.append(Span(
                start=span.start,
                end=new_end,
                text=new_text,
                entity_type=span.entity_type,
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
            ))

    return result


def normalize_name_types(spans: List[Span], text: str) -> List[Span]:
    """
    Normalize NAME subtypes based on context.

    Default to generic NAME unless strong contextual evidence exists.
    This prevents misclassification when ML models guess without context.

    Rules:
    - NAME_PROVIDER requires: Dr., MD, DO, NP, RN, PA, "ordered by", etc.
    - NAME_PATIENT requires: "Patient:", "Pt:", admission/condition context
    - NAME_RELATIVE requires: family relationship terms
    - Otherwise → NAME (safe default)
    """
    def has_context(span: Span, before_patterns: list, after_patterns: list = None) -> bool:
        """Check if span has matching context before or after."""
        before_start = max(0, span.start - NAME_CONTEXT_WINDOW)
        before_text = text[before_start:span.start]

        for pattern in before_patterns:
            if pattern.search(before_text):
                return True

        if after_patterns:
            after_end = min(len(text), span.end + NAME_CONTEXT_WINDOW)
            after_text = text[span.end:after_end]

            for pattern in after_patterns:
                if pattern.search(after_text):
                    return True

        return False

    def _create_span_with_type(span: Span, new_type: str) -> Span:
        """Create a new span with a different entity type (immutable pattern)."""
        return Span(
            start=span.start,
            end=span.end,
            text=span.text,
            entity_type=new_type,
            confidence=span.confidence,
            detector=span.detector,
            tier=span.tier,
            safe_harbor_value=span.safe_harbor_value,
            needs_review=span.needs_review,
            review_reason=span.review_reason,
            coref_anchor_value=span.coref_anchor_value,
            token=span.token,
        )

    result = []
    for span in spans:
        if span.entity_type == "NAME_PROVIDER":
            if not has_context(span, _PROVIDER_BEFORE_PATTERNS, _PROVIDER_AFTER_PATTERNS):
                result.append(_create_span_with_type(span, "NAME"))
            else:
                result.append(span)

        elif span.entity_type == "NAME_PATIENT":
            if not has_context(span, _PATIENT_BEFORE_PATTERNS, _PATIENT_AFTER_PATTERNS):
                result.append(_create_span_with_type(span, "NAME"))
            else:
                result.append(span)

        elif span.entity_type == "NAME_RELATIVE":
            if not has_context(span, _RELATIVE_BEFORE_PATTERNS):
                result.append(_create_span_with_type(span, "NAME"))
            else:
                result.append(span)
        else:
            result.append(span)

    return result
