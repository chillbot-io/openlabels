"""Authority-based span merging."""

import logging
import re
from typing import List, Dict, Set

logger = logging.getLogger(__name__)

# Try to import intervaltree for O(n log n) overlap detection
try:
    from intervaltree import IntervalTree
    _INTERVALTREE_AVAILABLE = True
except ImportError:
    _INTERVALTREE_AVAILABLE = False

# Try to import ahocorasick for O(n) multi-pattern matching
try:
    import ahocorasick
    _AHOCORASICK_AVAILABLE = True
except ImportError:
    _AHOCORASICK_AVAILABLE = False

from ..types import Span, CLINICAL_CONTEXT_TYPES
from ..constants import (
    MIN_NAME_LENGTH,
    NON_NAME_WORDS,
    NAME_CONNECTORS,
    WORD_BOUNDARY_EXPANSION_LIMIT,
    NAME_CONTEXT_WINDOW,
    ADDRESS_GAP_THRESHOLD,
    TRACKING_CONTEXT_WINDOW,
    INTERVALTREE_THRESHOLD,
)


# TYPE COMPATIBILITY

# Groups of entity types that are semantically equivalent for dedup purposes
COMPATIBLE_TYPE_GROUPS: List[Set[str]] = [
    {"NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE", "NAME_FAMILY"},
    {"ADDRESS", "STREET", "STREET_ADDRESS", "CITY", "STATE", "ZIP", "LOCATION"},
    {"DATE", "DOB", "DATE_DOB", "DATE_ADMISSION", "DATE_DISCHARGE"},
    {"PHONE", "FAX", "PHONE_MOBILE", "PHONE_HOME", "PHONE_WORK"},
    {"SSN", "SSN_PARTIAL"},
    {"MRN", "PATIENT_ID", "MEDICAL_RECORD"},
    {"HEALTH_PLAN_ID", "MEMBER_ID", "INSURANCE_ID"},
    {"EMPLOYER", "ORGANIZATION", "COMPANY", "COMPANYNAME"},
]

# Precompute type -> group_id mapping for O(1) compatibility checks
_TYPE_TO_GROUP: Dict[str, int] = {}
for _group_id, _group in enumerate(COMPATIBLE_TYPE_GROUPS):
    for _entity_type in _group:
        _TYPE_TO_GROUP[_entity_type] = _group_id


def types_compatible(t1: str, t2: str) -> bool:
    """Check if two entity types are semantically compatible for dedup.

    Uses precomputed group mapping for O(1) lookup instead of O(g) iteration.
    """
    if t1 == t2:
        return True
    # Check prefix match (NAME matches NAME_PATIENT)
    if t1.startswith(t2) or t2.startswith(t1):
        return True
    # O(1) group compatibility check
    g1 = _TYPE_TO_GROUP.get(t1)
    g2 = _TYPE_TO_GROUP.get(t2)
    return g1 is not None and g1 == g2


# SPAN CLEANUP

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

# Pre-compiled patterns for NAME type normalization (normalize_name_types)
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

    Args:
        spans: Spans to adjust
        text: Original text for boundary detection

    Returns:
        Spans with whitespace trimmed from boundaries
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


def trim_trailing_punctuation(spans: List[Span], text: str) -> List[Span]:
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


# CONTAINMENT DEDUPLICATION

def remove_contained_spans(spans: List[Span]) -> List[Span]:
    """
    Remove spans that are fully contained within larger compatible spans.

    Fixes issues like:
    - pii_bert detects "K." while pattern detects "K. Edwards, DNP"
    - Both survive exact dedup (different positions), but "K." should be dropped

    Uses IntervalTree for O(n log n) performance instead of O(n²).

    Args:
        spans: Deduplicated spans (after exact dedup, before greedy selection)

    Returns:
        Spans with contained duplicates removed
    """
    if len(spans) < 2:
        return spans

    # Sort by span length descending (larger spans first), then by tier and confidence
    # When lengths are equal, prefer higher tier (more authoritative), then higher confidence
    sorted_spans = sorted(spans, key=lambda s: (s.end - s.start, s.tier, s.confidence), reverse=True)

    if _INTERVALTREE_AVAILABLE:
        # O(n log n) approach using IntervalTree
        tree = IntervalTree()
        result = []

        for span in sorted_spans:
            # Query for overlapping intervals
            overlaps = tree[span.start:span.end]

            # Check if any overlapping span fully contains this one
            is_contained = False
            for interval in overlaps:
                accepted = interval.data
                # Containment: span is fully inside accepted
                if (span.start >= accepted.start and
                    span.end <= accepted.end and
                    types_compatible(span.entity_type, accepted.entity_type)):
                    is_contained = True
                    break

            if not is_contained:
                result.append(span)
                # Add to tree for future containment checks
                # Use span.end + 1 to handle edge cases with intervaltree's half-open intervals
                tree.addi(span.start, max(span.end, span.start + 1), span)

        return result
    else:
        # Fallback to O(n²) approach if IntervalTree not available
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


def filter_short_names(spans: List[Span]) -> List[Span]:
    """
    Filter out very short NAME spans that are likely false positives.
    
    Single initials like "K.", "R.", "G." are almost never standalone PHI.
    They're usually part of a larger name that should be detected separately.
    
    Args:
        spans: Spans to filter
        
    Returns:
        Spans with short names removed
    """
    result = []
    for span in spans:
        # Only filter NAME-type spans
        if span.entity_type == "NAME" or span.entity_type.startswith("NAME_"):
            # Get text without trailing punctuation
            text = span.text.rstrip('.')
            if len(text) < MIN_NAME_LENGTH:
                continue  # Skip this span
        result.append(span)
    
    return result


# ID CARD CONTEXT FILTERING

# Patterns that indicate text is from an ID card (not clinical notes)
_ID_CARD_PATTERNS = [
    re.compile(r"DRIVER'?S?\s*LICENSE", re.I),
    re.compile(r'\bDLN[:\s]', re.I),
    re.compile(r'\bSTATE\s+ID\b', re.I),
    re.compile(r'\bDUPS:\s*\d', re.I),  # Duplicate count on licenses
    re.compile(r'\bCLASS:\s*[A-Z]', re.I),  # License class
    re.compile(r'\bRESTR:', re.I),  # Restrictions
    re.compile(r'\b\d+[a-z]?(?:EXP|ISS):', re.I),  # Field codes like 4bEXP:
    re.compile(r'\bORGAN\s+DONOR\b', re.I),
]

def is_id_card_context(text: str) -> bool:
    """
    Detect if text appears to be from an ID card (driver's license, state ID).
    
    PHI-BERT is trained on clinical notes, so its MRN detections on ID cards
    are unreliable false positives.
    """
    matches = sum(1 for p in _ID_CARD_PATTERNS if p.search(text))
    return matches >= 2  # Require at least 2 ID card indicators


def filter_ml_mrn_on_id_cards(spans: List[Span], text: str) -> List[Span]:
    """
    Filter out MRN detections from ML models when processing ID cards.

    PHI-BERT is trained on clinical notes where MRN patterns make sense.
    On driver's licenses, it incorrectly flags:
    - "000" (DUPS count)
    - "99 999 999" (DL number)
    - "1234567890123" (document discriminator)

    Rule-based MRN detections (with explicit "MRN:" labels) are kept.
    """
    if not is_id_card_context(text):
        return spans  # Not an ID card, keep all spans

    result = []
    for span in spans:
        # Filter MRN from ML detectors on ID cards
        if span.entity_type == "MRN" and span.detector in ("phi_bert", "pii_bert", "ml"):
            # Skip this MRN - likely false positive on ID card
            continue
        result.append(span)

    return result


# TRACKING NUMBER FILTERING
# Common shipping carrier tracking number patterns that ML models misclassify as MRN

# Carrier tracking number patterns (compiled for efficiency)
_TRACKING_NUMBER_PATTERNS = [
    # USPS: 20-22 digits, often starting with 94
    re.compile(r'^94\d{18,20}$'),
    # USPS: Other formats (20-22 digits)
    re.compile(r'^\d{20,22}$'),
    # FedEx: 12-15 digits
    re.compile(r'^\d{12,15}$'),
    # FedEx: 20-22 digits (door tag)
    re.compile(r'^DT\d{12}$', re.I),
    # UPS: 18 digits starting with 1Z
    re.compile(r'^1Z[A-Z0-9]{16}$', re.I),
    # UPS: 9-11 digits
    re.compile(r'^\d{9,11}$'),
]

# Context patterns that indicate a tracking number context
_TRACKING_CONTEXT_PATTERNS = [
    re.compile(r'\b(?:USPS|UPS|FedEx|DHL|tracking)\s*[:#]?\s*$', re.I),
    re.compile(r'\btrack(?:ing)?\s*(?:number|#|no\.?)?\s*[:#]?\s*$', re.I),
    re.compile(r'\bshipment\s*[:#]?\s*$', re.I),
    re.compile(r'\bdelivery\s*[:#]?\s*$', re.I),
    re.compile(r'\bpackage\s*[:#]?\s*$', re.I),
]


def is_tracking_number(span_text: str, context_before: str) -> bool:
    """
    Check if a span looks like a shipping tracking number.

    Args:
        span_text: The detected span text (numbers only)
        context_before: Text immediately before the span (up to 30 chars)

    Returns:
        True if this looks like a tracking number
    """
    # Strip any spaces/dashes from the span text for pattern matching
    clean_text = re.sub(r'[\s\-]', '', span_text)

    # Check if text matches tracking number patterns
    matches_pattern = any(p.match(clean_text) for p in _TRACKING_NUMBER_PATTERNS)
    if not matches_pattern:
        return False

    # Check for tracking context
    context_lower = context_before.lower()
    has_tracking_context = any(p.search(context_before) for p in _TRACKING_CONTEXT_PATTERNS)

    # Also check for carrier names in context
    carrier_keywords = ('usps', 'ups', 'fedex', 'dhl', 'tracking', 'shipment', 'package')
    has_carrier_context = any(kw in context_lower for kw in carrier_keywords)

    return has_tracking_context or has_carrier_context


def filter_tracking_numbers(spans: List[Span], text: str) -> List[Span]:
    """
    Filter out tracking numbers that ML models misclassify as MRN.

    Shipping carriers use long numeric codes that look like medical record numbers
    to ML models trained on clinical notes. This filter removes MRN detections
    that match tracking number patterns when carrier context is present.

    Also filters out carrier name prefixes (USPS, UPS, FedEx, DHL) detected as MRN.

    Args:
        spans: Spans to filter
        text: Original text for context checking

    Returns:
        Spans with tracking number false positives removed
    """
    result = []
    ml_detectors = ("phi_bert", "pii_bert", "phi_bert_onnx", "pii_bert_onnx", "ml")
    carrier_names = ("usps", "ups", "fedex", "dhl")

    for span in spans:
        # Only filter MRN from ML detectors
        if span.entity_type == "MRN" and span.detector in ml_detectors:
            span_text_clean = span.text.strip().rstrip(':').lower()

            # Filter carrier name prefixes detected as MRN (e.g., "USPS:" or "UPS")
            if span_text_clean in carrier_names:
                continue

            # Get context before the span
            context_start = max(0, span.start - TRACKING_CONTEXT_WINDOW)
            context_before = text[context_start:span.start]

            if is_tracking_number(span.text, context_before):
                # Skip - this is a tracking number, not an MRN
                continue
        result.append(span)

    return result


# Common US city name suffixes (helps distinguish cities from names)
_CITY_SUFFIXES = (
    'burg', 'burgh', 'boro', 'borough', 'ville', 'view', 'field', 'ford',
    'port', 'land', 'wood', 'dale', 'vale', 'ton', 'town', 'city', 'springs',
    'falls', 'beach', 'heights', 'hills', 'park', 'lake', 'creek', 'ridge',
    'haven', 'grove', 'mount', 'point', 'bay', 'island',
)

# Pattern for "CITY, ST" format
# Requires comma or whitespace before state code to avoid false positives like "Williams" -> "Willia" + "MS"
_CITY_STATE_PATTERN = re.compile(
    r'^([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*)(?:,\s*|\s+)'
    r'(AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MA|MI|MN|MS|MO|'
    r'MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)$',
    re.I
)


def filter_city_as_name(spans: List[Span]) -> List[Span]:
    """
    Reclassify NAME spans that are actually city names to ADDRESS.
    
    Catches patterns like:
    - "HARRISBURG, PA" detected as NAME_PROVIDER
    - "Springfield" detected as NAME (ends in -field)
    - "Pittsburgh" detected as NAME (ends in -burgh)
    """
    result = []
    for span in spans:
        if span.entity_type.startswith("NAME"):
            text = span.text.strip()
            
            # Check for "CITY, STATE" pattern
            if _CITY_STATE_PATTERN.match(text):
                # Reclassify as ADDRESS
                result.append(Span(
                    start=span.start,
                    end=span.end,
                    text=span.text,
                    entity_type="ADDRESS",
                    confidence=span.confidence,
                    detector=span.detector,
                    tier=span.tier,
                ))
                continue
            
            # Check for city-like suffixes (case-insensitive)
            text_lower = text.lower()
            for suffix in _CITY_SUFFIXES:
                if text_lower.endswith(suffix) and len(text) > len(suffix) + 2:
                    # Looks like a city name - reclassify
                    result.append(Span(
                        start=span.start,
                        end=span.end,
                        text=span.text,
                        entity_type="ADDRESS",
                        confidence=span.confidence * 0.9,  # Slightly lower confidence
                        detector=span.detector,
                        tier=span.tier,
                    ))
                    break
            else:
                # Not a city, keep as-is
                result.append(span)
        else:
            result.append(span)
    
    return result


# ADDRESS MERGING

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
                detector=current.detector,  # Keep first detector
                tier=max(current.tier, next_span.tier),  # Keep highest tier
            )
        else:
            # Not adjacent, save current and start new
            merged.append(current)
            current = next_span
    
    # Don't forget the last one
    merged.append(current)
    
    return other_spans + merged


def trim_names_at_newlines(spans: List[Span], text: str) -> List[Span]:
    """
    Trim NAME spans at newlines to prevent over-extension.
    
    ML models sometimes extend NAME spans past line breaks into headers/labels.
    Example: "Dr. Luis Collins\nCOMPREHENSIVE METABOLIC PANEL" should be just 
    "Dr. Luis Collins".
    
    Args:
        spans: Spans to adjust (will create new spans, not mutate)
        text: Original text for boundary detection
        
    Returns:
        Adjusted spans
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
            # No newline, keep as-is
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
        # else: discard span entirely (nothing left after trim)

    return adjusted


def trim_name_at_non_name_words(spans: List[Span], text: str) -> List[Span]:
    """
    Trim NAME spans that end with non-name words.

    Defense in depth: catches NAME spans that extended past the actual name
    due to ML model boundary detection issues.

    A trailing word is trimmed if:
    1. It's in NON_NAME_WORDS (case-insensitive), OR
    2. It's lowercase, not a name connector, and > 5 chars

    Args:
        spans: Spans to trim (creates new spans, doesn't mutate)
        text: Original text for content lookup

    Returns:
        Spans with non-name trailing words removed
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
            # No trimming needed
            result.append(span)
        else:
            # Create trimmed span - find actual end position in original text
            # Note: while loop guarantees len(words) >= 1, so words is never empty
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
                # End at the word boundary - don't include trailing punctuation
                # that may belong to trimmed content (e.g., "Smith, ordered" -> "Smith")
                new_end = span.start + last_word_pos + len(last_word)
                new_text = text[span.start:new_end]
            else:
                # Fallback: reconstruct from words (loses original spacing)
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


def snap_to_word_boundaries(spans: List[Span], text: str) -> List[Span]:
    """
    Snap span boundaries to word edges to prevent partial word tokenization.

    Fixes issues like:
    - "[PHYS_1]YES" → "EYES" should be fully captured or not at all
    - "r[NAME_4]" → end of "our" shouldn't be tokenized
    - "5D[NAME_3]23" → partial document ID

    Algorithm:
    - If span starts mid-word, expand left to word start
    - If span ends mid-word, expand right to word end
    - Word boundaries: whitespace, punctuation, or string edges

    Args:
        spans: Spans to adjust
        text: Original text for boundary detection

    Returns:
        Adjusted spans (new span objects, originals not modified)
    """
    def is_word_char(c: str) -> bool:
        """Check if character is part of a word (not a boundary)."""
        return bool(c) and not _WORD_BOUNDARY.match(c)
    
    def find_word_start(pos: int) -> int:
        """Find the start of the word containing position."""
        while pos > 0 and is_word_char(text[pos - 1]):
            pos -= 1
        return pos
    
    def find_word_end(pos: int) -> int:
        """Find the end of the word containing position."""
        while pos < len(text) and is_word_char(text[pos]):
            pos += 1
        return pos
    
    adjusted = []
    for span in spans:
        new_start = span.start
        new_end = span.end
        
        # Safety: skip invalid spans (don't pass them through)
        if span.start < 0 or span.end > len(text) or span.start >= span.end:
            logger.warning(f"Skipping invalid span: start={span.start}, end={span.end}, text_len={len(text)}")
            continue
        
        # Check if we're starting mid-word
        # Need: char before exists, is word char, AND current char is word char
        if (span.start > 0 and 
            span.start < len(text) and 
            is_word_char(text[span.start - 1]) and 
            is_word_char(text[span.start])):
            # We're in the middle of a word - expand to word start
            new_start = find_word_start(span.start)
        
        # Check if we're ending mid-word  
        # Need: char at end exists, is word char, AND char before end is word char
        if (span.end > 0 and 
            span.end < len(text) and 
            is_word_char(text[span.end]) and 
            is_word_char(text[span.end - 1])):
            # We're in the middle of a word - expand to word end
            new_end = find_word_end(span.end)
        
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
                    confidence=span.confidence * 0.95,  # Slight confidence reduction for adjusted spans
                    detector=span.detector,
                    tier=span.tier,
                ))
            else:
                # Expansion too large - likely a bad detection, keep original
                adjusted.append(span)
        else:
            adjusted.append(span)
    
    return adjusted


# Type normalization map - different detectors emit different labels
# Sources: i2b2 2014, AI4Privacy, Stanford PHI-BERT, custom PII-BERT
TYPE_NORMALIZE: Dict[str, str] = {
    # === NAMES ===
    "PERSON": "NAME",
    "PER": "NAME",
    "PATIENT": "NAME_PATIENT",
    "DOCTOR": "NAME_PROVIDER",
    "PHYSICIAN": "NAME_PROVIDER",
    "NURSE": "NAME_PROVIDER",
    "STAFF": "NAME_PROVIDER",
    "HCW": "NAME_PROVIDER",  # Healthcare Worker (Stanford PHI-BERT)
    "RELATIVE": "NAME_RELATIVE",
    "FAMILY": "NAME_RELATIVE",
    # AI4Privacy name components
    "FIRSTNAME": "NAME",
    "LASTNAME": "NAME",
    "MIDDLENAME": "NAME",
    "PREFIX": "NAME",
    "SUFFIX": "NAME",
    "FULLNAME": "NAME",
    # i2b2 specific
    "USERNAME": "USERNAME",
    
    # === LOCATIONS ===
    "GPE": "ADDRESS",
    "LOC": "ADDRESS",
    "STREET_ADDRESS": "ADDRESS",
    "STREET": "ADDRESS",
    "CITY": "ADDRESS",
    "STATE": "ADDRESS",
    "COUNTRY": "ADDRESS",
    "COUNTY": "ADDRESS",
    "LOCATION-OTHER": "ADDRESS",
    "LOCATION_OTHER": "ADDRESS",
    "SECONDARYADDRESS": "ADDRESS",  # AI4Privacy - apt/suite/unit
    "BUILDINGNUMBER": "ADDRESS",    # AI4Privacy
    "ZIPCODE": "ADDRESS",
    "LOCATION_ZIP": "ADDRESS",
    "ZIP_CODE": "ADDRESS",
    "ZIP": "ADDRESS",
    "POSTCODE": "ADDRESS",
    "GPS": "GPS_COORDINATE",
    "COORDINATE": "GPS_COORDINATE",
    "COORDINATES": "GPS_COORDINATE",
    "LATITUDE": "GPS_COORDINATE",
    "LONGITUDE": "GPS_COORDINATE",
    "NEARBYGPSCOORDINATE": "GPS_COORDINATE",  # AI4Privacy
    
    # === IDENTIFIERS ===
    "ID": "MRN",  # Stanford PHI-BERT generic ID label
    "US_SSN": "SSN",
    "SOCIAL_SECURITY": "SSN",
    "SOCIALSECURITYNUMBER": "SSN",
    "SSN_PARTIAL": "SSN",
    "UKNINUMBER": "SSN",  # UK National Insurance - treat as SSN equivalent
    "MEDICAL_RECORD": "MRN",
    "MEDICALRECORD": "MRN",
    "HEALTHPLAN": "HEALTH_PLAN_ID",
    "HEALTH_PLAN": "HEALTH_PLAN_ID",
    "MEMBERID": "HEALTH_PLAN_ID",
    "MEMBER_ID": "HEALTH_PLAN_ID",
    # Financial
    "CREDIT_CARD_NUMBER": "CREDIT_CARD",
    "CREDITCARDNUMBER": "CREDIT_CARD",
    "CREDITCARD": "CREDIT_CARD",
    "CC": "CREDIT_CARD",
    "IBAN_CODE": "IBAN",
    "IBANCODE": "IBAN",
    "ACCOUNTNUMBER": "ACCOUNT_NUMBER",
    "BANK_ACCOUNT": "ACCOUNT_NUMBER",
    "BITCOINADDRESS": "ACCOUNT_NUMBER",
    "LITECOINADDRESS": "ACCOUNT_NUMBER",  # AI4Privacy
    "ETHEREUMADDRESS": "ACCOUNT_NUMBER",  # AI4Privacy
    "BIC": "ACCOUNT_NUMBER",
    "SWIFT": "ACCOUNT_NUMBER",
    "ROUTING": "ABA_ROUTING",
    "ROUTING_NUMBER": "ABA_ROUTING",
    "BANK_ROUTING": "ABA_ROUTING",  # NEW
    # Licenses
    "US_DRIVER_LICENSE": "DRIVER_LICENSE",
    "DRIVER_LICENSE_NUMBER": "DRIVER_LICENSE",
    "DRIVERSLICENSE": "DRIVER_LICENSE",
    "LICENSE": "DRIVER_LICENSE",
    "US_PASSPORT": "PASSPORT",
    "PASSPORT_NUMBER": "PASSPORT",
    "PASSPORTNUMBER": "PASSPORT",
    "ACCOUNT": "ACCOUNT_NUMBER",
    # Provider identifiers
    "NATIONAL_PROVIDER_IDENTIFIER": "NPI",
    "PROVIDER_NPI": "NPI",
    "DEA_NUMBER": "DEA",
    "PRESCRIBER_DEA": "DEA",
    
    # === CONTACT ===
    "PHONE_NUMBER": "PHONE",
    "PHONENUMBER": "PHONE",
    "US_PHONE_NUMBER": "PHONE",
    "TELEPHONE": "PHONE",
    "TEL": "PHONE",
    "MOBILE": "PHONE",
    "CELL": "PHONE",
    "EMAIL_ADDRESS": "EMAIL",
    "EMAILADDRESS": "EMAIL",
    "FAX_NUMBER": "FAX",
    "FAXNUMBER": "FAX",
    "PAGER": "PHONE",
    "PAGER_NUMBER": "PHONE",
    
    # === NETWORK/DEVICE ===
    "IP": "IP_ADDRESS",
    "IPADDRESS": "IP_ADDRESS",
    "IPV4": "IP_ADDRESS",
    "IPV6": "IP_ADDRESS",
    "MAC": "MAC_ADDRESS",
    "MACADDRESS": "MAC_ADDRESS",
    "IMEI": "DEVICE_ID",
    "DEVICE": "DEVICE_ID",
    "BIOID": "DEVICE_ID",
    "USERAGENT": "DEVICE_ID",
    "USER_AGENT": "DEVICE_ID",
    "PHONEIMEI": "DEVICE_ID",  # AI4Privacy
    
    # === DATES ===
    "DATE_TIME": "DATE",
    "DATETIME": "DATE",
    "TIME": "DATE",
    "BIRTHDAY": "DATE_DOB",
    "DOB": "DATE_DOB",
    "DATEOFBIRTH": "DATE_DOB",
    "DATE_OF_BIRTH": "DATE_DOB",
    "BIRTH_DATE": "DATE_DOB",
    "BIRTHDATE": "DATE_DOB",
    "BIRTH_YEAR": "BIRTH_YEAR",
    "YEAR_OF_BIRTH": "BIRTH_YEAR",
    
    # === VEHICLES ===
    "VEHICLEVIN": "VIN",
    "VEHICLE_VIN": "VIN",
    "VEHICLE_IDENTIFICATION": "VIN",
    "VEHICLEVRM": "LICENSE_PLATE",
    "VEHICLE_PLATE": "LICENSE_PLATE",
    "PLATE_NUMBER": "LICENSE_PLATE",
    "VEHICLE": "VIN",
    
    # === PROFESSIONAL (i2b2) ===
    "PROFESSION": "PROFESSION",
    "OCCUPATION": "PROFESSION",
    "JOB": "PROFESSION",
    "JOB_TITLE": "PROFESSION",
    "JOBTITLE": "PROFESSION",
    "JOBAREA": "PROFESSION",    # AI4Privacy
    "JOBTYPE": "PROFESSION",    # AI4Privacy
    
    # === EMPLOYER (companies/organizations) ===
    # CHANGED: These now map to EMPLOYER instead of FACILITY
    "COMPANYNAME": "EMPLOYER",
    "COMPANY": "EMPLOYER",
    "ORG": "EMPLOYER",
    "ORGANIZATION": "EMPLOYER",
    
    # === CLINICAL (context-only, filtered before output) ===
    "HOSPITAL": "FACILITY",
    "VENDOR": "FACILITY",
    
    # === MEDICATION ===
    # NEW: Dictionary detector outputs MEDICATION, but add DRUG mapping for safety
    "DRUG": "MEDICATION",
    "MEDICINE": "MEDICATION",
    "RX": "MEDICATION",
}

# NOTE: Clinical context types (LAB_TEST, DIAGNOSIS, etc.) are defined in types.py
# as CLINICAL_CONTEXT_TYPES - single source of truth for the entire codebase
# PROFESSION is NOT filtered - job titles ARE HIPAA Safe Harbor identifiers (#11)

# Healthcare facility keywords - FACILITY spans must contain at least one
# to avoid false positives on generic company names
HEALTHCARE_FACILITY_KEYWORDS = frozenset([
    # Facility types
    "hospital", "medical", "clinic", "health", "healthcare", 
    "care", "center", "centre", "memorial", "general",
    "regional", "community", "university", "teaching",
    "children", "pediatric", "veterans", "va",
    "rehabilitation", "rehab", "psychiatric", "behavioral",
    "surgery", "surgical", "emergency", "urgent",
    "oncology", "cancer", "cardiac", "heart",
    "orthopedic", "dental", "eye", "vision",
    "pharmacy", "lab", "laboratory", "diagnostic",
    "imaging", "radiology", "hospice", "nursing",
    "assisted", "living", "senior", "elder",
    "specialty",  # Catches "X Specialty Clinic"
    # Common name patterns
    "st.", "saint", "mount", "mt.",
    "mercy", "providence", "good samaritan", "sacred heart",
    "baptist", "methodist", "presbyterian", "lutheran", "adventist",
])

# Major health systems without obvious keywords (whitelist)
KNOWN_HEALTH_SYSTEMS = frozenset([
    "kaiser", "kaiser permanente",
    "mayo", "mayo clinic",
    "cleveland clinic",
    "johns hopkins",
    "mass general", "massachusetts general",
    "cedars-sinai", "cedars sinai",
    "mount sinai", "mt sinai",
    "nyu langone",
    "scripps",
    "geisinger",
    "intermountain",
    "ascension",
    "hca",
    "tenet",
    "commonspirit",
    "dignity health",
    "sutter",
    "banner",
    "advocate",
    "atrium",
    "beaumont",
    "spectrum",
    "wellstar",
    "northwell",
    "ochsner",
    "piedmont",
    "sentara",
    "christus",
    "sharp",
    "uchealth",
    "ucsf",
    "ucla health",
])

# Build Aho-Corasick automaton for O(n) healthcare keyword matching
# Type annotation uses Any to avoid import-time errors when ahocorasick unavailable
_HEALTHCARE_AUTOMATON = None
if _AHOCORASICK_AVAILABLE:
    _HEALTHCARE_AUTOMATON = ahocorasick.Automaton()
    for keyword in HEALTHCARE_FACILITY_KEYWORDS:
        _HEALTHCARE_AUTOMATON.add_word(keyword, keyword)
    for system in KNOWN_HEALTH_SYSTEMS:
        _HEALTHCARE_AUTOMATON.add_word(system, system)
    _HEALTHCARE_AUTOMATON.make_automaton()


def is_valid_healthcare_facility(text: str) -> bool:
    """
    Check if text looks like a healthcare facility name.

    Uses Aho-Corasick automaton for O(n) matching when available,
    falls back to O(k*n) iteration otherwise.

    Reduces false positives on generic company names while keeping
    hospitals, clinics, and known health systems.
    """
    text_lower = text.lower()

    # O(n) path with Aho-Corasick
    if _HEALTHCARE_AUTOMATON is not None:
        # iter() returns matches - we just need to know if any exist
        for _ in _HEALTHCARE_AUTOMATON.iter(text_lower):
            return True
        return False

    # O(k*n) fallback when ahocorasick not available
    for system in KNOWN_HEALTH_SYSTEMS:
        if system in text_lower:
            return True
    for keyword in HEALTHCARE_FACILITY_KEYWORDS:
        if keyword in text_lower:
            return True
    return False


def normalize_type(entity_type: str) -> str:
    """Normalize entity type to canonical form."""
    return TYPE_NORMALIZE.get(entity_type, entity_type)


def normalize_name_types(spans: List[Span], text: str) -> List[Span]:
    """
    Normalize NAME subtypes based on context.

    Default to generic NAME unless strong contextual evidence exists.
    This prevents misclassification when ML models guess without context.

    Uses pre-compiled regex patterns for performance (defined at module level).

    Rules:
    - NAME_PROVIDER requires: Dr., MD, DO, NP, RN, PA, "ordered by", "reviewed by", etc.
    - NAME_PATIENT requires: "Patient:", "Pt:", admission/condition context
    - NAME_RELATIVE requires: family relationship terms
    - Otherwise → NAME (safe default)

    Args:
        spans: Merged spans (not mutated)
        text: Original text for context lookup

    Returns:
        Spans with normalized name types (new span objects, originals not modified)
    """
    text_lower = text.lower()

    def has_context(span: Span, before_patterns: list, after_patterns: list = None) -> bool:
        """Check if span has matching context before or after using pre-compiled patterns."""
        before_start = max(0, span.start - NAME_CONTEXT_WINDOW)
        before_text = text_lower[before_start:span.start]

        for pattern in before_patterns:
            if pattern.search(before_text):
                return True

        if after_patterns:
            after_end = min(len(text), span.end + NAME_CONTEXT_WINDOW)
            after_text = text_lower[span.end:after_end]

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


# =============================================================================
# MERGE_SPANS HELPER FUNCTIONS
# =============================================================================

def _normalize_span_types(spans: List[Span]) -> List[Span]:
    """
    Normalize entity types in spans (immutable - creates new spans when needed).

    Args:
        spans: Input spans with potentially non-normalized types

    Returns:
        Spans with normalized entity types
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


def _dedup_by_position_type(spans: List[Span]) -> List[Span]:
    """
    Deduplicate spans with same (start, end, type) keeping highest tier.

    When multiple detectors find the same span with the same type,
    keep only the one with highest authority (tier, then confidence).

    Args:
        spans: Input spans potentially with duplicates

    Returns:
        Deduplicated spans with best span from each position-type group
    """
    groups: Dict[tuple, List[Span]] = {}
    for span in spans:
        key = (span.start, span.end, span.entity_type)
        if key not in groups:
            groups[key] = []
        groups[key].append(span)

    # Keep best from each group
    return [
        max(group, key=lambda s: (s.tier, s.confidence))
        for group in groups.values()
    ]


def _select_non_overlapping(spans: List[Span]) -> List[Span]:
    """
    Greedy select non-overlapping spans from authority-sorted input.

    Uses interval tree for O(n log n) when available and span count > 100,
    otherwise falls back to O(n²) pairwise comparison.

    Args:
        spans: Spans sorted by authority (tier desc, confidence desc, length desc)

    Returns:
        Non-overlapping spans (highest authority wins conflicts)
    """
    selected = []

    if _INTERVALTREE_AVAILABLE and len(spans) > 100:
        # O(n log n) with interval tree for large span counts
        tree = IntervalTree()
        for span in spans:
            if not tree.overlaps(span.start, span.end):
                selected.append(span)
                # IntervalTree uses half-open intervals [start, end)
                # Ensure minimum interval width of 1 for edge cases
                tree.addi(span.start, max(span.end, span.start + 1), span)
    else:
        # O(n²) fallback - fine for small span counts (<100 spans)
        for span in spans:
            if not any(span.overlaps(s) for s in selected):
                selected.append(span)

    return selected


def merge_spans(spans: List[Span], min_confidence: float = 0.50, text: str = None) -> List[Span]:
    """
    Merge overlapping spans using authority ranking.

    This function follows immutable patterns - input spans are not modified.
    New spans are created when modifications are needed.

    Algorithm:
    1. Normalize entity types to canonical forms
    2. Filter low confidence spans
    3. Filter clinical context types (LAB_TEST, DIAGNOSIS, etc.)
    4. Filter invalid healthcare facility spans
    5. Normalize span boundaries (if text provided):
       5a. Trim whitespace from boundaries
       5b. Snap to word boundaries
       5c. Trim NAME spans at newlines
       5d. Trim NAME spans at non-name words
       5e. Merge adjacent ADDRESS spans
       5f. Trim trailing punctuation from ID-type spans
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
        text: Original text (optional, enables boundary normalization and context filtering)

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

    # Step 1: Normalize types (immutable - create new spans)
    spans = _normalize_span_types(spans)

    # Step 2: Filter low confidence
    spans = [s for s in spans if s.confidence >= min_confidence]

    # Step 3: Filter clinical context types (case-insensitive)
    spans = [s for s in spans if s.entity_type.upper() not in CLINICAL_CONTEXT_TYPES]

    # Step 4: Filter FACILITY spans that don't look like healthcare facilities
    spans = [s for s in spans
             if s.entity_type != "FACILITY" or is_valid_healthcare_facility(s.text)]

    if not spans:
        return []

    # Step 5: Normalize span boundaries (requires original text)
    if text:
        # 5a: Trim whitespace from span boundaries
        spans = trim_span_whitespace(spans, text)
        # 5b: Snap to word boundaries (prevents partial word tokenization)
        spans = snap_to_word_boundaries(spans, text)
        # 5c: Trim NAME spans at newlines (prevents over-extension into headers)
        spans = trim_names_at_newlines(spans, text)
        # 5d: Trim NAME spans at non-name words
        spans = trim_name_at_non_name_words(spans, text)
        # 5e: Merge adjacent ADDRESS spans
        spans = merge_adjacent_addresses(spans, text)
        # 5f: Trim trailing punctuation from ID-type spans
        spans = trim_trailing_punctuation(spans, text)

    # Step 6: Fix misclassified emails (NAME that looks like email → EMAIL)
    spans = fix_misclassified_emails(spans)

    # Step 7: Exact dedup - group by (start, end, type), keep highest tier
    groups: Dict[tuple, List[Span]] = {}
    for span in spans:
        key = (span.start, span.end, span.entity_type)
        if key not in groups:
            groups[key] = []
        groups[key].append(span)

    deduped = []
    for group in groups.values():
        best = max(group, key=lambda s: (s.tier, s.confidence))
        deduped.append(best)

    # Step 8: Remove contained spans (e.g., "K." inside "K. Edwards, DNP")
    deduped = remove_contained_spans(deduped)

    # Step 9: Filter short NAME spans (isolated initials like "K.", "R.")
    deduped = filter_short_names(deduped)

    # Step 10: Reclassify city names detected as NAME to ADDRESS
    deduped = filter_city_as_name(deduped)

    # Steps 11-12: Context-aware ML false positive filtering (requires text)
    if text:
        # Step 11: Filter ML-based MRN on ID cards
        deduped = filter_ml_mrn_on_id_cards(deduped, text)
        # Step 12: Filter tracking numbers misclassified as MRN
        deduped = filter_tracking_numbers(deduped, text)

    # Step 13: Sort by authority (higher tier > higher confidence > longer span)
    deduped.sort(key=lambda s: (s.tier, s.confidence, len(s)), reverse=True)

    # Step 14: Greedy select non-overlapping spans
    selected = []

    if _INTERVALTREE_AVAILABLE and len(deduped) > INTERVALTREE_THRESHOLD:
        # O(n log n) with IntervalTree for large span counts
        tree = IntervalTree()
        for span in deduped:
            if not tree.overlaps(span.start, span.end):
                selected.append(span)
                # IntervalTree uses half-open intervals [start, end)
                tree.addi(span.start, max(span.end, span.start + 1), span)
    else:
        # O(n²) fallback for small span counts
        for span in deduped:
            if not any(span.overlaps(s) for s in selected):
                selected.append(span)

    # Step 15: Sort by position
    selected.sort(key=lambda s: s.start)

    return selected
