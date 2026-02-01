"""
Span filtering for false positive reduction.

Filters out common ML false positives:
- Short NAME spans (isolated initials)
- MRN detections on ID cards
- Tracking numbers misclassified as MRN
- City names detected as NAME
"""

import re
from typing import List

from ..types import Span
from ..constants import MIN_NAME_LENGTH, TRACKING_CONTEXT_WINDOW


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
            continue
        result.append(span)

    return result


# TRACKING NUMBER FILTERING

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
    """
    result = []
    ml_detectors = ("phi_bert", "pii_bert", "phi_bert_onnx", "pii_bert_onnx", "ml")
    carrier_names = ("usps", "ups", "fedex", "dhl")

    for span in spans:
        # Only filter MRN from ML detectors
        if span.entity_type == "MRN" and span.detector in ml_detectors:
            span_text_clean = span.text.strip().rstrip(':').lower()

            # Filter carrier name prefixes detected as MRN
            if span_text_clean in carrier_names:
                continue

            # Get context before the span
            context_start = max(0, span.start - TRACKING_CONTEXT_WINDOW)
            context_before = text[context_start:span.start]

            if is_tracking_number(span.text, context_before):
                continue
        result.append(span)

    return result


# SHORT NAME FILTERING

def filter_short_names(spans: List[Span]) -> List[Span]:
    """
    Filter out very short NAME spans that are likely false positives.

    Single initials like "K.", "R.", "G." are almost never standalone PHI.
    They're usually part of a larger name that should be detected separately.
    """
    result = []
    for span in spans:
        # Only filter NAME-type spans
        if span.entity_type == "NAME" or span.entity_type.startswith("NAME_"):
            # Get text without trailing punctuation
            text = span.text.rstrip('.')
            if len(text) < MIN_NAME_LENGTH:
                continue
        result.append(span)

    return result


# CITY-AS-NAME FILTERING

# Common US city name suffixes (helps distinguish cities from names)
_CITY_SUFFIXES = (
    'burg', 'burgh', 'boro', 'borough', 'ville', 'view', 'field', 'ford',
    'port', 'land', 'wood', 'dale', 'vale', 'ton', 'town', 'city', 'springs',
    'falls', 'beach', 'heights', 'hills', 'park', 'lake', 'creek', 'ridge',
    'haven', 'grove', 'mount', 'point', 'bay', 'island',
)

# Pattern for "CITY, ST" format
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
                result.append(span)
        else:
            result.append(span)

    return result
