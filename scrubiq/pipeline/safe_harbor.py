"""HIPAA Safe Harbor transformations per 45 CFR §164.514(b)(2)."""

import re
from typing import List, Optional

from ..types import Span


# 3-digit ZIP prefixes with population < 20,000 (2000 Census)
# Per HHS guidance, these must be replaced with "000"
HIPAA_ZERO_PREFIXES = frozenset([
    "036", "059", "063", "102", "203",
    "556", "692", "790", "821", "823",
    "830", "831", "878", "879", "884",
    "890", "893",
])

# Patterns for extracting year from dates
DATE_PATTERNS = [
    re.compile(r'\b(\d{4})\b'),                     # Bare year: 1980
    re.compile(r'\d{1,2}[/-]\d{1,2}[/-](\d{4})'),   # MM/DD/YYYY or MM-DD-YYYY
    re.compile(r'(\d{4})-\d{1,2}-\d{1,2}'),         # ISO: YYYY-MM-DD
    re.compile(r'[A-Za-z]+\s+\d{1,2},?\s+(\d{4})'), # Month DD, YYYY
    re.compile(r'\d{1,2}\s+[A-Za-z]+\s+(\d{4})'),   # DD Month YYYY
]


def extract_year(date_str: str) -> Optional[str]:
    """Extract year from date string. Returns year only per §164.514(b)(2)(i)(C)."""
    for pattern in DATE_PATTERNS:
        match = pattern.search(date_str)
        if match:
            return match.group(1)
    return None


def generalize_age(age_str: str) -> str:
    """Ages over 89 become '90+' per §164.514(b)(2)(i)(C)."""
    try:
        age = int(age_str)
        return "90+" if age > 89 else age_str
    except ValueError:
        return age_str


def truncate_zip(zip_str: str) -> str:
    """Truncate to 3 digits, or '000' for low-population areas per §164.514(b)(2)(i)(B)."""
    digits = re.sub(r'\D', '', zip_str)
    if len(digits) < 3:
        return zip_str
    prefix = digits[:3]
    return "000" if prefix in HIPAA_ZERO_PREFIXES else prefix


def apply_safe_harbor(spans: List[Span], session_id: str) -> List[Span]:
    """
    Set safe_harbor_value for audit compliance.

    This function follows immutable patterns - input spans are not modified.
    New spans are created when modifications are needed.

    Only 3 types get transformed values:
    - Dates → year only
    - Ages > 89 → "90+"
    - ZIPs → 3 digits (or "000")

    All other types get None here - tokenizer sets them to the token string,
    which is compliant per §164.514(c) (re-identification codes are permitted).
    """
    date_types = {"DATE", "DATE_DOB", "DATE_RANGE", "BIRTH_YEAR"}

    result = []
    for span in spans:
        if span.entity_type in date_types:
            new_value = extract_year(span.text)
        elif span.entity_type == "AGE":
            new_value = generalize_age(span.text)
        elif span.entity_type == "ZIP":
            new_value = truncate_zip(span.text)
        else:
            # Token becomes the safe harbor value (set in tokenizer)
            new_value = None

        # Create new span with safe_harbor_value set (immutable pattern)
        if new_value != span.safe_harbor_value:
            result.append(Span(
                start=span.start,
                end=span.end,
                text=span.text,
                entity_type=span.entity_type,
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
                safe_harbor_value=new_value,
                needs_review=span.needs_review,
                review_reason=span.review_reason,
                coref_anchor_value=span.coref_anchor_value,
                token=span.token,
            ))
        else:
            result.append(span)

    return result
