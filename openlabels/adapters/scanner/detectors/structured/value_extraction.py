"""
Value extraction from labeled fields.

Extracts and validates values following detected labels using type-specific
patterns and validation rules.
"""

import logging
import re
from dataclasses import dataclass
from typing import Dict, Optional

from ...constants import MAX_STRUCTURED_VALUE_LENGTH
from .label_detection import DetectedLabel
from .prose_detection import looks_like_prose, clean_field_value
from ..constants import (CONFIDENCE_RELIABLE)

logger = logging.getLogger(__name__)


# Type-specific value patterns
VALUE_PATTERNS: Dict[str, re.Pattern] = {
    # Dates
    "DATE": re.compile(r'(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})'),
    "DATE_DOB": re.compile(r'(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})'),

    # SSN
    "SSN": re.compile(r'(\d{3}[\-\s]?\d{2}[\-\s]?\d{4})'),

    # Phone/Fax
    "PHONE": re.compile(r'(\(?\d{3}\)?[\-\.\s]?\d{3}[\-\.\s]?\d{4})'),
    "FAX": re.compile(r'(\(?\d{3}\)?[\-\.\s]?\d{3}[\-\.\s]?\d{4})'),

    # Email
    "EMAIL": re.compile(r'([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})'),

    # Network identifiers
    "IP_ADDRESS": re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'),
    "MAC_ADDRESS": re.compile(
        r'([0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-]'
        r'[0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2})'
    ),

    # Device identifiers
    "DEVICE_ID": re.compile(r'((?:SN|S/N)?\s*[A-Z0-9\-]{5,20}|\(\d{2}\)\d{14,30})'),

    # Vehicle identifiers
    "LICENSE_PLATE": re.compile(r'([A-Z]{2,3}[\-\s]?\d{3,4}|\d{3,4}[\-\s]?[A-Z]{2,3})'),
    "VIN": re.compile(r'([A-HJ-NPR-Z0-9]{17})'),

    # ZIP
    "ZIP": re.compile(r'(\d{5}(?:\-\d{4})?)'),

    # Physical descriptors
    "PHYSICAL_DESC": re.compile(r"([A-Za-z0-9'\"\-]+)"),

    # Generic IDs
    "MRN": re.compile(r'([A-Z]*\d[\dA-Z\-]{3,15})'),
    "HEALTH_PLAN_ID": re.compile(r'([A-Z]*\d[\dA-Z\-]{3,20})'),
    "DRIVER_LICENSE": re.compile(r'([A-Z]*\d[\dA-Z\-\s]{3,15})'),
    "MEDICARE_ID": re.compile(r'([A-Z0-9]{10,12})'),
    "ACCOUNT_NUMBER": re.compile(r'([A-Z]*\d[\dA-Z\-]{3,15})'),
    "ENCOUNTER_ID": re.compile(r'([A-Z]*\d[\dA-Z\-]{3,15})'),
    "ACCESSION_ID": re.compile(r'([A-Z]*\d[\dA-Z\-]{3,15})'),
    "DOCUMENT_ID": re.compile(r'(\d{6,20})'),
    "ID_NUMBER": re.compile(r'([A-Z]*\d[\dA-Z\-]{3,15})'),
    "NPI": re.compile(r'(\d{10})'),
    "DEA": re.compile(r'([A-Z]{2}\d{7})'),
    "PASSPORT": re.compile(r'([A-Z0-9]{6,12})'),

    # Names
    "NAME": re.compile(
        r'((?:Dr\.?\s+)?[A-Z][A-Za-z\'\-]*(?:[\s,]+[A-Z][A-Za-z\'\-]*\.?){0,4})'
    ),
    "NAME_PATIENT": re.compile(
        r'((?:Dr\.?\s+)?[A-Z][A-Za-z\'\-]*(?:[\s,]+[A-Z][A-Za-z\'\-]*\.?){0,4})'
    ),
    "NAME_PROVIDER": re.compile(
        r'((?:Dr\.?\s+)?[A-Z][A-Za-z\'\-]*(?:[\s,]+[A-Z][A-Za-z\'\-]*\.?){0,4})'
    ),

    # Address
    "ADDRESS": re.compile(
        r'(\d+[^:\n]{5,50}?)(?=\s+\d{0,2}[a-z]?\s*[A-Z]{2,}:|\s{2,}|\n|$)'
    ),

    # Facility names
    "FACILITY": re.compile(
        r'([A-Z][A-Za-z.\s\'\-&]+(?:Hospital|Medical|Clinic|Center|Health)?)',
        re.I
    ),
}

# Generic terminator pattern - stops at next labeled field
GENERIC_TERMINATOR = re.compile(r'\s+(?:\d{0,2}[a-z]?\s+)?[A-Z]{2,}\s*[:\-]|\s{2,}|\n')


@dataclass
class ExtractedField:
    """A field label + value pair extracted from text."""
    label: str
    phi_type: str
    value: str
    value_start: int
    value_end: int
    confidence: float


def extract_value(
    text: str,
    label: DetectedLabel,
    next_label: Optional[DetectedLabel] = None
) -> Optional[ExtractedField]:
    """
    Extract the value following a label.

    Uses type-specific patterns when available, falls back to generic extraction.

    Args:
        text: Full document text
        label: The detected label
        next_label: The next label in sequence (if any) to bound extraction

    Returns:
        ExtractedField if value found, None otherwise
    """
    if label.phi_type is None:
        return None

    # Start extraction after label
    start = label.label_end

    # Skip leading whitespace
    while start < len(text) and text[start] in ' \t':
        start += 1

    # Find end boundary
    if next_label:
        max_end = next_label.label_start
    else:
        max_end = min(start + MAX_STRUCTURED_VALUE_LENGTH, len(text))

    # Extract candidate text
    candidate = text[start:max_end]

    if not candidate.strip():
        return None

    # Try type-specific pattern first
    value = None
    raw_value = None

    if label.phi_type in VALUE_PATTERNS:
        pattern = VALUE_PATTERNS[label.phi_type]
        match = pattern.match(candidate)
        if match:
            raw_value = match.group(1)
            value = raw_value.strip()

    # Fall back to generic extraction
    if value is None:
        term_match = GENERIC_TERMINATOR.search(candidate)
        if term_match:
            raw_value = candidate[:term_match.start()]
            value = raw_value.strip()
        else:
            raw_value = candidate.rstrip()
            value = raw_value.strip()

    if not value:
        return None

    # Clean the value
    value = clean_field_value(value, label.phi_type)

    if not value:
        return None

    # Reject prose-like values
    if looks_like_prose(value):
        logger.debug(f"Rejected prose-like value for {label.phi_type}")
        return None

    # Calculate exact positions
    value_start_in_candidate = raw_value.find(value) if raw_value else 0
    actual_start = start + value_start_in_candidate
    actual_end = actual_start + len(value)

    # Special handling for ADDRESS: extend to include city/state/zip
    if label.phi_type == "ADDRESS":
        remaining = text[actual_end:]
        multiline_continuation = re.match(
            r'(\s*\n\s*[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)',
            remaining
        )
        if multiline_continuation:
            continuation = multiline_continuation.group(1)
            value = value + continuation
            actual_end = actual_end + len(continuation)

    # Validate value
    if not validate_value(value, label.phi_type):
        return None

    return ExtractedField(
        label=label.label,
        phi_type=label.phi_type,
        value=value,
        value_start=actual_start,
        value_end=actual_end,
        confidence=CONFIDENCE_RELIABLE,  # High confidence for label-based extraction
    )


def validate_value(value: str, phi_type: str) -> bool:
    """
    Validate that extracted value is plausible for the PHI type.
    """
    if len(value) < 1:
        return False

    if phi_type in ("DATE", "DATE_DOB"):
        if not re.search(r'\d', value):
            return False

    elif phi_type == "SSN":
        digits = re.sub(r'\D', '', value)
        if len(digits) < 4 or len(digits) > 11:
            return False

    elif phi_type in ("PHONE", "FAX"):
        digits = re.sub(r'\D', '', value)
        if len(digits) < 7 or len(digits) > 15:
            return False

    elif phi_type == "EMAIL":
        if '@' not in value:
            return False

    elif phi_type == "ZIP":
        digits = re.sub(r'\D', '', value)
        if len(digits) not in (5, 9):
            return False

    elif phi_type in ("MRN", "HEALTH_PLAN_ID", "ACCOUNT_NUMBER", "ID_NUMBER", "DOCUMENT_ID"):
        if not re.search(r'[A-Za-z0-9]', value):
            return False
        if phi_type == "ID_NUMBER" and not re.search(r'\d', value):
            return False
        fp_words = {
            'range', 'result', 'value', 'normal', 'test', 'level', 'type', 'class', 'code'
        }
        if value.lower() in fp_words:
            return False
        if len(value) < 3:
            return False

    elif phi_type == "NAME" or phi_type.startswith("NAME_"):
        if not re.search(r'[A-Za-z]', value):
            return False
        if re.match(r'^[\d\s\-]+$', value):
            return False
        if len(value) < 2:
            return False
        words = value.split()
        if len(words) == 1 and not value[0].isupper():
            return False
        fp_words = {
            'range', 'result', 'results', 'test', 'tests', 'value', 'values',
            'normal', 'abnormal', 'positive', 'negative', 'pending', 'final',
            'report', 'chart', 'note', 'notes', 'history', 'physical',
            'loss', 'gain', 'change', 'changes', 'level', 'levels',
            'high', 'low', 'moderate', 'severe', 'mild', 'acute', 'chronic',
            'male', 'female', 'unknown', 'other', 'none', 'yes', 'no',
            'call', 'return', 'follow', 'see', 'refer', 'consult',
        }
        if value.lower() in fp_words:
            return False

    elif phi_type == "ADDRESS":
        if len(value) < 5:
            return False

    elif phi_type == "PHYSICAL_DESC":
        if len(value) < 2:
            return False
        fp_words = {'loss', 'gain', 'change', 'normal', 'abnormal', 'stable', 'unchanged'}
        if value.lower() in fp_words:
            return False

    elif phi_type == "DRIVER_LICENSE":
        if not re.search(r'[A-Za-z0-9]', value):
            return False

    return True
