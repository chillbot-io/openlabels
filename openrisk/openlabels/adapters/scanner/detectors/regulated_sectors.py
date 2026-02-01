"""Regulated sector detectors: FERPA (education), Legal, and Immigration identifiers.

These patterns detect identifiers protected under specific regulatory frameworks:
- FERPA: Student records, enrollment IDs, financial aid
- Legal: Court cases, attorney IDs, inmate numbers
- Immigration: Visa numbers, alien registration, green card numbers
"""

import logging
import re
from typing import List, Tuple

from ..types import Span, Tier
from .base import BasePatternDetector
from .constants import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_RELIABLE,
    CONFIDENCE_VERY_HIGH,
    CONFIDENCE_WEAK,
)
from .pattern_registry import create_pattern_adder

logger = logging.getLogger(__name__)

REGULATED_PATTERNS: List[Tuple[re.Pattern, str, float, int]] = []
_add = create_pattern_adder(REGULATED_PATTERNS)


# =============================================================================
# FERPA - Education Records (Family Educational Rights and Privacy Act)
# =============================================================================

# Student ID - Various formats
# Format: often 7-10 digits, sometimes with prefix
_add(
    r'(?:student[_\s]*(?:id|number|no\.?)|stu[_\s]*id)[:\s]*([A-Z]?\d{6,10})\b',
    'STUDENT_ID', CONFIDENCE_RELIABLE, 1, re.I
)

# Student ID with common prefixes (S, STU, SID)
_add(
    r'\b(S\d{7,9}|STU\d{6,9}|SID\d{6,9})\b',
    'STUDENT_ID', CONFIDENCE_HIGH, 1
)

# Enrollment ID
_add(
    r'(?:enrollment[_\s]*(?:id|number|no\.?))[:\s]*([A-Z0-9]{6,12})\b',
    'ENROLLMENT_ID', CONFIDENCE_RELIABLE, 1, re.I
)

# Financial Aid ID / FAFSA ID
# FAFSA ID is typically a 9-digit number
_add(
    r'(?:fafsa|financial[_\s]*aid)[_\s]*(?:id|number|no\.?)[:\s]*(\d{9})\b',
    'FINANCIAL_AID_ID', CONFIDENCE_VERY_HIGH, 1, re.I
)

# GPA (Grade Point Average)
_add(
    r'(?:gpa|grade[_\s]*point[_\s]*average)[:\s]*([0-4]\.\d{1,2})\b',
    'GPA', CONFIDENCE_RELIABLE, 1, re.I
)

# Transcript reference
_add(
    r'(?:transcript|academic[_\s]*record)[_\s]*(?:id|number|no\.?|#)[:\s]*([A-Z0-9\-]{6,15})\b',
    'TRANSCRIPT', CONFIDENCE_MEDIUM, 1, re.I
)

# IEP ID (Individualized Education Program)
_add(
    r'(?:iep|individualized[_\s]*education[_\s]*(?:program|plan))[_\s]*(?:id|number|no\.?)[:\s]*([A-Z0-9\-]{6,12})\b',
    'IEP_ID', CONFIDENCE_HIGH, 1, re.I
)

# Teacher/Instructor ID
_add(
    r'(?:teacher|instructor|faculty)[_\s]*(?:id|number|no\.?)[:\s]*([A-Z]?\d{5,8})\b',
    'TEACHER_ID', CONFIDENCE_MEDIUM, 1, re.I
)


# =============================================================================
# LEGAL - Court Records and Legal Professional IDs
# =============================================================================

# Case Number / Docket Number
# Federal format: 1:23-cv-12345, 2:23-cr-00123
_add(
    r'\b(\d{1,2}:\d{2}-(?:cv|cr|mc|mj|po|ap|bk|br)-\d{4,6})\b',
    'CASE_NUMBER', CONFIDENCE_VERY_HIGH, 1, re.I
)

# State case number format: 2023-CF-001234
_add(
    r'\b(\d{4}-[A-Z]{2,3}-\d{4,8})\b',
    'CASE_NUMBER', CONFIDENCE_HIGH, 1
)

# Generic case/docket reference
_add(
    r'(?:case|docket)[_\s]*(?:number|no\.?|#)[:\s]*([A-Z0-9\-]{6,20})\b',
    'CASE_NUMBER', CONFIDENCE_MEDIUM, 1, re.I
)

# Bar Number (Attorney registration)
# Format varies by state, typically 4-8 digits
_add(
    r'(?:bar|attorney)[_\s]*(?:number|no\.?|#|id)[:\s]*(\d{4,8})\b',
    'BAR_NUMBER', CONFIDENCE_RELIABLE, 1, re.I
)

# PACER ID (Public Access to Court Electronic Records)
_add(
    r'(?:pacer)[_\s]*(?:id|login|account)[:\s]*([a-zA-Z0-9]{4,20})\b',
    'PACER_ID', CONFIDENCE_MEDIUM, 1, re.I
)

# Inmate Number / BOP Register Number
# Federal BOP: 5 digits-3 digits (12345-678)
_add(
    r'\b(\d{5}-\d{3})\b',
    'INMATE_NUMBER', CONFIDENCE_HIGH, 1
)

# State inmate numbers (various formats)
_add(
    r'(?:inmate|prisoner|offender|bop)[_\s]*(?:number|no\.?|#|id)[:\s]*([A-Z]?\d{6,10})\b',
    'INMATE_NUMBER', CONFIDENCE_RELIABLE, 1, re.I
)

# Booking Number
_add(
    r'(?:booking)[_\s]*(?:number|no\.?|#)[:\s]*([A-Z0-9\-]{6,15})\b',
    'ARREST_RECORD', CONFIDENCE_MEDIUM, 1, re.I
)

# Probation/Parole ID
_add(
    r'(?:probation|parole)[_\s]*(?:id|number|no\.?|#)[:\s]*([A-Z0-9\-]{5,12})\b',
    'PROBATION_ID', CONFIDENCE_MEDIUM, 1, re.I
)

# Warrant Number
_add(
    r'(?:warrant)[_\s]*(?:number|no\.?|#)[:\s]*([A-Z0-9\-]{6,15})\b',
    'WARRANT_NUMBER', CONFIDENCE_MEDIUM, 1, re.I
)


# =============================================================================
# IMMIGRATION - USCIS and Visa Identifiers
# =============================================================================

# Alien Registration Number (A-Number)
# Format: A followed by 7-9 digits (A12345678 or A123456789)
_add(
    r'\b(A\d{7,9})\b',
    'A_NUMBER', CONFIDENCE_VERY_HIGH, 1
)

# A-Number with context
_add(
    r'(?:alien[_\s]*(?:registration|reg\.?)|a[_\s]*number|uscis[_\s]*number)[:\s]*(A?\d{7,9})\b',
    'A_NUMBER', CONFIDENCE_VERY_HIGH, 1, re.I
)

# Visa Number (typically on visa foil)
# Usually 8 alphanumeric characters
_add(
    r'(?:visa)[_\s]*(?:number|no\.?|#|foil)[:\s]*([A-Z0-9]{8})\b',
    'VISA_NUMBER', CONFIDENCE_RELIABLE, 1, re.I
)

# I-94 Number (Arrival/Departure Record)
# 11-digit number
_add(
    r'(?:i-?94|arrival[_\s]*departure)[_\s]*(?:number|no\.?|#)[:\s]*(\d{11})\b',
    'I94_NUMBER', CONFIDENCE_VERY_HIGH, 1, re.I
)

# Green Card Number (Permanent Resident Card)
# 13 characters: 3 letters + 10 digits (e.g., SRC0123456789)
# Note: Standalone pattern removed - same format as USCIS receipt numbers
# Use contextual pattern only to avoid false positives

# Green Card with context
_add(
    r'(?:green[_\s]*card|permanent[_\s]*resident[_\s]*card|prc)[_\s]*(?:number|no\.?|#)[:\s]*([A-Z0-9]{13})\b',
    'GREEN_CARD_NUMBER', CONFIDENCE_VERY_HIGH, 1, re.I
)

# EAD Number (Employment Authorization Document)
# Similar to green card format
_add(
    r'(?:ead|employment[_\s]*authorization)[_\s]*(?:number|no\.?|#)[:\s]*([A-Z]{3}\d{10})\b',
    'EAD_NUMBER', CONFIDENCE_VERY_HIGH, 1, re.I
)

# SEVIS ID (Student and Exchange Visitor Information System)
# Format: N followed by 10 digits (N1234567890)
_add(
    r'\b(N\d{10})\b',
    'SEVIS_ID', CONFIDENCE_HIGH, 1
)

# SEVIS with context
_add(
    r'(?:sevis)[_\s]*(?:id|number|no\.?|#)[:\s]*(N?\d{10})\b',
    'SEVIS_ID', CONFIDENCE_VERY_HIGH, 1, re.I
)

# USCIS Receipt Number (Petition tracking)
# Format: 3 letters + 10 digits (e.g., EAC2390000001)
_add(
    r'\b([A-Z]{3}\d{10})\b',
    'PETITION_NUMBER', CONFIDENCE_MEDIUM, 1
)

# Petition with context
_add(
    r'(?:receipt|petition|uscis[_\s]*case)[_\s]*(?:number|no\.?|#)[:\s]*([A-Z]{3}\d{10})\b',
    'PETITION_NUMBER', CONFIDENCE_VERY_HIGH, 1, re.I
)

# Travel Document Number
_add(
    r'(?:travel[_\s]*document|refugee[_\s]*travel)[_\s]*(?:number|no\.?|#)[:\s]*([A-Z0-9]{9,12})\b',
    'TRAVEL_DOCUMENT_NUMBER', CONFIDENCE_MEDIUM, 1, re.I
)

# Naturalization Certificate Number
_add(
    r'(?:naturalization|citizenship)[_\s]*(?:certificate|cert\.?)[_\s]*(?:number|no\.?|#)[:\s]*(\d{7,9})\b',
    'NATURALIZATION_NUMBER', CONFIDENCE_HIGH, 1, re.I
)


class RegulatedSectorDetector(BasePatternDetector):
    """
    Detects identifiers from regulated sectors:
    - FERPA (education records)
    - Legal (court records, attorney IDs)
    - Immigration (USCIS identifiers)
    """

    name = "regulated_sectors"
    tier = Tier.PATTERN

    def get_patterns(self):
        return REGULATED_PATTERNS

    def detect(self, text: str) -> List[Span]:
        spans = super().detect(text)

        if spans:
            type_counts = {}
            for span in spans:
                type_counts[span.entity_type] = type_counts.get(span.entity_type, 0) + 1
            logger.info(f"RegulatedSectorDetector found {len(spans)} entities: {type_counts}")

        return spans

    def _validate_match(self, entity_type: str, value: str) -> bool:
        """Additional validation for specific entity types."""
        if entity_type == 'A_NUMBER':
            # A-Number should be 7-9 digits after optional A prefix
            digits = value.lstrip('A')
            return 7 <= len(digits) <= 9 and digits.isdigit()

        if entity_type == 'GPA':
            # GPA should be 0.0-4.0 range
            try:
                gpa = float(value)
                return 0.0 <= gpa <= 4.0
            except ValueError:
                return False

        if entity_type == 'INMATE_NUMBER':
            # Federal BOP format validation
            if '-' in value:
                parts = value.split('-')
                if len(parts) == 2:
                    return parts[0].isdigit() and parts[1].isdigit()

        return True
