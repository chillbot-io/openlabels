"""Additional pattern detectors (EMPLOYER, AGE, HEALTH_PLAN_ID, NPI, BANK_ROUTING)."""

import logging
import re
from typing import List, Tuple

from ..types import Span, Tier
from .base import BasePatternDetector
from .constants import (
    CONFIDENCE_BORDERLINE,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MARGINAL,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_MEDIUM_LOW,
    CONFIDENCE_RELIABLE,
    CONFIDENCE_WEAK,
)

logger = logging.getLogger(__name__)

from .pattern_registry import create_pattern_adder

ADDITIONAL_PATTERNS: List[Tuple[str, str, float, int, int]] = []
_add = create_pattern_adder(ADDITIONAL_PATTERNS, compile_pattern=False)


# --- EMPLOYER - Company/Organization Names (~773 missed) ---
# Company names with common suffixes
_add(
    r"\b([A-Z][A-Za-z0-9&'\-]*(?:\s+[A-Z][A-Za-z0-9&'\-]*){0,5})\s+"
    r"(Inc\.?|Corp\.?|Corporation|Company|Co\.?|LLC|L\.L\.C\.?|"
    r"Ltd\.?|Limited|LP|L\.P\.?|LLP|L\.L\.P\.?|PLC|P\.L\.C\.?|NA|N\.A\.?|"
    r"Group|Holdings|Partners|Associates|Services|Solutions|"
    r"Industries|Enterprises|International|Consulting|Technologies|Tech)\b",
    "EMPLOYER", CONFIDENCE_LOW, 0, 0
)

# "employer: Company Name" or "works at Company Name"
_add(
    r"\b(?:employer|employed\s+(?:at|by)|works?\s+(?:at|for)|company)\s*[:\s]+([A-Z][A-Za-z0-9\s&'\-]{2,40}?)(?=[,.\n]|$)",
    "EMPLOYER", CONFIDENCE_MARGINAL, 1, re.IGNORECASE
)

# "employed by X" with capture
_add(
    r"\bemployed\s+by\s+([A-Z][A-Za-z0-9\s&'\-]{3,35}?)(?=\s+(?:as|since|for|where|located)|[,.\n]|$)",
    "EMPLOYER", CONFIDENCE_WEAK, 1, re.IGNORECASE
)


# --- AGE - Age Expressions (~579 missed) ---
# "45 years old", "45-year-old", "45 y/o", "45yo", "45 yr old"
_add(
    r"\b(\d{1,3})\s*[-–]?\s*(?:years?\s*old|year[-–]old|y/?o(?:ld)?|yo|yr\s*old)\b",
    "AGE", CONFIDENCE_RELIABLE, 0, re.IGNORECASE
)

# "age: 45", "age 45", "aged 45", "patient age: 45"
_add(
    r"\b(?:age[d]?|patient\s+age|pt\.?\s+age)\s*[:\s]\s*(\d{1,3})\b",
    "AGE", CONFIDENCE_MEDIUM, 1, re.IGNORECASE
)

# "45-year-old male/female/patient" (more specific context)
_add(
    r"\b(\d{1,3})[-–](?:year|yr)[-–]old\s+(?:male|female|patient|man|woman|child|infant|boy|girl|adult)\b",
    "AGE", 0.93, 1, re.IGNORECASE  # Specific: age + gender context
)

# "a 45 year old" (article before age)
_add(
    r"\b(?:a|an)\s+(\d{1,3})[-\s]?(?:year|yr)[-\s]?old\b",
    "AGE", CONFIDENCE_MEDIUM_LOW, 1, re.IGNORECASE
)

# Age in months for infants: "6 months old", "18 mo old"
_add(
    r"\b(\d{1,2})\s*(?:months?\s*old|mo\.?\s*old)\b",
    "AGE", CONFIDENCE_LOW, 0, re.IGNORECASE
)


# --- HEALTH_PLAN_ID / MEMBER_ID - Insurance Identifiers (~873 missed) ---
# "Member ID: ABC123456", "Subscriber ID: 123456789", "Policy #: XYZ789"
_add(
    r"\b(?:member|subscriber|policy|group|plan|insurance|ins|beneficiary)\s*"
    r"(?:id|ID|#|no\.?|number|num)\s*[:\s#]*([A-Z0-9]{5,20})\b",
    "HEALTH_PLAN_ID", CONFIDENCE_MEDIUM_LOW, 1, re.IGNORECASE
)

# Known insurance company prefixes (BCBS, UHC, etc.)
_add(
    r"\b((?:BCBS|UHC|UHG|AETNA|CIGNA|HUMANA|KAISER|ANTHEM|WPS|TRICARE|CHAMPUS)[A-Z0-9]{4,15})\b",
    "HEALTH_PLAN_ID", CONFIDENCE_MEDIUM, 1, 0
)

# Generic ID in insurance context
_add(
    r"\b(?:health\s*plan|insurance|coverage|carrier)\b.{0,30}?\b(?:id|#)\s*[:\s]*([A-Z0-9]{6,15})\b",
    "HEALTH_PLAN_ID", CONFIDENCE_BORDERLINE, 1, re.IGNORECASE
)

# Member ID standalone (common format)
_add(
    r"\bmember\s*(?:id|#|number)\s*[:\s#]*([A-Z]{2,4}\d{6,12})\b",
    "MEMBER_ID", CONFIDENCE_LOW, 1, re.IGNORECASE
)

# Medicaid/Medicare ID patterns
_add(
    r"\b(?:medicaid|medicare)\s*(?:id|#|number)?\s*[:\s#]*([A-Z0-9]{9,12})\b",
    "HEALTH_PLAN_ID", CONFIDENCE_MEDIUM_LOW, 1, re.IGNORECASE
)


# --- NPI - National Provider Identifier (10 digits, starts with 1 or 2) ---
_add(
    r"\b(?:NPI|national\s+provider\s+(?:id|identifier|number))\s*[:\s#]*([12]\d{9})\b",
    "NPI", CONFIDENCE_HIGH, 1, re.IGNORECASE
)

# NPI without label but in provider context (10 digits starting with 1 or 2)
_add(
    r"\bprovider\s*(?:id|#|number)?\s*[:\s#]*([12]\d{9})\b",
    "NPI", CONFIDENCE_LOW, 1, re.IGNORECASE
)


# --- BANK_ROUTING - ABA Routing Numbers (9 digits) ---
_add(
    r"\b(?:routing|ABA|RTN)\s*(?:number|#|no\.?)?\s*[:\s#]*(\d{9})\b",
    "BANK_ROUTING", CONFIDENCE_MEDIUM, 1, re.IGNORECASE
)

# "routing: 123456789" simple pattern
_add(
    r"\brouting\s*[:\s]+(\d{9})\b",
    "BANK_ROUTING", CONFIDENCE_MEDIUM_LOW, 1, re.IGNORECASE
)


# --- EMPLOYEE_ID - Employee/Staff Identifiers ---
_add(
    r"\b(?:employee|staff|personnel|worker)\s*(?:id|#|number|no\.?)\s*[:\s#]*([A-Z0-9]{4,15})\b",
    "EMPLOYEE_ID", CONFIDENCE_MARGINAL, 1, re.IGNORECASE
)

_add(
    r"\bemp(?:loyee)?\s*id\s*[:\s#]*([A-Z0-9]{4,12})\b",
    "EMPLOYEE_ID", CONFIDENCE_WEAK, 1, re.IGNORECASE
)


# --- Detector Class ---
class AdditionalPatternDetector(BasePatternDetector):
    """
    Pattern detector for additional entity types.

    Detects:
    - EMPLOYER: Company and organization names
    - AGE: Age expressions in various formats
    - HEALTH_PLAN_ID: Insurance member/subscriber IDs
    - MEMBER_ID: Alias for health plan IDs
    - NPI: National Provider Identifiers
    - BANK_ROUTING: ABA routing numbers
    - EMPLOYEE_ID: Employee identifiers
    """

    name = "additional_patterns"
    tier = Tier.PATTERN

    def __init__(self):
        self._compiled_patterns: List[Tuple[re.Pattern, str, float, int]] = []
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile all patterns."""
        compile_errors = 0
        for pattern, entity_type, confidence, group, flags in ADDITIONAL_PATTERNS:
            try:
                compiled = re.compile(pattern, flags)
                self._compiled_patterns.append((compiled, entity_type, confidence, group))
            except re.error as e:
                logger.warning(f"Invalid regex pattern for {entity_type}: {e}")
                compile_errors += 1

        if compile_errors > 0:
            logger.warning(f"AdditionalPatternDetector: {compile_errors} patterns failed to compile")
        else:
            logger.debug(f"AdditionalPatternDetector: compiled {len(self._compiled_patterns)} patterns")

    def is_available(self) -> bool:
        return len(self._compiled_patterns) > 0

    def get_patterns(self):
        """Return compiled patterns."""
        return self._compiled_patterns

    def detect(self, text: str) -> List[Span]:
        """Detect additional patterns in text with logging."""
        spans = super().detect(text)

        if spans:
            # Summarize by entity type
            type_counts = {}
            for span in spans:
                type_counts[span.entity_type] = type_counts.get(span.entity_type, 0) + 1
            logger.info(f"AdditionalPatternDetector found {len(spans)} entities: {type_counts}")

        return spans

    def _validate_match(self, entity_type: str, value: str) -> bool:
        """Validate matched values, especially AGE."""
        if entity_type == "AGE":
            try:
                # Extract just the number
                age_num = re.search(r'\d+', value)
                if age_num:
                    age = int(age_num.group())
                    if age < 0 or age > 120:
                        logger.debug(f"AGE validation failed: {age} is out of range (0-120)")
                        return False
            except ValueError as e:
                logger.debug(f"AGE validation failed: {e}")
                return False
        return True
