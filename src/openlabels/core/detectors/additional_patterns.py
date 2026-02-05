"""Additional pattern detectors for missing entity types.

Place this file in: scrubiq/detectors/additional_patterns.py

Then register in orchestrator.py (see bottom of file for instructions).

Covers entity types not handled by existing detectors:
- EMPLOYER: Company/organization names (773 missed in corpus)
- AGE: Age expressions (579 missed in corpus)
- HEALTH_PLAN_ID: Insurance member IDs (873 missed in corpus)
- MEMBER_ID: Alias for health plan IDs
- NPI: National Provider Identifiers
- BANK_ROUTING: ABA routing numbers
"""

import re
from typing import List, Tuple

from ..types import Span, Tier
from .base import BaseDetector


# Pattern definitions: (regex_pattern, entity_type, confidence, capture_group, flags)
ADDITIONAL_PATTERNS: List[Tuple[str, str, float, int, int]] = []


def _add(pattern: str, entity_type: str, confidence: float, group: int = 0, flags: int = 0):
    """Add a pattern to the list."""
    ADDITIONAL_PATTERNS.append((pattern, entity_type, confidence, group, flags))


# --- EMPLOYER - Company/Organization Names (~773 missed) ---
# Company names with common suffixes
_add(
    r"\b([A-Z][A-Za-z0-9&'\-]*(?:\s+[A-Z][A-Za-z0-9&'\-]*){0,5})\s+"
    r"(Inc\.?|Corp\.?|Corporation|Company|Co\.?|LLC|L\.L\.C\.?|"
    r"Ltd\.?|Limited|LP|L\.P\.?|LLP|L\.L\.P\.?|PLC|P\.L\.C\.?|NA|N\.A\.?|"
    r"Group|Holdings|Partners|Associates|Services|Solutions|"
    r"Industries|Enterprises|International|Consulting|Technologies|Tech)\b",
    "EMPLOYER", 0.85, 0, 0
)

# "employer: Company Name" or "works at Company Name"
_add(
    r"\b(?:employer|employed\s+(?:at|by)|works?\s+(?:at|for)|company)\s*[:\s]+([A-Z][A-Za-z0-9\s&'\-]{2,40}?)(?=[,.\n]|$)",
    "EMPLOYER", 0.82, 1, re.IGNORECASE
)

# "employed by X" with capture
_add(
    r"\bemployed\s+by\s+([A-Z][A-Za-z0-9\s&'\-]{3,35}?)(?=\s+(?:as|since|for|where|located)|[,.\n]|$)",
    "EMPLOYER", 0.80, 1, re.IGNORECASE
)


# --- AGE - Age Expressions (~579 missed) ---
# "45 years old", "45-year-old", "45 y/o", "45yo", "45 yr old"
_add(
    r"\b(\d{1,3})\s*[-–]?\s*(?:years?\s*old|year[-–]old|y/?o(?:ld)?|yo|yr\s*old)\b",
    "AGE", 0.92, 0, re.IGNORECASE
)

# "age: 45", "age 45", "aged 45", "patient age: 45"
_add(
    r"\b(?:age[d]?|patient\s+age|pt\.?\s+age)\s*[:\s]\s*(\d{1,3})\b",
    "AGE", 0.90, 1, re.IGNORECASE
)

# "45-year-old male/female/patient" (more specific context)
_add(
    r"\b(\d{1,3})[-–](?:year|yr)[-–]old\s+(?:male|female|patient|man|woman|child|infant|boy|girl|adult)\b",
    "AGE", 0.93, 1, re.IGNORECASE
)

# "a 45 year old" (article before age)
_add(
    r"\b(?:a|an)\s+(\d{1,3})[-\s]?(?:year|yr)[-\s]?old\b",
    "AGE", 0.88, 1, re.IGNORECASE
)

# Age in months for infants: "6 months old", "18 mo old"
_add(
    r"\b(\d{1,2})\s*(?:months?\s*old|mo\.?\s*old)\b",
    "AGE", 0.85, 0, re.IGNORECASE
)


# --- HEALTH_PLAN_ID / MEMBER_ID - Insurance Identifiers (~873 missed) ---
# "Member ID: ABC123456", "Subscriber ID: 123456789", "Policy #: XYZ789"
_add(
    r"\b(?:member|subscriber|policy|group|plan|insurance|ins|beneficiary)\s*"
    r"(?:id|ID|#|no\.?|number|num)\s*[:\s#]*([A-Z0-9]{5,20})\b",
    "HEALTH_PLAN_ID", 0.88, 1, re.IGNORECASE
)

# Known insurance company prefixes (BCBS, UHC, etc.)
_add(
    r"\b((?:BCBS|UHC|UHG|AETNA|CIGNA|HUMANA|KAISER|ANTHEM|WPS|TRICARE|CHAMPUS)[A-Z0-9]{4,15})\b",
    "HEALTH_PLAN_ID", 0.90, 1, 0
)

# Generic ID in insurance context
_add(
    r"\b(?:health\s*plan|insurance|coverage|carrier)\b.{0,30}?\b(?:id|#)\s*[:\s]*([A-Z0-9]{6,15})\b",
    "HEALTH_PLAN_ID", 0.78, 1, re.IGNORECASE
)

# Member ID standalone (common format)
_add(
    r"\bmember\s*(?:id|#|number)\s*[:\s#]*([A-Z]{2,4}\d{6,12})\b",
    "MEMBER_ID", 0.85, 1, re.IGNORECASE
)

# Medicaid/Medicare ID patterns
_add(
    r"\b(?:medicaid|medicare)\s*(?:id|#|number)?\s*[:\s#]*([A-Z0-9]{9,12})\b",
    "HEALTH_PLAN_ID", 0.88, 1, re.IGNORECASE
)


# --- NPI - National Provider Identifier (10 digits, starts with 1 or 2) ---
_add(
    r"\b(?:NPI|national\s+provider\s+(?:id|identifier|number))\s*[:\s#]*([12]\d{9})\b",
    "NPI", 0.95, 1, re.IGNORECASE
)

# NPI without label but in provider context (10 digits starting with 1 or 2)
_add(
    r"\bprovider\s*(?:id|#|number)?\s*[:\s#]*([12]\d{9})\b",
    "NPI", 0.85, 1, re.IGNORECASE
)


# --- BANK_ROUTING - ABA Routing Numbers (9 digits) ---
_add(
    r"\b(?:routing|ABA|RTN)\s*(?:number|#|no\.?)?\s*[:\s#]*(\d{9})\b",
    "BANK_ROUTING", 0.90, 1, re.IGNORECASE
)

# "routing: 123456789" simple pattern
_add(
    r"\brouting\s*[:\s]+(\d{9})\b",
    "BANK_ROUTING", 0.88, 1, re.IGNORECASE
)


# --- EMPLOYEE_ID - Employee/Staff Identifiers ---
_add(
    r"\b(?:employee|staff|personnel|worker)\s*(?:id|#|number|no\.?)\s*[:\s#]*([A-Z0-9]{4,15})\b",
    "EMPLOYEE_ID", 0.82, 1, re.IGNORECASE
)

_add(
    r"\bemp(?:loyee)?\s*id\s*[:\s#]*([A-Z0-9]{4,12})\b",
    "EMPLOYEE_ID", 0.80, 1, re.IGNORECASE
)


# --- Detector Class ---
class AdditionalPatternDetector(BaseDetector):
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
        for pattern, entity_type, confidence, group, flags in ADDITIONAL_PATTERNS:
            try:
                compiled = re.compile(pattern, flags)
                self._compiled_patterns.append((compiled, entity_type, confidence, group))
            except re.error as e:
                import logging
                logging.warning(f"Invalid regex pattern for {entity_type}: {e}")
    
    def is_available(self) -> bool:
        return len(self._compiled_patterns) > 0
    
    def detect(self, text: str) -> List[Span]:
        """Detect additional entity types in text."""
        spans = []
        
        for pattern, entity_type, confidence, group in self._compiled_patterns:
            for match in pattern.finditer(text):
                try:
                    if group > 0 and group <= len(match.groups()):
                        # Use specific capture group
                        value = match.group(group)
                        if value:
                            start = match.start(group)
                            end = match.end(group)
                        else:
                            continue
                    else:
                        # Use whole match
                        value = match.group(0)
                        start = match.start()
                        end = match.end()
                    
                    # Skip empty or too short matches
                    if not value or len(value.strip()) < 2:
                        continue
                    
                    # Validate AGE is reasonable (0-120)
                    if entity_type == "AGE":
                        try:
                            # Extract just the number
                            age_num = re.search(r'\d+', value)
                            if age_num:
                                age = int(age_num.group())
                                if age < 0 or age > 120:
                                    continue
                        except ValueError:
                            # Non-numeric age - skip this match
                            continue
                    
                    spans.append(Span(
                        start=start,
                        end=end,
                        text=text[start:end],
                        entity_type=entity_type,
                        confidence=confidence,
                        detector=self.name,
                        tier=self.tier,
                    ))

                except (IndexError, AttributeError, ValueError):
                    # Skip problematic matches (bad regex group, None match, etc.)
                    continue
        
        return spans


# --- ORCHESTRATOR REGISTRATION ---
# Add this to orchestrator.py in the _init_detectors() method:
#
# from .additional_patterns import AdditionalPatternDetector
#
# Then in the detector list, add:
#
#     AdditionalPatternDetector(),
#
# Or if using lazy loading:
#
#     ("additional_patterns", lambda: AdditionalPatternDetector()),
