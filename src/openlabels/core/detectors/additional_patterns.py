"""Additional pattern detectors for missing entity types.

Additional pattern detectors registered via the detector orchestrator.

Covers entity types not handled by existing detectors:
- EMPLOYER: Company/organization names (773 missed in corpus)
- AGE: Age expressions (579 missed in corpus)
- HEALTH_PLAN_ID: Insurance member IDs (873 missed in corpus)
- MEMBER_ID: Alias for health plan IDs
- NPI: National Provider Identifiers
- BANK_ROUTING: ABA routing numbers
"""

import re

from ..types import Span, Tier
from .base import BaseDetector
from .pattern_registry import PatternDefinition, _p
from .registry import register_detector

# Pattern definitions: frozen tuple of PatternDefinition objects
ADDITIONAL_PATTERNS: tuple[PatternDefinition, ...] = (
    # --- EMPLOYER - Company/Organization Names (~773 missed) ---
    # Company names with common suffixes
    _p(
        r"\b([A-Z][A-Za-z0-9&'\-]*(?:\s+[A-Z][A-Za-z0-9&'\-]*){0,5})\s+"
        r"(Inc\.?|Corp\.?|Corporation|Company|Co\.?|LLC|L\.L\.C\.?|"
        r"Ltd\.?|Limited|LP|L\.P\.?|LLP|L\.L\.P\.?|PLC|P\.L\.C\.?|NA|N\.A\.?|"
        r"Group|Holdings|Partners|Associates|Services|Solutions|"
        r"Industries|Enterprises|International|Consulting|Technologies|Tech)\b",
        "EMPLOYER", 0.85, 0, flags=0
    ),

    # "employer: Company Name" or "works at Company Name"
    _p(
        r"\b(?:employer|employed\s+(?:at|by)|works?\s+(?:at|for)|company)\s*[:\s]+([A-Z][A-Za-z0-9\s&'\-]{2,40}?)(?=[,.\n]|$)",
        "EMPLOYER", 0.82, 1, flags=re.IGNORECASE
    ),

    # "employed by X" with capture
    _p(
        r"\bemployed\s+by\s+([A-Z][A-Za-z0-9\s&'\-]{3,35}?)(?=\s+(?:as|since|for|where|located)|[,.\n]|$)",
        "EMPLOYER", 0.80, 1, flags=re.IGNORECASE
    ),

    # --- AGE - Age Expressions (~579 missed) ---
    # "45 years old", "45-year-old", "45 y/o", "45yo", "45 yr old"
    _p(
        r"\b(\d{1,3})\s*[-–]?\s*(?:years?\s*old|year[-–]old|y/?o(?:ld)?|yo|yr\s*old)\b",
        "AGE", 0.92, 0, flags=re.IGNORECASE
    ),

    # "age: 45", "age 45", "aged 45", "patient age: 45"
    _p(
        r"\b(?:age[d]?|patient\s+age|pt\.?\s+age)\s*[:\s]\s*(\d{1,3})\b",
        "AGE", 0.90, 1, flags=re.IGNORECASE
    ),

    # "45-year-old male/female/patient" (more specific context)
    _p(
        r"\b(\d{1,3})[-–](?:year|yr)[-–]old\s+(?:male|female|patient|man|woman|child|infant|boy|girl|adult)\b",
        "AGE", 0.93, 1, flags=re.IGNORECASE
    ),

    # "a 45 year old" (article before age)
    _p(
        r"\b(?:a|an)\s+(\d{1,3})[-\s]?(?:year|yr)[-\s]?old\b",
        "AGE", 0.88, 1, flags=re.IGNORECASE
    ),

    # Age in months for infants: "6 months old", "18 mo old"
    _p(
        r"\b(\d{1,2})\s*(?:months?\s*old|mo\.?\s*old)\b",
        "AGE", 0.85, 0, flags=re.IGNORECASE
    ),

    # --- HEALTH_PLAN_ID / MEMBER_ID - Insurance Identifiers (~873 missed) ---
    # "Member ID: ABC123456", "Subscriber ID: 123456789", "Policy #: XYZ789"
    _p(
        r"\b(?:member|subscriber|policy|group|plan|insurance|ins|beneficiary)\s*"
        r"(?:id|ID|#|no\.?|number|num)\s*[:\s#]*([A-Z0-9]{5,20})\b",
        "HEALTH_PLAN_ID", 0.88, 1, flags=re.IGNORECASE
    ),

    # Known insurance company prefixes (BCBS, UHC, etc.)
    _p(
        r"\b((?:BCBS|UHC|UHG|AETNA|CIGNA|HUMANA|KAISER|ANTHEM|WPS|TRICARE|CHAMPUS)[A-Z0-9]{4,15})\b",
        "HEALTH_PLAN_ID", 0.90, 1, flags=0
    ),

    # Generic ID in insurance context
    _p(
        r"\b(?:health\s*plan|insurance|coverage|carrier)\b.{0,30}?\b(?:id|#)\s*[:\s]*([A-Z0-9]{6,15})\b",
        "HEALTH_PLAN_ID", 0.78, 1, flags=re.IGNORECASE
    ),

    # Member ID standalone (common format)
    _p(
        r"\bmember\s*(?:id|#|number)\s*[:\s#]*([A-Z]{2,4}\d{6,12})\b",
        "MEMBER_ID", 0.85, 1, flags=re.IGNORECASE
    ),

    # Medicaid/Medicare ID patterns
    _p(
        r"\b(?:medicaid|medicare)\s*(?:id|#|number)?\s*[:\s#]*([A-Z0-9]{9,12})\b",
        "HEALTH_PLAN_ID", 0.88, 1, flags=re.IGNORECASE
    ),

    # --- NPI - National Provider Identifier (10 digits, starts with 1 or 2) ---
    _p(
        r"\b(?:NPI|national\s+provider\s+(?:id|identifier|number))\s*[:\s#]*([12]\d{9})\b",
        "NPI", 0.95, 1, flags=re.IGNORECASE
    ),

    # NPI without label but in provider context (10 digits starting with 1 or 2)
    _p(
        r"\bprovider\s*(?:id|#|number)?\s*[:\s#]*([12]\d{9})\b",
        "NPI", 0.85, 1, flags=re.IGNORECASE
    ),

    # --- BANK_ROUTING - ABA Routing Numbers (9 digits) ---
    _p(
        r"\b(?:routing|ABA|RTN)\s*(?:number|#|no\.?)?\s*[:\s#]*(\d{9})\b",
        "BANK_ROUTING", 0.90, 1, flags=re.IGNORECASE
    ),

    # "routing: 123456789" simple pattern
    _p(
        r"\brouting\s*[:\s]+(\d{9})\b",
        "BANK_ROUTING", 0.88, 1, flags=re.IGNORECASE
    ),

    # --- EMPLOYEE_ID - Employee/Staff Identifiers ---
    _p(
        r"\b(?:employee|staff|personnel|worker)\s*(?:id|#|number|no\.?)\s*[:\s#]*([A-Z0-9]{4,15})\b",
        "EMPLOYEE_ID", 0.82, 1, flags=re.IGNORECASE
    ),

    _p(
        r"\bemp(?:loyee)?\s*id\s*[:\s#]*([A-Z0-9]{4,12})\b",
        "EMPLOYEE_ID", 0.80, 1, flags=re.IGNORECASE
    ),
)


# --- Detector Class ---
@register_detector
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

    def detect(self, text: str) -> list[Span]:
        """Detect additional entity types in text."""
        spans = []

        for pdef in ADDITIONAL_PATTERNS:
            for match in pdef.pattern.finditer(text):
                try:
                    if pdef.group > 0 and pdef.group <= len(match.groups()):
                        # Use specific capture group
                        value = match.group(pdef.group)
                        if value:
                            start = match.start(pdef.group)
                            end = match.end(pdef.group)
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
                    if pdef.entity_type == "AGE":
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
                        entity_type=pdef.entity_type,
                        confidence=pdef.confidence,
                        detector=self.name,
                        tier=self.tier,
                    ))

                except (IndexError, AttributeError, ValueError):
                    # Skip problematic matches (bad regex group, None match, etc.)
                    continue

        return spans
