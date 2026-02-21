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

from __future__ import annotations

import re

from ..types import Span, Tier
from .base import BaseDetector
from .pattern_registry import PatternDefinition, _p
from .registry import register_detector

# Pattern definitions: frozen tuple of PatternDefinition objects
ADDITIONAL_PATTERNS: tuple[PatternDefinition, ...] = (
    # COMPANY - Company/Organization Names with legal suffixes
    # Detected as COMPANY (not EMPLOYER) so the type is not filtered out
    # by UNMAPPED_PRED_TYPES in benchmark scoring.
    _p(
        r"\b([A-Z][A-Za-z0-9&'\-]*(?:\s+[A-Z][A-Za-z0-9&'\-]*){0,5})\s+"
        r"(Inc\.?|Corp\.?|Corporation|Company|Co\.?|LLC|L\.L\.C\.?|"
        r"Ltd\.?|Limited|LP|L\.P\.?|LLP|L\.L\.P\.?|PLC|P\.L\.C\.?|NA|N\.A\.?|"
        r"Group|Holdings|Partners|Associates|Services|Solutions|"
        r"Industries|Enterprises|International|Consulting|Technologies|Tech)\b",
        "COMPANY", 0.85, 0, flags=0
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

    # COMPANY — "X and Sons", "X and Associates", "X, Y and Z" patterns
    # Name part: handles Mc/Mac/O' prefixes (McDonald, MacArthur, O'Brien)
    _p(
        r"\b((?:Mc|Mac|O')?[A-Z][a-z]+(?:\s+(?:Mc|Mac|O')?[A-Z][a-z]+)?\s+and\s+(?:Sons|Associates|Brothers|Partners|Daughters|Company))\b",
        "COMPANY", 0.85, 0, flags=0
    ),
    # "Halvorson, Streich and Beahan" — "X, Y and Z" pattern (faker-style)
    _p(
        r"\b((?:Mc|Mac|O')?[A-Z][a-z]+(?:[-'](?:Mc|Mac|O')?[A-Z][a-z]+)?\s*,\s*(?:Mc|Mac|O')?[A-Z][a-z]+(?:[-'](?:Mc|Mac|O')?[A-Z][a-z]+)?\s+and\s+(?:Mc|Mac|O')?[A-Z][a-z]+(?:[-'](?:Mc|Mac|O')?[A-Z][a-z]+)?)\b",
        "COMPANY", 0.82, 0, flags=0
    ),
    # "Schaden - Wolff", "Zieme - Kutch" — hyphenated company names
    _p(
        r"\b((?:Mc|Mac|O')?[A-Z][a-z]+(?:[-'](?:Mc|Mac|O')?[A-Z][a-z]+)?\s+-\s+(?:Mc|Mac|O')?[A-Z][a-z]+(?:[-'](?:Mc|Mac|O')?[A-Z][a-z]+)?)\b",
        "COMPANY", 0.75, 0, flags=0
    ),

    # AGE - Age Expressions (~579 missed)
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

    # "X years" without "old" — in context like "aged 58 years", "over 70 years"
    _p(
        r"\b(?:aged?|over|under|about|approximately|nearly)\s+(\d{1,3})\s*(?:years?|yrs?)\b",
        "AGE", 0.88, 1, flags=re.IGNORECASE
    ),

    # "X old" without "years" — grammatical shorthand: "I'm a 70 old Male"
    _p(
        r"\b(\d{1,3})\s+old\b",
        "AGE", 0.80, 0, flags=re.IGNORECASE
    ),

    # "aged X" without years — "patients aged over 58", "aged 41"
    _p(
        r"\baged\s+(?:over\s+|under\s+|about\s+|approximately\s+)?(\d{1,3})\b",
        "AGE", 0.88, 1, flags=re.IGNORECASE
    ),

    # "X years" in demographic context — "58 years", "61 years" near demographic words
    _p(
        r"\b(\d{1,3})\s+(?:years?|yrs?)\b(?=\s+(?:of\s+age|male|female|man|woman|patient|old)|\s*[,.])",
        "AGE", 0.85, 1, flags=re.IGNORECASE
    ),

    # Age with "as high as", "as old as", "up to" context
    _p(
        r"\b(?:as\s+(?:high|old|young)\s+as|up\s+to|at\s+least)\s+(\d{1,3})\b",
        "AGE", 0.82, 1, flags=re.IGNORECASE
    ),

    # "a 53 Female/Male" — article + age + gender (common in medical/demographic)
    _p(
        r"\b(?:a|an)\s+(\d{1,3})\s+(?:male|female|man|woman|patient|individual|person|child|infant)\b",
        "AGE", 0.85, 1, flags=re.IGNORECASE
    ),

    # "XX age group" — age before "age" keyword
    _p(
        r"\b(\d{1,3})\s+(?:age\s+group|age\s+range|age\s+bracket|age\s+category)\b",
        "AGE", 0.85, 1, flags=re.IGNORECASE
    ),

    # Demographic list: "Female, 40," or "Male, 67," — gender + age in comma list
    _p(
        r"\b(?:Male|Female|MTF|FTM|Transexual|Transgender|Non-binary)\s*,\s*(\d{1,3})\s*[,.]",
        "AGE", 0.80, 1, flags=re.IGNORECASE
    ),

    # "for 65 individuals" / "for 65 patients" — age before demographic word
    _p(
        r"\bfor\s+(\d{1,3})\s+(?:individuals?|patients?|persons?|people|adults?|seniors?|children)\b",
        "AGE", 0.78, 1, flags=re.IGNORECASE
    ),

    # Range: "from 82 to 37 years" — age range
    _p(
        r"\bfrom\s+(\d{1,3})\s+to\s+\d{1,3}\s*(?:years?|yrs?)?\b",
        "AGE", 0.80, 1, flags=re.IGNORECASE
    ),
    _p(
        r"\bfrom\s+\d{1,3}\s+to\s+(\d{1,3})\s*(?:years?|yrs?)?\b",
        "AGE", 0.80, 1, flags=re.IGNORECASE
    ),

    # CREDIT_CARD - Labeled context (bypasses Luhn for labeled patterns)
    # "credit card 6245478283474037", "card number is 8801520158172514"
    _p(
        r"\b(?:credit\s*card|debit\s*card|card\s*number|card\s*no\.?)\s*(?:is|:)?\s*(\d{13,19})\b",
        "CREDIT_CARD", 0.88, 1, flags=re.IGNORECASE
    ),
    # "charged to/through XXXX" — payment context
    _p(
        r"\b(?:charged?\s+to|payment\s+(?:of|through|via)|billed?\s+to|pay\s+(?:with|via|through))\s+(\d{13,19})\b",
        "CREDIT_CARD", 0.82, 1, flags=re.IGNORECASE
    ),
    # Card brand context: "jcb/visa/mastercard ... XXXX"
    _p(
        r"\b(?:visa|mastercard|amex|american\s+express|discover|jcb|diners[_\s]?club|unionpay|maestro)\s+\S*\s*(\d{13,19})\b",
        "CREDIT_CARD", 0.85, 1, flags=re.IGNORECASE
    ),

    # HEALTH_PLAN_ID / MEMBER_ID - Insurance Identifiers (~873 missed)
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

    # NPI - National Provider Identifier (10 digits, starts with 1 or 2)
    _p(
        r"\b(?:NPI|national\s+provider\s+(?:id|identifier|number))\s*[:\s#]*([12]\d{9})\b",
        "NPI", 0.95, 1, flags=re.IGNORECASE
    ),

    # NPI without label but in provider context (10 digits starting with 1 or 2)
    _p(
        r"\bprovider\s*(?:id|#|number)?\s*[:\s#]*([12]\d{9})\b",
        "NPI", 0.85, 1, flags=re.IGNORECASE
    ),

    # BANK_ROUTING - ABA Routing Numbers (9 digits)
    _p(
        r"\b(?:routing|ABA|RTN)\s*(?:number|#|no\.?)?\s*[:\s#]*(\d{9})\b",
        "BANK_ROUTING", 0.90, 1, flags=re.IGNORECASE
    ),

    # "routing: 123456789" simple pattern
    _p(
        r"\brouting\s*[:\s]+(\d{9})\b",
        "BANK_ROUTING", 0.88, 1, flags=re.IGNORECASE
    ),

    # EMPLOYEE_ID - Employee/Staff Identifiers
    _p(
        r"\b(?:employee|staff|personnel|worker)\s*(?:id|#|number|no\.?)\s*[:\s#]*([A-Z0-9]{4,15})\b",
        "EMPLOYEE_ID", 0.82, 1, flags=re.IGNORECASE
    ),

    _p(
        r"\bemp(?:loyee)?\s*id\s*[:\s#]*([A-Z0-9]{4,12})\b",
        "EMPLOYEE_ID", 0.80, 1, flags=re.IGNORECASE
    ),

    # EMP prefix without label: "EMP84518", "EMP730359"
    _p(
        r"\b(EMP\d{4,8})\b",
        "EMPLOYEE_ID", 0.85, 1, flags=0
    ),

    # EMPLOYEE_ID — broader context: "agent/representative/associate ID"
    # \b after id/number prevents matching "identified" as "id" + "entified"
    _p(
        r"\b(?:agent|representative|associate|contractor|intern)\s*(?:id\b|#|number|no\.?)\s*[:\s#]*([A-Z0-9]{4,15})\b",
        "EMPLOYEE_ID", 0.80, 1, flags=re.IGNORECASE
    ),

    # EMPLOYEE_ID — "identification number" + alphanumeric (employee context nearby)
    _p(
        r"\b(?:employee|staff|personnel)\s+(?:identification\s+)?(?:number|code)\s*[:\s#]*([A-Z]\d{5,12})\b",
        "EMPLOYEE_ID", 0.82, 1, flags=re.IGNORECASE
    ),

    # MRN - "MED" prefix: "MED15780803", "MED27468656"
    _p(
        r"\b(MED\d{5,10})\b",
        "MRN", 0.88, 1, flags=0
    ),

    # UNIQUE_ID - "UID-" prefix: "UID-6NPLXDV1", "UID-O7CTTWN5"
    _p(
        r"\b(UID-[A-Z0-9]{4,12})\b",
        "UNIQUE_ID", 0.88, 1, flags=0
    ),

    # UNIQUE_ID - "ID" prefix followed by alphanumeric (6+ chars total)
    _p(
        r"\b(ID[A-Z0-9]{4,12})\b",
        "UNIQUE_ID", 0.78, 1, flags=0
    ),

    # UNIQUE_ID - alphanumeric dash patterns: "AF7A-BHTY-92RH", "VVKF-IAMF-LDF7"
    # Requires at least one letter to avoid matching pure digit dashed sequences
    # (like credit card fragments "4012-8888-8888").
    _p(
        r"\b((?=[A-Z0-9]*[A-Z])[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})\b",
        "UNIQUE_ID", 0.75, 1, flags=0
    ),

    # ── Prefix-based patterns for under-detected types ──────────────────
    # These use well-known prefixes from the Gretel PII benchmark dataset
    # to correctly classify IDs that would otherwise be misclassified as
    # DRIVER_LICENSE, SSN, or CREDIT_CARD.

    # BIOMETRIC_ID — "BIO-" prefix: "BIO-584349070", "BIO-696292951"
    _p(
        r"\b(BIO-\d{6,12})\b",
        "BIOMETRIC_ID", 0.90, 1, flags=0
    ),
    # BIOMETRIC_ID — labeled context (require digit in value to avoid matching "device")
    _p(
        r"\b(?:biometric\s+(?:id\b|identifier)|fingerprint\s+(?:id\b|identifier))\s*[:\s#]*((?=[A-Z0-9]*\d)[A-Z0-9]{6,15})\b",
        "BIOMETRIC_ID", 0.85, 1, flags=re.IGNORECASE
    ),

    # HEALTH_PLAN_ID — "HPBN-" prefix: "HPBN-68005262", "HPBN-11321118"
    _p(
        r"\b(HPBN-\d{6,12})\b",
        "HEALTH_PLAN_ID", 0.92, 1, flags=0
    ),

    # CERTIFICATE_NUMBER — "CERT-" prefix: "CERT-2662017"
    _p(
        r"\b(CERT-\d{4,12})\b",
        "CERTIFICATE_NUMBER", 0.90, 1, flags=0
    ),
    # CERTIFICATE_NUMBER — "LIC-" prefix: "LIC-R7875623", "LIC-C721226"
    _p(
        r"\b(LIC-[A-Z]?\d{5,12})\b",
        "CERTIFICATE_NUMBER", 0.88, 1, flags=0
    ),
    # CERTIFICATE_NUMBER — labeled context
    # Require mandatory keyword (number/#/no.) to prevent matching "certificate <word>".
    # Use \b after "cert" to prevent matching prefix of "certificate".
    # Lookahead requires at least one digit in the value to exclude plain words.
    _p(
        r"\b(?:certificate|cert\b)\.?\s*(?:#|no\.?|number)\s*[:\s#]*((?=[A-Z0-9-]*\d)[A-Z0-9][-A-Z0-9]{4,19})\b",
        "CERTIFICATE_NUMBER", 0.82, 1, flags=re.IGNORECASE
    ),

    # MRN — "MRN-" prefix: "MRN-5292"
    _p(
        r"\b(MRN-\d{3,8})\b",
        "MRN", 0.90, 1, flags=0
    ),

    # ACCOUNT_NUMBER — "ACCT-" prefix: "ACCT-911155810"
    _p(
        r"\b(ACCT-\d{6,12})\b",
        "ACCOUNT_NUMBER", 0.90, 1, flags=0
    ),
    # ACCOUNT_NUMBER — "CUST" prefix: "CUST94287823", "CUST49375368"
    _p(
        r"\b(CUST\d{6,12})\b",
        "ACCOUNT_NUMBER", 0.88, 1, flags=0
    ),
    # ACCOUNT_NUMBER — labeled context with broader patterns
    _p(
        r"\b(?:account|acct|customer)\s*(?:#|no\.?|number|id)\s*[:\s#]*([A-Z]?\d{6,15})\b",
        "ACCOUNT_NUMBER", 0.82, 1, flags=re.IGNORECASE
    ),

    # ACCOUNT_NUMBER — alphanumeric format with context: "account G50145241932"
    # Catches letter+digit account numbers that would otherwise be missed.
    # Lookahead requires at least one digit to exclude pure-alpha words
    # like "expenses", "security", "connected", "Marketing".
    _p(
        r"\b(?:account|acct|customer)\s*(?:#|no\.?|number|id)?\s*[:\s#]+(?=[A-Z0-9]*\d)([A-Z][A-Z0-9]{7,15})\b",
        "ACCOUNT_NUMBER", 0.80, 1, flags=re.IGNORECASE
    ),

    # ACCOUNT_NUMBER — "assigned/designated/allocated number XXXX"
    _p(
        r"\b(?:assigned|designated|allocated)\s+(?:account\s+)?(?:number|id)\s*[:\s#]*([A-Z0-9]{6,17})\b",
        "ACCOUNT_NUMBER", 0.78, 1, flags=re.IGNORECASE
    ),

    # DEVICE_ID — labeled context for numeric device identifiers
    # Prevents 15-digit device IDs from being misclassified as CREDIT_CARD
    # Use identifier|id\b (longest first + word boundary) to prevent "id" matching prefix of "identifier"
    _p(
        r"\b(?:device\s+(?:identifier|serial|id\b)|serial\s+(?:number|#|no\.?))\s*[:\s#]*(\d{10,20})\b",
        "DEVICE_ID", 0.88, 1, flags=re.IGNORECASE
    ),
    # DEVICE_ID — labeled context for alphanumeric
    _p(
        r"\b(?:device\s+(?:identifier|id\b)|hardware\s+id\b)\s*[:\s#]*([A-Z0-9]{8,20})\b",
        "DEVICE_ID", 0.85, 1, flags=re.IGNORECASE
    ),
)


# Detector Class
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

                    # EMPLOYER: value must start with uppercase (reject "account")
                    if pdef.entity_type == "EMPLOYER":
                        if value[0].isalpha() and not value[0].isupper():
                            continue

                    # HEALTH_PLAN_ID/MEMBER_ID: must contain at least one digit
                    if pdef.entity_type in ("HEALTH_PLAN_ID", "MEMBER_ID"):
                        if not any(c.isdigit() for c in value):
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
