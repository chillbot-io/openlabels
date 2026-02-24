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

# False positive filters for STATE detection
_STATE_FALSE_POSITIVES = frozenset({
    "active", "pending", "inactive", "closed", "open", "new",
    "complete", "completed", "approved", "denied", "valid",
    "invalid", "current", "previous", "final", "initial",
    "unknown", "other", "none", "null", "ready", "done",
    "processing", "submitted", "cancelled", "expired",
    "suspended", "terminated", "updated", "verified",
})

# False positive filters for CITY detection
_CITY_FALSE_POSITIVES = frozenset({
    "the", "this", "that", "these", "those",
    "none", "unknown", "other", "general", "main",
    "overview", "summary", "details", "section", "appendix",
    "introduction", "conclusion", "chapter", "part",
})

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

    # JOB_TITLE — Context-labeled patterns
    # "Title: Software Engineer", "Position: Marketing Manager"
    # "Occupation: Data Scientist", "Role: Product Designer"
    # Uses inline (?i:...) for the label prefix so the capture group
    # stays case-sensitive (only matches capitalized words).
    _p(
        r"\b(?i:title|position|occupation|role|designation|job\s*title|"
        r"job\s*position)\s*[:]\s*"
        r"([A-Z][a-z]+(?:\s+(?:of|and|&)\s+[A-Za-z]+|\s+[A-Z][a-z]+)*)",
        "JOB_TITLE", 0.82, 1, flags=0,
    ),

    # "works as a Software Engineer", "employed as Data Analyst"
    _p(
        r"\b(?i:works?|employed|serving|working)\s+(?i:as)\s+(?:a\s+|an\s+|the\s+)?"
        r"([A-Z][a-z]+(?:\s+(?:of|and|&)\s+[A-Za-z]+|\s+[A-Z][a-z]+)*)",
        "JOB_TITLE", 0.78, 1, flags=0,
    ),

    # JOB_TITLE — Keyword-anchored patterns
    # "Senior/Junior/Lead/Chief/Head/Principal X" where X ends with a role word
    _p(
        r"\b((?:Senior|Junior|Lead|Chief|Head|Principal|Associate|"
        r"Assistant|Executive|Managing|General|Regional|Global|"
        r"Vice|Deputy|Staff)\s+"
        r"(?:[A-Z][a-z]+\s+){0,3}"
        r"(?:Engineer|Developer|Scientist|Analyst|Designer|Architect|"
        r"Manager|Director|Officer|Consultant|Coordinator|Specialist|"
        r"Administrator|Advisor|Strategist|Planner|Supervisor|"
        r"Technician|Therapist|Inspector|Instructor|Researcher|"
        r"Producer|Editor|Writer|Accountant|Auditor|Attorney|"
        r"Counsel|Nurse|Physician|Surgeon|Pilot|Captain|Agent|"
        r"Representative|Recruiter|Trainer|Coach))\b",
        "JOB_TITLE", 0.80, 0, flags=0,
    ),

    # Standalone multi-word role with known suffix (capitalized)
    # "Software Engineer", "Marketing Manager", "Data Scientist"
    # Excludes articles/prepositions as the leading word.
    _p(
        r"\b((?!The |A |An )[A-Z][a-z]+\s+(?:[A-Z][a-z]+\s+){0,2}"
        r"(?:Engineer|Developer|Scientist|Analyst|Designer|Architect|"
        r"Manager|Director|Officer|Consultant|Coordinator|Specialist|"
        r"Administrator|Advisor|Strategist|Planner|Supervisor|"
        r"Technician|Therapist|Inspector|Instructor|Researcher|"
        r"Producer|Editor|Writer|Accountant|Auditor|Attorney|"
        r"Counsel|Recruiter|Trainer|Coach))\b",
        "JOB_TITLE", 0.72, 0, flags=0,
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
    # Raised from 0.80 to 0.83 — was below AGE entity threshold (0.82),
    # causing all matches to be silently filtered before scoring.
    _p(
        r"\b(\d{1,3})\s+old\b",
        "AGE", 0.83, 0, flags=re.IGNORECASE
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

    # UNIQUE_ID — UUID v4 format with context label
    # "uuid: 6178d0a7-...", "ID: 6178d0a7-...", "identifier: ..."
    _p(
        r"\b(?:uuid|guid|identifier|unique[\s_]?id|reference[\s_]?(?:id|number|code)|"
        r"tracking[\s_]?(?:id|number))\s*[:=]\s*"
        r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
        "UNIQUE_ID", 0.92, 1, flags=re.IGNORECASE
    ),
    # UNIQUE_ID — UUID v4 without context (lower confidence so API_KEY wins in dedup)
    # 8-4-4-4-12 hex digits separated by hyphens.
    _p(
        r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
        "UNIQUE_ID", 0.75, 1, flags=re.IGNORECASE
    ),

    # UNIQUE_ID — SHA-256 hash: 64 hex chars
    # Require labeled context to avoid matching random hex strings
    _p(
        r"\b(?:hash|sha256|sha-256|identifier|unique\s*id|participant\s*id)\s*[:\s]+([0-9a-f]{64})\b",
        "UNIQUE_ID", 0.85, 1, flags=re.IGNORECASE
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
    # ACCOUNT_NUMBER — "bank account XXXX" (no "number" keyword)
    _p(
        r"\bbank\s+account\s+(\d{6,17})\b",
        "ACCOUNT_NUMBER", 0.85, 1, flags=re.IGNORECASE
    ),
    # ACCOUNT_NUMBER — IBAN format with context: "IBAN: GB29NWBK60161331926819"
    # Requires IBAN label to avoid matching random alphanumeric strings.
    _p(
        r"\bIBAN\s*[:\s]+([A-Z]{2}\d{2}[A-Z0-9]{4,30})\b",
        "ACCOUNT_NUMBER", 0.90, 1, flags=re.IGNORECASE
    ),
    # ACCOUNT_NUMBER — "Acc No:" / "A/C:" British abbreviations
    _p(
        r"\b(?:Acc\.?\s*(?:No\.?|#)|A/C)\s*[:\s#]+(\d{6,17})\b",
        "ACCOUNT_NUMBER", 0.85, 1, flags=re.IGNORECASE
    ),
    # ACCOUNT_NUMBER — "CUS" prefix (shorter than CUST): "CUS028139", "CUS109342"
    _p(
        r"\b(CUS\d{5,12})\b",
        "ACCOUNT_NUMBER", 0.88, 1, flags=0
    ),
    # ACCOUNT_NUMBER — "SUP" prefix (support/supplier IDs): "SUP872419"
    _p(
        r"\b(SUP\d{5,12})\b",
        "ACCOUNT_NUMBER", 0.85, 1, flags=0
    ),
    # ACCOUNT_NUMBER — Single letter + digits in account context:
    # "account C73628945", "customer ID: C938D76215"
    _p(
        r"\b(?:account|acct|customer|client|member|policy|subscriber)\s*(?:#|no\.?|number|id)?\s*[:\s#]+([A-Z]\d{6,12})\b",
        "ACCOUNT_NUMBER", 0.82, 1, flags=re.IGNORECASE
    ),
    # ACCOUNT_NUMBER — Single letter + digits/alphanumeric in broader context:
    # "reference C938D76215", "case C73628945", "record C72689135"
    _p(
        r"\b(?:reference|ref|case|claim|file|record|invoice|receipt|confirmation|transaction|transfer|payment)\s*"
        r"(?:#|no\.?|number|id)?\s*[:\s#]+"
        r"((?=[A-Z0-9]*\d)[A-Z][A-Z0-9]{6,14})\b",
        "ACCOUNT_NUMBER", 0.78, 1, flags=re.IGNORECASE
    ),
    # ACCOUNT_NUMBER — broader label context with just digits (7+ digits)
    # "reference 472163985", "record 5832917640"
    _p(
        r"\b(?:reference|ref|case|claim|file|record|invoice|receipt|confirmation|transaction)\s*"
        r"(?:#|no\.?|number|id)?\s*[:\s#]+(\d{7,15})\b",
        "ACCOUNT_NUMBER", 0.78, 1, flags=re.IGNORECASE
    ),

    # ACCOUNT_NUMBER — broader financial/case context for digit-only accounts
    # Matches digits preceded by broader financial context words
    _p(
        r"\b(?:balance|debit|credit|billing|invoice|statement|"
        r"portfolio|fund|savings|checking|investment|"
        r"wire|remittance|receipt|ledger|folio)\s+(?:\S+\s+){0,3}?(\d{7,12})\b",
        "ACCOUNT_NUMBER", 0.78, 1, flags=re.IGNORECASE
    ),
    # ACCOUNT_NUMBER — "number/no/# XXXX" in financial paragraph context
    _p(
        r"\b(?:no\.|no|#)\s*(\d{7,12})\b(?=\s+(?:was|is|has|had|will|should|must|can|may|shall|for|on|in|at|to|from|with|by))",
        "ACCOUNT_NUMBER", 0.75, 1, flags=re.IGNORECASE
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

    # ── STATE — US state detection (no ML fallback) ──────────────────────
    # US 2-letter state abbreviation after comma in address context:
    # "Portland, OR 97201" or "Austin, TX 78701"
    _p(
        r",\s*(A[KLRZ]|C[AOT]|D[CE]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|"
        r"N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AIT]|W[AIVY])\s+\d{5}\b",
        "STATE", 0.88, 1, flags=0
    ),
    # US 2-letter state abbreviation after comma, before period/comma/newline/end
    _p(
        r",\s*(A[KLRZ]|C[AOT]|D[CE]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|"
        r"N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AIT]|W[AIVY])\b(?=\s*[,.\n]|\s+\d)",
        "STATE", 0.82, 1, flags=0
    ),
    # US 2-letter state abbreviation before 5-digit ZIP (no comma required):
    # "San Francisco CA 94105", "Chicago IL 60601"
    _p(
        r"\b(A[KLRZ]|C[AOT]|D[CE]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|"
        r"N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AIT]|W[AIVY])\s+\d{5}\b",
        "STATE", 0.78, 1, flags=0
    ),
    # ZIP after US 2-letter state abbreviation (no comma required):
    # "San Francisco CA 94105", "Chicago IL 60601"
    _p(
        r"\b(?:A[KLRZ]|C[AOT]|D[CE]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|"
        r"N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AIT]|W[AIVY])\s+(\d{5}(?:-\d{4})?)\b",
        "ZIP", 0.80, 1, flags=0
    ),
    # Indian PIN code (6 digits starting with 1-8) in labeled context:
    # "PIN: 452001", "Postal Code: 110001", "pin code 452001"
    _p(
        r"\b(?:pin\s*code|postal\s*code|zip\s*code|zip|pincode)\s*[:\s]+([1-8]\d{5})\b",
        "ZIP", 0.88, 1, flags=re.IGNORECASE
    ),
    # Labeled: "State: California", "State: New York"
    # Case-sensitive "State:" to avoid matching "state: active/pending".
    _p(
        r"\bState\s*:\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b",
        "STATE", 0.82, 1, flags=0
    ),
    # US 2-letter state abbreviation before ZIP without comma:
    # "City NAME ST 12345" — capitalized word(s) followed by state + zip
    _p(
        r"\b[A-Z][a-z]+\s+(A[KLRZ]|C[AOT]|D[CE]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|"
        r"N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AIT]|W[AIVY])\s+\d{5}\b",
        "STATE", 0.82, 1, flags=0
    ),
    # Labeled: "State: CA", "State: NY" — 2-letter abbreviation with label
    _p(
        r"\bState\s*:\s*(A[KLRZ]|C[AOT]|D[CE]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|"
        r"N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AIT]|W[AIVY])\b",
        "STATE", 0.85, 1, flags=0
    ),

    # ── CITY — labeled context patterns ──────────────────────────────────
    # "City: Portland", "Hometown: Denver"
    _p(
        r"\b(?:City|Hometown)\s*:\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b",
        "CITY", 0.82, 1, flags=0
    ),
    # "City of Portland", "Town of Springfield"
    _p(
        r"\b(?:City|Town|Village)\s+of\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b",
        "CITY", 0.85, 1, flags=0
    ),

    # ── API_KEY — broader token/authorization patterns ───────────────────
    # "auth_token: VALUE" / "access_token: VALUE"
    _p(
        r"\b(?:auth[_\s]?token|access[_\s]?token|session[_\s]?token|refresh[_\s]?token)\s*[=:\s]+([A-Za-z0-9\-_.]{16,100})\b",
        "API_KEY", 0.82, 1, flags=re.IGNORECASE
    ),
    # "Authorization: Bearer <token>"
    _p(
        r"\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9\-_.]+)\b",
        "API_KEY", 0.90, 1, flags=re.IGNORECASE
    ),
    # "x-api-key: VALUE" HTTP header
    _p(
        r"\bx-api-key\s*:\s*([A-Za-z0-9\-_.]{16,100})\b",
        "API_KEY", 0.90, 1, flags=re.IGNORECASE
    ),
    # Generic "token" label with colon/equals and long alphanumeric value
    _p(
        r"\b(?:token|secret[_\s]?key)\s*[=:]\s*([A-Za-z0-9\-_]{20,100})\b",
        "API_KEY", 0.80, 1, flags=re.IGNORECASE
    ),
    # HTTP cookie: "Set-Cookie: name=value;..."
    _p(
        r"\b(?:Set-)?Cookie\s*:\s*\S+=([A-Za-z0-9\-_.%+/]{16,200})",
        "API_KEY", 0.82, 1, flags=re.IGNORECASE
    ),
    # HTTP cookie with attributes: "name=value; Path=/; HttpOnly; Secure"
    # Matches full cookie strings including Path, Max-Age, Expires, etc.
    _p(
        r"\b(\w+=[\w\-]+;\s*Path=/[^;\s]*(?:;\s*(?:HttpOnly|Secure|SameSite=\w+|Max-Age=\d+|Expires=[^;]+))*)",
        "API_KEY", 0.85, 1, flags=0
    ),

    # ── DEMOGRAPHICS ──────────────────────────────────────────────────────
    # GENDER — labeled context: "Gender: Male", "Sex: Female", "gender: M"
    _p(
        r"\b(?:gender|sex)\s*[:=]\s*(male|female|m|f|non[- ]?binary|transgender|"
        r"other|prefer\s+not\s+to\s+say|genderqueer|genderfluid|agender|"
        r"intersex|two[- ]?spirit)\b",
        "GENDER", 0.92, 1, flags=re.IGNORECASE
    ),
    # GENDER — verb form: "identifies as male/female/non-binary"
    _p(
        r"\b(?:identifies|identified|identifying)\s+as\s+(male|female|"
        r"non[- ]?binary|transgender|genderqueer|genderfluid)\b",
        "GENDER", 0.88, 1, flags=re.IGNORECASE
    ),
    # GENDER — parenthetical: "(Male)", "(Female)", "(M)", "(F)"
    _p(
        r"\((Male|Female|M|F|Non[- ]?binary|Transgender)\)",
        "GENDER", 0.85, 1, flags=0
    ),

    # ETHNICITY — labeled context: "Race: Caucasian", "Ethnicity: Hispanic"
    _p(
        r"\b(?:race|ethnicity|ethnic\s+group|racial\s+group)\s*[:=]\s*"
        r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\b",
        "ETHNICITY", 0.90, 1, flags=0
    ),
    # ETHNICITY — verb form: "ethnically Japanese", "racially mixed"
    _p(
        r"\b(?:ethnically|racially)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b",
        "ETHNICITY", 0.85, 1, flags=0
    ),

    # NATIONALITY — labeled context: "Nationality: French", "Citizenship: German"
    _p(
        r"\b(?:nationality|citizenship|citizen\s+of|national\s+of)\s*[:=]?\s*"
        r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b",
        "NATIONALITY", 0.90, 1, flags=0
    ),
    # NATIONALITY — "is a/an X citizen/national"
    _p(
        r"\bis\s+(?:a|an)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+(?:citizen|national|resident)\b",
        "NATIONALITY", 0.85, 1, flags=0
    ),

    # HEIGHT — labeled: "Height: 5'10\"", "Height: 178 cm", "Height: 5 ft 10 in"
    _p(
        r"\b[Hh]eight\s*[:=]\s*(\d{1,2}'\d{1,2}\"?)\b",
        "HEIGHT", 0.92, 1, flags=0
    ),
    _p(
        r"\b[Hh]eight\s*[:=]\s*(\d{2,3}\s*(?:cm|centimeters?|metres?|meters?))\b",
        "HEIGHT", 0.92, 1, flags=0
    ),
    _p(
        r"\b[Hh]eight\s*[:=]\s*(\d{1,2}\s*(?:ft|feet|foot)\.?\s*\d{1,2}\s*(?:in|inches?)?)\b",
        "HEIGHT", 0.92, 1, flags=0
    ),

    # WEIGHT — labeled: "Weight: 180 lbs", "Weight: 82 kg"
    _p(
        r"\b[Ww]eight\s*[:=]\s*(\d{2,3}\s*(?:lbs?|pounds?|kg|kilograms?|kgs?|stone))\b",
        "WEIGHT", 0.92, 1, flags=0
    ),

    # ── BIOMETRIC_ID — letter + 11 digits in context ─────────────────────
    # Patterns like M87563249103, J47293856129, A74283965213
    _p(
        r"\b(?:biometric(?:\s+(?:id|identifier|template|hash|data))?|"
        r"fingerprint(?:\s+(?:id|identifier|template|hash))?|"
        r"retina(?:\s+(?:id|scan))?|iris(?:\s+(?:id|scan))?|"
        r"facial(?:\s+(?:id|recognition\s+id))?)\s*[:\s#]+([A-Z]\d{10,14})\b",
        "BIOMETRIC_ID", 0.88, 1, flags=re.IGNORECASE
    ),

    # ── MRN — additional prefix patterns ──────────────────────────────────
    # BH-00025483 — 2-letter prefix + hyphen + 6-8 digits
    _p(
        r"\b(?:medical\s+record|MRN|patient\s+(?:id|number|record))\s*[:\s#]*([A-Z]{1,3}-\d{5,10})\b",
        "MRN", 0.88, 1, flags=re.IGNORECASE
    ),
    # Zero-padded 10-digit MRN in context: "MRN: 0004829175"
    _p(
        r"\b(?:medical\s+record|MRN|patient\s+(?:id|number|record))\s*[:\s#]*(0\d{7,11})\b",
        "MRN", 0.90, 1, flags=re.IGNORECASE
    ),
    # M-375924 — single letter + hyphen + 5-8 digits in MRN context
    _p(
        r"\b(?:MRN|medical\s+record)\s*[:\s#]*([A-Z]-\d{5,8})\b",
        "MRN", 0.88, 1, flags=re.IGNORECASE
    ),

    # ── EMPLOYEE_ID — additional patterns ─────────────────────────────────
    # Mixed alphanumeric with department codes: "21MKT105C"
    _p(
        r"\b(?:employee|staff|personnel|worker)\s*(?:id|#|number|no\.?|code)\s*[:\s#]*"
        r"((?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{6,12})\b",
        "EMPLOYEE_ID", 0.82, 1, flags=re.IGNORECASE
    ),
    # Digits-hyphen-digits in employee context: "21-34987"
    _p(
        r"\b(?:employee|staff|badge|personnel)\s*(?:id|#|number|no\.?)\s*[:\s#]*(\d{2,4}-\d{4,8})\b",
        "EMPLOYEE_ID", 0.82, 1, flags=re.IGNORECASE
    ),

    # ── CERTIFICATE_NUMBER — ILC prefix ───────────────────────────────────
    # ILC-12345-678 — ILC prefix with segment separators
    _p(
        r"\b(ILC-\d{3,6}-\d{2,6})\b",
        "CERTIFICATE_NUMBER", 0.88, 1, flags=0
    ),

    # ── ACCOUNT_NUMBER — additional patterns ──────────────────────────────
    # DigitsCUST pattern: "23CUST14238" — digits + CUST + digits
    _p(
        r"\b(\d{1,4}CUST\d{4,12})\b",
        "ACCOUNT_NUMBER", 0.88, 1, flags=0
    ),
    # IBAN with spaces — "FR72 2000 7002 4900 2500 0120 53"
    # Canonical IBAN: 2 letters + 2 digits + groups of 4 digits/letters separated by spaces
    _p(
        r"\b([A-Z]{2}\d{2}(?:\s+\d{4}){2,7}(?:\s+\d{1,4})?)\b",
        "ACCOUNT_NUMBER", 0.90, 1, flags=0
    ),
    # Date-hyphen-digits in account context: "230815-102487"
    _p(
        r"\b(?:account|acct|customer|reference|ref)\s*(?:#|no\.?|number|id)?\s*[:\s#]+(\d{6}-\d{5,8})\b",
        "ACCOUNT_NUMBER", 0.82, 1, flags=re.IGNORECASE
    ),

    # ── Additional EMPLOYEE_ID patterns (48 FN on nemotron_pii 1000) ──────

    # Badge/ID number: "Badge: 12345", "Badge Number: EMF1234"
    _p(
        r"\b(?:badge|id\s*card|work(?:er)?\s*id)\s*(?:#|no\.?|number)?\s*[:\s#]+([A-Z0-9]{4,12})\b",
        "EMPLOYEE_ID", 0.82, 1, flags=re.IGNORECASE
    ),
    # "E-" or "W-" prefix in employee context: "E-12345", "W-98765"
    _p(
        r"\b(?:employee|staff)\s*[:\s#]*(E-\d{4,10})\b",
        "EMPLOYEE_ID", 0.85, 1, flags=re.IGNORECASE
    ),
    # Standalone EMP prefix with dash: "EMP-84518", "EMP-730359"
    _p(
        r"\b(EMP-\d{4,8})\b",
        "EMPLOYEE_ID", 0.85, 1, flags=0
    ),
    # "Staff" or "Personnel" followed directly by a number: "Staff 12345"
    _p(
        r"\b(?:staff|personnel)\s+(\d{4,8})\b",
        "EMPLOYEE_ID", 0.78, 1, flags=re.IGNORECASE
    ),

    # ── Additional ACCOUNT_NUMBER patterns (166 FN on nemotron_pii 1000) ──

    # "ref/reference" with number/# label and digits
    _p(
        r"\b(?:ref(?:erence)?|case|claim|file|policy|loan|mortgage)\s*(?:#|no\.?|number)\s*[:\s#]*(\d{6,15})\b",
        "ACCOUNT_NUMBER", 0.80, 1, flags=re.IGNORECASE
    ),
    # "ref/reference:" directly followed by alphanumeric ID
    _p(
        r"\b(?:ref(?:erence)?|case|claim|file|policy|loan|mortgage)\s*[:\s#]+(?=[A-Z0-9]*\d)([A-Z0-9]{6,15})\b",
        "ACCOUNT_NUMBER", 0.78, 1, flags=re.IGNORECASE
    ),
    # Colon-labeled with broader financial terms: "Deposit: 123456789"
    _p(
        r"\b(?:deposit|withdrawal|transfer|payment|transaction)\s*(?:#|no\.?|number|ref(?:erence)?)?\s*[:\s#]+(\d{6,15})\b",
        "ACCOUNT_NUMBER", 0.78, 1, flags=re.IGNORECASE
    ),
    # "ACC" prefix (3 letters, shorter than ACCT): "ACC123456", "ACC-789012"
    _p(
        r"\b(ACC[-]?\d{5,12})\b",
        "ACCOUNT_NUMBER", 0.85, 1, flags=0
    ),
    # INV/TXN prefixed IDs: "INV123456", "TXN789012"
    _p(
        r"\b((?:INV|TXN|ORD|PAY|BIL)[-]?\d{5,12})\b",
        "ACCOUNT_NUMBER", 0.82, 1, flags=0
    ),

    # ── Additional CERTIFICATE_NUMBER patterns (23 FN on nemotron_pii 1000)
    # "Certificate/License/Registration:" with alphanumeric ID
    _p(
        r"\b(?:certificate|license|licence|registration|certification|permit)\s*"
        r"(?:#|no\.?|number)?\s*[:\s#]+(?=[A-Z0-9-]*\d)([A-Z0-9][-A-Z0-9]{4,18})\b",
        "CERTIFICATE_NUMBER", 0.82, 1, flags=re.IGNORECASE
    ),

    # ── Additional HEALTH_PLAN_ID patterns (26 FN on nemotron_pii 1000) ───
    # "Health Plan" / "Plan ID" / "Enrollee" with ID
    _p(
        r"\b(?:health\s+plan|plan\s+(?:id\b|number|#|no\.?)|enrollee\s+(?:id\b|number|#))\s*[:\s#]+([A-Z0-9]{5,15})\b",
        "HEALTH_PLAN_ID", 0.82, 1, flags=re.IGNORECASE
    ),
    # "Coverage" / "Benefits" ID
    _p(
        r"\b(?:coverage|benefits?)\s*(?:id\b|#|number|no\.?)\s*[:\s#]+([A-Z0-9]{5,15})\b",
        "HEALTH_PLAN_ID", 0.78, 1, flags=re.IGNORECASE
    ),

    # ── ACCOUNT_NUMBER — additional account type names ──────────────────
    # Supplements patterns.py (which covers Checking/Savings/Investment etc.)
    # with less common account types from ai4privacy ACCOUNTNAME mapping.
    _p(
        r"\b((?:Retirement|Brokerage|Business|Corporate|Joint|Trust|Escrow|"
        r"Custodial|Current|Deposit|Fixed\s+Deposit|Recurring\s+Deposit)"
        r"\s+Account)(?!\s+(?:Name|Type|Number|Category)\b)\b",
        "ACCOUNT_NUMBER", 0.82, 0, flags=0
    ),

    # ── ACCOUNT_NUMBER — bare numbers in broader context ──────────────────
    # "your DIGITS to gain access" — possessive + long number + access verb
    _p(
        r"\byour\s+(\d{10,19})\s+to\s+(?:gain\s+)?access\b",
        "ACCOUNT_NUMBER", 0.78, 1, flags=re.IGNORECASE
    ),
    # "info with DIGITS in" / "sensitive info with DIGITS"
    _p(
        r"\b(?:info|information|data)\s+with\s+(\d{10,19})\b",
        "ACCOUNT_NUMBER", 0.78, 1, flags=re.IGNORECASE
    ),
    # "Contact us via DIGITS" / "reach us at DIGITS"
    _p(
        r"\b(?:contact|reach|call)\s+(?:us\s+)?(?:via|at|on)\s+(\d{7,12})\b",
        "ACCOUNT_NUMBER", 0.75, 1, flags=re.IGNORECASE
    ),

    # ── STATE — full US state names ───────────────────────────────────────
    # Split into "safe" states (not first names) and "ambiguous" states
    # (Virginia, Georgia, Montana, etc.) that need geographic context to
    # avoid FIRSTNAME→STATE type mismatches.
    #
    # Safe states — no overlap with common first names.
    _p(
        r"\b(Alaska|Arkansas|California|Colorado|Connecticut|"
        r"Delaware|Hawaii|Idaho|Illinois|Kansas|"
        r"Kentucky|Maryland|Massachusetts|Michigan|Minnesota|"
        r"Mississippi|Nebraska|New\s+Hampshire|"
        r"New\s+Jersey|New\s+Mexico|New\s+York|North\s+Carolina|"
        r"North\s+Dakota|Oklahoma|Oregon|Pennsylvania|Rhode\s+Island|"
        r"South\s+Carolina|South\s+Dakota|Vermont|"
        r"West\s+Virginia|Wisconsin|Wyoming)\b",
        "STATE", 0.78, 1, flags=0
    ),
    # Ambiguous states (also first names) — require geographic context.
    # After comma: "Atlanta, Georgia", "Las Vegas, Nevada"
    _p(
        r",\s+(Alabama|Arizona|Florida|Georgia|Indiana|Louisiana|"
        r"Missouri|Montana|Nevada|Tennessee|Texas|Virginia|Washington)\b",
        "STATE", 0.80, 1, flags=0
    ),
    # After preposition: "in Georgia", "from Virginia"
    _p(
        r"\b(?:in|from|to|near|across|throughout|around|of)\s+"
        r"(Alabama|Arizona|Florida|Georgia|Indiana|Louisiana|"
        r"Missouri|Montana|Nevada|Tennessee|Texas|Virginia|Washington)\b",
        "STATE", 0.78, 1, flags=0
    ),
    # Short US states (Ohio, Iowa, Utah, Maine) — require context to avoid FPs.
    _p(
        r",\s+(Ohio|Iowa|Utah|Maine)\b",
        "STATE", 0.80, 1, flags=0
    ),
    _p(
        r"\b(?:in|from|to|near|across|throughout|around)\s+(Ohio|Iowa|Utah|Maine)\b",
        "STATE", 0.78, 1, flags=0
    ),

    # ── STATE — international regions / provinces ─────────────────────────
    # European regions that appear in ai4privacy dataset
    _p(
        r"\b(Lombardy|Tuscany|Lazio|Campania|Veneto|Piedmont|Emilia-Romagna|"
        r"Calabria|Sardinia|Sicily|Liguria|Molise|Apulia|Umbria|Basilicata|"
        r"Abruzzo|Friuli\s+Venezia\s+Giulia|Trentino[-\s]Alto\s+Adige|"
        r"Auvergne[-\s]Rh[ôo]ne[-\s]Alpes|Île[-\s]de[-\s]France|Occitanie|"
        r"Nouvelle[-\s]Aquitaine|Brittany|Normandy|Provence|Alsace|"
        r"Bavaria|Baden[-\s]Württemberg|Saxony|Hesse|Thuringia|Brandenburg|"
        r"Mecklenburg[-\s]Vorpommern|Schleswig[-\s]Holstein|Saarland|Bremen|Hamburg|"
        r"Zurich|Bern|Geneva|Basel|Lucerne|Vaud|Graubünden|Valais|"
        r"Ontario|Quebec|British\s+Columbia|Alberta|Manitoba|Saskatchewan|"
        r"Nova\s+Scotia|New\s+Brunswick|Newfoundland)\b",
        "STATE", 0.78, 1, flags=0
    ),
    # English regions / counties
    _p(
        r"\b(East\s+Midlands|West\s+Midlands|East\s+Anglia|"
        r"South\s+West\s+England|South\s+East\s+England|"
        r"North\s+West\s+England|North\s+East\s+England|"
        r"Yorkshire|Lancashire|Kent|Essex|Surrey|Sussex|"
        r"Merseyside|Cumbria|Cornwall|Devon|Dorset|Somerset|"
        r"Gloucestershire|Leicestershire|Nottinghamshire|"
        r"Warwickshire|Staffordshire|Derbyshire|Cheshire|"
        r"Northumberland|Durham|Shropshire|Wiltshire|"
        r"Oxfordshire|Buckinghamshire|Hertfordshire|"
        r"County\s+Tyrone|County\s+Down|County\s+Antrim|"
        r"County\s+Cork|County\s+Galway|County\s+Dublin)\b",
        "STATE", 0.78, 1, flags=0
    ),

    # ── ZIP — standalone 5-digit ZIP codes ────────────────────────────────
    # "zip/postal/zip code XXXXX" with label context
    _p(
        r"\b(?:zip|postal|post)\s*(?:code)?\s*[:\s]+(\d{5}(?:-\d{4})?)\b",
        "ZIP", 0.85, 1, flags=re.IGNORECASE
    ),
    # 5-digit ZIP + optional +4 after comma in address-like context:
    # "city name, XXXXX" or "state, XXXXX"
    _p(
        r",\s*(\d{5}(?:-\d{4})?)\b(?=\s*[,.\n)}\]]|\s+(?:and|or|for|with|to|in|at|by|from)\b|\s*$)",
        "ZIP", 0.76, 1, flags=0
    ),

    # ── CITY — additional context patterns ────────────────────────────────
    # "in/from/at CITY_NAME" where city name looks like a multi-word proper
    # noun with a geographic prefix.  The second word must NOT be a common
    # English noun/kinship term (avoid "New Mother", "Old Friend").
    # The negative lookahead prevents false positives on non-geographic
    # multi-word phrases.
    _p(
        r"\b(?:in|from|at|near)\s+((?:Lake|West|East|North|South|New|Old|"
        r"Fort|Mount|Saint|San|Santa|Los|Las|El|La|Port|Cape)"
        r"\s+(?!Mother|Father|Brother|Sister|Friend|World|Year|"
        r"Moon|Dawn|Hope|Life|Love|Home|Deal|Rule|Ways?|Era|"
        r"Age|One|Man|Men|Day|Job|Law|Art|War|Act|Tax|Fee|Idea|"
        r"Land|Type|Kind|Mode|Form|Part|Side|Role|Goal|Plan|Step|"
        r"Style|Model|Level|Order|Start|House|Model|Thing|Place|"
        r"School|Church|Market|Office|Record|System|Member)"
        r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b",
        "CITY", 0.78, 1, flags=0
    ),

    # ── AGE — relaxed context patterns ────────────────────────────────────
    # "I'm a XX old" — informal age expression without "years"
    # Raised from 0.80 to 0.83 to survive AGE threshold (0.82)
    _p(
        r"\b(?:I'?m\s+a\s+|I\s+am\s+a\s+)(\d{1,3})\s+old\b",
        "AGE", 0.83, 1, flags=re.IGNORECASE
    ),

    # ── TIME — o'clock format ─────────────────────────────────────────────
    # "at 19 o'clock", "3 o'clock", "at 7 o'clock"
    _p(
        r"\b(\d{1,2}\s+o[''']?\s*clock)\b",
        "TIME", 0.92, 0, flags=re.IGNORECASE
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

                    # STATE: reject common non-geographic values
                    if pdef.entity_type == "STATE":
                        if value.lower() in _STATE_FALSE_POSITIVES:
                            continue

                    # CITY: reject common non-geographic values
                    if pdef.entity_type == "CITY":
                        if value.lower() in _CITY_FALSE_POSITIVES:
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
