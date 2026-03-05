"""Content-aware label selection for GLiNER.

Profiles document content using keyword heuristics (no ML model)
and selects relevant label subsets for focused GLiNER inference.

Passing fewer, more relevant labels to GLiNER improves accuracy
(less attention dilution) and reduces inference time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..entity_domains import EntityDomain


@dataclass(frozen=True)
class ContentProfile:
    """Result of document content profiling."""

    categories: frozenset[EntityDomain]
    selected_labels: list[str]
    category_scores: dict[str, float]


# ---------------------------------------------------------------------------
# Category detection patterns
# ---------------------------------------------------------------------------
# Each tuple: (compiled regex, weight per match).
# Category activates when sum of (match_count * weight) >= threshold.

_CATEGORY_PATTERNS: dict[EntityDomain, list[tuple[re.Pattern[str], float]]] = {
    EntityDomain.MEDICAL: [
        (re.compile(
            r"\b(patient|diagnosis|clinical|medical|hospital|physician|nurse|"
            r"medication|prescription|MRN|chief complaint|discharge|admitted|"
            r"lab results?|vitals?|ICD[- ]?\d|CPT|NPI)\b", re.I,
        ), 1.0),
        (re.compile(
            r"\b(HIPAA|PHI|protected health|health plan|health insurance)\b", re.I,
        ), 2.0),
        (re.compile(
            r"\b(mg|mL|mcg|units?/day|q\.\d+h|p\.r\.n\.|b\.i\.d\.|t\.i\.d\.)\b", re.I,
        ), 0.5),
    ],
    EntityDomain.FINANCIAL: [
        (re.compile(
            r"\b(account|bank|credit card|debit|IBAN|SWIFT|BIC|routing|"
            r"transaction|wire transfer|invoice|payment|balance|statement)\b", re.I,
        ), 1.0),
        (re.compile(r"\b(bitcoin|ethereum|crypto|wallet|blockchain)\b", re.I), 1.0),
        (re.compile(r"\$\d+[,.]?\d*|\b(USD|EUR|GBP)\b", re.I), 0.5),
    ],
    EntityDomain.IDENTIFIER: [
        (re.compile(
            r"\b(SSN|social security|passport|driver.?s? license|national ID|"
            r"tax ID|TIN|EIN)\b", re.I,
        ), 2.0),
        (re.compile(
            r"\b(date of birth|DOB|born on|nationality|citizenship|visa|"
            r"immigration)\b", re.I,
        ), 1.0),
        (re.compile(r"\b\d{3}[-. ]\d{2}[-. ]\d{4}\b"), 1.5),
    ],
    EntityDomain.CONTACT: [
        (re.compile(
            r"\b(phone|email|address|street|city|state|zip|postal|fax|contact)\b", re.I,
        ), 0.5),
        (re.compile(r"@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), 1.0),
        (re.compile(r"\(\d{3}\)\s?\d{3}[-.]?\d{4}"), 1.0),
    ],
    EntityDomain.CREDENTIAL: [
        (re.compile(
            r"\b(API[_ ]?KEY|SECRET[_ ]?KEY|TOKEN|PASSWORD|PRIVATE[_ ]?KEY|"
            r"AWS|GITHUB|BEARER)\b", re.I,
        ), 2.0),
        (re.compile(r"\b(BEGIN (RSA |EC |)PRIVATE KEY)\b", re.I), 3.0),
        (re.compile(
            r"\b(ip address|MAC address|hostname|server|database|"
            r"connection string)\b", re.I,
        ), 1.0),
    ],
    EntityDomain.GOVERNMENT: [
        (re.compile(
            r"\b(classified|top secret|secret|confidential|FOUO|NOFORN|SCI|"
            r"clearance)\b", re.I,
        ), 2.0),
        (re.compile(r"\b(CAGE|DUNS|UEI|DOD|military|ITAR|EAR)\b", re.I), 1.5),
    ],
    EntityDomain.VEHICLE: [
        (re.compile(
            r"\b(VIN|vehicle identification|license plate|registration number|"
            r"DMV|motor vehicle|vehicle title|odometer)\b", re.I,
        ), 2.0),
        (re.compile(
            r"\b(automobile|car insurance|auto insurance|fleet|mileage|"
            r"make and model)\b", re.I,
        ), 1.5),
    ],
}

_CATEGORY_THRESHOLDS: dict[EntityDomain, float] = {
    EntityDomain.MEDICAL: 2.0,
    EntityDomain.FINANCIAL: 0.5,
    EntityDomain.IDENTIFIER: 1.5,
    EntityDomain.CONTACT: 0.5,
    EntityDomain.CREDENTIAL: 2.0,
    EntityDomain.GOVERNMENT: 2.0,
    EntityDomain.VEHICLE: 2.0,
}

# ---------------------------------------------------------------------------
# Domain → GLiNER label subsets
# ---------------------------------------------------------------------------
# Keys must match GLINER_LABEL_MAP keys in gliner.py exactly.

# Base labels are always included (no domain trigger required).
_BASE_LABELS: list[str] = [
    # --- Names: the primary reason GLiNER exists in the pipeline ---
    "person name",
    "first name",
    "last name",
    "middle name",
    # --- Locations: partial pattern coverage ---
    "street address",
    "city",
    # --- Government IDs: prevents type confusion ---
    # Without these, GLiNER maps SSN→PHONE, STATE_ID→BANK_ROUTING.
    "social security number",
    "national identity number",
    "driver license number",
    "tax identification number",
    # --- Contact: no reliable pattern alternative ---
    "username",
    # --- Secrets: contextual ("my password is X") ---
    "password",
    # --- Dates: only DOB — GLiNER catches "born on March 5" etc. ---
    # Generic "date"/"time"/"age" removed: pattern detectors have
    # 100% recall on structured dates/times, and GLiNER adds only
    # FPs for those.  But "date of birth" is semantically distinct
    # and produces real TPs that patterns miss.
    "date of birth",
    # --- Zip codes: partial pattern coverage ---
    # Pattern detectors handle US ZIP but miss international postal
    # codes.  GLiNER adds marginal recall here.
    "zip code",
    # --- Labels REMOVED from base set ---
    # company name, job title:
    #   Not PII.  Company/job don't identify individuals.  GLiNER
    #   "company name" generated 34 spurious + 11 name→COMPANY type
    #   mismatches on nemotron_pii.  Removing frees attention budget.
    # date, date and time, time, age:
    #   Pattern detectors achieve 100% recall on structured dates/times.
    #   GLiNER adds 26+ spurious FPs and 0 additional TP.
    # country: 93% FP rate; now covered by comprehensive country
    #   name patterns (8 regex groups covering ~200 countries).
    # employer: generates FPs without corroboration.
]

_DOMAIN_LABELS: dict[EntityDomain, list[str]] = {
    EntityDomain.MEDICAL: [
        "medical record number",
        "health plan number",
        "npi number",
        "medical license number",
        "biometric identifier",
    ],
    EntityDomain.FINANCIAL: [
        "credit card number",
        "bank account number",
        "iban",
        "swift code",
        "bank routing number",
        "bitcoin address",
        "ethereum address",
        "pin code",
    ],
    EntityDomain.IDENTIFIER: [
        # ssn, driver license, tax id, national id already in _BASE_LABELS
        "passport number",
        "certificate number",
        "employee id",
    ],
    EntityDomain.CONTACT: [
        "phone number",
        "email address",
        # street address, city, zip code, username already in _BASE_LABELS
        "state",
        "country",
        "county",
        # "gps coordinate" removed: pattern detectors cover all GPS formats
        # (bracket, decimal, DMS, labeled).  GLiNER produces 8 spurious.
        "url",
        "imei number",
    ],
    EntityDomain.CREDENTIAL: [
        "ip address",
        "mac address",
        "device identifier",
        "imei number",
        # password already in _BASE_LABELS
        "pin code",
        "api key",
    ],
    EntityDomain.GOVERNMENT: [
        "unique identifier",
    ],
    EntityDomain.VEHICLE: [
        "vehicle identification number",
        "license plate number",
    ],
}

def profile_content(text: str, sample_size: int = 5000) -> ContentProfile:
    """Profile document content and select GLiNER labels.

    Scans up to *sample_size* characters of the document for keyword
    heuristics.  Returns a :class:`ContentProfile` with the detected
    domains and the label list to pass to GLiNER.

    Args:
        text: Document text to profile.
        sample_size: Max characters to scan (default 5000).

    Returns:
        ContentProfile with selected labels.
    """
    sample = text[:sample_size]
    scores: dict[str, float] = {}
    active_domains: set[EntityDomain] = set()

    for domain, patterns in _CATEGORY_PATTERNS.items():
        cat_score = 0.0
        for pattern, weight in patterns:
            matches = pattern.findall(sample)
            cat_score += len(matches) * weight
        scores[domain.name] = cat_score
        threshold = _CATEGORY_THRESHOLDS[domain]
        if cat_score >= threshold:
            active_domains.add(domain)

    # Build label list: always start with base labels, then add domain-specific
    label_list: list[str] = []
    seen: set[str] = set()

    # Base labels are always included
    for label in _BASE_LABELS:
        if label not in seen:
            label_list.append(label)
            seen.add(label)

    # Add domain-specific labels for active domains
    for domain in EntityDomain:
        if domain in active_domains:
            for label in _DOMAIN_LABELS.get(domain, []):
                if label not in seen:
                    label_list.append(label)
                    seen.add(label)

    return ContentProfile(
        categories=frozenset(active_domains),
        selected_labels=label_list,
        category_scores=scores,
    )
