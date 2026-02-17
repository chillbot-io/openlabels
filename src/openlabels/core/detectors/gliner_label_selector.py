"""Content-aware label selection for GLiNER.

Profiles document content using keyword heuristics (no ML model)
and selects relevant label subsets for focused GLiNER inference.

Passing fewer, more relevant labels to GLiNER improves accuracy
(less attention dilution) and reduces inference time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Flag, auto


class ContentCategory(Flag):
    """Document content categories (combinable via bitwise OR)."""

    GENERAL = auto()
    MEDICAL = auto()
    FINANCIAL = auto()
    PERSONAL_ID = auto()
    CONTACT = auto()
    TECHNICAL = auto()
    GOVERNMENT = auto()


@dataclass(frozen=True)
class ContentProfile:
    """Result of document content profiling."""

    categories: ContentCategory
    selected_labels: list[str]
    category_scores: dict[str, float]


# ---------------------------------------------------------------------------
# Category detection patterns
# ---------------------------------------------------------------------------
# Each tuple: (compiled regex, weight per match).
# Category activates when sum of (match_count * weight) >= threshold.

_CATEGORY_PATTERNS: dict[ContentCategory, list[tuple[re.Pattern[str], float]]] = {
    ContentCategory.MEDICAL: [
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
    ContentCategory.FINANCIAL: [
        (re.compile(
            r"\b(account|bank|credit card|debit|IBAN|SWIFT|BIC|routing|"
            r"transaction|wire transfer|invoice|payment|balance|statement)\b", re.I,
        ), 1.0),
        (re.compile(r"\b(bitcoin|ethereum|crypto|wallet|blockchain)\b", re.I), 1.0),
        (re.compile(r"\$\d+[,.]?\d*|\b(USD|EUR|GBP)\b", re.I), 0.5),
    ],
    ContentCategory.PERSONAL_ID: [
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
    ContentCategory.CONTACT: [
        (re.compile(
            r"\b(phone|email|address|street|city|state|zip|postal|fax|contact)\b", re.I,
        ), 0.5),
        (re.compile(r"@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), 1.0),
        (re.compile(r"\(\d{3}\)\s?\d{3}[-.]?\d{4}"), 1.0),
    ],
    ContentCategory.TECHNICAL: [
        (re.compile(
            r"\b(API[_ ]?KEY|SECRET[_ ]?KEY|TOKEN|PASSWORD|PRIVATE[_ ]?KEY|"
            r"AWS|GITHUB|BEARER)\b",
        ), 2.0),
        (re.compile(r"\b(BEGIN (RSA |EC |)PRIVATE KEY)\b"), 3.0),
        (re.compile(
            r"\b(ip address|MAC address|hostname|server|database|"
            r"connection string)\b", re.I,
        ), 1.0),
    ],
    ContentCategory.GOVERNMENT: [
        (re.compile(
            r"\b(classified|top secret|secret|confidential|FOUO|NOFORN|SCI|"
            r"clearance)\b", re.I,
        ), 2.0),
        (re.compile(r"\b(CAGE|DUNS|UEI|DOD|military|ITAR|EAR)\b", re.I), 1.5),
    ],
}

_CATEGORY_THRESHOLDS: dict[ContentCategory, float] = {
    ContentCategory.MEDICAL: 2.0,
    ContentCategory.FINANCIAL: 1.5,
    ContentCategory.PERSONAL_ID: 1.5,
    ContentCategory.CONTACT: 1.0,
    ContentCategory.TECHNICAL: 2.0,
    ContentCategory.GOVERNMENT: 2.0,
}

# ---------------------------------------------------------------------------
# Category → GLiNER label subsets
# ---------------------------------------------------------------------------
# Keys must match GLINER_LABEL_MAP keys in gliner.py exactly.

_CATEGORY_LABELS: dict[ContentCategory, list[str]] = {
    ContentCategory.GENERAL: [
        "person name",
        "first name",
        "last name",
        "middle name",
        "email address",
        "phone number",
        "date of birth",
        "date",
        "date and time",
        "time",
        "age",
        "company name",
        "employer",
        "employee id",
        "job title",
        "unique identifier",
    ],
    ContentCategory.MEDICAL: [
        "medical record number",
        "health plan number",
        "npi number",
        "medical license number",
        "biometric identifier",
    ],
    ContentCategory.FINANCIAL: [
        "credit card number",
        "bank account number",
        "iban",
        "swift code",
        "bank routing number",
        "bitcoin address",
        "ethereum address",
    ],
    ContentCategory.PERSONAL_ID: [
        "social security number",
        "driver license number",
        "passport number",
        "tax identification number",
        "national identity number",
        "certificate number",
    ],
    ContentCategory.CONTACT: [
        "street address",
        "city",
        "state",
        "zip code",
        "country",
        "county",
        "gps coordinate",
        "url",
        "username",
    ],
    ContentCategory.TECHNICAL: [
        "ip address",
        "mac address",
        "device identifier",
        "imei number",
        "password",
        "api key",
    ],
    ContentCategory.GOVERNMENT: [
        "vehicle identification number",
        "license plate number",
    ],
}

# Minimum label count before we fall back to all labels.
_MIN_LABELS = 5


def profile_content(text: str, sample_size: int = 5000) -> ContentProfile:
    """Profile document content and select GLiNER labels.

    Scans up to *sample_size* characters of the document for keyword
    heuristics.  Returns a :class:`ContentProfile` with the detected
    categories and the label list to pass to GLiNER.

    Args:
        text: Document text to profile.
        sample_size: Max characters to scan (default 5000).

    Returns:
        ContentProfile with selected labels.
    """
    sample = text[:sample_size]
    scores: dict[str, float] = {}
    active_categories = ContentCategory.GENERAL

    for category, patterns in _CATEGORY_PATTERNS.items():
        cat_score = 0.0
        for pattern, weight in patterns:
            matches = pattern.findall(sample)
            cat_score += len(matches) * weight
        scores[category.name] = cat_score
        threshold = _CATEGORY_THRESHOLDS[category]
        if cat_score >= threshold:
            active_categories |= category

    # Build label list from active categories (preserving order, no dupes)
    label_list: list[str] = []
    seen: set[str] = set()
    for category in ContentCategory:
        if category in active_categories:
            for label in _CATEGORY_LABELS.get(category, []):
                if label not in seen:
                    label_list.append(label)
                    seen.add(label)

    # Safety: if too few labels, fall back to all labels
    if len(label_list) < _MIN_LABELS:
        from .gliner import GLINER_LABEL_MAP

        label_list = list(GLINER_LABEL_MAP.keys())

    return ContentProfile(
        categories=active_categories,
        selected_labels=label_list,
        category_scores=scores,
    )
