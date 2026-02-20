"""Context keyword verification for PII span confidence adjustment.

Adjusts raw detector confidence based on surrounding context keywords.
Spans near confirming keywords (e.g., "Phone:" before a phone number)
get a confidence boost; spans near contradicting keywords (e.g., "Order #"
before a number detected as a phone) get demoted.

Applied *before* tier calibration so adjustments operate on raw
detector confidence.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from ..types import Span

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ContextRule:
    """Defines boost/demote keywords for a single entity type."""

    boost_words: frozenset[str]
    demote_words: frozenset[str]
    boost_amount: float = 0.10
    demote_amount: float = 0.15
    window_chars: int = 100


# ── Per-entity context rules ──────────────────────────────────────────
CONTEXT_RULES: dict[str, ContextRule] = {
    "PHONE": ContextRule(
        boost_words=frozenset({
            "phone", "tel", "telephone", "call", "mobile", "cell",
            "fax", "contact", "dial", "reach",
        }),
        demote_words=frozenset({
            "serial", "order", "invoice", "ref", "part", "model",
            "sku", "item", "product", "catalog", "tracking",
        }),
        boost_amount=0.10,
        demote_amount=0.15,
    ),
    "SSN": ContextRule(
        boost_words=frozenset({
            "ssn", "social security", "soc sec", "ss#", "ss no",
            "social sec",
        }),
        demote_words=frozenset({
            "order", "invoice", "tracking", "confirmation",
            "reference", "receipt",
            "account", "routing", "transaction", "payment",
            "balance", "transfer", "deposit", "iban", "swift",
        }),
        boost_amount=0.10,
        demote_amount=0.20,
    ),
    "DATE_DOB": ContextRule(
        boost_words=frozenset({
            "dob", "born", "birth", "birthday", "date of birth",
            "birthdate",
        }),
        demote_words=frozenset(),
        boost_amount=0.15,
        demote_amount=0.0,
    ),
    "NAME": ContextRule(
        boost_words=frozenset({
            "name", "patient", "client", "mr", "mrs", "ms", "dr",
            "attn", "attention", "dear", "sincerely", "regards",
        }),
        demote_words=frozenset({
            "product", "brand", "model", "version", "file",
            "software", "app", "service",
        }),
        boost_amount=0.10,
        demote_amount=0.10,
    ),
    "FIRSTNAME": ContextRule(
        boost_words=frozenset({
            "name", "first name", "given name", "patient", "mr",
            "mrs", "ms", "dr", "dear", "sincerely", "regards",
        }),
        demote_words=frozenset({
            "product", "brand", "model", "version",
            "city", "town", "village", "county", "state", "province",
            "country", "located", "shipped", "delivered",
        }),
        boost_amount=0.10,
        demote_amount=0.12,
    ),
    "LASTNAME": ContextRule(
        boost_words=frozenset({
            "name", "last name", "surname", "family name", "patient",
            "dear", "sincerely", "regards",
        }),
        demote_words=frozenset({
            "product", "brand", "model", "version",
            "city", "town", "village", "county", "state", "province",
            "country", "located", "shipped", "delivered",
        }),
        boost_amount=0.10,
        demote_amount=0.12,
    ),
    "EMAIL": ContextRule(
        boost_words=frozenset({
            "email", "e-mail", "mailto", "contact", "send to",
        }),
        demote_words=frozenset(),
        boost_amount=0.05,
        demote_amount=0.0,
    ),
    "ADDRESS": ContextRule(
        boost_words=frozenset({
            "address", "street", "mailing", "residence", "lives at",
            "located at", "ship to", "billing",
        }),
        demote_words=frozenset({
            "ip address", "email address", "web address",
            "mac address", "url",
        }),
        boost_amount=0.10,
        demote_amount=0.15,
    ),
    "AGE": ContextRule(
        boost_words=frozenset({
            "age", "years old", "yr old", "y/o", "aged", "year-old",
        }),
        demote_words=frozenset({
            "quantity", "count", "total", "score", "level", "page",
            "chapter", "version", "step", "item",
        }),
        boost_amount=0.15,
        demote_amount=0.20,
    ),
    "CREDIT_CARD": ContextRule(
        boost_words=frozenset({
            "card", "visa", "mastercard", "amex", "credit", "debit",
            "payment", "cc", "card number",
        }),
        demote_words=frozenset(),
        boost_amount=0.05,
        demote_amount=0.0,
    ),
    "DRIVER_LICENSE": ContextRule(
        boost_words=frozenset({
            "driver", "license", "licence", "dl", "dl#",
            "driver's license",
        }),
        demote_words=frozenset({
            "account", "routing", "transaction", "payment",
            "balance", "transfer", "invoice", "iban", "swift",
            "deposit", "credit", "debit",
        }),
        boost_amount=0.10,
        demote_amount=0.15,
    ),
    "PASSPORT": ContextRule(
        boost_words=frozenset({
            "passport", "travel document", "passport number",
        }),
        demote_words=frozenset(),
        boost_amount=0.10,
        demote_amount=0.0,
    ),
    "IP_ADDRESS": ContextRule(
        boost_words=frozenset({
            "ip", "ip address", "server", "host", "network",
        }),
        demote_words=frozenset({
            "version", "v4", "v6",
        }),
        boost_amount=0.05,
        demote_amount=0.05,
    ),
    "MRN": ContextRule(
        boost_words=frozenset({
            "mrn", "medical record", "record number", "chart",
            "patient id",
        }),
        demote_words=frozenset({
            "order", "invoice", "amount", "total", "price", "cost",
        }),
        boost_amount=0.10,
        demote_amount=0.15,
    ),
    "VIN": ContextRule(
        boost_words=frozenset({
            "vin", "vehicle", "car", "auto", "motor", "registration",
            "insurance", "odometer", "mileage", "dealer", "title",
        }),
        demote_words=frozenset({
            "version", "vendor", "validation",
        }),
        boost_amount=0.12,
        demote_amount=0.10,
    ),
    "LICENSE_PLATE": ContextRule(
        boost_words=frozenset({
            "plate", "license plate", "tag", "registration", "vehicle",
            "car", "dmv", "motor",
        }),
        demote_words=frozenset({
            "serial", "order", "part", "model",
        }),
        boost_amount=0.10,
        demote_amount=0.10,
    ),
    "ACCOUNT_NUMBER": ContextRule(
        boost_words=frozenset({
            "account", "acct", "bank", "deposit", "savings", "checking",
            "financial", "statement", "balance",
        }),
        demote_words=frozenset({
            "serial", "part", "model", "version",
        }),
        boost_amount=0.10,
        demote_amount=0.10,
    ),
    "COMPANY": ContextRule(
        boost_words=frozenset({
            "company", "employer", "employed", "works at", "firm",
            "corporation", "organization", "business",
        }),
        demote_words=frozenset(),
        boost_amount=0.10,
        demote_amount=0.0,
    ),
    "JOB_TITLE": ContextRule(
        boost_words=frozenset({
            "title", "position", "role", "occupation", "employed as",
            "works as", "job", "profession",
        }),
        demote_words=frozenset(),
        boost_amount=0.10,
        demote_amount=0.0,
    ),
}


def apply_context_keywords(
    spans: list[Span],
    text: str,
) -> list[Span]:
    """Adjust span confidence based on surrounding context keywords.

    For each span, a window of text around the span is searched for
    boost/demote keywords.  Adjustments are applied once per span
    (multiple matching keywords do not stack).

    Args:
        spans: Detected spans with raw confidence.
        text: Full source text.

    Returns:
        New list of Span objects with adjusted confidence values.
        Spans whose entity type has no context rules pass through
        unchanged.
    """
    if not spans or not text:
        return list(spans)

    text_lower = text.lower()
    text_len = len(text)
    result: list[Span] = []

    for span in spans:
        rule = CONTEXT_RULES.get(span.entity_type)
        if rule is None:
            result.append(span)
            continue

        # Extract context window around the span
        window_start = max(0, span.start - rule.window_chars)
        window_end = min(text_len, span.end + rule.window_chars)
        context = text_lower[window_start:window_end]

        # Check for boost/demote keywords using word-boundary matching
        # to avoid false substring matches (e.g., "age" in "page").
        adjustment = 0.0
        has_boost = any(
            re.search(r'\b' + re.escape(kw) + r'\b', context)
            for kw in rule.boost_words
        )
        has_demote = any(
            re.search(r'\b' + re.escape(kw) + r'\b', context)
            for kw in rule.demote_words
        )

        if has_boost and not has_demote:
            adjustment = rule.boost_amount
        elif has_demote and not has_boost:
            adjustment = -rule.demote_amount
        # If both present, they cancel out (no adjustment)

        if adjustment == 0.0:
            result.append(span)
            continue

        new_confidence = max(0.0, min(1.0, span.confidence + adjustment))

        result.append(Span(
            start=span.start,
            end=span.end,
            text=span.text,
            entity_type=span.entity_type,
            confidence=new_confidence,
            detector=span.detector,
            tier=span.tier,
            context=span.context,
            needs_review=span.needs_review,
            review_reason=span.review_reason,
            coref_anchor_value=span.coref_anchor_value,
        ))

    return result
