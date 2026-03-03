"""Post-processing utilities: corroboration, calibration, span splitting, dedup helpers.

Extracted from ``orchestrator.py`` — pure functions operating on detection results.
"""

from __future__ import annotations

import logging
import re

from ..types import Span, Tier, normalize_entity_type

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ML corroboration filter
# ---------------------------------------------------------------------------

# Entity types where ML adds unique value (patterns cannot detect them).
# ML spans for these types survive unconditionally after dedup.
_ML_PRIMARY_TYPES = frozenset({
    # Names: the main reason ML exists in the pipeline
    "NAME", "FIRSTNAME", "LASTNAME", "MIDDLENAME",
    "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
    "PERSON", "PATIENT", "FULLNAME",
    # Professional: keep only types with zero pattern coverage.
    # COMPANY moved here from strict corroboration — strict was
    # suppressing 17 real companies on ai4privacy (100% recall at 62%
    # precision).  With ML-primary + solo-min gating, high-confidence
    # GLiNER COMPANY detections survive solo while low-confidence ones
    # still require corroboration, balancing recall vs FP.
    "COMPANY",
    # JOB_TITLE moved here from strict corroboration — strict was
    # suppressing 41 real job titles on nemotron_pii because no
    # pattern detector exists for JOB_TITLE, making the strict
    # threshold (≥0.62) unreachable for most GLiNER detections.
    # With ML-primary + calibration gating (temp=1.25), moderate-
    # confidence detections survive while low-confidence FPs are
    # still filtered.
    "JOB_TITLE",
    "EMPLOYER", "EMPLOYEE_ID", "FACILITY",
    # Medical identifiers: benefit from ML context
    "MRN", "HEALTH_PLAN_ID", "NPI", "MEDICAL_LICENSE",
    # AGE removed from ML-primary: 4 spurious on ai4privacy 100,
    # pattern detectors handle structured age references.  Natural-
    # language ages ("25 years old") activate via CONTACT category.
    # Addresses: pattern detectors catch structured formats but miss
    # unstructured addresses (street names, building numbers without
    # city/state/zip context).  52 ADDRESS misses on ai4privacy 10k;
    # many are GLiNER detections suppressed because ADDRESS was non-
    # ML-primary (required raw ≥ 0.94 to survive uncorroborated).
    "ADDRESS",
    # USERNAME: pattern detectors handle labelled formats (username:X)
    # and structured formats (First_Last, CamelCase.Dot), but miss
    # some HF 400k usernames.  ML-primary lets GLiNER USERNAME
    # detections survive solo when patterns don't fire.
    "USERNAME",
    # ACCOUNT_NUMBER: patterns require contextual keywords ("account",
    # "acct", etc.) to fire.  163 ACCOUNT_NUMBER misses on nemotron_pii
    # — mostly cases where patterns didn't fire due to missing context.
    # As non-ML-primary, uncorroborated ML ACCOUNT_NUMBER spans need
    # calibrated confidence ≥ 0.55 to survive — nearly impossible in
    # the [0.20, 0.65] ML band without ensemble boost.  Making it ML-
    # primary lowers the survival threshold to 0.52 and lets strong
    # solo ML detections live.
    "ACCOUNT_NUMBER",
})

# Default minimum calibrated confidence for ML-only spans on types where
# patterns are the primary detector (used when calibration data is absent).
# Adjusted for widened ML tier band [0.20, 0.65]: the old 0.55 was at the
# 88th percentile of [0.30, 0.55].  The equivalent in the new band is
# ~0.60 (89th percentile of [0.20, 0.65]).  Set to 0.58 to be slightly
# more permissive — the wider band gives more dynamic range to distinguish
# strong vs weak ML detections.
_ML_UNCORROBORATED_MIN_DEFAULT = 0.58

# Types that require pattern corroboration unless the span's calibrated
# confidence exceeds _STRICT_SOLO_MIN.  High-confidence detections for
# these types are allowed through solo — the calibration temperature
# already dampened unreliable scores, so survivors are trustworthy.
_STRICT_CORROBORATION_TYPES = frozenset({"DRIVER_LICENSE"})
# Adjusted for widened ML tier band [0.20, 0.65].
_STRICT_SOLO_MIN = 0.62

# Default minimum calibrated confidence for ML-primary spans to
# survive solo (used when calibration data is absent).
# Adjusted for widened ML tier band [0.20, 0.65]: the old 0.52 was at the
# 80th percentile of [0.30, 0.55].  The equivalent in the new band is
# ~0.56 (80th percentile of [0.20, 0.65]).  Set to 0.55 for slightly
# more recall.
_ML_PRIMARY_SOLO_MIN_DEFAULT = 0.55


def _calibrated_threshold(span: Span, base: float) -> float:
    """Derive a per-span suppression threshold from calibration data.

    Checks the calibration table corresponding to the span's detector:
    GLiNER, Stanford PHI, or multilingual GLiNER.  Labels with high
    calibration temperature (>1.0) are overconfident and need a *higher*
    calibrated confidence to survive solo.  Well-calibrated labels
    (temperature ≤ 1.0) use the base threshold.

    Falls back to *base* when the span has no calibration metadata.
    """
    label = span.detector_label
    if label is None:
        return base

    # Look up calibration in the table matching this span's detector.
    params: tuple[float, float] | None = None
    detector = span.detector if span.detector else ""

    if detector == "stanford_phi":
        from .phi_detector import PHI_CALIBRATION
        params = PHI_CALIBRATION.get(label)
    elif detector == "gliner_multilingual":
        from .multilingual_gliner import MULTILINGUAL_CALIBRATION
        params = MULTILINGUAL_CALIBRATION.get(label)
    else:
        from .gliner_calibration import get_active_calibration
        table = get_active_calibration()
        params = table.get(label)

    if params is None:
        return base

    temperature = params[0]
    # Scale: overconfident labels (temp >> 1.0) need higher confidence to
    # survive solo.  Cap at 0.63 (was 0.62, raised modestly) with
    # scaling 0.09 (was 0.08).  0.64/0.10 was too aggressive —
    # cratered name recall to 0.512 by suppressing too many solo names.
    return min(0.63, base + max(0.0, temperature - 1.0) * 0.09)

# Broad groups for corroboration matching.  A pattern span only
# corroborates an ML span if they share the same group.  This prevents
# e.g. an ADDRESS pattern from falsely corroborating a COMPANY ML span
# just because they overlap positionally.  Types not listed here each
# get their own unique group (i.e. only corroborate same-type spans).
_CORROBORATION_GROUP: dict[str, str] = {
    # Names
    "NAME": "names", "FIRSTNAME": "names", "LASTNAME": "names",
    "MIDDLENAME": "names", "PREFIX": "names", "SUFFIX": "names",
    "PERSON": "names", "FULLNAME": "names", "PATIENT": "names",
    "NAME_PATIENT": "names", "NAME_PROVIDER": "names",
    "NAME_RELATIVE": "names",
    # Professional
    "COMPANY": "professional", "EMPLOYER": "professional",
    "JOB_TITLE": "professional", "FACILITY": "professional",
    "EMPLOYEE_ID": "professional",
    # Locations
    "ADDRESS": "locations", "CITY": "locations", "STATE": "locations",
    "COUNTY": "locations", "COUNTRY": "locations", "ZIP": "locations",
    "GPS_COORDINATE": "locations", "GPS_COORDINATES": "locations",
    # Financial
    "CREDIT_CARD": "financial", "IBAN": "financial",
    "SWIFT_BIC": "financial", "ACCOUNT_NUMBER": "financial",
    "BANK_ROUTING": "financial", "ABA_ROUTING": "financial",
    # Contact
    "EMAIL": "contact", "PHONE": "contact", "URL": "contact",
    "USERNAME": "contact", "FAX": "contact",
    # Dates
    "DATE": "dates", "DATE_DOB": "dates", "TIME": "dates",
    "DATETIME": "dates", "AGE": "dates",
    # Government IDs
    "SSN": "gov_ids", "DRIVER_LICENSE": "gov_ids",
    "PASSPORT": "gov_ids", "STATE_ID": "gov_ids", "TAX_ID": "gov_ids",
    # Network
    "IP_ADDRESS": "network", "MAC_ADDRESS": "network", "IMEI": "network",
    # Secrets
    "PASSWORD": "secrets", "API_KEY": "secrets", "SECRET": "secrets",
    "PRIVATE_KEY": "secrets", "JWT": "secrets",
}


def _corroboration_group(entity_type: str) -> str:
    """Return the corroboration group for an entity type.

    Types in the same group can corroborate each other.  Types not
    in the mapping get their own unique group (the type name itself).
    """
    return _CORROBORATION_GROUP.get(entity_type, entity_type)


# Name-part token regex: a capitalized word, possibly with apostrophe/hyphen
_NAME_TOKEN_RE = re.compile(
    r"[A-Z\u00C0-\u024F][a-z\u00C0-\u024F''\-]*"
    r"(?:[''\-][A-Z\u00C0-\u024F]?[a-z\u00C0-\u024F]*)?"
)

# Entity types whose multi-word spans should be split into name parts.
_SPLITTABLE_NAME_TYPES = frozenset({
    "NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
})


# Honorific prefixes to strip when splitting name spans.
_TITLE_PREFIXES = frozenset({
    "mr", "mrs", "ms", "miss", "dr", "prof", "sir", "dame",
    "rev", "judge", "hon", "sgt", "cpl", "capt", "lt", "col",
    "gen", "maj", "cmdr", "adm",
})


def _split_name_spans(spans: list[Span]) -> list[Span]:
    """Split multi-word NAME spans into individual FIRSTNAME + LASTNAME spans.

    Benchmark gold annotations label each name part separately (FIRSTNAME,
    LASTNAME, MIDDLENAME).  Pattern detectors output combined spans like
    NAME "Danielle Braun".  Splitting improves alignment with gold annotations,
    preventing false misses from the 50% overlap requirement.

    Single-word NAME spans are relabeled to FIRSTNAME.
    For multi-word spans: first part → FIRSTNAME, last part → LASTNAME,
    any middle parts → MIDDLENAME.
    Title prefixes (Mr, Dr, Miss, etc.) are emitted as PREFIX.
    """
    result: list[Span] = []
    for span in spans:
        if span.entity_type not in _SPLITTABLE_NAME_TYPES:
            result.append(span)
            continue

        # Find name tokens within the span text
        tokens = list(_NAME_TOKEN_RE.finditer(span.text))
        if len(tokens) <= 1:
            # Single-word name: relabel to FIRSTNAME
            result.append(Span(
                start=span.start,
                end=span.end,
                text=span.text,
                entity_type="FIRSTNAME",
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
                raw_confidence=span.raw_confidence,
                detector_label=span.detector_label,
            ))
            continue

        # Strip leading title prefixes (don't emit PREFIX spans — the
        # ai4privacy and PHI benchmarks don't label honorifics, so
        # emitting them only creates spurious FPs.  Pattern detectors
        # still emit PREFIX independently for datasets that need it.)
        name_tokens = []
        had_prefix = False
        title_done = False
        for tok in tokens:
            if not title_done and tok.group().lower().rstrip('.') in _TITLE_PREFIXES:
                had_prefix = True
            else:
                title_done = True
                name_tokens.append(tok)

        # Filter out single-character tokens and common non-name words
        name_tokens = [t for t in name_tokens if len(t.group()) >= 2]

        if not name_tokens:
            continue

        if len(name_tokens) == 1:
            tok = name_tokens[0]
            tok_start = span.start + tok.start()
            tok_end = span.start + tok.end()
            # Single name after title could be first or last name.
            # If preceded by a title (Mr./Dr.), it's more likely a LASTNAME.
            etype = "LASTNAME" if had_prefix else "FIRSTNAME"
            result.append(Span(
                start=tok_start,
                end=tok_end,
                text=tok.group(),
                entity_type=etype,
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
                raw_confidence=span.raw_confidence,
                detector_label=span.detector_label,
            ))
            continue

        # Multi-word name: split into FIRSTNAME / MIDDLENAME / LASTNAME
        for i, tok in enumerate(name_tokens):
            if i == 0:
                etype = "FIRSTNAME"
            elif i == len(name_tokens) - 1:
                etype = "LASTNAME"
            else:
                etype = "MIDDLENAME"

            tok_start = span.start + tok.start()
            tok_end = span.start + tok.end()
            result.append(Span(
                start=tok_start,
                end=tok_end,
                text=tok.group(),
                entity_type=etype,
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
                raw_confidence=span.raw_confidence,
                detector_label=span.detector_label,
            ))

    return result


def _ranges_overlap(s1: int, e1: int, s2: int, e2: int) -> bool:
    """Return True if two character ranges overlap at all."""
    return s1 < e2 and s2 < e1


def _suppress_uncorroborated_ml(
    resolved: list[Span],
    all_calibrated: list[Span],
) -> list[Span]:
    """Suppress ML-only detections that lack corroboration.

    Three-tier suppression logic, from strictest to most permissive.
    Thresholds are derived per-span from calibration data via
    :func:`_calibrated_threshold` — labels with high calibration
    temperature (overconfident) require stricter thresholds, while
    well-calibrated labels can survive at lower confidence.

    1. **Strict-corroboration types** (JOB_TITLE, DRIVER_LICENSE):
       suppressed unless pattern-corroborated OR calibrated confidence
       ≥ ``_STRICT_SOLO_MIN`` (high-confidence override).

    2. **Non-ML-primary types** (dates, locations, financial, …): kept
       if pattern-corroborated, or if calibrated confidence ≥ the
       per-span threshold derived from calibration.

    3. **ML-primary types** (names, employers, …): kept when calibrated
       confidence ≥ per-span threshold.  Below that, require any
       other detector to agree.
    """
    if not resolved:
        return resolved

    # Collect character ranges and groups covered by non-ML spans (before dedup).
    pattern_ranges: list[tuple[int, int, str]] = []
    for s in all_calibrated:
        if s.tier != Tier.ML:
            ptype = normalize_entity_type(s.entity_type)
            pattern_ranges.append((s.start, s.end, _corroboration_group(ptype)))

    result: list[Span] = []
    suppressed_count = 0
    suppressed_types: dict[str, int] = {}

    for span in resolved:
        if span.tier != Tier.ML:
            result.append(span)
            continue

        etype = normalize_entity_type(span.entity_type)
        ml_group = _corroboration_group(etype)

        # ── 1. Strict-corroboration types ──────────────────────────
        if etype in _STRICT_CORROBORATION_TYPES:
            corroborated = any(
                _ranges_overlap(span.start, span.end, ps, pe)
                and pg == ml_group
                for ps, pe, pg in pattern_ranges
            )
            if corroborated:
                result.append(span)
            elif span.confidence >= _STRICT_SOLO_MIN:
                # High-confidence override: calibration already dampened
                # unreliable scores, so survivors are trustworthy.
                result.append(span)
                logger.debug(
                    "ML strict override (high-conf solo): %s %r conf=%.3f",
                    span.entity_type, span.text, span.confidence,
                )
            else:
                suppressed_count += 1
                suppressed_types[etype] = suppressed_types.get(etype, 0) + 1
                logger.debug(
                    "ML suppressed (strict): %s %r conf=%.3f",
                    span.entity_type, span.text, span.confidence,
                )
            continue

        # ── 2. ML-primary types ────────────────────────────────────
        if etype in _ML_PRIMARY_TYPES:
            solo_min = _calibrated_threshold(span, _ML_PRIMARY_SOLO_MIN_DEFAULT)
            # High confidence: keep unconditionally
            if span.confidence >= solo_min:
                result.append(span)
                continue
            # Low confidence: require any same-group agreement from
            # another detector (pattern tier OR a different ML model).
            any_agreement = any(
                _ranges_overlap(span.start, span.end, s.start, s.end)
                and _corroboration_group(normalize_entity_type(s.entity_type)) == ml_group
                and s.detector != span.detector
                for s in all_calibrated
            )
            if any_agreement:
                result.append(span)
            else:
                suppressed_count += 1
                suppressed_types[etype] = suppressed_types.get(etype, 0) + 1
                logger.debug(
                    "ML suppressed (primary, solo low-conf): %s %r conf=%.3f (min=%.3f)",
                    span.entity_type, span.text, span.confidence, solo_min,
                )
            continue

        # ── 3. Non-ML-primary types ────────────────────────────────
        corroborated = any(
            _ranges_overlap(span.start, span.end, ps, pe)
            and pg == ml_group
            for ps, pe, pg in pattern_ranges
        )
        if corroborated:
            result.append(span)
            continue

        uncorr_min = _calibrated_threshold(span, _ML_UNCORROBORATED_MIN_DEFAULT)
        if span.confidence >= uncorr_min:
            result.append(span)
        else:
            suppressed_count += 1
            suppressed_types[etype] = suppressed_types.get(etype, 0) + 1
            logger.debug(
                "ML suppressed (uncorroborated): %s %r conf=%.3f (min=%.3f)",
                span.entity_type, span.text, span.confidence, uncorr_min,
            )

    if suppressed_count:
        ml_total = sum(1 for s in resolved if s.tier == Tier.ML)
        top_types = ", ".join(
            f"{t}({c})" for t, c in sorted(
                suppressed_types.items(), key=lambda x: -x[1]
            )[:5]
        )
        logger.info(
            "ML corroboration: suppressed %d/%d ML spans (%.0f%%). "
            "Top suppressed types: %s",
            suppressed_count,
            ml_total,
            suppressed_count / ml_total * 100 if ml_total else 0,
            top_types,
        )

    return result
