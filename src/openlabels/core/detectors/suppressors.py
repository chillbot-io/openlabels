"""False-positive suppression functions for detection post-processing.

Extracted from ``orchestrator.py`` — standalone functions that filter
detection results to remove common false positives.

All 8 suppression functions:
- _suppress_pronoun_names
- _suppress_ml_name_collisions
- _suppress_name_location_collisions
- _suppress_ml_name_false_positives
- _suppress_ml_username_false_positives
- _suppress_ml_location_false_positives
- _suppress_uncorroborated_ml  (delegated to post_processing)
- _correct_type_confusions
"""

from __future__ import annotations

import logging
import re

from ..types import Span, Tier, normalize_entity_type
from .enrichment import (
    _CITY_CONFIDENCE_MARGIN,
    _CITY_GAZETTEER_MARGIN,
    _NAME_COLLISION_PRIORITY_TYPES,
    _get_city_gazetteer,
)
from .post_processing import _ranges_overlap

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pronoun suppression
# ---------------------------------------------------------------------------

# NAME-family types that can be false-positively assigned to pronouns.
_NAME_FAMILY = frozenset({
    "NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
    "FIRSTNAME", "LASTNAME", "MIDDLENAME",
})

# Personal pronouns (lower-cased) that are never PII by themselves.
# Covers English + the 8 other multilingual-supported languages.
_PRONOUNS = frozenset({
    # English
    "he", "him", "his", "she", "her", "hers",
    "they", "them", "their", "theirs",
    # Spanish
    "él", "ella", "ellos", "ellas",
    # French
    "il", "elle", "ils", "elles", "lui",
    # Portuguese
    "ele", "ela", "eles", "elas",
    # German
    "er", "sie", "es", "ihr", "ihm", "ihn",
    # Italian
    "egli", "essa", "esso", "loro",
    # Dutch
    "hij", "zij", "hen", "hun",
    # Greek
    "αυτός", "αυτή", "αυτό", "αυτοί", "αυτές", "αυτά",
})


def _suppress_pronoun_names(spans: list[Span]) -> list[Span]:
    """Remove NAME-family spans whose text is just a pronoun."""
    result: list[Span] = []
    for span in spans:
        if span.entity_type in _NAME_FAMILY and span.text.strip().lower() in _PRONOUNS:
            logger.debug("Pronoun suppressed: %s %r", span.entity_type, span.text)
            continue
        result.append(span)
    return result


# ---------------------------------------------------------------------------
# Pre-dedup: ML name fragment suppression
# ---------------------------------------------------------------------------

# Pattern types that should take priority over ML name detections at the
# same position.  USERNAME is the most important: patterns detect compound
# tokens like "Roma_Altenwerth" while GLiNER only sees the word fragment
# "Roma" → without suppression the ML FIRSTNAME absorbs the USERNAME in
# HIGHER_TIER dedup.  Locations suffer the same problem: "Florence" as
# CITY (pattern) vs FIRSTNAME (GLiNER).
_PATTERN_PRIORITY_OVER_NAMES = frozenset({
    "USERNAME",
    "CITY", "STATE", "COUNTY", "COUNTRY", "ZIP",
    "ADDRESS", "GPS_COORDINATE", "GPS_COORDINATES",
    # COMPANY: pattern detectors catch corporate suffixes (Inc, LLC, etc.)
    # but GLiNER also detects the same span as FIRSTNAME.  5 COMPANY→
    # FIRSTNAME type mismatches on nemotron_pii from this collision.
    "COMPANY",
})


def _suppress_ml_name_collisions(spans: list[Span]) -> list[Span]:
    """Remove ML name spans that overlap with pattern non-name spans.

    Must run BEFORE ``resolve_spans``.  Prevents ML FIRSTNAME/LASTNAME
    detections from absorbing pattern detections of more specific types
    during HIGHER_TIER dedup.

    Two scenarios fixed:
    1. USERNAME "Roma_Altenwerth" (PATTERN) vs FIRSTNAME "Roma" (ML)
       → remove the ML FIRSTNAME, keep the pattern USERNAME.
    2. CITY "Florence" (PATTERN) vs FIRSTNAME "Florence" (ML)
       → remove the ML FIRSTNAME, keep the pattern CITY.
    """
    from ..types import Tier

    # Collect ranges of non-ML spans with priority types
    priority_ranges: list[tuple[int, int]] = []
    for s in spans:
        if s.tier != Tier.ML:
            norm = normalize_entity_type(s.entity_type)
            if norm in _PATTERN_PRIORITY_OVER_NAMES:
                priority_ranges.append((s.start, s.end))

    if not priority_ranges:
        return spans

    result: list[Span] = []
    suppressed = 0
    for span in spans:
        if span.tier == Tier.ML and span.entity_type in _NAME_FAMILY:
            # Check if this ML name is contained within (or exactly matches)
            # a priority pattern span.
            is_fragment = any(
                ps <= span.start and span.end <= pe
                for ps, pe in priority_ranges
            )
            if is_fragment:
                suppressed += 1
                logger.debug(
                    "Pre-dedup ML name suppressed: %s %r (overlaps pattern)",
                    span.entity_type, span.text,
                )
                continue
        result.append(span)

    if suppressed:
        logger.info(
            "Pre-dedup: suppressed %d ML name fragments overlapping "
            "pattern USERNAME/location spans",
            suppressed,
        )
    return result


# ---------------------------------------------------------------------------
# Name–collision suppression (location, company, job title)
# ---------------------------------------------------------------------------

def _suppress_name_location_collisions(
    spans: list[Span],
    all_candidates: list[Span] | None = None,
) -> list[Span]:
    """Replace FIRSTNAME/LASTNAME spans with priority-type alternatives.

    City/state/county names (Florence, Georgia, Madison, Austin),
    company names (Apple, Chase), and usernames are common first names
    but are almost always the more specific type in PII contexts.

    When both a name and a priority-type span overlap at the same
    position, replace the name with the best priority-type span from
    ``all_candidates``.  If no suitable replacement is found, the name
    is suppressed entirely (legacy behaviour for edge cases).

    Uses a city gazetteer to apply additional confidence margin when
    the span text matches a known US city name.

    Args:
        spans: The resolved (post-dedup) span list to filter.
        all_candidates: Optional pre-dedup span list to source priority
            spans from.  GLiNER may detect both CITY and FIRSTNAME at
            the same position; dedup picks one winner (often FIRSTNAME
            with higher confidence).  By checking ``all_candidates`` we
            see priority detections that lost in dedup and can restore
            them as replacements instead of blanket-deleting.
    """
    source = spans if all_candidates is None else all_candidates
    gazetteer = _get_city_gazetteer()

    # Build a map: (start, end) → best priority-type span at that position.
    # When multiple priority spans overlap the same range, keep the one
    # with the highest confidence.
    priority_by_range: dict[tuple[int, int], Span] = {}
    for s in source:
        if s.entity_type in _NAME_COLLISION_PRIORITY_TYPES:
            key = (s.start, s.end)
            prev = priority_by_range.get(key)
            if prev is None or s.confidence > prev.confidence:
                priority_by_range[key] = s

    if not priority_by_range:
        return spans

    result: list[Span] = []
    for span in spans:
        if span.entity_type in _NAME_FAMILY:
            # Find the best overlapping priority-type span.
            best_priority: Span | None = None
            for (ps, pe), pspan in priority_by_range.items():
                if _ranges_overlap(span.start, span.end, ps, pe):
                    if best_priority is None or pspan.confidence > best_priority.confidence:
                        best_priority = pspan

            if best_priority is not None:
                # CITY gets a confidence margin because GLiNER
                # systematically under-scores city names relative to
                # first names for ambiguous tokens.
                margin = 0.0
                if best_priority.entity_type == "CITY":
                    margin = _CITY_CONFIDENCE_MARGIN
                    # Extra margin when text is a known US city
                    if best_priority.text.strip().lower() in gazetteer:
                        margin += _CITY_GAZETTEER_MARGIN
                if best_priority.confidence >= span.confidence - margin:
                    # Priority type has sufficient confidence — replace.
                    logger.debug(
                        "Name-collision replaced: %s %r (%.3f) → %s %r (%.3f)"
                        " [margin=%.3f]",
                        span.entity_type, span.text, span.confidence,
                        best_priority.entity_type, best_priority.text,
                        best_priority.confidence, margin,
                    )
                    result.append(best_priority)
                    continue
                # Name is higher confidence — keep it.  The priority span
                # was a weaker alternative and should not override.
                logger.debug(
                    "Name-collision kept name: %s %r (%.3f) over %s (%.3f)",
                    span.entity_type, span.text, span.confidence,
                    best_priority.entity_type, best_priority.confidence,
                )
        result.append(span)
    return result


# ---------------------------------------------------------------------------
# Type confusion correction
# ---------------------------------------------------------------------------

# Username format: contains underscore/dot between name parts, or trailing
# digits after a name — e.g. "First_Last", "John.Doe42", "Alice99"
_USERNAME_FORMAT_RE = re.compile(
    r'^[A-Za-z][A-Za-z0-9]*[._][A-Za-z][A-Za-z0-9]*(?:[._][A-Za-z0-9]+)*\d{0,4}$'
    r'|'
    r'^[A-Za-z]{2,15}\d{1,4}$'
)

# US SSN format: XXX-XX-XXXX (with various separators)
_SSN_FORMAT_RE = re.compile(
    r'^\d{3}[\s\-\.]\d{2}[\s\-\.]\d{4}$'
)


# Context words near a 9-digit number that indicate routing number
_ROUTING_CONTEXT_WORDS = frozenset({
    "routing", "aba", "transit", "wire", "wire transfer",
    "bank", "ach", "direct deposit", "routing number",
    "fed", "federal reserve",
})

# Context words near a 9-digit number that indicate SSN
_SSN_CONTEXT_WORDS = frozenset({
    "ssn", "social security", "soc sec", "ss#", "social sec",
    "tax", "employer identification",
})


def _correct_type_confusions(
    spans: list[Span],
    source_text: str | None = None,
) -> list[Span]:
    """Reclassify ML spans that match a more specific type's format.

    GLiNER has known confusion patterns (from nemotron_pii 1000-sample):
    - USERNAME → FIRSTNAME (14): usernames with underscores/dots/digits
    - PHONE → SSN: social security numbers in XXX-XX-XXXX format
    - SSN classified on routing numbers: 9-digit numbers passing ABA checksum
    - SSN ↔ BANK_ROUTING context disambiguation via nearby keywords

    Only reclassifies ML-tier spans (pattern detections are trusted).
    """
    from .checksum import validate_aba_routing

    result: list[Span] = []
    corrections: dict[str, int] = {}
    for span in spans:
        if span.tier != Tier.ML:
            result.append(span)
            continue

        etype = normalize_entity_type(span.entity_type)
        text = span.text.strip()
        new_type = None

        # FIRSTNAME/LASTNAME → USERNAME when text matches username format
        if etype in ("FIRSTNAME", "LASTNAME") and _USERNAME_FORMAT_RE.match(text):
            new_type = "USERNAME"

        # PHONE → SSN when text matches US SSN format (XXX-XX-XXXX)
        elif etype == "PHONE" and _SSN_FORMAT_RE.match(text):
            new_type = "SSN"

        # SSN → BANK_ROUTING: ABA checksum OR context keywords
        elif etype == "SSN":
            digits = re.sub(r'\D', '', text)
            if len(digits) == 9:
                valid, _ = validate_aba_routing(digits)
                if valid:
                    new_type = "BANK_ROUTING"
                elif source_text:
                    # Check surrounding context for routing keywords
                    ctx_start = max(0, span.start - 100)
                    ctx_end = min(len(source_text), span.end + 100)
                    context = source_text[ctx_start:ctx_end].lower()
                    has_routing = any(
                        re.search(r'\b' + re.escape(kw) + r'\b', context)
                        for kw in _ROUTING_CONTEXT_WORDS
                    )
                    has_ssn = any(
                        re.search(r'\b' + re.escape(kw) + r'\b', context)
                        for kw in _SSN_CONTEXT_WORDS
                    )
                    if has_routing and not has_ssn:
                        new_type = "BANK_ROUTING"

        # BANK_ROUTING → SSN: context keywords override when SSN words present
        elif etype == "BANK_ROUTING" and source_text:
            digits = re.sub(r'\D', '', text)
            if len(digits) == 9:
                ctx_start = max(0, span.start - 100)
                ctx_end = min(len(source_text), span.end + 100)
                context = source_text[ctx_start:ctx_end].lower()
                has_ssn = any(
                    re.search(r'\b' + re.escape(kw) + r'\b', context)
                    for kw in _SSN_CONTEXT_WORDS
                )
                has_routing = any(
                    re.search(r'\b' + re.escape(kw) + r'\b', context)
                    for kw in _ROUTING_CONTEXT_WORDS
                )
                if has_ssn and not has_routing:
                    new_type = "SSN"

        if new_type is not None:
            key = f"{etype}→{new_type}"
            corrections[key] = corrections.get(key, 0) + 1
            logger.debug(
                "Type correction: %s → %s for %r",
                span.entity_type, new_type, text,
            )
            result.append(Span(
                start=span.start,
                end=span.end,
                text=span.text,
                entity_type=new_type,
                confidence=span.confidence,
                detector=span.detector,
                tier=span.tier,
                raw_confidence=span.raw_confidence,
                detector_label=span.detector_label,
            ))
        else:
            result.append(span)

    if corrections:
        detail = ", ".join(f"{k}({v})" for k, v in corrections.items())
        logger.info("Type corrections applied: %s", detail)
    return result


# ---------------------------------------------------------------------------
# ML name false-positive suppression (common English words)
# ---------------------------------------------------------------------------

# Words that GLiNER frequently misclassifies as FIRSTNAME or LASTNAME.
# These are common English nouns, adjectives, demonyms, and business terms
# that are never standalone person names in PII contexts.
# Imported _NEVER_NAMES covers job titles and structural terms; this set
# adds GLiNER-specific false positives discovered through benchmarking.
_ML_NAME_BLOCKLIST = frozenset({
    # Business / legal terms frequently flagged as FIRSTNAME
    "strategies", "consent", "contractors", "recipient", "recipients",
    "submission", "submissions", "campaigns", "investments",
    "obligations", "acquisition", "acquisitions", "compliance",
    "governance", "initiatives", "procurement", "stakeholders",
    "implementation", "specifications", "authorization",
    "documentation", "infrastructure", "telecommunications",
    "unfortunately", "approximately", "alternatively",
    "comprehensive", "fundamentally", "subsequently",
    "assessment", "requirements", "procedures", "guidelines",
    "provisions", "regulations", "amendments", "transactions",
    "participants", "beneficiaries", "representatives",
    "notification", "notifications", "coordination",
    "considerations", "responsibilities", "recommendations",
    "arrangements", "acknowledgment", "acknowledgement",
    "correspondence", "miscellaneous", "supplementary",
    # Common words flagged as LASTNAME
    "spark", "nationalist", "mutual", "team", "mente",
    "premium", "quantum", "spectrum", "catalyst", "pinnacle",
    "velocity", "momentum", "paradigm", "syndicate",
    "global", "digital", "federal", "central", "capital",
    "premier", "summit", "alliance", "standard", "enterprise",
    "ventures", "holdings", "partners", "associates", "solutions",
    "dynamics", "analytics", "logistics", "advisory",
    # Demonyms / nationality-adjacent words
    "croat", "croatian", "emirati", "kuwaiti", "qatari",
    "bahraini", "omani", "yemeni", "somali", "afghan",
    "iraqi", "irani", "iranian", "syrian", "libyan",
    "lebanese", "jordanian", "palestinian", "israeli",
    "turkish", "egyptian", "tunisian", "algerian", "moroccan",
    # Place names GLiNER confuses with person names
    "kremlin", "hartford", "pentagon", "saharan",
    "broadway", "westminster", "manhattan", "brooklyn",
    # Short words / brand-adjacent
    "verde", "tone", "viva", "alto", "vista",
    "forte", "tempo", "presto", "largo", "motto",
    "baha",
    # Action / role words
    "claim", "claims", "overall", "overview",
    "appeal", "appeals", "reform", "reforms",
    "mandate", "mandates", "verdict", "verdicts",
    "pioneer", "advocate", "sentinel",
    "interim", "ongoing", "pending", "pursuant",
    # Common words that start sentences (title-cased by position)
    "cash", "yoga", "menu", "logo", "demo", "memo",
    "quota", "bonus", "forum", "salon", "plaza",
    "versus", "via", "per", "etc", "also",
    # Common nouns/adjectives falsely detected as names
    "universal", "regional", "municipal", "provincial",
    "residential", "commercial", "industrial", "financial",
    "clinical", "surgical", "medical", "dental", "optical",
    "tropical", "biological", "technical", "political",
    "electoral", "judicial", "criminal", "civil",
    "annual", "quarterly", "monthly", "weekly", "daily",
    "primary", "secondary", "tertiary", "preliminary",
    "internal", "external", "lateral", "bilateral",
    "rural", "urban", "suburban", "coastal",
    # Nemotron PII FP analysis — additional words
    "baha", "al", "sales", "jazeera", "brokerage",
})


# Suffixes that NEVER appear on real person names (for words >= 7 chars).
# Verified against name databases: no known first or last name of 7+
# characters ends with any of these suffixes.
# Examples of what they catch:
#   -tion: "Administration", "Registration", "Specification"
#   -sion: "Commission", "Submission", "Permission"
#   -ness: "Awareness", "Business", "Effectiveness"
#   -ful:  "Powerful", "Successful", "Meaningful"
#   -less: "Regardless", "Wireless", "Careless"
#   -ism:  "Capitalism", "Terrorism", "Journalism"
# Explicitly excluded: -ity (Trinity, Felicity, Charity),
# -ous (Precious), -ence (Florence, Clarence), -ance (Constance),
# -ive (Clive), -ment (Clement), -able (Constable), -ers (Rogers),
# -son (Johnson), -ton (Clinton), -ing (Sterling, Irving)
# Common English words that pattern-tier (dictionary) name detectors
# falsely match.  Dictionary detectors use name frequency databases
# that include rare or archaic names — some are overwhelmingly common
# English words in practice.  Benchmark: 367 name FPs, ~150 from
# pattern-tier dictionary detections on words like these.
_PATTERN_NAME_BLOCKLIST = frozenset({
    # Common nouns/verbs used as titles or headings
    "environmental", "supplies", "supply", "press", "overview",
    "search", "contact", "register", "submit", "subscribe",
    "download", "upload", "install", "remove", "delete",
    "update", "cancel", "confirm", "accept", "decline",
    "review", "approve", "reject", "forward", "select",
    # Business/document words
    "chase", "grant", "sterling", "reed", "hunter",
    "archer", "mason", "porter", "turner", "carter",
    "cooper", "foster", "barber", "miller", "baker",
    "fisher", "taylor", "walker", "young", "price",
    # Determiners / pronouns / particles
    "your", "our", "all", "any", "none", "some",
    "most", "such", "each", "every", "other", "both",
    "what", "which", "where", "when", "there", "here",
    "still", "just", "only", "even", "about", "being",
    # Common adjectives/adverbs
    "new", "old", "good", "best", "great", "high",
    "low", "long", "short", "full", "last", "next",
    "real", "open", "close", "free", "true", "false",
    "safe", "fair", "nice", "fine", "rich", "poor",
    "clean", "smart", "clear", "sharp", "bright",
    # Titles and section headers
    "introduction", "conclusion", "summary", "abstract",
    "chapter", "section", "appendix", "index", "table",
    "figure", "reference", "disclaimer", "notice", "warning",
    "privacy", "terms", "conditions", "policy", "statement",
    "welcome", "home", "help", "about", "blog", "news",
    "events", "resources", "services", "products", "support",
})

_NON_NAME_SUFFIXES = (
    "tion", "tions",
    "sion", "sions",
    "ness",
    "ful",
    "less",
    "ism", "isms",
    "ize", "ized", "izes", "izing",
    "ify", "ified", "ifies", "ifying",
    "ily",
    "ably", "ibly",
    "ally",
    "ously",
    "ingly",
    "ively",
    "ical",
    "ible",
)


def _suppress_ml_name_false_positives(spans: list[Span]) -> list[Span]:
    """Suppress NAME-family spans whose text is a common non-name English word.

    Applies to ALL tiers (ML and pattern) — dictionary name detectors
    also produce false positives on common words like "Environmental",
    "Supplies", "Press" that happen to match name databases.

    Uses three complementary strategies:
    1. Explicit blocklist (_ML_NAME_BLOCKLIST + _PATTERN_NAME_BLOCKLIST)
       for known FP words across all tiers
    2. _NEVER_NAMES from dictionary detector (job titles, structural terms)
    3. Suffix heuristic: words >= 7 chars ending in suffixes that never
       appear on real names (-tion, -sion, -ness, -ful, -less, etc.)
    """
    from .dictionary_names import _NEVER_NAMES

    result: list[Span] = []
    suppressed = 0
    for span in spans:
        if span.entity_type in _NAME_FAMILY:
            lower = span.text.strip().lower()
            if (
                lower in _ML_NAME_BLOCKLIST
                or lower in _NEVER_NAMES
                or lower in _PATTERN_NAME_BLOCKLIST
            ):
                suppressed += 1
                logger.debug(
                    "Name FP suppressed: %s %r (blocklist, tier=%s)",
                    span.entity_type, span.text, span.tier,
                )
                continue
            # Suffix heuristic: words with 7+ characters ending in
            # distinctly non-name English suffixes.
            if len(lower) >= 7 and lower.endswith(_NON_NAME_SUFFIXES):
                suppressed += 1
                logger.debug(
                    "Name FP suppressed: %s %r (suffix, tier=%s)",
                    span.entity_type, span.text, span.tier,
                )
                continue
        result.append(span)

    if suppressed:
        logger.info(
            "Name FP suppression: removed %d common-word name spans",
            suppressed,
        )
    return result


# ---------------------------------------------------------------------------
# ML USERNAME false-positive suppression
# ---------------------------------------------------------------------------

# Common English words GLiNER misclassifies as USERNAME.
# The pattern detector has _USERNAME_FALSE_POSITIVES but that only filters
# pattern-tier detections.  This covers ML-tier USERNAME spans.
_ML_USERNAME_BLOCKLIST = frozenset({
    "training", "obligations", "license", "licenses", "licensed",
    "named", "manual", "manuals", "experience", "experienced",
    "re-authenticated", "authenticated", "authentication",
    "registered", "registration", "certified", "certification",
    "authorized", "authorization", "qualified", "qualification",
    "approved", "approval", "designated", "designation",
    "processed", "processing", "completed", "completion",
    "submitted", "submission", "confirmed", "confirmation",
    "verified", "verification", "validated", "validation",
    "updated", "suspended", "terminated", "transferred",
    "recommended", "assigned", "associated", "documented",
    "referenced", "generated", "maintained", "established",
    "implemented", "distributed", "administered",
    # Additional from nemotron_pii benchmark
    "multiple", "security",
})

# Regex to strip leading/trailing non-alphanumeric chars for blocklist matching
_STRIP_NONALPHA_RE = re.compile(r'^[^a-z0-9]+|[^a-z0-9]+$')


def _suppress_ml_username_false_positives(spans: list[Span]) -> list[Span]:
    """Suppress USERNAME spans whose text is a common English word."""
    result: list[Span] = []
    for span in spans:
        if normalize_entity_type(span.entity_type) == "USERNAME":
            lower = span.text.strip().lower()
            if lower in _ML_USERNAME_BLOCKLIST:
                logger.debug(
                    "USERNAME FP suppressed: %r (blocklist, tier=%s)",
                    span.text, span.tier,
                )
                continue
            # Suffix heuristic: common English word suffixes → not a username
            if len(lower) >= 7 and lower.endswith(_NON_NAME_SUFFIXES):
                logger.debug(
                    "USERNAME FP suppressed: %r (suffix, tier=%s)",
                    span.text, span.tier,
                )
                continue
        result.append(span)
    return result


# ---------------------------------------------------------------------------
# ML CITY / location false-positive suppression
# ---------------------------------------------------------------------------

# Entity types to check for location false positives.
_LOCATION_FP_TYPES = frozenset({"CITY", "STATE", "COUNTY", "ADDRESS"})

# Common non-location words that GLiNER misclassifies as CITY.
_ML_CITY_BLOCKLIST = frozenset({
    # Business/organizational terms
    "summit", "alliance", "enterprise", "standard", "premium",
    "capital", "central", "federal", "national", "general",
    "premier", "pioneer", "advocate", "sentinel", "catalyst",
    "ventures", "holdings", "partners", "dynamics", "momentum",
    # Legal/governance
    "mandate", "verdict", "reform", "appeal", "consent",
    "governance", "compliance", "oversight", "tribunal",
    # Generic terms
    "overall", "overview", "interim", "mutual", "prime",
    "exchange", "gateway", "forum", "arena", "plaza",
})


def _suppress_ml_location_false_positives(spans: list[Span]) -> list[Span]:
    """Suppress CITY/location spans whose text is clearly not a place name.

    Uses two strategies:
    1. Explicit blocklist of business/organizational words
    2. Suffix heuristic: words >= 7 chars with non-name suffixes are never
       place names either (-tion, -sion, -ness, -ful, etc.)
    """
    result: list[Span] = []
    suppressed = 0
    for span in spans:
        etype = normalize_entity_type(span.entity_type)
        if etype in _LOCATION_FP_TYPES and span.tier == Tier.ML:
            lower = span.text.strip().lower()
            if lower in _ML_CITY_BLOCKLIST:
                suppressed += 1
                logger.debug(
                    "Location FP suppressed: %s %r (blocklist)",
                    span.entity_type, span.text,
                )
                continue
            if len(lower) >= 7 and lower.endswith(_NON_NAME_SUFFIXES):
                suppressed += 1
                logger.debug(
                    "Location FP suppressed: %s %r (suffix)",
                    span.entity_type, span.text,
                )
                continue
        result.append(span)
    if suppressed:
        logger.info(
            "Location FP suppression: removed %d ML location spans", suppressed,
        )
    return result
