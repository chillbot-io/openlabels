"""Context-aware enhancement for PII detection.

Implements industry-standard patterns from Microsoft Presidio and Google DLP:
1. Pre-filtering with deny lists (obvious false positives)
2. Pattern-based exclusions (company names, etc.)
3. Hotword-based confidence adjustment
4. Confidence routing to reduce LLM calls

Architecture:
    [Detectors] -> Spans -> [ContextEnhancer] -> Enhanced Spans -> [LLM Verifier]

The enhancer adjusts confidence scores based on context, allowing:
- High-confidence spans to pass without LLM verification
- Low-confidence spans to be rejected without LLM verification
- Only ambiguous spans go to LLM (reducing calls by ~80%)
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from ..types import Span, Tier

logger = logging.getLogger(__name__)


# =============================================================================
# DENY LISTS - Known false positives to reject immediately
# =============================================================================

# Common words that get falsely detected as NAMEs
NAME_DENY_LIST: set[str] = {
    # Common verbs/words that are rarely names
    "will", "may", "can",  # Modal verbs
    "ensure", "include", "require", "provide", "support", "involve",
    "advanced", "covered", "strong", "balance", "stress", "health",
    "involved", "details", "reference", "number", "identity", "reviewed",
    # Document/signature related false positives
    "signature", "signed", "reports", "requests", "verbalized",
    "confirmed", "understands", "agrees", "discussed", "prior",
    "reports prior", "requests bilingual",
    # Generic roles/terms
    "admin", "user", "customer", "client", "patient", "member",
    "manager", "director", "agent", "officer", "employee", "staff",
    # Tech/product terms often detected as names
    "null", "undefined", "none", "true", "false", "default",
    # HTML/form artifacts
    "input", "label", "form", "div", "span", "body",
    # Common single letters/short words
    "e", "in", "of", "or", "an", "to",
    # High-frequency FPs from benchmarks
    "dear", "account", "male", "female", "loan", "personal loan",
    "bitcoin", "bic", "iban", "presto", "apt", "sons", "global",
    "psychology", "human", "assurance", "done", "writing", "reaching out",
    # Titles alone (not followed by name)
    "mr", "mrs", "ms", "miss", "dr", "prof",
    # Currency names
    "dollar", "pound", "euro", "peso", "yen", "won", "rupee", "franc",
    "krona", "krone", "dinar", "dirham", "riyal", "ringgit", "baht",
    # Gender identities (not PII)
    "pangender", "agender", "bigender", "genderfluid", "genderqueer",
}

# Common words that get falsely detected as USERNAMEs
USERNAME_DENY_LIST: set[str] = {
    "has", "number", "agent", "details", "reference", "and",
    "the", "for", "with", "from", "that", "this", "are", "was",
    "attempts", "using", "name", "ending", "credentials", "linked",
    "which", "auto", "update", "needed", "login", "password",
    "admin", "user", "system", "root", "guest", "test",
}

# Common words that get falsely detected as ADDRESSes
ADDRESS_DENY_LIST: set[str] = {
    "maisonette", "apartment", "flat", "condo", "house", "building",
    "cottage", "bungalow", "villa", "penthouse", "studio", "loft",
    "operations", "department", "division", "unit", "section", "branch",
    "headquarters", "office", "floor", "room", "suite",
    "location", "site", "area", "zone", "region", "district",
}

# Common words falsely detected as MEDICATION
MEDICATION_DENY_LIST: set[str] = {
    "health", "healthy", "stress", "focus", "burn", "aged", "major", "assist",
    "care", "treatment", "therapy", "recovery", "wellness", "prevention",
    "diagnosis", "symptom", "condition", "disease", "disorder", "syndrome",
    "standardized", "clinical", "medical", "patient", "doctor", "nurse",
}

# Patterns that indicate NOT an MRN
MRN_EXCLUDE_PATTERNS = [
    # Dollar amounts with decimals: 440060.24, 512717.39
    re.compile(r'^\d+\.\d{2}$'),
    # Currency with explicit symbol: $850, EUR100
    re.compile(r'^[$\u20ac\u00a3\u00a5\u20b9]\d'),
    # Currency codes with symbol: RD$850, NZ$100
    re.compile(r'^[A-Z]{1,3}[$\u20ac\u00a3\u00a5\u20b9]\d'),
    # User agent versions: Chrome/25.0.801.0
    re.compile(r'(Chrome|Safari|Firefox|AppleWebKit|Gecko|Mozilla|MSIE|Trident)[/\d\.]', re.I),
    # Crypto addresses (long alphanumeric)
    re.compile(r'^[a-zA-Z0-9]{30,}$'),
]

# Company suffixes
COMPANY_SUFFIXES: set[str] = {
    "inc", "inc.", "llc", "llc.", "ltd", "ltd.", "corp", "corp.",
    "corporation", "company", "co", "co.", "group", "holdings",
    "partners", "associates", "services", "solutions", "systems",
    "technologies", "tech", "labs", "studio", "studios",
}


# =============================================================================
# HOTWORDS - Context words that adjust confidence
# =============================================================================

@dataclass
class HotwordRule:
    """A rule for adjusting confidence based on nearby words."""
    pattern: re.Pattern
    confidence_delta: float  # Positive = boost, negative = reduce
    window_before: int = 50
    window_after: int = 30
    description: str = ""


# Positive hotwords - increase confidence these are real names
NAME_POSITIVE_HOTWORDS: list[HotwordRule] = [
    HotwordRule(
        re.compile(r'\b(mr\.?|mrs\.?|ms\.?|miss|dr\.?|prof\.?)\s*$', re.I),
        confidence_delta=0.25,
        window_before=20, window_after=0,
        description="Title before name"
    ),
    HotwordRule(
        re.compile(r'\b(dear|attn:?|attention:?|to:?|from:?)\s*$', re.I),
        confidence_delta=0.15,
        window_before=30, window_after=0,
        description="Letter salutation"
    ),
    HotwordRule(
        re.compile(r'\b(patient|employee|customer|client|user):?\s*$', re.I),
        confidence_delta=0.20,
        window_before=30, window_after=0,
        description="Role label before name"
    ),
    HotwordRule(
        re.compile(r'\bname:?\s*$', re.I),
        confidence_delta=0.30,
        window_before=20, window_after=0,
        description="Explicit name label"
    ),
    HotwordRule(
        re.compile(r'\b(signed|sincerely|regards|best)\s*,?\s*$', re.I),
        confidence_delta=0.20,
        window_before=30, window_after=0,
        description="Letter closing"
    ),
]

# Negative hotwords - decrease confidence
NAME_NEGATIVE_HOTWORDS: list[HotwordRule] = [
    HotwordRule(
        re.compile(r'^\s*(inc\.?|llc\.?|ltd\.?|corp\.?|co\.?|group|holdings)\b', re.I),
        confidence_delta=-0.35,
        window_before=0, window_after=30,
        description="Company suffix after"
    ),
    HotwordRule(
        re.compile(r'^\s*(street|st\.?|avenue|ave\.?|road|rd\.?|drive|dr\.?|lane|ln\.?|blvd\.?)\b', re.I),
        confidence_delta=-0.35,
        window_before=0, window_after=30,
        description="Street suffix after"
    ),
    HotwordRule(
        re.compile(r'\b(from|purchased|ordered|shipped|via)\s+$', re.I),
        confidence_delta=-0.20,
        window_before=30, window_after=0,
        description="Transaction context"
    ),
    HotwordRule(
        re.compile(r'\b(at|in|to|from|through)\s+$', re.I),
        confidence_delta=-0.15,
        window_before=15, window_after=0,
        description="Location preposition"
    ),
    HotwordRule(
        re.compile(r'^\s*\'s\s+(site|website|page|app|service|product|store)\b', re.I),
        confidence_delta=-0.30,
        window_before=0, window_after=40,
        description="Possessive + product"
    ),
]


# =============================================================================
# PATTERN EXCLUSIONS
# =============================================================================

# Pattern: "X, Y and Z" or "X and Y" - likely a company/firm name
COMPANY_PATTERN = re.compile(
    r'^[A-Z][a-z]+(?:[-\s][A-Z][a-z]+)*'
    r'(?:,\s*[A-Z][a-z]+(?:[-\s][A-Z][a-z]+)*)*'
    r'\s+and\s+'
    r'[A-Z][a-z]+(?:[-\s][A-Z][a-z]+)*'
    r'\.?$',
    re.UNICODE
)

# Pattern: Greeting + name
GREETING_PATTERN = re.compile(r'^(hi|hello|hey|dear|greetings)\s+', re.I)

# Pattern: Contains HTML
HTML_PATTERN = re.compile(r'<[^>]+>|&[a-z]+;|</?\w+', re.I)

# Pattern: Reference codes
REFERENCE_CODE_PATTERN = re.compile(r'^(REF|INV|DOC|ID|M|SVE)[-\s]?\d', re.I)

# Pattern: Contains digits
HAS_DIGITS_PATTERN = re.compile(r'\d')

# Pattern: All caps
ALL_CAPS_PATTERN = re.compile(r'^[A-Z]{2,}$')

# Pattern: Trailing HTML
TRAILING_HTML_PATTERN = re.compile(r'<[^>]*>?\s*$|^\s*<[^>]*')

# Pattern: Possessive + product
POSSESSIVE_PRODUCT_PATTERN = re.compile(
    r"'s\s+(site|website|page|app|service|product|store|account|system|platform)",
    re.I
)

# Pattern: Hyphenated names like "Lewis-Osborne"
HYPHENATED_NAME_PATTERN = re.compile(r'^[A-Z][a-z]+(?:-[A-Z][a-z]+)+$', re.UNICODE)

# Business context words
BUSINESS_CONTEXT_WORDS = re.compile(
    r'\b(inc\.?|llc\.?|ltd\.?|corp\.?|co\.?|company|corporation|'
    r'firm|group|partners|associates|holdings|'
    r'agreement|contract|employed|employer|employment|'
    r'work(?:s|ed|ing)?\s+(?:at|for|with)|'
    r'hired|hire|hiring|'
    r'client|vendor|supplier|contractor|'
    r'invoice|payment|bill|account|'
    r'business|enterprise|organization)\b',
    re.I
)


# =============================================================================
# CONTEXT ENHANCER CLASS
# =============================================================================

@dataclass
class EnhancementResult:
    """Result of context enhancement for a span."""
    action: str  # "keep", "reject", "verify" (send to LLM)
    confidence: float
    reasons: list[str] = field(default_factory=list)
    span: Any | None = None  # Updated span (if text was modified), else None


class ContextEnhancer:
    """
    Context-aware enhancement for PII detection.

    Implements the industry-standard pattern from Microsoft Presidio
    and Google DLP for reducing false positives through:
    1. Deny list filtering
    2. Pattern-based exclusions
    3. Hotword-based confidence adjustment
    4. Confidence-based routing

    Usage:
        enhancer = ContextEnhancer()
        enhanced_spans = enhancer.enhance(text, spans)
    """

    def __init__(
        self,
        high_confidence_threshold: float = 0.85,
        low_confidence_threshold: float = 0.35,
        enable_deny_list: bool = True,
        enable_hotwords: bool = True,
        enable_patterns: bool = True,
    ):
        self.high_threshold = high_confidence_threshold
        self.low_threshold = low_confidence_threshold
        self.enable_deny_list = enable_deny_list
        self.enable_hotwords = enable_hotwords
        self.enable_patterns = enable_patterns

        # Entity types to apply enhancement to
        # SURGICAL: Only filter MRN for now (dollar amounts like 440060.24)
        self.enhanced_types = {"MRN"}

    def _get_context_window(
        self,
        text: str,
        span: Span,
        before: int,
        after: int
    ) -> tuple[str, str]:
        """Get text before and after the span."""
        text_before = text[max(0, span.start - before):span.start]
        text_after = text[span.end:min(len(text), span.end + after)]
        return text_before, text_after

    def _check_deny_list(self, span: Span) -> str | None:
        """Check if span text is in deny list. Returns reason if denied."""
        text_lower = span.text.lower().strip()
        span_text = span.text.strip()
        entity_type = span.entity_type.upper()

        text_normalized = text_lower.rstrip('.,;:!?')

        # Select appropriate deny list
        if entity_type in ("NAME", "PERSON", "PER"):
            deny_list = NAME_DENY_LIST
        elif entity_type == "USERNAME":
            deny_list = USERNAME_DENY_LIST
        elif entity_type == "ADDRESS":
            deny_list = ADDRESS_DENY_LIST
        elif entity_type == "MEDICATION":
            deny_list = MEDICATION_DENY_LIST
        elif entity_type == "MRN":
            # MRN uses pattern-based exclusion
            for pattern in MRN_EXCLUDE_PATTERNS:
                if pattern.search(span_text):
                    return f"mrn_exclude_pattern:{span_text[:30]}"
            return None
        else:
            deny_list = NAME_DENY_LIST

        if text_lower in deny_list:
            return f"deny_list:{text_lower}"

        if text_normalized in deny_list:
            return f"deny_list:{text_normalized}"

        # For NAME types, check company suffixes
        if entity_type in ("NAME", "PERSON", "PER"):
            for suffix in COMPANY_SUFFIXES:
                if text_lower.endswith(suffix) or text_lower.endswith(f" {suffix}"):
                    return f"company_suffix:{suffix}"

        return None

    def _normalize_text(self, span_text: str) -> str:
        """Normalize span text by stripping artifacts."""
        text = span_text.rstrip('.,;:!?')
        text = text.strip()
        return text

    def _check_patterns(self, text: str, span: Span) -> tuple[str | None, str | None, int]:
        """Check pattern-based exclusions."""
        span_text = span.text
        start_offset = 0

        # Normalize first
        normalized = self._normalize_text(span_text)
        if normalized != span_text:
            span_text = normalized

        # Check for HTML content
        if HTML_PATTERN.search(span_text):
            return (f"html_content:{span_text[:30]}", None, 0)

        if TRAILING_HTML_PATTERN.search(span_text):
            return (f"html_fragment:{span_text[:30]}", None, 0)

        # Reference codes
        if REFERENCE_CODE_PATTERN.match(span_text):
            return (f"reference_code:{span_text}", None, 0)

        # All caps (likely acronym)
        if ALL_CAPS_PATTERN.match(span_text) and len(span_text) > 2:
            return (f"all_caps:{span_text}", None, 0)

        # Company pattern
        if COMPANY_PATTERN.match(span_text):
            return (f"company_pattern:{span_text}", None, 0)

        # Contains digits (likely username)
        if HAS_DIGITS_PATTERN.search(span_text):
            if not re.search(r'\s+(II|III|IV|V|VI|Jr\.?|Sr\.?)$', span_text, re.I):
                return (f"contains_digits:{span_text}", None, 0)

        # Possessive + product
        context_around = text[max(0, span.start):min(len(text), span.end + 50)]
        if POSSESSIVE_PRODUCT_PATTERN.search(context_around):
            return (f"possessive_product:{span_text}", None, 0)

        # Hyphenated company names
        if HYPHENATED_NAME_PATTERN.match(span_text):
            context_window = text[max(0, span.start - 100):min(len(text), span.end + 100)]
            if BUSINESS_CONTEXT_WORDS.search(context_window):
                return (f"hyphenated_company:{span_text}", None, 0)

        # Greeting pattern - strip it
        greeting_match = GREETING_PATTERN.match(span_text)
        if greeting_match:
            start_offset = greeting_match.end()
            cleaned = span_text[start_offset:].strip()
            cleaned = cleaned.rstrip('.,;:')
            if cleaned and len(cleaned) >= 2:
                return (None, cleaned, start_offset)
            else:
                return (f"greeting_only:{span_text}", None, 0)

        # Return normalized if different
        if normalized != span.text and len(normalized) >= 2:
            return (None, normalized, 0)

        return (None, None, 0)

    def _apply_hotwords(
        self,
        text: str,
        span: Span,
        current_confidence: float
    ) -> tuple[float, list[str]]:
        """Apply hotword rules to adjust confidence."""
        confidence = current_confidence
        reasons = []

        entity_type = span.entity_type.upper()

        if entity_type in ("NAME", "PERSON", "PER"):
            positive_rules = NAME_POSITIVE_HOTWORDS
            negative_rules = NAME_NEGATIVE_HOTWORDS
        else:
            return confidence, reasons

        # Apply positive hotwords
        for rule in positive_rules:
            text_before, text_after = self._get_context_window(
                text, span, rule.window_before, rule.window_after
            )

            if rule.window_before > 0 and rule.pattern.search(text_before):
                confidence = min(1.0, confidence + rule.confidence_delta)
                reasons.append(f"+hotword:{rule.description}")
            elif rule.window_after > 0 and rule.pattern.search(text_after):
                confidence = min(1.0, confidence + rule.confidence_delta)
                reasons.append(f"+hotword:{rule.description}")

        # Apply negative hotwords
        for rule in negative_rules:
            text_before, text_after = self._get_context_window(
                text, span, rule.window_before, rule.window_after
            )

            if rule.window_before > 0 and rule.pattern.search(text_before):
                confidence = max(0.0, confidence + rule.confidence_delta)
                reasons.append(f"-hotword:{rule.description}")
            elif rule.window_after > 0 and rule.pattern.search(text_after):
                confidence = max(0.0, confidence + rule.confidence_delta)
                reasons.append(f"-hotword:{rule.description}")

        return confidence, reasons

    def enhance_span(self, text: str, span: Span) -> EnhancementResult:
        """Enhance a single span with context analysis."""
        reasons = []
        confidence = span.confidence

        # Skip enhancement for non-target types
        if span.entity_type.upper() not in self.enhanced_types:
            return EnhancementResult("keep", confidence, ["non_enhanced_type"])

        # Stage 1: Deny list check
        if self.enable_deny_list:
            deny_reason = self._check_deny_list(span)
            if deny_reason:
                if span.tier >= Tier.STRUCTURED:
                    logger.warning(
                        f"ContextEnhancer: Rejecting high-tier span '{span.text}' "
                        f"(tier={span.tier.name}) via deny list"
                    )
                return EnhancementResult("reject", 0.0, [deny_reason])

        # Skip remaining for high-tier
        if span.tier >= Tier.STRUCTURED:
            return EnhancementResult("keep", confidence, ["high_tier"])

        # Stage 2: Pattern exclusions
        if self.enable_patterns:
            reject_reason, cleaned_text, start_offset = self._check_patterns(text, span)
            if reject_reason:
                return EnhancementResult("reject", 0.0, [reject_reason])
            if cleaned_text:
                from dataclasses import replace
                new_start = span.start + start_offset
                span = replace(span, start=new_start, text=cleaned_text, end=new_start + len(cleaned_text))
                reasons.append(f"greeting_stripped:{cleaned_text}")

        # Stage 3: Hotword adjustment
        if self.enable_hotwords:
            confidence, hotword_reasons = self._apply_hotwords(text, span, confidence)
            reasons.extend(hotword_reasons)

        # Stage 4: Route based on confidence
        if confidence >= self.high_threshold:
            return EnhancementResult("keep", confidence, reasons + ["high_confidence"], span=span)
        elif confidence <= self.low_threshold:
            return EnhancementResult("reject", confidence, reasons + ["low_confidence"], span=span)
        else:
            return EnhancementResult("verify", confidence, reasons + ["needs_llm"], span=span)

    def enhance(
        self,
        text: str,
        spans: list[Span],
        return_stats: bool = False
    ) -> list[Span]:
        """
        Enhance a list of spans with context analysis.

        Args:
            text: Original text
            spans: List of detected spans
            return_stats: If True, log statistics

        Returns:
            List of spans to keep (verified or high-confidence)
        """
        if not spans:
            return spans

        kept = []
        rejected = 0
        needs_llm = 0
        passed_through = 0

        for span in spans:
            result = self.enhance_span(text, span)
            # Use returned span (may be a new object if text was modified)
            updated_span = result.span if result.span is not None else span

            if result.action == "keep":
                from dataclasses import replace
                updated_span = replace(updated_span, confidence=result.confidence)
                kept.append(updated_span)
                passed_through += 1
                logger.debug(
                    f"ContextEnhancer: KEEP '{updated_span.text}' ({updated_span.entity_type}) "
                    f"conf={result.confidence:.2f} reasons={result.reasons}"
                )
            elif result.action == "reject":
                rejected += 1
                logger.info(
                    f"ContextEnhancer: REJECT '{updated_span.text}' ({updated_span.entity_type}) "
                    f"reasons={result.reasons}"
                )
            else:  # verify
                from dataclasses import replace
                updated_span = replace(updated_span, confidence=result.confidence, needs_review=True, review_reason="llm_verification")
                kept.append(updated_span)
                needs_llm += 1
                logger.debug(
                    f"ContextEnhancer: VERIFY '{updated_span.text}' ({updated_span.entity_type}) "
                    f"conf={result.confidence:.2f} reasons={result.reasons}"
                )

        if return_stats or rejected > 0 or needs_llm > 0:
            logger.info(
                f"ContextEnhancer: {len(spans)} spans -> "
                f"{passed_through} kept, {needs_llm} need LLM, {rejected} rejected"
            )

        return kept


def create_enhancer(**kwargs) -> ContextEnhancer:
    """Create a context enhancer with default settings."""
    return ContextEnhancer(**kwargs)
