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

import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

from ..types import Span, Tier
from .constants import (
    CONFIDENCE_BOOST_HIGH,
    CONFIDENCE_BOOST_LOW,
    CONFIDENCE_BOOST_MEDIUM,
    CONFIDENCE_BOOST_MINIMAL,
    CONFIDENCE_LOW,
    CONFIDENCE_PENALTY_HIGH,
    CONFIDENCE_PENALTY_LOW,
    CONFIDENCE_PENALTY_MEDIUM,
    CONFIDENCE_PENALTY_MINIMAL,
    LOW_CONFIDENCE_THRESHOLD,
)

logger = logging.getLogger(__name__)


# --- Deny Lists (known false positives to reject) ---

# Common words that get falsely detected as NAMEs
NAME_DENY_LIST: Set[str] = {
    # Common verbs/words that are rarely names
    "will", "may", "can",  # Modal verbs - almost never names in context
    "ensure", "include", "require", "provide", "support", "involve",
    "advanced", "covered", "strong", "balance", "stress", "health",
    "involved", "details", "reference", "number", "identity", "reviewed",
    # Document/signature related false positives
    "signature", "signed", "reports", "requests", "verbalized",
    "confirmed", "understands", "agrees", "discussed", "prior",
    "reports prior", "requests bilingual",  # Common phrases in clinical notes
    # NOTE: Removed grant/mark/bill/chase/rob/sue/faith/hope/grace/joy/penny/holly/ivy/rose
    # These are common first names and cause recall loss
    # Generic roles/terms
    "admin", "user", "customer", "client", "patient", "member",
    "manager", "director", "agent", "officer", "employee", "staff",
    # Tech/product terms often detected as names
    "null", "undefined", "none", "true", "false", "default",
    # HTML/form artifacts
    "input", "label", "form", "div", "span", "strong", "body",
    # Common single letters/short words
    "e", "in", "of", "or", "an", "to",
    # High-frequency FPs from AI4Privacy benchmark (clearly not names)
    "dear", "account", "male", "female", "loan", "personal loan",
    "bitcoin", "bic", "iban", "presto", "apt", "sons", "global",
    "psychology", "human", "assurance", "done", "writing", "reaching out",
    # NOTE: Removed north/south/east/west/fort - can be part of real names
    # Titles alone (not followed by name)
    "mr", "mrs", "ms", "miss", "dr", "prof",
    # Currency names
    "dollar", "pound", "euro", "peso", "yen", "won", "rupee", "franc",
    "krona", "krone", "dinar", "dirham", "riyal", "ringgit", "baht",
    # Gender identities (not PII)
    "pangender", "agender", "bigender", "genderfluid", "genderqueer",
}

# Common words that get falsely detected as USERNAMEs
USERNAME_DENY_LIST: Set[str] = {
    # Common words from benchmark FPs
    "has", "number", "agent", "details", "reference", "and",
    "the", "for", "with", "from", "that", "this", "are", "was",
    "attempts", "using", "name", "ending", "credentials", "linked",
    "which", "auto", "update", "needed", "login", "password",
    # Generic roles
    "admin", "user", "system", "root", "guest", "test",
}

# Common words that get falsely detected as ADDRESSes
ADDRESS_DENY_LIST: Set[str] = {
    # Building types (not actual addresses)
    "maisonette", "apartment", "flat", "condo", "house", "building",
    "cottage", "bungalow", "villa", "penthouse", "studio", "loft",
    # Department/organizational terms
    "operations", "department", "division", "unit", "section", "branch",
    "headquarters", "office", "floor", "room", "suite",
    # Generic location words
    "location", "site", "area", "zone", "region", "district",
}

# Common words falsely detected as MEDICATION (not in actual drug lists)
MEDICATION_DENY_LIST: Set[str] = {
    # Generic health/medical words - not drug names
    "health", "healthy", "stress", "focus", "burn", "aged", "major", "assist",
    "care", "treatment", "therapy", "recovery", "wellness", "prevention",
    "diagnosis", "symptom", "condition", "disease", "disorder", "syndrome",
    # Common words that might appear in medical contexts
    "standardized", "clinical", "medical", "patient", "doctor", "nurse",
}

# Patterns that indicate NOT an MRN (dollar amounts, user agents, etc.)
MRN_EXCLUDE_PATTERNS = [
    # Dollar amounts with decimals: 440060.24, 512717.39
    re.compile(r'^\d+\.\d{2}$'),
    # Currency with explicit symbol: $850, €100, £50, ¥1000, ₹500
    re.compile(r'^[$€£¥₹]\d'),
    # Currency codes with symbol: RD$850, NZ$100, A$50
    re.compile(r'^[A-Z]{1,3}[$€£¥₹]\d'),
    # User agent versions: Chrome/25.0.801.0, Safari/537.1.0
    re.compile(r'(Chrome|Safari|Firefox|AppleWebKit|Gecko|Mozilla|MSIE|Trident)[/\d\.]', re.I),
    # Crypto addresses (long alphanumeric)
    re.compile(r'^[a-zA-Z0-9]{30,}$'),
]

# Company suffixes that indicate organization, not person
COMPANY_SUFFIXES: Set[str] = {
    "inc", "inc.", "llc", "llc.", "ltd", "ltd.", "corp", "corp.",
    "corporation", "company", "co", "co.", "group", "holdings",
    "partners", "associates", "services", "solutions", "systems",
    "technologies", "tech", "labs", "studio", "studios",
}

# Location suffixes that indicate place, not person
LOCATION_SUFFIXES: Set[str] = {
    "street", "st", "st.", "avenue", "ave", "ave.", "road", "rd", "rd.",
    "drive", "dr", "dr.", "lane", "ln", "ln.", "boulevard", "blvd",
    "court", "ct", "ct.", "place", "pl", "pl.", "way", "circle",
    "county", "city", "town", "village", "state", "country",
}


# --- Hotwords (context words that adjust confidence) ---

@dataclass
class HotwordRule:
    """A rule for adjusting confidence based on nearby words."""
    pattern: re.Pattern
    confidence_delta: float  # Positive = boost, negative = reduce
    window_before: int = 50  # Characters to look before entity
    window_after: int = 30   # Characters to look after entity
    description: str = ""


# Positive hotwords - increase confidence these are real names
NAME_POSITIVE_HOTWORDS: List[HotwordRule] = [
    HotwordRule(
        re.compile(r'\b(mr\.?|mrs\.?|ms\.?|miss|dr\.?|prof\.?)\s*$', re.I),
        confidence_delta=CONFIDENCE_BOOST_MEDIUM,
        window_before=20, window_after=0,
        description="Title before name"
    ),
    HotwordRule(
        re.compile(r'\b(dear|attn:?|attention:?|to:?|from:?)\s*$', re.I),
        confidence_delta=CONFIDENCE_BOOST_MINIMAL,
        window_before=30, window_after=0,
        description="Letter salutation"
    ),
    HotwordRule(
        re.compile(r'\b(patient|employee|customer|client|user):?\s*$', re.I),
        confidence_delta=CONFIDENCE_BOOST_LOW,
        window_before=30, window_after=0,
        description="Role label before name"
    ),
    HotwordRule(
        re.compile(r'\bname:?\s*$', re.I),
        confidence_delta=CONFIDENCE_BOOST_HIGH,
        window_before=20, window_after=0,
        description="Explicit name label"
    ),
    HotwordRule(
        re.compile(r'\b(signed|sincerely|regards|best)\s*,?\s*$', re.I),
        confidence_delta=CONFIDENCE_BOOST_LOW,
        window_before=30, window_after=0,
        description="Letter closing"
    ),
]

# Negative hotwords - decrease confidence (likely not a person name)
NAME_NEGATIVE_HOTWORDS: List[HotwordRule] = [
    HotwordRule(
        re.compile(r'^\s*(inc\.?|llc\.?|ltd\.?|corp\.?|co\.?|group|holdings)\b', re.I),
        confidence_delta=CONFIDENCE_PENALTY_HIGH,
        window_before=0, window_after=30,
        description="Company suffix after"
    ),
    HotwordRule(
        re.compile(r'^\s*(street|st\.?|avenue|ave\.?|road|rd\.?|drive|dr\.?|lane|ln\.?|blvd\.?)\b', re.I),
        confidence_delta=CONFIDENCE_PENALTY_HIGH,
        window_before=0, window_after=30,
        description="Street suffix after"
    ),
    HotwordRule(
        re.compile(r'\b(from|purchased|ordered|shipped|via)\s+$', re.I),
        confidence_delta=CONFIDENCE_PENALTY_LOW,
        window_before=30, window_after=0,
        description="Transaction context"
    ),
    HotwordRule(
        re.compile(r'\b(at|in|to|from|through)\s+$', re.I),
        confidence_delta=CONFIDENCE_PENALTY_MINIMAL,
        window_before=15, window_after=0,
        description="Location preposition"
    ),
    HotwordRule(
        re.compile(r'^\s*\'s\s+(site|website|page|app|service|product|store)\b', re.I),
        confidence_delta=CONFIDENCE_PENALTY_MEDIUM,
        window_before=0, window_after=40,
        description="Possessive + product"
    ),
]


# --- Pattern Exclusions (structural patterns indicating non-PII) ---

# Pattern: "X, Y and Z" or "X and Y" - likely a company/firm name
COMPANY_PATTERN = re.compile(
    r'^[A-Z][a-z]+(?:[-\s][A-Z][a-z]+)*'  # First name(s)
    r'(?:,\s*[A-Z][a-z]+(?:[-\s][A-Z][a-z]+)*)*'  # More comma-separated names
    r'\s+and\s+'  # "and"
    r'[A-Z][a-z]+(?:[-\s][A-Z][a-z]+)*'  # Final name(s)
    r'\.?$',  # Optional period
    re.UNICODE
)

# Pattern: Greeting + name (strip the greeting)
GREETING_PATTERN = re.compile(
    r'^(hi|hello|hey|dear|greetings)\s+',
    re.I
)

# Pattern: Contains HTML tags or entities
HTML_PATTERN = re.compile(r'<[^>]+>|&[a-z]+;|</?\w+', re.I)

# Pattern: Reference/document codes
REFERENCE_CODE_PATTERN = re.compile(r'^(REF|INV|DOC|ID|M|SVE)[-\s]?\d', re.I)

# Pattern: Contains digits (likely username or ID, not person name)
HAS_DIGITS_PATTERN = re.compile(r'\d')

# Pattern: All caps (likely acronym or label)
ALL_CAPS_PATTERN = re.compile(r'^[A-Z]{2,}$')

# Pattern: Trailing HTML or form artifacts
TRAILING_HTML_PATTERN = re.compile(r'<[^>]*>?\s*$|^\s*<[^>]*')

# Pattern: Possessive followed by product/service words
POSSESSIVE_PRODUCT_PATTERN = re.compile(
    r"'s\s+(site|website|page|app|service|product|store|account|system|platform)",
    re.I
)

# Pattern: Hyphenated company names like "Lewis-Osborne", "Walker-Kay"
# Two capitalized words joined by hyphen (common law firm / company naming pattern)
HYPHENATED_NAME_PATTERN = re.compile(
    r'^[A-Z][a-z]+(?:-[A-Z][a-z]+)+$',  # Word-Word or Word-Word-Word
    re.UNICODE
)

# Business context words that suggest a hyphenated name is a company, not a person
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



# --- Context Enhancer Class ---


@dataclass
class EnhancementResult:
    """Result of context enhancement for a span."""
    action: str  # "keep", "reject", "verify" (send to LLM)
    confidence: float
    reasons: List[str] = field(default_factory=list)


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
        low_confidence_threshold: float = LOW_CONFIDENCE_THRESHOLD,
        enable_deny_list: bool = True,
        enable_hotwords: bool = True,
        enable_patterns: bool = True,
    ):
        """
        Initialize the context enhancer.

        Args:
            high_confidence_threshold: Above this, keep without LLM
            low_confidence_threshold: Below this, reject without LLM
            enable_deny_list: Use deny list filtering
            enable_hotwords: Use hotword confidence adjustment
            enable_patterns: Use pattern-based exclusions
        """
        self.high_threshold = high_confidence_threshold
        self.low_threshold = low_confidence_threshold
        self.enable_deny_list = enable_deny_list
        self.enable_hotwords = enable_hotwords
        self.enable_patterns = enable_patterns

        # Entity types to apply enhancement to
        # SURGICAL: Only filter MRN for now (dollar amounts like 440060.24)
        # NAME/USERNAME filtering was causing unexpected recall drops
        self.enhanced_types = {"MRN"}

    def _get_context_window(
        self,
        text: str,
        span: Span,
        before: int,
        after: int
    ) -> Tuple[str, str]:
        """Get text before and after the span."""
        text_before = text[max(0, span.start - before):span.start]
        text_after = text[span.end:min(len(text), span.end + after)]
        return text_before, text_after

    def _check_deny_list(self, span: Span) -> Optional[str]:
        """Check if span text is in deny list. Returns reason if denied."""
        text_lower = span.text.lower().strip()
        span_text = span.text.strip()
        entity_type = span.entity_type.upper()

        # Also try without trailing punctuation
        text_normalized = text_lower.rstrip('.,;:!?')

        # Select appropriate deny list based on entity type
        if entity_type in ("NAME", "PERSON", "PER"):
            deny_list = NAME_DENY_LIST
        elif entity_type == "USERNAME":
            deny_list = USERNAME_DENY_LIST
        elif entity_type == "ADDRESS":
            deny_list = ADDRESS_DENY_LIST
        elif entity_type == "MEDICATION":
            deny_list = MEDICATION_DENY_LIST
        elif entity_type == "MRN":
            # MRN uses pattern-based exclusion, not deny list
            for pattern in MRN_EXCLUDE_PATTERNS:
                if pattern.search(span_text):
                    return f"mrn_exclude_pattern:{span_text[:30]}"
            return None
        else:
            deny_list = NAME_DENY_LIST  # Fallback

        if text_lower in deny_list:
            return f"deny_list:{text_lower}"

        if text_normalized in deny_list:
            return f"deny_list:{text_normalized}"

        # For NAME types, also check company suffixes
        if entity_type in ("NAME", "PERSON", "PER"):
            for suffix in COMPANY_SUFFIXES:
                if text_lower.endswith(suffix) or text_lower.endswith(f" {suffix}"):
                    return f"company_suffix:{suffix}"

        return None

    def _normalize_text(self, span_text: str) -> str:
        """Normalize span text by stripping artifacts."""
        # Strip trailing punctuation (but keep internal like O'Brien)
        text = span_text.rstrip('.,;:!?')
        # Strip leading/trailing whitespace
        text = text.strip()
        return text

    def _check_patterns(self, text: str, span: Span) -> Tuple[Optional[str], Optional[str], int]:
        """
        Check pattern-based exclusions.
        Returns (rejection_reason, cleaned_text, start_offset).
        - rejection_reason: why to reject, or None
        - cleaned_text: normalized text if greeting stripped, or None
        - start_offset: how many chars to move start forward (for greeting strip)
        """
        span_text = span.text
        start_offset = 0

        # Normalize first
        normalized = self._normalize_text(span_text)
        if normalized != span_text:
            span_text = normalized

        # Check for HTML content
        if HTML_PATTERN.search(span_text):
            return (f"html_content:{span_text[:30]}", None, 0)

        # Check for trailing HTML fragments
        if TRAILING_HTML_PATTERN.search(span_text):
            return (f"html_fragment:{span_text[:30]}", None, 0)

        # Check for reference codes (REF-123, INV-456, etc.)
        if REFERENCE_CODE_PATTERN.match(span_text):
            return (f"reference_code:{span_text}", None, 0)

        # Check for all caps (likely acronym/label, not name)
        if ALL_CAPS_PATTERN.match(span_text) and len(span_text) > 2:
            return (f"all_caps:{span_text}", None, 0)

        # Check for company pattern "X, Y and Z"
        if COMPANY_PATTERN.match(span_text):
            return (f"company_pattern:{span_text}", None, 0)

        # Check if name contains digits (likely username, not person name)
        # Exception: allow common patterns like "John Smith III" or "John Jr."
        if HAS_DIGITS_PATTERN.search(span_text):
            # Allow Roman numerals (II, III, IV, V, VI) at end
            if not re.search(r'\s+(II|III|IV|V|VI|Jr\.?|Sr\.?)$', span_text, re.I):
                return (f"contains_digits:{span_text}", None, 0)

        # Check for possessive + product pattern in full text context
        context_around = text[max(0, span.start):min(len(text), span.end + 50)]
        if POSSESSIVE_PRODUCT_PATTERN.search(context_around):
            return (f"possessive_product:{span_text}", None, 0)

        # Check for hyphenated company names like "Lewis-Osborne", "Walker-Kay"
        # These are common law firm/company naming patterns
        if HYPHENATED_NAME_PATTERN.match(span_text):
            # Check for business context in surrounding text (wider window)
            context_window = text[max(0, span.start - 100):min(len(text), span.end + 100)]
            if BUSINESS_CONTEXT_WORDS.search(context_window):
                return (f"hyphenated_company:{span_text}", None, 0)

        # Check for greeting pattern - strip it
        greeting_match = GREETING_PATTERN.match(span_text)
        if greeting_match:
            start_offset = greeting_match.end()
            cleaned = span_text[start_offset:].strip()
            # Also strip trailing comma/punctuation from cleaned
            cleaned = cleaned.rstrip('.,;:')
            if cleaned and len(cleaned) >= 2:
                return (None, cleaned, start_offset)
            else:
                return (f"greeting_only:{span_text}", None, 0)

        # If text was normalized (trailing punct stripped), return cleaned
        if normalized != span.text and len(normalized) >= 2:
            return (None, normalized, 0)

        return (None, None, 0)

    def _apply_hotwords(
        self,
        text: str,
        span: Span,
        current_confidence: float
    ) -> Tuple[float, List[str]]:
        """Apply hotword rules to adjust confidence."""
        confidence = current_confidence
        reasons = []

        entity_type = span.entity_type.upper()

        # Select hotword rules based on entity type
        if entity_type in ("NAME", "PERSON", "PER"):
            positive_rules = NAME_POSITIVE_HOTWORDS
            negative_rules = NAME_NEGATIVE_HOTWORDS
        else:
            # No hotwords for other types yet
            return confidence, reasons

        # Apply positive hotwords (look before entity)
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
        """
        Enhance a single span with context analysis.

        Returns an EnhancementResult with:
        - action: "keep" (high confidence), "reject" (low/denied), "verify" (send to LLM)
        - confidence: Adjusted confidence score
        - reasons: List of reasons for the decision
        """
        reasons = []
        confidence = span.confidence

        # Skip enhancement for non-target types
        if span.entity_type.upper() not in self.enhanced_types:
            return EnhancementResult("keep", confidence, ["non_enhanced_type"])

        # Stage 1: Deny list check - ALWAYS applied, even for high-tier spans
        # This catches common words like "ensure", "will", "may" that should
        # never be names regardless of how they were detected (including as
        # known entities from previous messages).
        if self.enable_deny_list:
            deny_reason = self._check_deny_list(span)
            if deny_reason:
                # Log when filtering a high-tier span - this indicates a
                # bad entry in the known entities store
                if span.tier >= Tier.STRUCTURED:
                    # Don't log actual PII values - log position and type only
                    logger.warning(
                        f"ContextEnhancer: Rejecting high-tier span {span.entity_type} "
                        f"at pos {span.start}-{span.end} (tier={span.tier.name}) via deny list - "
                        f"this may indicate a bad known entity"
                    )
                return EnhancementResult("reject", 0.0, [deny_reason])

        # Skip remaining enhancement for high-tier detections (checksum, structured)
        # These have already passed the deny list check above
        if span.tier >= Tier.STRUCTURED:
            return EnhancementResult("keep", confidence, ["high_tier"])

        # Stage 2: Pattern exclusions
        if self.enable_patterns:
            reject_reason, cleaned_text, start_offset = self._check_patterns(text, span)
            if reject_reason:
                return EnhancementResult("reject", 0.0, [reject_reason])
            if cleaned_text:
                # Update span text and positions (greeting stripped)
                span.start = span.start + start_offset
                span.text = cleaned_text
                span.end = span.start + len(cleaned_text)
                reasons.append(f"greeting_stripped:{cleaned_text}")

        # Stage 3: Hotword-based confidence adjustment
        if self.enable_hotwords:
            confidence, hotword_reasons = self._apply_hotwords(text, span, confidence)
            reasons.extend(hotword_reasons)

        # Stage 4: Route based on confidence
        if confidence >= self.high_threshold:
            return EnhancementResult("keep", confidence, reasons + ["high_confidence"])
        elif confidence <= self.low_threshold:
            return EnhancementResult("reject", confidence, reasons + ["low_confidence"])
        else:
            return EnhancementResult("verify", confidence, reasons + ["needs_llm"])

    def enhance(
        self,
        text: str,
        spans: List[Span],
        return_stats: bool = False
    ) -> List[Span]:
        """
        Enhance a list of spans with context analysis.

        Args:
            text: Original text
            spans: List of detected spans
            return_stats: If True, log statistics

        Returns:
            List of spans to keep (verified or high-confidence)
            Spans marked for LLM verification will have needs_review=True
        """
        if not spans:
            return spans

        kept = []
        rejected = 0
        needs_llm = 0
        passed_through = 0

        for span in spans:
            result = self.enhance_span(text, span)

            if result.action == "keep":
                span.confidence = result.confidence
                kept.append(span)
                passed_through += 1
                # Don't log actual PII values - log position and type only
                logger.debug(
                    f"ContextEnhancer: KEEP {span.entity_type} at pos {span.start}-{span.end} "
                    f"conf={result.confidence:.2f} reasons={result.reasons}"
                )
            elif result.action == "reject":
                rejected += 1
                # Don't log actual PII values - log position and type only
                logger.info(
                    f"ContextEnhancer: REJECT {span.entity_type} at pos {span.start}-{span.end} "
                    f"reasons={result.reasons}"
                )
            else:  # verify
                span.confidence = result.confidence
                span.needs_review = True
                span.review_reason = "llm_verification"
                kept.append(span)
                needs_llm += 1
                # Don't log actual PII values - log position and type only
                logger.debug(
                    f"ContextEnhancer: VERIFY {span.entity_type} at pos {span.start}-{span.end} "
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
