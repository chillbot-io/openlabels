"""
Intel Hyperscan-based pattern matcher for high-performance regex matching.

Hyperscan is a SIMD-accelerated regex library that can match thousands of
patterns simultaneously. This is ideal for PII/sensitive data detection
where we need to match many patterns (SSN, credit cards, etc.) in a single pass.

Performance comparison (typical):
- Python re: ~10 MB/s
- Python regex: ~50 MB/s
- Hyperscan: ~1-10 GB/s (100-1000x faster)

References:
- https://github.com/intel/hyperscan
- https://intel.github.io/hyperscan/dev-reference/
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntFlag
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# Check Hyperscan availability
try:
    import hyperscan
    HYPERSCAN_AVAILABLE = True
    logger.info("Intel Hyperscan available - using SIMD-accelerated regex")
except ImportError:
    HYPERSCAN_AVAILABLE = False
    logger.debug("Hyperscan not installed, falling back to standard regex")


class PatternFlags(IntFlag):
    """Hyperscan pattern flags."""

    CASELESS = 1        # Case-insensitive matching
    DOTALL = 2          # . matches newlines
    MULTILINE = 4       # ^ and $ match line boundaries
    SINGLEMATCH = 8     # Report only first match per pattern
    # Note: SOM_LEFTMOST (256) requires streaming mode in Hyperscan
    # We use re-matching in block mode to find match start positions


@dataclass
class PatternMatch:
    """A match found by Hyperscan."""

    pattern_id: int
    pattern_name: str
    entity_type: str
    start: int
    end: int
    matched_text: str
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)


@dataclass
class Pattern:
    """A pattern to be compiled into Hyperscan database."""

    id: int
    name: str
    entity_type: str
    regex: str
    flags: PatternFlags = PatternFlags.CASELESS
    confidence: float = 1.0
    validator: Optional[Callable[[str], bool]] = None  # Post-match validation (e.g., Luhn check)


# ============================================================================
# PII/Sensitive Data Patterns
# ============================================================================

# These patterns are designed for Hyperscan's regex dialect
# Note: Hyperscan uses PCRE-like syntax but with some restrictions

PII_PATTERNS: list[Pattern] = [
    # === US Identification Numbers ===
    Pattern(
        id=1,
        name="us_ssn",
        entity_type="SSN",
        regex=r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b",
        confidence=0.95,
    ),
    Pattern(
        id=2,
        name="us_ssn_no_dashes",
        entity_type="SSN",
        regex=r"\b(?!000|666|9\d{2})\d{9}\b",
        confidence=0.7,  # Lower confidence without dashes
    ),
    Pattern(
        id=3,
        name="us_itin",
        entity_type="ITIN",
        regex=r"\b9\d{2}[-\s]?[78]\d[-\s]?\d{4}\b",
        confidence=0.9,
    ),
    Pattern(
        id=4,
        name="us_ein",
        entity_type="EIN",
        regex=r"\b\d{2}[-\s]?\d{7}\b",
        confidence=0.6,  # Common format, needs context
    ),

    # === Financial ===
    Pattern(
        id=10,
        name="credit_card_visa",
        entity_type="CREDIT_CARD",
        regex=r"\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        confidence=0.95,
    ),
    Pattern(
        id=11,
        name="credit_card_mastercard",
        entity_type="CREDIT_CARD",
        regex=r"\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        confidence=0.95,
    ),
    Pattern(
        id=12,
        name="credit_card_amex",
        entity_type="CREDIT_CARD",
        regex=r"\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b",
        confidence=0.95,
    ),
    Pattern(
        id=13,
        name="credit_card_discover",
        entity_type="CREDIT_CARD",
        regex=r"\b6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        confidence=0.95,
    ),
    Pattern(
        id=14,
        name="bank_routing",
        entity_type="BANK_ROUTING",
        regex=r"\b(?:0[1-9]|[1-2]\d|3[0-2])\d{7}\b",
        confidence=0.6,
    ),
    Pattern(
        id=15,
        name="iban",
        entity_type="IBAN",
        regex=r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?\d{0,16})?\b",
        confidence=0.9,
    ),

    # === Contact Information ===
    Pattern(
        id=20,
        name="email",
        entity_type="EMAIL",
        regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        confidence=0.95,
    ),
    Pattern(
        id=21,
        name="us_phone",
        entity_type="PHONE",
        regex=r"\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
        confidence=0.8,
    ),
    Pattern(
        id=22,
        name="intl_phone",
        entity_type="PHONE",
        regex=r"\b\+\d{1,3}[-.\s]?\d{1,14}(?:[-.\s]?\d{1,13})?\b",
        confidence=0.85,
    ),

    # === Healthcare ===
    Pattern(
        id=30,
        name="us_npi",
        entity_type="NPI",
        regex=r"\b[12]\d{9}\b",
        confidence=0.7,
    ),
    Pattern(
        id=31,
        name="us_dea",
        entity_type="DEA_NUMBER",
        regex=r"\b[ABCDEFGHJKLMNPRSTUXabcdefghjklmnprstux][A-Za-z9]\d{7}\b",
        confidence=0.9,
    ),
    Pattern(
        id=32,
        name="medical_record_mrn",
        entity_type="MRN",
        regex=r"\b(?:MRN|MR#|Med\s*Rec)[-:\s#]*\d{6,12}\b",
        flags=PatternFlags.CASELESS,
        confidence=0.95,
    ),

    # === Government IDs (International) ===
    Pattern(
        id=40,
        name="uk_nino",
        entity_type="UK_NINO",
        regex=r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b",
        confidence=0.9,
    ),
    Pattern(
        id=41,
        name="uk_nhs",
        entity_type="UK_NHS",
        regex=r"\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b",
        confidence=0.7,
    ),
    Pattern(
        id=42,
        name="ca_sin",
        entity_type="CA_SIN",
        regex=r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b",
        confidence=0.7,
    ),
    Pattern(
        id=43,
        name="de_personalausweis",
        entity_type="DE_ID",
        regex=r"\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b",
        confidence=0.6,
    ),
    Pattern(
        id=44,
        name="passport_generic",
        entity_type="PASSPORT",
        regex=r"\b[A-Z]{1,2}\d{6,9}\b",
        confidence=0.5,
    ),

    # === Drivers Licenses (US) ===
    Pattern(
        id=50,
        name="dl_california",
        entity_type="DRIVERS_LICENSE",
        regex=r"\b[A-Z]\d{7}\b",
        confidence=0.6,
    ),
    Pattern(
        id=51,
        name="dl_new_york",
        entity_type="DRIVERS_LICENSE",
        regex=r"\b\d{9}\b",
        confidence=0.4,  # Very generic
    ),
    Pattern(
        id=52,
        name="dl_texas",
        entity_type="DRIVERS_LICENSE",
        regex=r"\b\d{8}\b",
        confidence=0.4,
    ),

    # === Network/Technical ===
    Pattern(
        id=60,
        name="ipv4",
        entity_type="IP_ADDRESS",
        regex=r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        confidence=0.95,
    ),
    Pattern(
        id=61,
        name="mac_address",
        entity_type="MAC_ADDRESS",
        regex=r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
        confidence=0.95,
    ),

    # === Credentials ===
    Pattern(
        id=70,
        name="aws_access_key",
        entity_type="AWS_KEY",
        regex=r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
        confidence=0.99,
    ),
    Pattern(
        id=71,
        name="aws_secret_key",
        entity_type="AWS_SECRET",
        regex=r"\b[A-Za-z0-9/+=]{40}\b",
        confidence=0.5,  # Too generic alone
    ),
    Pattern(
        id=72,
        name="github_token",
        entity_type="GITHUB_TOKEN",
        regex=r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b",
        confidence=0.99,
    ),
    Pattern(
        id=73,
        name="generic_api_key",
        entity_type="API_KEY",
        regex=r"\b(?:api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,64})['\"]?",
        flags=PatternFlags.CASELESS,
        confidence=0.8,
    ),

    # === Dates (for context, often combined with names for PII) ===
    Pattern(
        id=80,
        name="date_us",
        entity_type="DATE",
        regex=r"\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b",
        confidence=0.7,
    ),
    Pattern(
        id=81,
        name="date_iso",
        entity_type="DATE",
        regex=r"\b(?:19|20)\d{2}[-/](?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12]\d|3[01])\b",
        confidence=0.8,
    ),
    Pattern(
        id=82,
        name="date_of_birth_label",
        entity_type="DOB",
        regex=r"\b(?:DOB|D\.O\.B\.|Date\s+of\s+Birth|Birth\s*date)[-:\s]*(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b",
        flags=PatternFlags.CASELESS,
        confidence=0.95,
    ),
]


# ============================================================================
# Validators (Luhn, checksum verification, etc.)
# ============================================================================

def luhn_check(number: str) -> bool:
    """Validate a number using the Luhn algorithm (credit cards, etc.)."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 2:
        return False

    # Double every second digit from the right
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9

    return sum(digits) % 10 == 0


def ssn_validate(ssn: str) -> bool:
    """Validate SSN format and known invalid patterns."""
    digits = ''.join(c for c in ssn if c.isdigit())
    if len(digits) != 9:
        return False

    # Invalid patterns
    area = int(digits[:3])
    group = int(digits[3:5])
    serial = int(digits[5:])

    # Area number cannot be 000, 666, or 900-999
    if area == 0 or area == 666 or area >= 900:
        return False

    # Group and serial cannot be 00 or 0000
    if group == 0 or serial == 0:
        return False

    # Known invalid SSNs (advertising, etc.)
    known_invalid = {
        '078051120',  # Woolworth wallet
        '219099999',  # Advertising
        '457555462',  # Life Lock CEO
    }
    if digits in known_invalid:
        return False

    return True


# Map pattern names to validators
VALIDATORS: dict[str, Callable[[str], bool]] = {
    "credit_card_visa": luhn_check,
    "credit_card_mastercard": luhn_check,
    "credit_card_amex": luhn_check,
    "credit_card_discover": luhn_check,
    "us_ssn": ssn_validate,
    "us_ssn_no_dashes": ssn_validate,
}


# ============================================================================
# Hyperscan Matcher
# ============================================================================

class HyperscanMatcher:
    """
    High-performance pattern matcher using Intel Hyperscan.

    Compiles all patterns into a single database for simultaneous matching.
    Falls back to Python regex if Hyperscan is not available.
    """

    def __init__(
        self,
        patterns: Optional[list[Pattern]] = None,
        use_fallback: bool = True,
    ):
        self.patterns = patterns or PII_PATTERNS
        self._pattern_map = {p.id: p for p in self.patterns}
        self._use_fallback = use_fallback
        self._db: Optional[hyperscan.Database] = None
        self._scratch: Optional[hyperscan.Scratch] = None
        self._compiled = False

        if HYPERSCAN_AVAILABLE:
            self._compile_hyperscan()
        elif use_fallback:
            self._compile_fallback()
        else:
            raise RuntimeError("Hyperscan not available and fallback disabled")

    def _compile_hyperscan(self) -> None:
        """Compile patterns into Hyperscan database."""
        import re as re_module

        expressions = []
        flags = []
        ids = []

        # Also compile Python regex patterns for extracting match text
        # (Hyperscan in block mode only reports end positions)
        self._python_patterns: dict[int, re_module.Pattern] = {}

        for pattern in self.patterns:
            expressions.append(pattern.regex.encode('utf-8'))
            flags.append(int(pattern.flags))
            ids.append(pattern.id)

            # Compile Python regex for match extraction
            re_flags = 0
            if pattern.flags & PatternFlags.CASELESS:
                re_flags |= re_module.IGNORECASE
            if pattern.flags & PatternFlags.DOTALL:
                re_flags |= re_module.DOTALL
            if pattern.flags & PatternFlags.MULTILINE:
                re_flags |= re_module.MULTILINE
            try:
                self._python_patterns[pattern.id] = re_module.compile(pattern.regex, re_flags)
            except re_module.error as e:
                logger.warning(f"Failed to compile Python regex for {pattern.name}: {e}")

        try:
            # Use SOM_HORIZON_LARGE mode to support SOM_LEFTMOST flag on patterns
            # This allows Hyperscan to report start-of-match positions
            mode = hyperscan.HS_MODE_BLOCK | hyperscan.HS_MODE_SOM_HORIZON_LARGE
            import sys
            print(f"DEBUG: Hyperscan mode = {mode} (BLOCK={hyperscan.HS_MODE_BLOCK}, SOM_LARGE={hyperscan.HS_MODE_SOM_HORIZON_LARGE})", file=sys.stderr)
            self._db = hyperscan.Database(mode=mode)
            self._db.compile(
                expressions=expressions,
                flags=flags,
                ids=ids,
            )
            print(f"DEBUG: Compiled {len(expressions)} patterns successfully", file=sys.stderr)
            self._scratch = hyperscan.Scratch(self._db)
            self._compiled = True
            logger.info(f"Compiled {len(self.patterns)} patterns into Hyperscan database")
        except Exception as e:
            import sys
            print(f"DEBUG: Compile error: {e}", file=sys.stderr)
            logger.error(f"Failed to compile Hyperscan database: {e}")
            # Clear the database so we use fallback instead
            self._db = None
            self._scratch = None
            if self._use_fallback:
                self._compile_fallback()
            else:
                raise

    def _compile_fallback(self) -> None:
        """Compile patterns using standard Python regex."""
        import re as re_module

        self._fallback_patterns: dict[int, re_module.Pattern] = {}

        for pattern in self.patterns:
            try:
                re_flags = 0
                if pattern.flags & PatternFlags.CASELESS:
                    re_flags |= re_module.IGNORECASE
                if pattern.flags & PatternFlags.DOTALL:
                    re_flags |= re_module.DOTALL
                if pattern.flags & PatternFlags.MULTILINE:
                    re_flags |= re_module.MULTILINE

                self._fallback_patterns[pattern.id] = re_module.compile(
                    pattern.regex, re_flags
                )
            except re_module.error as e:
                logger.warning(f"Failed to compile pattern {pattern.name}: {e}")

        self._compiled = True
        logger.info(f"Compiled {len(self._fallback_patterns)} patterns using Python regex (fallback)")

    def scan(self, text: str) -> list[PatternMatch]:
        """
        Scan text for all patterns.

        Returns list of matches with positions and pattern info.
        """
        if not self._compiled:
            raise RuntimeError("Matcher not compiled")

        if HYPERSCAN_AVAILABLE and self._db:
            return self._scan_hyperscan(text)
        else:
            return self._scan_fallback(text)

    def _scan_hyperscan(self, text: str) -> list[PatternMatch]:
        """Scan using Hyperscan."""
        matches: list[PatternMatch] = []
        seen_matches: set[tuple[int, int, int]] = set()  # (pattern_id, start, end)
        text_bytes = text.encode('utf-8')
        callback_count = [0]  # Use list to allow mutation in nested function

        # Callback for each match - Hyperscan reports match end position in block mode
        def on_match(id: int, start: int, end: int, flags: int, context: None) -> Optional[bool]:
            callback_count[0] += 1
            pattern = self._pattern_map.get(id)
            if not pattern:
                logger.debug(f"on_match: Unknown pattern id {id}")
                return None

            # Convert byte end offset to character offset
            char_end = len(text_bytes[:end].decode('utf-8', errors='replace'))

            # Use Python regex to find the actual match ending at this position
            # Search backwards from end to find where the match started
            python_pattern = self._python_patterns.get(id)
            if not python_pattern:
                return None

            # Search in the text up to the end position for the pattern
            # Look at a reasonable window before the end position
            search_start = max(0, char_end - 200)  # Look back up to 200 chars
            search_text = text[search_start:char_end]

            # Find all matches in this window and get the one that ends at char_end
            matched_text = None
            actual_start = None
            actual_end = None

            for m in python_pattern.finditer(search_text):
                match_end_in_text = search_start + m.end()
                if match_end_in_text == char_end:
                    matched_text = m.group()
                    actual_start = search_start + m.start()
                    actual_end = char_end
                    break

            if not matched_text:
                return None

            # Deduplicate matches (same pattern at same position)
            match_key = (id, actual_start, actual_end)
            if match_key in seen_matches:
                return None
            seen_matches.add(match_key)

            logger.debug(f"on_match: id={id}, start={start}, end={end}, matched='{matched_text}'")

            # Run validator if defined
            validator = VALIDATORS.get(pattern.name)
            if validator and not validator(matched_text):
                logger.debug(f"on_match: Validator failed for {pattern.name}")
                return None  # Failed validation, skip

            matches.append(PatternMatch(
                pattern_id=pattern.id,
                pattern_name=pattern.name,
                entity_type=pattern.entity_type,
                start=actual_start,
                end=actual_end,
                matched_text=matched_text,
                confidence=pattern.confidence,
            ))

            return None  # Continue scanning

        try:
            self._db.scan(text_bytes, match_event_handler=on_match, scratch=self._scratch)
            if callback_count[0] == 0:
                # Debug: no callbacks at all - this helps diagnose scanning issues
                import sys
                print(f"DEBUG: Hyperscan scan returned 0 callbacks for text len={len(text)}", file=sys.stderr)
        except Exception as e:
            logger.error(f"Hyperscan scan error: {e}")
            import sys
            print(f"DEBUG: Hyperscan scan exception: {e}", file=sys.stderr)

        return matches

    def _scan_fallback(self, text: str) -> list[PatternMatch]:
        """Scan using Python regex (fallback)."""
        matches: list[PatternMatch] = []

        for pattern_id, compiled in self._fallback_patterns.items():
            pattern = self._pattern_map.get(pattern_id)
            if not pattern:
                continue

            for match in compiled.finditer(text):
                matched_text = match.group()

                # Run validator if defined
                validator = VALIDATORS.get(pattern.name)
                if validator and not validator(matched_text):
                    continue  # Failed validation, skip

                matches.append(PatternMatch(
                    pattern_id=pattern.id,
                    pattern_name=pattern.name,
                    entity_type=pattern.entity_type,
                    start=match.start(),
                    end=match.end(),
                    matched_text=matched_text,
                    confidence=pattern.confidence,
                ))

        return matches

    def scan_batch(self, texts: list[str]) -> list[list[PatternMatch]]:
        """Scan multiple texts efficiently."""
        return [self.scan(text) for text in texts]

    @property
    def pattern_count(self) -> int:
        return len(self.patterns)

    @property
    def using_hyperscan(self) -> bool:
        return HYPERSCAN_AVAILABLE and self._db is not None


# ============================================================================
# Global singleton for efficient reuse
# ============================================================================

_matcher_instance: Optional[HyperscanMatcher] = None


def get_matcher() -> HyperscanMatcher:
    """Get or create the global Hyperscan matcher instance."""
    global _matcher_instance
    if _matcher_instance is None:
        _matcher_instance = HyperscanMatcher()
    return _matcher_instance


def scan_text(text: str) -> list[PatternMatch]:
    """Convenience function to scan text using global matcher."""
    return get_matcher().scan(text)
