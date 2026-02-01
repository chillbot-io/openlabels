"""Native Rust-accelerated pattern detector.

Provides 6-8x speedup over pure Python pattern matching by using
Rust's regex crate. Releases the GIL during scanning, enabling
true parallelism with Python threads.

Falls back to pure Python if the Rust extension is not available.
"""

import logging
from typing import List

from ...types import Span, Tier
from .definitions import PATTERNS
from .false_positives import is_false_positive_name
from .validators import (
    validate_age,
    validate_date,
    validate_ip,
    validate_phone,
    validate_ssn_context,
    validate_vin,
)

logger = logging.getLogger(__name__)

# Try to import the Rust extension
try:
    from openlabels._rust import PatternMatcher, RawMatch, validate_luhn, is_native_available

    _NATIVE_AVAILABLE = is_native_available()
except ImportError as e:
    logger.debug(f"Rust extension not available: {e}")
    _NATIVE_AVAILABLE = False
    PatternMatcher = None
    RawMatch = None
    validate_luhn = None


class NativePatternDetector:
    """
    Pattern detector using Rust extension for 6-8x speedup.

    The Rust extension handles:
    - Pattern compilation (once, cached globally)
    - Pattern matching (releases GIL, enables true parallelism)
    - Basic validation (Luhn checksum)

    Python handles:
    - Complex validation (SSN context, name false positives)
    - Span creation and metadata
    """

    name = "pattern"
    tier = Tier.PATTERN

    _matcher: "PatternMatcher" = None
    _failed_patterns: List[tuple] = None

    def __init__(self):
        """Initialize the native pattern detector."""
        if not _NATIVE_AVAILABLE:
            raise ImportError("Rust extension not available")

        if NativePatternDetector._matcher is None:
            self._initialize_matcher()

    def is_available(self) -> bool:
        """Check if detector is ready to use."""
        return _NATIVE_AVAILABLE and self._matcher is not None

    @classmethod
    def _initialize_matcher(cls):
        """Initialize the Rust pattern matcher."""
        import regex

        # Convert PATTERNS to format Rust expects: (regex_str, entity_type, confidence, group_idx)
        patterns_for_rust = []
        cls._failed_patterns = []

        for i, (pattern, entity_type, confidence, group_idx) in enumerate(PATTERNS):
            # Prepend (?i) for case-insensitive patterns
            pattern_str = pattern.pattern
            if pattern.flags & regex.IGNORECASE:
                pattern_str = "(?i)" + pattern_str
            patterns_for_rust.append((pattern_str, entity_type, confidence, group_idx))

        # Create the matcher (compiles patterns in Rust)
        cls._matcher = PatternMatcher(patterns_for_rust)

        logger.info(
            f"Native pattern matcher initialized: "
            f"{cls._matcher.pattern_count} patterns compiled, "
            f"{cls._matcher.failed_count} use Python fallback"
        )

        # Track which patterns failed for Python fallback
        if cls._matcher.failed_count > 0:
            for i, (pattern, entity_type, confidence, group_idx) in enumerate(PATTERNS):
                if not cls._matcher.has_pattern(i):
                    cls._failed_patterns.append((pattern, entity_type, confidence, group_idx))

    def detect(self, text: str) -> List[Span]:
        """Detect entities using Rust-accelerated matching."""
        spans = []

        # Fast path: Rust does pattern matching (releases GIL)
        raw_matches: List[RawMatch] = self._matcher.find_matches(text)

        # For unicode text, we need to convert byte positions to char positions
        # Pre-compute byte-to-char mapping if text has non-ASCII characters
        text_bytes = text.encode("utf-8") if not text.isascii() else None

        # Process Rust matches with Python validation
        for match in raw_matches:
            if not self._validate(text, match):
                continue

            # Convert byte positions to character positions for unicode text
            if text_bytes is not None:
                start = len(text_bytes[:match.start].decode("utf-8"))
                end = len(text_bytes[:match.end].decode("utf-8"))
            else:
                start = match.start
                end = match.end

            spans.append(
                Span(
                    start=start,
                    end=end,
                    text=match.text,
                    entity_type=match.entity_type,
                    confidence=match.confidence,
                    detector=self.name,
                    tier=self.tier,
                )
            )

        # Run fallback patterns (those that failed Rust compilation)
        if self._failed_patterns:
            spans.extend(self._run_fallback_patterns(text))

        return spans

    def _validate(self, text: str, match: RawMatch) -> bool:
        """Run validation that requires Python logic."""
        et = match.entity_type
        value = match.text
        start = match.start

        if et == "IP_ADDRESS":
            return validate_ip(value)

        if et in ("PHONE", "PHONE_MOBILE", "PHONE_HOME", "PHONE_WORK", "FAX"):
            return validate_phone(value)

        if et in ("DATE", "DATE_DOB"):
            return self._validate_date_string(value)

        if et == "AGE":
            return validate_age(value)

        if et == "SSN":
            # Rust already validated format, Python checks context
            return validate_ssn_context(text, start, match.confidence)

        if et == "CREDIT_CARD":
            # Use Rust Luhn (faster than Python)
            return validate_luhn(value)

        if et == "VIN" and match.confidence < 0.90:
            return validate_vin(value)

        if et in ("NAME", "NAME_PROVIDER", "NAME_PATIENT", "NAME_RELATIVE"):
            return not is_false_positive_name(value)

        return True

    def _validate_date_string(self, value: str) -> bool:
        """Parse and validate a date string."""
        import re
        # Try to parse date components from common formats
        # MM/DD/YYYY, MM-DD-YYYY, YYYY/MM/DD, YYYY-MM-DD
        parts = re.split(r'[/\-.]', value)
        if len(parts) != 3:
            return True  # Can't validate, allow it

        try:
            nums = [int(p) for p in parts]
        except ValueError:
            return True  # Can't validate, allow it

        # Determine format based on component sizes
        if nums[0] > 31:  # YYYY-MM-DD format
            y, m, d = nums
        elif nums[2] > 31:  # MM-DD-YYYY format
            m, d, y = nums
        else:
            # Ambiguous, assume MM-DD-YY or MM-DD-YYYY
            m, d, y = nums
            if y < 100:
                y += 2000 if y < 50 else 1900

        return validate_date(m, d, y)

    def _run_fallback_patterns(self, text: str) -> List[Span]:
        """Run patterns that failed Rust compilation via Python regex."""
        spans = []

        for pattern, entity_type, confidence, group_idx in self._failed_patterns:
            for match in pattern.finditer(text):
                if group_idx > 0 and match.lastindex and group_idx <= match.lastindex:
                    value = match.group(group_idx)
                    start = match.start(group_idx)
                    end = match.end(group_idx)
                else:
                    value = match.group(0)
                    start = match.start()
                    end = match.end()

                if not value or not value.strip():
                    continue

                # Apply same validation as Rust path
                if entity_type == "IP_ADDRESS" and not validate_ip(value):
                    continue
                if entity_type in ("PHONE", "PHONE_MOBILE", "PHONE_HOME", "PHONE_WORK", "FAX"):
                    if not validate_phone(value):
                        continue
                if entity_type in ("DATE", "DATE_DOB"):
                    if not self._validate_date_string(value):
                        continue
                if entity_type == "AGE" and not validate_age(value):
                    continue
                if entity_type == "SSN" and not validate_ssn_context(text, start, confidence):
                    continue
                if entity_type == "CREDIT_CARD" and not validate_luhn(value):
                    continue
                if entity_type == "VIN" and confidence < 0.90:
                    if not validate_vin(value):
                        continue
                if entity_type in ("NAME", "NAME_PROVIDER", "NAME_PATIENT", "NAME_RELATIVE"):
                    if is_false_positive_name(value):
                        continue

                spans.append(
                    Span(
                        start=start,
                        end=end,
                        text=value,
                        entity_type=entity_type,
                        confidence=confidence,
                        detector=self.name,
                        tier=self.tier,
                    )
                )

        return spans


def is_native_detector_available() -> bool:
    """Check if the native detector can be used."""
    return _NATIVE_AVAILABLE
