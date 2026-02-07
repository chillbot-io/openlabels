"""
Hyperscan-accelerated detector for high-performance pattern matching.

This detector wraps the HyperscanMatcher to provide 10-100x faster regex
matching compared to standard Python re module. When Hyperscan is not
available, it automatically falls back to Python regex.

Usage:
    detector = HyperscanDetector()
    spans = detector.detect("My SSN is 123-45-6789")

Performance (typical on modern CPU):
    - Python re: ~10 MB/s
    - Hyperscan: ~1-10 GB/s
"""

import logging
from collections.abc import Sequence

from ..types import Span, Tier
from .base import BaseDetector
from ..agents.hyperscan_matcher import (
    HyperscanMatcher,
    HYPERSCAN_AVAILABLE,
    PII_PATTERNS,
    Pattern,
    PatternFlags,
)

logger = logging.getLogger(__name__)


class HyperscanDetector(BaseDetector):
    """
    High-performance detector using Intel Hyperscan for SIMD-accelerated regex.

    This detector can replace multiple pattern-based detectors (patterns.py,
    secrets.py, etc.) with a single pass through the text using Hyperscan's
    multi-pattern matching capability.

    Falls back to Python regex if Hyperscan is not installed.
    """

    name = "hyperscan"
    tier = Tier.PATTERN  # Same tier as pattern-based detectors

    def __init__(
        self,
        patterns: Sequence[Pattern] | None = None,
        additional_patterns: Sequence[Pattern] | None = None,
    ):
        """
        Initialize the Hyperscan detector.

        Args:
            patterns: Custom patterns to use (defaults to PII_PATTERNS)
            additional_patterns: Additional patterns to append to default set
        """
        # Start with provided patterns or default PII patterns
        all_patterns = list(patterns) if patterns else list(PII_PATTERNS)

        # Add any additional patterns
        if additional_patterns:
            # Ensure unique IDs for additional patterns
            max_id = max(p.id for p in all_patterns) if all_patterns else 0
            for i, p in enumerate(additional_patterns):
                if p.id <= max_id:
                    # Create new pattern with unique ID
                    all_patterns.append(Pattern(
                        id=max_id + i + 1,
                        name=p.name,
                        entity_type=p.entity_type,
                        regex=p.regex,
                        flags=p.flags,
                        confidence=p.confidence,
                        validator=p.validator,
                    ))
                else:
                    all_patterns.append(p)

        self._matcher = HyperscanMatcher(patterns=all_patterns, use_fallback=True)
        self._using_hyperscan = self._matcher.using_hyperscan

        if self._using_hyperscan:
            logger.info(
                f"HyperscanDetector initialized with {self._matcher.pattern_count} patterns "
                f"(SIMD-accelerated)"
            )
        else:
            logger.info(
                f"HyperscanDetector initialized with {self._matcher.pattern_count} patterns "
                f"(Python regex fallback)"
            )

    def detect(self, text: str) -> list[Span]:
        """
        Detect entities in text using Hyperscan.

        Args:
            text: Text to scan for entities

        Returns:
            List of Span objects for detected entities
        """
        if not text or not text.strip():
            return []

        matches = self._matcher.scan(text)

        spans = []
        for match in matches:
            spans.append(Span(
                start=match.start,
                end=match.end,
                text=match.matched_text,
                entity_type=match.entity_type,
                confidence=match.confidence,
                detector=self.name,
                tier=self.tier,
            ))

        return spans

    def is_available(self) -> bool:
        """Check if detector is ready (always True due to fallback)."""
        return self._matcher._compiled

    @property
    def using_hyperscan(self) -> bool:
        """Whether Hyperscan acceleration is being used."""
        return self._using_hyperscan

    @property
    def pattern_count(self) -> int:
        """Number of patterns loaded."""
        return self._matcher.pattern_count


def is_hyperscan_available() -> bool:
    """Check if Hyperscan library is installed and available."""
    return HYPERSCAN_AVAILABLE


# Additional patterns to supplement the built-in PII_PATTERNS
# These can be imported and added to the detector
SUPPLEMENTAL_PATTERNS: tuple[Pattern, ...] = (
    # VIN (Vehicle Identification Number)
    Pattern(
        id=100,
        name="vin",
        entity_type="VIN",
        regex=r"\b[A-HJ-NPR-Z0-9]{17}\b",
        confidence=0.7,
    ),
    # US Zip Codes
    Pattern(
        id=101,
        name="us_zip",
        entity_type="ZIP_CODE",
        regex=r"\b\d{5}(?:-\d{4})?\b",
        confidence=0.6,
    ),
    # UK Postcodes
    Pattern(
        id=102,
        name="uk_postcode",
        entity_type="POSTCODE",
        regex=r"\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b",
        flags=PatternFlags.CASELESS,
        confidence=0.8,
    ),
    # Generic UUID
    Pattern(
        id=103,
        name="uuid",
        entity_type="UUID",
        regex=r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        flags=PatternFlags.CASELESS,
        confidence=0.95,
    ),
    # JWT Token
    Pattern(
        id=104,
        name="jwt_token",
        entity_type="JWT",
        regex=r"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b",
        confidence=0.95,
    ),
    # Private Key Header
    Pattern(
        id=105,
        name="private_key",
        entity_type="PRIVATE_KEY",
        regex=r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
        confidence=0.99,
    ),
    # Slack Token
    Pattern(
        id=106,
        name="slack_token",
        entity_type="SLACK_TOKEN",
        regex=r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b",
        confidence=0.99,
    ),
    # Stripe API Key
    Pattern(
        id=107,
        name="stripe_key",
        entity_type="STRIPE_KEY",
        regex=r"\b[sr]k_live_[0-9a-zA-Z]{24}\b",
        confidence=0.99,
    ),
)
