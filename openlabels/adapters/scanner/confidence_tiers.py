"""Confidence tier constants for detector patterns.

This module defines standardized confidence levels for entity detection,
replacing magic numbers throughout the codebase with semantic constants.

Confidence tiers represent the likelihood that a detected pattern
is a true positive:

- VERY_HIGH (0.98): Near-certain matches with distinctive formats
  Examples: AWS keys (AKIA prefix), checksummed IDs (Luhn-validated credit cards)

- HIGH (0.90): Strong matches with clear patterns or context
  Examples: Labeled fields ("Patient: John Smith"), validated formats

- MEDIUM (0.85): Reasonable matches that may need context verification
  Examples: Unlabeled patterns, format-only matches without validation

- LOW (0.70): Possible matches that benefit from additional context
  Examples: Generic date formats, short patterns

- MINIMAL (0.60): Weak matches, high false positive potential
  Examples: Single names without context, ambiguous numbers

Usage:
    from ..confidence_tiers import Confidence

    # In pattern definitions:
    _add(r'\\b(AKIA[A-Z0-9]{16})\\b', 'AWS_ACCESS_KEY', Confidence.VERY_HIGH, 1)
    _add(r'\\b(\\d{3})[-.]?(\\d{3})[-.]?(\\d{4})\\b', 'PHONE', Confidence.MEDIUM)
"""

from enum import Enum
from typing import Dict


class Confidence:
    """Confidence tier constants for pattern matching.

    These replace hardcoded floats (0.98, 0.90, etc.) with semantic names
    that indicate the expected precision of pattern matches.
    """

    # === TIER DEFINITIONS ===

    # Near-certain: Distinctive prefixes, checksums, or unique formats
    # Use for: AWS AKIA prefix, validated checksums, PEM headers
    VERY_HIGH: float = 0.98

    # Strong: Clear patterns with good specificity
    # Use for: Labeled fields, contextual matches, format + length validation
    HIGH: float = 0.92

    # Good: Reasonable patterns that could have false positives
    # Use for: Unlabeled format matches, patterns without checksum
    MEDIUM_HIGH: float = 0.88

    # Moderate: May need context verification
    # Use for: Generic formats, partial patterns
    MEDIUM: float = 0.85

    # Lower: Potential false positives expected
    # Use for: Date formats, short patterns, ambiguous matches
    LOW: float = 0.75

    # Weak: High false positive potential
    # Use for: Single words without context, very generic patterns
    MINIMAL: float = 0.65

    # === ADJUSTMENT FACTORS ===

    # Apply when pattern has explicit label/context
    LABELED_BOOST: float = 0.05

    # Apply when pattern lacks contextual indicators
    UNLABELED_PENALTY: float = -0.05

    # Apply for test/development credentials (lower priority)
    TEST_CREDENTIAL_PENALTY: float = -0.08


# === DETECTOR-SPECIFIC CONFIDENCE FLOORS ===
# These ensure minimum confidence levels for certain detection methods

DETECTOR_CONFIDENCE_FLOORS: Dict[str, float] = {
    # Checksum-validated patterns (SSN, CC, IBAN) are very reliable
    "checksum": 0.92,

    # Structured extraction from labeled fields is reliable
    "structured": 0.90,

    # Known entities from previous context are highly reliable
    "known_entity": 0.95,

    # Pattern-only detection may have false positives
    "patterns": 0.70,

    # Dictionary matches depend on dictionary quality
    "dictionaries": 0.75,

    # ML/NER models vary by entity type
    "ml": 0.65,
}


# === CONFIDENCE THRESHOLDS FOR FILTERING ===

# Minimum confidence to include in results
DEFAULT_MIN_CONFIDENCE: float = 0.60

# Confidence above which context enhancement skips verification
SKIP_VERIFICATION_THRESHOLD: float = 0.95

# Confidence below which LLM verification is recommended
LLM_VERIFICATION_THRESHOLD: float = 0.80
