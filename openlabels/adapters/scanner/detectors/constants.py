"""Confidence level constants for PII/PHI detection.

These constants provide semantic meaning to confidence scores used throughout
the detector modules, replacing magic numbers with descriptive names.

Confidence Score Guide:
- 0.99 (PERFECT): Cryptographically verifiable or unique prefixes
- 0.98 (VERY_HIGH): Distinctive format with minimal false positive risk
- 0.95-0.96 (HIGH): Well-structured patterns with strong indicators
- 0.90-0.94 (MEDIUM): Standard patterns with reasonable confidence
- 0.85-0.88 (LOW): Default threshold level, context-dependent
- 0.70-0.82 (MINIMAL): Higher false positive risk, needs context
- 0.65-0.68 (SPECULATIVE): Near-threshold, high ambiguity
"""

# --- Primary Confidence Levels ---

# Top tier - cryptographic/format-based certainty
CONFIDENCE_PERFECT = 0.99      # Unique prefixes (AWS keys, GitHub tokens)
CONFIDENCE_VERY_HIGH = 0.98    # Distinctive formats, classification markings

# High tier - reliable detection
CONFIDENCE_NEAR_CERTAIN = 0.96 # Very strong patterns
CONFIDENCE_HIGH = 0.95         # Well-structured patterns
CONFIDENCE_HIGH_MEDIUM = 0.94  # Strong patterns with minor variation

# Medium tier - standard detection
CONFIDENCE_RELIABLE = 0.92     # Good patterns, some context needed
CONFIDENCE_MEDIUM = 0.90       # Standard patterns
CONFIDENCE_MEDIUM_LOW = 0.88   # Patterns with context requirements

# Low tier - threshold level
CONFIDENCE_LOW = 0.85          # Default detection threshold
CONFIDENCE_MARGINAL = 0.82     # Moderate false positive risk
CONFIDENCE_WEAK = 0.80         # Higher false positive risk
CONFIDENCE_BORDERLINE = 0.78   # Context-dependent

# Minimal tier - high false positive risk
CONFIDENCE_MINIMAL = 0.75      # Significant false positive risk
CONFIDENCE_VERY_LOW = 0.72     # High ambiguity
CONFIDENCE_LOWEST = 0.70       # Maximum acceptable ambiguity
CONFIDENCE_SPECULATIVE = 0.68  # Highly speculative
CONFIDENCE_TENTATIVE = 0.65    # Nearly unacceptable ambiguity


# --- Confidence Adjustments ---

# Positive boosts (when context increases confidence)
CONFIDENCE_BOOST_HIGH = 0.30
CONFIDENCE_BOOST_MEDIUM = 0.25
CONFIDENCE_BOOST_LOW = 0.20
CONFIDENCE_BOOST_MINIMAL = 0.15

# Negative penalties (when context decreases confidence)
CONFIDENCE_PENALTY_HIGH = -0.35
CONFIDENCE_PENALTY_MEDIUM = -0.30
CONFIDENCE_PENALTY_LOW = -0.20
CONFIDENCE_PENALTY_MINIMAL = -0.15



# --- Thresholds ---


# Below this threshold, matches are considered too unreliable
LOW_CONFIDENCE_THRESHOLD = 0.35

# Minimum confidence floor (used for small adjustments)
CONFIDENCE_FLOOR = 0.02


# --- Special Values ---

# Luhn-invalid credit card (typo detection)
CONFIDENCE_LUHN_INVALID = 0.87

# Checksum-aware adjustments
CONFIDENCE_CHECKSUM_PASS = 0.99
CONFIDENCE_CHECKSUM_FAIL_AREA = 0.85
CONFIDENCE_CHECKSUM_FAIL_MINOR = 0.80
