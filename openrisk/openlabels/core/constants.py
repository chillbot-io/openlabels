"""
OpenLabels Core Constants.

Centralized constants used across the OpenLabels system.
These were previously magic numbers scattered throughout the codebase.

Usage:
    from openlabels.core.constants import (
        DEFAULT_CONFIDENCE_THRESHOLD,
        CONFIDENCE_WHEN_NO_SPANS,
    )
"""


# --- Confidence Thresholds ---
# Previously hardcoded as 0.90 in multiple places

DEFAULT_CONFIDENCE_THRESHOLD = 0.90
"""
Default confidence threshold used when scoring entities.

This value is used as the default confidence parameter in scoring functions.
It represents a reasonable balance between precision and recall for
entity detection scoring.

Used in:
- core/scorer.py: score() and calculate_content_score()
- components/scorer.py: Scorer._calculate_average_confidence()
"""

CONFIDENCE_WHEN_NO_SPANS = 0.90
"""
Confidence value assigned when no detection spans are available.

When a detection has no span information (e.g., from an external DLP
service that doesn't provide positions), this default confidence is
used instead of failing or returning 0.

This choice is documented here rather than buried in code to make the
assumption explicit and reviewable.
"""



# --- Scoring Constants ---


MIN_CONFIDENCE = 0.0
"""Minimum allowed confidence value (0%)."""

MAX_CONFIDENCE = 1.0
"""Maximum allowed confidence value (100%)."""

MIN_SCORE = 0
"""Minimum risk score."""

MAX_SCORE = 100
"""Maximum risk score (capped)."""
