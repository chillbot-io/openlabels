"""
OpenLabels Risk Scoring.

This module provides risk scoring for detected entities,
taking into account entity types, counts, and exposure levels.
"""

from .scorer import (
    score,
    get_weight,
    get_category,
    get_categories,
    get_co_occurrence_multiplier,
    calculate_content_score,
    score_to_tier,
    ENTITY_WEIGHTS,
    ENTITY_CATEGORIES,
    EXPOSURE_MULTIPLIERS,
    TIER_THRESHOLDS,
    CO_OCCURRENCE_RULES,
)

__all__ = [
    "score",
    "get_weight",
    "get_category",
    "get_categories",
    "get_co_occurrence_multiplier",
    "calculate_content_score",
    "score_to_tier",
    "ENTITY_WEIGHTS",
    "ENTITY_CATEGORIES",
    "EXPOSURE_MULTIPLIERS",
    "TIER_THRESHOLDS",
    "CO_OCCURRENCE_RULES",
]
