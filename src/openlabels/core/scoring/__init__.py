"""Risk scoring for detected entities based on type, count, and exposure level."""

from .scorer import (
    CO_OCCURRENCE_RULES,
    ENTITY_CATEGORIES,
    ENTITY_WEIGHTS,
    EXPOSURE_MULTIPLIERS,
    TIER_THRESHOLDS,
    calculate_content_score,
    get_categories,
    get_category,
    get_co_occurrence_multiplier,
    get_weight,
    score,
    score_to_tier,
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
