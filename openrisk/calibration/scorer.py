"""
OpenLabels Scorer - Risk score calculation from detected entities.

This is the calibration version for tuning parameters.
Final parameters will be ported to openlabels/core/scorer.py
"""

import math
from typing import Dict, Set, Tuple, List
from dataclasses import dataclass
from enum import Enum


class RiskTier(Enum):
    MINIMAL = "Minimal"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# --- Calibration Parameters ---

# Entity weights calibrated so:
# - Single SSN/CC → Medium (score ~35)
# - SSN + health → High (score ~65+)
# - Bulk sensitive → Critical (score 86+)
# Math: weight × 1.0 × 0.9 = base score for single entity
ENTITY_WEIGHTS = {
    # Direct Identifiers - single instance should be Medium
    'ssn': 40,           # 40 × 0.9 = 36 → Medium
    'passport': 38,
    'drivers_license': 32,
    'tax_id': 36,

    # Financial - single CC should be Medium
    'credit_card': 40,   # 40 × 0.9 = 36 → Medium
    'bank_account': 25,
    'routing_number': 15,

    # Medical/Health - important for HIPAA combos
    'mrn': 28,
    'diagnosis': 25,
    'medication': 20,
    'procedure': 20,
    'lab_result': 22,
    'health_plan_id': 18,

    # Personal Identifiers - single should be Low
    'full_name': 12,     # 12 × 0.9 = 10.8 → Minimal (needs combo)
    'physical_address': 15,
    'email': 10,         # Slightly lower - common, less risky alone
    'phone': 10,
    'ip_address': 8,
    'date_of_birth': 18,

    # Quasi-identifiers - minimal risk alone
    'age': 5,
    'gender': 4,
    'postal_code': 6,
    'ethnicity': 8,

    # Secrets/Credentials - single should be High
    'api_key': 70,       # 70 × 0.9 = 63 → High
    'password': 70,
    'private_key': 80,
    'access_token': 65,
    'aws_key': 75,
}

# Default weight for unknown entity types
DEFAULT_WEIGHT = 10

# Entity categories for co-occurrence rules
ENTITY_CATEGORIES = {
    # Direct identifiers
    'ssn': 'direct_id',
    'passport': 'direct_id',
    'drivers_license': 'direct_id',
    'tax_id': 'direct_id',

    # Financial
    'credit_card': 'financial',
    'bank_account': 'financial',
    'routing_number': 'financial',

    # Health/Medical
    'mrn': 'health',
    'diagnosis': 'health',
    'medication': 'health',
    'procedure': 'health',
    'lab_result': 'health',
    'health_plan_id': 'health',

    # Personal
    'full_name': 'personal',
    'physical_address': 'personal',
    'date_of_birth': 'personal',

    # Credentials
    'api_key': 'credentials',
    'password': 'credentials',
    'private_key': 'credentials',
    'access_token': 'credentials',
    'aws_key': 'credentials',
}

# Co-occurrence multipliers: certain combinations are worse than sum of parts
CO_OCCURRENCE_RULES: List[Tuple[Set[str], float]] = [
    # HIPAA: Direct ID + Health data = major violation
    ({'direct_id', 'health'}, 2.0),

    # Identity theft: Direct ID + Financial
    ({'direct_id', 'financial'}, 1.8),

    # Credentials always high risk
    ({'credentials'}, 1.5),

    # Personal + Health (even without direct ID)
    ({'personal', 'health'}, 1.5),

    # Full identity package
    ({'direct_id', 'personal', 'financial'}, 2.2),
]

# Tier thresholds (score -> tier)
# Calibrated so:
# - Single direct ID (SSN, CC) = Medium (~36)
# - Direct ID + personal = High (~55+)
# - HIPAA/bulk = Critical (80+)
TIER_THRESHOLDS = {
    'critical': 80,      # HIPAA violations, bulk data, credentials
    'high': 55,          # Direct ID + context, or multiple high-risk
    'medium': 31,        # Single direct ID
    'low': 11,           # Personal info without direct ID
    # Below 11 = Minimal
}

# Exposure multipliers (applied after content scoring)
# Keys match ExposureLevel enum names (lowercase)
EXPOSURE_MULTIPLIERS = {
    'private': 1.0,
    'internal': 1.2,
    'org_wide': 1.8,  # Consistent with adapters (was incorrectly 'over_exposed')
    'public': 2.5,
}


# --- Scoring Implementation ---

def get_categories(entities: Dict[str, int]) -> Set[str]:
    """Get set of categories present in entities."""
    categories = set()
    for entity_type in entities:
        cat = ENTITY_CATEGORIES.get(entity_type)
        if cat:
            categories.add(cat)
    return categories


def get_co_occurrence_multiplier(entities: Dict[str, int]) -> float:
    """Get the highest applicable co-occurrence multiplier."""
    if not entities:
        return 1.0

    categories = get_categories(entities)
    max_mult = 1.0

    for required_cats, mult in CO_OCCURRENCE_RULES:
        if required_cats.issubset(categories):
            max_mult = max(max_mult, mult)

    return max_mult


def calculate_content_score(
    entities: Dict[str, int],
    confidence: float = 0.90,
) -> float:
    """
    Calculate content sensitivity score from detected entities.

    Args:
        entities: Dict of {entity_type: count}
        confidence: Detection confidence (0.0-1.0)

    Returns:
        Content score (0-100 scale, before exposure adjustment)
    """
    if not entities:
        return 0.0

    # Stage 1: Base entity scoring
    base_score = 0.0
    for entity_type, count in entities.items():
        weight = ENTITY_WEIGHTS.get(entity_type, DEFAULT_WEIGHT)
        # Log aggregation: diminishing returns for more instances
        aggregation = 1 + math.log(max(1, count))
        entity_score = weight * aggregation * confidence
        base_score += entity_score

    # Stage 2: Co-occurrence multiplier
    multiplier = get_co_occurrence_multiplier(entities)
    adjusted_score = base_score * multiplier

    # Stage 3: Normalize to 0-100
    # Cap at 100 for now, could use sigmoid for smoother curve
    final_score = min(100.0, adjusted_score)

    return round(final_score, 1)


def calculate_risk_score(
    content_score: float,
    exposure: str = 'private',
) -> float:
    """
    Calculate final risk score including exposure context.

    Args:
        content_score: Content sensitivity score (0-100)
        exposure: Exposure level (private, internal, over_exposed, public)

    Returns:
        Risk score (0-100)
    """
    multiplier = EXPOSURE_MULTIPLIERS.get(exposure, 1.0)
    risk_score = content_score * multiplier
    return min(100.0, round(risk_score, 1))


def score_to_tier(score: float) -> RiskTier:
    """Map score to risk tier."""
    if score >= TIER_THRESHOLDS['critical']:
        return RiskTier.CRITICAL
    elif score >= TIER_THRESHOLDS['high']:
        return RiskTier.HIGH
    elif score >= TIER_THRESHOLDS['medium']:
        return RiskTier.MEDIUM
    elif score >= TIER_THRESHOLDS['low']:
        return RiskTier.LOW
    else:
        return RiskTier.MINIMAL


@dataclass
class ScoringResult:
    """Complete scoring result for a sample."""
    content_score: float
    risk_score: float
    tier: RiskTier
    categories: Set[str]
    co_occurrence_multiplier: float
    exposure: str = 'private'

    def to_dict(self) -> dict:
        return {
            'content_score': self.content_score,
            'risk_score': self.risk_score,
            'tier': self.tier.value,
            'categories': list(self.categories),
            'co_occurrence_multiplier': self.co_occurrence_multiplier,
            'exposure': self.exposure,
        }


def score_entities(
    entities: Dict[str, int],
    exposure: str = 'private',
    confidence: float = 0.90,
) -> ScoringResult:
    """
    Full scoring pipeline for a set of entities.

    Args:
        entities: Dict of {entity_type: count}
        exposure: Exposure level
        confidence: Detection confidence

    Returns:
        ScoringResult with all scoring details
    """
    content_score = calculate_content_score(entities, confidence)
    risk_score = calculate_risk_score(content_score, exposure)
    tier = score_to_tier(risk_score)
    categories = get_categories(entities)
    multiplier = get_co_occurrence_multiplier(entities)

    return ScoringResult(
        content_score=content_score,
        risk_score=risk_score,
        tier=tier,
        categories=categories,
        co_occurrence_multiplier=multiplier,
        exposure=exposure,
    )


if __name__ == '__main__':
    # Quick test cases
    test_cases = [
        ({}, 'Empty'),
        ({'email': 1}, 'Single email'),
        ({'phone': 1}, 'Single phone'),
        ({'ssn': 1}, 'Single SSN'),
        ({'full_name': 1, 'email': 1}, 'Name + email'),
        ({'ssn': 1, 'full_name': 1}, 'SSN + name'),
        ({'ssn': 1, 'diagnosis': 1}, 'SSN + diagnosis (HIPAA)'),
        ({'ssn': 1, 'diagnosis': 1, 'full_name': 1}, 'Full HIPAA'),
        ({'credit_card': 10}, 'Bulk credit cards'),
        ({'ssn': 100, 'diagnosis': 50}, 'Bulk PHI'),
        ({'api_key': 1}, 'API key'),
        ({'private_key': 1}, 'Private key'),
    ]

    print("=" * 70)
    print("OpenLabels Scorer Test Cases")
    print("=" * 70)

    for entities, description in test_cases:
        result = score_entities(entities)
        print(f"\n{description}")
        print(f"  Entities: {entities}")
        print(f"  Content Score: {result.content_score}")
        print(f"  Risk Score: {result.risk_score} ({result.exposure})")
        print(f"  Tier: {result.tier.value}")
        if result.co_occurrence_multiplier > 1.0:
            print(f"  Co-occurrence: {result.co_occurrence_multiplier}x ({result.categories})")
