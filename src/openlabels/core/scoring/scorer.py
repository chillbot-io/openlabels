"""
OpenLabels Risk Scoring Engine.

Computes risk scores from detected entities and exposure context.

Formula:
    content_score = Σ(weight × WEIGHT_SCALE × (1 + ln(count)) × confidence)
    content_score *= co_occurrence_multiplier
    final_score = min(100, content_score × exposure_multiplier)

Weights are on a 1-10 scale:
- 10: Critical (SSN, Passport, Credit Card, API Keys)
- 8-9: High (MRN, Driver's License)
- 6-7: Elevated (Phone, Email)
- 4-5: Moderate (Name, Address)
- 2-3: Low (Date, City)
- 1: Minimal
"""

import logging
import math
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

from ..types import RiskTier, ScoringResult, normalize_entity_type

logger = logging.getLogger(__name__)

# =============================================================================
# CALIBRATION PARAMETERS
# =============================================================================

# Scale factor: converts weights (1-10) to scoring weights
# Calibrated so single SSN (weight=10) at PRIVATE = Medium tier (~40)
WEIGHT_SCALE = 4.0

# Default confidence threshold
DEFAULT_CONFIDENCE = 0.85

# Tier thresholds
TIER_THRESHOLDS = {
    'critical': 80,
    'high': 55,
    'medium': 31,
    'low': 11,
}

# Exposure multipliers
EXPOSURE_MULTIPLIERS = {
    'PRIVATE': 1.0,
    'INTERNAL': 1.2,
    'ORG_WIDE': 1.8,
    'PUBLIC': 2.5,
}

# =============================================================================
# ENTITY WEIGHTS
# =============================================================================

ENTITY_WEIGHTS: Dict[str, int] = {
    # Critical identifiers (10)
    "SSN": 10,
    "PASSPORT": 10,
    "CREDIT_CARD": 10,
    "PASSWORD": 10,
    "API_KEY": 10,
    "PRIVATE_KEY": 10,
    "AWS_ACCESS_KEY": 10,
    "AWS_SECRET_KEY": 10,
    "DATABASE_URL": 10,
    "GITHUB_TOKEN": 10,
    "GITLAB_TOKEN": 10,
    "SLACK_TOKEN": 10,
    "STRIPE_KEY": 10,
    "CRYPTO_SEED_PHRASE": 10,

    # High (8-9)
    "MRN": 9,
    "DIAGNOSIS": 9,
    "HEALTH_PLAN_ID": 9,
    "JWT": 9,
    "DRIVER_LICENSE": 8,
    "NPI": 8,
    "DEA": 8,
    "TAX_ID": 8,
    "MILITARY_ID": 8,

    # Elevated (6-7)
    "BITCOIN_ADDRESS": 7,
    "ETHEREUM_ADDRESS": 7,
    "IBAN": 7,
    "SWIFT_BIC": 7,
    "PHONE": 6,
    "EMAIL": 6,
    "SENDGRID_KEY": 6,
    "TWILIO_KEY": 6,

    # Moderate (4-5)
    "NAME": 5,
    "ADDRESS": 5,
    "IP_ADDRESS": 5,
    "MAC_ADDRESS": 5,
    "VIN": 5,
    "CUSIP": 5,
    "ISIN": 5,
    "LEI": 5,
    "DATE_DOB": 5,
    "AGE": 4,
    "CLASSIFICATION_LEVEL": 4,
    "DOD_CONTRACT": 4,
    "GSA_CONTRACT": 4,
    "CAGE_CODE": 4,
    "UEI": 4,

    # Low (2-3)
    "DATE": 3,
    "ZIP": 3,
    "CITY": 2,
    "STATE": 2,
    "COUNTRY": 2,
    "TRACKING_NUMBER": 2,

    # Minimal (1)
    "FACILITY": 1,
    "ORGANIZATION": 1,
}

DEFAULT_WEIGHT = 5  # For unknown entity types

# =============================================================================
# ENTITY CATEGORIES
# =============================================================================

ENTITY_CATEGORIES: Dict[str, str] = {
    # Direct identifiers
    "SSN": "direct_identifier",
    "PASSPORT": "direct_identifier",
    "DRIVER_LICENSE": "direct_identifier",
    "MILITARY_ID": "direct_identifier",
    "TAX_ID": "direct_identifier",
    "MRN": "direct_identifier",
    "STATE_ID": "direct_identifier",

    # Health info
    "DIAGNOSIS": "health_info",
    "MEDICATION": "health_info",
    "HEALTH_PLAN_ID": "health_info",
    "NPI": "health_info",
    "DEA": "health_info",
    "LAB_TEST": "health_info",
    "PROCEDURE": "health_info",

    # Financial
    "CREDIT_CARD": "financial",
    "IBAN": "financial",
    "SWIFT_BIC": "financial",
    "ACCOUNT_NUMBER": "financial",
    "CUSIP": "financial",
    "ISIN": "financial",
    "BITCOIN_ADDRESS": "financial",
    "ETHEREUM_ADDRESS": "financial",
    "CRYPTO_SEED_PHRASE": "financial",

    # Contact
    "EMAIL": "contact",
    "PHONE": "contact",
    "ADDRESS": "contact",
    "ZIP": "contact",
    "FAX": "contact",

    # Credentials
    "PASSWORD": "credential",
    "API_KEY": "credential",
    "PRIVATE_KEY": "credential",
    "JWT": "credential",
    "AWS_ACCESS_KEY": "credential",
    "AWS_SECRET_KEY": "credential",
    "GITHUB_TOKEN": "credential",
    "GITLAB_TOKEN": "credential",
    "SLACK_TOKEN": "credential",
    "STRIPE_KEY": "credential",
    "DATABASE_URL": "credential",

    # Quasi-identifiers
    "NAME": "quasi_identifier",
    "DATE_DOB": "quasi_identifier",
    "AGE": "quasi_identifier",
    "DATE": "quasi_identifier",

    # Classification markings
    "CLASSIFICATION_LEVEL": "classification_marking",
    "CLASSIFICATION_MARKING": "classification_marking",
    "SCI_MARKING": "classification_marking",
    "DISSEMINATION_CONTROL": "classification_marking",
}

# =============================================================================
# CO-OCCURRENCE RULES
# =============================================================================

# (required_categories, multiplier, rule_name)
CO_OCCURRENCE_RULES: List[Tuple[Set[str], float, str]] = [
    # HIPAA: Direct ID + Health data
    ({'direct_identifier', 'health_info'}, 2.0, 'hipaa_phi'),
    # Identity theft: Direct ID + Financial
    ({'direct_identifier', 'financial'}, 1.8, 'identity_theft'),
    # Credentials always risky
    ({'credential'}, 1.5, 'credential_exposure'),
    # Personal + Health (even without direct ID)
    ({'quasi_identifier', 'health_info'}, 1.5, 'phi_without_id'),
    # Contact + Health
    ({'contact', 'health_info'}, 1.4, 'phi_with_contact'),
    # Full identity package
    ({'direct_identifier', 'quasi_identifier', 'financial'}, 2.2, 'full_identity'),
    # Classified data
    ({'classification_marking'}, 2.5, 'classified_data'),
]


# =============================================================================
# SCORING FUNCTIONS
# =============================================================================

def get_weight(entity_type: str) -> int:
    """Get weight for an entity type (1-10 scale)."""
    normalized = normalize_entity_type(entity_type)
    return ENTITY_WEIGHTS.get(normalized, DEFAULT_WEIGHT)


def get_category(entity_type: str) -> str:
    """Get category for an entity type."""
    normalized = normalize_entity_type(entity_type)
    return ENTITY_CATEGORIES.get(normalized, "unknown")


def get_categories(entities: Dict[str, int]) -> Set[str]:
    """Get set of categories present in entities."""
    categories = set()
    for entity_type in entities:
        cat = get_category(entity_type)
        if cat and cat != "unknown":
            categories.add(cat)
    return categories


def get_co_occurrence_multiplier(entities: Dict[str, int]) -> Tuple[float, List[str]]:
    """Get the highest applicable co-occurrence multiplier."""
    if not entities:
        return 1.0, []

    categories = get_categories(entities)
    max_mult = 1.0
    triggered_rules = []

    for required_cats, mult, rule_name in CO_OCCURRENCE_RULES:
        if required_cats.issubset(categories):
            if mult > max_mult:
                max_mult = mult
                triggered_rules = [rule_name]
            elif mult == max_mult:
                triggered_rules.append(rule_name)

    return max_mult, triggered_rules


def calculate_content_score(
    entities: Dict[str, int],
    confidence: float = DEFAULT_CONFIDENCE,
) -> float:
    """
    Calculate content sensitivity score from detected entities.

    Args:
        entities: Dict of {entity_type: count}
        confidence: Average detection confidence (0.0-1.0)

    Returns:
        Content score (0-100 scale, before exposure adjustment)
    """
    if not entities:
        return 0.0

    base_score = 0.0
    for entity_type, count in entities.items():
        weight = get_weight(entity_type) * WEIGHT_SCALE
        # Log aggregation: diminishing returns for more instances
        aggregation = 1 + math.log(max(1, count))
        entity_score = weight * aggregation * confidence
        base_score += entity_score

    # Apply co-occurrence multiplier
    multiplier, _ = get_co_occurrence_multiplier(entities)
    adjusted_score = base_score * multiplier

    return min(100.0, adjusted_score)


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


def score(
    entities: Dict[str, int],
    exposure: str = 'PRIVATE',
    confidence: float = DEFAULT_CONFIDENCE,
) -> ScoringResult:
    """
    Calculate risk score from detected entities and exposure context.

    This is the main scoring function used by OpenLabels.

    Args:
        entities: Dict of {entity_type: count} from detection
        exposure: Exposure level (PRIVATE, INTERNAL, ORG_WIDE, PUBLIC)
        confidence: Average detection confidence

    Returns:
        ScoringResult with score, tier, and breakdown

    Example:
        >>> result = score({'SSN': 1, 'DIAGNOSIS': 1}, exposure='PUBLIC')
        >>> print(f"Risk: {result.score} ({result.tier.value})")
        Risk: 100 (CRITICAL)
    """
    # Calculate content score
    content_score = calculate_content_score(entities, confidence)

    # Get co-occurrence info
    co_mult, co_rules = get_co_occurrence_multiplier(entities)

    # Apply exposure multiplier
    exp_mult = EXPOSURE_MULTIPLIERS.get(exposure.upper(), 1.0)
    final_score = min(100.0, content_score * exp_mult)

    # Determine tier
    tier = score_to_tier(final_score)

    return ScoringResult(
        score=int(round(final_score)),
        tier=tier,
        content_score=round(content_score, 1),
        exposure_multiplier=exp_mult,
        co_occurrence_multiplier=co_mult,
        co_occurrence_rules=co_rules,
        categories=get_categories(entities),
        exposure=exposure.upper(),
    )
