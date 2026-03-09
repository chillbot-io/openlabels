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

import math

from ..entity_domains import get_all_domains, get_max_score_multiplier
from ..types import RiskTier, ScoringResult, normalize_entity_type

# CALIBRATION PARAMETERS
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

# ENTITY WEIGHTS
ENTITY_WEIGHTS: dict[str, int] = {
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
    "VAULT_TOKEN": 10,
    "OPENAI_KEY": 10,
    "ANTHROPIC_KEY": 10,

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
    "ITIN": 8,
    "EIN": 8,
    "UK_NINO": 8,
    "IN_PAN": 8,
    "SG_NRIC_FIN": 8,
    "ES_NIE": 8,
    "ES_NIF": 8,
    "PL_PESEL": 8,
    "KR_RRN": 8,
    "IT_FISCAL_CODE": 8,
    "AADHAAR": 8,
    "CURP": 8,
    "SVNR": 8,
    "TFN": 8,
    "ATLASSIAN_TOKEN": 9,

    # Elevated (6-7)
    "BITCOIN_ADDRESS": 7,
    "ETHEREUM_ADDRESS": 7,
    "IBAN": 7,
    "SWIFT_BIC": 7,
    "FI_HETU": 7,
    "TH_TNIN": 7,
    "IN_GSTIN": 7,
    "IN_VOTER": 7,
    "IT_VAT": 7,
    "NHS_NUMBER": 7,
    "AUTH_NUMBER": 7,
    "BMI": 6,
    "SOLANA_ADDRESS": 7,
    "MONERO_ADDRESS": 7,
    "GOOGLE_OAUTH_TOKEN": 7,
    "GRAFANA_KEY": 7,
    "LINEAR_KEY": 7,
    "DOPPLER_TOKEN": 7,
    "VERCEL_TOKEN": 7,
    "SUPABASE_KEY": 7,
    "PLANETSCALE_TOKEN": 7,
    "PHONE": 6,
    "EMAIL": 6,
    "SENDGRID_KEY": 6,
    "TWILIO_KEY": 6,

    # High — government IDs detected by GLiNER
    "STATE_ID": 8,

    # Elevated — financial
    "ACCOUNT_NUMBER": 7,

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
    "FIRSTNAME": 4,
    "LASTNAME": 4,
    "LICENSE_PLATE": 4,
    "AGE": 4,
    "CLASSIFICATION_LEVEL": 4,
    "DOD_CONTRACT": 4,
    "GSA_CONTRACT": 4,
    "CAGE_CODE": 4,
    "UEI": 4,

    # Low (2-3)
    "DATE": 3,
    "ZIP": 3,
    "USERNAME": 3,
    "CITY": 2,
    "STATE": 2,
    "COUNTRY": 2,
    "TRACKING_NUMBER": 2,
    "URL": 2,

    # Minimal (1)
    "BED_NUMBER": 2,
    "FACILITY": 1,
    "ORGANIZATION": 1,
    "COMPANY": 1,
}

DEFAULT_WEIGHT = 5  # For unknown entity types


# SCORING FUNCTIONS
def get_weight(entity_type: str) -> int:
    """Get weight for an entity type (1-10 scale)."""
    normalized = normalize_entity_type(entity_type)
    return ENTITY_WEIGHTS.get(normalized, DEFAULT_WEIGHT)


def get_co_occurrence_multiplier(entities: dict[str, int]) -> tuple[float, list[str]]:
    """Get the highest applicable co-occurrence multiplier.

    Delegates to the domain-based compliance compositions defined in
    :mod:`openlabels.core.entity_domains`.
    """
    return get_max_score_multiplier(entities)


def calculate_content_score(
    entities: dict[str, int],
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
    entities: dict[str, int],
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
        categories={d.value for d in get_all_domains(entities)},
        exposure=exposure.upper(),
    )
