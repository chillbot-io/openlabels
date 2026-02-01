"""
OpenLabels Scan Triggers.

Determines when to trigger a content scan even if classification labels exist.

Triggers are used to decide when the scanner should run verification:
- NO_LABELS: No existing classification data
- PUBLIC_ACCESS: Public exposure is too risky to trust labels alone
- ORG_WIDE: Broad access warrants verification
- NO_ENCRYPTION: Unencrypted data needs verification
- STALE_DATA: Old data may have changed
- LOW_CONFIDENCE_HIGH_RISK: High-risk entity with uncertain detection

Decision Matrix:
┌─────────────────────────────────────────┬───────┬─────────────────────────────┐
│ Scenario                                │ Scan? │ Reason                      │
├─────────────────────────────────────────┼───────┼─────────────────────────────┤
│ No labels                               │  ✓    │ Nothing to go on            │
│ Labels exist, private, high confidence  │  ✗    │ Trust external tool         │
│ Labels exist, PUBLIC                    │  ✓    │ Exposure too high to trust  │
│ Labels exist, no encryption             │  ✓    │ Protection gap              │
│ Labels exist, stale >1yr                │  ✓    │ Verify still accurate       │
│ Labels: SSN @ 0.65 confidence           │  ✓    │ High risk + uncertain       │
│ Labels: EMAIL @ 0.35 confidence         │  ✗    │ Lower risk, trust it        │
│ Labels: CREDIT_CARD @ 0.90 confidence   │  ✗    │ High confidence, trust it   │
└─────────────────────────────────────────┴───────┴─────────────────────────────┘
"""

import logging
from enum import Enum
from typing import List, Tuple, Optional

from ..adapters.base import Entity, NormalizedContext, ExposureLevel
from .registry import get_weight


class ScanTrigger(Enum):
    """Reasons to trigger a content scan."""
    NO_LABELS = "no_labels"                         # No external classification
    PUBLIC_ACCESS = "public_access"                 # Public = always verify
    ORG_WIDE = "org_wide"                           # Broadly shared = verify
    NO_ENCRYPTION = "no_encryption"                 # Unprotected = verify
    STALE_DATA = "stale_data"                       # Old data = verify
    LOW_CONFIDENCE_HIGH_RISK = "low_conf_high_risk" # Uncertain critical finding


# Configuration
CONFIDENCE_THRESHOLD = 0.80

# Weight threshold for "high risk" entities (weight >= this is high risk)
# Weights 8-10 include: SSN, PASSPORT, CREDIT_CARD, credentials, biometrics
HIGH_RISK_WEIGHT_THRESHOLD = 8

# Staleness threshold in days (1 year)
STALENESS_THRESHOLD_DAYS = 365


def should_scan(
    entities: Optional[List[Entity]],
    context: NormalizedContext,
) -> Tuple[bool, List[ScanTrigger]]:
    """
    Determine if scanning is needed and why.

    This function evaluates whether to run the content scanner even when
    external classification labels exist. The goal is to verify high-risk
    scenarios while trusting labels in low-risk situations.

    Args:
        entities: List of entities from external classification (Macie, DLP, etc.)
                 Can be None or empty if no classification exists.
        context: Normalized context with exposure, encryption, staleness, etc.

    Returns:
        Tuple of (should_scan: bool, triggers: List[ScanTrigger])

    Examples:
        >>> # No labels - must scan
        >>> should_scan([], context)
        (True, [ScanTrigger.NO_LABELS])

        >>> # Public bucket with labels - scan anyway
        >>> context.exposure = "PUBLIC"
        >>> should_scan([entity], context)
        (True, [ScanTrigger.PUBLIC_ACCESS])

        >>> # Private, encrypted, high confidence - trust labels
        >>> context.exposure = "PRIVATE"
        >>> context.encryption = "customer_managed"
        >>> should_scan([high_conf_entity], context)
        (False, [])
    """
    triggers: List[ScanTrigger] = []

    # No labels = must scan
    if not entities or not context.has_classification:
        triggers.append(ScanTrigger.NO_LABELS)

    # Exposure-based triggers
    exposure_str = context.exposure.upper() if isinstance(context.exposure, str) else context.exposure.name

    if exposure_str == "PUBLIC" or context.exposure == ExposureLevel.PUBLIC:
        triggers.append(ScanTrigger.PUBLIC_ACCESS)
    elif exposure_str == "ORG_WIDE" or context.exposure == ExposureLevel.ORG_WIDE:
        triggers.append(ScanTrigger.ORG_WIDE)

    # Protection gaps
    if context.encryption == "none":
        triggers.append(ScanTrigger.NO_ENCRYPTION)

    # Staleness
    if context.staleness_days > STALENESS_THRESHOLD_DAYS:
        triggers.append(ScanTrigger.STALE_DATA)

    # High-risk entity with low/medium confidence = verify
    if entities:
        for entity in entities:
            weight = get_weight(entity.type.upper())
            is_high_risk = weight >= HIGH_RISK_WEIGHT_THRESHOLD
            is_uncertain = entity.confidence < CONFIDENCE_THRESHOLD

            if is_high_risk and is_uncertain:
                triggers.append(ScanTrigger.LOW_CONFIDENCE_HIGH_RISK)
                break  # One is enough

    return len(triggers) > 0, triggers


def get_trigger_descriptions(triggers: List[ScanTrigger]) -> List[str]:
    """
    Get human-readable descriptions for triggers.

    Args:
        triggers: List of triggered scan triggers

    Returns:
        List of description strings
    """
    descriptions = {
        ScanTrigger.NO_LABELS: "No existing classification labels found",
        ScanTrigger.PUBLIC_ACCESS: "Public access requires verification",
        ScanTrigger.ORG_WIDE: "Broad organization-wide access detected",
        ScanTrigger.NO_ENCRYPTION: "Data is not encrypted",
        ScanTrigger.STALE_DATA: f"Data not modified in over {STALENESS_THRESHOLD_DAYS} days",
        ScanTrigger.LOW_CONFIDENCE_HIGH_RISK: "High-risk entity with uncertain confidence",
    }
    return [descriptions.get(t, t.value) for t in triggers]


def calculate_scan_priority(
    context: NormalizedContext,
    triggers: List[ScanTrigger],
) -> int:
    """
    Calculate scan priority based on context and triggers.

    Higher priority = more urgent. Used for queue ordering.

    Priority scale:
    - 0-25:   Low priority (private, encrypted, no triggers)
    - 26-50:  Medium priority (internal exposure)
    - 51-75:  High priority (org-wide or unencrypted)
    - 76-100: Critical priority (public + multiple risk factors)

    Args:
        context: Normalized context
        triggers: List of active triggers

    Returns:
        Priority score 0-100
    """
    priority = 0

    # Exposure-based priority
    exposure_str = context.exposure.upper() if isinstance(context.exposure, str) else context.exposure.name
    exposure_priorities = {
        "PRIVATE": 0,
        "INTERNAL": 10,
        "ORG_WIDE": 30,
        "PUBLIC": 50,
    }
    priority += exposure_priorities.get(exposure_str, 0)

    # Trigger-based boosts
    if ScanTrigger.NO_ENCRYPTION in triggers:
        priority += 20
    if ScanTrigger.LOW_CONFIDENCE_HIGH_RISK in triggers:
        priority += 25
    if ScanTrigger.STALE_DATA in triggers:
        priority += 5
    if ScanTrigger.NO_LABELS in triggers:
        priority += 15

    # Cap at 100
    return min(100, priority)


def needs_scan(
    entities: Optional[List[Entity]],
    context: NormalizedContext,
) -> bool:
    """
    Simple boolean check for whether scanning is needed.

    Args:
        entities: List of entities from external classification
        context: Normalized context

    Returns:
        True if scan should be triggered, False otherwise
    """
    should, _ = should_scan(entities, context)
    return should


def get_scan_urgency(
    entities: Optional[List[Entity]],
    context: NormalizedContext,
) -> str:
    """
    Get urgency level for scanning.

    Args:
        entities: List of entities from external classification
        context: Normalized context

    Returns:
        One of: "IMMEDIATE", "HIGH", "MEDIUM", "LOW", "NONE"
    """
    should, triggers = should_scan(entities, context)

    if not should:
        return "NONE"

    priority = calculate_scan_priority(context, triggers)

    if priority >= 75:
        return "IMMEDIATE"
    elif priority >= 50:
        return "HIGH"
    elif priority >= 25:
        return "MEDIUM"
    else:
        return "LOW"



# --- Testing ---


if __name__ == "__main__":
    # Configure logging for test output
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    logger = logging.getLogger(__name__)

    # Test cases
    from ..adapters.base import Entity, NormalizedContext

    logger.info("OpenLabels Scan Triggers Test")
    logger.info("=" * 60)

    # Test 1: No labels
    ctx1 = NormalizedContext(
        exposure="PRIVATE",
        has_classification=False,
    )
    should, triggers = should_scan([], ctx1)
    logger.info(f"\n1. No labels, private:")
    logger.info(f"   Should scan: {should}")
    logger.info(f"   Triggers: {[t.value for t in triggers]}")

    # Test 2: Public access with labels
    ctx2 = NormalizedContext(
        exposure="PUBLIC",
        has_classification=True,
        encryption="none",
    )
    entities2 = [Entity(type="SSN", count=1, confidence=0.95, source="macie")]
    should, triggers = should_scan(entities2, ctx2)
    logger.info(f"\n2. Public access with SSN:")
    logger.info(f"   Should scan: {should}")
    logger.info(f"   Triggers: {[t.value for t in triggers]}")
    logger.info(f"   Priority: {calculate_scan_priority(ctx2, triggers)}")

    # Test 3: Private, encrypted, high confidence
    ctx3 = NormalizedContext(
        exposure="PRIVATE",
        has_classification=True,
        encryption="customer_managed",
        staleness_days=30,
    )
    entities3 = [Entity(type="EMAIL", count=5, confidence=0.92, source="dlp")]
    should, triggers = should_scan(entities3, ctx3)
    logger.info(f"\n3. Private, encrypted, high confidence EMAIL:")
    logger.info(f"   Should scan: {should}")
    logger.info(f"   Triggers: {[t.value for t in triggers]}")

    # Test 4: Low confidence high-risk
    ctx4 = NormalizedContext(
        exposure="INTERNAL",
        has_classification=True,
        encryption="platform",
        staleness_days=100,
    )
    entities4 = [Entity(type="SSN", count=1, confidence=0.65, source="purview")]
    should, triggers = should_scan(entities4, ctx4)
    logger.info(f"\n4. SSN at 0.65 confidence (internal):")
    logger.info(f"   Should scan: {should}")
    logger.info(f"   Triggers: {[t.value for t in triggers]}")
    logger.info(f"   Urgency: {get_scan_urgency(entities4, ctx4)}")
