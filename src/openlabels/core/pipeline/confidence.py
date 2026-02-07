"""Confidence calibration for cross-tier span comparison.

Normalizes raw confidence scores so that spans from different detection
tiers (checksum, structured, pattern, ML) are comparable on a single
0.0–1.0 scale.

The calibration applies a tier-based floor so that a high-confidence ML
detection (tier 1) never outranks a checksum-validated detection (tier 4),
even if the raw scores look similar.
"""

from __future__ import annotations

from ..types import Span, Tier

# Tier floors — the minimum calibrated score for each tier.
# A CHECKSUM span will always score >= 0.90 after calibration,
# so it can never be beaten by a PATTERN span at 0.85.
_TIER_FLOORS: dict[Tier, float] = {
    Tier.ML: 0.00,
    Tier.PATTERN: 0.50,
    Tier.STRUCTURED: 0.75,
    Tier.CHECKSUM: 0.90,
}


def calibrate_confidence(span: Span) -> float:
    """Return a calibrated confidence for *span*.

    The calibrated value sits in [floor, ceiling] where the floor is
    determined by the span's tier and the ceiling is the next tier's
    floor (or 1.0 for CHECKSUM).

    Formula: ``floor + raw_confidence * (ceiling - floor)``
    """
    floor = _TIER_FLOORS.get(span.tier, 0.0)
    ceiling = _next_ceiling(span.tier)
    return floor + span.confidence * (ceiling - floor)


def calibrate_spans(spans: list[Span]) -> list[Span]:
    """Return a new list with calibrated confidence on every span."""
    return [
        Span(
            start=s.start,
            end=s.end,
            text=s.text,
            entity_type=s.entity_type,
            confidence=calibrate_confidence(s),
            detector=s.detector,
            tier=s.tier,
            context=s.context,
            needs_review=s.needs_review,
            review_reason=s.review_reason,
            coref_anchor_value=s.coref_anchor_value,
        )
        for s in spans
    ]


def _next_ceiling(tier: Tier) -> float:
    """Ceiling for a tier = floor of the next tier, or 1.0."""
    ordered = [Tier.ML, Tier.PATTERN, Tier.STRUCTURED, Tier.CHECKSUM]
    idx = ordered.index(tier)
    if idx >= len(ordered) - 1:
        return 1.0
    return _TIER_FLOORS[ordered[idx + 1]]
