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
#
# ML band widened from [0.30, 0.55] to [0.20, 0.65]: the original
# 0.25-point range compressed all ML scores too aggressively,
# making the corroboration thresholds (0.52, 0.55) extremely
# sensitive.  With a 0.45-point band, high-confidence ML detections
# can compete with low-confidence pattern detections, while still
# maintaining clear tier separation (pattern floor is 0.65).
_TIER_FLOORS: dict[Tier, float] = {
    Tier.ML: 0.20,
    Tier.PATTERN: 0.65,
    Tier.STRUCTURED: 0.80,
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
            raw_confidence=s.raw_confidence,
            detector_label=s.detector_label,
        )
        for s in spans
    ]


def _next_ceiling(tier: Tier) -> float:
    """Ceiling for a tier = floor of the next tier, or 1.0.

    Returns 1.0 as a safe default for unknown or unexpected tier values
    so that calibration never crashes on new/custom tiers.
    """
    ordered = [Tier.ML, Tier.PATTERN, Tier.STRUCTURED, Tier.CHECKSUM]
    try:
        idx = ordered.index(tier)
    except (ValueError, TypeError):
        # Unknown tier, new enum member, or non-Tier value: fall back to
        # the widest possible ceiling so calibration still produces a
        # value in [0.0, 1.0].
        return 1.0
    if idx >= len(ordered) - 1:
        return 1.0
    return _TIER_FLOORS.get(ordered[idx + 1], 1.0)
