"""Confidence score normalization for consistent detector outputs.

This module provides standardized confidence
normalization across all detectors, ensuring all confidence values are
properly calibrated to the 0-1 scale.

Different detectors produce confidence scores on different scales or
with different distributions. This module normalizes them to a consistent
scale while preserving relative ordering within each detector.
"""

import math
from typing import List
from ..types import Span

# Detector-specific calibration parameters
# Format: {detector_name: (scale_factor, offset, min_output, max_output)}
# Applied as: calibrated = clamp(raw * scale_factor + offset, min_output, max_output)
DETECTOR_CALIBRATION = {
    # ML models often output logits or softmax values
    "phi_bert": (1.0, 0.0, 0.0, 1.0),  # Already normalized
    "pii_bert": (1.0, 0.0, 0.0, 1.0),  # Already normalized
    "phi_bert_onnx": (1.0, 0.0, 0.0, 1.0),
    "pii_bert_onnx": (1.0, 0.0, 0.0, 1.0),

    # Pattern detectors often have fixed confidence values
    "patterns": (1.0, 0.0, 0.0, 1.0),
    "additional_patterns": (1.0, 0.0, 0.0, 1.0),

    # Checksum-validated detectors have high confidence
    "checksum": (1.0, 0.0, 0.85, 1.0),  # Floor at 0.85 (validated)

    # Structured extraction (label-based) is high confidence
    "structured": (1.0, 0.0, 0.90, 1.0),  # Floor at 0.90

    # Dictionary-based detection
    "dictionaries": (1.0, 0.0, 0.0, 1.0),

    # Known entity detection (from entity persistence)
    "known_entity": (1.0, 0.0, 0.95, 1.0),  # Floor at 0.95

    # Domain-specific detectors
    "secrets": (1.0, 0.0, 0.80, 1.0),  # High confidence for secrets
    "financial": (1.0, 0.0, 0.0, 1.0),
    "government": (1.0, 0.0, 0.0, 1.0),

    # Coref resolution
    "coref": (1.0, 0.0, 0.0, 1.0),
}

# Default calibration for unknown detectors
DEFAULT_CALIBRATION = (1.0, 0.0, 0.0, 1.0)


def normalize_confidence(raw: float, detector: str) -> float:
    """
    Normalize detector-specific confidence to 0-1 scale.

    Applies detector-specific calibration to ensure confidence values
    are comparable across different detector types.

    Args:
        raw: Raw confidence value from detector
        detector: Name of the detector that produced the value

    Returns:
        Calibrated confidence value in [0, 1]

    Note:
        NaN values are normalized to the detector's floor (safest default).
        Positive infinity is clamped to the detector's ceiling.
        Negative infinity is clamped to the detector's floor.
    """
    # Get calibration parameters
    scale, offset, floor, ceil = DETECTOR_CALIBRATION.get(
        detector, DEFAULT_CALIBRATION
    )

    # Handle special float values explicitly
    if math.isnan(raw):
        # NaN → use floor as safest default (conservative)
        return floor
    if math.isinf(raw):
        # +inf → ceil, -inf → floor
        return ceil if raw > 0 else floor

    # Apply calibration
    calibrated = raw * scale + offset

    # Clamp to valid range with detector-specific floor/ceiling
    return max(floor, min(ceil, calibrated))


def clamp_confidence(value: float) -> float:
    """
    Clamp confidence value to valid [0, 1] range.

    Simple utility for ensuring confidence values stay in bounds
    after arithmetic operations.

    Args:
        value: Confidence value (potentially out of range)

    Returns:
        Value clamped to [0, 1]

    Note:
        NaN values are clamped to 0.0 (conservative).
        Positive infinity is clamped to 1.0.
        Negative infinity is clamped to 0.0.
    """
    # Handle special float values explicitly
    if math.isnan(value):
        return 0.0
    if math.isinf(value):
        return 1.0 if value > 0 else 0.0
    return max(0.0, min(1.0, value))


def normalize_span_confidence(span: Span) -> Span:
    """
    Create a new span with normalized confidence (immutable pattern).

    If the confidence value changes after normalization, returns a new
    span with the calibrated value. Otherwise returns the original span.

    Args:
        span: Input span with potentially uncalibrated confidence

    Returns:
        Span with normalized confidence value
    """
    calibrated = normalize_confidence(span.confidence, span.detector)

    if calibrated != span.confidence:
        return Span(
            start=span.start,
            end=span.end,
            text=span.text,
            entity_type=span.entity_type,
            confidence=calibrated,
            detector=span.detector,
            tier=span.tier,
            safe_harbor_value=span.safe_harbor_value,
            needs_review=span.needs_review,
            review_reason=span.review_reason,
            coref_anchor_value=span.coref_anchor_value,
            token=span.token,
        )
    return span


def normalize_spans_confidence(spans: List[Span]) -> List[Span]:
    """
    Normalize confidence for all spans in a list (immutable pattern).

    Applies detector-specific calibration to each span, creating new
    spans only when the confidence value actually changes.

    Args:
        spans: List of spans with potentially uncalibrated confidence

    Returns:
        List of spans with normalized confidence values
    """
    return [normalize_span_confidence(span) for span in spans]


def combine_confidences(confidences: List[float], method: str = "max") -> float:
    """
    Combine multiple confidence scores into a single value.

    Used when multiple detectors find the same span.

    Args:
        confidences: List of confidence values to combine
        method: Combination method:
            - "max": Take the maximum (default, most aggressive)
            - "avg": Take the average
            - "weighted_avg": Weighted by confidence (higher conf = more weight)

    Returns:
        Combined confidence value in [0, 1]
    """
    if not confidences:
        return 0.0

    if method == "max":
        return max(confidences)
    elif method == "avg":
        return sum(confidences) / len(confidences)
    elif method == "weighted_avg":
        # Weight each confidence by itself (higher = more weight)
        total_weight = sum(confidences)
        if total_weight == 0:
            return 0.0
        weighted_sum = sum(c * c for c in confidences)
        return weighted_sum / total_weight
    else:
        raise ValueError(f"Unknown combination method: {method}")


# Confidence level constants for common thresholds
class ConfidenceLevel:
    """Standard confidence thresholds for decision making."""

    # Very high confidence - validated by checksum or explicit label
    VERIFIED = 0.95

    # High confidence - strong evidence
    HIGH = 0.85

    # Medium confidence - default threshold
    MEDIUM = 0.70

    # Low confidence - may need review
    LOW = 0.50

    # Minimum for any action
    MINIMUM = 0.30
