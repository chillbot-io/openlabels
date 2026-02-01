"""Tests for confidence score normalization in confidence.py.

Tests detector-specific calibration, confidence combination methods,
threshold checking, and special float value handling.
"""

import math
import pytest
from scrubiq.types import Span, Tier
from scrubiq.pipeline.confidence import (
    normalize_confidence,
    clamp_confidence,
    normalize_span_confidence,
    normalize_spans_confidence,
    combine_confidences,
    confidence_meets_threshold,
    ConfidenceLevel,
    DETECTOR_CALIBRATION,
    DEFAULT_CALIBRATION,
)


def make_span(text, start=0, entity_type="NAME", confidence=0.9, detector="test", tier=2):
    """Helper to create spans with correct end position."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=Tier.from_value(tier),
    )


# =============================================================================
# DETECTOR CALIBRATION CONSTANTS TESTS
# =============================================================================

class TestDetectorCalibration:
    """Tests for DETECTOR_CALIBRATION constant."""

    def test_ml_detectors_have_full_range(self):
        """ML detectors use full 0-1 range."""
        for detector in ["phi_bert", "pii_bert", "phi_bert_onnx", "pii_bert_onnx"]:
            scale, offset, floor, ceil = DETECTOR_CALIBRATION[detector]
            assert floor == 0.0
            assert ceil == 1.0

    def test_checksum_has_high_floor(self):
        """Checksum detector has high floor (validated)."""
        scale, offset, floor, ceil = DETECTOR_CALIBRATION["checksum"]
        assert floor >= 0.85

    def test_structured_has_high_floor(self):
        """Structured detector has high floor (label-based)."""
        scale, offset, floor, ceil = DETECTOR_CALIBRATION["structured"]
        assert floor >= 0.90

    def test_known_entity_has_highest_floor(self):
        """Known entity detector has highest floor."""
        scale, offset, floor, ceil = DETECTOR_CALIBRATION["known_entity"]
        assert floor >= 0.95

    def test_default_calibration_is_passthrough(self):
        """Default calibration is passthrough (no change)."""
        scale, offset, floor, ceil = DEFAULT_CALIBRATION
        assert scale == 1.0
        assert offset == 0.0
        assert floor == 0.0
        assert ceil == 1.0


# =============================================================================
# NORMALIZE CONFIDENCE TESTS
# =============================================================================

class TestNormalizeConfidence:
    """Tests for normalize_confidence()."""

    def test_passthrough_for_known_detector(self):
        """Known detectors with passthrough calibration return value as-is."""
        result = normalize_confidence(0.75, "phi_bert")
        assert result == 0.75

    def test_unknown_detector_uses_default(self):
        """Unknown detectors use default calibration."""
        result = normalize_confidence(0.75, "unknown_detector")
        assert result == 0.75

    def test_checksum_detector_applies_floor(self):
        """Checksum detector applies floor to low values."""
        # Raw 0.5 should be raised to checksum floor (0.85)
        result = normalize_confidence(0.5, "checksum")
        assert result == 0.85

    def test_structured_detector_applies_floor(self):
        """Structured detector applies floor to low values."""
        result = normalize_confidence(0.5, "structured")
        assert result == 0.90

    def test_known_entity_applies_floor(self):
        """Known entity detector applies floor."""
        result = normalize_confidence(0.5, "known_entity")
        assert result == 0.95

    def test_high_value_not_changed(self):
        """High values within range are not changed."""
        result = normalize_confidence(0.99, "checksum")
        assert result == 0.99

    def test_clamps_to_ceiling(self):
        """Values above ceiling are clamped."""
        result = normalize_confidence(1.5, "phi_bert")
        assert result == 1.0

    def test_clamps_to_floor(self):
        """Values below floor are clamped."""
        result = normalize_confidence(-0.5, "phi_bert")
        assert result == 0.0

    def test_nan_returns_floor(self):
        """NaN value returns detector floor (conservative)."""
        result = normalize_confidence(float('nan'), "checksum")
        assert result == 0.85  # Checksum floor

    def test_positive_inf_returns_ceiling(self):
        """Positive infinity returns detector ceiling."""
        result = normalize_confidence(float('inf'), "phi_bert")
        assert result == 1.0

    def test_negative_inf_returns_floor(self):
        """Negative infinity returns detector floor."""
        result = normalize_confidence(float('-inf'), "checksum")
        assert result == 0.85  # Checksum floor


# =============================================================================
# CLAMP CONFIDENCE TESTS
# =============================================================================

class TestClampConfidence:
    """Tests for clamp_confidence()."""

    def test_value_in_range_unchanged(self):
        """Values in [0, 1] are unchanged."""
        assert clamp_confidence(0.5) == 0.5
        assert clamp_confidence(0.0) == 0.0
        assert clamp_confidence(1.0) == 1.0

    def test_clamps_above_one(self):
        """Values above 1.0 are clamped."""
        assert clamp_confidence(1.5) == 1.0
        assert clamp_confidence(100.0) == 1.0

    def test_clamps_below_zero(self):
        """Values below 0.0 are clamped."""
        assert clamp_confidence(-0.5) == 0.0
        assert clamp_confidence(-100.0) == 0.0

    def test_nan_returns_zero(self):
        """NaN returns 0.0 (conservative)."""
        assert clamp_confidence(float('nan')) == 0.0

    def test_positive_inf_returns_one(self):
        """Positive infinity returns 1.0."""
        assert clamp_confidence(float('inf')) == 1.0

    def test_negative_inf_returns_zero(self):
        """Negative infinity returns 0.0."""
        assert clamp_confidence(float('-inf')) == 0.0


# =============================================================================
# NORMALIZE SPAN CONFIDENCE TESTS
# =============================================================================

class TestNormalizeSpanConfidence:
    """Tests for normalize_span_confidence()."""

    def test_returns_new_span_when_changed(self):
        """Returns new span when confidence changes."""
        span = make_span("123-45-6789", entity_type="SSN", confidence=0.5, detector="checksum")
        result = normalize_span_confidence(span)

        assert result is not span  # New span created
        assert result.confidence == 0.85  # Checksum floor applied

    def test_returns_same_span_when_unchanged(self):
        """Returns same span when confidence doesn't change."""
        span = make_span("John Smith", confidence=0.9, detector="phi_bert")
        result = normalize_span_confidence(span)

        assert result is span  # Same span returned

    def test_preserves_all_span_fields(self):
        """All span fields are preserved in new span."""
        span = Span(
            start=10,
            end=21,
            text="123-45-6789",
            entity_type="SSN",
            confidence=0.5,
            detector="checksum",
            tier=Tier.PATTERN,
            safe_harbor_value="***-**-6789",
            needs_review=True,
            review_reason="Low confidence",
        )
        result = normalize_span_confidence(span)

        assert result.start == 10
        assert result.end == 21
        assert result.text == "123-45-6789"
        assert result.entity_type == "SSN"
        assert result.detector == "checksum"
        assert result.tier == Tier.PATTERN
        assert result.safe_harbor_value == "***-**-6789"
        assert result.needs_review is True
        assert result.review_reason == "Low confidence"
        # Only confidence changed
        assert result.confidence == 0.85


# =============================================================================
# NORMALIZE SPANS CONFIDENCE TESTS
# =============================================================================

class TestNormalizeSpansConfidence:
    """Tests for normalize_spans_confidence()."""

    def test_normalizes_all_spans(self):
        """All spans in list are normalized."""
        spans = [
            make_span("SSN1", confidence=0.5, detector="checksum"),
            make_span("SSN2", confidence=0.5, detector="structured"),
            make_span("Name", confidence=0.9, detector="phi_bert"),
        ]
        result = normalize_spans_confidence(spans)

        assert len(result) == 3
        assert result[0].confidence == 0.85  # Checksum floor
        assert result[1].confidence == 0.90  # Structured floor
        assert result[2].confidence == 0.9   # Unchanged

    def test_empty_list_returns_empty(self):
        """Empty list returns empty list."""
        result = normalize_spans_confidence([])
        assert result == []

    def test_preserves_order(self):
        """Order of spans is preserved."""
        spans = [
            make_span("First", confidence=0.5),
            make_span("Second", confidence=0.6),
            make_span("Third", confidence=0.7),
        ]
        result = normalize_spans_confidence(spans)

        assert result[0].text == "First"
        assert result[1].text == "Second"
        assert result[2].text == "Third"


# =============================================================================
# COMBINE CONFIDENCES TESTS
# =============================================================================

class TestCombineConfidences:
    """Tests for combine_confidences()."""

    def test_max_method(self):
        """Max method returns maximum value."""
        result = combine_confidences([0.5, 0.8, 0.3], method="max")
        assert result == 0.8

    def test_avg_method(self):
        """Avg method returns average value."""
        result = combine_confidences([0.5, 0.8, 0.3], method="avg")
        assert result == pytest.approx(0.533, rel=0.01)

    def test_weighted_avg_method(self):
        """Weighted avg method weights by confidence."""
        result = combine_confidences([0.5, 0.9], method="weighted_avg")
        # weighted_sum = 0.5*0.5 + 0.9*0.9 = 0.25 + 0.81 = 1.06
        # total_weight = 0.5 + 0.9 = 1.4
        # result = 1.06 / 1.4 ≈ 0.757
        assert result == pytest.approx(0.757, rel=0.01)

    def test_default_method_is_max(self):
        """Default method is max."""
        result = combine_confidences([0.3, 0.9, 0.5])
        assert result == 0.9

    def test_empty_list_returns_zero(self):
        """Empty list returns 0.0."""
        assert combine_confidences([]) == 0.0
        assert combine_confidences([], method="avg") == 0.0
        assert combine_confidences([], method="weighted_avg") == 0.0

    def test_single_value_returns_that_value(self):
        """Single value returns that value."""
        assert combine_confidences([0.75], method="max") == 0.75
        assert combine_confidences([0.75], method="avg") == 0.75
        assert combine_confidences([0.75], method="weighted_avg") == 0.75

    def test_weighted_avg_with_all_zeros(self):
        """Weighted avg with all zeros returns 0.0."""
        result = combine_confidences([0.0, 0.0, 0.0], method="weighted_avg")
        assert result == 0.0

    def test_unknown_method_raises(self):
        """Unknown method raises ValueError."""
        with pytest.raises(ValueError, match="Unknown combination method"):
            combine_confidences([0.5, 0.8], method="unknown")


# =============================================================================
# CONFIDENCE MEETS THRESHOLD TESTS
# =============================================================================

class TestConfidenceMeetsThreshold:
    """Tests for confidence_meets_threshold()."""

    def test_meets_threshold(self):
        """Confidence >= threshold returns True."""
        assert confidence_meets_threshold(0.8, 0.7) is True
        assert confidence_meets_threshold(0.7, 0.7) is True

    def test_below_threshold(self):
        """Confidence < threshold returns False."""
        assert confidence_meets_threshold(0.6, 0.7) is False

    def test_with_detector_normalization(self):
        """Detector name causes normalization before comparison."""
        # Raw 0.5 with checksum floor → 0.85, which is >= 0.8
        result = confidence_meets_threshold(0.5, 0.8, detector="checksum")
        assert result is True

    def test_without_detector_no_normalization(self):
        """Without detector, no normalization applied."""
        # Raw 0.5 without normalization is < 0.8
        result = confidence_meets_threshold(0.5, 0.8)
        assert result is False


# =============================================================================
# CONFIDENCE LEVEL CLASS TESTS
# =============================================================================

class TestConfidenceLevel:
    """Tests for ConfidenceLevel class constants."""

    def test_verified_is_highest(self):
        """VERIFIED is the highest threshold."""
        assert ConfidenceLevel.VERIFIED == 0.95
        assert ConfidenceLevel.VERIFIED > ConfidenceLevel.HIGH

    def test_levels_are_ordered(self):
        """Levels are in descending order."""
        assert ConfidenceLevel.VERIFIED > ConfidenceLevel.HIGH
        assert ConfidenceLevel.HIGH > ConfidenceLevel.MEDIUM
        assert ConfidenceLevel.MEDIUM > ConfidenceLevel.LOW
        assert ConfidenceLevel.LOW > ConfidenceLevel.MINIMUM

    def test_specific_values(self):
        """Specific threshold values are correct."""
        assert ConfidenceLevel.VERIFIED == 0.95
        assert ConfidenceLevel.HIGH == 0.85
        assert ConfidenceLevel.MEDIUM == 0.70
        assert ConfidenceLevel.LOW == 0.50
        assert ConfidenceLevel.MINIMUM == 0.30


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for confidence normalization."""

    def test_exact_boundary_values(self):
        """Exact boundary values are handled correctly."""
        assert clamp_confidence(0.0) == 0.0
        assert clamp_confidence(1.0) == 1.0

    def test_very_small_positive(self):
        """Very small positive values are preserved."""
        result = clamp_confidence(0.0001)
        assert result == 0.0001

    def test_very_close_to_one(self):
        """Values very close to 1 are preserved."""
        result = clamp_confidence(0.9999)
        assert result == 0.9999

    def test_detector_name_case_sensitivity(self):
        """Detector names are case-sensitive."""
        # "phi_bert" exists, "PHI_BERT" uses default
        result1 = normalize_confidence(0.5, "phi_bert")
        result2 = normalize_confidence(0.5, "PHI_BERT")
        # Both should be 0.5 since phi_bert is passthrough and default is also passthrough
        assert result1 == 0.5
        assert result2 == 0.5

    def test_multiple_spans_with_mixed_detectors(self):
        """Multiple spans with different detectors are handled correctly."""
        spans = [
            make_span("SSN", confidence=0.5, detector="checksum"),
            make_span("Name", confidence=0.5, detector="phi_bert"),
            make_span("Label", confidence=0.5, detector="structured"),
            make_span("Unknown", confidence=0.5, detector="unknown_detector"),
        ]
        result = normalize_spans_confidence(spans)

        assert result[0].confidence == 0.85  # checksum floor
        assert result[1].confidence == 0.5   # phi_bert passthrough
        assert result[2].confidence == 0.90  # structured floor
        assert result[3].confidence == 0.5   # default passthrough
