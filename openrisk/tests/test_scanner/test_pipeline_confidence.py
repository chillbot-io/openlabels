"""
Tests for openlabels.adapters.scanner.pipeline.confidence module.

Tests confidence normalization and combination logic.
"""

import pytest
import math
from unittest.mock import Mock


class TestNormalizeConfidence:
    """Tests for normalize_confidence function."""

    def test_passthrough_for_valid_value(self):
        """Should pass through valid values unchanged."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_confidence

        result = normalize_confidence(0.75, "patterns")
        assert result == 0.75

    def test_clamps_above_one(self):
        """Should clamp values above 1.0."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_confidence

        result = normalize_confidence(1.5, "patterns")
        assert result == 1.0

    def test_clamps_below_zero(self):
        """Should clamp values below 0.0."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_confidence

        result = normalize_confidence(-0.5, "patterns")
        assert result == 0.0

    def test_nan_returns_floor(self):
        """NaN should return detector floor."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_confidence

        result = normalize_confidence(float('nan'), "patterns")
        assert result == 0.0  # patterns floor is 0.0

    def test_nan_returns_checksum_floor(self):
        """NaN for checksum detector should return 0.85 floor."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_confidence

        result = normalize_confidence(float('nan'), "checksum")
        assert result == 0.85

    def test_positive_infinity_returns_ceil(self):
        """Positive infinity should return ceiling."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_confidence

        result = normalize_confidence(float('inf'), "patterns")
        assert result == 1.0

    def test_negative_infinity_returns_floor(self):
        """Negative infinity should return floor."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_confidence

        result = normalize_confidence(float('-inf'), "patterns")
        assert result == 0.0

    def test_checksum_detector_floor(self):
        """Checksum detector should have 0.85 floor."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_confidence

        # Low value should be raised to floor
        result = normalize_confidence(0.5, "checksum")
        assert result == 0.85

    def test_structured_detector_floor(self):
        """Structured detector should have 0.90 floor."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_confidence

        result = normalize_confidence(0.5, "structured")
        assert result == 0.90

    def test_known_entity_detector_floor(self):
        """Known entity detector should have 0.95 floor."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_confidence

        result = normalize_confidence(0.5, "known_entity")
        assert result == 0.95

    def test_secrets_detector_floor(self):
        """Secrets detector should have 0.80 floor."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_confidence

        result = normalize_confidence(0.5, "secrets")
        assert result == 0.80

    def test_unknown_detector_uses_default(self):
        """Unknown detector should use default calibration."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_confidence

        result = normalize_confidence(0.75, "unknown_detector")
        assert result == 0.75


class TestClampConfidence:
    """Tests for clamp_confidence function."""

    def test_valid_value_unchanged(self):
        """Valid values should be unchanged."""
        from openlabels.adapters.scanner.pipeline.confidence import clamp_confidence

        assert clamp_confidence(0.5) == 0.5
        assert clamp_confidence(0.0) == 0.0
        assert clamp_confidence(1.0) == 1.0

    def test_clamps_above_one(self):
        """Values above 1 should be clamped."""
        from openlabels.adapters.scanner.pipeline.confidence import clamp_confidence

        assert clamp_confidence(1.5) == 1.0
        assert clamp_confidence(100.0) == 1.0

    def test_clamps_below_zero(self):
        """Values below 0 should be clamped."""
        from openlabels.adapters.scanner.pipeline.confidence import clamp_confidence

        assert clamp_confidence(-0.5) == 0.0
        assert clamp_confidence(-100.0) == 0.0

    def test_nan_returns_zero(self):
        """NaN should return 0.0."""
        from openlabels.adapters.scanner.pipeline.confidence import clamp_confidence

        assert clamp_confidence(float('nan')) == 0.0

    def test_positive_infinity_returns_one(self):
        """Positive infinity should return 1.0."""
        from openlabels.adapters.scanner.pipeline.confidence import clamp_confidence

        assert clamp_confidence(float('inf')) == 1.0

    def test_negative_infinity_returns_zero(self):
        """Negative infinity should return 0.0."""
        from openlabels.adapters.scanner.pipeline.confidence import clamp_confidence

        assert clamp_confidence(float('-inf')) == 0.0


class TestCombineConfidences:
    """Tests for combine_confidences function."""

    def test_max_method(self):
        """Max method should return maximum value."""
        from openlabels.adapters.scanner.pipeline.confidence import combine_confidences

        result = combine_confidences([0.5, 0.8, 0.6], method="max")
        assert result == 0.8

    def test_avg_method(self):
        """Avg method should return average."""
        from openlabels.adapters.scanner.pipeline.confidence import combine_confidences

        result = combine_confidences([0.4, 0.6, 0.8], method="avg")
        assert abs(result - 0.6) < 0.001

    def test_weighted_avg_method(self):
        """Weighted avg should weight by confidence."""
        from openlabels.adapters.scanner.pipeline.confidence import combine_confidences

        # Higher confidences get more weight
        result = combine_confidences([0.1, 0.9], method="weighted_avg")
        # (0.1*0.1 + 0.9*0.9) / (0.1 + 0.9) = (0.01 + 0.81) / 1.0 = 0.82
        assert abs(result - 0.82) < 0.001

    def test_empty_list_returns_zero(self):
        """Empty list should return 0.0."""
        from openlabels.adapters.scanner.pipeline.confidence import combine_confidences

        assert combine_confidences([], method="max") == 0.0
        assert combine_confidences([], method="avg") == 0.0
        assert combine_confidences([], method="weighted_avg") == 0.0

    def test_single_value(self):
        """Single value should return that value."""
        from openlabels.adapters.scanner.pipeline.confidence import combine_confidences

        assert combine_confidences([0.7], method="max") == 0.7
        assert combine_confidences([0.7], method="avg") == 0.7
        assert combine_confidences([0.7], method="weighted_avg") == 0.7

    def test_default_method_is_max(self):
        """Default method should be max."""
        from openlabels.adapters.scanner.pipeline.confidence import combine_confidences

        result = combine_confidences([0.5, 0.8, 0.6])
        assert result == 0.8

    def test_invalid_method_raises(self):
        """Invalid method should raise ValueError."""
        from openlabels.adapters.scanner.pipeline.confidence import combine_confidences

        with pytest.raises(ValueError) as exc_info:
            combine_confidences([0.5], method="invalid")
        assert "Unknown combination method" in str(exc_info.value)

    def test_weighted_avg_all_zeros(self):
        """Weighted avg with all zeros should return 0."""
        from openlabels.adapters.scanner.pipeline.confidence import combine_confidences

        result = combine_confidences([0.0, 0.0, 0.0], method="weighted_avg")
        assert result == 0.0


class TestNormalizeSpanConfidence:
    """Tests for normalize_span_confidence function."""

    @pytest.fixture
    def sample_span(self):
        """Create a sample span."""
        from openlabels.adapters.scanner.types import Span, Tier

        return Span(
            start=0,
            end=10,
            text="1234567890",
            entity_type="SSN",
            confidence=0.75,
            detector="patterns",
            tier=Tier.PATTERN,
        )

    def test_returns_same_span_if_unchanged(self, sample_span):
        """Should return same span if confidence unchanged."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_span_confidence

        result = normalize_span_confidence(sample_span)
        # patterns detector doesn't change 0.75
        assert result is sample_span

    def test_returns_new_span_if_changed(self):
        """Should return new span if confidence changed."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_span_confidence
        from openlabels.adapters.scanner.types import Span, Tier

        span = Span(
            start=0,
            end=11,
            text="12345678901",  # 11 chars to match span length
            entity_type="SSN",
            confidence=0.5,  # Below checksum floor
            detector="checksum",
            tier=Tier.CHECKSUM,
        )

        result = normalize_span_confidence(span)

        assert result is not span
        assert result.confidence == 0.85  # Raised to floor

    def test_preserves_other_attributes(self):
        """Should preserve all other span attributes."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_span_confidence
        from openlabels.adapters.scanner.types import Span, Tier

        span = Span(
            start=5,
            end=15,
            text="0123456789",  # 10 chars to match span length
            entity_type="PHONE",
            confidence=0.3,  # Below checksum floor
            detector="checksum",
            tier=Tier.CHECKSUM,
            safe_harbor_value="[PHONE]",
            needs_review=True,
            review_reason="test",
        )

        result = normalize_span_confidence(span)

        assert result.start == 5
        assert result.end == 15
        assert result.text == "0123456789"
        assert result.entity_type == "PHONE"
        assert result.detector == "checksum"
        assert result.tier == Tier.CHECKSUM
        assert result.safe_harbor_value == "[PHONE]"
        assert result.needs_review is True
        assert result.review_reason == "test"


class TestNormalizeSpansConfidence:
    """Tests for normalize_spans_confidence function."""

    def test_normalizes_all_spans(self):
        """Should normalize all spans in list."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_spans_confidence
        from openlabels.adapters.scanner.types import Span, Tier

        spans = [
            Span(start=0, end=5, text="12345", entity_type="SSN",
                 confidence=0.3, detector="checksum", tier=Tier.CHECKSUM),
            Span(start=5, end=10, text="67890", entity_type="SSN",
                 confidence=0.4, detector="checksum", tier=Tier.CHECKSUM),
        ]

        result = normalize_spans_confidence(spans)

        assert len(result) == 2
        assert result[0].confidence == 0.85
        assert result[1].confidence == 0.85

    def test_empty_list(self):
        """Should handle empty list."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_spans_confidence

        result = normalize_spans_confidence([])
        assert result == []

    def test_mixed_detectors(self):
        """Should apply correct normalization per detector."""
        from openlabels.adapters.scanner.pipeline.confidence import normalize_spans_confidence
        from openlabels.adapters.scanner.types import Span, Tier

        spans = [
            Span(start=0, end=5, text="12345", entity_type="SSN",
                 confidence=0.5, detector="checksum", tier=Tier.CHECKSUM),
            Span(start=5, end=10, text="email", entity_type="EMAIL",
                 confidence=0.5, detector="patterns", tier=Tier.PATTERN),
        ]

        result = normalize_spans_confidence(spans)

        assert result[0].confidence == 0.85  # checksum floor
        assert result[1].confidence == 0.5   # patterns no floor


class TestConfidenceLevel:
    """Tests for ConfidenceLevel constants."""

    def test_verified_level(self):
        """VERIFIED should be 0.95."""
        from openlabels.adapters.scanner.pipeline.confidence import ConfidenceLevel

        assert ConfidenceLevel.VERIFIED == 0.95

    def test_high_level(self):
        """HIGH should be 0.85."""
        from openlabels.adapters.scanner.pipeline.confidence import ConfidenceLevel

        assert ConfidenceLevel.HIGH == 0.85

    def test_medium_level(self):
        """MEDIUM should be 0.70."""
        from openlabels.adapters.scanner.pipeline.confidence import ConfidenceLevel

        assert ConfidenceLevel.MEDIUM == 0.70

    def test_low_level(self):
        """LOW should be 0.50."""
        from openlabels.adapters.scanner.pipeline.confidence import ConfidenceLevel

        assert ConfidenceLevel.LOW == 0.50

    def test_minimum_level(self):
        """MINIMUM should be 0.30."""
        from openlabels.adapters.scanner.pipeline.confidence import ConfidenceLevel

        assert ConfidenceLevel.MINIMUM == 0.30

    def test_ordering(self):
        """Levels should be properly ordered."""
        from openlabels.adapters.scanner.pipeline.confidence import ConfidenceLevel

        assert ConfidenceLevel.MINIMUM < ConfidenceLevel.LOW
        assert ConfidenceLevel.LOW < ConfidenceLevel.MEDIUM
        assert ConfidenceLevel.MEDIUM < ConfidenceLevel.HIGH
        assert ConfidenceLevel.HIGH < ConfidenceLevel.VERIFIED


class TestDetectorCalibration:
    """Tests for detector calibration configuration."""

    def test_all_calibrations_valid(self):
        """All calibrations should have valid format."""
        from openlabels.adapters.scanner.pipeline.confidence import DETECTOR_CALIBRATION

        for detector, calibration in DETECTOR_CALIBRATION.items():
            assert len(calibration) == 4, f"Invalid calibration for {detector}"
            scale, offset, floor, ceil = calibration
            assert isinstance(scale, (int, float))
            assert isinstance(offset, (int, float))
            assert 0.0 <= floor <= 1.0, f"Invalid floor for {detector}"
            assert 0.0 <= ceil <= 1.0, f"Invalid ceil for {detector}"
            assert floor <= ceil, f"Floor > ceil for {detector}"

    def test_default_calibration_valid(self):
        """Default calibration should be valid."""
        from openlabels.adapters.scanner.pipeline.confidence import DEFAULT_CALIBRATION

        assert len(DEFAULT_CALIBRATION) == 4
        scale, offset, floor, ceil = DEFAULT_CALIBRATION
        assert scale == 1.0
        assert offset == 0.0
        assert floor == 0.0
        assert ceil == 1.0

    def test_ml_detectors_no_floor(self):
        """ML detectors should have no floor."""
        from openlabels.adapters.scanner.pipeline.confidence import DETECTOR_CALIBRATION

        for detector in ["phi_bert", "pii_bert", "phi_bert_onnx", "pii_bert_onnx"]:
            _, _, floor, _ = DETECTOR_CALIBRATION[detector]
            assert floor == 0.0
