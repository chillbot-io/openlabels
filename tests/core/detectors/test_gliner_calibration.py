"""Tests for GLiNER Platt scaling confidence calibration."""

import math

import pytest

from openlabels.core.detectors.gliner_calibration import (
    GLINER_CALIBRATION,
    calibrate_gliner_score,
)


class TestPlattScalingIdentity:
    """Test that identity parameters (temp=1.0, bias=0.0) preserve score."""

    def test_identity_at_half(self):
        """Score 0.5 with identity params returns 0.5."""
        result = calibrate_gliner_score("swift code", 0.5)
        assert result == pytest.approx(0.5, abs=1e-6)

    def test_identity_preserves_score(self):
        """Identity transform (1.0, 0.0) should preserve any score."""
        for score in [0.1, 0.3, 0.5, 0.7, 0.9]:
            result = calibrate_gliner_score("swift code", score)
            assert result == pytest.approx(score, abs=1e-6)


class TestPlattScalingTemperature:
    """Test temperature scaling effects."""

    def test_high_temperature_reduces_confidence(self):
        """Temperature > 1 should reduce overconfident scores toward 0.5."""
        # "phone number" has temp=1.40, bias=0.10
        raw = 0.90
        result = calibrate_gliner_score("phone number", raw)
        assert result < raw  # Tempered overconfidence

    def test_low_temperature_sharpens_confidence(self):
        """Temperature < 1 should move confident scores further from 0.5."""
        # "email address" has temp=0.90, bias=-0.05
        raw = 0.80
        result = calibrate_gliner_score("email address", raw)
        assert result > raw  # Sharpened toward 1.0

    def test_temperature_on_low_score(self):
        """High temperature on a low score pushes it toward 0.5."""
        # "age" has temp=1.50, bias=0.12
        raw = 0.45
        result = calibrate_gliner_score("age", raw)
        # Bias shifts down, temperature spreads → should be near or above 0.5
        assert 0.0 < result < 1.0


class TestPlattScalingBias:
    """Test bias adjustment effects."""

    def test_positive_bias_shifts_down(self):
        """Positive bias (model is overconfident) reduces calibrated score."""
        # "person name" has temp=1.25, bias=0.05
        raw = 0.80
        result = calibrate_gliner_score("person name", raw)
        assert result < raw

    def test_negative_bias_shifts_up(self):
        """Negative bias (model is underconfident) increases calibrated score."""
        # "email address" has temp=0.90, bias=-0.05
        raw = 0.70
        result = calibrate_gliner_score("email address", raw)
        assert result > raw


class TestPlattScalingUnknownLabel:
    """Unknown labels should return raw score unchanged."""

    def test_unknown_label_returns_raw(self):
        result = calibrate_gliner_score("alien_entity", 0.75)
        assert result == 0.75

    def test_empty_label_returns_raw(self):
        result = calibrate_gliner_score("", 0.60)
        assert result == 0.60


class TestPlattScalingEdgeCases:
    """Edge cases for numerical stability."""

    def test_score_near_zero(self):
        """Score very close to 0 doesn't cause math errors."""
        result = calibrate_gliner_score("person name", 0.001)
        assert 0.0 < result < 1.0
        assert math.isfinite(result)

    def test_score_near_one(self):
        """Score very close to 1 doesn't cause math errors."""
        result = calibrate_gliner_score("person name", 0.999)
        assert 0.0 < result < 1.0
        assert math.isfinite(result)

    def test_score_exactly_zero(self):
        """Score of exactly 0.0 is clamped and doesn't crash."""
        result = calibrate_gliner_score("person name", 0.0)
        assert 0.0 < result < 1.0
        assert math.isfinite(result)

    def test_score_exactly_one(self):
        """Score of exactly 1.0 is clamped and doesn't crash."""
        result = calibrate_gliner_score("person name", 1.0)
        assert 0.0 < result < 1.0
        assert math.isfinite(result)

    def test_all_calibrated_labels_produce_finite_output(self):
        """Every label in the calibration table produces finite output."""
        for label in GLINER_CALIBRATION:
            for raw in [0.01, 0.25, 0.5, 0.75, 0.99]:
                result = calibrate_gliner_score(label, raw)
                assert math.isfinite(result), f"{label} at {raw} produced {result}"
                assert 0.0 < result < 1.0


class TestPlattScalingMonotonicity:
    """Calibration should preserve ordering of raw scores."""

    @pytest.mark.parametrize("label", list(GLINER_CALIBRATION.keys())[:10])
    def test_monotonic_increasing(self, label):
        """Higher raw scores should produce higher calibrated scores."""
        scores = [0.2, 0.4, 0.6, 0.8]
        calibrated = [calibrate_gliner_score(label, s) for s in scores]
        for i in range(len(calibrated) - 1):
            assert calibrated[i] < calibrated[i + 1], (
                f"Non-monotonic for {label}: "
                f"{scores[i]}→{calibrated[i]} vs {scores[i+1]}→{calibrated[i+1]}"
            )
