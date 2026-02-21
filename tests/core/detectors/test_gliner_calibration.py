"""Tests for GLiNER Platt scaling confidence calibration."""

import json
import math

import pytest

from openlabels.core.detectors.gliner_calibration import (
    GLINER_CALIBRATION,
    calibrate_gliner_score,
    fit_calibration,
    get_active_calibration,
    load_calibration,
    reset_calibration,
    save_calibration,
)


class TestPlattScalingIdentity:
    """Test that identity parameters (temp=1.0, bias=0.0) preserve score."""

    def test_identity_at_half(self):
        """Score 0.5 with identity params returns 0.5."""
        result = calibrate_gliner_score("phone number", 0.5)
        assert result == pytest.approx(0.5, abs=1e-6)

    def test_identity_preserves_score(self):
        """Identity transform (1.0, 0.0) should preserve any score."""
        for score in [0.1, 0.3, 0.5, 0.7, 0.9]:
            result = calibrate_gliner_score("phone number", score)
            assert result == pytest.approx(score, abs=1e-6)


class TestPlattScalingTemperature:
    """Test temperature scaling effects."""

    def test_high_temperature_reduces_confidence(self):
        """Temperature > 1 should reduce overconfident scores toward 0.5."""
        # "person name" has temp=1.35, bias=0.06
        raw = 0.90
        result = calibrate_gliner_score("person name", raw)
        assert result < raw  # Tempered overconfidence

    def test_low_temperature_sharpens_confidence(self):
        """Temperature < 1 should move confident scores further from 0.5."""
        # "email address" has temp=0.90, bias=-0.05
        raw = 0.80
        result = calibrate_gliner_score("email address", raw)
        assert result > raw  # Sharpened toward 1.0

    def test_temperature_on_low_score(self):
        """High temperature on a low score pushes it toward 0.5."""
        # "first name" has temp=2.00, bias=0.185
        raw = 0.45
        result = calibrate_gliner_score("first name", raw)
        # High temp + positive bias → spreads and shifts down
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


class TestCustomCalibration:
    """Test load/save/reset of custom calibration tables."""

    def setup_method(self):
        """Reset calibration before each test."""
        reset_calibration()

    def teardown_method(self):
        """Reset after each test."""
        reset_calibration()

    def test_load_calibration_overrides_builtin(self, tmp_path):
        """Custom calibration overrides built-in table."""
        cal_file = tmp_path / "cal.json"
        cal_file.write_text(json.dumps({
            "person name": [1.0, 0.0],
            "email address": [1.0, 0.0],
        }))
        load_calibration(cal_file)

        # With identity params, score should pass through
        result = calibrate_gliner_score("person name", 0.80)
        assert result == pytest.approx(0.80, abs=1e-6)

    def test_reset_restores_builtin(self, tmp_path):
        """reset_calibration() restores built-in parameters."""
        cal_file = tmp_path / "cal.json"
        cal_file.write_text(json.dumps({"person name": [1.0, 0.0]}))
        load_calibration(cal_file)

        # Identity produces raw score
        assert calibrate_gliner_score("person name", 0.80) == pytest.approx(0.80, abs=1e-6)

        reset_calibration()
        # Built-in has temp > 1 → score is reduced
        assert calibrate_gliner_score("person name", 0.80) < 0.80

    def test_save_and_reload(self, tmp_path):
        """Save then load produces identical calibration."""
        params = {"test_label": (1.25, 0.05), "other_label": (0.9, -0.03)}
        out = tmp_path / "saved.json"
        save_calibration(params, out)

        loaded = load_calibration(out)
        assert loaded["test_label"] == pytest.approx((1.25, 0.05))
        assert loaded["other_label"] == pytest.approx((0.9, -0.03))

    def test_get_active_calibration_default(self):
        """get_active_calibration returns built-in when no custom loaded."""
        active = get_active_calibration()
        assert active == GLINER_CALIBRATION

    def test_get_active_calibration_custom(self, tmp_path):
        """get_active_calibration returns custom table after load."""
        cal_file = tmp_path / "cal.json"
        cal_file.write_text(json.dumps({"person name": [1.5, 0.1]}))
        load_calibration(cal_file)

        active = get_active_calibration()
        assert active == {"person name": (1.5, 0.1)}

    def test_load_invalid_json_raises(self, tmp_path):
        """Loading malformed JSON raises ValueError."""
        cal_file = tmp_path / "bad.json"
        cal_file.write_text(json.dumps({"person name": [1.0]}))  # missing bias
        with pytest.raises(ValueError, match="expected.*temperature.*bias"):
            load_calibration(cal_file)

    def test_load_negative_temperature_raises(self, tmp_path):
        """Temperature <= 0 raises ValueError."""
        cal_file = tmp_path / "bad.json"
        cal_file.write_text(json.dumps({"person name": [-1.0, 0.0]}))
        with pytest.raises(ValueError, match="temperature must be > 0"):
            load_calibration(cal_file)

    def test_load_nonexistent_file_raises(self):
        """Loading a non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_calibration("/tmp/does_not_exist_calibration.json")


class TestFitCalibration:
    """Test fitting Platt scaling from labeled data."""

    def test_fit_identity_on_perfect_predictions(self):
        """Perfect predictions (all correct at high conf) → near identity."""
        labels = ["test"] * 50
        scores = [0.9] * 50
        correct = [True] * 50
        result = fit_calibration(labels, scores, correct)
        assert "test" in result
        temp, bias = result["test"]
        # Should be near identity since model is already well-calibrated
        assert 0.5 < temp < 2.0
        assert -0.5 < bias < 0.5

    def test_fit_with_mixed_correct_incorrect(self):
        """Mixed predictions produce reasonable parameters."""
        labels = ["label_a"] * 100
        scores = [0.9] * 50 + [0.3] * 50
        correct = [True] * 50 + [False] * 50
        result = fit_calibration(labels, scores, correct)
        assert "label_a" in result
        temp, bias = result["label_a"]
        assert temp > 0

    def test_fit_insufficient_samples_defaults_to_identity(self):
        """Labels with < min_samples get identity params."""
        labels = ["rare_label"] * 5
        scores = [0.8] * 5
        correct = [True] * 5
        result = fit_calibration(labels, scores, correct, min_samples=10)
        assert result["rare_label"] == (1.0, 0.0)

    def test_fit_multiple_labels(self):
        """Multiple labels each get their own parameters."""
        labels = ["a"] * 20 + ["b"] * 20
        scores = [0.9] * 20 + [0.5] * 20
        correct = [True] * 20 + [False] * 20
        result = fit_calibration(labels, scores, correct)
        assert "a" in result
        assert "b" in result
        # They should have different parameters
        assert result["a"] != result["b"]

    def test_fit_result_can_be_saved_and_loaded(self, tmp_path):
        """Fitted params can round-trip through save/load."""
        labels = ["x"] * 30
        scores = [0.8] * 15 + [0.3] * 15
        correct = [True] * 15 + [False] * 15
        params = fit_calibration(labels, scores, correct)

        out = tmp_path / "fitted.json"
        save_calibration(params, out)
        loaded = load_calibration(out)
        assert loaded["x"] == pytest.approx(params["x"])
