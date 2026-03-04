"""Tests for multi-model calibration threshold and ensemble boost tuning.

Covers:
- _calibrated_threshold dispatching to GLiNER, PHI, and multilingual tables
- Ensemble boost triple-agreement bonus
- Cross-model Platt scaling consistency
"""

import math

import pytest

from openlabels.core.detectors.orchestrator import _calibrated_threshold
from openlabels.core.types import Span, Tier


def _make_ml_span(
    entity_type: str = "FIRSTNAME",
    confidence: float = 0.50,
    detector: str = "gliner",
    detector_label: str | None = "first name",
    start: int = 0,
    text: str = "Alice",
) -> Span:
    """Build a minimal ML span for threshold testing."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=Tier.ML,
        detector_label=detector_label,
    )


# ---------------------------------------------------------------------------
# _calibrated_threshold: multi-model dispatch
# ---------------------------------------------------------------------------


class TestCalibratedThresholdGliner:
    """_calibrated_threshold uses GLiNER calibration table for gliner spans."""

    def test_known_label_raises_threshold(self):
        """GLiNER 'first name' (temp=1.65) raises threshold above base."""
        span = _make_ml_span(detector="gliner", detector_label="first name")
        base = 0.52
        result = _calibrated_threshold(span, base)
        assert result > base

    def test_identity_label_returns_base(self):
        """GLiNER 'phone number' (temp=1.0) returns base threshold."""
        span = _make_ml_span(detector="gliner", detector_label="phone number")
        base = 0.52
        result = _calibrated_threshold(span, base)
        assert result == pytest.approx(base, abs=1e-6)

    def test_unknown_label_returns_base(self):
        """Unknown label in GLiNER table falls back to base."""
        span = _make_ml_span(detector="gliner", detector_label="unknown_entity_xyz")
        base = 0.55
        result = _calibrated_threshold(span, base)
        assert result == base

    def test_no_detector_label_returns_base(self):
        """Span with no detector_label returns base."""
        span = _make_ml_span(detector="gliner", detector_label=None)
        base = 0.52
        result = _calibrated_threshold(span, base)
        assert result == base


class TestCalibratedThresholdPHI:
    """_calibrated_threshold uses PHI calibration table for stanford_phi spans."""

    def test_patient_label_raises_threshold(self):
        """PHI 'PATIENT' (temp=1.65) raises threshold above base."""
        span = _make_ml_span(
            detector="stanford_phi",
            detector_label="PATIENT",
            entity_type="NAME_PATIENT",
        )
        base = 0.52
        result = _calibrated_threshold(span, base)
        assert result > base
        # temp=1.65, scaling=0.09 → base + 0.65*0.09 = 0.5785
        assert result == pytest.approx(min(0.63, base + 0.65 * 0.09), abs=1e-6)

    def test_account_label_mild_raise(self):
        """PHI 'ACCOUNT' (temp=1.10) gives mild threshold increase."""
        span = _make_ml_span(
            detector="stanford_phi",
            detector_label="ACCOUNT",
            entity_type="ACCOUNT_NUMBER",
        )
        base = 0.55
        result = _calibrated_threshold(span, base)
        # temp=1.10 → base + 0.10*0.09 = 0.559
        assert result == pytest.approx(0.559, abs=1e-6)

    def test_phi_unknown_label_returns_base(self):
        """PHI label not in PHI_CALIBRATION falls back to base."""
        span = _make_ml_span(
            detector="stanford_phi",
            detector_label="UNKNOWN_PHI_LABEL",
        )
        base = 0.55
        result = _calibrated_threshold(span, base)
        assert result == base

    def test_phi_email_below_one_returns_base(self):
        """PHI 'EMAIL' (temp=0.95 < 1.0) returns base (no increase)."""
        span = _make_ml_span(
            detector="stanford_phi",
            detector_label="EMAIL",
            entity_type="EMAIL",
        )
        base = 0.55
        result = _calibrated_threshold(span, base)
        assert result == base


class TestCalibratedThresholdMultilingual:
    """_calibrated_threshold uses multilingual table for gliner_multilingual."""

    def test_first_name_raises_threshold(self):
        """Multilingual 'first name' (temp=1.25) raises threshold."""
        span = _make_ml_span(
            detector="gliner_multilingual",
            detector_label="first name",
        )
        base = 0.52
        result = _calibrated_threshold(span, base)
        assert result > base
        # temp=1.25 → base + 0.25*0.09 = 0.5425
        assert result == pytest.approx(0.5425, abs=1e-6)

    def test_city_raises_threshold(self):
        """Multilingual 'city' (temp=1.35) raises threshold."""
        span = _make_ml_span(
            detector="gliner_multilingual",
            detector_label="city",
            entity_type="CITY",
        )
        base = 0.55
        result = _calibrated_threshold(span, base)
        # temp=1.35 → base + 0.35*0.09 = 0.5815
        assert result == pytest.approx(0.5815, abs=1e-6)

    def test_email_below_one_returns_base(self):
        """Multilingual 'email address' (temp=0.95) returns base."""
        span = _make_ml_span(
            detector="gliner_multilingual",
            detector_label="email address",
            entity_type="EMAIL",
        )
        base = 0.55
        result = _calibrated_threshold(span, base)
        assert result == base


class TestCalibratedThresholdCap:
    """Threshold is capped at 0.63."""

    def test_high_temp_capped(self):
        """Very high temperature is capped at 0.63."""
        # GLiNER "country" has temp=2.00 → base + 1.0*0.09 = 0.64 → capped at 0.63
        span = _make_ml_span(detector="gliner", detector_label="country")
        base = 0.55
        result = _calibrated_threshold(span, base)
        assert result == pytest.approx(0.63, abs=1e-6)

    def test_cap_applies_across_models(self):
        """Cap applies regardless of which calibration table is used."""
        # PHI GEO has temp=1.65 → 0.55 + 0.65*0.09 = 0.6085
        span = _make_ml_span(
            detector="stanford_phi",
            detector_label="GEO",
            entity_type="ADDRESS",
        )
        result = _calibrated_threshold(span, 0.55)
        assert result <= 0.63


# ---------------------------------------------------------------------------
# Cross-model Platt scaling consistency
# ---------------------------------------------------------------------------


class TestCrossModelCalibration:
    """Verify all three calibration tables produce valid output."""

    def test_gliner_calibration_all_finite(self):
        """Every GLiNER label produces finite calibrated scores."""
        from openlabels.core.detectors.gliner_calibration import (
            GLINER_CALIBRATION,
            calibrate_gliner_score,
        )
        for label in GLINER_CALIBRATION:
            for raw in [0.01, 0.25, 0.5, 0.75, 0.99]:
                result = calibrate_gliner_score(label, raw)
                assert math.isfinite(result), f"GLiNER {label} at {raw}"
                assert 0.0 < result < 1.0

    def test_phi_calibration_all_finite(self):
        """Every PHI label produces finite calibrated scores."""
        from openlabels.core.detectors.gliner_calibration import _platt_transform
        from openlabels.core.detectors.phi_detector import PHI_CALIBRATION
        for label, (temp, bias) in PHI_CALIBRATION.items():
            for raw in [0.01, 0.25, 0.5, 0.75, 0.99]:
                result = _platt_transform(raw, temp, bias)
                assert math.isfinite(result), f"PHI {label} at {raw}"
                assert 0.0 < result < 1.0

    def test_multilingual_calibration_all_finite(self):
        """Every multilingual label produces finite calibrated scores."""
        from openlabels.core.detectors.gliner_calibration import _platt_transform
        from openlabels.core.detectors.multilingual_gliner import (
            MULTILINGUAL_CALIBRATION,
        )
        for label, (temp, bias) in MULTILINGUAL_CALIBRATION.items():
            for raw in [0.01, 0.25, 0.5, 0.75, 0.99]:
                result = _platt_transform(raw, temp, bias)
                assert math.isfinite(result), f"Multilingual {label} at {raw}"
                assert 0.0 < result < 1.0

    def test_all_temperatures_positive(self):
        """All calibration temperatures are > 0 across all tables."""
        from openlabels.core.detectors.gliner_calibration import GLINER_CALIBRATION
        from openlabels.core.detectors.multilingual_gliner import (
            MULTILINGUAL_CALIBRATION,
        )
        from openlabels.core.detectors.phi_detector import PHI_CALIBRATION

        for name, table in [
            ("GLiNER", GLINER_CALIBRATION),
            ("PHI", PHI_CALIBRATION),
            ("Multilingual", MULTILINGUAL_CALIBRATION),
        ]:
            for label, (temp, _bias) in table.items():
                assert temp > 0, f"{name} {label} has temp={temp}"


# ---------------------------------------------------------------------------
# Ensemble boost: triple-agreement bonus
# ---------------------------------------------------------------------------


class TestEnsembleTripleBonus:
    """Test that 3-model agreement gets the enhanced triple bonus."""

    def _make_orchestrator(self):
        from openlabels.core.detectors.config import DetectionConfig
        from openlabels.core.detectors.orchestrator import DetectorOrchestrator

        config = DetectionConfig(
            enable_ml=False, enable_checksum=False, enable_secrets=False,
            enable_financial=False, enable_government=False, enable_patterns=False,
            enable_phi=False, enable_context_keywords=False,
        )
        return DetectorOrchestrator(config=config)

    def _make_span_for_ensemble(
        self,
        detector: str,
        entity_type: str = "FIRSTNAME",
        confidence: float = 0.45,
        raw_confidence: float = 0.80,
        start: int = 0,
        text: str = "Alice",
    ) -> Span:
        return Span(
            start=start,
            end=start + len(text),
            text=text,
            entity_type=entity_type,
            confidence=confidence,
            detector=detector,
            tier=Tier.ML,
            raw_confidence=raw_confidence,
        )

    def test_two_detectors_get_base_boost(self):
        """Two detectors agreeing get base boost (0.10-0.20), no triple bonus."""
        orch = self._make_orchestrator()
        spans = [
            self._make_span_for_ensemble("gliner", raw_confidence=0.80),
            self._make_span_for_ensemble("stanford_phi", raw_confidence=0.80,
                                         entity_type="NAME_PATIENT"),
        ]
        result = orch._apply_ensemble_boost(spans)
        # First span should be boosted
        assert result[0].confidence > 0.45
        # But NOT triple-boosted: boost = BOOST_MIN + t*(BOOST_MAX-BOOST_MIN)
        # t = (0.80-0.5)/0.4 = 0.75 → boost = 0.10 + 0.75*0.10 = 0.175
        expected_boost = 0.10 + 0.75 * (0.20 - 0.10)
        assert result[0].confidence == pytest.approx(0.45 + expected_boost, abs=0.01)

    def test_three_detectors_get_triple_bonus(self):
        """Three detectors agreeing get base boost PLUS triple bonus (0.12)."""
        orch = self._make_orchestrator()
        spans = [
            self._make_span_for_ensemble("gliner", raw_confidence=0.80),
            self._make_span_for_ensemble("stanford_phi", raw_confidence=0.80,
                                         entity_type="NAME_PATIENT"),
            self._make_span_for_ensemble("gliner_multilingual", raw_confidence=0.80),
        ]
        result = orch._apply_ensemble_boost(spans)
        # First span gets base boost + triple bonus
        t = (0.80 - 0.5) / 0.4  # 0.75
        base_boost = 0.10 + t * (0.20 - 0.10)  # 0.175
        triple_bonus = 0.12
        total_boost = base_boost + triple_bonus  # 0.295
        assert result[0].confidence == pytest.approx(0.45 + total_boost, abs=0.01)

    def test_triple_bonus_is_0_12(self):
        """Verify triple bonus constant is 0.12."""
        orch = self._make_orchestrator()
        assert orch._ENSEMBLE_TRIPLE_EXTRA == 0.12

    def test_no_boost_for_single_detector(self):
        """Single detector gets no boost."""
        orch = self._make_orchestrator()
        spans = [
            self._make_span_for_ensemble("gliner", raw_confidence=0.80),
        ]
        result = orch._apply_ensemble_boost(spans)
        assert result[0].confidence == 0.45

    def test_no_boost_for_different_categories(self):
        """Detectors with different entity categories don't boost each other."""
        orch = self._make_orchestrator()
        spans = [
            self._make_span_for_ensemble("gliner", entity_type="FIRSTNAME",
                                         raw_confidence=0.80),
            self._make_span_for_ensemble("stanford_phi", entity_type="DATE",
                                         raw_confidence=0.80),
        ]
        result = orch._apply_ensemble_boost(spans)
        # Neither should be boosted — different categories
        assert result[0].confidence == 0.45
        assert result[1].confidence == 0.45


# ---------------------------------------------------------------------------
# PHI-specific calibration score tests
# ---------------------------------------------------------------------------


class TestPHICalibrationScores:
    """Test PHI calibration produces expected score adjustments."""

    def test_patient_dampened_heavily(self):
        """PATIENT (temp=1.65, bias=0.12) heavily dampens high confidence."""
        from openlabels.core.detectors.phi_detector import _calibrate_phi_score
        raw = 0.90
        result = _calibrate_phi_score("PATIENT", raw)
        assert result < raw
        # Should be significantly dampened
        assert result < 0.85

    def test_account_mild_dampening(self):
        """ACCOUNT (temp=1.10, bias=0.02) only mildly dampens."""
        from openlabels.core.detectors.phi_detector import _calibrate_phi_score
        raw = 0.85
        result = _calibrate_phi_score("ACCOUNT", raw)
        assert result < raw
        # But not by much — close to raw
        assert result > 0.75

    def test_email_boosted(self):
        """EMAIL (temp=0.95, bias=-0.03) slightly boosts confidence."""
        from openlabels.core.detectors.phi_detector import _calibrate_phi_score
        raw = 0.75
        result = _calibrate_phi_score("EMAIL", raw)
        assert result > raw


# ---------------------------------------------------------------------------
# Multilingual calibration score tests
# ---------------------------------------------------------------------------


class TestMultilingualCalibrationScores:
    """Test multilingual calibration produces expected score adjustments."""

    def test_first_name_dampened(self):
        """Multilingual 'first name' (temp=1.35) dampens high scores."""
        from openlabels.core.detectors.multilingual_gliner import (
            _calibrate_multilingual_score,
        )
        raw = 0.85
        result = _calibrate_multilingual_score("first name", raw)
        assert result < raw

    def test_city_dampened(self):
        """Multilingual 'city' (temp=1.35) dampens city scores."""
        from openlabels.core.detectors.multilingual_gliner import (
            _calibrate_multilingual_score,
        )
        raw = 0.80
        result = _calibrate_multilingual_score("city", raw)
        assert result < raw

    def test_email_boosted(self):
        """Multilingual 'email address' (temp=0.95) boosts confidence."""
        from openlabels.core.detectors.multilingual_gliner import (
            _calibrate_multilingual_score,
        )
        raw = 0.70
        result = _calibrate_multilingual_score("email address", raw)
        assert result > raw

    def test_bank_account_mild_dampening(self):
        """Multilingual 'bank account number' (temp=1.10) mildly dampened."""
        from openlabels.core.detectors.multilingual_gliner import (
            _calibrate_multilingual_score,
        )
        raw = 0.80
        result = _calibrate_multilingual_score("bank account number", raw)
        assert result < raw
        # Only mild dampening — close to raw
        assert result > 0.70
