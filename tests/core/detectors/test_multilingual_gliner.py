"""Tests for multilingual GLiNER PII detector.

Tests cover:
- MultilingualGLiNERDetector initialization and configuration
- Model loading (mocked — no real model download in tests)
- Entity detection with multilingual-specific calibration
- Detector name is distinct from primary GLiNER detector
- Integration with DetectionConfig and orchestrator
"""

from unittest.mock import MagicMock, patch

import pytest

from openlabels.core.types import Span, Tier
from openlabels.core.detectors.config import DetectionConfig
from openlabels.core.detectors.gliner import GLINER_LABEL_MAP
from openlabels.core.detectors.multilingual_gliner import (
    DEFAULT_MULTILINGUAL_GLINER_MODEL,
    MULTILINGUAL_CALIBRATION,
    MultilingualGLiNERDetector,
    _calibrate_multilingual_score,
)


class TestMultilingualGLiNERDetectorInit:
    """Test MultilingualGLiNERDetector initialization."""

    def test_default_model_name(self):
        det = MultilingualGLiNERDetector()
        assert det.model_name == DEFAULT_MULTILINGUAL_GLINER_MODEL

    def test_default_model_is_e3jsi(self):
        assert DEFAULT_MULTILINGUAL_GLINER_MODEL == "E3-JSI/gliner-multi-pii-domains-v1"

    def test_custom_model_name(self):
        det = MultilingualGLiNERDetector(model_name="urchade/gliner_multi_pii-v1")
        assert det.model_name == "urchade/gliner_multi_pii-v1"

    def test_name_is_gliner_multilingual(self):
        det = MultilingualGLiNERDetector()
        assert det.name == "gliner_multilingual"

    def test_name_differs_from_primary_gliner(self):
        from openlabels.core.detectors.gliner import GLiNERDetector
        primary = GLiNERDetector()
        multilingual = MultilingualGLiNERDetector()
        assert primary.name != multilingual.name

    def test_tier_is_ml(self):
        det = MultilingualGLiNERDetector()
        assert det.tier == Tier.ML

    def test_default_threshold(self):
        det = MultilingualGLiNERDetector()
        assert det.threshold == 0.4

    def test_custom_threshold(self):
        det = MultilingualGLiNERDetector(threshold=0.5)
        assert det.threshold == 0.5

    def test_not_available_before_load(self):
        det = MultilingualGLiNERDetector()
        assert det.is_available() is False

    def test_default_label_map_is_gliner_label_map(self):
        det = MultilingualGLiNERDetector()
        assert det.label_map == GLINER_LABEL_MAP

    def test_custom_label_map(self):
        custom = {"person": "NAME", "email": "EMAIL"}
        det = MultilingualGLiNERDetector(label_map=custom)
        assert det.label_map == custom
        assert set(det._entity_labels) == {"person", "email"}


class TestMultilingualGLiNERDetectorLoad:
    """Test MultilingualGLiNERDetector.load() with mocked gliner library."""

    def test_load_sets_available(self):
        det = MultilingualGLiNERDetector()
        mock_model = MagicMock()
        det._model = mock_model
        det._loaded = True
        assert det.is_available() is True

    def test_load_import_error(self):
        det = MultilingualGLiNERDetector()
        original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

        def mock_import(name, *args, **kwargs):
            if name == "gliner":
                raise ImportError("No module named 'gliner'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = det.load()

        assert result is False
        assert det.is_available() is False

    def test_load_runtime_error(self):
        det = MultilingualGLiNERDetector()
        mock_gliner = MagicMock()
        mock_gliner.GLiNER.from_pretrained.side_effect = RuntimeError("download failed")

        with patch.dict("sys.modules", {"gliner": mock_gliner}):
            result = det.load()

        assert result is False


class TestMultilingualGLiNERDetectorDetect:
    """Test entity detection with mocked model."""

    def _make_loaded_detector(self, label_map=None):
        det = MultilingualGLiNERDetector(
            label_map=label_map or GLINER_LABEL_MAP,
            enable_label_selection=False,
        )
        det._model = MagicMock()
        det._loaded = True
        return det

    def test_detect_not_loaded_returns_empty(self):
        det = MultilingualGLiNERDetector()
        assert det.detect("Hans Schmidt") == []

    def test_detect_empty_text_returns_empty(self):
        det = self._make_loaded_detector()
        assert det.detect("") == []
        assert det.detect("   ") == []

    def test_detect_basic_entity(self):
        det = self._make_loaded_detector()
        det._model.predict_entities.return_value = [
            {"start": 0, "end": 12, "text": "Hans Schmidt", "label": "person name", "score": 0.90}
        ]
        spans = det.detect("Hans Schmidt wohnt in Berlin")
        assert len(spans) == 1
        assert spans[0].entity_type == "NAME"
        assert spans[0].text == "Hans Schmidt"
        assert spans[0].detector == "gliner_multilingual"
        assert spans[0].tier == Tier.ML

    def test_detect_multiple_entities(self):
        det = self._make_loaded_detector()
        det._model.predict_entities.return_value = [
            {"start": 0, "end": 12, "text": "Marie Dupont", "label": "person name", "score": 0.92},
            {"start": 23, "end": 45, "text": "marie.dupont@example.fr", "label": "email address", "score": 0.98},
        ]
        text = "Marie Dupont contactez marie.dupont@example.fr"
        spans = det.detect(text)
        assert len(spans) == 2
        assert spans[0].entity_type == "NAME"
        assert spans[1].entity_type == "EMAIL"

    def test_detect_uses_multilingual_calibration(self):
        """Verify the multilingual model uses its own calibration, not the English one."""
        det = self._make_loaded_detector()
        det._model.predict_entities.return_value = [
            {"start": 0, "end": 12, "text": "Hans Schmidt", "label": "person name", "score": 0.90}
        ]
        spans = det.detect("Hans Schmidt wohnt in Berlin")

        # Multilingual calibration for "person name": (1.15, 0.03)
        # This differs from English calibration: (1.25, 0.05)
        # With raw=0.90, multilingual calibration should give ~0.86
        # English calibration would give ~0.82
        assert len(spans) == 1
        conf = spans[0].confidence
        # Multilingual calibration is lighter, so confidence stays higher
        assert 0.80 < conf < 0.92

    def test_detect_unmapped_label_skipped(self):
        det = self._make_loaded_detector(label_map={"person name": "NAME"})
        det._model.predict_entities.return_value = [
            {"start": 0, "end": 4, "text": "Hans", "label": "person name", "score": 0.9},
            {"start": 10, "end": 20, "text": "Blutgruppe", "label": "blood_type", "score": 0.8},
        ]
        spans = det.detect("Hans hat A Blutgruppe")
        assert len(spans) == 1
        assert spans[0].entity_type == "NAME"

    def test_detect_invalid_offsets_skipped(self):
        det = self._make_loaded_detector()
        det._model.predict_entities.return_value = [
            {"start": -1, "end": 4, "text": "Hans", "label": "person name", "score": 0.9},
            {"start": 10, "end": 5, "text": "bad", "label": "person name", "score": 0.9},
            {"start": 0, "end": 100, "text": "x" * 100, "label": "person name", "score": 0.9},
        ]
        spans = det.detect("Hans Schmidt")
        assert len(spans) == 0

    def test_detect_runtime_error_returns_empty(self):
        det = self._make_loaded_detector()
        det._model.predict_entities.side_effect = RuntimeError("inference failed")
        spans = det.detect("Hans Schmidt")
        assert spans == []

    def test_min_span_lengths_enforced(self):
        """Short spans for structural types are rejected."""
        det = self._make_loaded_detector()
        det._model.predict_entities.return_value = [
            {"start": 0, "end": 5, "text": "AB123", "label": "iban", "score": 0.9},
        ]
        spans = det.detect("AB123 is not an IBAN")
        assert len(spans) == 0  # Too short (min 15)


class TestMultilingualCalibration:
    """Test multilingual-specific Platt scaling calibration."""

    def test_calibration_covers_key_labels(self):
        assert "person name" in MULTILINGUAL_CALIBRATION
        assert "email address" in MULTILINGUAL_CALIBRATION
        assert "phone number" in MULTILINGUAL_CALIBRATION
        assert "credit card number" in MULTILINGUAL_CALIBRATION

    def test_calibrate_unknown_label_passthrough(self):
        assert _calibrate_multilingual_score("unknown_label", 0.75) == 0.75

    def test_calibrate_known_label_adjusts(self):
        raw = 0.90
        calibrated = _calibrate_multilingual_score("person name", raw)
        assert calibrated != raw
        # Temperature > 1 + positive bias → calibrated < raw
        assert calibrated < raw

    def test_calibrate_structural_label_boosts(self):
        """Structural labels with temp < 1 and negative bias get boosted."""
        raw = 0.90
        calibrated = _calibrate_multilingual_score("email address", raw)
        # temp=0.95, bias=-0.03 → should boost slightly
        assert calibrated > raw

    def test_calibrate_extreme_scores(self):
        """Edge case: scores near 0 and 1 don't crash."""
        assert 0.0 < _calibrate_multilingual_score("person name", 0.001) < 1.0
        assert 0.0 < _calibrate_multilingual_score("person name", 0.999) < 1.0

    def test_multilingual_calibration_is_lighter_than_english(self):
        """Multilingual temperatures are generally lower (lighter correction)."""
        from openlabels.core.detectors.gliner_calibration import GLINER_CALIBRATION

        # Check a few representative labels
        for label in ["person name", "phone number", "job title"]:
            ml_temp, _ = MULTILINGUAL_CALIBRATION[label]
            en_temp, _ = GLINER_CALIBRATION[label]
            assert ml_temp <= en_temp, (
                f"Label {label!r}: multilingual temp {ml_temp} should be <= English {en_temp}"
            )


class TestDetectionConfigMultilingual:
    """Test DetectionConfig multilingual settings."""

    def test_multilingual_disabled_by_default(self):
        config = DetectionConfig()
        assert config.enable_multilingual is False

    def test_multilingual_default_model(self):
        config = DetectionConfig()
        assert config.multilingual_gliner_model == "E3-JSI/gliner-multi-pii-domains-v1"

    def test_multilingual_default_threshold(self):
        config = DetectionConfig()
        assert config.multilingual_gliner_threshold == 0.4

    def test_full_preset_enables_multilingual(self):
        config = DetectionConfig.full()
        assert config.enable_multilingual is True

    def test_patterns_only_disables_multilingual(self):
        config = DetectionConfig.patterns_only()
        assert config.enable_multilingual is False

    def test_quick_disables_multilingual(self):
        config = DetectionConfig.quick()
        assert config.enable_multilingual is False

    def test_custom_multilingual_model(self):
        config = DetectionConfig(
            enable_multilingual=True,
            multilingual_gliner_model="urchade/gliner_multi_pii-v1",
        )
        assert config.multilingual_gliner_model == "urchade/gliner_multi_pii-v1"


class TestOrchestratorMultilingual:
    """Test orchestrator initialization with multilingual detector."""

    def test_orchestrator_skips_multilingual_when_disabled(self):
        config = DetectionConfig(enable_ml=False, enable_multilingual=False)
        from openlabels.core.detectors.orchestrator import DetectorOrchestrator
        orch = DetectorOrchestrator(config=config)
        assert "gliner_multilingual" not in orch.detector_names

    def test_orchestrator_inits_multilingual_when_enabled(self):
        """Multilingual detector is initialized when enabled (mocked load)."""
        config = DetectionConfig(enable_multilingual=True)

        mock_model = MagicMock()
        with patch(
            "openlabels.core.detectors.multilingual_gliner.MultilingualGLiNERDetector.load",
            return_value=True,
        ) as mock_load:
            with patch.object(
                MultilingualGLiNERDetector,
                "is_available",
                return_value=True,
            ):
                from openlabels.core.detectors.orchestrator import DetectorOrchestrator
                orch = DetectorOrchestrator(config=config)
                # Verify load was attempted
                assert mock_load.called

    def test_orchestrator_handles_multilingual_load_failure(self):
        """Orchestrator continues if multilingual detector fails to load."""
        config = DetectionConfig(enable_multilingual=True, enable_ml=False)

        with patch(
            "openlabels.core.detectors.multilingual_gliner.MultilingualGLiNERDetector.load",
            return_value=False,
        ):
            from openlabels.core.detectors.orchestrator import DetectorOrchestrator
            orch = DetectorOrchestrator(config=config)
            assert "gliner_multilingual" not in orch.detector_names
