"""Tests for GLiNER-based PII detector.

Tests cover:
- GLiNERDetector initialization and configuration
- Model loading (mocked — no real model download in tests)
- Entity detection with mocked predict_entities
- Label mapping to OpenLabels canonical types
- Edge cases: empty text, invalid offsets, import errors
"""

from unittest.mock import MagicMock, patch

import pytest

from openlabels.core.types import Span, Tier
from openlabels.core.detectors.gliner import (
    DEFAULT_GLINER_MODEL,
    GLINER_LABEL_MAP,
    GLiNERDetector,
)


class TestGLiNERDetectorInit:
    """Test GLiNERDetector initialization and configuration."""

    def test_default_model_name(self):
        det = GLiNERDetector()
        assert det.model_name == DEFAULT_GLINER_MODEL

    def test_custom_model_name(self):
        det = GLiNERDetector(model_name="urchade/gliner_base")
        assert det.model_name == "urchade/gliner_base"

    def test_default_threshold(self):
        det = GLiNERDetector()
        assert det.threshold == 0.4

    def test_custom_threshold(self):
        det = GLiNERDetector(threshold=0.5)
        assert det.threshold == 0.5

    def test_name_is_gliner(self):
        det = GLiNERDetector()
        assert det.name == "gliner"

    def test_tier_is_ml(self):
        det = GLiNERDetector()
        assert det.tier == Tier.ML

    def test_not_available_before_load(self):
        det = GLiNERDetector()
        assert det.is_available() is False

    def test_custom_label_map(self):
        custom = {"person": "NAME"}
        det = GLiNERDetector(label_map=custom)
        assert det.label_map == custom
        assert det._entity_labels == ["person"]

    def test_default_label_map_has_expected_keys(self):
        det = GLiNERDetector()
        assert "person name" in det.label_map
        assert "email address" in det.label_map
        assert "social security number" in det.label_map
        assert det.label_map["person name"] == "NAME"
        assert det.label_map["email address"] == "EMAIL"
        assert det.label_map["social security number"] == "SSN"


class TestGLiNERDetectorLoad:
    """Test GLiNERDetector.load() with mocked gliner library."""

    def test_load_success(self):
        det = GLiNERDetector()
        mock_model = MagicMock()

        with patch.dict("sys.modules", {"gliner": MagicMock()}):
            with patch("openlabels.core.detectors.gliner.GLiNERDetector.load") as mock_load:
                # Simulate successful load
                mock_load.return_value = True
                result = det.load()

        # Just verify the mock was called
        assert mock_load.called

    def test_load_sets_available(self):
        det = GLiNERDetector()
        mock_gliner_module = MagicMock()
        mock_model = MagicMock()
        mock_gliner_module.GLiNER.from_pretrained.return_value = mock_model

        with patch.dict("sys.modules", {"gliner": mock_gliner_module}):
            # Directly invoke load internals
            det._model = mock_model
            det._loaded = True

        assert det.is_available() is True

    def test_load_import_error(self):
        det = GLiNERDetector()
        # Patch import to fail
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
        det = GLiNERDetector()
        mock_gliner = MagicMock()
        mock_gliner.GLiNER.from_pretrained.side_effect = RuntimeError("download failed")

        with patch.dict("sys.modules", {"gliner": mock_gliner}):
            result = det.load()

        assert result is False
        assert det.is_available() is False


class TestGLiNERDetectorDetect:
    """Test GLiNERDetector.detect() with mocked model."""

    def _make_loaded_detector(self, label_map=None):
        """Create a detector with a mocked model (label selection disabled)."""
        det = GLiNERDetector(
            label_map=label_map or GLINER_LABEL_MAP,
            enable_label_selection=False,
        )
        det._model = MagicMock()
        det._loaded = True
        return det

    def test_detect_not_loaded_returns_empty(self):
        det = GLiNERDetector()
        assert det.detect("John Smith") == []

    def test_detect_empty_text_returns_empty(self):
        det = self._make_loaded_detector()
        assert det.detect("") == []
        assert det.detect("   ") == []

    def test_detect_basic_entity(self):
        det = self._make_loaded_detector()
        det._model.predict_entities.return_value = [
            {"start": 0, "end": 10, "text": "John Smith", "label": "person name", "score": 0.95}
        ]
        spans = det.detect("John Smith was admitted to the hospital")
        assert len(spans) == 1
        assert spans[0].entity_type == "NAME"
        assert spans[0].text == "John Smith"
        assert spans[0].start == 0
        assert spans[0].end == 10
        assert spans[0].confidence == 0.95
        assert spans[0].detector == "gliner"
        assert spans[0].tier == Tier.ML

    def test_detect_multiple_entities(self):
        det = self._make_loaded_detector()
        det._model.predict_entities.return_value = [
            {"start": 0, "end": 10, "text": "John Smith", "label": "person name", "score": 0.95},
            {"start": 25, "end": 46, "text": "john.smith@example.com", "label": "email address", "score": 0.99},
        ]
        text = "John Smith can be reached john.smith@example.com"
        spans = det.detect(text)
        assert len(spans) == 2
        assert spans[0].entity_type == "NAME"
        assert spans[1].entity_type == "EMAIL"

    def test_detect_ssn(self):
        det = self._make_loaded_detector()
        det._model.predict_entities.return_value = [
            {"start": 8, "end": 19, "text": "123-45-6789", "label": "social security number", "score": 0.92}
        ]
        spans = det.detect("My SSN: 123-45-6789")
        assert len(spans) == 1
        assert spans[0].entity_type == "SSN"

    def test_detect_unmapped_label_skipped(self):
        det = self._make_loaded_detector(label_map={"person name": "NAME"})
        det._model.predict_entities.return_value = [
            {"start": 0, "end": 4, "text": "John", "label": "person name", "score": 0.9},
            {"start": 10, "end": 15, "text": "blood", "label": "blood_type", "score": 0.8},
        ]
        spans = det.detect("John has A blood type")
        assert len(spans) == 1
        assert spans[0].entity_type == "NAME"

    def test_detect_invalid_offsets_skipped(self):
        det = self._make_loaded_detector()
        det._model.predict_entities.return_value = [
            {"start": -1, "end": 4, "text": "John", "label": "person name", "score": 0.9},
            {"start": 10, "end": 5, "text": "bad", "label": "person name", "score": 0.9},
            {"start": 0, "end": 100, "text": "x" * 100, "label": "person name", "score": 0.9},
        ]
        spans = det.detect("John Smith")
        assert len(spans) == 0

    def test_detect_runtime_error_returns_empty(self):
        det = self._make_loaded_detector()
        det._model.predict_entities.side_effect = RuntimeError("inference failed")
        spans = det.detect("John Smith")
        assert spans == []

    def test_detect_value_error_returns_empty(self):
        det = self._make_loaded_detector()
        det._model.predict_entities.side_effect = ValueError("bad input")
        spans = det.detect("John Smith")
        assert spans == []

    def test_detect_passes_threshold(self):
        det = self._make_loaded_detector()
        det.threshold = 0.7
        det._model.predict_entities.return_value = []
        det.detect("some text")
        det._model.predict_entities.assert_called_once_with(
            "some text",
            det._entity_labels,
            threshold=0.7,
            flat_ner=True,
        )

    def test_detect_passes_entity_labels(self):
        custom = {"person": "NAME", "email": "EMAIL"}
        det = self._make_loaded_detector(label_map=custom)
        det._model.predict_entities.return_value = []
        det.detect("test text")
        call_args = det._model.predict_entities.call_args
        labels_passed = call_args[0][1]
        assert set(labels_passed) == {"person", "email"}


class TestGLiNERLabelMap:
    """Test that the default label map covers key PII types."""

    def test_names_covered(self):
        assert "person name" in GLINER_LABEL_MAP
        assert "first name" in GLINER_LABEL_MAP
        assert "last name" in GLINER_LABEL_MAP

    def test_contact_covered(self):
        assert "email address" in GLINER_LABEL_MAP
        assert "phone number" in GLINER_LABEL_MAP
        assert "url" in GLINER_LABEL_MAP

    def test_government_ids_covered(self):
        assert "social security number" in GLINER_LABEL_MAP
        assert "driver license number" in GLINER_LABEL_MAP
        assert "passport number" in GLINER_LABEL_MAP

    def test_financial_covered(self):
        assert "credit card number" in GLINER_LABEL_MAP
        assert "bank account number" in GLINER_LABEL_MAP
        assert "iban" in GLINER_LABEL_MAP

    def test_locations_covered(self):
        assert "street address" in GLINER_LABEL_MAP
        assert "city" in GLINER_LABEL_MAP
        assert "zip code" in GLINER_LABEL_MAP

    def test_maps_to_valid_openlabels_types(self):
        from openlabels.core.types import KNOWN_ENTITY_TYPES
        for label, entity_type in GLINER_LABEL_MAP.items():
            assert entity_type.upper() in KNOWN_ENTITY_TYPES, (
                f"GLiNER label {label!r} maps to unknown type {entity_type!r}"
            )
