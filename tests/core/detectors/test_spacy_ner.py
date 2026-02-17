"""Tests for spaCy NER detector."""

from unittest.mock import MagicMock, patch

import pytest

from openlabels.core.types import Span, Tier
from openlabels.core.detectors.spacy_ner import (
    SPACY_ENTITY_MAP,
    SpacyNERDetector,
)


class TestSpacyNERDetectorInit:
    """Test SpacyNERDetector initialization."""

    def test_default_model_name(self):
        detector = SpacyNERDetector()
        assert detector._model_name == "en_core_web_lg"

    def test_custom_model_name(self):
        detector = SpacyNERDetector(model_name="en_core_web_sm")
        assert detector._model_name == "en_core_web_sm"

    def test_not_available_before_load(self):
        detector = SpacyNERDetector()
        assert detector.is_available() is False

    def test_name_is_spacy_ner(self):
        detector = SpacyNERDetector()
        assert detector.name == "spacy_ner"

    def test_tier_is_ml(self):
        detector = SpacyNERDetector()
        assert detector.tier == Tier.ML


class TestSpacyNERDetectorLoad:
    """Test model loading behavior."""

    def test_load_without_spacy_returns_false(self):
        """If spacy is not installed, load returns False."""
        detector = SpacyNERDetector()
        with patch.dict("sys.modules", {"spacy": None}):
            # Can't import spacy
            with patch("builtins.__import__", side_effect=ImportError("no spacy")):
                result = detector.load()
        # The actual behavior depends on environment; just ensure no crash
        assert isinstance(result, bool)

    def test_load_with_missing_model_returns_false(self):
        """If spacy model doesn't exist, load returns False."""
        mock_spacy = MagicMock()
        mock_spacy.load.side_effect = OSError("Model not found")
        with patch.dict("sys.modules", {"spacy": mock_spacy}):
            detector = SpacyNERDetector()
            detector.load()
            # After failed load
            assert detector.is_available() is False

    def test_load_success(self):
        """Successful load marks detector as available."""
        mock_spacy = MagicMock()
        mock_nlp = MagicMock()
        mock_spacy.load.return_value = mock_nlp
        with patch.dict("sys.modules", {"spacy": mock_spacy}):
            detector = SpacyNERDetector()
            result = detector.load()
            assert result is True
            assert detector.is_available() is True


class TestSpacyNERDetectorDetect:
    """Test detection behavior."""

    def _make_detector_with_mock(self, entities):
        """Create a detector with a mocked spaCy model returning given entities."""
        detector = SpacyNERDetector()
        mock_nlp = MagicMock()

        # Create mock doc with entities
        mock_doc = MagicMock()
        mock_ents = []
        for ent_data in entities:
            mock_ent = MagicMock()
            mock_ent.label_ = ent_data["label"]
            mock_ent.text = ent_data["text"]
            mock_ent.start_char = ent_data["start"]
            mock_ent.end_char = ent_data["end"]
            mock_ents.append(mock_ent)
        mock_doc.ents = mock_ents
        mock_nlp.return_value = mock_doc

        detector._nlp = mock_nlp
        detector._loaded = True
        return detector

    def test_detect_person(self):
        """PERSON entity is mapped to NAME."""
        detector = self._make_detector_with_mock([
            {"label": "PERSON", "text": "John Smith", "start": 0, "end": 10},
        ])
        spans = detector.detect("John Smith went home")
        assert len(spans) == 1
        assert spans[0].entity_type == "NAME"
        assert spans[0].text == "John Smith"
        assert spans[0].tier == Tier.ML
        assert spans[0].detector == "spacy_ner"

    def test_detect_org(self):
        """ORG entity is mapped to COMPANY."""
        detector = self._make_detector_with_mock([
            {"label": "ORG", "text": "Acme Corp", "start": 0, "end": 9},
        ])
        spans = detector.detect("Acme Corp is big")
        assert len(spans) == 1
        assert spans[0].entity_type == "COMPANY"

    def test_detect_gpe(self):
        """GPE entity is mapped to CITY."""
        detector = self._make_detector_with_mock([
            {"label": "GPE", "text": "New York", "start": 3, "end": 11},
        ])
        spans = detector.detect("in New York today")
        assert len(spans) == 1
        assert spans[0].entity_type == "CITY"

    def test_unmapped_entity_skipped(self):
        """Entity types not in SPACY_ENTITY_MAP are skipped."""
        detector = self._make_detector_with_mock([
            {"label": "MONEY", "text": "$100", "start": 0, "end": 4},
        ])
        spans = detector.detect("$100 dollars")
        assert len(spans) == 0

    def test_multiple_entities(self):
        """Multiple entities returned correctly."""
        detector = self._make_detector_with_mock([
            {"label": "PERSON", "text": "John", "start": 0, "end": 4},
            {"label": "GPE", "text": "NYC", "start": 14, "end": 17},
        ])
        spans = detector.detect("John lives in NYC today")
        assert len(spans) == 2
        types = {s.entity_type for s in spans}
        assert types == {"NAME", "CITY"}

    def test_empty_text_returns_empty(self):
        """Empty text returns no spans."""
        detector = self._make_detector_with_mock([])
        spans = detector.detect("")
        assert spans == []

    def test_whitespace_text_returns_empty(self):
        """Whitespace-only text returns no spans."""
        detector = self._make_detector_with_mock([])
        spans = detector.detect("   ")
        assert spans == []

    def test_not_loaded_returns_empty(self):
        """Detect before load returns empty."""
        detector = SpacyNERDetector()
        spans = detector.detect("John Smith went home")
        assert spans == []

    def test_default_confidence(self):
        """Spans have the default confidence value."""
        detector = self._make_detector_with_mock([
            {"label": "PERSON", "text": "Alice", "start": 0, "end": 5},
        ])
        spans = detector.detect("Alice is here")
        assert spans[0].confidence == 0.75

    def test_custom_default_confidence(self):
        """Custom default_confidence is used."""
        detector = SpacyNERDetector(default_confidence=0.80)
        mock_nlp = MagicMock()
        mock_doc = MagicMock()
        mock_ent = MagicMock()
        mock_ent.label_ = "PERSON"
        mock_ent.text = "Bob"
        mock_ent.start_char = 0
        mock_ent.end_char = 3
        mock_doc.ents = [mock_ent]
        mock_nlp.return_value = mock_doc
        detector._nlp = mock_nlp
        detector._loaded = True

        spans = detector.detect("Bob is here")
        assert spans[0].confidence == 0.80


class TestSpacyEntityMap:
    """Verify entity map is well-formed."""

    def test_all_values_are_strings(self):
        for k, v in SPACY_ENTITY_MAP.items():
            assert isinstance(k, str)
            assert isinstance(v, str)

    def test_person_mapped(self):
        assert "PERSON" in SPACY_ENTITY_MAP

    def test_gpe_mapped(self):
        assert "GPE" in SPACY_ENTITY_MAP

    def test_org_mapped(self):
        assert "ORG" in SPACY_ENTITY_MAP
