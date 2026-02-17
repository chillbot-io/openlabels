"""spaCy NER detector for ensemble PII detection.

Provides complementary NER signal alongside GLiNER. spaCy's
transformer-based NER excels at contextual entities (names,
organizations, locations) that zero-shot models sometimes miss.

Requires: ``pip install spacy`` and a model download:
    ``python -m spacy download en_core_web_lg``

This detector is opt-in (``enable_spacy_ner=False`` by default)
because it adds a ~500MB model dependency.
"""

from __future__ import annotations

import logging
from typing import Any

from ..types import Span, Tier
from .base import BaseDetector

logger = logging.getLogger(__name__)

# spaCy entity label → OpenLabels canonical type
SPACY_ENTITY_MAP: dict[str, str] = {
    "PERSON": "NAME",
    "GPE": "CITY",         # Geopolitical entity (city, country, state)
    "ORG": "COMPANY",
    "DATE": "DATE",
    "LOC": "ADDRESS",      # Non-GPE locations
    "FAC": "FACILITY",
}

# Default confidence for spaCy entities.
# spaCy NER doesn't provide per-entity confidence scores,
# so we assign a fixed value in the middle of the ML band.
_DEFAULT_CONFIDENCE = 0.75


class SpacyNERDetector(BaseDetector):
    """PII detector using spaCy's pretrained NER model.

    Complements GLiNER by providing orthogonal NER signal from
    a different model architecture (CNN or transformer).
    """

    name = "spacy_ner"
    tier = Tier.ML

    def __init__(
        self,
        model_name: str = "en_core_web_lg",
        default_confidence: float = _DEFAULT_CONFIDENCE,
    ):
        self._model_name = model_name
        self._default_confidence = default_confidence
        self._nlp: Any = None
        self._loaded = False

    def is_available(self) -> bool:
        return self._loaded

    def load(self) -> bool:
        """Load a spaCy NER model.

        Returns:
            True if loaded successfully.
        """
        try:
            import spacy
        except ImportError:
            logger.warning(
                "spacy library not installed — spaCy NER disabled. "
                "Install with: pip install spacy"
            )
            return False

        try:
            self._nlp = spacy.load(
                self._model_name,
                disable=["tok2vec", "tagger", "parser", "attribute_ruler", "lemmatizer"],
            )
            self._loaded = True
            logger.info("spaCy NER model loaded: %s", self._model_name)
            return True
        except OSError:
            logger.warning(
                "spaCy model %r not found. Download with: "
                "python -m spacy download %s",
                self._model_name, self._model_name,
            )
            return False

    def detect(self, text: str) -> list[Span]:
        """Detect entities using spaCy NER.

        Args:
            text: Input text to scan.

        Returns:
            List of detected Span objects for mapped entity types.
        """
        if not self._loaded or not self._nlp:
            return []

        if not text or not text.strip():
            return []

        try:
            doc = self._nlp(text)
        except (RuntimeError, ValueError) as e:
            logger.error("spaCy inference failed: %s", e)
            return []

        spans: list[Span] = []
        for ent in doc.ents:
            entity_type = SPACY_ENTITY_MAP.get(ent.label_)
            if entity_type is None:
                continue

            span_text = ent.text
            start = ent.start_char
            end = ent.end_char

            # Validate
            if start < 0 or end <= start or end > len(text):
                continue

            try:
                spans.append(Span(
                    start=start,
                    end=end,
                    text=span_text,
                    entity_type=entity_type,
                    confidence=self._default_confidence,
                    detector=self.name,
                    tier=self.tier,
                ))
            except ValueError as e:
                logger.debug("spaCy NER: Invalid span skipped: %s", e)

        return spans
