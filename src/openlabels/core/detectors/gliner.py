"""Tier 1: GLiNER-based PII detector using Gretel's fine-tuned model.

Zero-shot NER model that detects 30+ PII entity types.
Uses gretelai/gretel-gliner-bi-base-v1.0 (Apache-2.0 license).

The model is loaded from HuggingFace Hub and cached locally.
No manual model file management required.
"""

from __future__ import annotations

import logging
from typing import Any

from ..types import Span, Tier
from .base import BaseDetector
from .registry import register_detector

logger = logging.getLogger(__name__)

# Default model — Gretel's PII-tuned GLiNER (Apache-2.0)
DEFAULT_GLINER_MODEL = "gretelai/gretel-gliner-bi-base-v1.0"

# Entity labels we ask GLiNER to detect, mapped to OpenLabels canonical types.
# Keys are the natural-language labels passed to predict_entities().
# Values are the OpenLabels entity type strings.
GLINER_LABEL_MAP: dict[str, str] = {
    # Names
    "person name": "NAME",
    "first name": "FIRSTNAME",
    "last name": "LASTNAME",
    # Contact
    "email address": "EMAIL",
    "phone number": "PHONE",
    "url": "URL",
    "username": "USERNAME",
    # Locations
    "street address": "ADDRESS",
    "city": "CITY",
    "state": "STATE",
    "zip code": "ZIP",
    "country": "COUNTRY",
    # Dates
    "date of birth": "DATE_DOB",
    "date": "DATE",
    "age": "AGE",
    # Government IDs
    "social security number": "SSN",
    "driver license number": "DRIVER_LICENSE",
    "passport number": "PASSPORT",
    "tax identification number": "TAX_ID",
    "national identity number": "STATE_ID",
    # Medical
    "medical record number": "MRN",
    # Financial
    "credit card number": "CREDIT_CARD",
    "bank account number": "ACCOUNT_NUMBER",
    "iban": "IBAN",
    # Network / Device
    "ip address": "IP_ADDRESS",
    "mac address": "MAC_ADDRESS",
    # Vehicle
    "vehicle identification number": "VIN",
    "license plate number": "LICENSE_PLATE",
    # Crypto
    "bitcoin address": "BITCOIN_ADDRESS",
    "ethereum address": "ETHEREUM_ADDRESS",
    # Professional
    "company name": "COMPANY",
    # Secrets
    "password": "PASSWORD",
}


@register_detector
class GLiNERDetector(BaseDetector):
    """PII detector using GLiNER zero-shot NER.

    Loads a pre-trained GLiNER model (default: Gretel's PII-tuned variant)
    and runs entity extraction using natural-language entity labels.

    The model is downloaded from HuggingFace Hub on first use and cached
    locally by the ``gliner`` library.
    """

    name = "gliner"
    tier = Tier.ML

    def __init__(
        self,
        model_name: str = DEFAULT_GLINER_MODEL,
        threshold: float = 0.3,
        label_map: dict[str, str] | None = None,
    ):
        self.model_name = model_name
        self.threshold = threshold
        self.label_map = label_map or GLINER_LABEL_MAP
        self._model: Any = None
        self._loaded = False
        self._entity_labels = list(self.label_map.keys())

    def is_available(self) -> bool:
        return self._loaded

    def load(self) -> bool:
        """Load GLiNER model from HuggingFace Hub.

        Returns:
            True if loaded successfully.
        """
        try:
            from gliner import GLiNER

            self._model = GLiNER.from_pretrained(self.model_name)
            self._loaded = True
            logger.info("GLiNER model loaded: %s", self.model_name)
            return True
        except ImportError:
            logger.warning(
                "gliner library not installed — GLiNER detection disabled. "
                "Install with: pip install gliner"
            )
            return False
        except (OSError, RuntimeError, ValueError) as e:
            logger.error("Failed to load GLiNER model %s: %s", self.model_name, e)
            return False

    def detect(self, text: str) -> list[Span]:
        """Detect PII entities using GLiNER.

        Args:
            text: Input text to scan.

        Returns:
            List of detected Span objects.
        """
        if not self._loaded or not self._model:
            return []

        if not text or not text.strip():
            return []

        try:
            entities = self._model.predict_entities(
                text,
                self._entity_labels,
                threshold=self.threshold,
                flat_ner=True,
            )
        except (RuntimeError, ValueError, TypeError) as e:
            logger.error("GLiNER inference failed: %s", e)
            return []

        spans: list[Span] = []
        for entity in entities:
            label = entity.get("label", "")
            canonical_type = self.label_map.get(label)
            if canonical_type is None:
                continue

            start = int(entity["start"])
            end = int(entity["end"])
            score = float(entity["score"])

            # Validate offsets
            if start < 0 or end <= start or end > len(text):
                continue

            span_text = text[start:end]

            try:
                span = Span(
                    start=start,
                    end=end,
                    text=span_text,
                    entity_type=canonical_type,
                    confidence=score,
                    detector=self.name,
                    tier=self.tier,
                )
                spans.append(span)
            except ValueError as e:
                logger.debug("GLiNER: Invalid span skipped: %s", e)

        return spans
