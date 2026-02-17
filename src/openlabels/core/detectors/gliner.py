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
        use_onnx: bool = False,
        enable_label_selection: bool = True,
    ):
        self.model_name = model_name
        self.threshold = threshold
        self.label_map = label_map or GLINER_LABEL_MAP
        self.use_onnx = use_onnx
        self.enable_label_selection = enable_label_selection
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

            self._model = GLiNER.from_pretrained(
                self.model_name,
                load_onnx_model=self.use_onnx,
            )
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

    # GLiNER token window is ~512 tokens; ~4 chars/token = ~2048 chars.
    # Use conservative chunk size to stay well within the window.
    _MAX_CHUNK_CHARS = 1500
    _CHUNK_OVERLAP = 200

    def detect(self, text: str) -> list[Span]:
        """Detect PII entities using GLiNER.

        Long texts are automatically chunked into overlapping windows
        to avoid silent entity loss beyond the transformer window.

        If ``enable_label_selection`` is True, the label set is narrowed
        based on lightweight content profiling (keyword heuristics).

        Args:
            text: Input text to scan.

        Returns:
            List of detected Span objects.
        """
        if not self._loaded or not self._model:
            return []

        if not text or not text.strip():
            return []

        # Select labels based on content profiling
        labels = self._select_labels(text)

        # Chunk if text exceeds GLiNER's effective window
        if len(text) > self._MAX_CHUNK_CHARS:
            return self._detect_chunked(text, labels)

        return self._detect_single(text, labels)

    def _select_labels(self, text: str) -> list[str]:
        """Select GLiNER labels based on document content profiling."""
        if not self.enable_label_selection:
            return self._entity_labels

        try:
            from .gliner_label_selector import profile_content
            profile = profile_content(text)
            logger.debug(
                "GLiNER label selection: %d/%d labels from categories %s",
                len(profile.selected_labels),
                len(self._entity_labels),
                profile.categories,
            )
            return profile.selected_labels
        except Exception as e:
            logger.warning("Label selection failed, using all labels: %s", e)
            return self._entity_labels

    def _detect_single(
        self,
        text: str,
        labels: list[str],
        offset: int = 0,
    ) -> list[Span]:
        """Run GLiNER on a single text segment.

        Args:
            text: Text to scan.
            labels: GLiNER label strings to detect.
            offset: Character offset to add to span positions
                (used when processing chunks of a larger document).
        """
        try:
            entities = self._model.predict_entities(
                text,
                labels,
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
            score_val = float(entity["score"])

            # Validate offsets against the chunk text
            if start < 0 or end <= start or end > len(text):
                continue

            span_text = text[start:end]

            try:
                span = Span(
                    start=start + offset,
                    end=end + offset,
                    text=span_text,
                    entity_type=canonical_type,
                    confidence=score_val,
                    detector=self.name,
                    tier=self.tier,
                )
                spans.append(span)
            except ValueError as e:
                logger.debug("GLiNER: Invalid span skipped: %s", e)

        return spans

    def _detect_chunked(self, text: str, labels: list[str]) -> list[Span]:
        """Split text into overlapping chunks, detect per chunk, merge results."""
        from ..pipeline.chunking import TextChunker

        chunker = TextChunker(
            max_chunk_size=self._MAX_CHUNK_CHARS,
            overlap=self._CHUNK_OVERLAP,
        )
        chunks = chunker.chunk(text)

        all_spans: list[Span] = []
        for chunk in chunks:
            chunk_spans = self._detect_single(chunk.text, labels, offset=chunk.start)
            all_spans.extend(chunk_spans)

        return self._dedup_chunk_spans(all_spans)

    @staticmethod
    def _dedup_chunk_spans(spans: list[Span]) -> list[Span]:
        """Deduplicate overlapping spans from adjacent chunks.

        Keeps the higher-confidence span when two spans overlap
        by more than 50% of the shorter span's length.
        """
        if not spans:
            return []

        spans_sorted = sorted(spans, key=lambda s: (s.start, -s.confidence))
        result = [spans_sorted[0]]

        for span in spans_sorted[1:]:
            prev = result[-1]
            # Check for significant overlap
            if span.start < prev.end:
                overlap = prev.end - span.start
                min_len = min(prev.end - prev.start, span.end - span.start)
                if min_len > 0 and overlap > min_len * 0.5:
                    # Keep higher confidence
                    if span.confidence > prev.confidence:
                        result[-1] = span
                    continue
            result.append(span)

        return result
