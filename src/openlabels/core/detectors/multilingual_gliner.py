"""Multilingual GLiNER-based PII detector.

Uses E3-JSI/gliner-multi-pii-domains-v1 for PII detection in 9 languages:
English, Spanish, French, Portuguese, German, Italian, Greek, Dutch, Slovene.

The model is fine-tuned from urchade/gliner_multi_pii-v1 with additional
domain-specific training (healthcare, finance, legal, banking).

Architecture is identical to the primary GLiNER detector — same library,
same inference API, same label format.  Results are merged via the
standard span resolver, so on English text the primary Gretel model's
higher-confidence spans typically win; on non-English text this detector
provides coverage that Gretel lacks.
"""

from __future__ import annotations

import logging

from .gliner import GLINER_LABEL_MAP, GLiNERDetector
from .registry import register_detector

logger = logging.getLogger(__name__)

DEFAULT_MULTILINGUAL_GLINER_MODEL = "E3-JSI/gliner-multi-pii-domains-v1"

# Calibration parameters for the multilingual model.
# The E3-JSI model is trained on synthetic multilingual data and tends
# to be slightly less confident than the Gretel model on English text
# but more variable across languages.  We use lighter temperature
# scaling than the English-specific calibration — the model is not as
# systematically overconfident, but still benefits from mild correction
# on noisy label types.
#
# Format: (temperature, bias)  — same Platt scaling as gliner_calibration.py
MULTILINGUAL_CALIBRATION: dict[str, tuple[float, float]] = {
    # Names: slight overconfidence on partial matches across languages
    "person name": (1.15, 0.03),
    "first name": (1.10, 0.02),
    "last name": (1.10, 0.02),
    "middle name": (1.20, 0.05),
    # Contact: structural entities are well-calibrated
    "email address": (0.95, -0.03),
    "phone number": (1.30, 0.08),
    "url": (0.95, -0.02),
    "username": (1.20, 0.04),
    # Locations: multi-token spans vary more across languages
    "street address": (1.20, 0.05),
    "city": (1.10, 0.02),
    "state": (1.10, 0.02),
    "zip code": (1.05, 0.01),
    "country": (1.05, 0.01),
    "county": (1.15, 0.03),
    # Dates
    "date of birth": (1.05, 0.02),
    "date": (1.10, 0.03),
    "date and time": (1.10, 0.03),
    "age": (1.40, 0.10),
    # Government IDs: noisy on alphanumeric codes
    "social security number": (1.05, 0.01),
    "driver license number": (1.25, 0.06),
    "passport number": (1.20, 0.05),
    "tax identification number": (1.20, 0.05),
    "national identity number": (1.20, 0.05),
    # Medical
    "medical record number": (1.20, 0.05),
    "health plan number": (1.15, 0.04),
    "npi number": (1.10, 0.02),
    # Financial
    "credit card number": (0.95, -0.02),
    "bank account number": (1.25, 0.06),
    "iban": (0.95, -0.02),
    "swift code": (1.00, 0.00),
    "bank routing number": (1.20, 0.05),
    # Network
    "ip address": (0.90, -0.04),
    "mac address": (0.90, -0.04),
    # Professional
    "company name": (1.25, 0.06),
    "job title": (1.30, 0.08),
    "employee id": (1.10, 0.03),
    # Vehicle
    "vehicle identification number": (1.35, 0.10),
    "license plate number": (1.30, 0.08),
    # Secrets
    "password": (1.25, 0.06),
    "pin code": (1.30, 0.08),
}


def _calibrate_multilingual_score(label: str, raw_score: float) -> float:
    """Apply Platt scaling for the multilingual GLiNER model.

    Uses the multilingual-specific calibration table rather than the
    English-tuned parameters from gliner_calibration.py.
    """
    import math

    params = MULTILINGUAL_CALIBRATION.get(label)
    if params is None:
        return raw_score

    temperature, bias = params
    clamped = max(1e-7, min(1.0 - 1e-7, raw_score))
    logit = math.log(clamped / (1.0 - clamped))
    scaled = (logit - bias) / temperature
    return 1.0 / (1.0 + math.exp(-scaled))


@register_detector
class MultilingualGLiNERDetector(GLiNERDetector):
    """Multilingual PII detector using E3-JSI GLiNER model.

    Supports 9 languages: English, Spanish, French, Portuguese,
    German, Italian, Greek, Dutch, and Slovene.

    Inherits all chunking, label selection, and deduplication logic
    from GLiNERDetector.  Uses multilingual-specific calibration
    parameters.
    """

    name = "gliner_multilingual"

    def __init__(
        self,
        model_name: str = DEFAULT_MULTILINGUAL_GLINER_MODEL,
        threshold: float = 0.4,
        label_map: dict[str, str] | None = None,
        use_onnx: bool = False,
        enable_label_selection: bool = True,
    ):
        super().__init__(
            model_name=model_name,
            threshold=threshold,
            label_map=label_map or GLINER_LABEL_MAP,
            use_onnx=use_onnx,
            enable_label_selection=enable_label_selection,
        )

    def _detect_single(
        self,
        text: str,
        labels: list[str],
        offset: int = 0,
    ) -> list[Span]:
        """Run multilingual GLiNER on a single text segment.

        Overrides the parent to use multilingual-specific calibration.
        """
        from ..types import Span

        from .gliner import _MIN_SPAN_LENGTHS

        try:
            entities = self._model.predict_entities(
                text,
                labels,
                threshold=self.threshold,
                flat_ner=True,
            )
        except (RuntimeError, ValueError, TypeError) as e:
            logger.error("Multilingual GLiNER inference failed: %s", e)
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

            # Apply multilingual-specific calibration
            score_val = _calibrate_multilingual_score(label, score_val)

            if start < 0 or end <= start or end > len(text):
                continue

            span_text = text[start:end]

            min_len = _MIN_SPAN_LENGTHS.get(canonical_type)
            if min_len is not None and len(span_text.strip()) < min_len:
                continue

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
                logger.debug("Multilingual GLiNER: Invalid span skipped: %s", e)

        return spans
