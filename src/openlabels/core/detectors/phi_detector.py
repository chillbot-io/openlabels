"""Stanford Clinical De-identifier PHI detector.

Uses StanfordAIMI/stanford-deidentifier-base — a PubMedBERT model
fine-tuned on i2b2/n2c2 clinical de-identification data for detecting
HIPAA Safe Harbor PHI categories.

The model predicts 22 entity types covering patient names, dates,
healthcare workers, hospitals, phone/fax/email, government IDs,
medical record numbers, and more.

References:
    Chambon et al. "Automated deidentification of radiology reports
    combining transformer and 'hide in plain sight' rule-based methods."
    JAMIA, Volume 30, Issue 2, February 2023.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..constants import DEFAULT_MODELS_DIR, PRODUCT_CODE_PREFIXES
from ..types import Span, Tier
from .base import BaseDetector
from .registry import register_detector

logger = logging.getLogger(__name__)

# Default: load from HuggingFace Hub if no local path configured
DEFAULT_PHI_MODEL = "StanfordAIMI/stanford-deidentifier-base"

# Stanford model output labels -> OpenLabels canonical entity types.
# The model uses BIO tagging; after HuggingFace pipeline aggregation
# we receive the base labels without B-/I- prefix.
STANFORD_PHI_LABEL_MAP: dict[str, str] = {
    # Names
    "PATIENT": "NAME_PATIENT",
    "HCW": "NAME_PROVIDER",
    # Suppressed — clinical model sees every institution name as PHI;
    # on general-purpose text FACILITY has ~78% FP rate even at 0.80.
    # GLiNER COMPANY already covers professional entities well.
    #   HOSPITAL -> FACILITY  (suppressed)
    #   VENDOR   -> FACILITY  (suppressed)
    # Dates / age
    "DATE": "DATE",
    "DATES": "DATE",
    "AGE": "AGE",
    # Contact
    "PHONE": "PHONE",
    "FAX": "PHONE",
    "EMAIL": "EMAIL",
    "WEB": "URL",
    # Identifiers
    "MRN": "MRN",
    "SSN": "SSN",
    "LICENSE": "DRIVER_LICENSE",
    "ACCOUNT": "ACCOUNT_NUMBER",
    "VIN": "VIN",
    "DEVICE": "DEVICE_ID",
    # Other HIPAA categories
    "GEO": "ADDRESS",
    # Suppressed — too generic for general-purpose PII detection; no matching
    # gold labels in non-clinical benchmarks (AI4Privacy), producing only FPs:
    #   ID, UNIQUE  -> generic "ID" (no eval category)
    #   PLAN        -> HEALTH_PLAN  (no eval category)
    #   BIOMETRIC   -> BIOMETRIC    (no eval category)
    #   PHOTO       -> PHOTO_ID     (no eval category)
}

# ---------------------------------------------------------------------------
# Platt-scaling calibration for PHI model outputs.
#
# The Stanford model was trained on clinical de-identification data (i2b2/n2c2)
# where every patient/provider name, date, and address IS a PHI entity.
# On general-purpose text, it over-fires — names of companies, geographic
# references, and generic dates are flagged as PHI.
#
# Temperature > 1.0 dampens overconfident scores; bias > 0 shifts down.
# Values are conservative initial estimates; use fit_calibration() with
# benchmark data to derive optimal parameters.
#
# Format: Stanford_label → (temperature, bias)
# ---------------------------------------------------------------------------
PHI_CALIBRATION: dict[str, tuple[float, float]] = {
    # Names: clinical model is very aggressive on general text
    "PATIENT": (1.60, 0.12),
    "HCW": (1.50, 0.10),
    # Dates: reasonable on structured dates, overconfident on ambiguous ones
    "DATE": (1.20, 0.04),
    "DATES": (1.20, 0.04),
    # Age: decent on "XX years old" but fires on bare numbers
    "AGE": (1.40, 0.08),
    # Contact: structural patterns are reliable
    "PHONE": (1.05, 0.01),
    "FAX": (1.10, 0.02),
    "EMAIL": (0.95, -0.03),
    "WEB": (1.00, 0.00),
    # Identifiers: clinical model catches some that GLiNER misses
    "MRN": (1.10, 0.02),
    "SSN": (1.05, 0.01),
    "LICENSE": (1.30, 0.06),
    "ACCOUNT": (1.25, 0.05),
    "VIN": (1.20, 0.04),
    "DEVICE": (1.30, 0.06),
    # Address: heavily overconfident on general text
    "GEO": (1.50, 0.10),
}


def _calibrate_phi_score(label: str, raw_score: float) -> float:
    """Apply Platt scaling to Stanford PHI model raw scores.

    Normalizes PHI confidence into a comparable scale with GLiNER,
    dampening overconfident clinical predictions on general-purpose text.
    """
    from .gliner_calibration import _platt_transform

    params = PHI_CALIBRATION.get(label)
    if params is None:
        return raw_score
    return _platt_transform(raw_score, *params)


# Chunk size for long texts (characters). The model's token limit is 512;
# at ~4 chars/token we use a conservative character budget to avoid
# truncation, with overlap to catch entities at boundaries.
CHUNK_MAX_CHARS = 1500
CHUNK_OVERLAP = 200


@register_detector
class StanfordPHIDetector(BaseDetector):
    """Stanford Clinical De-identifier for HIPAA PHI detection.

    Wraps the StanfordAIMI/stanford-deidentifier-base model via
    HuggingFace transformers ``token-classification`` pipeline.

    Can load from:
    1. A local model directory (model_path kwarg)
    2. The openlabels model registry (DEFAULT_MODELS_DIR / stanford_phi)
    3. HuggingFace Hub (downloads on first use)
    """

    name = "stanford_phi"
    tier = Tier.ML

    def __init__(
        self,
        model_path: Path | str | None = None,
        threshold: float = 0.5,
    ):
        self._model_path = model_path
        self.threshold = threshold
        self._pipeline = None
        self._loaded = False

    def is_available(self) -> bool:
        return self._loaded

    def _resolve_model_path(self) -> str:
        """Resolve model location: explicit path > registry > HuggingFace Hub."""
        if self._model_path is not None:
            return str(self._model_path)

        # Check registry location
        registry_path = DEFAULT_MODELS_DIR / "stanford_phi"
        if registry_path.is_dir() and (registry_path / "config.json").exists():
            return str(registry_path)

        # Fall back to HuggingFace Hub (will download on first use)
        return DEFAULT_PHI_MODEL

    def load(self) -> bool:
        """Load the Stanford de-identifier model.

        Returns:
            True if loaded successfully.
        """
        try:
            from transformers import pipeline
        except ImportError:
            logger.warning(
                "stanford_phi: transformers not installed — "
                "install with: pip install transformers torch"
            )
            return False

        model_id = self._resolve_model_path()

        try:
            self._pipeline = pipeline(
                "token-classification",
                model=model_id,
                aggregation_strategy="simple",
            )
            self._loaded = True
            logger.info("Stanford PHI detector loaded: %s", model_id)
            return True
        except OSError as e:
            logger.warning("stanford_phi: failed to load model from %s: %s", model_id, e)
            return False
        except (RuntimeError, ValueError) as e:
            logger.error("stanford_phi: model load error: %s", e)
            return False

    def detect(self, text: str) -> list[Span]:
        """Detect PHI entities in text.

        Handles long documents by splitting into overlapping chunks
        and deduplicating boundary entities.
        """
        if not self._loaded or not self._pipeline:
            return []

        if not text or not text.strip():
            return []

        if len(text) <= CHUNK_MAX_CHARS:
            return self._detect_chunk(text, offset=0)

        return self._detect_chunked(text)

    def _detect_chunk(self, text: str, offset: int = 0) -> list[Span]:
        """Run detection on a single text chunk."""
        try:
            results = self._pipeline(text)
        except (RuntimeError, ValueError, TypeError) as e:
            logger.error("stanford_phi: inference failed: %s", e)
            return []

        spans: list[Span] = []
        for r in results:
            raw_label = r.get("entity_group", r.get("entity", ""))
            # Strip B-/I- prefix if pipeline didn't aggregate
            if raw_label.startswith(("B-", "I-")):
                raw_label = raw_label[2:]

            canonical = STANFORD_PHI_LABEL_MAP.get(raw_label)
            if canonical is None:
                continue

            raw_score = float(r["score"])
            if raw_score < self.threshold:
                continue

            # Apply Platt scaling calibration
            score = _calibrate_phi_score(raw_label, raw_score)

            start = int(r["start"]) + offset
            end = int(r["end"]) + offset

            # Expand to word boundaries
            while start > offset and not text[start - offset - 1].isspace():
                start -= 1
            while end - offset < len(text) and not text[end - offset].isspace():
                end += 1

            span_text = text[start - offset:end - offset]

            # Filter product codes
            if canonical == "MRN":
                first_part = span_text.split("-")[0].split("_")[0].split("#")[0].lower()
                if first_part in PRODUCT_CODE_PREFIXES:
                    continue

            try:
                spans.append(Span(
                    start=start,
                    end=end,
                    text=span_text,
                    entity_type=canonical,
                    confidence=score,
                    detector=self.name,
                    tier=self.tier,
                    raw_confidence=raw_score,
                    detector_label=raw_label,
                ))
            except ValueError as e:
                logger.debug("stanford_phi: invalid span skipped: %s", e)

        return spans

    def _detect_chunked(self, text: str) -> list[Span]:
        """Split long text into overlapping chunks and detect."""
        all_spans: list[Span] = []
        pos = 0
        text_len = len(text)

        while pos < text_len:
            chunk_end = min(pos + CHUNK_MAX_CHARS, text_len)

            # Break at sentence/paragraph boundary if possible
            if chunk_end < text_len:
                search_start = max(pos, chunk_end - 300)
                search_text = text[search_start:chunk_end]
                for sep in ["\n\n", ". ", ".\n", "\n"]:
                    idx = search_text.rfind(sep)
                    if idx != -1:
                        chunk_end = search_start + idx + len(sep)
                        break

            chunk_text = text[pos:chunk_end]
            chunk_spans = self._detect_chunk(chunk_text, offset=pos)
            all_spans.extend(chunk_spans)

            next_pos = chunk_end - CHUNK_OVERLAP
            if next_pos <= pos:
                next_pos = pos + CHUNK_MAX_CHARS - CHUNK_OVERLAP
            pos = next_pos

        return self._dedup_spans(all_spans)

    @staticmethod
    def _dedup_spans(spans: list[Span]) -> list[Span]:
        """Remove duplicate spans from overlapping chunks."""
        if not spans:
            return []

        spans = sorted(spans, key=lambda s: (s.start, -s.confidence))
        result: list[Span] = [spans[0]]

        for span in spans[1:]:
            last = result[-1]
            if span.start < last.end:
                # Overlapping — keep higher confidence
                if span.confidence > last.confidence:
                    result[-1] = span
            else:
                result.append(span)

        return result
