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

# Minimum span text length for structured entity types.
# GLiNER often hallucinates these types on short alphanumeric fragments
# (transaction codes, reference numbers, EDI segment IDs) that are far
# too short to be the claimed entity.  Pattern / checksum detectors
# already catch real instances of these types reliably.
_MIN_SPAN_LENGTHS: dict[str, int] = {
    "VIN": 11,               # Real VINs are 17 chars
    "LICENSE_PLATE": 4,      # Plates are 4-8 chars
    "IBAN": 15,              # Minimum IBAN length
    "CREDIT_CARD": 12,       # Minimum CC length (with spaces)
    "SWIFT_BIC": 8,          # SWIFT/BIC is 8 or 11 chars
    "BANK_ROUTING": 9,       # US ABA routing is 9 digits
    "ACCOUNT_NUMBER": 5,     # Must be at least 5 chars
    "IP_ADDRESS": 7,         # Minimum "0.0.0.0"
    "MAC_ADDRESS": 12,       # "AA:BB:CC:DD:EE:FF" minimum with separators
}

# Entity labels we ask GLiNER to detect, mapped to OpenLabels canonical types.
# Keys are the natural-language labels passed to predict_entities().
# Values are the OpenLabels entity type strings.
GLINER_LABEL_MAP: dict[str, str] = {
    # Names
    "person name": "NAME",
    "first name": "FIRSTNAME",
    "last name": "LASTNAME",
    "middle name": "MIDDLENAME",
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
    "county": "COUNTY",
    "gps coordinate": "GPS_COORDINATE",
    # Dates / Time
    "date of birth": "DATE_DOB",
    "date": "DATE",
    "date and time": "DATETIME",
    "time": "TIME",
    "age": "AGE",
    # Government IDs
    "social security number": "SSN",
    "driver license number": "DRIVER_LICENSE",
    "passport number": "PASSPORT",
    "tax identification number": "TAX_ID",
    "national identity number": "STATE_ID",
    # Medical
    "medical record number": "MRN",
    "health plan number": "HEALTH_PLAN_ID",
    "npi number": "NPI",
    "medical license number": "MEDICAL_LICENSE",
    # Financial
    "credit card number": "CREDIT_CARD",
    "bank account number": "ACCOUNT_NUMBER",
    "bank routing number": "BANK_ROUTING",
    "iban": "IBAN",
    "swift code": "SWIFT_BIC",
    # Network / Device
    "ip address": "IP_ADDRESS",
    "mac address": "MAC_ADDRESS",
    "device identifier": "DEVICE_ID",
    "imei number": "IMEI",
    # Vehicle
    "vehicle identification number": "VIN",
    "license plate number": "LICENSE_PLATE",
    # Crypto
    "bitcoin address": "BITCOIN_ADDRESS",
    "ethereum address": "ETHEREUM_ADDRESS",
    # Professional
    "company name": "COMPANY",
    "employer": "EMPLOYER",
    "employee id": "EMPLOYEE_ID",
    "job title": "JOB_TITLE",
    # IDs / Certificates
    "unique identifier": "UNIQUE_ID",
    "certificate number": "CERTIFICATE_NUMBER",
    "biometric identifier": "BIOMETRIC_ID",
    # Secrets
    "password": "PASSWORD",
    "pin code": "PASSWORD",
    "api key": "API_KEY",
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
        threshold: float = 0.4,
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

        When ``use_onnx`` is True but the model has no ONNX weights,
        automatically falls back to the PyTorch checkpoint.

        Returns:
            True if loaded successfully.
        """
        try:
            from gliner import GLiNER
        except ImportError:
            logger.warning(
                "gliner library not installed — GLiNER detection disabled. "
                "Install with: pip install gliner"
            )
            return False

        try:
            self._model = GLiNER.from_pretrained(
                self.model_name,
                load_onnx_model=self.use_onnx,
            )
            self._loaded = True
            logger.info(
                "GLiNER model loaded: %s (onnx=%s)",
                self.model_name, self.use_onnx,
            )
            return True
        except (OSError, RuntimeError, ValueError) as e:
            if self.use_onnx:
                logger.warning(
                    "ONNX load failed for %s, falling back to PyTorch: %s",
                    self.model_name, e,
                )
                try:
                    self._model = GLiNER.from_pretrained(
                        self.model_name,
                        load_onnx_model=False,
                    )
                    self.use_onnx = False
                    self._loaded = True
                    logger.info(
                        "GLiNER model loaded (PyTorch fallback): %s",
                        self.model_name,
                    )
                    return True
                except (OSError, RuntimeError, ValueError) as e2:
                    logger.error(
                        "Failed to load GLiNER model %s: %s",
                        self.model_name, e2,
                    )
                    return False
            logger.error("Failed to load GLiNER model %s: %s", self.model_name, e)
            return False

    # GLiNER token window is ~512 tokens.  Character-per-token ratios vary
    # by content: prose ≈ 4 chars/token, dense financial/numeric text ≈ 2–2.5.
    # These are fallback defaults; when a model is loaded the actual
    # chars-per-token ratio is measured and chunk sizes are scaled.
    _MAX_CHUNK_CHARS = 1024
    _CHUNK_OVERLAP = 200
    _CHUNK_TARGET_TOKENS = 350  # leaves headroom for special tokens + bi-encoder overhead

    def _estimate_chars_per_token(self, text: str, sample_size: int = 500) -> float:
        """Estimate chars-per-token for *text* using the model's tokenizer.

        Falls back to 4.0 (typical English prose) when no tokenizer is
        accessible.
        """
        if not self._model:
            return 4.0

        sample = text[:sample_size]
        try:
            tokenizer = getattr(self._model, "data_processor", None)
            if tokenizer is None:
                tokenizer = getattr(self._model, "tokenizer", None)
            if tokenizer is None:
                return 4.0

            # The GLiNER data_processor / tokenizer exposes a tokenize method
            tok_fn = getattr(tokenizer, "tokenize", None)
            if tok_fn is not None:
                tokens = tok_fn(sample)
                n_tokens = max(len(tokens) - 2, 1)
            else:
                # Try encode
                enc_fn = getattr(tokenizer, "encode", None)
                if enc_fn is not None:
                    encoded = enc_fn(sample)
                    if hasattr(encoded, "ids"):
                        n_tokens = max(len(encoded.ids) - 2, 1)
                    elif isinstance(encoded, list):
                        n_tokens = max(len(encoded) - 2, 1)
                    else:
                        return 4.0
                else:
                    return 4.0

            return len(sample) / n_tokens
        except Exception:
            return 4.0

    def _compute_chunk_params(self, text: str) -> tuple[int, int]:
        """Return (max_chars, overlap) tuned for *text*."""
        cpt = self._estimate_chars_per_token(text)
        max_chars = max(400, int(self._CHUNK_TARGET_TOKENS * cpt))
        overlap = max(80, int(max_chars * 0.15))
        return max_chars, overlap

    def detect(self, text: str) -> list[Span]:
        """Detect PII entities using GLiNER.

        Long texts are automatically chunked into overlapping windows
        to avoid silent entity loss beyond the transformer window.
        Chunk sizes are computed dynamically based on the tokenizer's
        actual chars-per-token ratio for the input text.

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

        # Compute tokenizer-aware chunk sizes
        max_chars, overlap = self._compute_chunk_params(text)

        # Chunk if text exceeds GLiNER's effective window
        if len(text) > max_chars:
            return self._detect_chunked(text, labels, max_chars, overlap)

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
        from .gliner_calibration import calibrate_gliner_score

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
            raw_score = float(entity["score"])

            # Apply Platt scaling calibration
            score_val = calibrate_gliner_score(label, raw_score)

            # Validate offsets against the chunk text
            if start < 0 or end <= start or end > len(text):
                continue

            span_text = text[start:end]

            # Reject spans that are too short for their entity type.
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
                    raw_confidence=raw_score,
                    detector_label=label,
                )
                spans.append(span)
            except ValueError as e:
                logger.debug("GLiNER: Invalid span skipped: %s", e)

        return spans

    def _detect_chunked(
        self,
        text: str,
        labels: list[str],
        max_chars: int = 0,
        overlap: int = 0,
    ) -> list[Span]:
        """Split text into overlapping chunks, detect per chunk, merge results."""
        from ..pipeline.chunking import TextChunker

        chunker = TextChunker(
            max_chunk_size=max_chars or self._MAX_CHUNK_CHARS,
            overlap=overlap or self._CHUNK_OVERLAP,
        )
        chunks = chunker.chunk(text)

        all_spans: list[Span] = []
        for chunk in chunks:
            chunk_spans = self._detect_single(chunk.text, labels, offset=chunk.start)
            all_spans.extend(chunk_spans)

        return self._dedup_chunk_spans(all_spans, source_text=text)

    @staticmethod
    def _dedup_chunk_spans(spans: list[Span], source_text: str = "") -> list[Span]:
        """Deduplicate overlapping spans from adjacent chunks.

        Uses cluster-based deduplication with weighted interval
        scheduling to select the optimal non-overlapping set.
        Same-type overlapping spans are merged; different-type
        overlaps are resolved by choosing the combination that
        maximises total (confidence * length).
        """
        if not spans:
            return []

        spans_sorted = sorted(spans, key=lambda s: (s.start, -s.confidence))

        # Group overlapping spans into clusters
        clusters: list[list[Span]] = []
        cluster: list[Span] = [spans_sorted[0]]
        cluster_end = spans_sorted[0].end

        for span in spans_sorted[1:]:
            if span.start < cluster_end:
                cluster.append(span)
                cluster_end = max(cluster_end, span.end)
            else:
                clusters.append(cluster)
                cluster = [span]
                cluster_end = span.end
        clusters.append(cluster)

        result: list[Span] = []
        for grp in clusters:
            if len(grp) == 1:
                result.extend(grp)
                continue

            # Merge same-type overlapping spans
            by_type: dict[str, list[Span]] = {}
            for s in grp:
                by_type.setdefault(s.entity_type, []).append(s)

            merged: list[Span] = []
            for etype, type_spans in by_type.items():
                type_spans.sort(key=lambda s: s.start)
                cur = type_spans[0]
                for s in type_spans[1:]:
                    overlap = cur.end - s.start
                    min_len = min(cur.end - cur.start, s.end - s.start)
                    if min_len > 0 and overlap > min_len * 0.5:
                        # Merge: widen extent, keep max confidence
                        new_start = min(cur.start, s.start)
                        new_end = max(cur.end, s.end)
                        new_conf = max(cur.confidence, s.confidence)
                        best = cur if cur.confidence >= s.confidence else s

                        # Derive merged text from source document when
                        # available so that the text always matches the
                        # widened [start, end) range.  Fall back to
                        # reconstructing from the two overlapping span
                        # texts when source_text is not provided.
                        if source_text:
                            merged_text = source_text[new_start:new_end]
                        else:
                            # Reconstruct: left span first, append
                            # non-overlapping tail of right span.
                            if cur.start <= s.start:
                                left, right = cur, s
                            else:
                                left, right = s, cur
                            ovl = left.end - right.start
                            merged_text = left.text + right.text[max(ovl, 0):]

                        cur = Span(
                            start=new_start,
                            end=new_end,
                            text=merged_text,
                            entity_type=etype,
                            confidence=new_conf,
                            detector=best.detector,
                            tier=best.tier,
                        )
                    else:
                        merged.append(cur)
                        cur = s
                merged.append(cur)

            merged.sort(key=lambda s: s.end)

            if len(merged) == 1:
                result.extend(merged)
                continue

            # Weighted interval scheduling for optimal selection
            n = len(merged)
            weights = [s.confidence * (s.end - s.start) for s in merged]

            p = [-1] * n
            for i in range(n):
                for j in range(i - 1, -1, -1):
                    if merged[j].end <= merged[i].start:
                        p[i] = j
                        break

            dp = [0.0] * n
            dp[0] = weights[0]
            for i in range(1, n):
                include = weights[i] + (dp[p[i]] if p[i] >= 0 else 0)
                dp[i] = max(dp[i - 1], include)

            selected: list[Span] = []
            i = n - 1
            while i >= 0:
                include = weights[i] + (dp[p[i]] if p[i] >= 0 else 0)
                if i == 0 or include >= dp[i - 1]:
                    selected.append(merged[i])
                    i = p[i]
                else:
                    i -= 1
            selected.reverse()
            result.extend(selected)

        return result
