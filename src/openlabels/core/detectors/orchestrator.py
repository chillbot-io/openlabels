"""Coordinates parallel detectors with deduplication and post-processing."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from openlabels.core.constants import DETECTOR_TIMEOUT
from openlabels.exceptions import DetectionError

from ..pipeline.confidence import calibrate_spans
from ..pipeline.span_resolver import resolve_spans
from ..policies.engine import get_policy_engine
from ..policies.schema import EntityMatch
from ..types import DetectionResult, Span, Tier, normalize_entity_type
from .base import BaseDetector
from .config import DetectionConfig
from .registry import create_detector

logger = logging.getLogger(__name__)

# Default confidence threshold for filtering
DEFAULT_CONFIDENCE_THRESHOLD = 0.70


class DetectorOrchestrator:
    """Runs detectors in parallel, deduplicates results, and applies post-processing."""

    def __init__(self, config: DetectionConfig | None = None):
        self.config = config or DetectionConfig()
        self.confidence_threshold = self.config.confidence_threshold
        self.max_workers = self.config.max_workers
        self.detectors: list[BaseDetector] = []
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self._using_hyperscan = False
        self._entity_threshold_map: dict[str, float] = dict(
            self.config.entity_thresholds
        )

        if self.config.enable_hyperscan:
            self._init_hyperscan_detector()

        _CONFIG_TO_DETECTORS: list[tuple[str, list[str]]] = [
            ("enable_checksum", ["checksum"]),
            ("enable_secrets", ["secrets"]),
            ("enable_financial", ["financial"]),
            ("enable_government", ["government"]),
            ("enable_patterns", ["pattern", "additional_patterns"]),
            ("enable_dictionary_names", ["dictionary_names"]),
        ]

        for flag, names in _CONFIG_TO_DETECTORS:
            if getattr(self.config, flag):
                for name in names:
                    try:
                        self.detectors.append(create_detector(name))
                    except KeyError:
                        logger.warning("Detector %r not registered — skipping", name)

        if self.config.enable_ml:
            self._init_ml_detectors(self.config.ml_model_dir, self.config.use_onnx)

        if self.config.enable_multilingual:
            self._init_multilingual_gliner()

        if self.config.enable_spacy_ner:
            self._init_spacy_ner()

        self._coref_resolver: Callable[..., list[Span]] | None = None
        self._context_enhancer: Any = None
        if self.config.enable_coref or self.config.enable_context_enhancement:
            self._init_pipeline(
                self.config.enable_coref,
                self.config.enable_context_enhancement,
            )

        logger.info(
            f"DetectorOrchestrator initialized with {len(self.detectors)} detectors: "
            f"{[d.name for d in self.detectors]}"
            f"{' (Hyperscan accelerated)' if self._using_hyperscan else ''}"
        )

    def _init_hyperscan_detector(self) -> None:
        """Initialize Hyperscan-accelerated detector."""
        try:
            from .hyperscan import SUPPLEMENTAL_PATTERNS, HyperscanDetector

            hyperscan_detector = HyperscanDetector(
                additional_patterns=SUPPLEMENTAL_PATTERNS
            )
            self.detectors.append(hyperscan_detector)
            self._using_hyperscan = hyperscan_detector.using_hyperscan
            logger.info(
                f"Hyperscan detector initialized with {hyperscan_detector.pattern_count} patterns"
                f" ({'SIMD-accelerated' if self._using_hyperscan else 'Python fallback'})"
            )
        except (ImportError, RuntimeError, OSError, ValueError) as e:
            logger.warning(f"Failed to initialize Hyperscan detector: {e}")

    def _init_ml_detectors(
        self,
        model_dir: Path | None,
        use_onnx: bool = True
    ) -> None:
        """Initialize ML-based detectors (GLiNER)."""
        try:
            from .gliner import GLiNERDetector

            gliner = GLiNERDetector(
                model_name=self.config.gliner_model,
                threshold=self.config.gliner_threshold,
                use_onnx=use_onnx,
                enable_label_selection=self.config.enable_label_selection,
            )
            if gliner.load():
                self.detectors.append(gliner)
                logger.info("GLiNER detector loaded: %s", self.config.gliner_model)
            else:
                logger.warning("GLiNER detector failed to load")

        except ImportError as e:
            logger.warning("GLiNER detector not available: %s", e)

    def _init_multilingual_gliner(self) -> None:
        """Initialize multilingual GLiNER detector (9 EU languages)."""
        try:
            from .multilingual_gliner import MultilingualGLiNERDetector

            ml_gliner = MultilingualGLiNERDetector(
                model_name=self.config.multilingual_gliner_model,
                threshold=self.config.multilingual_gliner_threshold,
                use_onnx=self.config.use_onnx,
                enable_label_selection=self.config.enable_label_selection,
            )
            if ml_gliner.load():
                self.detectors.append(ml_gliner)
                logger.info(
                    "Multilingual GLiNER detector loaded: %s",
                    self.config.multilingual_gliner_model,
                )
            else:
                logger.warning("Multilingual GLiNER detector failed to load")

        except ImportError as e:
            logger.warning("Multilingual GLiNER detector not available: %s", e)

    def _init_spacy_ner(self) -> None:
        """Initialize spaCy NER detector for ensemble."""
        try:
            from .spacy_ner import SpacyNERDetector

            spacy_det = SpacyNERDetector()
            if spacy_det.load():
                self.detectors.append(spacy_det)
                logger.info("spaCy NER detector loaded")
            else:
                logger.warning("spaCy NER detector failed to load")
        except ImportError as e:
            logger.warning("spaCy NER detector not available: %s", e)

    def _init_pipeline(
        self,
        enable_coref: bool,
        enable_context_enhancement: bool
    ) -> None:
        """Initialize post-processing pipeline components."""
        if enable_coref:
            try:
                from ..pipeline import resolve_coreferences
                self._coref_resolver = resolve_coreferences
                logger.info("Coreference resolution enabled")
            except ImportError as e:
                logger.warning(f"Coreference resolution not available: {e}")

        if enable_context_enhancement:
            try:
                from ..pipeline import create_enhancer
                self._context_enhancer = create_enhancer()
                logger.info("Context enhancement enabled")
            except ImportError as e:
                logger.warning(f"Context enhancement not available: {e}")

    async def detect(self, text: str) -> DetectionResult:
        """Async wrapper around detect_sync via run_in_executor."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.detect_sync, text)

    def detect_sync(self, text: str) -> DetectionResult:
        """Run all detectors on the input text (synchronous entry point)."""
        start_time = time.time()

        if not text or not text.strip():
            return DetectionResult(
                spans=[],
                entity_counts={},
                processing_time_ms=0.0,
                detectors_used=[],
                text_length=0,
            )

        all_spans: list[Span] = []
        detectors_used: list[str] = []

        future_to_detector = {
            self._executor.submit(self._run_detector, detector, text): detector
            for detector in self.detectors
        }

        try:
            for future in as_completed(future_to_detector, timeout=DETECTOR_TIMEOUT):
                detector = future_to_detector[future]
                try:
                    spans = future.result()
                    all_spans.extend(spans)
                    if spans:
                        detectors_used.append(detector.name)
                except (DetectionError, RuntimeError, ValueError, OSError) as e:
                    logger.error(f"Detector {detector.name} failed: {e}")
        except TimeoutError:
            timed_out = [
                future_to_detector[f].name
                for f in future_to_detector
                if not f.done()
            ]
            logger.error(f"Detector timeout ({DETECTOR_TIMEOUT}s): {timed_out}")

        processed_spans = self._post_process(all_spans, text=text)

        if self.config.enable_allowlist and processed_spans:
            from .allowlist import get_allowlist
            processed_spans = get_allowlist().filter_spans(processed_spans)

        if self._coref_resolver and processed_spans:
            try:
                processed_spans = self._coref_resolver(text, processed_spans)
            except (RuntimeError, ValueError, IndexError) as e:
                logger.error(f"Coreference resolution failed: {e}")

        if self._context_enhancer and processed_spans:
            try:
                processed_spans = self._context_enhancer.enhance(text, processed_spans)
            except (RuntimeError, ValueError, IndexError) as e:
                logger.error(f"Context enhancement failed: {e}")

        policy_result = None
        if self.config.enable_policy and processed_spans:
            try:
                entity_matches = [
                    EntityMatch(
                        entity_type=span.entity_type,
                        value=span.text,
                        confidence=span.confidence,
                        start=span.start,
                        end=span.end,
                        source=span.detector,
                    )
                    for span in processed_spans
                ]
                policy_result = get_policy_engine().evaluate(entity_matches)
            except (ValueError, KeyError, RuntimeError) as e:
                logger.error(f"Policy evaluation failed: {e}")

        entity_counts: dict[str, int] = {}
        for span in processed_spans:
            normalized = normalize_entity_type(span.entity_type)
            entity_counts[normalized] = entity_counts.get(normalized, 0) + 1

        processing_time_ms = (time.time() - start_time) * 1000

        return DetectionResult(
            spans=processed_spans,
            entity_counts=entity_counts,
            processing_time_ms=processing_time_ms,
            detectors_used=detectors_used,
            text_length=len(text),
            policy_result=policy_result,
        )

    def _run_detector(self, detector: BaseDetector, text: str) -> list[Span]:
        """Run a single detector with error handling."""
        try:
            if not detector.is_available():
                logger.warning(f"Detector {detector.name} not available")
                return []
            return detector.detect(text)
        except (DetectionError, RuntimeError, ValueError, OSError) as e:
            logger.error(f"Error in detector {detector.name}: {e}")
            return []

    def shutdown(self) -> None:
        """Shut down the persistent thread pool."""
        self._executor.shutdown(wait=False)

    def _passes_threshold(self, span: Span) -> bool:
        """Check if a span meets its confidence threshold.

        Per-entity thresholds take priority, then ML vs global threshold.
        """
        entity_thresh = self._entity_threshold_map.get(span.entity_type)
        if entity_thresh is not None:
            return span.confidence >= entity_thresh
        if span.tier == Tier.ML:
            return span.confidence >= self.config.ml_confidence_threshold
        return span.confidence >= self.confidence_threshold

    # Ensemble boost amount when 2+ detectors agree on the same span.
    _ENSEMBLE_BOOST = 0.15

    def _post_process(
        self,
        spans: list[Span],
        text: str | None = None,
    ) -> list[Span]:
        """Post-process: filter, context-adjust, calibrate, ensemble, deduplicate.

        Pipeline order:
        1. Filter by per-entity / per-tier raw confidence threshold
        2. Apply context keyword boost/demote (on raw confidence)
        3. Calibrate into unified tier bands
        4. Ensemble boost (when 2+ detectors agree)
        5. Resolve overlapping spans
        6. Proximity boost (optional)
        """
        filtered = [s for s in spans if self._passes_threshold(s)]

        # Context keyword adjustment (before calibration)
        if self.config.enable_context_keywords and text and filtered:
            from ..pipeline.context_keywords import apply_context_keywords
            filtered = apply_context_keywords(filtered, text)

        calibrated = calibrate_spans(filtered)

        # Ensemble boost: when multiple detectors agree on overlapping
        # spans with the same entity type, boost the best span's confidence.
        calibrated = self._apply_ensemble_boost(calibrated)

        resolved = resolve_spans(
            calibrated, confidence_threshold=0.0, source_text=text,
        )

        if self.config.enable_proximity_boost and resolved:
            from ..pipeline.entity_proximity import analyze_proximity
            proximity = analyze_proximity(
                resolved,
                proximity_chars=self.config.proximity_window_chars,
            )
            if proximity.boost_count:
                logger.debug(
                    "Proximity boosting: %d/%d spans boosted across %d clusters",
                    proximity.boost_count,
                    proximity.original_span_count,
                    len(proximity.clusters),
                )
            resolved = proximity.boosted_spans

        return resolved

    def _apply_ensemble_boost(self, spans: list[Span]) -> list[Span]:
        """Boost confidence when multiple detectors agree on the same entity.

        For each span, checks if a different detector produced an overlapping
        span with a compatible entity type (same evaluation category, e.g.
        FIRSTNAME and NAME are both "names").  If so, the higher-confidence
        span gets boosted (clamped to 1.0).

        This rewards multi-detector agreement without adding new detections.
        """
        if len(spans) < 2:
            return spans

        from ..benchmark.entity_mapping import EVAL_CATEGORIES

        def _entity_group(entity_type: str) -> str:
            """Return the category group for an entity type, or its normalized form."""
            norm = normalize_entity_type(entity_type)
            return EVAL_CATEGORIES.get(norm, norm)

        boosted_indices: set[int] = set()
        result = list(spans)

        for i, span_a in enumerate(spans):
            if i in boosted_indices:
                continue
            group_a = _entity_group(span_a.entity_type)
            for j, span_b in enumerate(spans):
                if i == j or span_a.detector == span_b.detector:
                    continue
                if not span_a.overlaps(span_b):
                    continue
                group_b = _entity_group(span_b.entity_type)
                if group_a != group_b:
                    continue
                # Two different detectors agree — boost the stronger one.
                if i not in boosted_indices:
                    new_conf = min(1.0, span_a.confidence + self._ENSEMBLE_BOOST)
                    result[i] = Span(
                        start=span_a.start,
                        end=span_a.end,
                        text=span_a.text,
                        entity_type=span_a.entity_type,
                        confidence=new_conf,
                        detector=span_a.detector,
                        tier=span_a.tier,
                        context=span_a.context,
                        needs_review=span_a.needs_review,
                        review_reason=span_a.review_reason,
                        coref_anchor_value=span_a.coref_anchor_value,
                    )
                    boosted_indices.add(i)
                    logger.debug(
                        "Ensemble boost: %s %r %.3f→%.3f (corroborated by %s)",
                        span_a.entity_type, span_a.text,
                        span_a.confidence, new_conf, span_b.detector,
                    )
                break  # Only boost once per span

        return result

    def add_detector(self, detector: BaseDetector) -> None:
        """Add a custom detector to the orchestrator."""
        self.detectors.append(detector)
        logger.info(f"Added detector: {detector.name}")

    def remove_detector(self, name: str) -> bool:
        """Remove a detector by name."""
        for i, detector in enumerate(self.detectors):
            if detector.name == name:
                self.detectors.pop(i)
                logger.info(f"Removed detector: {name}")
                return True
        return False

    @property
    def detector_names(self) -> list[str]:
        """Get list of active detector names."""
        return [d.name for d in self.detectors]


def detect(
    text: str,
    config: DetectionConfig | None = None,
    **kwargs: object,
) -> DetectionResult:
    """Detect entities in text using a one-shot orchestrator."""
    if config is None:
        from dataclasses import fields as dc_fields
        config_kwargs = {
            k: v for k, v in kwargs.items()
            if k in {f.name for f in dc_fields(DetectionConfig)}
        }
        config = DetectionConfig(**config_kwargs)  # type: ignore[arg-type]

    orchestrator = DetectorOrchestrator(config=config)
    return orchestrator.detect_sync(text)
