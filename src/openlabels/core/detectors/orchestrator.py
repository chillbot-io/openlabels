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
from ..types import DetectionResult, Span, normalize_entity_type
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

        if self.config.enable_hyperscan:
            self._init_hyperscan_detector()

        _CONFIG_TO_DETECTORS: list[tuple[str, list[str]]] = [
            ("enable_checksum", ["checksum"]),
            ("enable_secrets", ["secrets"]),
            ("enable_financial", ["financial"]),
            ("enable_government", ["government"]),
            ("enable_patterns", ["pattern", "additional_patterns"]),
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
        """Initialize ML-based detectors."""
        if model_dir is None:
            from openlabels.core.constants import DEFAULT_MODELS_DIR
            model_dir = DEFAULT_MODELS_DIR

        model_dir = Path(model_dir).expanduser()

        if not model_dir.exists():
            logger.warning(
                "ML model directory not found: %s  "
                "(download models with: openlabels models download ner)",
                model_dir,
            )
            return

        if use_onnx:
            # Try ONNX detectors first (faster)
            try:
                from .ml_onnx import PHIBertONNXDetector, PIIBertONNXDetector

                phi_bert = PHIBertONNXDetector(model_dir=model_dir)
                if phi_bert.is_available():
                    self.detectors.append(phi_bert)
                    logger.info("PHI-BERT ONNX detector loaded")

                pii_bert = PIIBertONNXDetector(model_dir=model_dir)
                if pii_bert.is_available():
                    self.detectors.append(pii_bert)
                    logger.info("PII-BERT ONNX detector loaded")

            except ImportError as e:
                logger.warning(f"ONNX detectors not available: {e}")
                use_onnx = False

        if not use_onnx:
            # Fall back to HuggingFace transformers
            try:
                from .ml import PHIBertDetector, PIIBertDetector

                phi_bert_dir = model_dir / "phi_bert"
                if phi_bert_dir.exists():
                    phi_hf = PHIBertDetector(model_path=phi_bert_dir)
                    if phi_hf.is_available():
                        self.detectors.append(phi_hf)
                        logger.info("PHI-BERT HF detector loaded")

                pii_bert_dir = model_dir / "pii_bert"
                if pii_bert_dir.exists():
                    pii_hf = PIIBertDetector(model_path=pii_bert_dir)
                    if pii_hf.is_available():
                        self.detectors.append(pii_hf)
                        logger.info("PII-BERT HF detector loaded")

            except ImportError as e:
                logger.warning(f"HuggingFace detectors not available: {e}")

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

        processed_spans = self._post_process(all_spans)

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

    def _post_process(self, spans: list[Span]) -> list[Span]:
        """Post-process: calibrate confidence, filter, deduplicate, sort."""
        calibrated = calibrate_spans(spans)
        return resolve_spans(
            calibrated,
            confidence_threshold=self.confidence_threshold,
        )

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
