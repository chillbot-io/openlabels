"""
Detector orchestrator for OpenLabels detection engine.

Coordinates multiple detectors running in parallel and handles
deduplication and post-processing of results.

Supports:
- Pattern-based detectors (checksum, secrets, financial, government)
- Hyperscan-accelerated detection (10-100x faster when available)
- ML detectors (PHI-BERT, PII-BERT) with optional ONNX acceleration
- Post-processing pipeline (coref, context enhancement)
"""

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from ..types import Span, DetectionResult, normalize_entity_type
from ..pipeline.span_resolver import resolve_spans
from ..policies.engine import get_policy_engine
from ..policies.schema import EntityMatch
from .base import BaseDetector
from .checksum import ChecksumDetector
from .config import DetectionConfig
from .secrets import SecretsDetector
from .financial import FinancialDetector
from .government import GovernmentDetector
from .patterns import PatternDetector
from .additional_patterns import AdditionalPatternDetector

logger = logging.getLogger(__name__)

# Default detector timeout in seconds
DETECTOR_TIMEOUT = 30.0

# Default confidence threshold for filtering
DEFAULT_CONFIDENCE_THRESHOLD = 0.70


class DetectorOrchestrator:
    """
    Orchestrates multiple detectors for comprehensive entity detection.

    Features:
    - Runs detectors in parallel for performance
    - Supports pattern-based and ML-based detectors
    - Optional Hyperscan acceleration (10-100x faster regex)
    - Handles deduplication across detectors
    - Higher tier detections take precedence
    - Optional post-processing pipeline (coref, context enhancement)

    Usage:
        orchestrator = DetectorOrchestrator()
        result = orchestrator.detect("My SSN is 123-45-6789")
        for span in result.spans:
            print(f"{span.entity_type}: {span.text}")

        # With Hyperscan acceleration:
        orchestrator = DetectorOrchestrator(DetectionConfig(enable_hyperscan=True))

        # Full config with ML:
        orchestrator = DetectorOrchestrator(DetectionConfig.full())
    """

    def __init__(self, config: DetectionConfig | None = None):
        """
        Initialize the orchestrator with configured detectors.

        Args:
            config: Detection configuration. Uses DetectionConfig() defaults
                    (all pattern detectors enabled, no ML) when not provided.
        """
        self.config = config or DetectionConfig()
        self.confidence_threshold = self.config.confidence_threshold
        self.max_workers = self.config.max_workers
        self.detectors: List[BaseDetector] = []
        self._using_hyperscan = False

        # Initialize Hyperscan detector if enabled
        if self.config.enable_hyperscan:
            self._init_hyperscan_detector()

        # Initialize pattern-based detectors
        if self.config.enable_checksum:
            self.detectors.append(ChecksumDetector())
        if self.config.enable_secrets:
            self.detectors.append(SecretsDetector())
        if self.config.enable_financial:
            self.detectors.append(FinancialDetector())
        if self.config.enable_government:
            self.detectors.append(GovernmentDetector())
        if self.config.enable_patterns:
            self.detectors.append(PatternDetector())
            self.detectors.append(AdditionalPatternDetector())

        # Initialize ML detectors if enabled
        if self.config.enable_ml:
            self._init_ml_detectors(self.config.ml_model_dir, self.config.use_onnx)

        # Initialize post-processing components
        self._coref_resolver: Callable[..., List[Span]] | None = None
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
            from .hyperscan import HyperscanDetector, SUPPLEMENTAL_PATTERNS

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
        model_dir: Optional[Path],
        use_onnx: bool = True
    ) -> None:
        """Initialize ML-based detectors."""
        if model_dir is None:
            from openlabels.core.constants import DEFAULT_MODELS_DIR
            model_dir = DEFAULT_MODELS_DIR

        model_dir = Path(model_dir).expanduser()

        if not model_dir.exists():
            logger.warning(f"ML model directory not found: {model_dir}")
            return

        if use_onnx:
            # Try ONNX detectors first (faster)
            try:
                from .ml_onnx import PHIBertONNXDetector, PIIBertONNXDetector

                # PHI-BERT for clinical/healthcare NER
                phi_bert = PHIBertONNXDetector(model_dir=model_dir)
                if phi_bert.is_available():
                    self.detectors.append(phi_bert)
                    logger.info("PHI-BERT ONNX detector loaded")

                # PII-BERT for general PII NER
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

                # PHI-BERT
                phi_bert_dir = model_dir / "phi_bert"
                if phi_bert_dir.exists():
                    phi_hf = PHIBertDetector(model_path=phi_bert_dir)
                    if phi_hf.is_available():
                        self.detectors.append(phi_hf)
                        logger.info("PHI-BERT HF detector loaded")

                # PII-BERT
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
        """
        Async: run all detectors via run_in_executor.

        Use this from async code (server, jobs).  For synchronous
        callers (CLI, tests), use ``detect_sync`` instead.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.detect_sync, text)

    def detect_sync(self, text: str) -> DetectionResult:
        """
        Run all detectors on the input text (synchronous).

        Args:
            text: Text to scan for entities

        Returns:
            DetectionResult with all detected spans
        """
        start_time = time.time()

        if not text or not text.strip():
            return DetectionResult(
                spans=[],
                entity_counts={},
                processing_time_ms=0.0,
                detectors_used=[],
                text_length=0,
            )

        # Run detectors in parallel
        all_spans: List[Span] = []
        detectors_used: List[str] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_detector = {
                executor.submit(self._run_detector, detector, text): detector
                for detector in self.detectors
            }

            for future in as_completed(future_to_detector, timeout=DETECTOR_TIMEOUT):
                detector = future_to_detector[future]
                try:
                    spans = future.result()
                    all_spans.extend(spans)
                    if spans:
                        detectors_used.append(detector.name)
                except (RuntimeError, ValueError, OSError) as e:
                    logger.error(f"Detector {detector.name} failed: {e}")

        # Post-process: deduplicate, filter, sort
        processed_spans = self._post_process(all_spans)

        # Run coreference resolution if enabled
        if self._coref_resolver and processed_spans:
            try:
                processed_spans = self._coref_resolver(text, processed_spans)
            except (RuntimeError, ValueError, IndexError) as e:
                logger.error(f"Coreference resolution failed: {e}")

        # Run context enhancement if enabled
        if self._context_enhancer and processed_spans:
            try:
                processed_spans = self._context_enhancer.enhance(text, processed_spans)
            except (RuntimeError, ValueError, IndexError) as e:
                logger.error(f"Context enhancement failed: {e}")

        # Policy evaluation
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

        # Calculate entity counts
        entity_counts: Dict[str, int] = {}
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

    def _run_detector(self, detector: BaseDetector, text: str) -> List[Span]:
        """Run a single detector with error handling."""
        try:
            if not detector.is_available():
                logger.warning(f"Detector {detector.name} not available")
                return []
            return detector.detect(text)
        except (RuntimeError, ValueError, OSError) as e:
            logger.error(f"Error in detector {detector.name}: {e}")
            return []

    def _post_process(self, spans: List[Span]) -> List[Span]:
        """Post-process: filter by confidence, deduplicate, sort."""
        return resolve_spans(
            spans,
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
    def detector_names(self) -> List[str]:
        """Get list of active detector names."""
        return [d.name for d in self.detectors]


# Convenience function for simple usage
def detect(
    text: str,
    config: DetectionConfig | None = None,
    **kwargs: object,
) -> DetectionResult:
    """
    Convenience function to detect entities in text.

    Args:
        text: Text to scan
        config: Detection configuration (defaults to patterns-only)
        **kwargs: Override individual DetectionConfig fields

    Returns:
        DetectionResult with detected spans
    """
    if config is None:
        # Build config from kwargs for backwards-compatible call sites
        from dataclasses import fields as dc_fields
        config_kwargs = {
            k: v for k, v in kwargs.items()
            if k in {f.name for f in dc_fields(DetectionConfig)}
        }
        config = DetectionConfig(**config_kwargs)  # type: ignore[arg-type]

    orchestrator = DetectorOrchestrator(config=config)
    return orchestrator.detect_sync(text)
