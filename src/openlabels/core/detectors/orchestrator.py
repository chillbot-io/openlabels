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

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

from ..types import Span, Tier, DetectionResult, normalize_entity_type
from .base import BaseDetector
from .checksum import ChecksumDetector
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
        orchestrator = DetectorOrchestrator(enable_hyperscan=True)

        # With ML detectors:
        from openlabels.core.constants import DEFAULT_MODELS_DIR
        orchestrator = DetectorOrchestrator(
            enable_ml=True,
            ml_model_dir=DEFAULT_MODELS_DIR,
            use_onnx=True,
        )
    """

    def __init__(
        self,
        enable_checksum: bool = True,
        enable_secrets: bool = True,
        enable_financial: bool = True,
        enable_government: bool = True,
        enable_patterns: bool = True,
        enable_hyperscan: bool = False,
        enable_ml: bool = False,
        ml_model_dir: Optional[Path] = None,
        use_onnx: bool = True,
        enable_coref: bool = False,
        enable_context_enhancement: bool = False,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
        max_workers: int = 4,
    ):
        """
        Initialize the orchestrator with configured detectors.

        Args:
            enable_checksum: Enable checksum-validated detector
            enable_secrets: Enable secrets/credentials detector
            enable_financial: Enable financial instruments detector
            enable_government: Enable government markings detector
            enable_patterns: Enable general pattern detector (phone, email, date, name, etc.)
            enable_hyperscan: Enable Hyperscan-accelerated detector (10-100x faster)
            enable_ml: Enable ML-based detectors (requires model files)
            ml_model_dir: Directory containing ML model files
            use_onnx: Use ONNX-optimized ML detectors (faster)
            enable_coref: Run coreference resolution on NAME entities
            enable_context_enhancement: Run context enhancement for FP filtering
            confidence_threshold: Minimum confidence to include results
            max_workers: Max parallel detector threads
        """
        self.confidence_threshold = confidence_threshold
        self.max_workers = max_workers
        self.enable_coref = enable_coref
        self.enable_context_enhancement = enable_context_enhancement
        self.detectors: List[BaseDetector] = []
        self._using_hyperscan = False

        # Initialize Hyperscan detector if enabled
        if enable_hyperscan:
            self._init_hyperscan_detector()

        # Initialize pattern-based detectors
        if enable_checksum:
            self.detectors.append(ChecksumDetector())
        if enable_secrets:
            self.detectors.append(SecretsDetector())
        if enable_financial:
            self.detectors.append(FinancialDetector())
        if enable_government:
            self.detectors.append(GovernmentDetector())
        if enable_patterns:
            self.detectors.append(PatternDetector())
            self.detectors.append(AdditionalPatternDetector())

        # Initialize ML detectors if enabled
        if enable_ml:
            self._init_ml_detectors(ml_model_dir, use_onnx)

        # Initialize post-processing components
        self._coref_resolver = None
        self._context_enhancer = None
        if enable_coref or enable_context_enhancement:
            self._init_pipeline(enable_coref, enable_context_enhancement)

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
        except Exception as e:
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
                    phi_bert = PHIBertDetector(model_path=phi_bert_dir)
                    if phi_bert.is_available():
                        self.detectors.append(phi_bert)
                        logger.info("PHI-BERT HF detector loaded")

                # PII-BERT
                pii_bert_dir = model_dir / "pii_bert"
                if pii_bert_dir.exists():
                    pii_bert = PIIBertDetector(model_path=pii_bert_dir)
                    if pii_bert.is_available():
                        self.detectors.append(pii_bert)
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

    def detect(self, text: str) -> DetectionResult:
        """
        Run all detectors on the input text.

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
                except Exception as e:
                    logger.error(f"Detector {detector.name} failed: {e}")

        # Post-process: deduplicate, filter, sort
        processed_spans = self._post_process(all_spans)

        # Run coreference resolution if enabled
        if self._coref_resolver and processed_spans:
            try:
                processed_spans = self._coref_resolver(text, processed_spans)
            except Exception as e:
                logger.error(f"Coreference resolution failed: {e}")

        # Run context enhancement if enabled
        if self._context_enhancer and processed_spans:
            try:
                processed_spans = self._context_enhancer.enhance(text, processed_spans)
            except Exception as e:
                logger.error(f"Context enhancement failed: {e}")

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
        )

    def _run_detector(self, detector: BaseDetector, text: str) -> List[Span]:
        """Run a single detector with error handling."""
        try:
            if not detector.is_available():
                logger.warning(f"Detector {detector.name} not available")
                return []
            return detector.detect(text)
        except Exception as e:
            logger.error(f"Error in detector {detector.name}: {e}")
            return []

    def _post_process(self, spans: List[Span]) -> List[Span]:
        """
        Post-process detected spans.

        1. Filter by confidence threshold
        2. Deduplicate overlapping spans (higher tier wins)
        3. Sort by position
        """
        if not spans:
            return []

        # Filter by confidence
        filtered = [s for s in spans if s.confidence >= self.confidence_threshold]

        # Deduplicate: for overlapping spans, keep the one with higher tier
        # (or higher confidence if same tier)
        deduped = self._deduplicate(filtered)

        # Sort by start position
        deduped.sort(key=lambda s: (s.start, -s.end))

        return deduped

    def _deduplicate(self, spans: List[Span]) -> List[Span]:
        """
        Remove duplicate/overlapping detections.

        When two spans overlap at the same position:
        - Higher tier wins (CHECKSUM > STRUCTURED > PATTERN > ML)
        - If same tier, higher confidence wins
        """
        if not spans:
            return []

        # Sort by start position, then by tier (descending), then by confidence (descending)
        sorted_spans = sorted(
            spans,
            key=lambda s: (s.start, -s.tier.value, -s.confidence)
        )

        result: List[Span] = []
        for span in sorted_spans:
            # Check if this span overlaps with any already accepted span
            overlaps = False
            for accepted in result:
                if span.overlaps(accepted):
                    # If same position, the first one (higher tier) wins
                    if span.start == accepted.start and span.end == accepted.end:
                        overlaps = True
                        break
                    # If contained within, skip
                    if accepted.contains(span):
                        overlaps = True
                        break

            if not overlaps:
                result.append(span)

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
    def detector_names(self) -> List[str]:
        """Get list of active detector names."""
        return [d.name for d in self.detectors]


# Convenience function for simple usage
def detect(
    text: str,
    enable_ml: bool = False,
    enable_patterns: bool = True,
    enable_hyperscan: bool = False,
    ml_model_dir: Optional[Union[str, Path]] = None,
    use_onnx: bool = True,
    enable_coref: bool = False,
    enable_context_enhancement: bool = False,
    **kwargs
) -> DetectionResult:
    """
    Convenience function to detect entities in text.

    Args:
        text: Text to scan
        enable_ml: Enable ML-based detectors (requires model files)
        enable_patterns: Enable general pattern detector (phone, email, date, name, etc.)
        enable_hyperscan: Enable Hyperscan-accelerated detection (10-100x faster)
        ml_model_dir: Directory containing ML model files
        use_onnx: Use ONNX-optimized ML detectors (faster)
        enable_coref: Run coreference resolution on NAME entities
        enable_context_enhancement: Run context enhancement for FP filtering
        **kwargs: Additional options passed to DetectorOrchestrator

    Returns:
        DetectionResult with detected spans
    """
    if ml_model_dir is not None:
        ml_model_dir = Path(ml_model_dir)

    orchestrator = DetectorOrchestrator(
        enable_ml=enable_ml,
        enable_patterns=enable_patterns,
        enable_hyperscan=enable_hyperscan,
        ml_model_dir=ml_model_dir,
        use_onnx=use_onnx,
        enable_coref=enable_coref,
        enable_context_enhancement=enable_context_enhancement,
        **kwargs
    )
    return orchestrator.detect(text)
