"""
Tiered detection pipeline for efficient PII/PHI detection.

Implements a multi-stage detection strategy:
- Stage 1 (Fast Triage): Pattern/checksum detectors only
- Stage 2 (ML Escalation): ML detectors when needed
- Stage 3 (Deep Analysis): PHI-BERT + PII-BERT for medical context

Key features:
- Avoids running ML on every document (saves compute)
- Medical context auto-detection triggers PHI+PII dual analysis
- Confidence-based escalation (< 0.7 triggers ML)
- OCR text detection before full pipeline
- Coreference resolution (disabled by default, available if needed)

Usage:
    from openlabels.core.pipeline.tiered import TieredPipeline

    pipeline = TieredPipeline()
    result = pipeline.detect(text)

    # With medical context auto-detection:
    pipeline = TieredPipeline(auto_detect_medical=True)

    # For images with OCR:
    result = pipeline.detect_image(image_path)
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

from ..types import Span, DetectionResult, normalize_entity_type
from ..policies.engine import get_policy_engine
from ..policies.schema import EntityMatch, PolicyResult

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

# Escalation threshold - spans below this confidence trigger ML escalation
ESCALATION_THRESHOLD = 0.70

# Entity types that benefit from ML refinement
ML_BENEFICIAL_TYPES: Set[str] = frozenset([
    "NAME", "NAME_PATIENT", "NAME_PROVIDER", "PERSON",
    "ADDRESS", "LOCATION_OTHER",
    "DATE", "AGE",
])

# File extensions that need OCR
OCR_FILE_EXTENSIONS: Set[str] = frozenset([
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif",
    ".webp", ".heic", ".heif",
])

# Default detector timeout
DETECTOR_TIMEOUT = 30.0


class PipelineStage(Enum):
    """Pipeline execution stages."""
    FAST_TRIAGE = "fast_triage"       # Pattern/checksum only
    ML_ESCALATION = "ml_escalation"   # Add ML detectors
    DEEP_ANALYSIS = "deep_analysis"   # PHI-BERT + PII-BERT


@dataclass
class PipelineConfig:
    """Configuration for the tiered pipeline."""

    # Escalation settings
    escalation_threshold: float = ESCALATION_THRESHOLD
    auto_detect_medical: bool = True
    medical_triggers_dual_bert: bool = True  # PHI + PII when medical

    # Stage enablement
    enable_checksum: bool = True
    enable_secrets: bool = True
    enable_financial: bool = True
    enable_government: bool = True
    enable_patterns: bool = True
    enable_hyperscan: bool = False

    # ML settings
    ml_model_dir: Optional[Path] = None
    use_onnx: bool = True
    eager_load_ml: bool = False  # If True, load ML detectors at init rather than on first escalation

    # Post-processing (coreference disabled by default)
    enable_coref: bool = False
    enable_context_enhancement: bool = False

    # Policy evaluation
    enable_policy_evaluation: bool = True

    # Performance
    max_workers: int = 4
    confidence_threshold: float = 0.70


@dataclass
class PipelineResult:
    """Result from tiered pipeline with stage metadata."""
    result: DetectionResult
    stages_executed: List[PipelineStage]
    medical_context_detected: bool
    escalation_reason: Optional[str]
    ocr_used: bool = False
    ocr_text_detected: bool = False
    policy_result: Optional[PolicyResult] = None

    @property
    def spans(self) -> List[Span]:
        return self.result.spans

    @property
    def processing_time_ms(self) -> float:
        return self.result.processing_time_ms


class TieredPipeline:
    """
    Multi-stage detection pipeline with intelligent escalation.

    Stage 1 (Fast Triage):
        - Checksum-validated detectors (SSN, credit cards, etc.)
        - Secret/credential patterns
        - Financial instrument patterns
        - Government marking patterns
        - General regex patterns

    Stage 2 (ML Escalation) - triggered when:
        - Any Stage 1 span has confidence < 0.7
        - Medical context is detected in text
        - Specific entity types need refinement

    Stage 3 (Deep Analysis) - for medical context:
        - PHI-BERT for clinical entities
        - PII-BERT for general PII
        - Both run together (PHI-BERT alone misses PII in medical docs)
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        """
        Initialize the tiered pipeline.

        Args:
            config: Pipeline configuration (uses defaults if None)
        """
        self.config = config or PipelineConfig()
        self._stage1_detectors = []
        self._ml_detectors = []
        self._phi_bert = None
        self._pii_bert = None
        self._medical_detector = None
        self._coref_resolver = None
        self._context_enhancer = None
        self._ocr_engine = None

        self._init_stage1_detectors()
        self._init_medical_detector()

        if self.config.eager_load_ml:
            logger.info("Eager ML loading enabled - initializing ML detectors at startup")
            self._init_ml_detectors()

    def _init_stage1_detectors(self) -> None:
        """Initialize Stage 1 (fast triage) detectors."""
        from ..detectors.checksum import ChecksumDetector
        from ..detectors.secrets import SecretsDetector
        from ..detectors.financial import FinancialDetector
        from ..detectors.government import GovernmentDetector
        from ..detectors.patterns import PatternDetector
        from ..detectors.additional_patterns import AdditionalPatternDetector

        if self.config.enable_checksum:
            self._stage1_detectors.append(ChecksumDetector())
        if self.config.enable_secrets:
            self._stage1_detectors.append(SecretsDetector())
        if self.config.enable_financial:
            self._stage1_detectors.append(FinancialDetector())
        if self.config.enable_government:
            self._stage1_detectors.append(GovernmentDetector())
        if self.config.enable_patterns:
            self._stage1_detectors.append(PatternDetector())
            self._stage1_detectors.append(AdditionalPatternDetector())

        # Optional Hyperscan acceleration
        if self.config.enable_hyperscan:
            try:
                from ..detectors.hyperscan import HyperscanDetector, SUPPLEMENTAL_PATTERNS
                self._stage1_detectors.append(
                    HyperscanDetector(additional_patterns=SUPPLEMENTAL_PATTERNS)
                )
            except ImportError:
                logger.warning("Hyperscan not available, using standard detectors")

        logger.info(
            f"TieredPipeline Stage 1 initialized with {len(self._stage1_detectors)} detectors"
        )

    def _init_medical_detector(self) -> None:
        """Initialize medical context detector using dictionaries."""
        if not self.config.auto_detect_medical:
            return

        try:
            # Try relative import first (for package usage)
            from ...dictionaries import get_dictionary_loader
            self._medical_detector = get_dictionary_loader()
            logger.info("Medical context detector initialized")
        except ImportError:
            try:
                # Fallback to absolute import (for installed package)
                from openlabels.dictionaries import get_dictionary_loader
                self._medical_detector = get_dictionary_loader()
                logger.info("Medical context detector initialized")
            except ImportError as e:
                logger.warning(f"Dictionary loader not available: {e}")

    def _init_ml_detectors(self) -> None:
        """Load ML detectors (called eagerly or on first escalation).

        Resolves the model directory, checks for model availability using
        model_config, and attempts to load whichever models are present.
        Logs clear diagnostics when models are missing.
        """
        if self._ml_detectors:
            return  # Already loaded

        model_dir = self.config.ml_model_dir
        if model_dir is None:
            from openlabels.core.constants import DEFAULT_MODELS_DIR
            model_dir = DEFAULT_MODELS_DIR
        model_dir = Path(model_dir).expanduser()

        if not model_dir.exists():
            logger.warning(
                f"ML model directory not found: {model_dir}. "
                f"ML detectors will be unavailable. "
                f"To enable ML detection, create this directory and place model files there. "
                f"See openlabels.core.detectors.model_config for expected file layout."
            )
            return

        # Check model availability and log a clear report
        try:
            from ..detectors.model_config import check_models_available
            report = check_models_available(
                model_dir=model_dir, use_onnx=self.config.use_onnx
            )
            if not report.any_available:
                logger.warning(
                    f"No ML models found in {model_dir}. "
                    f"ML detectors will be unavailable. "
                    f"Model status:\n{report.summary()}"
                )
            else:
                logger.info(f"ML model check: {report.summary()}")
        except Exception as e:
            logger.debug(f"Model availability check failed (non-fatal): {e}")

        if self.config.use_onnx:
            try:
                from ..detectors.ml_onnx import PHIBertONNXDetector, PIIBertONNXDetector

                phi_bert = PHIBertONNXDetector(model_dir=model_dir)
                if phi_bert.is_available():
                    self._phi_bert = phi_bert
                    self._ml_detectors.append(phi_bert)
                    logger.info("PHI-BERT ONNX loaded for escalation")
                else:
                    logger.info(
                        f"PHI-BERT ONNX not loaded: model files not found in {model_dir}. "
                        f"Expected phi_bert_int8.onnx or phi_bert.onnx plus tokenizer."
                    )

                pii_bert = PIIBertONNXDetector(model_dir=model_dir)
                if pii_bert.is_available():
                    self._pii_bert = pii_bert
                    self._ml_detectors.append(pii_bert)
                    logger.info("PII-BERT ONNX loaded for escalation")
                else:
                    logger.info(
                        f"PII-BERT ONNX not loaded: model files not found in {model_dir}. "
                        f"Expected pii_bert_int8.onnx or pii_bert.onnx plus tokenizer."
                    )

            except ImportError as e:
                logger.warning(
                    f"ONNX detectors not available (missing dependency): {e}. "
                    f"Install onnxruntime to enable ONNX-based ML detection."
                )
        else:
            try:
                from ..detectors.ml import PHIBertDetector, PIIBertDetector

                phi_bert_dir = model_dir / "phi_bert"
                if phi_bert_dir.exists():
                    phi_bert = PHIBertDetector(model_path=phi_bert_dir)
                    if phi_bert.is_available():
                        self._phi_bert = phi_bert
                        self._ml_detectors.append(phi_bert)
                        logger.info("PHI-BERT (HuggingFace) loaded for escalation")
                else:
                    logger.info(
                        f"PHI-BERT not loaded: directory not found at {phi_bert_dir}. "
                        f"Expected config.json and model weights."
                    )

                pii_bert_dir = model_dir / "pii_bert"
                if pii_bert_dir.exists():
                    pii_bert = PIIBertDetector(model_path=pii_bert_dir)
                    if pii_bert.is_available():
                        self._pii_bert = pii_bert
                        self._ml_detectors.append(pii_bert)
                        logger.info("PII-BERT (HuggingFace) loaded for escalation")
                else:
                    logger.info(
                        f"PII-BERT not loaded: directory not found at {pii_bert_dir}. "
                        f"Expected config.json and model weights."
                    )

            except ImportError as e:
                logger.warning(
                    f"HuggingFace detectors not available (missing dependency): {e}. "
                    f"Install transformers and torch to enable HuggingFace-based ML detection."
                )

        if self._ml_detectors:
            logger.info(
                f"ML detectors initialized: {[d.name for d in self._ml_detectors]}"
            )
        else:
            logger.warning(
                "No ML detectors were loaded. Pipeline will operate with "
                "pattern-based detection only (Stage 1)."
            )

    def _init_post_processing(self) -> None:
        """Lazy-load post-processing components."""
        if self.config.enable_coref and self._coref_resolver is None:
            try:
                from . import resolve_coreferences
                self._coref_resolver = resolve_coreferences
                logger.info("Coreference resolution enabled")
            except ImportError:
                logger.warning("Coreference resolution not available")

        if self.config.enable_context_enhancement and self._context_enhancer is None:
            try:
                from . import create_enhancer
                self._context_enhancer = create_enhancer()
                logger.info("Context enhancement enabled")
            except ImportError:
                logger.warning("Context enhancement not available")

    def detect(self, text: str) -> PipelineResult:
        """
        Run tiered detection on text.

        Args:
            text: Text to analyze

        Returns:
            PipelineResult with detection results and stage metadata
        """
        start_time = time.time()
        stages_executed = []
        escalation_reason = None
        medical_context = False

        if not text or not text.strip():
            return PipelineResult(
                result=DetectionResult(
                    spans=[],
                    entity_counts={},
                    processing_time_ms=0.0,
                    detectors_used=[],
                    text_length=0,
                ),
                stages_executed=[],
                medical_context_detected=False,
                escalation_reason=None,
            )

        # Stage 1: Fast Triage
        stage1_spans, stage1_detectors = self._run_stage1(text)
        stages_executed.append(PipelineStage.FAST_TRIAGE)

        # Check escalation conditions
        should_escalate, reason = self._should_escalate(text, stage1_spans)

        # Check medical context
        if self.config.auto_detect_medical:
            medical_context = self._detect_medical_context(text)
            if medical_context:
                should_escalate = True
                reason = reason or "medical_context_detected"

        all_spans = stage1_spans.copy()
        all_detectors = stage1_detectors.copy()

        # Stage 2: ML Escalation
        if should_escalate:
            escalation_reason = reason
            self._init_ml_detectors()

            if medical_context and self.config.medical_triggers_dual_bert:
                # Deep analysis: both PHI-BERT and PII-BERT
                stage3_spans, stage3_detectors = self._run_deep_analysis(text)
                all_spans.extend(stage3_spans)
                all_detectors.extend(stage3_detectors)
                stages_executed.append(PipelineStage.DEEP_ANALYSIS)
            elif self._ml_detectors:
                # Standard ML escalation
                stage2_spans, stage2_detectors = self._run_stage2(text)
                all_spans.extend(stage2_spans)
                all_detectors.extend(stage2_detectors)
                stages_executed.append(PipelineStage.ML_ESCALATION)

        # Post-process
        processed_spans = self._post_process(text, all_spans)

        # Build result
        entity_counts: Dict[str, int] = {}
        for span in processed_spans:
            normalized = normalize_entity_type(span.entity_type)
            entity_counts[normalized] = entity_counts.get(normalized, 0) + 1

        # Policy evaluation
        policy_result = None
        if self.config.enable_policy_evaluation and processed_spans:
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
            except Exception as e:
                logger.error(f"Policy evaluation failed: {e}")

        processing_time_ms = (time.time() - start_time) * 1000

        return PipelineResult(
            result=DetectionResult(
                spans=processed_spans,
                entity_counts=entity_counts,
                processing_time_ms=processing_time_ms,
                detectors_used=list(set(all_detectors)),
                text_length=len(text),
            ),
            stages_executed=stages_executed,
            medical_context_detected=medical_context,
            escalation_reason=escalation_reason,
            policy_result=policy_result,
        )

    def _run_stage1(self, text: str) -> Tuple[List[Span], List[str]]:
        """Run Stage 1 (fast triage) detectors."""
        all_spans = []
        detectors_used = []

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {
                executor.submit(self._run_detector, d, text): d
                for d in self._stage1_detectors
            }

            for future in as_completed(futures, timeout=DETECTOR_TIMEOUT):
                detector = futures[future]
                try:
                    spans = future.result()
                    all_spans.extend(spans)
                    if spans:
                        detectors_used.append(detector.name)
                except Exception as e:
                    logger.error(f"Stage 1 detector {detector.name} failed: {e}")

        return all_spans, detectors_used

    def _run_stage2(self, text: str) -> Tuple[List[Span], List[str]]:
        """Run Stage 2 (ML escalation) detectors."""
        all_spans = []
        detectors_used = []

        # Run PII-BERT by default for general PII
        if self._pii_bert:
            try:
                spans = self._pii_bert.detect(text)
                all_spans.extend(spans)
                if spans:
                    detectors_used.append(self._pii_bert.name)
            except Exception as e:
                logger.error(f"PII-BERT failed: {e}")

        return all_spans, detectors_used

    def _run_deep_analysis(self, text: str) -> Tuple[List[Span], List[str]]:
        """
        Run Stage 3 (deep analysis) with both PHI-BERT and PII-BERT.

        Medical context requires both because:
        - PHI-BERT is trained on clinical text but misses some standard PII
        - PII-BERT catches general PII that PHI-BERT may miss
        """
        all_spans = []
        detectors_used = []

        # Run both in parallel
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = []

            if self._phi_bert:
                futures.append(
                    executor.submit(self._run_detector, self._phi_bert, text)
                )
            if self._pii_bert:
                futures.append(
                    executor.submit(self._run_detector, self._pii_bert, text)
                )

            for future, detector in zip(futures, [self._phi_bert, self._pii_bert]):
                if detector is None:
                    continue
                try:
                    spans = future.result()
                    all_spans.extend(spans)
                    if spans:
                        detectors_used.append(detector.name)
                except Exception as e:
                    logger.error(f"Deep analysis detector {detector.name} failed: {e}")

        return all_spans, detectors_used

    def _run_detector(self, detector, text: str) -> List[Span]:
        """Run a single detector with error handling."""
        try:
            if not detector.is_available():
                return []
            return detector.detect(text)
        except Exception as e:
            logger.error(f"Detector {detector.name} error: {e}")
            return []

    def _should_escalate(
        self, text: str, stage1_spans: List[Span]
    ) -> Tuple[bool, Optional[str]]:
        """
        Determine if ML escalation is needed.

        Returns:
            Tuple of (should_escalate, reason)
        """
        # Check confidence threshold
        low_confidence_spans = [
            s for s in stage1_spans
            if s.confidence < self.config.escalation_threshold
        ]
        if low_confidence_spans:
            return True, f"low_confidence_spans: {len(low_confidence_spans)}"

        # Check for entity types that benefit from ML
        for span in stage1_spans:
            if normalize_entity_type(span.entity_type) in ML_BENEFICIAL_TYPES:
                # Only escalate if confidence isn't already high
                if span.confidence < 0.9:
                    return True, f"ml_beneficial_type: {span.entity_type}"

        return False, None

    def _detect_medical_context(self, text: str) -> bool:
        """Check if text contains medical/clinical context."""
        if self._medical_detector is None:
            return False

        try:
            return self._medical_detector.has_medical_context(text)
        except Exception as e:
            logger.debug(f"Medical context detection failed: {e}")
            return False

    def _post_process(self, text: str, spans: List[Span]) -> List[Span]:
        """Post-process detected spans."""
        if not spans:
            return []

        # Filter by confidence
        filtered = [
            s for s in spans
            if s.confidence >= self.config.confidence_threshold
        ]

        # Deduplicate
        deduped = self._deduplicate(filtered)

        # Optional coreference resolution
        if self.config.enable_coref:
            self._init_post_processing()
            if self._coref_resolver and deduped:
                try:
                    deduped = self._coref_resolver(text, deduped)
                except Exception as e:
                    logger.error(f"Coreference resolution failed: {e}")

        # Optional context enhancement
        if self.config.enable_context_enhancement:
            self._init_post_processing()
            if self._context_enhancer and deduped:
                try:
                    deduped = self._context_enhancer.enhance(text, deduped)
                except Exception as e:
                    logger.error(f"Context enhancement failed: {e}")

        # Sort by position
        deduped.sort(key=lambda s: (s.start, -s.end))

        return deduped

    def _deduplicate(self, spans: List[Span]) -> List[Span]:
        """Remove duplicate/overlapping spans (higher tier wins)."""
        if not spans:
            return []

        # Sort by start, then tier (descending), then confidence (descending)
        sorted_spans = sorted(
            spans,
            key=lambda s: (s.start, -s.tier.value, -s.confidence)
        )

        result = []
        for span in sorted_spans:
            overlaps = False
            for accepted in result:
                if span.overlaps(accepted):
                    if span.start == accepted.start and span.end == accepted.end:
                        overlaps = True
                        break
                    if accepted.contains(span):
                        overlaps = True
                        break

            if not overlaps:
                result.append(span)

        return result

    # =========================================================================
    # OCR INTEGRATION
    # =========================================================================

    def detect_image(
        self,
        image_path: Union[str, Path],
        skip_if_no_text: bool = True,
    ) -> PipelineResult:
        """
        Run detection on an image using OCR.

        Args:
            image_path: Path to image file
            skip_if_no_text: Skip full pipeline if quick check shows no text

        Returns:
            PipelineResult with OCR metadata
        """
        image_path = Path(image_path)

        # Quick text detection check
        if skip_if_no_text:
            has_text = self._quick_text_check(image_path)
            if not has_text:
                return PipelineResult(
                    result=DetectionResult(
                        spans=[],
                        entity_counts={},
                        processing_time_ms=0.0,
                        detectors_used=[],
                        text_length=0,
                    ),
                    stages_executed=[],
                    medical_context_detected=False,
                    escalation_reason=None,
                    ocr_used=True,
                    ocr_text_detected=False,
                )

        # Run full OCR
        text = self._extract_text_ocr(image_path)
        if not text:
            return PipelineResult(
                result=DetectionResult(
                    spans=[],
                    entity_counts={},
                    processing_time_ms=0.0,
                    detectors_used=[],
                    text_length=0,
                ),
                stages_executed=[],
                medical_context_detected=False,
                escalation_reason=None,
                ocr_used=True,
                ocr_text_detected=False,
            )

        # Run detection pipeline on OCR text
        result = self.detect(text)
        result.ocr_used = True
        result.ocr_text_detected = True

        return result

    def _quick_text_check(self, image_path: Path) -> bool:
        """
        Quick check to see if image likely contains text.

        Uses a lightweight approach before running full OCR:
        1. Check image dimensions (very small images unlikely to have readable text)
        2. Run OCR detection model only (no recognition) if available
        3. Fall back to assuming text exists

        Returns:
            True if text likely exists, False otherwise
        """
        try:
            from PIL import Image

            with Image.open(image_path) as img:
                width, height = img.size

                # Very small images unlikely to have readable text
                if width < 50 or height < 50:
                    logger.debug(f"Image too small for text: {width}x{height}")
                    return False

                # Very large dimension ratio might be decorative
                ratio = max(width, height) / min(width, height)
                if ratio > 20:
                    logger.debug(f"Unusual aspect ratio, likely decorative: {ratio}")
                    return False

            # For now, assume text exists for normal images
            # Future: could use text detection model only (faster than full OCR)
            return True

        except Exception as e:
            logger.debug(f"Quick text check failed: {e}")
            return True  # Assume text exists on error

    def _extract_text_ocr(self, image_path: Path) -> str:
        """Extract text from image using OCR."""
        if self._ocr_engine is None:
            try:
                from ..ocr import OCREngine
                self._ocr_engine = OCREngine()
            except ImportError:
                logger.warning("OCR engine not available")
                return ""

        try:
            return self._ocr_engine.extract_text(image_path)
        except Exception as e:
            logger.error(f"OCR extraction failed: {e}")
            return ""

    # =========================================================================
    # CONVENIENCE METHODS
    # =========================================================================

    def detect_file(
        self,
        file_path: Union[str, Path],
        content: Optional[str] = None,
    ) -> PipelineResult:
        """
        Detect PII/PHI in a file, auto-selecting OCR for images.

        Args:
            file_path: Path to file
            content: Optional pre-extracted text content

        Returns:
            PipelineResult
        """
        file_path = Path(file_path)

        # If content provided, use it directly
        if content is not None:
            return self.detect(content)

        # Check if OCR is needed
        if file_path.suffix.lower() in OCR_FILE_EXTENSIONS:
            return self.detect_image(file_path)

        # For text files, read and detect
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            return self.detect(text)
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return PipelineResult(
                result=DetectionResult(
                    spans=[],
                    entity_counts={},
                    processing_time_ms=0.0,
                    detectors_used=[],
                    text_length=0,
                ),
                stages_executed=[],
                medical_context_detected=False,
                escalation_reason=f"file_read_error: {e}",
            )

    @property
    def stage1_detector_names(self) -> List[str]:
        """Get names of Stage 1 detectors."""
        return [d.name for d in self._stage1_detectors]

    def get_ml_status(self) -> Dict[str, object]:
        """Return status of ML detectors for health checks and diagnostics.

        Returns:
            Dict with keys:
                - ml_loaded: bool, whether any ML detectors are loaded
                - phi_bert: dict with 'loaded' and 'name' keys (or None)
                - pii_bert: dict with 'loaded' and 'name' keys (or None)
                - detectors: list of loaded detector names
                - model_dir: str, the resolved model directory path
                - use_onnx: bool, whether ONNX backend is configured
        """
        model_dir = self.config.ml_model_dir
        if model_dir is None:
            from openlabels.core.constants import DEFAULT_MODELS_DIR
            model_dir = DEFAULT_MODELS_DIR

        status = {
            "ml_loaded": bool(self._ml_detectors),
            "phi_bert": None,
            "pii_bert": None,
            "detectors": [d.name for d in self._ml_detectors],
            "model_dir": str(Path(model_dir).expanduser()),
            "use_onnx": self.config.use_onnx,
        }

        if self._phi_bert is not None:
            status["phi_bert"] = {
                "loaded": self._phi_bert.is_available(),
                "name": self._phi_bert.name,
            }

        if self._pii_bert is not None:
            status["pii_bert"] = {
                "loaded": self._pii_bert.is_available(),
                "name": self._pii_bert.name,
            }

        return status

    @property
    def ml_available(self) -> bool:
        """Check if ML detectors are available."""
        self._init_ml_detectors()
        return bool(self._ml_detectors)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_pipeline(
    auto_detect_medical: bool = True,
    enable_hyperscan: bool = False,
    ml_model_dir: Optional[Path] = None,
    **kwargs,
) -> TieredPipeline:
    """
    Create a configured tiered pipeline.

    Args:
        auto_detect_medical: Auto-detect medical context for PHI+PII
        enable_hyperscan: Use Hyperscan acceleration if available
        ml_model_dir: Directory containing ML models
        **kwargs: Additional PipelineConfig options

    Returns:
        Configured TieredPipeline instance
    """
    config = PipelineConfig(
        auto_detect_medical=auto_detect_medical,
        enable_hyperscan=enable_hyperscan,
        ml_model_dir=ml_model_dir,
        **kwargs,
    )
    return TieredPipeline(config)


def detect_tiered(
    text: str,
    auto_detect_medical: bool = True,
    **kwargs,
) -> PipelineResult:
    """
    Convenience function for tiered detection.

    Args:
        text: Text to analyze
        auto_detect_medical: Auto-detect medical context
        **kwargs: Additional pipeline config options

    Returns:
        PipelineResult
    """
    pipeline = create_pipeline(auto_detect_medical=auto_detect_medical, **kwargs)
    return pipeline.detect(text)
