"""
OpenLabels Core Detection Engine.

This module provides the detection and scoring capabilities for OpenLabels,
including entity detection, risk scoring, and classification.

Usage:
    from openlabels.core import detect, score

    # Detect entities in text
    result = detect("My SSN is 123-45-6789 and my email is test@example.com")
    for span in result.spans:
        print(f"{span.entity_type}: {span.text}")

    # Score detected entities
    score_result = score(result.entity_counts, exposure='INTERNAL')
    print(f"Risk: {score_result.score} ({score_result.tier.value})")

    # Run coreference resolution on names
    from openlabels.core import resolve_coreferences
    expanded_spans = resolve_coreferences(text, result.spans)
"""

from .detectors.base import BaseDetector
from .detectors.config import DetectionConfig
from .detectors.orchestrator import (
    DetectorOrchestrator,
    detect,
)
from .extractors import (
    BaseExtractor,
    DOCXExtractor,
    ExtractionResult,
    ImageExtractor,
    PageInfo,
    PDFExtractor,
    RTFExtractor,
    TextExtractor,
    XLSXExtractor,
    extract_text,
    get_extractor,
)
from .ocr import (
    OCRBlock,
    OCREngine,
    OCRResult,
    clean_ocr_text,
)
from .pipeline import (
    ContextEnhancer,
    create_enhancer,
    is_fastcoref_available,
    is_onnx_available,
    resolve_coreferences,
    validate_span_positions,
)
from .processor import (
    FileClassification,
    FileProcessor,
    process_file,
)
from .scoring.scorer import (
    calculate_content_score,
    get_category,
    get_weight,
    score,
    score_to_tier,
)
from .types import (
    CLINICAL_CONTEXT_TYPES,
    KNOWN_ENTITY_TYPES,
    DetectionResult,
    ExposureLevel,
    RiskTier,
    ScoringResult,
    Span,
    SpanContext,
    Tier,
    is_clinical_context_type,
    normalize_entity_type,
    validate_entity_type,
)

__all__ = [
    # Types
    "Span",
    "SpanContext",
    "Tier",
    "RiskTier",
    "ExposureLevel",
    "DetectionResult",
    "ScoringResult",
    # Constants
    "KNOWN_ENTITY_TYPES",
    "CLINICAL_CONTEXT_TYPES",
    # Functions
    "validate_entity_type",
    "is_clinical_context_type",
    "normalize_entity_type",
    # Detection
    "DetectionConfig",
    "DetectorOrchestrator",
    "detect",
    "BaseDetector",
    # Scoring
    "score",
    "get_weight",
    "get_category",
    "calculate_content_score",
    "score_to_tier",
    # Processor
    "FileProcessor",
    "FileClassification",
    "process_file",
    # Extractors
    "BaseExtractor",
    "ExtractionResult",
    "PageInfo",
    "PDFExtractor",
    "DOCXExtractor",
    "XLSXExtractor",
    "ImageExtractor",
    "TextExtractor",
    "RTFExtractor",
    "extract_text",
    "get_extractor",
    # Pipeline
    "resolve_coreferences",
    "is_onnx_available",
    "is_fastcoref_available",
    "ContextEnhancer",
    "create_enhancer",
    "validate_span_positions",
    # OCR
    "OCREngine",
    "OCRResult",
    "OCRBlock",
    "clean_ocr_text",
]
