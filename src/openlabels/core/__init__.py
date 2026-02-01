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

from .types import (
    Span,
    Tier,
    RiskTier,
    ExposureLevel,
    DetectionResult,
    ScoringResult,
    KNOWN_ENTITY_TYPES,
    CLINICAL_CONTEXT_TYPES,
    validate_entity_type,
    is_clinical_context_type,
    normalize_entity_type,
)

from .detectors.orchestrator import (
    DetectorOrchestrator,
    detect,
)

from .detectors.base import BaseDetector

from .scoring.scorer import (
    score,
    get_weight,
    get_category,
    calculate_content_score,
    score_to_tier,
)

from .processor import (
    FileProcessor,
    FileClassification,
    process_file,
)

from .pipeline import (
    resolve_coreferences,
    is_onnx_available,
    is_fastcoref_available,
    ContextEnhancer,
    create_enhancer,
    validate_span_positions,
)

__all__ = [
    # Types
    "Span",
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
    # Pipeline
    "resolve_coreferences",
    "is_onnx_available",
    "is_fastcoref_available",
    "ContextEnhancer",
    "create_enhancer",
    "validate_span_positions",
]
