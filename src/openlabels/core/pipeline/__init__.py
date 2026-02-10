"""
Pipeline components for OpenLabels detection.

Main components:
- TieredPipeline: Multi-stage detection with intelligent escalation
- Coreference resolution (FastCoref) - requires numpy
- Context enhancement (false positive filtering)
- Span validation
"""

from .confidence import (
    calibrate_confidence,
    calibrate_spans,
)
from .context_enhancer import (
    ContextEnhancer,
    EnhancementResult,
    create_enhancer,
)
from .entity_resolver import (
    Entity,
    EntityResolver,
    Mention,
    get_entity_counts,
    resolve_entities,
)
from .span_resolver import (
    OverlapStrategy,
    resolve_spans,
)
from .span_validation import (
    SpanValidationError,
    check_for_overlaps,
    validate_after_coref,
    validate_span_positions,
)
from .tiered import (
    ESCALATION_THRESHOLD,
    PipelineConfig,
    PipelineResult,
    PipelineStage,
    TieredPipeline,
    create_pipeline,
    detect_tiered,
)

__all__ = [
    # Confidence calibration
    "calibrate_confidence",
    "calibrate_spans",
    # Span resolution
    "resolve_spans",
    "OverlapStrategy",
    # Tiered pipeline
    "TieredPipeline",
    "PipelineConfig",
    "PipelineResult",
    "PipelineStage",
    "create_pipeline",
    "detect_tiered",
    "ESCALATION_THRESHOLD",
    # Context enhancement
    "ContextEnhancer",
    "create_enhancer",
    "EnhancementResult",
    # Validation
    "validate_span_positions",
    "validate_after_coref",
    "check_for_overlaps",
    "SpanValidationError",
    # Entity resolution
    "EntityResolver",
    "Entity",
    "Mention",
    "resolve_entities",
    "get_entity_counts",
]

# Coreference resolution - optional (requires numpy)
# Import explicitly when needed:
#   from openlabels.core.pipeline.coref import resolve_coreferences
try:
    from .coref import (
        NAME_TYPES,
        PRONOUNS,
        is_fastcoref_available,
        is_onnx_available,
        resolve_coreferences,
        set_models_dir,
    )
    __all__.extend([
        "resolve_coreferences",
        "is_onnx_available",
        "is_fastcoref_available",
        "set_models_dir",
        "NAME_TYPES",
        "PRONOUNS",
    ])
except ImportError:
    # numpy not available - coref features disabled
    def resolve_coreferences(*args, **kwargs):
        raise ImportError("Coreference resolution requires numpy. Install with: pip install numpy")

    def is_onnx_available():
        return False

    def is_fastcoref_available():
        return False

    __all__.extend(["resolve_coreferences", "is_onnx_available", "is_fastcoref_available"])
