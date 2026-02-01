"""
Pipeline components for OpenLabels detection.

Post-processing pipeline stages:
- Coreference resolution (FastCoref) - requires numpy
- Context enhancement (false positive filtering)
- Span validation
"""

from .context_enhancer import (
    ContextEnhancer,
    create_enhancer,
    EnhancementResult,
)
from .span_validation import (
    validate_span_positions,
    validate_after_coref,
    check_for_overlaps,
    SpanValidationError,
)

__all__ = [
    # Context enhancement
    "ContextEnhancer",
    "create_enhancer",
    "EnhancementResult",
    # Validation
    "validate_span_positions",
    "validate_after_coref",
    "check_for_overlaps",
    "SpanValidationError",
]

# Coreference resolution - optional (requires numpy)
# Import explicitly when needed:
#   from openlabels.core.pipeline.coref import resolve_coreferences
try:
    from .coref import (
        resolve_coreferences,
        is_onnx_available,
        is_fastcoref_available,
        set_models_dir,
        NAME_TYPES,
        PRONOUNS,
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
