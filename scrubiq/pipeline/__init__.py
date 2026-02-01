"""Processing pipeline stages."""

__all__ = [
    "normalize_text",
    "normalize_ocr_numerics",
    "merge_spans",
    "resolve_coreferences",
    "apply_safe_harbor",
    "tokenize",
    "restore",
    "apply_allowlist",
    "ConversationContext",
    "validate_span_positions",
    "validate_after_coref",
]

def __getattr__(name):
    """Lazy import to avoid circular dependencies."""
    if name == "normalize_text":
        from .normalizer import normalize_text
        return normalize_text
    elif name == "normalize_ocr_numerics":
        from .normalizer import normalize_ocr_numerics
        return normalize_ocr_numerics
    elif name == "merge_spans":
        from .merger import merge_spans
        return merge_spans
    elif name == "resolve_coreferences":
        from .coref import resolve_coreferences
        return resolve_coreferences
    elif name == "apply_safe_harbor":
        from .safe_harbor import apply_safe_harbor
        return apply_safe_harbor
    elif name == "tokenize":
        from .tokenizer import tokenize
        return tokenize
    elif name == "restore":
        from .restorer import restore
        return restore
    elif name == "apply_allowlist":
        from .allowlist import apply_allowlist
        return apply_allowlist
    elif name == "ConversationContext":
        from .conversation_context import ConversationContext
        return ConversationContext
    elif name == "validate_span_positions":
        from .span_validation import validate_span_positions
        return validate_span_positions
    elif name == "validate_after_coref":
        from .span_validation import validate_after_coref
        return validate_after_coref
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
