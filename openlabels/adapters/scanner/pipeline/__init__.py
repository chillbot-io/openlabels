"""
Span processing pipeline.

Provides span merging, normalization, and deduplication functionality.
"""

from .merger import (
    merge_spans,
    normalize_type,
    types_compatible,
    TYPE_NORMALIZE,
    normalize_name_types,
)

__all__ = [
    "merge_spans",
    "normalize_type",
    "types_compatible",
    "TYPE_NORMALIZE",
    "normalize_name_types",
]
