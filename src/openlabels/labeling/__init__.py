"""
Labeling engine for applying MIP sensitivity labels.

Provides:
- LabelingEngine: Unified interface for applying sensitivity labels
- MIPClient: Microsoft Information Protection SDK wrapper
- LabelCache: Thread-safe label caching with TTL
- Cross-platform fallbacks (Office metadata, PDF metadata, Sidecar)
"""

from .engine import (
    CachedLabel,
    LabelCache,
    LabelingEngine,
    LabelResult,
    create_labeling_engine,
    get_label_cache,
)
from .mip import (
    LabelingResult,
    MIPClient,
    SensitivityLabel,
    is_mip_available,
)

__all__ = [
    # Engine
    "LabelingEngine",
    "LabelResult",
    "create_labeling_engine",
    # Caching
    "LabelCache",
    "CachedLabel",
    "get_label_cache",
    # MIP SDK
    "MIPClient",
    "SensitivityLabel",
    "LabelingResult",
    "is_mip_available",
]
