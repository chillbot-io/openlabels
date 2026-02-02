"""
Labeling engine for applying MIP sensitivity labels.

Provides:
- LabelingEngine: Unified interface for applying sensitivity labels
- MIPClient: Microsoft Information Protection SDK wrapper
- LabelCache: Thread-safe label caching with TTL
- Cross-platform fallbacks (Office metadata, PDF metadata, Sidecar)
"""

from .engine import (
    LabelingEngine,
    LabelResult,
    LabelCache,
    CachedLabel,
    get_label_cache,
)
from .mip import (
    MIPClient,
    SensitivityLabel,
    LabelingResult,
    is_mip_available,
)

__all__ = [
    # Engine
    "LabelingEngine",
    "LabelResult",
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
