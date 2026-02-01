"""
OpenLabels Detectors.

This module provides entity detection capabilities through
multiple specialized detectors.

Detectors:
- ChecksumDetector: Validates entities with checksums (SSN, Credit Card, etc.)
- SecretsDetector: Detects API keys, tokens, credentials
- FinancialDetector: Detects financial identifiers and crypto addresses
- GovernmentDetector: Detects classification markings and government IDs

ML Detectors (optional, require additional dependencies):
- PHIBertDetector: Stanford Clinical PHI-BERT (HuggingFace)
- PIIBertDetector: AI4Privacy PII-BERT (HuggingFace)
- PHIBertONNXDetector: Stanford Clinical PHI-BERT (ONNX optimized)
- PIIBertONNXDetector: AI4Privacy PII-BERT (ONNX optimized)
"""

from .base import BaseDetector
from .checksum import ChecksumDetector
from .secrets import SecretsDetector
from .financial import FinancialDetector
from .government import GovernmentDetector
from .orchestrator import DetectorOrchestrator, detect
from .labels import PHI_BERT_LABELS, PII_BERT_LABELS

__all__ = [
    # Base
    "BaseDetector",
    # Pattern detectors
    "ChecksumDetector",
    "SecretsDetector",
    "FinancialDetector",
    "GovernmentDetector",
    # Orchestration
    "DetectorOrchestrator",
    "detect",
    # Labels
    "PHI_BERT_LABELS",
    "PII_BERT_LABELS",
]

# ML Detectors - optional imports (require numpy, onnxruntime, transformers)
# Import these explicitly when needed, e.g.:
#   from openlabels.core.detectors.ml import PHIBertDetector
#   from openlabels.core.detectors.ml_onnx import PHIBertONNXDetector
try:
    from .ml import (
        MLDetector,
        PHIBertDetector,
        PIIBertDetector,
        get_device,
        get_device_info,
    )
    __all__.extend([
        "MLDetector",
        "PHIBertDetector",
        "PIIBertDetector",
        "get_device",
        "get_device_info",
    ])
except ImportError:
    pass

try:
    from .ml_onnx import (
        ONNXDetector,
        PHIBertONNXDetector,
        PIIBertONNXDetector,
    )
    __all__.extend([
        "ONNXDetector",
        "PHIBertONNXDetector",
        "PIIBertONNXDetector",
    ])
except ImportError:
    pass
