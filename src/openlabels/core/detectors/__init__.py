"""
OpenLabels Detectors.

Detectors:
- ChecksumDetector: Validates entities with checksums (SSN, Credit Card, etc.)
- SecretsDetector: Detects API keys, tokens, credentials
- FinancialDetector: Detects financial identifiers and crypto addresses
- GovernmentDetector: Detects classification markings and government IDs
- HyperscanDetector: SIMD-accelerated multi-pattern matching (10-100x faster)

ML Detectors (optional, require additional dependencies):
- GLiNERDetector: Gretel GLiNER PII detector (Apache-2.0, zero-shot NER)
- PHIBertDetector: Stanford Clinical PHI-BERT (HuggingFace) [legacy]
- PIIBertDetector: AI4Privacy PII-BERT (HuggingFace) [legacy]
- PHIBertONNXDetector: Stanford Clinical PHI-BERT (ONNX optimized) [legacy]
- PIIBertONNXDetector: AI4Privacy PII-BERT (ONNX optimized) [legacy]
"""

import logging

from .additional_patterns import AdditionalPatternDetector
from .base import BaseDetector
from .checksum import ChecksumDetector
from .config import DetectionConfig
from .financial import FinancialDetector
from .government import GovernmentDetector
from .labels import PHI_BERT_LABELS, PII_BERT_LABELS
from .orchestrator import DetectorOrchestrator, detect
from .patterns import PatternDetector
from .registry import (
    create_all_detectors,
    create_detector,
    get_detector_names,
    get_registered_detectors,
    register_detector,
)
from .secrets import SecretsDetector

__all__ = [
    # Base
    "BaseDetector",
    # Configuration
    "DetectionConfig",
    # Registry
    "register_detector",
    "get_registered_detectors",
    "get_detector_names",
    "create_detector",
    "create_all_detectors",
    # Pattern detectors
    "ChecksumDetector",
    "SecretsDetector",
    "FinancialDetector",
    "GovernmentDetector",
    "PatternDetector",
    "AdditionalPatternDetector",
    # Orchestration
    "DetectorOrchestrator",
    "detect",
    # Labels
    "PHI_BERT_LABELS",
    "PII_BERT_LABELS",
]

logger = logging.getLogger(__name__)

# GLiNER Detector - optional (requires gliner library)
try:
    from .gliner import GLiNERDetector, GLINER_LABEL_MAP
    __all__.extend(["GLiNERDetector", "GLINER_LABEL_MAP"])
except ImportError:
    logger.debug("GLiNER detector not available - gliner not installed")

# Multilingual GLiNER Detector - optional (requires gliner library)
try:
    from .multilingual_gliner import MultilingualGLiNERDetector
    __all__.append("MultilingualGLiNERDetector")
except ImportError:
    logger.debug("Multilingual GLiNER detector not available - gliner not installed")

# Hyperscan Detector - optional (requires hyperscan library)
try:
    from .hyperscan import HyperscanDetector, is_hyperscan_available
    __all__.extend(["HyperscanDetector", "is_hyperscan_available"])
except ImportError:
    # Hyperscan not installed - SIMD acceleration unavailable
    logger.debug("Hyperscan library not available - using standard pattern matching")

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
    # ML detectors require transformers/torch - optional feature
    logger.debug("ML detectors not available - transformers/torch not installed")

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
    # ONNX detectors require onnxruntime - optional feature
    logger.debug("ONNX detectors not available - onnxruntime not installed")
