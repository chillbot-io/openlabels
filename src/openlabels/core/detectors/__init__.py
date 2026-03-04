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
- StanfordPHIDetector: Stanford Clinical De-identifier (PubMedBERT, PHI NER)
"""

import logging

from .additional_patterns import AdditionalPatternDetector
from .base import BaseDetector
from .checksum import ChecksumDetector
from .config import DetectionConfig
from .dictionary_names import DictionaryNameDetector
from .financial import FinancialDetector
from .government import GovernmentDetector
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
    "DictionaryNameDetector",
    # Orchestration
    "DetectorOrchestrator",
    "detect",
]

logger = logging.getLogger(__name__)

# GLiNER Detector - optional (requires gliner library)
try:
    from .gliner import GLINER_LABEL_MAP, GLiNERDetector  # noqa: F401
    __all__.extend(["GLiNERDetector", "GLINER_LABEL_MAP"])
except ImportError:
    logger.debug("GLiNER detector not available - gliner not installed")

# Multilingual GLiNER Detector - optional (requires gliner library)
try:
    from .multilingual_gliner import MultilingualGLiNERDetector  # noqa: F401
    __all__.append("MultilingualGLiNERDetector")
except ImportError:
    logger.debug("Multilingual GLiNER detector not available - gliner not installed")

# Hyperscan Detector - optional (requires hyperscan library)
try:
    from .hyperscan import HyperscanDetector, is_hyperscan_available  # noqa: F401
    __all__.extend(["HyperscanDetector", "is_hyperscan_available"])
except ImportError:
    # Hyperscan not installed - SIMD acceleration unavailable
    logger.debug("Hyperscan library not available - using standard pattern matching")

# Stanford PHI Detector - optional (requires transformers)
try:
    from .phi_detector import StanfordPHIDetector  # noqa: F401
    __all__.append("StanfordPHIDetector")
except ImportError:
    logger.debug("Stanford PHI detector not available - transformers not installed")

# ML utilities - optional (require onnxruntime)
try:
    from .ml import MLDetector, get_device, get_device_info  # noqa: F401
    __all__.extend(["MLDetector", "get_device", "get_device_info"])
except ImportError:
    logger.debug("ML utilities not available - onnxruntime not installed")

try:
    from .ml_onnx import ONNXDetector  # noqa: F401
    __all__.append("ONNXDetector")
except ImportError:
    logger.debug("ONNX detector base not available - onnxruntime not installed")
