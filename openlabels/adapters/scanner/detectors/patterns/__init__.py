"""Pattern-based detectors for PHI/PII entity recognition."""

import logging
import os

logger = logging.getLogger(__name__)

from .detector import PatternDetector as _StandardPatternDetector

# Detector selection priority:
# 1. Native Rust (if available) - 6-8x faster, enabled by default
# 2. Hyperscan (if enabled via env var) - 2-3x faster, slow startup
# 3. Standard Python - fallback

_USE_NATIVE = os.environ.get("OPENLABELS_NO_NATIVE", "").lower() not in ("1", "true", "yes")
_USE_HYPERSCAN = os.environ.get("OPENLABELS_USE_HYPERSCAN", "").lower() in ("1", "true", "yes")

# Try native Rust detector first (best performance)
if _USE_NATIVE:
    try:
        from .native import NativePatternDetector, is_native_detector_available

        if is_native_detector_available():
            PatternDetector = NativePatternDetector
            logger.debug("Using native Rust pattern detector (6-8x faster)")
        else:
            PatternDetector = _StandardPatternDetector
    except ImportError:
        PatternDetector = _StandardPatternDetector

# Fall back to Hyperscan if explicitly requested
elif _USE_HYPERSCAN:
    try:
        from .hyperscan_detector import HyperscanDetector, _HYPERSCAN_AVAILABLE

        if _HYPERSCAN_AVAILABLE:
            PatternDetector = HyperscanDetector
            logger.debug("Using Hyperscan pattern detector (2-3x faster)")
        else:
            PatternDetector = _StandardPatternDetector
    except ImportError:
        PatternDetector = _StandardPatternDetector

else:
    PatternDetector = _StandardPatternDetector

__all__ = ["PatternDetector"]
