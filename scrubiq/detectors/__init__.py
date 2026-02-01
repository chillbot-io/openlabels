"""PHI/PII detection modules."""

__all__ = [
    "detect_all",
    "DetectorOrchestrator",
    "DetectionQueueFullError",
    "get_detection_queue_depth",
    "ChecksumDetector",
    "PatternDetector",
    "PHIBertDetector",
    "PIIBertDetector",
    "DictionaryDetector",
]


def __getattr__(name):
    """Lazy import."""
    if name == "detect_all":
        from .orchestrator import detect_all
        return detect_all
    elif name == "DetectorOrchestrator":
        from .orchestrator import DetectorOrchestrator
        return DetectorOrchestrator
    elif name == "DetectionQueueFullError":
        from .orchestrator import DetectionQueueFullError
        return DetectionQueueFullError
    elif name == "get_detection_queue_depth":
        from .orchestrator import get_detection_queue_depth
        return get_detection_queue_depth
    elif name == "ChecksumDetector":
        from .checksum import ChecksumDetector
        return ChecksumDetector
    elif name == "PatternDetector":
        from .patterns import PatternDetector
        return PatternDetector
    elif name == "PHIBertDetector":
        from .ml import PHIBertDetector
        return PHIBertDetector
    elif name == "PIIBertDetector":
        from .ml import PIIBertDetector
        return PIIBertDetector
    elif name == "DictionaryDetector":
        from .dictionaries import DictionaryDetector
        return DictionaryDetector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
