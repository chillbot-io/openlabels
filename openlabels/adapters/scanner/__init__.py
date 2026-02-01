"""
OpenLabels Scanner - PII/PHI detection engine.

Text extraction from various file formats with OCR support.
"""

from .adapter import Detector, detect, detect_file
from .config import Config
from .types import DetectionResult, Span
from .scanner_adapter import ScannerAdapter, create_scanner_adapter
from .extractors import extract_text, get_extractor, ExtractionResult
from .validators import (
    validate_file,
    validate_uploaded_file,
    detect_mime_from_magic_bytes,
    infer_content_type,
    sanitize_filename,
    is_allowed_extension,
    is_allowed_mime,
)

# OCR is optional (requires numpy, onnxruntime)
OCREngine = None
_OCR_AVAILABLE = False
try:
    from .ocr import OCREngine, _OCR_AVAILABLE
except ImportError:
    pass

# OCR Priority Queue
from .queue import (
    OCRJob,
    OCRPriorityQueue,
    QueueStatus,
    OCRQueueWorker,
    calculate_priority,
    calculate_priority_from_context,
)

__all__ = [
    # Core API
    "Detector",
    "Config",
    "DetectionResult",
    "Span",
    "detect",
    "detect_file",
    # Adapter Interface
    "ScannerAdapter",
    "create_scanner_adapter",
    # Extraction
    "extract_text",
    "get_extractor",
    "ExtractionResult",
    # Validation
    "validate_file",
    "validate_uploaded_file",
    "detect_mime_from_magic_bytes",
    "infer_content_type",
    "sanitize_filename",
    "is_allowed_extension",
    "is_allowed_mime",
    # OCR (optional)
    "OCREngine",
    "_OCR_AVAILABLE",
    # OCR Priority Queue
    "OCRJob",
    "OCRPriorityQueue",
    "QueueStatus",
    "OCRQueueWorker",
    "calculate_priority",
    "calculate_priority_from_context",
]
