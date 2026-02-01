"""
File processing module for ScrubIQ.

Handles file upload, text extraction, OCR, and PHI detection for documents.

Uses lazy imports to avoid loading heavy dependencies (RapidOCR, etc.) at module load time.
"""

__all__ = [
    # OCR
    "OCREngine",
    "OCRBlock",
    "OCRResult",
    # Validation
    "validate_file",
    "ALLOWED_TYPES",
    "FileValidationError",
    # Extraction
    "ExtractionResult",
    "PageInfo",
    "BaseExtractor",
    "PDFExtractor",
    "DOCXExtractor",
    "XLSXExtractor",
    "ImageExtractor",
    "TextExtractor",
    "RTFExtractor",
    # Jobs
    "FileJob",
    "JobStatus",
    "JobManager",
    # Processing
    "FileProcessor",
    # Temp storage
    "SecureTempDir",
]


def __getattr__(name):
    """Lazy import for heavy modules."""
    if name in ("OCREngine", "OCRBlock", "OCRResult"):
        from .ocr import OCREngine, OCRBlock, OCRResult
        return {"OCREngine": OCREngine, "OCRBlock": OCRBlock, "OCRResult": OCRResult}[name]
    elif name in ("validate_file", "ALLOWED_TYPES", "FileValidationError"):
        from .validators import validate_file, ALLOWED_TYPES, FileValidationError
        return {"validate_file": validate_file, "ALLOWED_TYPES": ALLOWED_TYPES, "FileValidationError": FileValidationError}[name]
    elif name in ("ExtractionResult", "PageInfo", "BaseExtractor", "PDFExtractor", "DOCXExtractor", 
                  "XLSXExtractor", "ImageExtractor", "TextExtractor", "RTFExtractor"):
        from .extractor import (
            ExtractionResult, PageInfo, BaseExtractor, PDFExtractor, DOCXExtractor,
            XLSXExtractor, ImageExtractor, TextExtractor, RTFExtractor,
        )
        return {
            "ExtractionResult": ExtractionResult,
            "PageInfo": PageInfo,
            "BaseExtractor": BaseExtractor,
            "PDFExtractor": PDFExtractor,
            "DOCXExtractor": DOCXExtractor,
            "XLSXExtractor": XLSXExtractor,
            "ImageExtractor": ImageExtractor,
            "TextExtractor": TextExtractor,
            "RTFExtractor": RTFExtractor,
        }[name]
    elif name in ("FileJob", "JobStatus", "JobManager"):
        from .jobs import FileJob, JobStatus, JobManager
        return {"FileJob": FileJob, "JobStatus": JobStatus, "JobManager": JobManager}[name]
    elif name == "FileProcessor":
        from .processor import FileProcessor
        return FileProcessor
    elif name == "SecureTempDir":
        from .temp_storage import SecureTempDir
        return SecureTempDir
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
