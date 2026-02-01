"""
OpenLabels Scanner Exceptions.

Exception Hierarchy:
    ScannerError (base)
    ├── ConfigurationError
    ├── DetectionError
    └── ProcessingError
        └── FileValidationError
"""

__all__ = [
    "ScannerError",
    "ConfigurationError",
    "DetectionError",
    "ProcessingError",
    "FileValidationError",
]


class ScannerError(Exception):
    """Base exception for all scanner errors."""


class ConfigurationError(ScannerError):
    """Configuration or initialization error."""


class DetectionError(ScannerError):
    """Error during PII/PHI detection."""


class ProcessingError(ScannerError):
    """Error during file/text processing."""


class FileValidationError(ProcessingError):
    """File validation failed (type, size, etc.)."""
    def __init__(self, message: str, filename: str = None):
        self.filename = filename
        super().__init__(message)
