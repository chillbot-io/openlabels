"""
ScrubIQ Exceptions.

Provides a clear hierarchy of exceptions for error handling.

Usage:
    from scrubiq.exceptions import (
        ScrubIQError,
        ConfigurationError,
        DetectionError,
        StorageError,
        ProcessingError,
        AuthenticationError,
    )

Exception Hierarchy:
    ScrubIQError (base)
    ├── ConfigurationError
    ├── DetectionError
    ├── StorageError
    ├── ProcessingError
    │   └── FileValidationError
    └── AuthenticationError
"""

__all__ = [
    # Base
    "ScrubIQError",
    # Categories
    "ConfigurationError",
    "DetectionError",
    "StorageError",
    "ProcessingError",
    "AuthenticationError",
    # Specific (actually used)
    "FileValidationError",
]


# --- BASE EXCEPTION ---
class ScrubIQError(Exception):
    """Base exception for all ScrubIQ errors."""
    pass


# --- CATEGORY EXCEPTIONS ---
class ConfigurationError(ScrubIQError):
    """Configuration or initialization error."""
    pass


class DetectionError(ScrubIQError):
    """Error during PHI/PII detection."""
    pass


class StorageError(ScrubIQError):
    """Error with data storage."""
    pass


class ProcessingError(ScrubIQError):
    """Error during file/text processing."""
    pass


class AuthenticationError(ScrubIQError):
    """Authentication or authorization error."""
    pass


# --- SPECIFIC EXCEPTIONS (actually used) ---
class FileValidationError(ProcessingError):
    """File validation failed (type, size, etc.)."""
    def __init__(self, message: str, filename: str = None):
        self.filename = filename
        super().__init__(message)
