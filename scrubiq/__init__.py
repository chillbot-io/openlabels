"""
ScrubIQ - Privacy Infrastructure That Just Works.

Simple API:
    from scrubiq import redact, restore, scan

    safe_text = redact("Patient John Smith, SSN 123-45-6789")
    # → "Patient [NAME_1], SSN [SSN_1]"

Full control:
    from scrubiq import Redactor

    r = Redactor(confidence_threshold=0.9)
    result = r.redact(text)

Server mode (API key auth):
    # Start API server, authenticate with API key
    # See scrubiq.api for REST API endpoints
"""

__version__ = "0.1.0"

# SDK exports (lazy loaded)
__all__ = [
    # Version
    "__version__",
    # Simple API
    "redact",
    "redact_full",  # Alias for redact (backward compatibility)
    "restore",
    "scan",
    "chat",
    "preload",
    "preload_async",
    # Full API
    "Redactor",
    "RedactorConfig",
    "Session",  # Alias for Redactor (backward compatibility)
    "RedactionResult",
    "ScanResult",
    "ChatResult",
    "FileResult",
    "Entity",
    "ReviewItem",
    # Sub-interfaces
    "ConversationsInterface",
    "ReviewInterface",
    "MemoryInterface",
    "AuditInterface",
    # Server API
    "ScrubIQ",
    # Types
    "Span",
    # Exceptions
    "ScrubIQError",
    "ConfigurationError",
    "DetectionError",
    "StorageError",
    "ProcessingError",
    "AuthenticationError",
]


def __getattr__(name):
    """Lazy import for heavy modules."""
    # SDK classes and functions
    if name in (
        "Redactor", "RedactorConfig", "Session", "RedactionResult", "ScanResult", "ChatResult",
        "FileResult", "Entity", "ReviewItem",
        "ConversationsInterface", "ReviewInterface", "MemoryInterface", "AuditInterface",
        "redact", "redact_full", "restore", "scan", "chat", "preload", "preload_async",
    ):
        from .sdk import (
            Redactor, RedactorConfig, Session, RedactionResult, ScanResult, ChatResult,
            FileResult, Entity, ReviewItem,
            ConversationsInterface, ReviewInterface, MemoryInterface, AuditInterface,
            redact, redact_full, restore, scan, chat, preload, preload_async,
        )
        return {
            "Redactor": Redactor,
            "RedactorConfig": RedactorConfig,
            "Session": Session,
            "RedactionResult": RedactionResult,
            "ScanResult": ScanResult,
            "ChatResult": ChatResult,
            "FileResult": FileResult,
            "Entity": Entity,
            "ReviewItem": ReviewItem,
            "ConversationsInterface": ConversationsInterface,
            "ReviewInterface": ReviewInterface,
            "MemoryInterface": MemoryInterface,
            "AuditInterface": AuditInterface,
            "redact": redact,
            "redact_full": redact_full,
            "restore": restore,
            "scan": scan,
            "chat": chat,
            "preload": preload,
            "preload_async": preload_async,
        }[name]
    
    # Server class
    if name == "ScrubIQ":
        from .core import ScrubIQ
        return ScrubIQ
    
    # Types
    if name == "Span":
        from .types import Span
        return Span
    
    # Exceptions
    if name in ("ScrubIQError", "ConfigurationError", "DetectionError", 
                "StorageError", "ProcessingError", "AuthenticationError"):
        from .exceptions import (
            ScrubIQError, ConfigurationError, DetectionError,
            StorageError, ProcessingError, AuthenticationError,
        )
        return {
            "ScrubIQError": ScrubIQError,
            "ConfigurationError": ConfigurationError,
            "DetectionError": DetectionError,
            "StorageError": StorageError,
            "ProcessingError": ProcessingError,
            "AuthenticationError": AuthenticationError,
        }[name]
    
    # Image protection (backwards compatibility)
    if name in ("MetadataStripper", "MetadataStrippingResult", "FileType"):
        from .image_protection.metadata_stripper import (
            MetadataStripper, MetadataStrippingResult, FileType
        )
        _exports = {
            "MetadataStripper": MetadataStripper,
            "MetadataStrippingResult": MetadataStrippingResult,
            "FileType": FileType,
        }
        return _exports[name]

    if name in ("FaceDetector", "FaceDetection", "FaceDetectionResult",
                "redact_faces", "detect_faces", "get_detector"):
        from .image_protection.face_detection import (
            FaceDetector, FaceDetection, FaceDetectionResult,
            redact_faces, detect_faces, get_detector
        )
        _exports = {
            "FaceDetector": FaceDetector,
            "FaceDetection": FaceDetection,
            "FaceDetectionResult": FaceDetectionResult,
            "redact_faces": redact_faces,
            "detect_faces": detect_faces,
            "get_detector": get_detector,
        }
        return _exports[name]

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
