"""Text extractors for various file formats."""

from .base import BaseExtractor, ExtractionResult, PageInfo
from .registry import extract_text, get_extractor
from .archive import (
    ArchiveExtractor,
    ArchiveSecurityError,
    SUPPORTED_ARCHIVE_EXTENSIONS,
)

__all__ = [
    "BaseExtractor",
    "ExtractionResult",
    "PageInfo",
    "extract_text",
    "get_extractor",
    "ArchiveExtractor",
    "ArchiveSecurityError",
    "SUPPORTED_ARCHIVE_EXTENSIONS",
]
