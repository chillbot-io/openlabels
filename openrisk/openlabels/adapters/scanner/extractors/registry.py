"""Extractor registry and convenience functions."""

import logging
from pathlib import Path
from typing import List, Optional

from .base import BaseExtractor, ExtractionResult

logger = logging.getLogger(__name__)

_EXTRACTORS: List[BaseExtractor] = []


def _init_extractors() -> List[BaseExtractor]:
    """Initialize extractor registry lazily."""
    global _EXTRACTORS
    if not _EXTRACTORS:
        from .pdf import PDFExtractor
        from .image import ImageExtractor
        from .office import DOCXExtractor, XLSXExtractor, TextExtractor, RTFExtractor
        from .archive import ArchiveExtractor

        _EXTRACTORS = [
            # Archive extractor first - it delegates to others for contained files
            ArchiveExtractor(),
            PDFExtractor(),
            DOCXExtractor(),
            XLSXExtractor(),
            ImageExtractor(),
            TextExtractor(),
            RTFExtractor(),
        ]
    return _EXTRACTORS


def get_extractor(content_type: str, extension: str) -> Optional[BaseExtractor]:
    """Get the appropriate extractor for a file based on content type and extension."""
    extractors = _init_extractors()
    for extractor in extractors:
        if extractor.can_handle(content_type, extension):
            return extractor
    return None


def extract_text(
    content: bytes,
    filename: str,
    content_type: Optional[str] = None,
) -> ExtractionResult:
    """Extract text from file content."""
    import mimetypes

    extension = Path(filename).suffix.lower()

    if content_type is None:
        content_type, _ = mimetypes.guess_type(filename)
        content_type = content_type or "application/octet-stream"

    extractor = get_extractor(content_type, extension)

    if extractor is None:
        return ExtractionResult(
            text="",
            pages=0,
            warnings=[f"No extractor available for {content_type} / {extension}"],
        )

    try:
        return extractor.extract(content, filename)
    except Exception as e:
        logger.error(f"Extraction failed for {filename}: {e}")
        return ExtractionResult(
            text="",
            pages=0,
            warnings=[f"Extraction failed: {e}"],
        )
