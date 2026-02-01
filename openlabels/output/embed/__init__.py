"""
OpenLabels Embedded Label Writer.

Writes labels directly into file native metadata:
- PDF: XMP metadata
- DOCX/XLSX/PPTX: Custom Document Properties
- Images (JPEG/PNG/TIFF): XMP or EXIF

Per the spec, embedded labels contain the full LabelSet JSON and are
the source of truth for files that support native metadata.

This module provides a unified interface for reading/writing embedded labels
across all supported file types.
"""

import logging
from pathlib import Path
from typing import Optional, Union

from ...core.labels import LabelSet

logger = logging.getLogger(__name__)

# Import base class and constants
from .base import (
    EmbeddedLabelWriter,
    OPENLABELS_XMP_NS,
    OPENLABELS_XMP_PREFIX,
)

# Import format-specific writers
from .pdf import PDFLabelWriter
from .office import OfficeLabelWriter
from .image import ImageLabelWriter



# --- Unified Interface ---


# Registry of writers by file type
_WRITERS = [
    PDFLabelWriter(),
    OfficeLabelWriter(),
    ImageLabelWriter(),
]


def get_writer(path: Union[str, Path]) -> Optional[EmbeddedLabelWriter]:
    """Get the appropriate writer for a file type."""
    path = Path(path)
    for writer in _WRITERS:
        if writer.supports(path):
            return writer
    return None


def supports_embedded_labels(path: Union[str, Path]) -> bool:
    """Check if a file type supports embedded labels."""
    return get_writer(path) is not None


def write_embedded_label(
    path: Union[str, Path],
    label_set: LabelSet,
) -> bool:
    """
    Write a LabelSet to a file's native metadata.

    Args:
        path: Path to the file
        label_set: The LabelSet to embed

    Returns:
        True if successful, False otherwise

    Example:
        >>> from openlabels.core.labels import LabelSet, Label
        >>> labels = [Label(type="SSN", confidence=0.99, detector="checksum", value_hash="15e2b0")]
        >>> label_set = LabelSet.create(labels, content, source="openlabels:1.0.0")
        >>> write_embedded_label("document.pdf", label_set)
        True
    """
    path = Path(path)
    writer = get_writer(path)
    if writer is None:
        logger.warning(f"No embedded label writer for {path.suffix}")
        return False
    return writer.write(path, label_set)


def read_embedded_label(path: Union[str, Path]) -> Optional[LabelSet]:
    """
    Read a LabelSet from a file's native metadata.

    Args:
        path: Path to the file

    Returns:
        LabelSet if found, None otherwise

    Example:
        >>> label_set = read_embedded_label("document.pdf")
        >>> if label_set:
        ...     print(f"Found {len(label_set.labels)} labels")
    """
    path = Path(path)
    writer = get_writer(path)
    if writer is None:
        return None
    return writer.read(path)


# Export all public symbols
__all__ = [
    # Base class and constants
    'EmbeddedLabelWriter',
    'OPENLABELS_XMP_NS',
    'OPENLABELS_XMP_PREFIX',
    # Format-specific writers
    'PDFLabelWriter',
    'OfficeLabelWriter',
    'ImageLabelWriter',
    # Unified interface
    'get_writer',
    'supports_embedded_labels',
    'write_embedded_label',
    'read_embedded_label',
]
