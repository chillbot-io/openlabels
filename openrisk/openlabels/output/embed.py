"""
OpenLabels Embedded Label Writer - Backward compatibility module.

This module re-exports all symbols from the embed package for backward
compatibility. New code should import directly from openlabels.output.embed.

Writes labels directly into file native metadata:
- PDF: XMP metadata
- DOCX/XLSX/PPTX: Custom Document Properties
- Images (JPEG/PNG/TIFF): XMP or EXIF
"""

# Re-export everything from the embed package
from .embed import (
    # Base class and constants
    EmbeddedLabelWriter,
    OPENLABELS_XMP_NS,
    OPENLABELS_XMP_PREFIX,
    # Format-specific writers
    PDFLabelWriter,
    OfficeLabelWriter,
    ImageLabelWriter,
    # Unified interface
    get_writer,
    supports_embedded_labels,
    write_embedded_label,
    read_embedded_label,
)

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
