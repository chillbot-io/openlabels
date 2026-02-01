"""
PDF embedded label writer.

Uses pikepdf for PDF manipulation.
Stores labels in XMP metadata namespace: http://openlabels.dev/ns/1.0/
"""

from pathlib import Path
from typing import Optional

from ...core.labels import LabelSet
from .base import EmbeddedLabelWriter, OPENLABELS_XMP_NS, logger


class PDFLabelWriter(EmbeddedLabelWriter):
    """
    Write/read labels to PDF XMP metadata.

    Uses pikepdf for PDF manipulation.
    Stores in XMP namespace: http://openlabels.dev/ns/1.0/
    Property name: openlabels
    """

    SUPPORTED_EXTENSIONS = {'.pdf'}

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    def write(self, path: Path, label_set: LabelSet) -> bool:
        """Write LabelSet to PDF XMP metadata."""
        try:
            import pikepdf
        except ImportError:
            logger.warning("pikepdf not installed, cannot write PDF labels")
            return False

        try:
            with pikepdf.open(path, allow_overwriting_input=True) as pdf:
                with pdf.open_metadata() as meta:
                    meta[f'{{{OPENLABELS_XMP_NS}}}openlabels'] = label_set.to_json(compact=True)
                pdf.save(path)
            return True

        except (OSError, ValueError) as e:
            logger.error(f"Failed to write PDF labels: {e}")
            return False

    def read(self, path: Path) -> Optional[LabelSet]:
        """Read LabelSet from PDF XMP metadata."""
        try:
            import pikepdf
        except ImportError:
            logger.warning("pikepdf not installed, cannot read PDF labels")
            return None

        try:
            with pikepdf.open(path) as pdf:
                with pdf.open_metadata() as meta:
                    # Try to read our namespace
                    key = f'{{{OPENLABELS_XMP_NS}}}openlabels'
                    if key in meta:
                        json_str = str(meta[key])
                        return LabelSet.from_json(json_str)
            return None

        except (OSError, ValueError) as e:
            logger.debug(f"No labels found in PDF: {e}")
            return None


__all__ = ['PDFLabelWriter']
