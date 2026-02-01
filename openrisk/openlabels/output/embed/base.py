"""
Base class and constants for embedded label writers.

Embedded labels are stored directly in file native metadata,
making them the source of truth for files that support this feature.
"""

import logging
from pathlib import Path
from abc import ABC, abstractmethod
from typing import Optional

from ...core.labels import LabelSet

logger = logging.getLogger(__name__)

# XMP namespace for OpenLabels
OPENLABELS_XMP_NS = "http://openlabels.dev/ns/1.0/"
OPENLABELS_XMP_PREFIX = "openlabels"


class EmbeddedLabelWriter(ABC):
    """Abstract base class for embedded label writers."""

    @abstractmethod
    def write(self, path: Path, label_set: LabelSet) -> bool:
        """
        Write a LabelSet to the file's native metadata.

        Args:
            path: Path to the file
            label_set: The LabelSet to embed

        Returns:
            True if successful, False otherwise
        """
        ...

    @abstractmethod
    def read(self, path: Path) -> Optional[LabelSet]:
        """
        Read a LabelSet from the file's native metadata.

        Args:
            path: Path to the file

        Returns:
            LabelSet if found, None otherwise
        """
        ...

    @abstractmethod
    def supports(self, path: Path) -> bool:
        """Check if this writer supports the given file type."""
        ...


__all__ = [
    'EmbeddedLabelWriter',
    'OPENLABELS_XMP_NS',
    'OPENLABELS_XMP_PREFIX',
    'logger',
]
