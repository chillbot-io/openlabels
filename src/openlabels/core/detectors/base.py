"""
Base detector interface for OpenLabels detection engine.

All detectors must inherit from BaseDetector and implement the detect() method.
"""

from abc import ABC, abstractmethod

from ..types import Span, Tier


class BaseDetector(ABC):
    """
    Base class for all detectors.

    Each detector:
    - Has a name and tier
    - Takes normalized text
    - Returns list of Span
    - Is independent (no shared state between detect() calls)

    Attributes:
        name: Unique identifier for the detector
        tier: Authority level (CHECKSUM > STRUCTURED > PATTERN > ML)
    """

    name: str = "base"
    tier: Tier = Tier.PATTERN

    @abstractmethod
    def detect(self, text: str) -> list[Span]:
        """
        Detect entities in text.

        Args:
            text: Normalized UTF-8 text to scan

        Returns:
            List of detected Span objects
        """
        pass

    def is_available(self) -> bool:
        """
        Check if detector is ready to use.

        Override this method to check for required resources
        (models loaded, API keys configured, etc.)

        Returns:
            True if detector is operational
        """
        return True

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, tier={self.tier.name})"
