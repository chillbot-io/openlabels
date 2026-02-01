"""Base detector interface."""

from abc import ABC, abstractmethod
from typing import List

from ..types import Span, Tier


class BaseDetector(ABC):
    """
    Base class for all detectors.
    
    Each detector:
    - Has a name and tier
    - Takes normalized text
    - Returns list of Span
    - Is independent (no shared state)
    """

    name: str = "base"
    tier: Tier = Tier.ML

    @abstractmethod
    def detect(self, text: str) -> List[Span]:
        """
        Detect PHI/PII in text.
        
        Args:
            text: Normalized UTF-8 text
        
        Returns:
            List of detected spans
        """
        pass

    def is_available(self) -> bool:
        """Check if detector is ready to use."""
        return True
