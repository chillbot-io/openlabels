"""
OpenLabels Detectors.

This module provides entity detection capabilities through
multiple specialized detectors.

Detectors:
- ChecksumDetector: Validates entities with checksums (SSN, Credit Card, etc.)
- SecretsDetector: Detects API keys, tokens, credentials
- FinancialDetector: Detects financial identifiers and crypto addresses
- GovernmentDetector: Detects classification markings and government IDs
"""

from .base import BaseDetector
from .checksum import ChecksumDetector
from .secrets import SecretsDetector
from .financial import FinancialDetector
from .government import GovernmentDetector
from .orchestrator import DetectorOrchestrator, detect

__all__ = [
    "BaseDetector",
    "ChecksumDetector",
    "SecretsDetector",
    "FinancialDetector",
    "GovernmentDetector",
    "DetectorOrchestrator",
    "detect",
]
