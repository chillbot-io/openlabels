"""Pattern definitions for PHI/PII entity recognition.

This module aggregates all domain-specific pattern definitions and provides
backward compatibility through the PATTERNS list.

Domain-specific modules:
- pii.py: Phone, Email, Dates, Time, Age, Room/Bed, Names
- healthcare.py: MRN, NPI, Health Plan IDs, MBI, NDC, Blood type, Pharmacy, Clinics
- government.py: SSN, Driver's License, State ID, Passport, Military IDs, International IDs
- financial.py: Credit Card, VIN, License Plate, Bank routing, Account numbers
- credentials.py: IP, MAC, IMEI, URLs, Username, Password, Biometric IDs
- address.py: Address patterns, ZIP codes, GPS coordinates
"""

import regex  # Use regex module for ReDoS timeout protection (CVE-READY-003)
from typing import List, Tuple

# Import domain-specific patterns
from .pii import PII_PATTERNS
from .healthcare import HEALTHCARE_PATTERNS
from .government import GOVERNMENT_PATTERNS
from .financial import FINANCIAL_PATTERNS
from .credentials import CREDENTIALS_PATTERNS
from .address import ADDRESS_PATTERNS

# PATTERN DEFINITIONS
# Each pattern is (regex, entity_type, confidence, group_index)
# group_index is which capture group contains the value (default 0 = whole match)

# Aggregate all patterns for backward compatibility
PATTERNS: List[Tuple[regex.Pattern, str, float, int]] = []
PATTERNS.extend(PII_PATTERNS)
PATTERNS.extend(HEALTHCARE_PATTERNS)
PATTERNS.extend(GOVERNMENT_PATTERNS)
PATTERNS.extend(FINANCIAL_PATTERNS)
PATTERNS.extend(CREDENTIALS_PATTERNS)
PATTERNS.extend(ADDRESS_PATTERNS)


def add_pattern(pattern: str, entity_type: str, confidence: float, group: int = 0, flags: int = 0):
    """Helper to add patterns to the global PATTERNS list.

    This function is kept for backward compatibility and for any patterns
    that don't fit cleanly into domain-specific modules.
    """
    PATTERNS.append((regex.compile(pattern, flags), entity_type, confidence, group))


# Export all domain pattern lists for direct access
__all__ = [
    'PATTERNS',
    'add_pattern',
    'PII_PATTERNS',
    'HEALTHCARE_PATTERNS',
    'GOVERNMENT_PATTERNS',
    'FINANCIAL_PATTERNS',
    'CREDENTIALS_PATTERNS',
    'ADDRESS_PATTERNS',
]
