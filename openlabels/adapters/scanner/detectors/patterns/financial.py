"""Financial patterns: credit cards, routing numbers, accounts, VIN, license plates."""

import regex  # Use regex module for ReDoS timeout protection (CVE-READY-003)
from typing import List, Tuple
from ..constants import (
    CONFIDENCE_HIGH,
    CONFIDENCE_HIGH_MEDIUM,
    CONFIDENCE_LOW,
    CONFIDENCE_MARGINAL,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_MEDIUM_LOW,
    CONFIDENCE_MINIMAL,
    CONFIDENCE_NEAR_CERTAIN,
    CONFIDENCE_WEAK,
)

from ..pattern_registry import create_pattern_adder

FINANCIAL_PATTERNS: List[Tuple[regex.Pattern, str, float, int]] = []
add_pattern = create_pattern_adder(FINANCIAL_PATTERNS)



# --- Aba Routing Numbers ---


add_pattern(r'(?:Routing|ABA|RTN)[:\s#]+(\d{9})\b', 'ABA_ROUTING', CONFIDENCE_HIGH, 1, regex.I)



# --- Account Numbers ---


# Account numbers - both numeric-only and alphanumeric formats
add_pattern(r'(?:Account)\s*(?:Number|No|#)?[:\s#]+(\d{8,17})\b', 'ACCOUNT_NUMBER', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
add_pattern(r'(?:Account)\s*(?:Number|No|#)?[:\s#]+([A-Z0-9][-A-Z0-9]{5,19})', 'ACCOUNT_NUMBER', CONFIDENCE_LOW, 1, regex.I)

# === Additional Account Numbers (Safe Harbor #10) ===
add_pattern(r'(?:Patient\s+)?(?:Acct)\s*(?:Number|No|#)?[:\s#]+([A-Z0-9-]{6,20})', 'ACCOUNT_NUMBER', CONFIDENCE_LOW, 1, regex.I)
add_pattern(r'(?:Invoice|Billing|Statement)\s*(?:Number|No|#)?\s*[:#]\s*([A-Z0-9-]{6,20})', 'ACCOUNT_NUMBER', CONFIDENCE_WEAK, 1, regex.I)
add_pattern(r'(?:Claim)\s*(?:Number|No|#)?\s*[:#]\s*([A-Z0-9-]{8,20})', 'CLAIM_NUMBER', CONFIDENCE_MEDIUM_LOW, 1, regex.I)


# --- Certificate/License Numbers (Safe Harbor #11) ---

add_pattern(r'(?:Certificate|Certification)\s+(?:Number|No|#)[:\s]+([A-Z0-9-]{5,20})', 'CERTIFICATE_NUMBER', CONFIDENCE_LOW, 1, regex.I)
# NOTE: Require at least one digit to avoid matching "Radiologist"
add_pattern(r'(?:Board\s+Certified?|Certified)\s+#?[:\s]*([A-Z]*\d[A-Z0-9]{4,14})', 'CERTIFICATE_NUMBER', CONFIDENCE_WEAK, 1, regex.I)


# --- Unique Identifiers (Safe Harbor #18) ---

# Require explicit colon or # separator (not just whitespace) to avoid FPs
add_pattern(r'(?:Case|File|Record)\s*(?:Number|No|#)?\s*[:#]\s*([A-Z0-9-]{5,20})', 'UNIQUE_ID', CONFIDENCE_MINIMAL, 1, regex.I)



# --- Credit Card Numbers ---


# 13-19 digits, optionally separated by spaces/dashes
# Luhn validation done in detector
add_pattern(r'(?:Card|Credit\s*Card|CC|Payment)[:\s#]+(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7})', 'CREDIT_CARD', CONFIDENCE_HIGH_MEDIUM, 1, regex.I)
# Bare credit card patterns (with separators to distinguish from random numbers)
add_pattern(r'\b(\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4})\b', 'CREDIT_CARD', CONFIDENCE_MEDIUM_LOW, 1)
add_pattern(r'\b(\d{4}[\s-]\d{6}[\s-]\d{5})\b', 'CREDIT_CARD', CONFIDENCE_MEDIUM_LOW, 1)  # Amex format
# Last 4 of card
add_pattern(r'(?:ending\s+in|last\s+4|xxxx)[:\s]*(\d{4})\b', 'CREDIT_CARD_PARTIAL', CONFIDENCE_MARGINAL, 1, regex.I)


# --- Vehicle Identifiers (HIPAA Required) ---

# === VIN (Vehicle Identification Number) ===
# 17 characters: A-Z (except I, O, Q) and 0-9
# Position 9 is check digit, position 10 is model year
# Common in accident/injury records, insurance claims
add_pattern(r'(?:VIN|Vehicle\s*(?:ID|Identification)(?:\s*Number)?)[:\s#]+([A-HJ-NPR-Z0-9]{17})\b', 'VIN', CONFIDENCE_NEAR_CERTAIN, 1, regex.I)
# Bare VIN with word boundary - must be exactly 17 valid VIN characters
add_pattern(r'\b([A-HJ-NPR-Z0-9]{17})\b', 'VIN', CONFIDENCE_MINIMAL, 1)

# === License Plate ===
add_pattern(r'(?:License\s*Plate|Plate\s*(?:Number|No|#)|Tag)[:\s#]+([A-Z0-9]{2,8})', 'LICENSE_PLATE', CONFIDENCE_MEDIUM_LOW, 1, regex.I)

# State-specific license plate formats (high confidence)
# California: 1ABC234 (1 digit, 3 letters, 3 digits)
add_pattern(r'\b(\d[A-Z]{3}\d{3})\b', 'LICENSE_PLATE', CONFIDENCE_MARGINAL, 1)
# New York: ABC-1234 (3 letters, 4 digits with dash)
add_pattern(r'\b([A-Z]{3}-\d{4})\b', 'LICENSE_PLATE', CONFIDENCE_LOW, 1)
# Texas: ABC-1234 or ABC 1234
add_pattern(r'\b([A-Z]{3}[-\s]\d{4})\b', 'LICENSE_PLATE', CONFIDENCE_MARGINAL, 1)
# Florida: ABC D12 or ABCD12 (letter-heavy)
add_pattern(r'\b([A-Z]{3,4}\s?[A-Z]?\d{2})\b', 'LICENSE_PLATE', CONFIDENCE_MINIMAL, 1)
