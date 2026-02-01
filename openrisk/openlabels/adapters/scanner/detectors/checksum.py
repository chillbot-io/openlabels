"""Tier 3: Checksum-validated detectors."""

import logging
import re
from typing import List, Tuple

from ..types import Span, Tier
from .base import BaseDetector
from .constants import (
    CONFIDENCE_LOW,
    CONFIDENCE_LUHN_INVALID,
    CONFIDENCE_PERFECT,
    CONFIDENCE_WEAK,
)

logger = logging.getLogger(__name__)


# VALIDATORS

def luhn_check(num: str) -> bool:
    """Luhn algorithm for credit card / NPI validation."""
    digits = [int(d) for d in num if d.isdigit()]
    if len(digits) < 2:
        logger.debug(f"Luhn check failed: too few digits ({len(digits)})")
        return False

    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d

    result = checksum % 10 == 0
    if not result:
        logger.debug(f"Luhn check failed: checksum={checksum} mod 10 = {checksum % 10}")
    return result


def validate_ssn(ssn: str) -> Tuple[bool, float]:
    """
    Validate SSN format and structure.

    Returns (True, confidence) for anything that LOOKS like an SSN.
    Security-first: Invalid area codes still detected with lower confidence.

    Confidence levels:
    - 0.99: Fully valid SSN (valid area, group, serial)
    - 0.85: Invalid area (000, 666, 900+) but otherwise valid structure
    - 0.80: Invalid group (00) or serial (0000) but valid format

    Security: Only accepts ASCII digits and standard separators (hyphen, space).
    Rejects unicode digits and special characters to prevent evasion.
    """
    # Strip leading/trailing whitespace
    ssn = ssn.strip()

    # Security: Only accept ASCII digits and standard separators
    # This prevents evasion via unicode digits (１２３) or special chars (123@45#6789)
    if not re.match(r'^[0-9\- ]+$', ssn):
        return False, 0.0

    # Extract only ASCII digits
    digits = re.sub(r'[^0-9]', '', ssn)
    if len(digits) != 9:
        return False, 0.0

    area, group, serial = digits[:3], digits[3:5], digits[5:]

    # Check for invalid patterns - still detect, but lower confidence
    confidence = CONFIDENCE_PERFECT

    # Invalid area numbers (000, 666, 900-999)
    if area in ('000', '666') or area.startswith('9'):
        logger.debug(f"SSN has invalid area code {area}, reducing confidence")
        confidence = CONFIDENCE_LOW  # Still detect for safety

    # Invalid group (00) - even lower confidence
    if group == '00':
        logger.debug(f"SSN has invalid group {group}, reducing confidence")
        confidence = min(confidence, CONFIDENCE_WEAK)

    # Invalid serial (0000) - even lower confidence
    if serial == '0000':
        logger.debug(f"SSN has invalid serial {serial}, reducing confidence")
        confidence = min(confidence, CONFIDENCE_WEAK)

    return True, confidence


def validate_credit_card(cc: str) -> Tuple[bool, float]:
    """Validate credit card using Luhn + prefix check.

    For PHI detection, over-detection is preferred - we detect cards with
    valid prefixes even if Luhn checksum fails (could be typo).

    Confidence levels:
    - 0.99: Valid prefix AND valid Luhn checksum
    - 0.87: Valid prefix but INVALID Luhn (possible typo - still detect for safety)
           Note: Must be above default threshold (0.85) to actually be detected
    """
    digits = re.sub(r'\D', '', cc)

    if len(digits) < 13 or len(digits) > 19:
        return False, 0.0

    # Check known prefixes
    prefix2 = int(digits[:2]) if len(digits) >= 2 else 0
    prefix3 = int(digits[:3]) if len(digits) >= 3 else 0
    prefix4 = int(digits[:4]) if len(digits) >= 4 else 0

    valid_prefix = (
        digits.startswith('4') or                    # Visa
        (51 <= prefix2 <= 55) or                     # Mastercard (classic)
        (2221 <= prefix4 <= 2720) or                 # Mastercard (new range)
        digits.startswith(('34', '37')) or           # Amex
        digits.startswith('6011') or                 # Discover
        digits.startswith('65') or                   # Discover
        (644 <= prefix3 <= 649) or                   # Discover
        digits.startswith('35') or                   # JCB
        digits.startswith('36') or                   # Diners Club International
        (300 <= prefix3 <= 305) or                   # Diners Club Carte Blanche
        digits.startswith('38') or                   # Diners Club International
        digits.startswith('39')                      # Diners Club International
    )

    if not valid_prefix:
        return False, 0.0

    # PHI safety: detect even with invalid Luhn (possible typo)
    if not luhn_check(digits):
        logger.debug(f"Credit card has valid prefix but failed Luhn check, detecting with reduced confidence")
        return True, CONFIDENCE_LUHN_INVALID  # Lower confidence but still detect (above default 0.85 threshold)

    return True, 0.99


def validate_npi(npi: str) -> Tuple[bool, float]:
    """Validate NPI using Luhn with 80840 prefix."""
    digits = re.sub(r'\D', '', npi)

    if len(digits) != 10:
        return False, 0.0

    if digits[0] not in ('1', '2'):
        return False, 0.0

    # Prepend 80840 for Luhn check
    check_digits = '80840' + digits
    if not luhn_check(check_digits):
        return False, 0.0

    return True, 0.99


def validate_dea(dea: str) -> Tuple[bool, float]:
    """
    Validate DEA number using DEA checksum formula.
    
    Format: 2 letters + 7 digits
    Checksum: (d1 + d3 + d5 + 2*(d2 + d4 + d6)) mod 10 == d7
    """
    dea = dea.upper().replace(' ', '')

    if len(dea) != 9:
        return False, 0.0

    if not dea[0].isalpha() or not dea[1].isalpha():
        return False, 0.0

    if not dea[2:].isdigit():
        return False, 0.0

    d = [int(c) for c in dea[2:]]
    checksum = d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5])

    if checksum % 10 != d[6]:
        return False, 0.0

    return True, 0.99


def validate_iban(iban: str) -> Tuple[bool, float]:
    """Validate IBAN using Mod-97 algorithm."""
    iban = iban.upper().replace(' ', '')

    if len(iban) < 15 or len(iban) > 34:
        return False, 0.0

    # Move first 4 chars to end
    rearranged = iban[4:] + iban[:4]

    # Convert letters to numbers (A=10, B=11, etc.)
    numeric = ''
    for c in rearranged:
        if c.isdigit():
            numeric += c
        elif c.isalpha():
            numeric += str(ord(c) - 55)
        else:
            return False, 0.0

    # Mod 97 check
    if int(numeric) % 97 != 1:
        return False, 0.0

    return True, 0.99


def validate_vin(vin: str) -> Tuple[bool, float]:
    """
    Validate VIN using check digit (position 9).
    
    17 chars, no I/O/Q, weighted transliteration.
    """
    vin = vin.upper().replace(' ', '')

    if len(vin) != 17:
        return False, 0.0

    # I, O, Q not allowed
    if any(c in vin for c in 'IOQ'):
        return False, 0.0

    # Transliteration values
    trans = {
        'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
        'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
        'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
    }

    # Position weights
    weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]

    total = 0
    for i, c in enumerate(vin):
        if c.isdigit():
            value = int(c)
        elif c in trans:
            value = trans[c]
        else:
            return False, 0.0
        total += value * weights[i]

    check = total % 11
    check_char = 'X' if check == 10 else str(check)

    if vin[8] != check_char:
        return False, 0.0

    return True, 0.99


def validate_aba_routing(aba: str) -> Tuple[bool, float]:
    """
    Validate ABA routing number using prefix and 3-7-1 weighted checksum.

    Valid ABA prefixes (first two digits):
    - 00-12: Federal Reserve Bank districts
    - 21-32: Thrift institutions
    - 61-72: Electronic transactions
    - 80: Traveler's checks
    """
    digits = re.sub(r'\D', '', aba)

    if len(digits) != 9:
        return False, 0.0

    # Check valid prefix ranges
    prefix = int(digits[:2])
    valid_prefix = (
        (0 <= prefix <= 12) or
        (21 <= prefix <= 32) or
        (61 <= prefix <= 72) or
        prefix == 80
    )

    if not valid_prefix:
        return False, 0.0

    d = [int(c) for c in digits]
    checksum = (3 * (d[0] + d[3] + d[6]) +
                7 * (d[1] + d[4] + d[7]) +
                1 * (d[2] + d[5] + d[8]))

    if checksum % 10 != 0:
        return False, 0.0

    return True, 0.99


# --- Shipping / Tracking Number Validators ---

def validate_ups_tracking(tracking: str) -> Tuple[bool, float]:
    """
    Validate UPS tracking number using check digit.

    Format: 1Z + 6 char shipper + 2 digit service + 8 digit package + check digit
    Total: 18 characters (1Z + 16 alphanumeric)

    Check digit algorithm:
    1. Take chars after "1Z" (16 chars)
    2. Convert letters to numbers (A=2, B=3, ..., Z=27, but only odd values used)
    3. Alternate add/double from right
    4. Check digit = (10 - (sum mod 10)) mod 10
    """
    tracking = tracking.upper().replace(' ', '')

    if not tracking.startswith('1Z'):
        return False, 0.0

    if len(tracking) != 18:
        return False, 0.0

    # Mapping for letters (UPS uses specific values)
    # Only A-Z allowed, no I or O
    letter_values = {
        'A': 2, 'B': 3, 'C': 4, 'D': 5, 'E': 6, 'F': 7, 'G': 8, 'H': 9,
        'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'Q': 8, 'R': 9,
        'S': 1, 'T': 2, 'U': 3, 'V': 4, 'W': 5, 'X': 6, 'Y': 7, 'Z': 8,
    }

    # Get the part after 1Z (should be 16 chars)
    data = tracking[2:]

    # Convert to numeric values
    values = []
    for c in data:
        if c.isdigit():
            values.append(int(c))
        elif c in letter_values:
            values.append(letter_values[c])
        else:
            return False, 0.0

    # Calculate check digit using odd positions (1, 3, 5, ...) * 2
    total = 0
    for i, v in enumerate(values[:-1]):  # Exclude check digit
        if i % 2 == 1:  # Odd position (0-indexed, so 1, 3, 5...)
            total += v * 2
        else:
            total += v

    expected_check = (10 - (total % 10)) % 10
    actual_check = values[-1]

    if expected_check != actual_check:
        return False, 0.0

    return True, 0.99


def validate_fedex_tracking(tracking: str) -> Tuple[bool, float]:
    """
    Validate FedEx tracking number.

    Formats:
    - 12 digits: Express/Ground (check digit is last digit, mod 10 weighted)
    - 15 digits: Ground 96 (starts with 96, embedded check)
    - 20 digits: Ground SSC (starts with 00-09, mod 10)
    - 22 digits: SmartPost (starts with 92, USPS compatible)
    """
    digits = re.sub(r'\D', '', tracking)

    if len(digits) == 12:
        # FedEx Express: weighted mod 10
        weights = [1, 7, 3, 1, 7, 3, 1, 7, 3, 1, 7]
        total = sum(int(d) * w for d, w in zip(digits[:11], weights))
        check = (total % 11) % 10
        if check != int(digits[11]):
            return False, 0.0
        return True, 0.99

    elif len(digits) == 15 and digits.startswith('96'):
        # FedEx Ground 96: use last digit as check
        # Simple mod 10 on sum
        total = sum(int(d) for d in digits[:14])
        check = (10 - (total % 10)) % 10
        if check != int(digits[14]):
            return False, 0.0
        return True, 0.99

    elif len(digits) == 20:
        # FedEx Ground SSC: weighted mod 10
        weights = [3, 1] * 9 + [3]
        total = sum(int(d) * w for d, w in zip(digits[:19], weights))
        check = (10 - (total % 10)) % 10
        if check != int(digits[19]):
            return False, 0.0
        return True, 0.99

    elif len(digits) == 22 and digits.startswith('92'):
        # SmartPost: USPS compatible, mod 10
        weights = [3, 1] * 10 + [3]
        total = sum(int(d) * w for d, w in zip(digits[:21], weights))
        check = (10 - (total % 10)) % 10
        if check != int(digits[21]):
            return False, 0.0
        return True, 0.99

    return False, 0.0


def validate_usps_tracking(tracking: str) -> Tuple[bool, float]:
    """
    Validate USPS tracking number using Mod 10 check digit.

    Formats:
    - 20 digits: Most common (starts with various prefixes)
    - 22 digits: IMpb format (starts with 92, 93, 94)
    - 13 characters: International (2 letters + 9 digits + 2 letters)

    Mod 10 algorithm (for numeric):
    Multiply digits by weights [3,1,3,1,...], sum, check = (10 - sum%10) % 10
    """
    tracking = tracking.upper().replace(' ', '')

    # International format: 2 letters + 9 digits + 2 letters (e.g., EZ123456789US)
    if len(tracking) == 13 and tracking[:2].isalpha() and tracking[-2:].isalpha():
        digits = tracking[2:11]
        if not digits.isdigit():
            return False, 0.0
        weights = [8, 6, 4, 2, 3, 5, 9, 7]
        total = sum(int(d) * w for d, w in zip(digits[:8], weights))
        check = 11 - (total % 11)
        if check == 10:
            check = 0
        elif check == 11:
            check = 5
        if check != int(digits[8]):
            return False, 0.0
        return True, 0.99

    # Numeric formats
    digits = re.sub(r'\D', '', tracking)

    if len(digits) in (20, 22):
        # Mod 10 with alternating 3,1 weights
        weights = ([3, 1] * ((len(digits) - 1) // 2 + 1))[:len(digits) - 1]
        total = sum(int(d) * w for d, w in zip(digits[:-1], weights))
        check = (10 - (total % 10)) % 10
        if check != int(digits[-1]):
            return False, 0.0
        return True, 0.99

    return False, 0.0


# PATTERNS

CHECKSUM_PATTERNS = [
    # SSN - various formats
    # Use negative lookbehind/ahead to prevent matching inside product codes like SKU-123-45-6789
    # Real SSNs don't have letters adjacent to them
    (re.compile(r'(?<![A-Za-z-])(\d{3}-\d{2}-\d{4})(?![A-Za-z])'), 'SSN', validate_ssn),
    (re.compile(r'(?<![A-Za-z])(\d{3}\s\d{2}\s\d{4})(?![A-Za-z])'), 'SSN', validate_ssn),
    # Evasion resistance: spaces around dashes (e.g., "123 - 45 - 6789")
    (re.compile(r'(?<![A-Za-z-])(\d{3}\s*-\s*\d{2}\s*-\s*\d{4})(?![A-Za-z])'), 'SSN', validate_ssn),
    # Evasion resistance: multiple spaces (e.g., "123  45  6789")
    (re.compile(r'(?<![A-Za-z])(\d{3}\s{2,}\d{2}\s{2,}\d{4})(?![A-Za-z])'), 'SSN', validate_ssn),
    # Evasion resistance: space between every digit (e.g., "1 2 3 - 4 5 - 6 7 8 9")
    (re.compile(r'(?<![A-Za-z\d])(\d\s+\d\s+\d\s*-?\s*\d\s+\d\s*-?\s*\d\s+\d\s+\d\s+\d)(?![A-Za-z\d])'), 'SSN', validate_ssn),
    # Bare 9-digit SSN - labeled context required to avoid false positives
    (re.compile(r'(?:SSN|social\s*security)[:\s#]*(\d{9})\b', re.I), 'SSN', validate_ssn),

    # Credit Card - various formats (evasion resistance: accept -, space, dot, underscore as separators)
    (re.compile(r'\b(\d{4}[-\s._]?\d{4}[-\s._]?\d{4}[-\s._]?\d{4})\b'), 'CREDIT_CARD', validate_credit_card),
    (re.compile(r'\b(\d{4}[-\s._]?\d{6}[-\s._]?\d{5})\b'), 'CREDIT_CARD', validate_credit_card),  # Amex
    # Continuous 13-19 digits (let Luhn + prefix validation filter)
    (re.compile(r'\b(\d{13,19})\b'), 'CREDIT_CARD', validate_credit_card),

    # NPI - 10 digits starting with 1 or 2
    (re.compile(r'\b([12]\d{9})\b'), 'NPI', validate_npi),

    # DEA
    (re.compile(r'\b([A-Za-z]{2}\d{7})\b'), 'DEA', validate_dea),

    # IBAN
    (re.compile(r'\b([A-Z]{2}\d{2}[A-Z0-9]{4,30})\b', re.I), 'IBAN', validate_iban),

    # VIN
    (re.compile(r'\b([A-HJ-NPR-Z0-9]{17})\b', re.I), 'VIN', validate_vin),

    # ABA Routing - REQUIRE context to avoid SSN collision
    # Bare 9-digit numbers default to SSN in healthcare context
    # Labeled patterns handled in patterns.py

    # -------------------------------------------------------------------------
    # SHIPPING TRACKING NUMBERS (prevent false positive as MRN/SSN)
    # -------------------------------------------------------------------------

    # UPS: 1Z + 16 alphanumeric (18 total)
    (re.compile(r'\b(1Z[A-Z0-9]{16})\b', re.I), 'TRACKING_NUMBER', validate_ups_tracking),

    # FedEx: 12, 15, 20, or 22 digits
    (re.compile(r'\b(\d{12})\b'), 'TRACKING_NUMBER', validate_fedex_tracking),
    (re.compile(r'\b(96\d{13})\b'), 'TRACKING_NUMBER', validate_fedex_tracking),  # 15-digit starting with 96
    (re.compile(r'\b(\d{20})\b'), 'TRACKING_NUMBER', validate_fedex_tracking),
    (re.compile(r'\b(92\d{20})\b'), 'TRACKING_NUMBER', validate_fedex_tracking),  # 22-digit SmartPost

    # USPS: 20-22 digits or international format
    (re.compile(r'\b(\d{20,22})\b'), 'TRACKING_NUMBER', validate_usps_tracking),
    (re.compile(r'\b([A-Z]{2}\d{9}[A-Z]{2})\b'), 'TRACKING_NUMBER', validate_usps_tracking),  # International
]


# DETECTOR

class ChecksumDetector(BaseDetector):
    """
    Tier 3 detector: Algorithmic validation.

    High confidence (0.99) because validation is mathematical.
    """

    name = "checksum"
    tier = Tier.CHECKSUM

    def detect(self, text: str) -> List[Span]:
        spans = []
        seen = set()  # (start, end, text) to avoid duplicates from overlapping patterns
        validation_failures = 0
        duplicates_skipped = 0

        for pattern, entity_type, validator in CHECKSUM_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(1)
                is_valid, confidence = validator(value)

                if is_valid:
                    key = (match.start(1), match.end(1), value)
                    if key in seen:
                        duplicates_skipped += 1
                        continue
                    seen.add(key)

                    span = Span(
                        start=match.start(1),
                        end=match.end(1),
                        text=value,
                        entity_type=entity_type,
                        confidence=confidence,
                        detector=self.name,
                        tier=self.tier,
                    )
                    spans.append(span)
                    logger.debug(f"Detected {entity_type} at {match.start(1)}-{match.end(1)} with confidence {confidence:.2f}")
                else:
                    validation_failures += 1

        if spans:
            # Summarize by entity type
            type_counts = {}
            for span in spans:
                type_counts[span.entity_type] = type_counts.get(span.entity_type, 0) + 1
            logger.info(f"ChecksumDetector found {len(spans)} entities: {type_counts}")

        if validation_failures > 0:
            logger.debug(f"ChecksumDetector: {validation_failures} pattern matches failed validation")
        if duplicates_skipped > 0:
            logger.debug(f"ChecksumDetector: {duplicates_skipped} duplicate matches skipped")

        return spans
