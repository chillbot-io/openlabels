"""
Checksum-validated detector (Tier 4 - highest confidence).

Validates entities using mathematical checksums:
- SSN: Format and area code validation
- Credit Card: Luhn algorithm + card network prefix
- NPI: Luhn with healthcare prefix
- DEA: DEA-specific checksum
- IBAN: Mod-97 international bank account
- VIN: Vehicle identification check digit
- ABA: Bank routing number checksum
- Tracking numbers: UPS, FedEx, USPS

These detections have the highest confidence (0.99) because
they are mathematically validated, not just pattern-matched.
"""

import logging
import re
from typing import List, Tuple

from ..types import Span, Tier
from .base import BaseDetector
from .registry import register_detector
from .._rust.validators_py import (
    validate_luhn,
    validate_ssn as _validate_ssn_bool,
    validate_cusip as _validate_cusip_bool,
    validate_isin as _validate_isin_bool,
)

logger = logging.getLogger(__name__)

# =============================================================================
# VALIDATORS (Python fallback — Rust overrides these below)
# Core bool validators imported from _rust/validators_py (single source of truth).
# Wrappers below add (bool, float) return signatures where needed.
# =============================================================================

luhn_check = validate_luhn


def validate_ssn(ssn: str) -> Tuple[bool, float]:
    """
    Validate SSN format and structure.

    Security-first: Invalid area codes still detected with lower confidence.
    Core validation delegates to the canonical validator in _rust/validators_py.

    Confidence levels:
    - 0.99: Fully valid SSN
    - 0.85: Invalid area code but valid structure
    - 0.80: Invalid group/serial but valid format
    """
    ssn = ssn.strip()

    # Only accept ASCII digits and standard separators
    if not re.match(r'^[0-9\- ]+$', ssn):
        return False, 0.0

    digits = re.sub(r'[^0-9]', '', ssn)
    if len(digits) != 9:
        return False, 0.0

    # Use canonical validator for strict check
    if _validate_ssn_bool(digits):
        return True, 0.99

    # The canonical validator rejected this SSN (invalid area, group, or serial),
    # but we still detect it at lower confidence for security.
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    confidence = 0.85
    if group == '00':
        confidence = min(confidence, 0.80)
    if serial == '0000':
        confidence = min(confidence, 0.80)

    return True, confidence


def validate_credit_card(cc: str) -> Tuple[bool, float]:
    """
    Validate credit card using Luhn + prefix check.

    Confidence levels:
    - 0.99: Valid prefix AND valid Luhn
    - 0.87: Valid prefix but invalid Luhn (possible typo)
    """
    digits = re.sub(r'\D', '', cc)

    if len(digits) < 13 or len(digits) > 19:
        return False, 0.0

    prefix2 = int(digits[:2]) if len(digits) >= 2 else 0
    prefix3 = int(digits[:3]) if len(digits) >= 3 else 0
    prefix4 = int(digits[:4]) if len(digits) >= 4 else 0

    valid_prefix = (
        digits.startswith('4') or                    # Visa
        (51 <= prefix2 <= 55) or                     # Mastercard
        (2221 <= prefix4 <= 2720) or                 # Mastercard (new)
        digits.startswith(('34', '37')) or           # Amex
        digits.startswith('6011') or                 # Discover
        digits.startswith('65') or                   # Discover
        (644 <= prefix3 <= 649) or                   # Discover
        digits.startswith('35') or                   # JCB
        digits.startswith('36') or                   # Diners Club
        (300 <= prefix3 <= 305) or                   # Diners Club
        digits.startswith(('38', '39'))              # Diners Club
    )

    if not valid_prefix:
        return False, 0.0

    if not luhn_check(digits):
        return True, 0.87  # Still detect for safety

    return True, 0.99


def validate_npi(npi: str) -> Tuple[bool, float]:
    """Validate NPI using Luhn with 80840 prefix."""
    digits = re.sub(r'\D', '', npi)

    if len(digits) != 10:
        return False, 0.0

    if digits[0] not in ('1', '2'):
        return False, 0.0

    check_digits = '80840' + digits
    if not luhn_check(check_digits):
        return False, 0.0

    return True, 0.99


def validate_dea(dea: str) -> Tuple[bool, float]:
    """
    Validate DEA number using DEA checksum formula.
    Format: 2 letters + 7 digits
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

    rearranged = iban[4:] + iban[:4]

    numeric = ''
    for c in rearranged:
        if c.isdigit():
            numeric += c
        elif c.isalpha():
            numeric += str(ord(c) - 55)
        else:
            return False, 0.0

    if int(numeric) % 97 != 1:
        return False, 0.0

    return True, 0.99


def validate_vin(vin: str) -> Tuple[bool, float]:
    """Validate VIN using check digit (position 9)."""
    vin = vin.upper().replace(' ', '')

    if len(vin) != 17:
        return False, 0.0

    if any(c in vin for c in 'IOQ'):
        return False, 0.0

    trans = {
        'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
        'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
        'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
    }

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
    """Validate ABA routing number using prefix and checksum."""
    digits = re.sub(r'\D', '', aba)

    if len(digits) != 9:
        return False, 0.0

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


# =============================================================================
# TRACKING NUMBER VALIDATORS
# =============================================================================

def validate_ups_tracking(tracking: str) -> Tuple[bool, float]:
    """Validate UPS tracking number (1Z + 16 alphanumeric)."""
    tracking = tracking.upper().replace(' ', '')

    if not tracking.startswith('1Z') or len(tracking) != 18:
        return False, 0.0

    letter_values = {
        'A': 2, 'B': 3, 'C': 4, 'D': 5, 'E': 6, 'F': 7, 'G': 8, 'H': 9,
        'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'Q': 8, 'R': 9,
        'S': 1, 'T': 2, 'U': 3, 'V': 4, 'W': 5, 'X': 6, 'Y': 7, 'Z': 8,
    }

    data = tracking[2:]
    values = []
    for c in data:
        if c.isdigit():
            values.append(int(c))
        elif c in letter_values:
            values.append(letter_values[c])
        else:
            return False, 0.0

    total = 0
    for i, v in enumerate(values[:-1]):
        if i % 2 == 1:
            total += v * 2
        else:
            total += v

    expected_check = (10 - (total % 10)) % 10
    if expected_check != values[-1]:
        return False, 0.0

    return True, 0.99


def validate_fedex_tracking(tracking: str) -> Tuple[bool, float]:
    """Validate FedEx tracking number (12, 15, 20, or 22 digits)."""
    digits = re.sub(r'\D', '', tracking)

    if len(digits) == 12:
        weights = [1, 7, 3, 1, 7, 3, 1, 7, 3, 1, 7]
        total = sum(int(d) * w for d, w in zip(digits[:11], weights))
        check = (total % 11) % 10
        if check != int(digits[11]):
            return False, 0.0
        return True, 0.99

    elif len(digits) == 15 and digits.startswith('96'):
        total = sum(int(d) for d in digits[:14])
        check = (10 - (total % 10)) % 10
        if check != int(digits[14]):
            return False, 0.0
        return True, 0.99

    elif len(digits) == 20:
        weights = [3, 1] * 9 + [3]
        total = sum(int(d) * w for d, w in zip(digits[:19], weights))
        check = (10 - (total % 10)) % 10
        if check != int(digits[19]):
            return False, 0.0
        return True, 0.99

    elif len(digits) == 22 and digits.startswith('92'):
        weights = [3, 1] * 10 + [3]
        total = sum(int(d) * w for d, w in zip(digits[:21], weights))
        check = (10 - (total % 10)) % 10
        if check != int(digits[21]):
            return False, 0.0
        return True, 0.99

    return False, 0.0


def validate_usps_tracking(tracking: str) -> Tuple[bool, float]:
    """Validate USPS tracking number."""
    tracking = tracking.upper().replace(' ', '')

    # International format: 2 letters + 9 digits + 2 letters
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
        weights = ([3, 1] * ((len(digits) - 1) // 2 + 1))[:len(digits) - 1]
        total = sum(int(d) * w for d, w in zip(digits[:-1], weights))
        check = (10 - (total % 10)) % 10
        if check != int(digits[-1]):
            return False, 0.0
        return True, 0.99

    return False, 0.0


# =============================================================================
# FINANCIAL INSTRUMENT VALIDATORS
# =============================================================================

def validate_cusip(cusip: str) -> Tuple[bool, float]:
    """Validate CUSIP (9-character security identifier).

    Delegates to the canonical validator in _rust/validators_py.
    """
    if not _validate_cusip_bool(cusip):
        return False, 0.0
    return True, 0.99


def validate_isin(isin: str) -> Tuple[bool, float]:
    """Validate ISIN (12-character international security identifier).

    Delegates to the canonical validator in _rust/validators_py.
    """
    if not _validate_isin_bool(isin):
        return False, 0.0
    return True, 0.99


# =============================================================================
# RUST ACCELERATION (default — Python above is fallback only)
# =============================================================================

try:
    from openlabels_matcher import (
        checksum_ssn as _rust_ssn,
        checksum_credit_card as _rust_cc,
        checksum_npi as _rust_npi,
        checksum_dea as _rust_dea,
        checksum_iban as _rust_iban,
        checksum_vin as _rust_vin,
        checksum_aba_routing as _rust_aba,
        checksum_ups_tracking as _rust_ups,
        checksum_fedex_tracking as _rust_fedex,
        checksum_usps_tracking as _rust_usps,
        checksum_cusip as _rust_cusip,
        checksum_isin as _rust_isin,
    )

    # Rebind module-level names so CHECKSUM_PATTERNS captures Rust functions
    validate_ssn = _rust_ssn
    validate_credit_card = _rust_cc
    validate_npi = _rust_npi
    validate_dea = _rust_dea
    validate_iban = _rust_iban
    validate_vin = _rust_vin
    validate_aba_routing = _rust_aba
    validate_ups_tracking = _rust_ups
    validate_fedex_tracking = _rust_fedex
    validate_usps_tracking = _rust_usps
    validate_cusip = _rust_cusip
    validate_isin = _rust_isin

    logger.info("Checksum validators: using Rust acceleration")
except ImportError:
    logger.info("Checksum validators: using Python fallback")


# =============================================================================
# PATTERNS
# =============================================================================

CHECKSUM_PATTERNS: tuple[tuple[re.Pattern[str], str, object], ...] = (
    # SSN - various formats with anti-evasion
    (re.compile(r'(?<![A-Za-z-])(\d{3}-\d{2}-\d{4})(?![A-Za-z])'), 'SSN', validate_ssn),
    (re.compile(r'(?<![A-Za-z])(\d{3}\s\d{2}\s\d{4})(?![A-Za-z])'), 'SSN', validate_ssn),
    (re.compile(r'(?<![A-Za-z-])(\d{3}\s*-\s*\d{2}\s*-\s*\d{4})(?![A-Za-z])'), 'SSN', validate_ssn),
    (re.compile(r'(?:SSN|social\s*security)[:\s#]*(\d{9})\b', re.I), 'SSN', validate_ssn),

    # Credit Card - various formats
    (re.compile(r'\b(\d{4}[-\s._]?\d{4}[-\s._]?\d{4}[-\s._]?\d{4})\b'), 'CREDIT_CARD', validate_credit_card),
    (re.compile(r'\b(\d{4}[-\s._]?\d{6}[-\s._]?\d{5})\b'), 'CREDIT_CARD', validate_credit_card),
    (re.compile(r'\b(\d{13,19})\b'), 'CREDIT_CARD', validate_credit_card),

    # NPI - 10 digits starting with 1 or 2
    (re.compile(r'\b([12]\d{9})\b'), 'NPI', validate_npi),

    # DEA - 2 letters + 7 digits
    (re.compile(r'\b([A-Za-z]{2}\d{7})\b'), 'DEA', validate_dea),

    # IBAN
    (re.compile(r'\b([A-Z]{2}\d{2}[A-Z0-9]{4,30})\b', re.I), 'IBAN', validate_iban),

    # VIN - 17 characters (no I, O, Q)
    (re.compile(r'\b([A-HJ-NPR-Z0-9]{17})\b', re.I), 'VIN', validate_vin),

    # CUSIP - 9 characters
    (re.compile(r'\b([A-Z0-9]{9})\b'), 'CUSIP', validate_cusip),

    # ISIN - 12 characters (2 letters + 10 alphanumeric)
    (re.compile(r'\b([A-Z]{2}[A-Z0-9]{10})\b'), 'ISIN', validate_isin),

    # Tracking Numbers
    (re.compile(r'\b(1Z[A-Z0-9]{16})\b', re.I), 'TRACKING_NUMBER', validate_ups_tracking),
    (re.compile(r'\b(\d{12})\b'), 'TRACKING_NUMBER', validate_fedex_tracking),
    (re.compile(r'\b(96\d{13})\b'), 'TRACKING_NUMBER', validate_fedex_tracking),
    (re.compile(r'\b(\d{20})\b'), 'TRACKING_NUMBER', validate_fedex_tracking),
    (re.compile(r'\b(92\d{20})\b'), 'TRACKING_NUMBER', validate_fedex_tracking),
    (re.compile(r'\b(\d{20,22})\b'), 'TRACKING_NUMBER', validate_usps_tracking),
    (re.compile(r'\b([A-Z]{2}\d{9}[A-Z]{2})\b'), 'TRACKING_NUMBER', validate_usps_tracking),
)


# =============================================================================
# DETECTOR
# =============================================================================

@register_detector
class ChecksumDetector(BaseDetector):
    """
    Tier 4 detector: Algorithmic validation.

    High confidence (0.99) because validation is mathematical.
    """

    name = "checksum"
    tier = Tier.CHECKSUM

    def detect(self, text: str) -> List[Span]:
        spans = []
        seen = set()  # (start, end, text) to avoid duplicates

        for pattern, entity_type, validator in CHECKSUM_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(1)
                is_valid, confidence = validator(value)

                if is_valid:
                    key = (match.start(1), match.end(1), value)
                    if key in seen:
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

        return spans
