"""Validation functions for pattern-detected entities."""

import re
from ..constants import CONFIDENCE_MINIMAL
from ..checksum import luhn_check


def validate_ip(ip: str) -> bool:
    """Validate IP address octets are 0-255."""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


_INVALID_AREA_CODES = frozenset({
    '000', '555', '911', '411', '611', '711', '811', '311', '211', '511',
})


def validate_phone(phone: str) -> bool:
    """Validate US phone number - rejects invalid area codes and test numbers."""
    digits = ''.join(c for c in phone if c.isdigit())

    if len(digits) < 10:
        return True  # Can't validate, allow through

    area_code = digits[:3]

    if area_code in _INVALID_AREA_CODES:
        return False
    if digits[:10] == '0000000000':
        return False
    if digits[:10] == '1234567890':
        return False
    if len(set(digits[:10])) == 1:
        return False

    return True


def validate_date(month: int, day: int, year: int) -> bool:
    """Validate date is a real calendar date."""
    if not (1900 <= year <= 2100):
        return False
    if not (1 <= month <= 12):
        return False

    days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

    is_leap = (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
    if is_leap and month == 2:
        max_day = 29
    else:
        max_day = days_in_month[month]

    return 1 <= day <= max_day


def validate_age(value: str) -> bool:
    """Validate age is reasonable (0-125)."""
    try:
        age = int(value)
        return 0 <= age <= 125
    except ValueError:
        return False


# validate_luhn is imported from checksum module as luhn_check
# Alias for backward compatibility
validate_luhn = luhn_check


def validate_vin(vin: str) -> bool:
    """Validate VIN check digit (position 9)."""
    if len(vin) != 17:
        return False

    trans = {
        'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
        'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
        'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
    }

    weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]

    try:
        total = 0
        for i, char in enumerate(vin.upper()):
            if char.isdigit():
                value = int(char)
            elif char in trans:
                value = trans[char]
            else:
                return False
            total += value * weights[i]

        check = total % 11
        check_char = 'X' if check == 10 else str(check)
        return vin[8].upper() == check_char
    except (ValueError, IndexError):
        return False


_SSN_FALSE_POSITIVE_PREFIXES = frozenset([
    'page', 'pg', 'room', 'rm', 'order', 'ref', 'reference', 'invoice',
    'confirmation', 'tracking', 'case', 'ticket', 'claim', 'check',
    'acct', 'record', 'file', 'document', 'doc',
    'no', 'num', '#', 'code', 'pin', 'serial', 'model',
    'part', 'item', 'sku', 'upc', 'isbn', 'version', 'ver',
    'batch', 'lot', 'catalog', 'product', 'unit', 'id',
    'make', 'type', 'series',
])

_SSN_FP_PATTERN = re.compile(
    r'\b(' + '|'.join(re.escape(w) for w in _SSN_FALSE_POSITIVE_PREFIXES) + r')\b',
    re.IGNORECASE
)


def validate_ssn_context(text: str, start: int, confidence: float) -> bool:
    """Check if a 9-digit number is likely NOT an SSN based on preceding context."""
    if confidence > 0.75:
        return True

    prefix_start = max(0, start - 30)
    prefix = text[prefix_start:start].lower()

    if _SSN_FP_PATTERN.search(prefix):
        return False

    immediate_prefix = prefix[-5:].strip() if len(prefix) >= 5 else prefix.strip()
    if immediate_prefix.endswith(('#', ':', '.', '-')):
        before_sep = prefix[:-1].strip()
        for fp_word in _SSN_FALSE_POSITIVE_PREFIXES:
            if before_sep.endswith(fp_word):
                return False

    return True
