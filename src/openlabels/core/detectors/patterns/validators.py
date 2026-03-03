"""Validation functions for pattern-detected entities.

Contains all _validate_* functions used for checksum verification, format
validation, and context-based false positive rejection. Also includes
helper data structures (frozensets, compiled regexes) used by validators.
"""

from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# International Government ID Validators (used inline in pattern definitions)
# ---------------------------------------------------------------------------


def _validate_ein(value: str) -> bool:
    """Validate US EIN campus code prefix (first 2 digits)."""
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 9:
        return False
    prefix = int(digits[:2])
    return (
        (1 <= prefix <= 6) or (10 <= prefix <= 16) or
        (20 <= prefix <= 27) or (30 <= prefix <= 38) or
        (40 <= prefix <= 48) or (50 <= prefix <= 59) or
        (60 <= prefix <= 68) or (71 <= prefix <= 77) or
        (80 <= prefix <= 88) or (90 <= prefix <= 93) or
        prefix in (98, 99)
    )


def _validate_uk_nino(value: str) -> bool:
    """Validate UK National Insurance Number prefix exclusions."""
    cleaned = value.upper().replace(' ', '')
    if len(cleaned) != 9:
        return False
    prefix = cleaned[:2]
    invalid_prefixes = {'BG', 'GB', 'NK', 'KN', 'NT', 'TN', 'ZZ'}
    return prefix not in invalid_prefixes


def _validate_es_nie(value: str) -> bool:
    """Validate Spanish NIE check letter (mod-23)."""
    letters = 'TRWAGMYFPDXBNJZSQVHLCKE'
    v = value.upper()
    if len(v) != 9:
        return False
    prefix_map = {'X': '0', 'Y': '1', 'Z': '2'}
    num_str = prefix_map.get(v[0], '') + v[1:8]
    try:
        return letters[int(num_str) % 23] == v[8]
    except (ValueError, IndexError):
        return False


def _validate_es_nif(value: str) -> bool:
    """Validate Spanish NIF check letter (mod-23)."""
    letters = 'TRWAGMYFPDXBNJZSQVHLCKE'
    v = value.upper()
    if len(v) != 9:
        return False
    try:
        return letters[int(v[:8]) % 23] == v[8]
    except (ValueError, IndexError):
        return False


def _validate_pl_pesel(value: str) -> bool:
    """Validate Polish PESEL using weighted checksum."""
    if len(value) != 11 or not value.isdigit():
        return False
    weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
    total = sum(int(d) * w for d, w in zip(value[:10], weights))
    check = (10 - (total % 10)) % 10
    return check == int(value[10])


def _validate_nhs(value: str) -> bool:
    """Validate UK NHS Number using mod-11 checksum."""
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 10:
        return False
    total = sum(int(d) * w for d, w in zip(digits[:9], range(10, 1, -1)))
    remainder = 11 - (total % 11)
    if remainder == 11:
        remainder = 0
    if remainder == 10:
        return False  # Invalid NHS number
    return remainder == int(digits[9])


# ---------------------------------------------------------------------------
# EU MULTILINGUAL VALIDATORS
# ---------------------------------------------------------------------------

def _validate_nl_bsn(value: str) -> bool:
    """Validate Dutch BSN (Burgerservicenummer) using 11-proof checksum.

    The BSN is 9 digits where:
    9*d1 + 8*d2 + 7*d3 + 6*d4 + 5*d5 + 4*d6 + 3*d7 + 2*d8 - 1*d9
    must be divisible by 11 and != 0.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 9:
        return False
    d = [int(c) for c in digits]
    total = 9*d[0] + 8*d[1] + 7*d[2] + 6*d[3] + 5*d[4] + 4*d[5] + 3*d[6] + 2*d[7] - 1*d[8]
    return total % 11 == 0 and total != 0


def _validate_fr_nir(value: str) -> bool:
    """Validate French NIR (Numero d'Inscription au Repertoire) / INSEE number.

    15 digits: sex(1) + birth_year(2) + birth_month(2) + dept(2-3) +
    commune(2-3) + order(3) + key(2).  Key = 97 - (number mod 97).
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 15:
        return False
    # Sex digit must be 1 or 2
    if digits[0] not in ('1', '2'):
        return False
    # Month 01-12 (or 20-42 for overseas/special)
    month = int(digits[3:5])
    if not (1 <= month <= 12 or 20 <= month <= 42):
        return False
    # Mod-97 key check
    number = int(digits[:13])
    key = int(digits[13:15])
    return 97 - (number % 97) == key


def _validate_de_steuer_id(value: str) -> bool:
    """Validate German Steuerliche Identifikationsnummer (Tax ID).

    11 digits: first digit != 0, exactly one digit appears twice,
    exactly one digit is missing from 0-9, last digit is a check digit.
    Uses modified ISO 7064 Mod 11,10 algorithm.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 11:
        return False
    if digits[0] == '0':
        return False
    # Check digit validation (ISO 7064 Mod 11,10)
    product = 10
    for i in range(10):
        s = (int(digits[i]) + product) % 10
        if s == 0:
            s = 10
        product = (s * 2) % 11
    check = (11 - product) % 10
    return check == int(digits[10])


def _validate_el_amka(value: str) -> bool:
    """Validate Greek AMKA (social security number).

    11 digits: DDMMYY + 5-digit serial.  Uses Luhn checksum.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 11:
        return False
    # Basic date validation (DDMMYY)
    day, month = int(digits[0:2]), int(digits[2:4])
    if not (1 <= day <= 31 and 1 <= month <= 12):
        return False
    # Luhn checksum
    total = 0
    for i, d in enumerate(digits):
        n = int(d)
        if i % 2 == 1:  # 0-indexed, so odd positions are doubled
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _validate_el_afm(value: str) -> bool:
    """Validate Greek AFM (tax identification number).

    9 digits with weighted checksum. Last digit is check digit.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 9:
        return False
    # Weights: 256, 128, 64, 32, 16, 8, 4, 2 for positions 0-7
    total = sum(int(digits[i]) * (1 << (8 - i)) for i in range(8))
    check = (total % 11) % 10
    return check == int(digits[8])


def _validate_br_cpf(value: str) -> bool:
    """Validate Brazilian CPF (Cadastro de Pessoa Fisica).

    11 digits with two check digits.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 11:
        return False
    # Reject known invalid sequences (all same digit)
    if digits == digits[0] * 11:
        return False
    # First check digit
    total = sum(int(digits[i]) * (10 - i) for i in range(9))
    remainder = (total * 10) % 11
    if remainder == 10:
        remainder = 0
    if remainder != int(digits[9]):
        return False
    # Second check digit
    total = sum(int(digits[i]) * (11 - i) for i in range(10))
    remainder = (total * 10) % 11
    if remainder == 10:
        remainder = 0
    return remainder == int(digits[10])


def _validate_br_cnpj(value: str) -> bool:
    """Validate Brazilian CNPJ (Cadastro Nacional da Pessoa Juridica).

    14 digits with two check digits.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 14:
        return False
    if digits == digits[0] * 14:
        return False
    # First check digit
    weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(int(digits[i]) * weights1[i] for i in range(12))
    remainder = total % 11
    check1 = 0 if remainder < 2 else 11 - remainder
    if check1 != int(digits[12]):
        return False
    # Second check digit
    weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(int(digits[i]) * weights2[i] for i in range(13))
    remainder = total % 11
    check2 = 0 if remainder < 2 else 11 - remainder
    return check2 == int(digits[13])


def _validate_pt_nif(value: str) -> bool:
    """Validate Portuguese NIF (Numero de Identificacao Fiscal).

    9 digits.  First digit indicates entity type (1-3: individual, 5: legal, etc.).
    Mod-11 checksum.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 9:
        return False
    # Valid first digits
    if digits[0] not in ('1', '2', '3', '5', '6', '7', '8', '9'):
        return False
    # Mod-11 checksum
    total = sum(int(digits[i]) * (9 - i) for i in range(8))
    remainder = total % 11
    check = 0 if remainder < 2 else 11 - remainder
    return check == int(digits[8])


def _validate_si_emso(value: str) -> bool:
    """Validate Slovenian EMSO (Enotna Maticna Stevilka Obcana).

    13 digits: DDMMYYY + RR + SSS + C (same as former Yugoslav JMBG).
    Uses mod-11 weighted checksum.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 13:
        return False
    # Basic date validation
    day, month = int(digits[0:2]), int(digits[2:4])
    if not (1 <= day <= 31 and 1 <= month <= 12):
        return False
    # Mod-11 checksum
    weights = [7, 6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
    total = sum(int(digits[i]) * weights[i] for i in range(12))
    remainder = total % 11
    if remainder == 0:
        check = 0
    elif remainder == 1:
        return False  # Invalid EMSO
    else:
        check = 11 - remainder
    return check == int(digits[12])


# ---------------------------------------------------------------------------
# General-purpose validators (used in PatternDetector.detect())
# ---------------------------------------------------------------------------

def _validate_ip(ip: str) -> bool:
    """Validate an IPv4 or IPv6 address."""
    if ':' in ip:
        # IPv6: 3-8 groups of 1-4 hex digits separated by colons
        parts = ip.split(':')
        if len(parts) < 3 or len(parts) > 8:
            return False
        non_empty = [p for p in parts if p]
        if not all(
            len(p) <= 4 and all(c in '0123456789abcdefABCDEF' for c in p)
            for p in non_empty
        ):
            return False
        # Reject MAC-like patterns: exactly 6 groups, each exactly 2 hex chars
        # MAC addresses use colon-separated pairs (00:1A:2B:3C:4D:5E) which
        # the compressed IPv6 regex incorrectly matches.
        if len(parts) == 6 and all(len(p) == 2 for p in parts):
            return False
        # Reject time-like patterns: 3 groups of pure digits (HH:MM:SS).
        # Real compressed IPv6 addresses have 4+ groups or contain hex a-f.
        if len(parts) == 3 and all(
            p.isdigit() and len(p) <= 2 for p in parts
        ):
            return False
        return True
    # IPv4: 4 octets 0-255
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# Regex for version-string context before an IPv4 address.
# Matches "version 1.2.3.4", "v1.2.3.4", "build 1.2.3.4" etc.
# Uses \b to avoid matching inside words like "Server".
_IP_VERSION_CONTEXT = re.compile(
    r'\b(?:version|ver|build|release)\s*[=:.]?\s*$|'
    r'\bv\d*\s*[=:.]?\s*$',
    re.I,
)


def _validate_url(url: str) -> bool:
    """Validate URL has a plausible domain with at least one dot or localhost."""
    url = url.rstrip('.,;:!?)]\'"')
    try:
        after_scheme = url.split('://', 1)[1]
        domain = after_scheme.split('/')[0].split(':')[0].split('@')[-1]
    except (IndexError, ValueError):
        return False
    if '.' not in domain and domain.lower() != 'localhost':
        return False
    if '..' in domain:
        return False
    return len(domain) >= 3


def _validate_mac(value: str) -> bool:
    """Validate MAC address — reject trivial and time-like patterns."""
    parts = re.split(r'[:-]', value)
    if len(parts) != 6:
        return False
    # Reject if all groups are identical (trivial)
    if len(set(parts)) == 1:
        return False
    # Reject if all groups are pure decimal <= 59 (looks like time)
    if all(p.isdigit() and int(p) <= 59 for p in parts):
        return False
    return True


# Invalid US area codes - these should not be detected as valid phone numbers
_INVALID_AREA_CODES = frozenset({
    '000',  # Invalid
    '555',  # Reserved for fictional use (555-0100 to 555-0199 are real directory assistance)
    '911',  # Emergency services
    '411',  # Directory assistance
    '611',  # Repair service
    '711',  # TDD relay
    '811',  # Utility locator
    '311',  # Non-emergency municipal
    '211',  # Community services
    '511',  # Traffic/road conditions
})


def _validate_phone(phone: str) -> bool:
    """
    Validate US phone number.

    Rejects:
    - Invalid area codes (000, 555, etc.)
    - All zeros (000-000-0000)
    - Sequential/repeated digits that are likely test data
    """
    # Extract digits only
    digits = ''.join(c for c in phone if c.isdigit())

    # Must have at least 10 digits for US number
    if len(digits) < 10:
        return True  # Can't validate, allow through

    # Get area code (first 3 digits for US)
    area_code = digits[:3]

    # Reject invalid area codes
    if area_code in _INVALID_AREA_CODES:
        return False

    # Reject all zeros
    if digits[:10] == '0000000000':
        return False

    # Reject sequential digits (1234567890)
    if digits[:10] == '1234567890':
        return False

    # Reject repeated digits (1111111111, 2222222222, etc.)
    if len(set(digits[:10])) == 1:
        return False

    return True


def _validate_date(month: int, day: int, year: int) -> bool:
    """
    Validate date is a real calendar date.

    Checks:
    - Month 1-12
    - Day appropriate for month (handles Feb 28/29, 30-day months)
    - Year in reasonable range (1900-2100)
    """
    # Basic year check
    if not (1900 <= year <= 2100):
        return False

    # Month check
    if not (1 <= month <= 12):
        return False

    # Days per month (non-leap year)
    days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

    # Check for leap year
    is_leap = (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
    if is_leap and month == 2:
        max_day = 29
    else:
        max_day = days_in_month[month]

    return 1 <= day <= max_day


def _validate_age(value: str) -> bool:
    """Validate age is reasonable (0-125)."""
    try:
        age = int(value)
        return 0 <= age <= 125
    except ValueError:
        # Non-numeric age value - invalid
        return False


def _validate_imei(value: str) -> bool:
    """Validate an IMEI number using the Luhn algorithm.

    IMEI is 15 digits with a Luhn check digit. Rejects trivial patterns.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 15:
        return False
    if len(set(digits)) == 1:
        return False
    return _validate_luhn(digits)


def _validate_sin(value: str) -> bool:
    """Validate a Canadian Social Insurance Number.

    Checks: 9 digits, first digit 1-9, not all same digit, Luhn checksum.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 9:
        return False
    if digits[0] == '0':
        return False
    if len(set(digits)) == 1:
        return False
    return _validate_luhn(digits)


def _validate_luhn(number: str) -> bool:
    """
    Validate a number using the Luhn algorithm.
    Used for credit cards and NPIs.
    """
    # Remove spaces and dashes
    digits = ''.join(c for c in number if c.isdigit())
    if not digits:
        return False

    total = 0
    for i, digit in enumerate(reversed(digits)):
        d = int(digit)
        if i % 2 == 1:  # Double every second digit from right
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _validate_vin(vin: str) -> bool:
    """
    Validate VIN check digit (position 9).
    """
    if len(vin) != 17:
        return False

    # Transliteration values
    trans = {
        'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
        'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
        'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
    }

    # Position weights
    weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]

    try:
        total = 0
        for i, char in enumerate(vin.upper()):
            if char.isdigit():
                value = int(char)
            elif char in trans:
                value = trans[char]
            else:
                return False  # Invalid character
            total += value * weights[i]

        check = total % 11
        check_char = 'X' if check == 10 else str(check)
        return vin[8].upper() == check_char
    except (ValueError, IndexError):
        # VIN too short or contains invalid characters
        return False


# Words that precede numbers but indicate non-SSN context
_SSN_FALSE_POSITIVE_PREFIXES = frozenset([
    'page', 'pg', 'room', 'rm', 'order', 'ref', 'reference', 'invoice',
    'confirmation', 'tracking', 'case', 'ticket', 'claim', 'check',
    'acct', 'account', 'record', 'file', 'document', 'doc',
    'no', 'num', '#', 'code', 'pin', 'serial', 'model',
    'part', 'item', 'sku', 'upc', 'isbn', 'version', 'ver',
    'batch', 'lot', 'catalog', 'product', 'unit', 'id',
    'make', 'type', 'series',
    # Financial context — digit sequences in financial text are rarely SSNs
    'routing', 'aba', 'rtn', 'balance', 'transaction', 'payment',
    'transfer', 'deposit', 'withdrawal', 'amount', 'total',
    'iban', 'swift', 'bic', 'bban',
])

# Regex to find these prefixes in a wider window
_SSN_FP_PATTERN = re.compile(
    r'\b(' + '|'.join(re.escape(w) for w in _SSN_FALSE_POSITIVE_PREFIXES) + r')\b',
    re.IGNORECASE
)


def _validate_ssn_context(text: str, start: int, confidence: float) -> bool:
    """
    Check if a 9-digit number is likely NOT an SSN based on preceding context.

    Only applies to LOW confidence (unlabeled) SSN matches.
    Returns True if it looks like a valid SSN context, False to reject.
    """
    # Only filter low-confidence bare 9-digit matches
    if confidence > 0.75:
        return True

    # Look at the 30 characters before the match (wider window)
    prefix_start = max(0, start - 30)
    prefix = text[prefix_start:start].lower()

    # Check if any false positive word appears in the prefix
    if _SSN_FP_PATTERN.search(prefix):
        return False

    # Also check immediate prefix for separators like "# " or ": "
    immediate_prefix = prefix[-5:].strip() if len(prefix) >= 5 else prefix.strip()
    if immediate_prefix.endswith(('#', ':', '.', '-')):
        before_sep = prefix[:-1].strip()
        for fp_word in _SSN_FALSE_POSITIVE_PREFIXES:
            if before_sep.endswith(fp_word):
                return False

    return True
