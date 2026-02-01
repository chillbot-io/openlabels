"""
Python fallback validators for pattern matching.

These are used when the Rust extension is not available.
"""


def validate(text: str, validator: str) -> tuple[bool, float]:
    """
    Run a validator and return (is_valid, confidence_boost).

    Args:
        text: Text to validate
        validator: Validator name

    Returns:
        Tuple of (is_valid, confidence_boost)
    """
    validators = {
        "luhn": (validate_luhn, 0.15),
        "ssn": (validate_ssn, 0.10),
        "phone": (validate_phone, 0.05),
        "email": (validate_email, 0.05),
        "ipv4": (validate_ipv4, 0.05),
        "iban": (validate_iban, 0.15),
        "npi": (validate_npi, 0.15),
        "cusip": (validate_cusip, 0.15),
        "isin": (validate_isin, 0.15),
    }

    if validator in validators:
        func, boost = validators[validator]
        if func(text):
            return (True, boost)
        return (False, 0.0)

    # Unknown validator - pass through
    return (True, 0.0)


def validate_luhn(text: str) -> bool:
    """Validate a number using the Luhn algorithm."""
    digits = [int(c) for c in text if c.isdigit()]
    if len(digits) < 2:
        return False

    total = 0
    double = False

    for digit in reversed(digits):
        if double:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
        double = not double

    return total % 10 == 0


def validate_ssn(text: str) -> bool:
    """Validate a US Social Security Number."""
    digits = "".join(c for c in text if c.isdigit())
    if len(digits) != 9:
        return False

    area = int(digits[0:3])
    group = int(digits[3:5])
    serial = int(digits[5:9])

    # Invalid area numbers
    if area == 0 or area == 666 or 900 <= area <= 999:
        return False

    # Group and serial must be non-zero
    if group == 0 or serial == 0:
        return False

    return True


def validate_phone(text: str) -> bool:
    """Validate a phone number has reasonable digit count."""
    digits = [c for c in text if c.isdigit()]
    return 10 <= len(digits) <= 15


def validate_email(text: str) -> bool:
    """Validate an email address format."""
    parts = text.split("@")
    if len(parts) != 2:
        return False

    local, domain = parts
    return (
        len(local) > 0
        and len(domain) > 0
        and "." in domain
        and not domain.startswith(".")
        and not domain.endswith(".")
    )


def validate_ipv4(text: str) -> bool:
    """Validate an IPv4 address."""
    parts = text.split(".")
    if len(parts) != 4:
        return False

    for part in parts:
        try:
            n = int(part)
            if not 0 <= n <= 255:
                return False
        except ValueError:
            return False

    return True


def validate_iban(text: str) -> bool:
    """Validate an IBAN using mod-97 checksum."""
    cleaned = "".join(c for c in text if c.isalnum()).upper()

    if not 15 <= len(cleaned) <= 34:
        return False

    # Move first 4 chars to end
    rearranged = cleaned[4:] + cleaned[:4]

    # Convert letters to numbers (A=10, B=11, etc.)
    numeric = ""
    for c in rearranged:
        if c.isdigit():
            numeric += c
        else:
            numeric += str(ord(c) - ord("A") + 10)

    # Mod 97 check
    return int(numeric) % 97 == 1


def validate_npi(text: str) -> bool:
    """Validate a US National Provider Identifier."""
    digits = [int(c) for c in text if c.isdigit()]
    if len(digits) != 10:
        return False

    # NPI uses Luhn with prefix 80840
    prefixed = [8, 0, 8, 4, 0] + digits

    total = 0
    double = False

    for digit in reversed(prefixed):
        if double:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
        double = not double

    return total % 10 == 0


def validate_cusip(text: str) -> bool:
    """Validate a CUSIP."""
    cleaned = "".join(c for c in text if c.isalnum()).upper()
    if len(cleaned) != 9:
        return False

    total = 0
    for i, c in enumerate(cleaned[:8]):
        if c.isdigit():
            val = int(c)
        else:
            val = ord(c) - ord("A") + 10

        if i % 2 == 1:
            val *= 2

        total += val // 10 + val % 10

    check_digit = (10 - (total % 10)) % 10
    try:
        return int(cleaned[8]) == check_digit
    except ValueError:
        return False


def validate_isin(text: str) -> bool:
    """Validate an ISIN."""
    cleaned = "".join(c for c in text if c.isalnum()).upper()
    if len(cleaned) != 12:
        return False

    # First two characters must be letters
    if not cleaned[0].isalpha() or not cleaned[1].isalpha():
        return False

    # Convert to digits
    numeric = ""
    for c in cleaned:
        if c.isdigit():
            numeric += c
        else:
            numeric += str(ord(c) - ord("A") + 10)

    # Luhn check
    digits = [int(c) for c in numeric]
    total = 0
    double = False

    for digit in reversed(digits):
        if double:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
        double = not double

    return total % 10 == 0
