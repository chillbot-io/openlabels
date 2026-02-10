"""
Python fallback pattern definitions.

These mirror the Rust patterns for use when the extension is not available.
"""

from __future__ import annotations

# Built-in patterns for sensitive data detection.
# Format: (name, regex_pattern, validator, base_confidence)
BUILTIN_PATTERNS: list[tuple[str, str, str | None, float]] = [
    # === FINANCIAL ===

    # Credit Card Numbers
    ("CREDIT_CARD_VISA", r"\b4[0-9]{12}(?:[0-9]{3})?\b", "luhn", 0.80),
    ("CREDIT_CARD_MASTERCARD", r"\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b", "luhn", 0.80),
    ("CREDIT_CARD_AMEX", r"\b3[47][0-9]{13}\b", "luhn", 0.80),
    ("CREDIT_CARD_DISCOVER", r"\b6(?:011|5[0-9]{2})[0-9]{12}\b", "luhn", 0.80),
    ("CREDIT_CARD_FORMATTED", r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "luhn", 0.75),

    # Bank Account Numbers
    ("IBAN", r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b", "iban", 0.85),
    ("US_BANK_ROUTING", r"\b(?:0[1-9]|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|80)[0-9]{7}\b", None, 0.60),

    # Securities
    ("CUSIP", r"\b[0-9A-Z]{9}\b", "cusip", 0.75),
    ("ISIN", r"\b[A-Z]{2}[A-Z0-9]{9}[0-9]\b", "isin", 0.80),
    ("SEDOL", r"\b[0-9BCDFGHJKLMNPQRSTVWXYZ]{7}\b", None, 0.65),

    # === PERSONAL IDENTIFIERS ===

    # Social Security Numbers
    ("SSN", r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b", "ssn", 0.85),

    # National Provider Identifier
    ("NPI", r"\b[12][0-9]{9}\b", "npi", 0.80),

    # DEA Number
    ("DEA_NUMBER", r"\b[ABCDEFGHJKLMNPRSTUVWXYabcdefghjklmnprstuvwxy][A-Za-z9][0-9]{7}\b", None, 0.75),

    # Driver's License
    ("DRIVERS_LICENSE_CA", r"\b[A-Z][0-9]{7}\b", None, 0.50),

    # Passport
    ("US_PASSPORT", r"\b[0-9]{9}\b", None, 0.40),

    # === CONTACT INFORMATION ===

    # Email
    ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "email", 0.90),

    # Phone Numbers
    ("PHONE_US", r"\b(?:\+1[-.\s]?)?\(?[2-9][0-9]{2}\)?[-.\s]?[2-9][0-9]{2}[-.\s]?[0-9]{4}\b", "phone", 0.75),
    ("PHONE_INTL", r"\b\+[1-9][0-9]{6,14}\b", "phone", 0.70),

    # === NETWORK/TECHNICAL ===

    # IP Addresses
    ("IPV4", r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", "ipv4", 0.85),
    ("IPV6", r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", None, 0.85),

    # MAC Address
    ("MAC_ADDRESS", r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", None, 0.80),

    # === SECRETS & CREDENTIALS ===

    # API Keys
    ("API_KEY_GENERIC", r"\b(?:api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?", None, 0.70),

    # AWS Keys
    ("AWS_ACCESS_KEY", r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b", None, 0.95),
    ("AWS_SECRET_KEY", r"\b[A-Za-z0-9/+=]{40}\b", None, 0.50),

    # GitHub Token
    ("GITHUB_TOKEN", r"\bgh[ps]_[A-Za-z0-9]{36}\b", None, 0.95),

    # Private Keys
    ("PRIVATE_KEY_RSA", r"-----BEGIN RSA PRIVATE KEY-----", None, 0.99),
    ("PRIVATE_KEY_GENERIC", r"-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----", None, 0.99),

    # JWT
    ("JWT", r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", None, 0.90),

    # Password in Config
    ("PASSWORD_ASSIGNMENT", r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?", None, 0.75),

    # === HEALTHCARE ===

    # Medical Record Number
    ("MRN", r"\b(?:MRN|mrn)[:\s#]*[0-9]{6,12}\b", None, 0.80),

    # ICD-10 Codes
    ("ICD10", r"\b[A-TV-Z][0-9][0-9AB](?:\.[0-9A-TV-Z]{1,4})?\b", None, 0.70),

    # === DATES ===

    # Date of Birth
    ("DATE_OF_BIRTH", r"(?i)(?:dob|date\s*of\s*birth|birth\s*date)[:\s]*\d{1,2}[-/]\d{1,2}[-/]\d{2,4}", None, 0.85),

    # === GOVERNMENT ===

    ("CLASSIFICATION_MARKING", r"(?i)\b(?:TOP\s*SECRET|SECRET|CONFIDENTIAL|UNCLASSIFIED|FOUO|NOFORN|ORCON|REL\s*TO)\b", None, 0.95),
]
