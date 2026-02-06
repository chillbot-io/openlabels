"""
Financial identifiers and cryptocurrency detector.

Detects financial security identifiers and cryptocurrency addresses,
with checksum validation where applicable.

Entity Types:
- CUSIP: Committee on Uniform Securities Identification (9 chars)
- ISIN: International Securities Identification Number (12 chars)
- SEDOL: Stock Exchange Daily Official List (7 chars, UK)
- SWIFT_BIC: Bank Identifier Code (8 or 11 chars)
- FIGI: Financial Instrument Global Identifier (12 chars)
- LEI: Legal Entity Identifier (20 chars)
- BITCOIN_ADDRESS: Bitcoin wallet addresses (all formats)
- ETHEREUM_ADDRESS: Ethereum wallet addresses (0x + 40 hex)
- CRYPTO_SEED_PHRASE: BIP-39 mnemonic seed phrases
- SOLANA_ADDRESS, CARDANO_ADDRESS, LITECOIN_ADDRESS, etc.
"""

import re
import hashlib
from typing import List, Tuple

from ..types import Span, Tier
from .base import BaseDetector
from .._rust.validators_py import (
    validate_cusip as _validate_cusip,
    validate_isin as _validate_isin,
)


def _validate_sedol(sedol: str) -> bool:
    """Validate SEDOL check digit (7 chars)."""
    sedol = sedol.upper().replace(' ', '')
    if len(sedol) != 7 or any(c in 'AEIOU' for c in sedol):
        return False

    weights = [1, 3, 1, 7, 3, 9, 1]

    def char_value(c: str) -> int:
        if c.isdigit():
            return int(c)
        elif c.isalpha():
            return ord(c) - ord('A') + 10
        return -1

    total = 0
    for i, c in enumerate(sedol[:6]):
        val = char_value(c)
        if val < 0:
            return False
        total += val * weights[i]

    check_digit = (10 - (total % 10)) % 10
    try:
        return int(sedol[6]) == check_digit
    except ValueError:
        # Check digit is not numeric - invalid SEDOL
        return False


def _validate_swift(swift: str) -> bool:
    """Validate SWIFT/BIC code format (8 or 11 chars)."""
    swift = swift.upper().replace(' ', '')
    if len(swift) not in (8, 11):
        return False

    # Common English words that match SWIFT format
    SWIFT_DENY_LIST = {
        "REFERRAL", "HOSPITAL", "TERMINAL", "NATIONAL", "REGIONAL", "MATERIAL",
        "PERSONAL", "OFFICIAL", "ORIGINAL", "CARDINAL", "APPROVAL", "TROPICAL",
        "INFORMATION", "APPLICATION", "DESCRIPTION",
    }

    if swift in SWIFT_DENY_LIST:
        return False

    if not swift[:4].isalpha() or not swift[4:6].isalpha():
        return False
    if not swift[6:8].isalnum():
        return False
    if len(swift) == 11 and not swift[8:11].isalnum():
        return False

    return True


def _validate_lei(lei: str) -> bool:
    """Validate LEI using ISO 7064 Mod 97-10 (20 chars)."""
    lei = lei.upper().replace(' ', '').replace('-', '')
    if len(lei) != 20 or not lei.isalnum():
        return False

    numeric = ''
    for c in lei:
        if c.isdigit():
            numeric += c
        else:
            numeric += str(ord(c) - ord('A') + 10)

    return int(numeric) % 97 == 1


def _validate_bitcoin_base58(address: str) -> bool:
    """Validate Bitcoin legacy/P2SH address."""
    if not address or len(address) < 25 or len(address) > 34:
        return False
    if address[0] not in ('1', '3'):
        return False

    base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if not all(c in base58_chars for c in address):
        return False

    try:
        n = 0
        for c in address:
            n = n * 58 + base58_chars.index(c)
        data = n.to_bytes(25, 'big')
        payload, checksum = data[:-4], data[-4:]
        hash1 = hashlib.sha256(payload).digest()
        hash2 = hashlib.sha256(hash1).digest()
        return hash2[:4] == checksum
    except (OverflowError, ValueError):
        # Invalid Base58 encoding or address too large
        return False


def _validate_bitcoin_bech32(address: str) -> bool:
    """Validate Bitcoin Bech32 address (SegWit)."""
    address = address.lower()
    if not address.startswith('bc1'):
        return False

    data_part = address[3:]
    charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

    if len(data_part) < 8:
        return False
    if not all(c in charset for c in data_part):
        return False

    witness_version = data_part[0]
    if witness_version not in ('q', 'p'):
        return False

    total_len = len(address)
    if witness_version == 'q' and total_len not in (42, 62):
        return False
    if witness_version == 'p' and total_len != 62:
        return False

    return True


def _validate_ethereum(address: str) -> bool:
    """Validate Ethereum address (0x + 40 hex)."""
    if not address.startswith(('0x', '0X')):
        return False
    hex_part = address[2:]
    if len(hex_part) != 40:
        return False
    try:
        int(hex_part, 16)
        return True
    except ValueError:
        # Contains non-hex characters - invalid Ethereum address
        return False


# BIP-39 sample words for seed phrase validation
BIP39_SAMPLE_WORDS = {
    'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb',
    'abstract', 'absurd', 'abuse', 'access', 'accident', 'account',
    'zebra', 'zero', 'zone', 'zoo',
}


def _validate_seed_phrase(text: str) -> bool:
    """Validate BIP-39 seed phrase structure."""
    words = text.lower().split()
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    common_bip39 = sum(1 for w in words if w in BIP39_SAMPLE_WORDS)
    return common_bip39 >= len(words) * 0.5


# =============================================================================
# PATTERNS
# =============================================================================

FINANCIAL_PATTERNS: List[Tuple[re.Pattern, str, float, int, callable]] = []


def _add(pattern: str, entity_type: str, confidence: float, group: int = 0,
         validator: callable = None, flags: int = 0):
    """Helper to add patterns with optional validator."""
    FINANCIAL_PATTERNS.append((
        re.compile(pattern, flags),
        entity_type,
        confidence,
        group,
        validator
    ))


# --- SECURITY IDENTIFIERS ---
_add(r'(?:CUSIP)[:\s#]+([A-Z0-9]{9})\b', 'CUSIP', 0.98, 1, _validate_cusip, re.I)
_add(r'\b([0-9]{3}[A-Z0-9]{5}[0-9])\b', 'CUSIP', 0.85, 1, _validate_cusip)

_add(r'(?:ISIN)[:\s#]+([A-Z]{2}[A-Z0-9]{10})\b', 'ISIN', 0.98, 1, _validate_isin, re.I)
_add(r'\b([A-Z]{2}[A-Z0-9]{9}[0-9])\b', 'ISIN', 0.85, 1, _validate_isin)

_add(r'(?:SEDOL)[:\s#]+([B-DF-HJ-NP-TV-Z0-9]{7})\b', 'SEDOL', 0.98, 1, _validate_sedol, re.I)
_add(r'\b([B-DF-HJ-NP-TV-Z0-9]{7})\b', 'SEDOL', 0.70, 1, _validate_sedol)

_add(r'(?:SWIFT|BIC)[:\s#]+([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b', 'SWIFT_BIC', 0.98, 1, _validate_swift, re.I)

_add(r'(?:LEI)[:\s#]+([A-Z0-9]{20})\b', 'LEI', 0.98, 1, _validate_lei, re.I)
_add(r'\b([A-Z0-9]{18}[0-9]{2})\b', 'LEI', 0.80, 1, _validate_lei)

_add(r'(?:FIGI)[:\s#]+([A-Z0-9]{12})\b', 'FIGI', 0.98, 1, None, re.I)
_add(r'\b(BBG[A-Z0-9]{9})\b', 'FIGI', 0.95, 1, None)

# --- CRYPTOCURRENCY ---
_add(r'\b(1[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25,34})\b',
     'BITCOIN_ADDRESS', 0.95, 1, _validate_bitcoin_base58)
_add(r'\b(3[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25,34})\b',
     'BITCOIN_ADDRESS', 0.95, 1, _validate_bitcoin_base58)
_add(r'\b(bc1q[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,})\b',
     'BITCOIN_ADDRESS', 0.98, 1, _validate_bitcoin_bech32, re.I)
_add(r'\b(bc1p[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58,})\b',
     'BITCOIN_ADDRESS', 0.98, 1, _validate_bitcoin_bech32, re.I)

_add(r'\b(0x[a-fA-F0-9]{40})\b', 'ETHEREUM_ADDRESS', 0.98, 1, _validate_ethereum)

_add(r'\b(addr1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{50,})\b', 'CARDANO_ADDRESS', 0.95, 1, None, re.I)

_add(r'\b([LM][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{26,34})\b',
     'LITECOIN_ADDRESS', 0.85, 1, None)
_add(r'\b(ltc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,})\b', 'LITECOIN_ADDRESS', 0.95, 1, None, re.I)

_add(r'\b(D[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{26,34})\b',
     'DOGECOIN_ADDRESS', 0.80, 1, None)

_add(r'\b(r[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{24,34})\b',
     'XRP_ADDRESS', 0.80, 1, None)

# --- SEED PHRASES ---
_add(r'(?:seed|mnemonic|recovery|backup)\s*(?:phrase|words?)?[:\s]+([a-z]+(?:\s+[a-z]+){11})\b',
     'CRYPTO_SEED_PHRASE', 0.95, 1, _validate_seed_phrase, re.I)
_add(r'(?:seed|mnemonic|recovery|backup)\s*(?:phrase|words?)?[:\s]+([a-z]+(?:\s+[a-z]+){23})\b',
     'CRYPTO_SEED_PHRASE', 0.95, 1, _validate_seed_phrase, re.I)


class FinancialDetector(BaseDetector):
    """
    Detects financial security identifiers and cryptocurrency addresses.

    Uses checksum validation where applicable for high confidence.
    """

    name = "financial"
    tier = Tier.CHECKSUM

    def detect(self, text: str) -> List[Span]:
        spans = []
        seen = set()

        for pattern, entity_type, confidence, group_idx, validator in FINANCIAL_PATTERNS:
            for match in pattern.finditer(text):
                if group_idx > 0 and match.lastindex and group_idx <= match.lastindex:
                    value = match.group(group_idx)
                    start = match.start(group_idx)
                    end = match.end(group_idx)
                else:
                    value = match.group(0)
                    start = match.start()
                    end = match.end()

                if not value or not value.strip():
                    continue

                key = (start, end)
                if key in seen:
                    continue

                if validator and not validator(value):
                    continue

                seen.add(key)

                final_confidence = confidence
                if validator:
                    final_confidence = min(0.99, confidence + 0.02)

                span = Span(
                    start=start,
                    end=end,
                    text=value,
                    entity_type=entity_type,
                    confidence=final_confidence,
                    detector=self.name,
                    tier=self.tier,
                )
                spans.append(span)

        return spans
