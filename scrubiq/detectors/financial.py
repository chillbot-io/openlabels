"""Tier 3: Financial identifiers and cryptocurrency detectors.

Detects financial security identifiers and cryptocurrency addresses,
with checksum validation where applicable.

Entity Types:
- CUSIP: Committee on Uniform Securities Identification Procedures (9 chars)
- ISIN: International Securities Identification Number (12 chars)
- SEDOL: Stock Exchange Daily Official List (7 chars, UK)
- SWIFT_BIC: Bank Identifier Code (8 or 11 chars)
- FIGI: Financial Instrument Global Identifier (12 chars)
- LEI: Legal Entity Identifier (20 chars)
- BITCOIN_ADDRESS: Bitcoin wallet addresses (all formats)
- ETHEREUM_ADDRESS: Ethereum wallet addresses (0x + 40 hex)
- CRYPTO_SEED_PHRASE: BIP-39 mnemonic seed phrases (12/24 words)
- SOLANA_ADDRESS: Solana wallet addresses (base58, 32-44 chars)
- CARDANO_ADDRESS: Cardano wallet addresses (addr1...)
"""

import re
import hashlib
from typing import List, Tuple, Optional

from ..types import Span, Tier
from .base import BaseDetector


# --- CHECKSUM VALIDATORS ---
def _validate_cusip(cusip: str) -> bool:
    """
    Validate CUSIP check digit (position 9).
    
    CUSIP: 9 characters
    - Positions 1-6: Issuer (alphanumeric)
    - Positions 7-8: Issue (alphanumeric)
    - Position 9: Check digit
    
    Algorithm: Modified Luhn (different from credit card Luhn)
    """
    cusip = cusip.upper().replace(' ', '').replace('-', '')
    
    if len(cusip) != 9:
        return False
    
    # Convert characters to values
    # Digits: face value
    # Letters: A=10, B=11, ..., Z=35
    # Special: *=36, @=37, #=38
    def char_value(c: str) -> int:
        if c.isdigit():
            return int(c)
        elif c.isalpha():
            return ord(c) - ord('A') + 10
        elif c == '*':
            return 36
        elif c == '@':
            return 37
        elif c == '#':
            return 38
        else:
            return -1
    
    total = 0
    for i, c in enumerate(cusip[:8]):  # First 8 characters
        val = char_value(c)
        if val < 0:
            return False
        
        # Double every second digit (0-indexed: positions 1, 3, 5, 7)
        if i % 2 == 1:
            val *= 2
        
        # Sum the digits
        total += val // 10 + val % 10
    
    check_digit = (10 - (total % 10)) % 10
    
    try:
        return int(cusip[8]) == check_digit
    except ValueError:
        return False


def _validate_isin(isin: str) -> bool:
    """
    Validate ISIN check digit using Luhn algorithm.
    
    ISIN: 12 characters
    - Positions 1-2: Country code (letters)
    - Positions 3-11: National security identifier (alphanumeric)
    - Position 12: Check digit
    """
    isin = isin.upper().replace(' ', '').replace('-', '')
    
    if len(isin) != 12:
        return False
    
    # First two must be letters (country code)
    if not isin[:2].isalpha():
        return False
    
    # Convert to numeric string: A=10, B=11, ..., Z=35
    numeric = ''
    for c in isin:
        if c.isdigit():
            numeric += c
        elif c.isalpha():
            numeric += str(ord(c) - ord('A') + 10)
        else:
            return False
    
    # Apply Luhn algorithm
    total = 0
    for i, digit in enumerate(reversed(numeric)):
        d = int(digit)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    
    return total % 10 == 0


def _validate_sedol(sedol: str) -> bool:
    """
    Validate SEDOL check digit.
    
    SEDOL: 7 characters (alphanumeric, no vowels)
    Weights: 1, 3, 1, 7, 3, 9, 1
    """
    sedol = sedol.upper().replace(' ', '')
    
    if len(sedol) != 7:
        return False
    
    # SEDOL cannot contain vowels
    if any(c in 'AEIOU' for c in sedol):
        return False
    
    weights = [1, 3, 1, 7, 3, 9, 1]
    
    def char_value(c: str) -> int:
        if c.isdigit():
            return int(c)
        elif c.isalpha():
            return ord(c) - ord('A') + 10
        return -1
    
    total = 0
    for i, c in enumerate(sedol[:6]):  # First 6 characters
        val = char_value(c)
        if val < 0:
            return False
        total += val * weights[i]
    
    check_digit = (10 - (total % 10)) % 10
    
    try:
        return int(sedol[6]) == check_digit
    except ValueError:
        return False


def _validate_swift(swift: str) -> bool:
    """
    Validate SWIFT/BIC code format.

    SWIFT: 8 or 11 characters
    - Positions 1-4: Bank code (letters)
    - Positions 5-6: Country code (letters)
    - Positions 7-8: Location code (alphanumeric)
    - Positions 9-11: Branch code (alphanumeric, optional)
    """
    swift = swift.upper().replace(' ', '')

    if len(swift) not in (8, 11):
        return False

    # Reject common English words that happen to match SWIFT format
    # These are 8 or 11 letter words that pass the letter/alphanumeric checks
    SWIFT_DENY_LIST = {
        # 8-letter words
        "REFERRAL", "HOSPITAL", "TERMINAL", "NATIONAL", "REGIONAL", "MATERIAL",
        "PERSONAL", "OFFICIAL", "ORIGINAL", "CARDINAL", "APPROVAL", "TROPICAL",
        "COLONIAL", "CULTURAL", "SURGICAL", "CLINICAL", "PHYSICAL", "CHEMICAL",
        "CRITICAL", "BIBLICAL", "VERTICAL", "ABNORMAL", "INFORMAL", "INTERNAL",
        "EXTERNAL", "MATERNAL", "PATERNAL", "MEDIEVAL", "CRIMINAL", "MARGINAL",
        "COMMUNAL", "MEMORIAL", "CEREBRAL", "DOCTORAL", "PASTORAL", "SEASONAL",
        "IMPERIAL", "ARTERIAL", "TUTORIAL", "HABITUAL", "EVENTUAL", "RESIDUAL",
        "SKELETAL", "SOCIETAL", "PARENTAL", "PRENATAL", "POSTNATAL", "NEONATAL",
        "CORPORAL", "TEMPORAL", "SPECTRAL", "DISPOSAL", "PROPOSAL", "REVERSAL",
        "REHEARSAL", "DISMISSAL", "APPRAISAL", "CONFORMAL", "EMOTIONAL",
        "INSURANCE", "STATEMENT", "TREATMENT", "EQUIPMENT", "PROCEDURE",
        "DIAGNOSIS", "PROGNOSIS", "EMERGENCY", "ADMISSION", "DISCHARGE",
        "BILATERAL", "UNILATERAL", "PROGRESS", "PROVIDER", "PROBLEMS", "PROTOCOL",
        "OUTCOMES", "OBSERVED", "OBTAINED", "ORIENTED", "BASELINE", "COMPLETE",
        "ANALYSIS", "RESPONSE", "SYMPTOMS", "FINDINGS", "VERIFIED", "SERVICES",
        # 10/11-letter words (including healthcare terms)
        "MEDICATIONS", "ASSESSMENT", "ALLERGIES", "LABORATORY", "OUTPATIENT",
        # 11-letter words
        "INFORMATION", "APPLICATION", "DESCRIPTION", "INSTRUCTION", "OBSERVATION",
        "EXAMINATION", "EXPLANATION", "PREPARATION", "COMBINATION", "CELEBRATION",
        "DESTINATION", "IMAGINATION", "EDUCATIONAL", "OPERATIONAL", "TRADITIONAL",
        "PROMOTIONAL", "CONDITIONAL", "EXCEPTIONAL", "RESIDENTIAL", "PROVISIONAL",
        "CONFIDENTIAL", "SUBSTANTIAL", "INFLUENTIAL", "TERRITORIAL", "MINISTERIAL",
        "FUNDAMENTAL", "CONTINENTAL", "SENTIMENTAL", "DEPARTMENTAL", "DETRIMENTAL",
        "MONUMENTAL", "ACCIDENTAL", "INCREMENTAL", "DEVELOPMENTAL", "SUPPLEMENTAL",
        # US Cities/States that appear on IDs (8-11 letters)
        "TALLAHASSEE", "JACKSONVILLE", "SACRAMENTO", "SPRINGFIELD", "INDIANAPOLIS",
        "MINNEAPOLIS", "PHILADELPHIA", "ALBUQUERQUE", "CHARLESTON", "BIRMINGHAM",
        "PITTSBURGH", "SCOTTSDALE", "PROVIDENCE", "CLEVELAND", "MILWAUKEE",
        "NASHVILLE", "ANNAPOLIS", "BATON ROUGE", "LOUISIANA", "TENNESSEE",
        "CALIFORNIA", "WASHINGTON", "PENNSYLVANIA", "CONNECTICUT", "MASSACHUSETTS",
        # Common ID document terms
        "MOTORCYCLE", "SAFEDRIVER", "COMMERCIAL", "PASSENGER", "DUPLICATE",
        "RESTRICTED", "ENDORSEMENT", "EXPIRATION", "OPERATION",
        # Common words that match SWIFT pattern (8-11 alphanumeric)
        "REPLACED", "REQUIRED", "SOBRIETY", "SUNSHINE", "SINSHINE",
        "CENSTITUTES", "CONSTITUTES", "MOTORONLY", "CONSENTS",
        "BIRTHDAY", "RECEIVED", "TRANSFER", "CUSTOMER", "EMPLOYER",
        "EMPLOYEE", "GUARDIAN", "OPERATOR", "SPECIMEN", "STANDARD",
        "INCLUDES", "EXCLUDES", "APPROVED", "ENDORSED", "LICENSED",
    }

    if swift in SWIFT_DENY_LIST:
        return False

    # Bank code: 4 letters
    if not swift[:4].isalpha():
        return False

    # Country code: 2 letters (valid ISO 3166-1)
    if not swift[4:6].isalpha():
        return False

    # Location code: 2 alphanumeric
    if not swift[6:8].isalnum():
        return False

    # Branch code (if present): 3 alphanumeric
    if len(swift) == 11:
        if not swift[8:11].isalnum():
            return False

    return True


def _validate_lei(lei: str) -> bool:
    """
    Validate LEI (Legal Entity Identifier) using ISO 7064 Mod 97-10.
    
    LEI: 20 characters
    - Positions 1-4: LOU prefix
    - Positions 5-6: Reserved (00)
    - Positions 7-18: Entity-specific
    - Positions 19-20: Check digits
    """
    lei = lei.upper().replace(' ', '').replace('-', '')
    
    if len(lei) != 20:
        return False
    
    if not lei.isalnum():
        return False
    
    # Convert to numeric (A=10, B=11, ...)
    numeric = ''
    for c in lei:
        if c.isdigit():
            numeric += c
        else:
            numeric += str(ord(c) - ord('A') + 10)
    
    # ISO 7064 Mod 97-10 check
    return int(numeric) % 97 == 1


def _validate_figi(figi: str) -> bool:
    """
    Validate FIGI (Financial Instrument Global Identifier).
    
    FIGI: 12 characters
    - Starts with BBG (Bloomberg) or other provider prefix
    - Check digit at position 12
    """
    figi = figi.upper().replace(' ', '')
    
    if len(figi) != 12:
        return False
    
    if not figi.isalnum():
        return False
    
    # Common prefixes
    valid_prefixes = ['BBG', 'GGG']  # Bloomberg, others
    if not any(figi.startswith(p) for p in valid_prefixes):
        # Allow other prefixes but lower confidence handled elsewhere
        pass
    
    # Basic check digit (Luhn-like for alphanumeric)
    # FIGI uses a modified algorithm, simplified validation here
    return True  # Format check only


def _validate_bitcoin_base58(address: str) -> bool:
    """
    Validate Bitcoin legacy/P2SH address (Base58Check).
    
    Legacy (P2PKH): Starts with 1, 25-34 chars
    P2SH: Starts with 3, 25-34 chars
    """
    if not address or len(address) < 25 or len(address) > 34:
        return False
    
    if address[0] not in ('1', '3'):
        return False
    
    # Base58 alphabet (no 0, O, I, l)
    base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    
    if not all(c in base58_chars for c in address):
        return False
    
    # Full Base58Check validation with double SHA-256
    try:
        # Decode Base58
        n = 0
        for c in address:
            n = n * 58 + base58_chars.index(c)

        # Convert to bytes (25 bytes for Bitcoin addresses)
        data = n.to_bytes(25, 'big')

        # Last 4 bytes are checksum
        payload, checksum = data[:-4], data[-4:]

        # Verify checksum (double SHA-256)
        hash1 = hashlib.sha256(payload).digest()
        hash2 = hashlib.sha256(hash1).digest()

        return hash2[:4] == checksum
    except (OverflowError, ValueError):
        return False


def _validate_bitcoin_bech32(address: str) -> bool:
    """
    Validate Bitcoin Bech32 address (SegWit).

    Format: bc1 + witness version + data + checksum
    - Native SegWit (P2WPKH): bc1q + 38 chars (witness v0)
    - Taproot (P2TR): bc1p + 58 chars (witness v1)

    The '1' in 'bc1' is the Bech32 separator between HRP and data.
    """
    address = address.lower()

    # Must start with bc1 (mainnet) - the '1' is the separator
    if not address.startswith('bc1'):
        return False

    # Data part is everything after 'bc1'
    data_part = address[3:]

    # Bech32 charset (excludes 1, b, i, o to avoid confusion)
    charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

    # Check minimum length (version + program + 6-char checksum)
    if len(data_part) < 8:
        return False

    # Check all characters are valid Bech32
    if not all(c in charset for c in data_part):
        return False

    # Check witness version (first char): q=0, p=1
    witness_version = data_part[0]
    if witness_version not in ('q', 'p'):
        return False

    # Validate length based on witness version
    # v0 (q): 42 chars total (bc1q + 38) for P2WPKH, or 62 for P2WSH
    # v1 (p): 62 chars total (bc1p + 58) for Taproot
    total_len = len(address)
    if witness_version == 'q' and total_len not in (42, 62):
        return False
    if witness_version == 'p' and total_len != 62:
        return False

    return True


def _validate_ethereum(address: str) -> bool:
    """
    Validate Ethereum address format.
    
    Format: 0x + 40 hexadecimal characters
    """
    if not address.startswith('0x') and not address.startswith('0X'):
        return False
    
    hex_part = address[2:]
    
    if len(hex_part) != 40:
        return False
    
    try:
        int(hex_part, 16)
        return True
    except ValueError:
        return False


# BIP-39 word list (first 100 for validation - full list would be 2048 words)
# In production, load full list from file
BIP39_SAMPLE_WORDS = {
    'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
    'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
    'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
    'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
    'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent',
    'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album',
    'alcohol', 'alert', 'alien', 'all', 'alley', 'allow', 'almost', 'alone',
    'alpha', 'already', 'also', 'alter', 'always', 'amateur', 'amazing', 'among',
    'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry',
    'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna', 'antique',
    'anxiety', 'any', 'apart', 'apology', 'appear', 'apple', 'approve', 'april',
    'zebra', 'zero', 'zone', 'zoo',  # Include some end words
}


def _validate_seed_phrase(text: str) -> bool:
    """
    Validate BIP-39 seed phrase structure.
    
    Must be 12, 15, 18, 21, or 24 words.
    Words should be from BIP-39 word list.
    """
    words = text.lower().split()
    
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    
    # Check at least 80% of words are in BIP-39 list
    # (Using sample list - in production use full 2048 word list)
    common_bip39 = sum(1 for w in words if w in BIP39_SAMPLE_WORDS)
    
    return common_bip39 >= len(words) * 0.5  # Relaxed for sample list


# --- PATTERN DEFINITIONS ---
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
# CUSIP: 9 alphanumeric (labeled)
_add(r'(?:CUSIP)[:\s#]+([A-Z0-9]{9})\b', 'CUSIP', 0.98, 1, _validate_cusip, re.I)
# CUSIP: Bare format (requires validation)
_add(r'\b([0-9]{3}[A-Z0-9]{5}[0-9])\b', 'CUSIP', 0.85, 1, _validate_cusip)

# ISIN: 12 characters, starts with country code
_add(r'(?:ISIN)[:\s#]+([A-Z]{2}[A-Z0-9]{10})\b', 'ISIN', 0.98, 1, _validate_isin, re.I)
_add(r'\b([A-Z]{2}[A-Z0-9]{9}[0-9])\b', 'ISIN', 0.85, 1, _validate_isin)

# SEDOL: 7 alphanumeric, no vowels
_add(r'(?:SEDOL)[:\s#]+([B-DF-HJ-NP-TV-Z0-9]{7})\b', 'SEDOL', 0.98, 1, _validate_sedol, re.I)
_add(r'\b([B-DF-HJ-NP-TV-Z0-9]{7})\b', 'SEDOL', 0.70, 1, _validate_sedol)  # Lower confidence bare

# SWIFT/BIC: 8 or 11 characters
# Note: Standalone pattern disabled (0.40) - too many false positives on common words
# Use only with SWIFT/BIC prefix for reliable detection
_add(r'(?:SWIFT|BIC)[:\s#]+([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b', 'SWIFT_BIC', 0.98, 1, _validate_swift, re.I)
_add(r'\b([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b', 'SWIFT_BIC', 0.40, 1, _validate_swift)

# LEI: 20 alphanumeric
_add(r'(?:LEI)[:\s#]+([A-Z0-9]{20})\b', 'LEI', 0.98, 1, _validate_lei, re.I)
_add(r'\b([A-Z0-9]{18}[0-9]{2})\b', 'LEI', 0.80, 1, _validate_lei)

# FIGI: 12 characters, starts with BBG
_add(r'(?:FIGI)[:\s#]+([A-Z0-9]{12})\b', 'FIGI', 0.98, 1, _validate_figi, re.I)
_add(r'\b(BBG[A-Z0-9]{9})\b', 'FIGI', 0.95, 1, _validate_figi)


# --- CRYPTOCURRENCY ---
# Bitcoin Legacy (P2PKH): starts with 1
_add(r'\b(1[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25,34})\b', 
     'BITCOIN_ADDRESS', 0.95, 1, _validate_bitcoin_base58)

# Bitcoin P2SH: starts with 3
_add(r'\b(3[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25,34})\b', 
     'BITCOIN_ADDRESS', 0.95, 1, _validate_bitcoin_base58)

# Bitcoin Bech32 (SegWit): starts with bc1q
_add(r'\b(bc1q[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,})\b', 
     'BITCOIN_ADDRESS', 0.98, 1, _validate_bitcoin_bech32, re.I)

# Bitcoin Bech32m (Taproot): starts with bc1p
_add(r'\b(bc1p[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58,})\b', 
     'BITCOIN_ADDRESS', 0.98, 1, _validate_bitcoin_bech32, re.I)

# Ethereum: 0x + 40 hex
_add(r'\b(0x[a-fA-F0-9]{40})\b', 'ETHEREUM_ADDRESS', 0.98, 1, _validate_ethereum)

# Solana: Base58, 32-44 characters
_add(r'\b([1-9A-HJ-NP-Za-km-z]{32,44})\b(?=.*(?:solana|sol|phantom|wallet))', 
     'SOLANA_ADDRESS', 0.85, 1, None, re.I)

# Cardano: starts with addr1 or addr_test1
_add(r'\b(addr1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{50,})\b', 'CARDANO_ADDRESS', 0.95, 1, None, re.I)

# Litecoin: starts with L, M, or ltc1
_add(r'\b([LM][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{26,34})\b', 
     'LITECOIN_ADDRESS', 0.85, 1, None)
_add(r'\b(ltc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,})\b', 'LITECOIN_ADDRESS', 0.95, 1, None, re.I)

# Dogecoin: starts with D
_add(r'\b(D[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{26,34})\b', 
     'DOGECOIN_ADDRESS', 0.80, 1, None)

# XRP/Ripple: starts with r
_add(r'\b(r[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{24,34})\b', 
     'XRP_ADDRESS', 0.80, 1, None)


# --- SEED PHRASES ---
# 12-word seed phrase (contextual)
_add(r'(?:seed|mnemonic|recovery|backup)\s*(?:phrase|words?)?[:\s]+([a-z]+(?:\s+[a-z]+){11})\b', 
     'CRYPTO_SEED_PHRASE', 0.95, 1, _validate_seed_phrase, re.I)

# 24-word seed phrase (contextual)
_add(r'(?:seed|mnemonic|recovery|backup)\s*(?:phrase|words?)?[:\s]+([a-z]+(?:\s+[a-z]+){23})\b', 
     'CRYPTO_SEED_PHRASE', 0.95, 1, _validate_seed_phrase, re.I)


# --- DETECTOR CLASS ---
class FinancialDetector(BaseDetector):
    """
    Detects financial security identifiers and cryptocurrency addresses.
    
    Uses checksum validation where applicable for high confidence.
    """
    
    name = "financial"
    tier = Tier.CHECKSUM  # Uses validation like checksum.py
    
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
                
                # Dedupe
                key = (start, end)
                if key in seen:
                    continue
                
                # Run validator if present
                if validator:
                    if not validator(value):
                        continue
                
                seen.add(key)
                
                # Boost confidence if validator passed
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
