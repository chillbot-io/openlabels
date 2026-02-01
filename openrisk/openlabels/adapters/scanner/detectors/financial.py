"""Tier 3: Financial identifiers and cryptocurrency (CUSIP, ISIN, SWIFT, crypto addresses)."""

import hashlib
import logging
import re
import secrets
from functools import wraps
from typing import Callable, List, Optional, Tuple

from ..types import Span, Tier
from .base import BasePatternDetector
from .constants import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_LOWEST,
    CONFIDENCE_PERFECT,
    CONFIDENCE_VERY_HIGH,
    CONFIDENCE_WEAK,
)

logger = logging.getLogger(__name__)


def checksum_validator(
    name: str,
    length: Optional[int] = None,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    normalize: bool = True,
) -> Callable:
    """
    Decorator factory for checksum validators.

    Handles common boilerplate: normalization, length validation, debug logging.

    Args:
        name: Identifier name for logging (e.g., 'CUSIP', 'ISIN')
        length: Exact required length (mutually exclusive with min/max)
        min_length: Minimum length (use with max_length for ranges)
        max_length: Maximum length (use with min_length for ranges)
        normalize: If True, uppercase and remove spaces/hyphens
    """
    def decorator(func: Callable[[str], bool]) -> Callable[[str], bool]:
        @wraps(func)
        def wrapper(value: str) -> bool:
            if normalize:
                value = value.upper().replace(' ', '').replace('-', '')

            # Length validation
            if length is not None and len(value) != length:
                logger.debug(f"{name} validation failed: expected {length} chars, got {len(value)}")
                return False
            if min_length is not None and len(value) < min_length:
                logger.debug(f"{name} validation failed: min {min_length} chars, got {len(value)}")
                return False
            if max_length is not None and len(value) > max_length:
                logger.debug(f"{name} validation failed: max {max_length} chars, got {len(value)}")
                return False

            result = func(value)
            if not result:
                logger.debug(f"{name} validation failed: checksum mismatch")
            return result
        return wrapper
    return decorator


def _cusip_char_value(c: str) -> int:
    """Convert CUSIP character to numeric value."""
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
    return -1


def _alpha_to_numeric(s: str) -> Optional[str]:
    """Convert alphanumeric string to numeric (A=10, B=11, ..., Z=35)."""
    result = ''
    for c in s:
        if c.isdigit():
            result += c
        elif c.isalpha():
            result += str(ord(c) - ord('A') + 10)
        else:
            return None
    return result


@checksum_validator('CUSIP', length=9)
def _validate_cusip(cusip: str) -> bool:
    """Validate CUSIP check digit using modified Luhn algorithm."""
    total = 0
    for i, c in enumerate(cusip[:8]):
        val = _cusip_char_value(c)
        if val < 0:
            return False
        if i % 2 == 1:
            val *= 2
        total += val // 10 + val % 10

    check_digit = (10 - (total % 10)) % 10
    try:
        return int(cusip[8]) == check_digit
    except ValueError:
        return False


@checksum_validator('ISIN', length=12)
def _validate_isin(isin: str) -> bool:
    """Validate ISIN check digit using Luhn algorithm."""
    if not isin[:2].isalpha():
        return False

    numeric = _alpha_to_numeric(isin)
    if numeric is None:
        return False

    # Luhn algorithm
    total = 0
    for i, digit in enumerate(reversed(numeric)):
        d = int(digit)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d

    return total % 10 == 0


@checksum_validator('SEDOL', length=7)
def _validate_sedol(sedol: str) -> bool:
    """Validate SEDOL check digit using weighted sum."""
    if any(c in 'AEIOU' for c in sedol):
        return False

    weights = [1, 3, 1, 7, 3, 9, 1]

    total = 0
    for i, c in enumerate(sedol[:6]):
        if c.isdigit():
            val = int(c)
        elif c.isalpha():
            val = ord(c) - ord('A') + 10
        else:
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


@checksum_validator('LEI', length=20)
def _validate_lei(lei: str) -> bool:
    """Validate LEI using ISO 7064 Mod 97-10."""
    if not lei.isalnum():
        return False

    numeric = _alpha_to_numeric(lei)
    if numeric is None:
        return False

    return int(numeric) % 97 == 1


@checksum_validator('FIGI', length=12)
def _validate_figi(figi: str) -> bool:
    """Validate FIGI format (simplified - format check only)."""
    return figi.isalnum()


BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BECH32_CHARS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


@checksum_validator('Bitcoin', min_length=25, max_length=34, normalize=False)
def _validate_bitcoin_base58(address: str) -> bool:
    """Validate Bitcoin legacy/P2SH address using Base58Check with double SHA-256."""
    if address[0] not in ('1', '3'):
        return False

    if not all(c in BASE58_CHARS for c in address):
        return False

    try:
        n = 0
        for c in address:
            n = n * 58 + BASE58_CHARS.index(c)

        data = n.to_bytes(25, 'big')
        payload, checksum = data[:-4], data[-4:]

        hash1 = hashlib.sha256(payload).digest()
        hash2 = hashlib.sha256(hash1).digest()

        return secrets.compare_digest(hash2[:4], checksum)
    except (OverflowError, ValueError):
        return False


@checksum_validator('Bitcoin Bech32', min_length=42, max_length=62, normalize=False)
def _validate_bitcoin_bech32(address: str) -> bool:
    """Validate Bitcoin Bech32 address (SegWit/Taproot)."""
    address = address.lower()

    if not address.startswith('bc1'):
        return False

    data_part = address[3:]
    if not all(c in BECH32_CHARS for c in data_part):
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
    """Validate Ethereum address: 0x + 40 hex characters."""
    if not address.startswith(('0x', '0X')):
        return False

    hex_part = address[2:]
    
    if len(hex_part) != 40:
        return False
    
    try:
        int(hex_part, 16)
        return True
    except ValueError:
        return False


# BIP-39 word list loading
def _load_bip39_wordlist() -> frozenset:
    """
    Load the full BIP-39 English wordlist (2048 words).

    Falls back to a minimal sample if file not found.
    """
    from pathlib import Path

    wordlist_path = Path(__file__).parent.parent / "dictionaries" / "bip39_english.txt"

    try:
        if wordlist_path.exists():
            words = wordlist_path.read_text().strip().split('\n')
            logger.debug(f"Loaded {len(words)} BIP-39 words from {wordlist_path}")
            return frozenset(w.strip().lower() for w in words if w.strip())
    except (OSError, IOError) as e:
        logger.warning(f"Failed to load BIP-39 wordlist: {e}")

    # Fallback sample (first/last words for basic validation)
    logger.warning("Using fallback BIP-39 sample - seed phrase detection may be incomplete")
    return frozenset({
        'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
        'zebra', 'zero', 'zone', 'zoo',
    })

BIP39_WORDS = _load_bip39_wordlist()


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
    valid_words = sum(1 for w in words if w in BIP39_WORDS)

    return valid_words >= len(words) * 0.8  # Require 80% match with full list


# --- PATTERN DEFINITIONS ---
from .pattern_registry import create_pattern_adder

FINANCIAL_PATTERNS: List[Tuple[re.Pattern, str, float, int, callable]] = []
_add = create_pattern_adder(FINANCIAL_PATTERNS, support_validator=True)


# --- SECURITY IDENTIFIERS ---
# CUSIP: 9 alphanumeric (labeled)
_add(r'(?:CUSIP)[:\s#]+([A-Z0-9]{9})\b', 'CUSIP', CONFIDENCE_VERY_HIGH, 1, _validate_cusip, re.I)
# CUSIP: Bare format (requires validation)
_add(r'\b([0-9]{3}[A-Z0-9]{5}[0-9])\b', 'CUSIP', CONFIDENCE_LOW, 1, _validate_cusip)

# ISIN: 12 characters, starts with country code
_add(r'(?:ISIN)[:\s#]+([A-Z]{2}[A-Z0-9]{10})\b', 'ISIN', CONFIDENCE_VERY_HIGH, 1, _validate_isin, re.I)
_add(r'\b([A-Z]{2}[A-Z0-9]{9}[0-9])\b', 'ISIN', CONFIDENCE_LOW, 1, _validate_isin)

# SEDOL: 7 alphanumeric, no vowels
_add(r'(?:SEDOL)[:\s#]+([B-DF-HJ-NP-TV-Z0-9]{7})\b', 'SEDOL', CONFIDENCE_VERY_HIGH, 1, _validate_sedol, re.I)
_add(r'\b([B-DF-HJ-NP-TV-Z0-9]{7})\b', 'SEDOL', CONFIDENCE_LOWEST, 1, _validate_sedol)  # Lower confidence bare

# SWIFT/BIC: 8 or 11 characters
# Note: Standalone pattern disabled (0.40) - too many false positives on common words
# Use only with SWIFT/BIC prefix for reliable detection
_add(r'(?:SWIFT|BIC)[:\s#]+([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b', 'SWIFT_BIC', CONFIDENCE_VERY_HIGH, 1, _validate_swift, re.I)
_add(r'\b([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b', 'SWIFT_BIC', 0.40, 1, _validate_swift)

# LEI: 20 alphanumeric
_add(r'(?:LEI)[:\s#]+([A-Z0-9]{20})\b', 'LEI', CONFIDENCE_VERY_HIGH, 1, _validate_lei, re.I)
_add(r'\b([A-Z0-9]{18}[0-9]{2})\b', 'LEI', CONFIDENCE_WEAK, 1, _validate_lei)

# FIGI: 12 characters, starts with BBG
_add(r'(?:FIGI)[:\s#]+([A-Z0-9]{12})\b', 'FIGI', CONFIDENCE_VERY_HIGH, 1, _validate_figi, re.I)
_add(r'\b(BBG[A-Z0-9]{9})\b', 'FIGI', CONFIDENCE_HIGH, 1, _validate_figi)


# --- CRYPTOCURRENCY ---
# Bitcoin Legacy (P2PKH): starts with 1
_add(r'\b(1[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25,34})\b', 
     'BITCOIN_ADDRESS', CONFIDENCE_HIGH, 1, _validate_bitcoin_base58)

# Bitcoin P2SH: starts with 3
_add(r'\b(3[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25,34})\b', 
     'BITCOIN_ADDRESS', CONFIDENCE_HIGH, 1, _validate_bitcoin_base58)

# Bitcoin Bech32 (SegWit): starts with bc1q
_add(r'\b(bc1q[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,})\b', 
     'BITCOIN_ADDRESS', CONFIDENCE_VERY_HIGH, 1, _validate_bitcoin_bech32, re.I)

# Bitcoin Bech32m (Taproot): starts with bc1p
_add(r'\b(bc1p[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58,})\b', 
     'BITCOIN_ADDRESS', CONFIDENCE_VERY_HIGH, 1, _validate_bitcoin_bech32, re.I)

# Ethereum: 0x + 40 hex
_add(r'\b(0x[a-fA-F0-9]{40})\b', 'ETHEREUM_ADDRESS', CONFIDENCE_VERY_HIGH, 1, _validate_ethereum)

# Solana: Base58, 32-44 characters
_add(r'\b([1-9A-HJ-NP-Za-km-z]{32,44})\b(?=.*(?:solana|sol|phantom|wallet))', 
     'SOLANA_ADDRESS', CONFIDENCE_LOW, 1, None, re.I)

# Cardano: starts with addr1 or addr_test1
_add(r'\b(addr1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{50,})\b', 'CARDANO_ADDRESS', CONFIDENCE_HIGH, 1, None, re.I)

# Litecoin: starts with L, M, or ltc1
_add(r'\b([LM][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{26,34})\b', 
     'LITECOIN_ADDRESS', CONFIDENCE_LOW, 1, None)
_add(r'\b(ltc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,})\b', 'LITECOIN_ADDRESS', CONFIDENCE_HIGH, 1, None, re.I)

# Dogecoin: starts with D
_add(r'\b(D[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{26,34})\b', 
     'DOGECOIN_ADDRESS', CONFIDENCE_WEAK, 1, None)

# XRP/Ripple: starts with r
_add(r'\b(r[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{24,34})\b', 
     'XRP_ADDRESS', CONFIDENCE_WEAK, 1, None)


# --- SEED PHRASES ---
# 12-word seed phrase (contextual)
_add(r'(?:seed|mnemonic|recovery|backup)\s*(?:phrase|words?)?[:\s]+([a-z]+(?:\s+[a-z]+){11})\b', 
     'CRYPTO_SEED_PHRASE', CONFIDENCE_HIGH, 1, _validate_seed_phrase, re.I)

# 24-word seed phrase (contextual)
_add(r'(?:seed|mnemonic|recovery|backup)\s*(?:phrase|words?)?[:\s]+([a-z]+(?:\s+[a-z]+){23})\b', 
     'CRYPTO_SEED_PHRASE', CONFIDENCE_HIGH, 1, _validate_seed_phrase, re.I)


# --- CONTEXT KEYWORDS FOR CONFIDENCE BOOSTING ---
# Keywords that, when found near a match, indicate higher likelihood of true positive
CONTEXT_KEYWORDS = {
    'SWIFT_BIC': frozenset({'swift', 'bic', 'bank', 'transfer', 'wire', 'iban', 'routing', 'payment'}),
    'CUSIP': frozenset({'cusip', 'security', 'bond', 'stock', 'equity', 'ticker', 'sedol', 'isin'}),
    'ISIN': frozenset({'isin', 'security', 'stock', 'bond', 'equity', 'cusip', 'sedol', 'ticker'}),
    'SEDOL': frozenset({'sedol', 'london', 'lse', 'stock', 'security', 'uk', 'exchange'}),
    'LEI': frozenset({'lei', 'legal', 'entity', 'identifier', 'gleif', 'corporate'}),
    'LITECOIN_ADDRESS': frozenset({'litecoin', 'ltc', 'crypto', 'wallet', 'address', 'send', 'receive'}),
    'DOGECOIN_ADDRESS': frozenset({'dogecoin', 'doge', 'crypto', 'wallet', 'address', 'tip'}),
    'XRP_ADDRESS': frozenset({'xrp', 'ripple', 'crypto', 'wallet', 'address', 'ledger'}),
    'SOLANA_ADDRESS': frozenset({'solana', 'sol', 'phantom', 'crypto', 'wallet', 'address'}),
}

# How much to boost confidence when context keywords are found
CONTEXT_BOOST_AMOUNT = 0.25
CONTEXT_WINDOW_SIZE = 100  # Characters before/after match to search for context


# --- DETECTOR CLASS ---
class FinancialDetector(BasePatternDetector):
    """
    Detects financial security identifiers and cryptocurrency addresses.

    Uses checksum validation where applicable for high confidence.
    Applies context-aware confidence boosting for low-confidence patterns.
    """

    name = "financial"
    tier = Tier.CHECKSUM  # Uses validation like checksum.py

    def get_patterns(self):
        """Return financial patterns."""
        return FINANCIAL_PATTERNS

    def detect(self, text: str) -> List[Span]:
        """Detect financial identifiers in text with logging and context boosting."""
        spans = super().detect(text)

        # Apply context-aware confidence boosting for low-confidence patterns
        text_lower = text.lower()
        boosted_spans = []
        for span in spans:
            boosted_span = self._boost_confidence_by_context(span, text_lower)
            boosted_spans.append(boosted_span)
        spans = boosted_spans

        if spans:
            # Summarize by entity type
            type_counts = {}
            for span in spans:
                type_counts[span.entity_type] = type_counts.get(span.entity_type, 0) + 1
            logger.info(f"FinancialDetector found {len(spans)} entities: {type_counts}")

            # Log crypto addresses at DEBUG (high-value targets)
            crypto_types = ['BITCOIN_ADDRESS', 'ETHEREUM_ADDRESS', 'CRYPTO_SEED_PHRASE']
            for span in spans:
                if span.entity_type in crypto_types:
                    logger.debug(f"Cryptocurrency entity detected: {span.entity_type} at position {span.start}-{span.end}")

        return spans

    def _boost_confidence_by_context(self, span: Span, text_lower: str) -> Span:
        """
        Boost confidence if contextual keywords are found near the match.

        For low-confidence patterns (e.g., bare SWIFT codes at 0.40), finding
        relevant context keywords nearby increases our confidence that the
        match is a true positive.

        Args:
            span: The detected span
            text_lower: Lowercased full text for context search

        Returns:
            Span with potentially boosted confidence
        """
        # Only boost patterns that have context keywords defined
        context_keywords = CONTEXT_KEYWORDS.get(span.entity_type)
        if not context_keywords:
            return span

        # Only boost low-confidence matches (< 0.70)
        if span.confidence >= 0.70:
            return span

        # Extract context window around match
        start = max(0, span.start - CONTEXT_WINDOW_SIZE)
        end = min(len(text_lower), span.end + CONTEXT_WINDOW_SIZE)
        context = text_lower[start:end]

        # Check for context keywords
        for keyword in context_keywords:
            if keyword in context:
                new_confidence = min(1.0, span.confidence + CONTEXT_BOOST_AMOUNT)
                logger.debug(
                    f"Context boost for {span.entity_type}: '{keyword}' found nearby, "
                    f"confidence {span.confidence:.2f} -> {new_confidence:.2f}"
                )
                return Span(
                    start=span.start,
                    end=span.end,
                    text=span.text,
                    entity_type=span.entity_type,
                    confidence=new_confidence,
                    detector=span.detector,
                    tier=span.tier,
                )

        return span

    def _adjust_confidence(self, entity_type: str, confidence: float,
                           value: str, has_validator: bool) -> float:
        """Boost confidence if validator passed."""
        if has_validator:
            logger.debug(f"Boosting confidence for {entity_type}: validator passed")
            return min(CONFIDENCE_PERFECT, confidence + 0.02)
        return confidence
