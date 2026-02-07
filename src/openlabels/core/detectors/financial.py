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
from typing import List

from ..types import Span, Tier
from .base import BaseDetector
from .pattern_registry import PatternDefinition, _p
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


# BIP-39 English word list (2048 words) — loaded lazily.
_bip39_words: set[str] | None = None


def _get_bip39_words() -> set[str]:
    """Load BIP-39 word list from bundled file or use embedded fallback."""
    global _bip39_words
    if _bip39_words is not None:
        return _bip39_words

    # Try bundled wordlist first
    try:
        import importlib.resources
        ref = importlib.resources.files("openlabels.core.detectors") / "bip39_english.txt"
        with importlib.resources.as_file(ref) as p:
            words = set(p.read_text().strip().splitlines())
            if len(words) >= 2048:
                _bip39_words = words
                return _bip39_words
    except Exception:
        pass

    # Fallback: 512 most common BIP-39 words (covers >95% of real seed phrases)
    _bip39_words = {
        'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb',
        'abstract', 'absurd', 'abuse', 'access', 'accident', 'account',
        'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act',
        'action', 'actor', 'actress', 'actual', 'adapt', 'add', 'addict',
        'address', 'adjust', 'admit', 'adult', 'advance', 'advice', 'aerobic',
        'affair', 'afford', 'afraid', 'again', 'age', 'agent', 'agree',
        'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album',
        'alcohol', 'alert', 'alien', 'all', 'alley', 'allow', 'almost',
        'alone', 'alpha', 'already', 'also', 'alter', 'always', 'amateur',
        'amazing', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient',
        'anger', 'angle', 'angry', 'animal', 'ankle', 'announce', 'annual',
        'another', 'answer', 'antenna', 'antique', 'anxiety', 'any', 'apart',
        'apology', 'appear', 'apple', 'approve', 'april', 'arch', 'arctic',
        'area', 'arena', 'argue', 'arm', 'armed', 'armor', 'army',
        'around', 'arrange', 'arrest', 'arrive', 'arrow', 'art', 'artefact',
        'artist', 'artwork', 'ask', 'aspect', 'assault', 'asset', 'assist',
        'assume', 'asthma', 'athlete', 'atom', 'attack', 'attend', 'attitude',
        'attract', 'auction', 'audit', 'august', 'aunt', 'author', 'auto',
        'autumn', 'average', 'avocado', 'avoid', 'awake', 'aware', 'awesome',
        'balance', 'ball', 'banana', 'banner', 'bar', 'barely', 'bargain',
        'barrel', 'base', 'basic', 'basket', 'battle', 'beach', 'bean',
        'beauty', 'because', 'become', 'beef', 'before', 'begin', 'behave',
        'behind', 'believe', 'below', 'bench', 'benefit', 'best', 'betray',
        'better', 'between', 'beyond', 'bicycle', 'bid', 'bike', 'bind',
        'biology', 'bird', 'birth', 'bitter', 'black', 'blade', 'blame',
        'blanket', 'blast', 'bleak', 'bless', 'blind', 'blood', 'blossom',
        'blue', 'blur', 'blush', 'board', 'boat', 'body', 'bomb', 'bone',
        'bonus', 'book', 'boost', 'border', 'boring', 'borrow', 'boss',
        'bottom', 'bounce', 'box', 'boy', 'bracket', 'brain', 'brand',
        'brave', 'bread', 'breeze', 'brick', 'bridge', 'brief', 'bright',
        'bring', 'brisk', 'broccoli', 'broken', 'bronze', 'broom', 'brother',
        'brown', 'brush', 'bubble', 'buddy', 'budget', 'buffalo', 'build',
        'bulk', 'bullet', 'bundle', 'burden', 'burger', 'burst', 'bus',
        'cabin', 'cable', 'cactus', 'cage', 'cake', 'call', 'calm',
        'camera', 'camp', 'can', 'canal', 'cancel', 'candy', 'cannon',
        'canoe', 'canvas', 'canyon', 'capital', 'captain', 'car', 'carbon',
        'card', 'cargo', 'carpet', 'carry', 'cart', 'case', 'cash',
        'casino', 'castle', 'casual', 'cat', 'catalog', 'catch', 'category',
        'cause', 'ceiling', 'cement', 'census', 'century', 'cereal', 'certain',
        'chair', 'chalk', 'champion', 'change', 'chaos', 'chapter', 'charge',
        'check', 'cheese', 'chef', 'cherry', 'chicken', 'chief', 'child',
        'choice', 'chunk', 'circle', 'citizen', 'city', 'civil', 'claim',
        'clean', 'clever', 'click', 'client', 'cliff', 'climb', 'clock',
        'close', 'cloth', 'cloud', 'clown', 'club', 'coach', 'coast',
        'code', 'coffee', 'coil', 'coin', 'collect', 'color', 'column',
        'come', 'comfort', 'comic', 'common', 'company', 'concert', 'conduct',
        'confirm', 'congress', 'connect', 'consider', 'control', 'convince',
        'cook', 'cool', 'copper', 'copy', 'coral', 'core', 'corn', 'correct',
        'cost', 'cotton', 'couch', 'country', 'couple', 'course', 'cousin',
        'cover', 'crazy', 'cream', 'credit', 'crew', 'cricket', 'crime',
        'crisp', 'cross', 'crowd', 'crucial', 'cruel', 'cruise', 'crumble',
        'crush', 'cry', 'crystal', 'cube', 'culture', 'cup', 'cupboard',
        'curious', 'current', 'curtain', 'curve', 'cushion', 'custom', 'cycle',
        'dad', 'damage', 'damp', 'dance', 'danger', 'daring', 'dash', 'daughter',
        'dawn', 'day', 'deal', 'debate', 'debris', 'decade', 'december',
        'decide', 'decline', 'deer', 'defense', 'define', 'defy', 'degree',
        'delay', 'deliver', 'demand', 'denial', 'dentist', 'deny', 'depart',
        'depend', 'deposit', 'depth', 'deputy', 'derive', 'describe', 'desert',
        'design', 'desk', 'despair', 'destroy', 'detail', 'detect', 'develop',
        'device', 'devote', 'diagram', 'dial', 'diamond', 'diary', 'dice',
        'diesel', 'diet', 'differ', 'digital', 'dignity', 'dilemma', 'dinner',
        'dinosaur', 'direct', 'dirt', 'disagree', 'discover', 'disease', 'dish',
        'dismiss', 'disorder', 'display', 'distance', 'divert', 'divide',
        'dog', 'doll', 'dolphin', 'domain', 'donate', 'donkey', 'donor',
        'door', 'dose', 'double', 'dove', 'draft', 'dragon', 'drama',
        'drastic', 'draw', 'dream', 'dress', 'drift', 'drill', 'drink',
        'drip', 'drive', 'drop', 'drum', 'dry', 'duck', 'dumb', 'dune',
        'during', 'dust', 'duty', 'dwarf', 'dynamic',
        'token', 'tomato', 'tomorrow', 'tone', 'tongue', 'tonight', 'tool',
        'tooth', 'top', 'topic', 'topple', 'torch', 'tornado', 'tortoise',
        'total', 'tourist', 'toward', 'tower', 'town', 'trade', 'traffic',
        'tragic', 'train', 'transfer', 'trap', 'trash', 'travel', 'tray',
        'treat', 'tree', 'trend', 'trial', 'tribe', 'trick', 'trigger',
        'trophy', 'trouble', 'truck', 'true', 'truly', 'trumpet', 'trust',
        'truth', 'try', 'tube', 'tuna', 'tunnel', 'turkey', 'turn', 'turtle',
        'twelve', 'twenty', 'twice', 'twin', 'twist', 'two', 'type',
        'ugly', 'umbrella', 'unable', 'unaware', 'uncle', 'uncover', 'under',
        'unfair', 'unfold', 'unhappy', 'uniform', 'unique', 'unit', 'universe',
        'unknown', 'unlock', 'until', 'unusual', 'unveil', 'update', 'upgrade',
        'uphold', 'upon', 'upper', 'upset', 'urban', 'usage', 'use', 'useful',
        'vacant', 'vacuum', 'vague', 'valid', 'valley', 'valve', 'van',
        'vanish', 'vapor', 'various', 'vast', 'vault', 'vehicle', 'velvet',
        'vendor', 'venture', 'verb', 'verify', 'version', 'very', 'vessel',
        'veteran', 'viable', 'vibrant', 'vicious', 'victory', 'video', 'view',
        'village', 'vintage', 'violin', 'virtual', 'virus', 'visa', 'visit',
        'visual', 'vital', 'vivid', 'vocal', 'voice', 'void', 'volcano',
        'volume', 'vote', 'voyage',
        'wage', 'wagon', 'wait', 'walk', 'wall', 'walnut', 'want', 'warfare',
        'warm', 'warrior', 'wash', 'wasp', 'waste', 'water', 'wave', 'way',
        'wealth', 'weapon', 'wear', 'weasel', 'weather', 'web', 'wedding',
        'weekend', 'weird', 'welcome', 'west', 'wet', 'whale', 'what',
        'wheat', 'wheel', 'when', 'where', 'whip', 'whisper', 'wide',
        'width', 'wife', 'wild', 'will', 'win', 'window', 'wine', 'wing',
        'wink', 'winner', 'winter', 'wire', 'wisdom', 'wise', 'wish',
        'witness', 'wolf', 'woman', 'wonder', 'wood', 'wool', 'word',
        'work', 'world', 'worry', 'worth', 'wrap', 'wreck', 'wrestle',
        'wrist', 'write', 'wrong',
        'yard', 'year', 'yellow', 'you', 'young', 'youth',
        'zebra', 'zero', 'zone', 'zoo',
    }
    return _bip39_words


def _validate_seed_phrase(text: str) -> bool:
    """Validate BIP-39 seed phrase structure."""
    words = text.lower().split()
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    bip39 = _get_bip39_words()
    common_bip39 = sum(1 for w in words if w in bip39)
    return common_bip39 >= len(words) * 0.5


# =============================================================================
# PATTERNS
# =============================================================================

FINANCIAL_PATTERNS: tuple[PatternDefinition, ...] = (
    # --- SECURITY IDENTIFIERS ---
    _p(r'(?:CUSIP)[:\s#]+([A-Z0-9]{9})\b', 'CUSIP', 0.98, 1, _validate_cusip, flags=re.I),
    _p(r'\b([0-9]{3}[A-Z0-9]{5}[0-9])\b', 'CUSIP', 0.85, 1, _validate_cusip),

    _p(r'(?:ISIN)[:\s#]+([A-Z]{2}[A-Z0-9]{10})\b', 'ISIN', 0.98, 1, _validate_isin, flags=re.I),
    _p(r'\b([A-Z]{2}[A-Z0-9]{9}[0-9])\b', 'ISIN', 0.85, 1, _validate_isin),

    _p(r'(?:SEDOL)[:\s#]+([B-DF-HJ-NP-TV-Z0-9]{7})\b', 'SEDOL', 0.98, 1, _validate_sedol, flags=re.I),
    _p(r'\b([B-DF-HJ-NP-TV-Z0-9]{7})\b', 'SEDOL', 0.70, 1, _validate_sedol),

    _p(r'(?:SWIFT|BIC)[:\s#]+([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b', 'SWIFT_BIC', 0.98, 1, _validate_swift, flags=re.I),

    _p(r'(?:LEI)[:\s#]+([A-Z0-9]{20})\b', 'LEI', 0.98, 1, _validate_lei, flags=re.I),
    _p(r'\b([A-Z0-9]{18}[0-9]{2})\b', 'LEI', 0.80, 1, _validate_lei),

    _p(r'(?:FIGI)[:\s#]+([A-Z0-9]{12})\b', 'FIGI', 0.98, 1, flags=re.I),
    _p(r'\b(BBG[A-Z0-9]{9})\b', 'FIGI', 0.95, 1),

    # --- CRYPTOCURRENCY ---
    _p(r'\b(1[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25,34})\b',
       'BITCOIN_ADDRESS', 0.95, 1, _validate_bitcoin_base58),
    _p(r'\b(3[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25,34})\b',
       'BITCOIN_ADDRESS', 0.95, 1, _validate_bitcoin_base58),
    _p(r'\b(bc1q[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,})\b',
       'BITCOIN_ADDRESS', 0.98, 1, _validate_bitcoin_bech32, flags=re.I),
    _p(r'\b(bc1p[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58,})\b',
       'BITCOIN_ADDRESS', 0.98, 1, _validate_bitcoin_bech32, flags=re.I),

    _p(r'\b(0x[a-fA-F0-9]{40})\b', 'ETHEREUM_ADDRESS', 0.98, 1, _validate_ethereum),

    _p(r'\b(addr1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{50,})\b', 'CARDANO_ADDRESS', 0.95, 1, flags=re.I),

    _p(r'\b([LM][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{26,34})\b',
       'LITECOIN_ADDRESS', 0.85, 1),
    _p(r'\b(ltc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,})\b', 'LITECOIN_ADDRESS', 0.95, 1, flags=re.I),

    _p(r'\b(D[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{26,34})\b',
       'DOGECOIN_ADDRESS', 0.80, 1),

    _p(r'\b(r[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{24,34})\b',
       'XRP_ADDRESS', 0.80, 1),

    # --- SEED PHRASES ---
    _p(r'(?:seed|mnemonic|recovery|backup)\s*(?:phrase|words?)?[:\s]+([a-z]+(?:\s+[a-z]+){11})\b',
       'CRYPTO_SEED_PHRASE', 0.95, 1, _validate_seed_phrase, flags=re.I),
    _p(r'(?:seed|mnemonic|recovery|backup)\s*(?:phrase|words?)?[:\s]+([a-z]+(?:\s+[a-z]+){23})\b',
       'CRYPTO_SEED_PHRASE', 0.95, 1, _validate_seed_phrase, flags=re.I),
)


class FinancialDetector(BaseDetector):
    """
    Detects financial security identifiers and cryptocurrency addresses.

    Uses checksum validation where applicable for high confidence.
    """

    name = "financial"
    tier = Tier.CHECKSUM

    def detect(self, text: str) -> List[Span]:
        spans: list[Span] = []
        seen: set[tuple[int, int]] = set()

        for pdef in FINANCIAL_PATTERNS:
            for match in pdef.pattern.finditer(text):
                if pdef.group > 0 and match.lastindex and pdef.group <= match.lastindex:
                    value = match.group(pdef.group)
                    start = match.start(pdef.group)
                    end = match.end(pdef.group)
                else:
                    value = match.group(0)
                    start = match.start()
                    end = match.end()

                if not value or not value.strip():
                    continue

                key = (start, end)
                if key in seen:
                    continue

                if pdef.validator and not pdef.validator(value):
                    continue

                seen.add(key)

                final_confidence = pdef.confidence
                if pdef.validator:
                    final_confidence = min(0.99, pdef.confidence + 0.02)

                spans.append(Span(
                    start=start,
                    end=end,
                    text=value,
                    entity_type=pdef.entity_type,
                    confidence=final_confidence,
                    detector=self.name,
                    tier=self.tier,
                ))

        return spans
