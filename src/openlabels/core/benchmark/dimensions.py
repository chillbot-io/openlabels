"""NER difficulty-dimension classification for benchmark samples.

Implements the five evaluation dimensions from Singh & Narayanan 2025
("Unmasking the Reality of PII Masking Models"):

1. **BASIC** — straightforward entity recognition with explicit labels
2. **CONTEXTUAL** — entities requiring disambiguation (e.g. "May" = name or month)
3. **NOISY** — text with OCR artifacts, typos, or informal language
4. **NOVEL** — emerging or uncommon PII formats (UPI, newer crypto, etc.)
5. **CROSS_LINGUAL** — non-English text requiring multilingual handling

Each sample can belong to multiple dimensions.  The classifier examines
both the text content and the gold entity types to assign dimensions.
"""

from __future__ import annotations

import re
from enum import Enum

from .dataset import BenchmarkSample

__all__ = ["NERDimension", "classify_sample", "classify_samples"]


class NERDimension(str, Enum):
    """The five NER evaluation dimensions from Singh & Narayanan 2025."""

    BASIC = "basic"
    CONTEXTUAL = "contextual"
    NOISY = "noisy"
    NOVEL = "novel"
    CROSS_LINGUAL = "cross_lingual"


# ── Heuristics ────────────────────────────────────────────────────────

# Words that are ambiguous between PII and common language
_AMBIGUOUS_WORDS: set[str] = {
    # Names that are also common words
    "may", "will", "grace", "mark", "bill", "frank", "penny", "joy",
    "faith", "hope", "august", "march", "april", "june", "hunter",
    "chase", "grant", "chance", "drew", "brook", "reed", "wade",
    "moss", "clay", "stone", "dale", "glen", "cliff", "heath",
    "lance", "don", "rob", "bob", "pat", "art", "ray", "sue",
    "dawn", "rose", "iris", "violet", "daisy", "holly", "ivy",
    "olive", "ginger", "basil", "sage",
}

# Patterns indicating noisy/OCR-affected text
_NOISY_PATTERNS = [
    re.compile(r'[A-Za-z]+\d+[A-Za-z]+'),        # Interleaved letters/digits (OCR)
    re.compile(r'\b[A-Z]{2,}\s+[A-Z]{2,}\b'),     # CONSECUTIVE CAPS WORDS
    re.compile(r'[^\x00-\x7F]{2,}'),              # Non-ASCII clusters (encoding issues)
    re.compile(r'\s{3,}'),                         # Excessive whitespace
    re.compile(r'[.]{3,}|[_]{3,}|[-]{3,}'),       # Repeated punctuation
    re.compile(r'\b\w*[0Oo][0Oo]\w*\b'),          # O/0 confusion (OCR)
    re.compile(r'\bl\d|\d[lI]\b'),                 # l/1/I confusion (OCR)
]

# Entity types that represent "novel" or emerging PII formats
_NOVEL_ENTITY_TYPES: frozenset[str] = frozenset({
    # Newer crypto
    "SOLANA_ADDRESS", "CARDANO_ADDRESS", "POLKADOT_ADDRESS",
    "DOGECOIN_ADDRESS", "XRP_ADDRESS", "MONERO_ADDRESS",
    "CRYPTO_SEED_PHRASE",
    # India-specific
    "AADHAAR", "IN_PAN", "IN_GSTIN", "IN_VOTER",
    # Other emerging / regional IDs
    "CURP", "SVNR", "TH_TNIN", "KR_RRN",
    "SG_NRIC_FIN", "ES_NIE", "ES_NIF", "PL_PESEL", "FI_HETU",
    "IT_FISCAL_CODE", "IT_VAT",
})


def _has_ambiguous_entity_text(sample: BenchmarkSample) -> bool:
    """Check if any gold span text is an ambiguous word."""
    for span in sample.gold_spans:
        if span.text.lower().strip() in _AMBIGUOUS_WORDS:
            return True
    return False


def _has_noisy_text(text: str) -> bool:
    """Check if the text shows signs of noise/OCR artifacts."""
    for pattern in _NOISY_PATTERNS:
        if pattern.search(text):
            return True
    return False


def _has_novel_entities(sample: BenchmarkSample) -> bool:
    """Check if the sample contains novel/emerging PII types."""
    return bool(sample.entity_types_present & _NOVEL_ENTITY_TYPES)


def _is_cross_lingual(sample: BenchmarkSample) -> bool:
    """Check if the sample is non-English."""
    return sample.language != "en"


def classify_sample(sample: BenchmarkSample) -> set[NERDimension]:
    """Classify a single sample into NER difficulty dimensions.

    Every sample is at least BASIC.  Additional dimensions are added
    based on content heuristics.
    """
    dims: set[NERDimension] = {NERDimension.BASIC}

    if _has_ambiguous_entity_text(sample):
        dims.add(NERDimension.CONTEXTUAL)

    if _has_noisy_text(sample.text):
        dims.add(NERDimension.NOISY)

    if _has_novel_entities(sample):
        dims.add(NERDimension.NOVEL)

    if _is_cross_lingual(sample):
        dims.add(NERDimension.CROSS_LINGUAL)

    return dims


def classify_samples(
    samples: list[BenchmarkSample],
) -> dict[NERDimension, list[int]]:
    """Classify all samples and return dimension -> sample_id mapping.

    Returns:
        Dict mapping each ``NERDimension`` to a list of sample IDs
        that belong to that dimension.
    """
    result: dict[NERDimension, list[int]] = {d: [] for d in NERDimension}
    for sample in samples:
        dims = classify_sample(sample)
        for d in dims:
            result[d].append(sample.sample_id)
    return result
