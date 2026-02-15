"""Allowlist-based false positive suppression.

Uses dictionary lookups and an explicit allowlist file to suppress
detected spans that are known non-PII (facility names detected as
person names, drug names detected as names, etc.).
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..constants import DEFAULT_DICTIONARIES_DIR
from ..types import Span

logger = logging.getLogger(__name__)

# Resolve dictionary directory: prefer the configured data dir, fall back to
# the package-bundled dictionaries (useful in development / CI).
_PACKAGE_DICT_DIR = Path(__file__).resolve().parent.parent.parent / "dictionaries"
_DICT_DIR = DEFAULT_DICTIONARIES_DIR if DEFAULT_DICTIONARIES_DIR.exists() else _PACKAGE_DICT_DIR

# Suppression rules: (dictionary_file, entity_types_to_suppress)
# If a detected span's text matches a term in the dictionary AND the span's
# entity_type is in the suppression set, the span is suppressed.
_SUPPRESSION_RULES: list[tuple[str, frozenset[str]]] = [
    ("facilities.txt", frozenset({
        "NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
        "FIRSTNAME", "LASTNAME", "USERNAME",
    })),
    ("professions.txt", frozenset({
        "NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
        "FIRSTNAME", "LASTNAME",
    })),
    ("us_cities.txt", frozenset({
        "NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
        "FIRSTNAME", "LASTNAME", "USERNAME",
    })),
    ("drugs.txt", frozenset({
        "NAME", "NAME_PATIENT", "NAME_PROVIDER", "FIRSTNAME", "LASTNAME",
    })),
    ("clinical_stopwords.txt", frozenset({
        "NAME", "NAME_PATIENT", "NAME_PROVIDER", "USERNAME",
        "FIRSTNAME", "LASTNAME",
    })),
]


class Allowlist:
    """Suppresses false positive detections using dictionary lookups."""

    def __init__(
        self,
        dict_dir: Path | None = None,
        custom_allowlist: Path | None = None,
    ):
        self._dict_dir = dict_dir or _DICT_DIR
        self._rules: list[tuple[frozenset[str], frozenset[str]]] = []
        # Custom allowlist: maps term -> set of entity types to suppress
        # (empty set = suppress all types)
        self._custom: dict[str, frozenset[str]] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True

        for filename, suppress_types in _SUPPRESSION_RULES:
            filepath = self._dict_dir / filename
            if not filepath.exists():
                logger.debug("Allowlist dictionary not found: %s", filepath)
                continue
            terms = _load_terms(filepath)
            if terms:
                self._rules.append((terms, suppress_types))
                logger.debug(
                    "Loaded %d allowlist terms from %s", len(terms), filename
                )

        # Load custom allowlist if present
        custom_path = self._dict_dir / "allowlist.txt"
        if custom_path.exists():
            self._custom = _load_custom_allowlist(custom_path)
            logger.debug(
                "Loaded %d custom allowlist entries", len(self._custom)
            )

    def should_suppress(self, span: Span) -> bool:
        """Check if a detected span should be suppressed as a false positive."""
        self._ensure_loaded()

        text_lower = span.text.lower().strip()
        if not text_lower:
            return False

        # Check custom allowlist first
        if text_lower in self._custom:
            allowed_types = self._custom[text_lower]
            if not allowed_types or span.entity_type in allowed_types:
                return True

        # Check dictionary-backed rules
        for terms, suppress_types in self._rules:
            if span.entity_type in suppress_types and text_lower in terms:
                return True

        return False

    def filter_spans(self, spans: list[Span]) -> list[Span]:
        """Filter a list of spans, removing suppressed ones."""
        result = []
        for span in spans:
            if self.should_suppress(span):
                logger.debug(
                    "Allowlist suppressed: %s (%s)",
                    span.entity_type, span.text[:30],
                )
            else:
                result.append(span)
        return result


def _load_terms(filepath: Path) -> frozenset[str]:
    """Load terms from a dictionary file (one per line, case-insensitive)."""
    terms: set[str] = set()
    try:
        with open(filepath, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                terms.add(line.lower())
    except OSError as e:
        logger.warning("Failed to load allowlist dictionary %s: %s", filepath, e)
    return frozenset(terms)


def _load_custom_allowlist(filepath: Path) -> dict[str, frozenset[str]]:
    """Load custom allowlist file.

    Format: one entry per line
      term                   # suppress this term for ALL entity types
      term<TAB>TYPE1,TYPE2   # suppress only for specific types
    """
    entries: dict[str, frozenset[str]] = {}
    try:
        with open(filepath, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "\t" in line:
                    term, types_str = line.split("\t", 1)
                    types = frozenset(t.strip().upper() for t in types_str.split(","))
                else:
                    term = line
                    types = frozenset()  # empty = all types
                entries[term.lower().strip()] = types
    except OSError as e:
        logger.warning("Failed to load custom allowlist %s: %s", filepath, e)
    return entries


# Singleton
_allowlist: Allowlist | None = None


def get_allowlist() -> Allowlist:
    """Get the singleton allowlist instance."""
    global _allowlist
    if _allowlist is None:
        _allowlist = Allowlist()
    return _allowlist
