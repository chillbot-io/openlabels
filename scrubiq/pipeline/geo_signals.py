"""Geographic signal detection for facility redaction.

Facilities are not among HIPAA's 18 Safe Harbor identifiers, but facility
names that reveal sub-state geography (city, county, region) can enable
re-identification. This module detects geographic signals in facility names
to determine if redaction is warranted.

Per HHS guidance: "Facility names and employer locations can indirectly
identify individuals, particularly in rural areas or rare-service clinics.
Treat such mentions as geographic identifiers and redact them when they
would reveal a location smaller than a state."

Usage:
    from .geo_signals import load_geo_signals, facility_has_geo_signal
    
    signals = load_geo_signals(config.dictionaries_dir)
    if facility_has_geo_signal("Boise Valley Medical", signals):
        # Redact this facility
"""

import logging
from pathlib import Path
from typing import FrozenSet, Optional, Set

logger = logging.getLogger(__name__)

# Cached geo signals (loaded once per process)
_GEO_SIGNALS: Optional[FrozenSet[str]] = None
_GEO_BIGRAMS: Optional[FrozenSet[str]] = None


def load_geo_signals(dictionaries_dir: Path) -> FrozenSet[str]:
    """
    Load geographic signals from dictionary files.
    
    Loads from dictionaries_dir/geo/:
    - us_states.txt
    - us_counties.txt
    - us_cities.txt
    - regional_patterns.txt
    
    Returns:
        Frozen set of lowercase geographic terms
    """
    global _GEO_SIGNALS, _GEO_BIGRAMS
    
    if _GEO_SIGNALS is not None:
        return _GEO_SIGNALS
    
    signals: Set[str] = set()
    bigrams: Set[str] = set()
    geo_dir = dictionaries_dir / "geo"
    
    if not geo_dir.exists():
        logger.warning(f"Geo dictionaries not found: {geo_dir}")
        _GEO_SIGNALS = frozenset()
        _GEO_BIGRAMS = frozenset()
        return _GEO_SIGNALS
    
    # Load all .txt files in geo directory
    for file_path in geo_dir.glob("*.txt"):
        try:
            for line in file_path.read_text(encoding='utf-8').splitlines():
                line = line.strip().lower()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                # Track bigrams separately for efficient matching
                if ' ' in line:
                    bigrams.add(line)
                else:
                    signals.add(line)
        except Exception as e:
            logger.error(f"Failed to load {file_path}: {e}")
    
    _GEO_SIGNALS = frozenset(signals)
    _GEO_BIGRAMS = frozenset(bigrams)
    
    logger.info(
        f"Loaded geo signals: {len(_GEO_SIGNALS)} terms, "
        f"{len(_GEO_BIGRAMS)} bigrams from {geo_dir}"
    )
    
    return _GEO_SIGNALS


def get_geo_bigrams() -> FrozenSet[str]:
    """Get loaded bigrams (must call load_geo_signals first)."""
    return _GEO_BIGRAMS or frozenset()


def facility_has_geo_signal(
    facility_text: str,
    geo_signals: Optional[FrozenSet[str]] = None,
) -> bool:
    """
    Check if facility name contains a geographic signal.
    
    Returns True if the facility name contains:
    - A city name (e.g., "Boise", "Phoenix")
    - A county name (e.g., "Ada", "Maricopa")
    - A state name (e.g., "Texas", "California")
    - A regional indicator (e.g., "Valley", "Regional")
    
    Args:
        facility_text: The facility name to check
        geo_signals: Set of geo terms (if None, uses cached)
    
    Returns:
        True if geographic signal detected
    
    Examples:
        >>> facility_has_geo_signal("Boise Valley Internal Medicine")
        True
        >>> facility_has_geo_signal("Mayo Clinic")
        False
        >>> facility_has_geo_signal("Cleveland Clinic")
        True
    """
    if geo_signals is None:
        geo_signals = _GEO_SIGNALS or frozenset()
    
    if not geo_signals and not _GEO_BIGRAMS:
        # No signals loaded - default to not redacting
        return False
    
    # Normalize text
    text_lower = facility_text.lower()
    
    # Tokenize into words (handle punctuation)
    words = []
    current_word = []
    for char in text_lower:
        if char.isalnum():
            current_word.append(char)
        else:
            if current_word:
                words.append(''.join(current_word))
                current_word = []
    if current_word:
        words.append(''.join(current_word))
    
    # Check single words against signals
    for word in words:
        if word in geo_signals:
            logger.debug(f"Geo signal match found (single word)")
            return True
    
    # Check bigrams (for "New York", "Los Angeles", "Salt Lake", etc.)
    bigrams = get_geo_bigrams()
    for i in range(len(words) - 1):
        bigram = f"{words[i]} {words[i+1]}"
        if bigram in bigrams:
            logger.debug(f"Geo signal match found (bigram)")
            return True
    
    # Check trigrams for three-word cities (e.g., "Salt Lake City")
    for i in range(len(words) - 2):
        trigram = f"{words[i]} {words[i+1]} {words[i+2]}"
        if trigram in bigrams:
            logger.debug(f"Geo signal match found (trigram)")
            return True
    
    return False


def facility_near_address_span(
    facility_start: int,
    facility_end: int,
    address_spans: list,
    proximity_chars: int = 150,
) -> bool:
    """
    Check if facility span is within proximity of an ADDRESS/ZIP span.
    
    This catches cases like:
    "seen at Internal Medicine Associates, 123 Main St, Boise"
    where the facility itself has no geo signal but is adjacent to one.
    
    Args:
        facility_start: Start position of facility span
        facility_end: End position of facility span
        address_spans: List of (start, end) tuples for ADDRESS/ZIP spans
        proximity_chars: Maximum character distance to consider "near"
    
    Returns:
        True if facility is within proximity of an address span
    """
    for addr_start, addr_end in address_spans:
        # Check if spans are within proximity
        if facility_end + proximity_chars >= addr_start and \
           facility_start - proximity_chars <= addr_end:
            return True
    return False


def should_redact_facility(
    facility_text: str,
    facility_start: int,
    facility_end: int,
    address_spans: list,
    geo_signals: Optional[FrozenSet[str]] = None,
    proximity_chars: int = 150,
) -> bool:
    """
    Determine if a facility should be redacted.
    
    Redact if:
    1. Facility name contains a geographic signal (city, county, state, region)
    2. Facility is within proximity of a detected ADDRESS/ZIP span
    
    Args:
        facility_text: The facility name
        facility_start: Start position in text
        facility_end: End position in text
        address_spans: List of (start, end) tuples for ADDRESS/ZIP spans
        geo_signals: Set of geo terms (if None, uses cached)
        proximity_chars: Max distance to ADDRESS to trigger redaction
    
    Returns:
        True if facility should be redacted
    """
    # Check for geographic signal in name
    if facility_has_geo_signal(facility_text, geo_signals):
        return True
    
    # Check proximity to address spans
    if facility_near_address_span(
        facility_start, facility_end, address_spans, proximity_chars
    ):
        logger.debug(
            f"Facility near address span - marking for redaction"
        )
        return True
    
    return False
