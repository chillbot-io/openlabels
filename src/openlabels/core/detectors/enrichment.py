"""City gazetteer loading/caching and name-location collision detection.

Extracted from ``orchestrator.py`` — enrichment logic for resolving
ambiguous entities that could be either person names or locations.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..types import Span, normalize_entity_type
from .post_processing import _ranges_overlap

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# City gazetteer
# ---------------------------------------------------------------------------

_LOCATION_TYPES = frozenset({
    "ADDRESS", "CITY", "STATE", "COUNTY", "COUNTRY", "ZIP",
    "GPS_COORDINATE", "GPS_COORDINATES",
})

# Entity types that should beat FIRSTNAME/LASTNAME in a collision.
# Includes locations (Florence→CITY vs FIRSTNAME) and professional
# types (Apple→COMPANY vs FIRSTNAME, Engineer→JOB_TITLE vs FIRSTNAME).
# Benchmark: 5 COMPANY→FIRSTNAME, 4 CITY→FIRSTNAME, 2 JOB_TITLE→FIRSTNAME
# type mismatches on nemotron_pii traced to dedup picking FIRSTNAME over
# these more specific types.
_NAME_COLLISION_PRIORITY_TYPES = _LOCATION_TYPES | frozenset({
    "COMPANY", "EMPLOYER", "JOB_TITLE", "USERNAME",
})

# CITY-specific confidence margin for name-collision replacement.
# GLiNER systematically scores FIRSTNAME higher than CITY for ambiguous
# names (Florence, Austin, Sherwood).  ML calibration compresses all ML
# spans into [0.20, 0.65], so we need a larger margin than the original
# 0.05 to compensate.  Benchmark: 23 CITY→FIRSTNAME type mismatches —
# the old 0.05 margin was too small after tier calibration crushed CITY
# confidence.  Raised to 0.12 to close the typical gap.
_CITY_CONFIDENCE_MARGIN = 0.12

# Additional margin when the span text is found in a city gazetteer.
# This lets us definitively resolve ambiguous names like "Florence",
# "Austin", "Madison" when they appear in US city databases.
_CITY_GAZETTEER_MARGIN = 0.08


def _load_city_gazetteer() -> frozenset[str]:
    """Load US city names from the dictionary for gazetteer lookups."""
    cities_path = Path(__file__).resolve().parent.parent.parent / "dictionaries" / "us_cities.txt"
    if not cities_path.exists():
        return frozenset()
    cities: set[str] = set()
    with open(cities_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                cities.add(line.lower())
    return frozenset(cities)


# Lazy-loaded city gazetteer
_city_gazetteer: frozenset[str] | None = None


def _get_city_gazetteer() -> frozenset[str]:
    global _city_gazetteer
    if _city_gazetteer is None:
        _city_gazetteer = _load_city_gazetteer()
    return _city_gazetteer
