"""
Healthcare facility vocabulary and validation.

Provides keyword sets and validation functions for identifying
healthcare-related organizations vs generic company names.
"""

# Try to import ahocorasick for O(n) multi-pattern matching
try:
    import ahocorasick
    _AHOCORASICK_AVAILABLE = True
except ImportError:
    _AHOCORASICK_AVAILABLE = False


# Healthcare facility keywords - FACILITY spans must contain at least one
# to avoid false positives on generic company names
HEALTHCARE_FACILITY_KEYWORDS = frozenset([
    # Facility types
    "hospital", "medical", "clinic", "health", "healthcare",
    "care", "center", "centre", "memorial", "general",
    "regional", "community", "university", "teaching",
    "children", "pediatric", "veterans", "va",
    "rehabilitation", "rehab", "psychiatric", "behavioral",
    "surgery", "surgical", "emergency", "urgent",
    "oncology", "cancer", "cardiac", "heart",
    "orthopedic", "dental", "eye", "vision",
    "pharmacy", "lab", "laboratory", "diagnostic",
    "imaging", "radiology", "hospice", "nursing",
    "assisted", "living", "senior", "elder",
    "specialty",  # Catches "X Specialty Clinic"
    # Common name patterns
    "st.", "saint", "mount", "mt.",
    "mercy", "providence", "good samaritan", "sacred heart",
    "baptist", "methodist", "presbyterian", "lutheran", "adventist",
])

# Major health systems without obvious keywords (whitelist)
KNOWN_HEALTH_SYSTEMS = frozenset([
    "kaiser", "kaiser permanente",
    "mayo", "mayo clinic",
    "cleveland clinic",
    "johns hopkins",
    "mass general", "massachusetts general",
    "cedars-sinai", "cedars sinai",
    "mount sinai", "mt sinai",
    "nyu langone",
    "scripps",
    "geisinger",
    "intermountain",
    "ascension",
    "hca",
    "tenet",
    "commonspirit",
    "dignity health",
    "sutter",
    "banner",
    "advocate",
    "atrium",
    "beaumont",
    "spectrum",
    "wellstar",
    "northwell",
    "ochsner",
    "piedmont",
    "sentara",
    "christus",
    "sharp",
    "uchealth",
    "ucsf",
    "ucla health",
])

# Build Aho-Corasick automaton for O(n) healthcare keyword matching
_HEALTHCARE_AUTOMATON = None
if _AHOCORASICK_AVAILABLE:
    _HEALTHCARE_AUTOMATON = ahocorasick.Automaton()
    for keyword in HEALTHCARE_FACILITY_KEYWORDS:
        _HEALTHCARE_AUTOMATON.add_word(keyword, keyword)
    for system in KNOWN_HEALTH_SYSTEMS:
        _HEALTHCARE_AUTOMATON.add_word(system, system)
    _HEALTHCARE_AUTOMATON.make_automaton()


def is_valid_healthcare_facility(text: str) -> bool:
    """
    Check if text looks like a healthcare facility name.

    Uses Aho-Corasick automaton for O(n) matching when available,
    falls back to O(k*n) iteration otherwise.

    Reduces false positives on generic company names while keeping
    hospitals, clinics, and known health systems.
    """
    text_lower = text.lower()

    # O(n) path with Aho-Corasick
    if _HEALTHCARE_AUTOMATON is not None:
        # iter() returns matches - we just need to know if any exist
        for _ in _HEALTHCARE_AUTOMATON.iter(text_lower):
            return True
        return False

    # O(k*n) fallback when ahocorasick not available
    for system in KNOWN_HEALTH_SYSTEMS:
        if system in text_lower:
            return True
    for keyword in HEALTHCARE_FACILITY_KEYWORDS:
        if keyword in text_lower:
            return True
    return False
