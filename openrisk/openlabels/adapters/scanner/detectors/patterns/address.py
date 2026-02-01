"""Address patterns: street addresses, city/state, ZIP codes, GPS coordinates."""

import regex  # Use regex module for ReDoS timeout protection (CVE-READY-003)
from typing import List, Tuple
from ..constants import (
    CONFIDENCE_HIGH,
    CONFIDENCE_HIGH_MEDIUM,
    CONFIDENCE_LOW,
    CONFIDENCE_MARGINAL,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_MEDIUM_LOW,
    CONFIDENCE_NEAR_CERTAIN,
    CONFIDENCE_RELIABLE,
    CONFIDENCE_WEAK,
)

from ..pattern_registry import create_pattern_adder

ADDRESS_PATTERNS: List[Tuple[regex.Pattern, str, float, int]] = []
add_pattern = create_pattern_adder(ADDRESS_PATTERNS)



# --- Shared Components ---


# === Street Suffixes (shared) ===
_STREET_SUFFIXES = (
    # Common
    r'Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|'
    r'Court|Ct|Way|Place|Pl|'
    # Additional common suffixes
    r'Terrace|Ter|Terr|Circle|Cir|Trail|Trl|Parkway|Pkwy|Pky|'
    r'Highway|Hwy|Square|Sq|Loop|Path|Alley|Aly|'
    r'Crossing|Xing|Point|Pt|Pike|Run|Pass|Cove|'
    r'Glen|Ridge|View|Hill|Heights|Hts|Park|Plaza|Walk|Commons|'
    r'Expressway|Expy|Freeway|Fwy|Turnpike|Tpke|'
    # Residential
    r'Row|Mews|Close|Gardens|Gdn|Estate|Estates'
)

# === State Abbreviations (shared) ===
_STATE_ABBREV = r'(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)'

# === Full State Names (shared) ===
_STATE_FULL = r'(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New\s+Hampshire|New\s+Jersey|New\s+Mexico|New\s+York|North\s+Carolina|North\s+Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode\s+Island|South\s+Carolina|South\s+Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West\s+Virginia|Wisconsin|Wyoming)'

# === City Name Pattern (shared) ===
_CITY_NAME = r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*"  # Capitalized words



# --- Multi-Line Address Patterns ---


# === Multi-line Address (discharge summary format) ===
# Matches:
#   ADDRESS: 123 Main St
#            Springfield, IL 62701
# Captures the FULL address as a single span
add_pattern(
    rf'ADDRESS:\s*'
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'\s*[\n\r]+\s*'  # Newline with leading whitespace on next line
    rf'{_CITY_NAME}\s*,\s*{_STATE_ABBREV}\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', CONFIDENCE_NEAR_CERTAIN, 1, regex.I
)

# === Multi-line Address WITHOUT label (common in forms/documents) ===
# Matches:
#   2199 Seventh Place
#            San Antonio, TX 78201
# Captures the FULL address as a single span
add_pattern(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'\s*[\n\r]+\s*'  # Newline with leading whitespace on next line
    rf'{_CITY_NAME}\s*,\s*{_STATE_ABBREV}\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', CONFIDENCE_HIGH_MEDIUM, 1, regex.I
)


# --- Full Address Patterns ---

# Full address: street, optional apt, city, state, zip
# "5734 Mill Highway, Apt 773, Springfield, IL 62701"
add_pattern(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|#|Bldg|Building|Floor|Fl)\.?\s*#?\s*[A-Za-z0-9]+)?'
    rf'\s*,\s*{_CITY_NAME}'
    rf'\s*,\s*{_STATE_ABBREV}'
    rf'\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', CONFIDENCE_HIGH, 1, regex.I
)

# Full address without apt: "123 Main St, Springfield, IL 62701"
add_pattern(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'\s*,\s*{_CITY_NAME}'
    rf'\s*,\s*{_STATE_ABBREV}'
    rf'\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', CONFIDENCE_HIGH_MEDIUM, 1, regex.I
)

# Full address without comma before state: "123 Main St, Boston MA 02101"
add_pattern(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'\s*,\s*{_CITY_NAME}'
    rf'\s+{_STATE_ABBREV}'  # No comma, just space before state
    rf'\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', 0.93, 1, regex.I
)

# Address without ZIP: "123 Main St, Springfield, IL"
add_pattern(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|#|Bldg|Building|Floor|Fl)\.?\s*#?\s*[A-Za-z0-9]+)?'
    rf'\s*,\s*{_CITY_NAME}'
    rf'\s*,\s*{_STATE_ABBREV})\b',
    'ADDRESS', CONFIDENCE_RELIABLE, 1, regex.I
)


# --- City, State Patterns ---

# City, State ZIP: "Springfield, IL 62701"
add_pattern(
    rf'({_CITY_NAME}\s*,\s*{_STATE_ABBREV}\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', CONFIDENCE_MEDIUM, 1
)

# City, State without ZIP: "Springfield, IL"
add_pattern(
    rf'({_CITY_NAME}\s*,\s*{_STATE_ABBREV})\b(?!\s*\d)',
    'ADDRESS', CONFIDENCE_LOW, 1
)



# --- Street Address Patterns ---


# Street address only (no city/state): "123 Main St" or "5734 Mill Highway, Apt 773"
add_pattern(
    rf'\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?\b'
    rf'(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|#|Bldg|Building|Floor|Fl)\.?\s*#?\s*[A-Za-z0-9]+)?',
    'ADDRESS', CONFIDENCE_MARGINAL, 0, regex.I
)

# === Directional Street Addresses (no suffix required) ===
# Common format: "9820 W. Fairview", "1050 S. Vista", "4500 NE Industrial"
# The directional prefix strongly indicates address context even without street suffix
_DIRECTIONAL = r'(?:N|S|E|W|NE|NW|SE|SW|North|South|East|West|Northeast|Northwest|Southeast|Southwest)\.?'
add_pattern(
    rf'\b(\d+[A-Za-z]?\s+{_DIRECTIONAL}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b',
    'ADDRESS', CONFIDENCE_MEDIUM_LOW, 1
)

# ID card field-labeled address: "8 123 MAIN STREET" where 8 is field number
# Matches: single digit + space + normal street address
add_pattern(
    rf'\b\d\s+(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES}))\.?\b',
    'ADDRESS', CONFIDENCE_MEDIUM, 1, regex.I
)

# All-caps street address (common in OCR from IDs): "123 MAIN STREET"
add_pattern(
    rf'\b(\d+[A-Z]?\s+[A-Z]+(?:\s+[A-Z]+)*\s+(?:STREET|ST|AVENUE|AVE|ROAD|RD|BOULEVARD|BLVD|LANE|LN|DRIVE|DR|COURT|CT|WAY|PLACE|PL|TERRACE|TER|CIRCLE|CIR|TRAIL|TRL|PARKWAY|PKWY|HIGHWAY|HWY))\b',
    'ADDRESS', CONFIDENCE_MEDIUM_LOW, 1
)

# PO Box
add_pattern(r'P\.?O\.?\s*Box\s+\d+', 'ADDRESS', CONFIDENCE_MEDIUM_LOW, 0, regex.I)

# Context-based location: "lives in Springfield", "from Chicago"
# NOTE: No regex.I flag - _CITY_NAME requires capitalized words to avoid matching
# everything after "from" (e.g., "from Los Angeles treated" would match too much)
add_pattern(rf'(?:[Ll]ives?\s+in|[Ff]rom|[Rr]esident\s+of|[Ll]ocated\s+in|[Bb]ased\s+in|[Bb]orn\s+in)\s+({_CITY_NAME})', 'ADDRESS', CONFIDENCE_WEAK, 1)



# --- Zip Code Patterns ---


# === ZIP Code (standalone, labeled only) ===
add_pattern(r'(?:ZIP|Postal|Zip\s*Code)[:\s]+(\d{5}(?:-\d{4})?)', 'ZIP', CONFIDENCE_HIGH, 1, regex.I)

# === HIPAA Safe Harbor Restricted ZIP Prefixes ===
# These 17 prefixes have populations < 20,000 and MUST be detected even without labels
# Per 45 CFR 164.514(b)(2)(i)(B), they get replaced with "000" in safe harbor output
# Ref: scanner pipeline for the transformation logic

# Vermont (036, 059)
add_pattern(r'\b(036\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)
add_pattern(r'\b(059\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)

# Connecticut (063)
add_pattern(r'\b(063\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)

# New York (102)
add_pattern(r'\b(102\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)

# Connecticut (203) - Note: area code overlap, but zip detection context helps
add_pattern(r'\b(203\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_LOW, 1)

# Minnesota (556)
add_pattern(r'\b(556\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)

# Guam/Pacific (692)
add_pattern(r'\b(692\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)

# Texas (790)
add_pattern(r'\b(790\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)

# Wyoming (821, 823, 830, 831)
add_pattern(r'\b(821\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)
add_pattern(r'\b(823\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)
add_pattern(r'\b(830\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)
add_pattern(r'\b(831\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)

# Colorado/Utah (878, 879, 884)
add_pattern(r'\b(878\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)
add_pattern(r'\b(879\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)
add_pattern(r'\b(884\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)

# Nevada (890, 893)
add_pattern(r'\b(890\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)
add_pattern(r'\b(893\d{2}(?:-\d{4})?)\b', 'ZIP', CONFIDENCE_MEDIUM_LOW, 1)

# NOTE: European patterns (streets, postal codes, dates) are in european.py
# They only run on non-English text to avoid false positives.



# --- Gps Coordinates ---


# Decimal degrees: 41.8781, -87.6298 or 41.8781 N, 87.6298 W
add_pattern(r'(-?\d{1,3}\.\d{4,8})[,\s]+(-?\d{1,3}\.\d{4,8})', 'GPS_COORDINATES', CONFIDENCE_MEDIUM_LOW, 0)
add_pattern(r'(\d{1,3}\.\d{4,8})\u00b0?\s*[NS][,\s]+(\d{1,3}\.\d{4,8})\u00b0?\s*[EW]', 'GPS_COORDINATES', CONFIDENCE_RELIABLE, 0, regex.I)
# DMS format: 41 52'43"N 87 37'47"W
add_pattern(r'(\d{1,3}\u00b0\d{1,2}[\'\u2032]\d{1,2}[\"\u2033]?[NS])\s*(\d{1,3}\u00b0\d{1,2}[\'\u2032]\d{1,2}[\"\u2033]?[EW])', 'GPS_COORDINATES', CONFIDENCE_MEDIUM, 0)
# With label
add_pattern(r'(?:GPS|Coordinates?|Location|Lat(?:itude)?[/,]\s*Lon(?:gitude)?)[:\s]+(.{10,40})', 'GPS_COORDINATES', CONFIDENCE_LOW, 1, regex.I)
