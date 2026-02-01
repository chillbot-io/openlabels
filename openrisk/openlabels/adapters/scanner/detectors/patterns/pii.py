"""PII patterns: phone, email, dates, times, age, names."""

import regex  # Use regex module for ReDoS timeout protection (CVE-READY-003)
from typing import List, Tuple
from ..constants import (
    CONFIDENCE_BORDERLINE,
    CONFIDENCE_HIGH,
    CONFIDENCE_HIGH_MEDIUM,
    CONFIDENCE_LOW,
    CONFIDENCE_LOWEST,
    CONFIDENCE_MARGINAL,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_MEDIUM_LOW,
    CONFIDENCE_MINIMAL,
    CONFIDENCE_NEAR_CERTAIN,
    CONFIDENCE_RELIABLE,
    CONFIDENCE_TENTATIVE,
    CONFIDENCE_VERY_LOW,
    CONFIDENCE_WEAK,
)

from ..pattern_registry import create_pattern_adder

PII_PATTERNS: List[Tuple[regex.Pattern, str, float, int]] = []
add_pattern = create_pattern_adder(PII_PATTERNS)


# Phone Numbers

add_pattern(r'\((\d{3})\)\s*(\d{3})[-.]?(\d{4})', 'PHONE', CONFIDENCE_MEDIUM)
add_pattern(r'\b(\d{3})[-.](\d{3})[-.](\d{4})\b', 'PHONE', CONFIDENCE_LOW)
# International formats - no leading \b since + isn't a word character
add_pattern(r'(?:^|(?<=\s))\+1[-.\s]?(\d{3})[-.\s]?(\d{3})[-.\s]?(\d{4})\b', 'PHONE', CONFIDENCE_MEDIUM)
add_pattern(r'(?:^|(?<=\s))\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b', 'PHONE', CONFIDENCE_LOW)
# Labeled phone - tighter pattern: only digits, spaces, dashes, parens, plus
add_pattern(r'(?:phone|tel|fax|call|contact)[:\s]+([()\d\s+.-]{10,20})', 'PHONE', CONFIDENCE_RELIABLE, 1, regex.I)

# === OCR-Aware Phone Patterns ===
# Common OCR substitutions in phone numbers: l/I->1, O->0, S->5, B->8
# Only labeled to reduce false positives
# Phone with S for 5: "(S55) 123-4567" or "55S-1234"
add_pattern(r'(?:phone|tel|call|contact)[:\s]+\(([S5]\d{2})\)\s*(\d{3})[-.]?(\d{4})', 'PHONE', CONFIDENCE_MEDIUM_LOW, 0, regex.I)
add_pattern(r'(?:phone|tel|call|contact)[:\s]+\((\d[S5]\d)\)\s*(\d{3})[-.]?(\d{4})', 'PHONE', CONFIDENCE_MEDIUM_LOW, 0, regex.I)
add_pattern(r'(?:phone|tel|call|contact)[:\s]+\((\d{2}[S5])\)\s*(\d{3})[-.]?(\d{4})', 'PHONE', CONFIDENCE_MEDIUM_LOW, 0, regex.I)
# Phone with l/I for 1: "(555) l23-4567"
add_pattern(r'(?:phone|tel|call|contact)[:\s]+\((\d{3})\)\s*([lI1]\d{2})[-.]?(\d{4})', 'PHONE', CONFIDENCE_MEDIUM_LOW, 0, regex.I)
# Phone with B for 8: "(555) 123-456B" or "55B-1234"
add_pattern(r'(?:phone|tel|call|contact)[:\s]+\((\d{3})\)\s*(\d{3})[-.]?(\d{3}[B8])', 'PHONE', CONFIDENCE_MEDIUM_LOW, 0, regex.I)


# Email

add_pattern(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'EMAIL', CONFIDENCE_HIGH)
add_pattern(r'(?:email|e-mail)[:\s]+([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})', 'EMAIL', CONFIDENCE_NEAR_CERTAIN, 1, regex.I)


# Dates

add_pattern(r'\b(\d{1,2})/(\d{1,2})/(\d{4})\b', 'DATE', CONFIDENCE_LOWEST)
add_pattern(r'\b(\d{1,2})-(\d{1,2})-(\d{4})\b', 'DATE', CONFIDENCE_LOWEST)
add_pattern(r'\b(\d{4})-(\d{1,2})-(\d{1,2})\b', 'DATE', CONFIDENCE_LOWEST)
# Dates with 2-digit years: "12/27/25", "01/15/24"
# Lower confidence due to ambiguity (could be scores, prices, etc.)
add_pattern(r'\b(\d{1,2}/\d{1,2}/\d{2})\b', 'DATE', CONFIDENCE_TENTATIVE)
add_pattern(r'\b(\d{1,2}-\d{1,2}-\d{2})\b', 'DATE', CONFIDENCE_TENTATIVE)

# Date with dots (European format): "15.03.1985" or "03.15.1985"
add_pattern(r'(?:DOB|Date)[:\s]+(\d{1,2}\.\d{1,2}\.\d{4})', 'DATE', CONFIDENCE_LOW, 1, regex.I)
add_pattern(r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b', 'DATE', CONFIDENCE_MINIMAL, 0, regex.I)
add_pattern(r'\b\d{1,2}\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b', 'DATE', CONFIDENCE_MINIMAL, 0, regex.I)
# Edge case: "November 3., 1986" - day with period before comma/year (evasion pattern)
add_pattern(r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}\.,\s*\d{4}\b', 'DATE', CONFIDENCE_BORDERLINE, 0, regex.I)
# Abbreviated month names: "Oct 11, 1984", "Mar 19, 1988", "Jan 15th, 1980"
add_pattern(r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}\b', 'DATE', CONFIDENCE_MINIMAL, 0, regex.I)
add_pattern(r'\b\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{4}\b', 'DATE', CONFIDENCE_MINIMAL, 0, regex.I)
# DOB with abbreviated months
add_pattern(r'(?:DOB|Date\s+of\s+Birth|Birth\s*date)[:\s]+((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4})', 'DATE_DOB', CONFIDENCE_HIGH, 1, regex.I)
add_pattern(r'(?:DOB|Date\s+of\s+Birth|Birth\s*date)[:\s]+(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})', 'DATE_DOB', CONFIDENCE_HIGH, 1, regex.I)
add_pattern(r'(?:admission|admit|discharge)[:\s]+(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})', 'DATE', CONFIDENCE_MEDIUM, 1, regex.I)

# === Ordinal Date Formats ===
# "3rd of March, 1990", "1st of January, 2020"
add_pattern(r'\b(\d{1,2}(?:st|nd|rd|th)\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)(?:\s*,?\s*\d{4})?)\b', 'DATE', CONFIDENCE_WEAK, 0, regex.I)
# "3rd of March" (without year), "22nd of December"
add_pattern(r'\b(\d{1,2}(?:st|nd|rd|th)\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December))\b', 'DATE', CONFIDENCE_MINIMAL, 0, regex.I)
# "3rd March 1990", "1st January 2020" (ordinal without "of")
add_pattern(r'\b(\d{1,2}(?:st|nd|rd|th)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)(?:\s*,?\s*\d{4})?)\b', 'DATE', CONFIDENCE_BORDERLINE, 0, regex.I)
# "the 15th of January" (with "the")
add_pattern(r'\b(the\s+\d{1,2}(?:st|nd|rd|th)\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December))\b', 'DATE', CONFIDENCE_WEAK, 0, regex.I)

# === Weekday + Date Formats ===
# "Fri, Mar 3, 2024", "Monday, January 15, 2024"
add_pattern(r'\b((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\s*,?\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December)\.?\s+\d{1,2}\s*,?\s*\d{4})\b', 'DATE', CONFIDENCE_MARGINAL, 0, regex.I)

# === Date ranges with written months ===
# "between January 1 and January 15"
add_pattern(r'\b((?:between|from)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2})\b', 'DATE', CONFIDENCE_MINIMAL, 0, regex.I)
add_pattern(r'\b((?:and|to|through)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2})\b', 'DATE', CONFIDENCE_MINIMAL, 0, regex.I)
# "March 1-15, 2024" (date range with hyphen)
add_pattern(r'\b((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}\s*[-\u2013\u2014]\s*\d{1,2}\s*,?\s*\d{4})\b', 'DATE', CONFIDENCE_BORDERLINE, 0, regex.I)


# Time

# Safe Harbor requires removal of time elements (they're part of date under HIPAA)
# Standard 12-hour: "11:30 PM", "9:42 AM", "11:30PM"
add_pattern(r'\b(\d{1,2}:\d{2}\s*(?:AM|PM|am|pm|a\.m\.|p\.m\.))\b', 'TIME', CONFIDENCE_MEDIUM_LOW, 0, regex.I)
# With seconds: "11:30:45 PM"
add_pattern(r'\b(\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM|am|pm|a\.m\.|p\.m\.))\b', 'TIME', CONFIDENCE_MEDIUM_LOW, 0, regex.I)
# Contextual: "at 3:30 PM", "@ 11:45"
add_pattern(r'(?:at|@)\s*(\d{1,2}:\d{2}\s*(?:AM|PM|am|pm)?)\b', 'TIME', CONFIDENCE_LOW, 1, regex.I)
# Labeled: "Time: 14:30", "recorded at 2:15 PM"
add_pattern(r'(?:time|recorded|documented|signed)[:\s]+(\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM|am|pm)?)', 'TIME', CONFIDENCE_MEDIUM, 1, regex.I)

# === 24-hour time formats ===
# "14:30:00" - 24-hour with seconds (ISO style)
add_pattern(r'\b(\d{2}:\d{2}:\d{2})\b', 'TIME', CONFIDENCE_MARGINAL, 1)

# === ISO 8601 datetime formats ===
# "2024-03-15T14:30:00Z" - full ISO with timezone
add_pattern(r'\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b', 'DATETIME', CONFIDENCE_RELIABLE, 1)
# "2024-03-15 14:30:00" - ISO-like without T separator
add_pattern(r'\b(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\b', 'DATETIME', CONFIDENCE_MEDIUM_LOW, 1)

# === Timezone-aware times ===
# "14:30:00-05:00" - time with timezone offset
add_pattern(r'\b(\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2})\b', 'TIME', CONFIDENCE_LOW, 1)
# "14:30:00Z" - time with Z (UTC) suffix
add_pattern(r'\b(\d{2}:\d{2}:\d{2}Z)\b', 'TIME', CONFIDENCE_MEDIUM_LOW, 1)

# === Clinical time contexts ===
# "Surgery began 08:00", "procedure at 14:30"
add_pattern(r'(?:began|started|ended|completed|performed)\s+(?:at\s+)?(\d{2}:\d{2})\b', 'TIME', CONFIDENCE_LOW, 1, regex.I)


# Age

# Standard forms: "46 years old", "46 year old"
add_pattern(r'\b(\d{1,3})\s*(?:year|yr)s?\s*old\b', 'AGE', CONFIDENCE_MEDIUM, 1, regex.I)
# Hyphenated form: "46-year-old" (common in clinical notes)
add_pattern(r'\b(\d{1,3})[-\u2010\u2011\u2013\u2014]\s*(?:year|yr)s?[-\u2010\u2011\u2013\u2014]\s*old\b', 'AGE', CONFIDENCE_MEDIUM, 1, regex.I)
# Abbreviations: "46 y/o", "46y/o", "46 yo", "46yo"
add_pattern(r'\b(\d{1,3})\s*y/?o\b', 'AGE', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
# Labeled: "age 46", "aged 46"
add_pattern(r'\b(?:age|aged)[:\s]+(\d{1,3})\b', 'AGE', CONFIDENCE_RELIABLE, 1, regex.I)  # \b prevents matching "Page 123"


# Room/Bed Numbers (facility location identifiers)

# "Room: 625", "Rm: 302A", "Room 101"
add_pattern(r'(?:Room|Rm)[:\s#]+(\d{1,4}[A-Z]?)', 'ROOM', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
# "Bed: 2", "Bed 3A"
add_pattern(r'(?:Bed)[:\s#]+(\d{1,2}[A-Z]?)', 'ROOM', CONFIDENCE_LOW, 1, regex.I)
# Combined: "Room 302, Bed 2"
add_pattern(r'(?:Room|Rm)[:\s#]+(\d{1,4}[A-Z]?)\s*,?\s*(?:Bed)[:\s#]*(\d{1,2}[A-Z]?)', 'ROOM', CONFIDENCE_MEDIUM, 0, regex.I)


# Name Patterns

# === Name Components ===
# Name part: MUST start with capital letter (proper noun)
# Unicode: include common accented characters (Jose, Francois)
# FIXED: Support Irish/Scottish names like O'Connor, O'Brien, McDonald, MacArthur
# Pattern: Capital + lowercase + optional (apostrophe/hyphen + Capital + lowercase)
_NAME = r"[A-Z\u00C0-\u00D6\u00D8-\u00DE][a-z\u00E0-\u00F6\u00F8-\u00FF''\-]*(?:[''\-][A-Z\u00C0-\u00D6\u00D8-\u00DEa-z\u00E0-\u00F6\u00F8-\u00FF][a-z\u00E0-\u00F6\u00F8-\u00FF]*)?"

# Multi-part names: handles "Mary Anne", "Jean-Pierre", "van der Berg"
_NAME_PART = r"(?:[A-Z\u00C0-\u00D6\u00D8-\u00DE][a-z\u00E0-\u00F6\u00F8-\u00FF''\-]*(?:[''\-][A-Z\u00C0-\u00D6\u00D8-\u00DEa-z\u00E0-\u00F6\u00F8-\u00FF][a-z\u00E0-\u00F6\u00F8-\u00FF]*)?)"

# Use [ \t]+ (horizontal whitespace) NOT \s+ (which includes newlines)

# === Initials patterns (J. Wilson, A. Smith, R.J. Thompson) ===
# Single initial: "J. Wilson" or "J Wilson" (with optional period)
_INITIAL = r"[A-Z]\.?"
# Double initial: "R.J." or "R. J." or "RJ"
_DOUBLE_INITIAL = r"[A-Z]\.?\s*[A-Z]\.?"

# === Credential Suffixes (comprehensive list) ===
# Medical doctors, nurses, physician assistants, pharmacists, therapists, dentists, etc.
_CREDENTIALS = (
    r'(?:MD|DO|MBBS|'                           # Medical doctors
    r'RN|BSN|MSN|LPN|LVN|CNA|'                  # Nurses
    r'NP|FNP|ANP|PNP|ACNP|AGNP|WHNP|'          # Nurse practitioners
    r'DNP|APRN|CNM|CNS|CRNA|'                   # Advanced practice nurses
    r'PA|PA-C|'                                  # Physician assistants
    r'PhD|PharmD|RPh|'                          # Pharmacists/researchers
    r'DPM|DPT|OT|OTR|PT|'                       # Podiatry, therapy
    r'DDS|DMD|RDH|'                             # Dentistry
    r'OD|'                                       # Optometry
    r'DC|'                                       # Chiropractic
    r'LCSW|LMFT|LPC|LMHC|PsyD|'                 # Mental health (licensed)
    r'MSW|LMSW|LSW|LISW|DSW|CSW|'              # Social work credentials
    r'RT|RRT|CRT|'                              # Respiratory therapy
    r'EMT|EMT-P|Paramedic|'                     # Emergency medical
    r'MA|CMA|RMA|CCMA)'                         # Medical assistants
)

# === PROVIDER PATTERNS WITH TITLE AND CREDENTIALS ===
# These patterns capture the FULL span including Dr./Doctor prefix and credential suffixes

# Single-word provider name with Dr.: "Dr. Ali", "Dr. Singh" (common in consult notes)
# NOTE: No regex.I - _NAME must stay case-sensitive to avoid matching "from", "the", etc.
add_pattern(rf'((?:[Dd][Rr]\.?|[Dd]octor)[ \t]+{_NAME})\b', 'NAME_PROVIDER', CONFIDENCE_MEDIUM_LOW, 1)

# Dr./Doctor + First Last: "Dr. John Smith", "Doctor Jane Doe"
# NOTE: No regex.I - _NAME must stay case-sensitive to avoid matching lowercase words
add_pattern(rf'((?:[Dd][Rr]\.?|[Dd]octor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{1,2}})\b', 'NAME_PROVIDER', CONFIDENCE_HIGH_MEDIUM, 1)

# Dr./Doctor + Initial + Last: "Dr. J. Smith", "Dr. R.J. Thompson"
add_pattern(rf'((?:Dr\.?|Doctor)[ \t]+{_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', CONFIDENCE_MEDIUM, 1, regex.I)
add_pattern(rf'((?:Dr\.?|Doctor)[ \t]+{_DOUBLE_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', CONFIDENCE_MEDIUM, 1, regex.I)

# Name + Credentials (no Dr.): "John Smith, MD", "Jane Doe, RN", "S. Roberts, DNP"
# NOTE: No regex.I flag - credentials must be uppercase to avoid matching "slept" as PT, "edema" as MA
# NOTE: \b at start prevents matching mid-word like "repORT" -> "O RT"
add_pattern(rf'\b({_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})\b', 'NAME_PROVIDER', CONFIDENCE_RELIABLE, 1)
add_pattern(rf'\b({_INITIAL}[ \t]+{_NAME},?\s*{_CREDENTIALS})\b', 'NAME_PROVIDER', CONFIDENCE_MEDIUM, 1)
add_pattern(rf'\b({_DOUBLE_INITIAL}[ \t]+{_NAME},?\s*{_CREDENTIALS})\b', 'NAME_PROVIDER', CONFIDENCE_MEDIUM, 1)

# Dr. + Name + Credentials: "Dr. John Smith, MD" (redundant but occurs)
# NOTE: regex.I kept for "Dr./Doctor" but credentials must match case
add_pattern(rf'((?:Dr\.?|Doctor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})\b', 'NAME_PROVIDER', CONFIDENCE_HIGH, 1)

# Electronic signature context (high confidence): "Electronically signed by: Joyce Kim, RN"
add_pattern(rf'(?:Electronically\s+signed|E-signed|Authenticated|Verified|Approved)\s+(?:by)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})', 'NAME_PROVIDER', CONFIDENCE_NEAR_CERTAIN, 1, regex.I)
add_pattern(rf'(?:Electronically\s+signed|E-signed|Authenticated|Verified|Approved)\s+(?:by)[:\s]+((?:Dr\.?|Doctor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PROVIDER', CONFIDENCE_NEAR_CERTAIN, 1, regex.I)

# Lab/clinical context: "drawn by J. Wilson" "reviewed by A. Smith MD"
add_pattern(rf'(?:drawn|reviewed|verified|reported|signed|approved|dictated|transcribed|entered|ordered)\s+(?:by|per)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})', 'NAME_PROVIDER', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
add_pattern(rf'(?:drawn|reviewed|verified|reported|signed|approved|dictated|transcribed|entered|ordered)\s+(?:by|per)[:\s]+({_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', CONFIDENCE_VERY_LOW, 1)
add_pattern(rf'(?:drawn|reviewed|verified|reported|signed|approved|dictated|transcribed|entered|ordered)\s+(?:by|per)[:\s]+({_DOUBLE_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', CONFIDENCE_VERY_LOW, 1)

# cc: list context: "cc: Dr. M. Brown, Cardiology"
add_pattern(rf'(?:cc|CC)[:\s]+((?:Dr\.?|Doctor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PROVIDER', CONFIDENCE_LOW, 1, regex.I)
add_pattern(rf'(?:cc|CC)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})', 'NAME_PROVIDER', CONFIDENCE_LOW, 1, regex.I)

# Nurse/NP/PA with name: "Nurse Jane Smith", "NP John Doe"
# NOTE: \b prevents matching "Return" as "RN", colon required to prevent cross-line matching
add_pattern(rf'\b(?:Nurse|NP|PA|RN):\s*({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PROVIDER', CONFIDENCE_LOW, 1, regex.I)

# Provider with label - IMPORTANT: Middle initial requires period
_MIDDLE_INITIAL = r"[A-Z]\."

# Primary patterns - First Last, First Middle Last
add_pattern(rf'(?:Provider|Attending|Referring|Ordering|Treating|Primary\s+Care|Consultant)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{1,2}})', 'NAME_PROVIDER', CONFIDENCE_HIGH_MEDIUM, 1, regex.I)
add_pattern(rf'(?:Provider|Attending|Referring|Ordering|Treating|Primary\s+Care|Consultant)[:\s]+((?:Dr\.?|Doctor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PROVIDER', CONFIDENCE_HIGH, 1, regex.I)
# With middle initial (period required): "Provider: Jonathan K. Kim"
add_pattern(rf'(?:Provider|Attending|Referring|Ordering|Treating|Primary\s+Care)[:\s]+({_NAME}[ \t]+{_MIDDLE_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', CONFIDENCE_HIGH_MEDIUM, 1)
# Signature patterns
add_pattern(rf'(?:Provider\s+Signature)[:\s]*({_NAME}(?:[ \t]+{_NAME}){{1,2}})', 'NAME_PROVIDER', CONFIDENCE_HIGH_MEDIUM, 1, regex.I)
add_pattern(rf'(?:Provider\s+Signature)[:\s]*({_NAME}[ \t]+{_MIDDLE_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', CONFIDENCE_HIGH_MEDIUM, 1)

# School/social services staff patterns (counselors, social workers, etc.)
# These appear in pediatric notes and school records
add_pattern(rf'(?:School\s+)?(?:Counselor|Social\s*Worker|Psychologist|Principal|Teacher)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{1,2}},?\s*{_CREDENTIALS})', 'NAME', CONFIDENCE_HIGH_MEDIUM, 1, regex.I)
add_pattern(rf'(?:School\s+)?(?:Counselor|Social\s*Worker|Psychologist|Principal|Teacher)[:\s]+({_NAME}[ \t]+{_MIDDLE_INITIAL}[ \t]+{_NAME})', 'NAME', CONFIDENCE_RELIABLE, 1, regex.I)
add_pattern(rf'(?:School\s+)?(?:Counselor|Social\s*Worker|Psychologist|Principal|Teacher)[:\s]+({_NAME}[ \t]+{_MIDDLE_INITIAL}[ \t]+{_NAME},?\s*{_CREDENTIALS})', 'NAME', CONFIDENCE_HIGH_MEDIUM, 1, regex.I)

# Handwritten/cursive signature detection (common on IDs)
# Matches names that appear with mixed case in signature style (e.g., "Andrew Sample")
# This catches signatures that OCR extracts from ID cards
add_pattern(rf'\b([A-Z][a-z]+\s+[A-Z][a-z]+)\s*$', 'NAME', CONFIDENCE_MINIMAL, 1)  # First Last at end of line

# ID card signature after restrictions field (e.g., "RESTR:NONE Andrew Sample 5DD:")
# On driver's licenses, signature appears after the restrictions field
add_pattern(r'(?:RESTR|RESTRICTION)[:\s]*(?:NONE|[A-Z])\s+([A-Z][a-z]+\s+[A-Z][a-z]+)(?=\s+\d|\s*$)', 'NAME', CONFIDENCE_LOW, 1, regex.I)

# === ID CARD ALL-CAPS NAME PATTERNS ===
# Driver's licenses and state IDs often have names in ALL CAPS
# These patterns use positional/contextual clues to avoid false positives

# Last name after DOB on ID cards: "DOB: 01/01/1990 SMITH 2 JOHN"
# Field code 1 = last name, but may not have "1" prefix in OCR
add_pattern(r'(?:DOB)[:\s]+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\s+([A-Z]{2,20})(?=\s+\d|\s*$)', 'NAME', CONFIDENCE_MARGINAL, 1, regex.I)

# First/middle name after field code 2: "2 JOHN MICHAEL 8" or "2 ANDREW JASON 8123"
# Must be followed by field code 8 (address) which starts with digit
add_pattern(r'\b2\s+([A-Z]{2,15}(?:\s+[A-Z]{2,15})?)\s+(?=\d{1,5}\s+[A-Z])', 'NAME', CONFIDENCE_WEAK, 1)

# === INTERNATIONAL LABELED NAME PATTERNS ===
# French: Nom, Prenom (last name, first name)
add_pattern(rf'(?:Nom|Pr\u00e9nom|Nom\s+de\s+famille)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
# German: Name, Vorname, Nachname (name, first name, last name)
add_pattern(rf'(?:Vorname|Nachname|Familienname)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
# Spanish: Nombre, Apellido (name, surname)
add_pattern(rf'(?:Nombre|Apellido|Apellidos)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
# Italian: Nome, Cognome (name, surname)
add_pattern(rf'(?:Nome|Cognome)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
# Dutch: Naam, Voornaam, Achternaam (name, first name, last name)
add_pattern(rf'(?:Naam|Voornaam|Achternaam)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
# Portuguese: Nome, Sobrenome (name, surname)
add_pattern(rf'(?:Sobrenome)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
# Full name field (international): "Full Name:", "Complete Name:"
add_pattern(rf'(?:Full\s+Name|Complete\s+Name|Legal\s+Name|Vollst\u00e4ndiger\s+Name|Nom\s+complet|Nombre\s+completo)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{1,3}})', 'NAME', CONFIDENCE_MEDIUM, 1, regex.I)

# === PATIENT NAME PATTERNS ===

# Patient labeled patterns - REQUIRE COLON to avoid matching "Patient reports..."
add_pattern(rf'(?:Patient(?:\s+Name)?|Pt):\s*({_NAME}(?:[ \t]+{_NAME}){{1,3}})', 'NAME_PATIENT', CONFIDENCE_RELIABLE, 1, regex.I)

# Patient without colon - REQUIRES First Last format (two+ capitalized words) to avoid false positives
# "Patient John Smith" matches, but "Patient reports" doesn't (lowercase verb)
# IMPORTANT: NO regex.I flag - name parts must be Capitalized to distinguish from verbs
# Using (?i:Patient) for case-insensitive prefix only
add_pattern(rf'\b(?i:Patient)[ \t]+({_NAME}[ \t]+{_NAME}(?:[ \t]+{_NAME})?)\b', 'NAME_PATIENT', 0.87, 1)
add_pattern(rf'(?:Name):\s*({_NAME}(?:[ \t]+{_NAME}){{1,3}})', 'NAME_PATIENT', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
add_pattern(rf'(?:RE|Re|Regarding):\s*({_NAME}(?:[ \t]+{_NAME}){{1,3}})\s*\(', 'NAME_PATIENT', CONFIDENCE_MEDIUM, 1, regex.I)
# Last, First format common in referrals: "RE: Smith, John" - capture as "Smith, John"
add_pattern(rf'(?:RE|Re|Regarding):\s*({_NAME},\s*{_NAME}(?:[ \t]+{_NAME}){{0,1}})', 'NAME_PATIENT', CONFIDENCE_MEDIUM, 1, regex.I)

# Single labeled name: "Patient: John" - requires explicit colon
add_pattern(rf'(?:Patient):\s*({_NAME})\b', 'NAME_PATIENT', CONFIDENCE_MINIMAL, 1, regex.I)

# Patient names with initials: "Patient: A. Whitaker", "Patient: A. B. Smith"
add_pattern(rf'(?:Patient(?:\s+Name)?|Pt):\s*({_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', CONFIDENCE_MEDIUM, 1, regex.I)
add_pattern(rf'(?:Patient(?:\s+Name)?|Pt):\s*({_DOUBLE_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', CONFIDENCE_MEDIUM, 1, regex.I)
# Patient names with middle initial: "Patient: John A. Smith"
add_pattern(rf'(?:Patient(?:\s+Name)?|Pt):\s*({_NAME}[ \t]+{_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', CONFIDENCE_RELIABLE, 1, regex.I)

# Last, First format without RE: prefix (common in headers/lists)
# "Smith, John" - only when followed by context like DOB, MRN, or newline
add_pattern(rf'({_NAME}),\s+({_NAME})(?=\s*(?:\(|DOB|MRN|SSN|\d{{1,2}}/|\n))', 'NAME_PATIENT', CONFIDENCE_VERY_LOW, 0)

# Last, First in prescription/order context: "prescribed to Smith, John"
add_pattern(rf'(?:prescribed|ordered|given|administered|dispensed)\s+(?:to|for)\s+({_NAME},\s+{_NAME})', 'NAME_PATIENT', CONFIDENCE_MINIMAL, 1, regex.I)

# Inline names: "the patient, John Smith, arrived" - comma-delimited name
add_pattern(rf'(?:(?:the)\s+)?(?:patient),\s+({_NAME}(?:[ \t]+{_NAME}){{1,2}}),', 'NAME_PATIENT', CONFIDENCE_BORDERLINE, 1, regex.I)

# Patient patterns - Mr/Mrs/Ms/Miss indicate patient (non-provider) in clinical context
# NOTE: \b required to prevent "symptoms" matching as "Ms" + name
add_pattern(rf'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PATIENT', CONFIDENCE_MEDIUM, 1, regex.I)

# === INTERNATIONAL HONORIFIC/TITLE PATTERNS ===
# German: Herr, Frau, Fraulein
add_pattern(rf'\b(?:Herr|Frau|Fr\u00e4ulein|Hr\.|Fr\.)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', CONFIDENCE_MEDIUM_LOW, 1)
# French: Monsieur, Madame, Mademoiselle, Docteur(e)
add_pattern(rf'\b(?:Monsieur|Madame|Mademoiselle|M\.|Mme\.?|Mlle\.?|Docteur|Docteure|Dr\.)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', CONFIDENCE_MEDIUM_LOW, 1)
# Spanish: Senor, Senora, Senorita, Don, Dona
add_pattern(rf'\b(?:Se\u00f1or|Se\u00f1ora|Se\u00f1orita|Sr\.|Sra\.|Srta\.|Don|Do\u00f1a)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', CONFIDENCE_MEDIUM_LOW, 1)
# Italian: Signor, Signora, Signorina
add_pattern(rf'\b(?:Signor|Signora|Signorina|Sig\.|Sig\.ra|Sig\.na)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', CONFIDENCE_MEDIUM_LOW, 1)
# Dutch: Meneer, Mevrouw, de heer, mevrouw (often followed by name)
add_pattern(rf'\b(?:Meneer|Mevrouw|Mevr\.|Dhr\.|de[ \t]+heer)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', CONFIDENCE_MEDIUM_LOW, 1)
# Portuguese: Senhor, Senhora
add_pattern(rf'\b(?:Senhor|Senhora|Sr\.|Sra\.)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', CONFIDENCE_MEDIUM_LOW, 1)
# With initials: "Mr. A. Whitaker", "Mrs. A. B. Smith"
add_pattern(rf'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss)[ \t]+({_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', CONFIDENCE_MEDIUM, 1, regex.I)
add_pattern(rf'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss)[ \t]+({_DOUBLE_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', CONFIDENCE_MEDIUM, 1, regex.I)
# With middle initial: "Mr. John A. Smith"
add_pattern(rf'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss)[ \t]+({_NAME}[ \t]+{_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', CONFIDENCE_RELIABLE, 1, regex.I)

# === RELATIVE/FAMILY NAME PATTERNS ===

# Explicit labels
add_pattern(rf'(?:Emergency\s+Contact|Next\s+of\s+Kin|NOK)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,3}})', 'NAME_RELATIVE', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
add_pattern(rf'(?:Spouse|Partner|Guardian|Caregiver)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_RELATIVE', CONFIDENCE_MEDIUM_LOW, 1, regex.I)

# Relationship context: "husband John", "wife Mary", "son Michael"
# NOTE: \b required to prevent "Anderson" matching as "son", [ \t]+ prevents newline crossing
add_pattern(rf'\b(?:husband|wife|spouse|partner|son|daughter|mother|father|brother|sister|parent|child|guardian)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_RELATIVE', CONFIDENCE_MARGINAL, 1, regex.I)
# Possessive: "patient's husband John", "her mother Mary"
add_pattern(rf"\b(?:patient'?s?|his|her|their)[ \t]+(?:husband|wife|spouse|partner|son|daughter|mother|father|brother|sister|parent|child)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})", 'NAME_RELATIVE', CONFIDENCE_LOW, 1, regex.I)
# "mother's name is Sarah", "father is John Smith"
add_pattern(rf"\b(?:mother|father|spouse|partner|guardian)(?:'s[ \t]+name)?[ \t]+(?:is|was)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})", 'NAME_RELATIVE', CONFIDENCE_WEAK, 1, regex.I)

# === SELF-IDENTIFICATION PATTERNS ===
# "my name is John Smith", "I am John Smith", "I'm John Smith"
# High confidence because explicit self-identification is very clear
add_pattern(rf"\b(?:my\s+name\s+is|I\s+am|I'm)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})", 'NAME_PATIENT', CONFIDENCE_MEDIUM, 1, regex.I)
# "this is John Smith" (phone/intro context)
add_pattern(rf'\bthis\s+is[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})(?:\s+speaking|\s+calling)?', 'NAME_PATIENT', CONFIDENCE_LOW, 1, regex.I)


# === STANDALONE NAME PATTERNS (CLINICAL CONTEXT) ===
# These patterns detect single first names in clinical/conversational contexts
# where ML models may fail. Case-sensitive _NAME prevents matching verbs.
# NOTE: NO regex.I flag - _NAME must stay case-sensitive to avoid matching lowercase words.
# Use (?i:...) inline for case-insensitive verb matching only.

# Clinical verb + name: "saw John", "examined Mary", "treated Bob"
# Wide range of clinical verbs that precede patient names
# NOTE: Single name only (no {1,2}) - multi-word names handled by other patterns
_CLINICAL_VERBS_PAST = (
    r'(?i:saw|examined|evaluated|assessed|treated|diagnosed|'
    r'admitted|discharged|transferred|referred|counseled|advised|'
    r'informed|educated|instructed|observed|monitored|'
    r'interviewed|consulted|cleared|stabilized|sedated|intubated)'
)
add_pattern(rf'\b{_CLINICAL_VERBS_PAST}[ \t]+({_NAME})\b', 'NAME_PATIENT', CONFIDENCE_MARGINAL, 1)

# "spoke with John", "met with Mary", "talked to Bob"
add_pattern(rf'\b(?i:spoke|met|talked|visited|checked|followed\s+up)[ \t]+(?i:with|to)[ \t]+({_NAME})\b', 'NAME_PATIENT', CONFIDENCE_WEAK, 1)

# Name's + clinical term (possessive): "John's condition", "Mary's symptoms"
_CLINICAL_NOUNS = (
    r'(?i:condition|symptoms?|diagnosis|prognosis|labs?|results?|'
    r'medication|medications|treatment|therapy|care|recovery|'
    r'vitals?|imaging|x-?rays?|scans?|tests?|bloodwork|'
    r'chart|records?|history|case|progress|status|'
    r'appointment|visit|admission|discharge|surgery|procedure|'
    r'prescription|dosage|regimen|pain|complaints?|'
    r'family|wife|husband|mother|father|son|daughter|'
    r'doctor|physician|nurse|provider|specialist)'
)
add_pattern(rf"\b({_NAME})'s[ \t]+{_CLINICAL_NOUNS}\b", 'NAME_PATIENT', CONFIDENCE_MARGINAL, 1)

# NOTE: Removed aggressive standalone name patterns to improve precision:
# - "Name + verb" patterns (John said, Mary has)
# - Greeting/closing patterns (Hi John, Thanks Mary)
# - Direct address patterns (John, please...)
# - Transport patterns (bring John to)
# These caused too many false positives. Keep only labeled/contextual patterns.
