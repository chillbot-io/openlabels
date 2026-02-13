"""Tier 2: Pattern-based detectors for PHI/PII entity recognition."""

from __future__ import annotations

import logging
import re

from ..types import Span, Tier
from .base import BaseDetector
from .pattern_registry import PatternDefinition, _p
from .registry import register_detector

logger = logging.getLogger(__name__)

# FALSE POSITIVE FILTERS

# Common words/phrases that get incorrectly matched as names
# These are document headers, labels, medical terms that match NAME patterns
FALSE_POSITIVE_NAMES: set[str] = {
    # Document types/headers
    "LABORATORY", "REPORT", "LICENSE", "CERTIFICATE", "DOCUMENT",
    "INSURANCE", "CARD", "STATEMENT", "RECORD", "FORM", "APPLICATION",
    "DISCHARGE", "SUMMARY", "ASSESSMENT", "EVALUATION", "CONSULTATION",
    "HISTORY", "PHYSICAL", "PROGRESS", "NOTE", "NOTES", "CHART",

    # Field labels that might match
    "MRN", "DOB", "SSN", "DOD", "DOS", "NPI", "DEA", "EXP", "ISS",
    "PATIENT", "PROVIDER", "MEMBER", "SUBSCRIBER", "INSURED",
    "FACILITY", "HOSPITAL", "CLINIC", "PHARMACY", "LABORATORY",

    # State abbreviations that might match with credentials
    "PA", "MD", "MA", "ME", "NH", "NJ", "NM", "NY", "NC", "ND",
    "OH", "OK", "OR", "RI", "SC", "SD", "TN", "TX", "UT", "VT",
    "VA", "WA", "WV", "WI", "WY", "DC", "PR",

    # Common OCR artifacts
    "USA", "APT", "STE", "SUITE", "UNIT", "BLDG", "FLOOR",

    # Medical terms
    "DIAGNOSIS", "PROCEDURE", "MEDICATION", "PRESCRIPTION", "TREATMENT",
    "SPECIMEN", "COLLECTION", "RESULT", "RESULTS", "TEST", "TESTS",

    # Insurance company name fragments (not PHI)
    "BLUECROSS", "BLUESHIELD", "AETNA", "CIGNA", "UNITED", "HEALTHCARE",
    "ANTHEM", "HUMANA", "KAISER", "MEDICARE", "MEDICAID",

    # International honorifics/titles (these precede names, are not names themselves)
    "HERR", "FRAU", "FRÄULEIN",  # German
    "MONSIEUR", "MADAME", "MADEMOISELLE",  # French
    "SEÑOR", "SEÑORA", "SEÑORITA", "DON", "DOÑA",  # Spanish
    "SIGNOR", "SIGNORA", "SIGNORINA",  # Italian
    "MENEER", "MEVROUW", "VROUW",  # Dutch
    "SENHOR", "SENHORA",  # Portuguese
    "DOCTOR", "DOCTEUR", "DOCTEURE",  # Doctor variants

    # Common words that look like names (capitalized) but aren't
    "GENDER", "MALE", "FEMALE", "OTHER", "UNKNOWN",
    "CITY", "STREET", "ADDRESS", "COUNTRY", "STATE", "REGION",
    "DATE", "TIME", "YEAR", "MONTH", "DAY", "WEEK",
    "NAME", "FIRST", "LAST", "MIDDLE", "FULL", "SURNAME",
    "EMAIL", "PHONE", "MOBILE", "FAX", "CONTACT",
    "ACCOUNT", "NUMBER", "CODE", "TYPE", "STATUS",
    "CHECK", "VERIFY", "CONFIRM", "UPDATE", "SUBMIT",
    "PLAN", "DAILY", "WEEKLY", "MONTHLY", "ANNUAL",
    "TRAINING", "SESSION", "MEETING", "APPOINTMENT",
    "INCLUDE", "EXCLUDE", "ENSURE", "REQUIRE", "COMPLETE",
    # Common verbs/nouns that get falsely detected as names
    "SIGNATURE", "SIGNED", "REPORTS", "REQUESTS", "VERBALIZED",
    "CONFIRMED", "REVIEWED", "DISCUSSED", "UNDERSTANDS", "AGREES",
    "GENTILE", "CHER", "CHERS", "LIEBER", "LIEBE",  # Greeting words
    "HELLO", "DEAR", "REGARDS", "SINCERELY", "THANKS",
    "HALLO", "BONJOUR", "HOLA", "CIAO", "GUTEN",
}

# Compile into lowercase set for case-insensitive matching
_FALSE_POSITIVE_NAMES_LOWER = {s.lower() for s in FALSE_POSITIVE_NAMES}


def _is_false_positive_name(value: str) -> bool:
    """Check if a detected name is likely a false positive."""
    # Split into words and check each
    words = value.split()

    # Single character "names" are almost always false positives
    if len(words) == 1 and len(words[0]) == 1:
        return True

    # Very short matches (< 3 chars) are usually false positives
    if len(value.replace(' ', '')) < 3:
        return True

    # If ALL words are false positives, reject
    if all(w.upper() in FALSE_POSITIVE_NAMES for w in words):
        return True

    # If first word is a common document term (not a name), likely FP
    if words and words[0].upper() in {
        "LABORATORY", "REPORT", "LICENSE", "CERTIFICATE", "DOCUMENT",
        "INSURANCE", "DISCHARGE", "SUMMARY", "ASSESSMENT", "CONSULTATION",
    }:
        return True

    # If last word is a common document term, likely FP (catches "Y REPORT", "RY REPORT")
    if words and words[-1].upper() in {
        "REPORT", "REPORTS", "FORM", "DOCUMENT", "CERTIFICATE", "LICENSE",
        "SUMMARY", "RESULTS", "HISTORY", "NOTES", "CHART",
    }:
        return True

    # Check for patterns that look like document text fragments
    # e.g., "Y REPORT", "A visitPA", "RY REPORT"
    # These usually have very short first words or all-caps
    if len(words) >= 2:
        first_word = words[0]
        last_word = words[-1]

        # Short first word + document term = likely fragment (e.g., "Y REPORT")
        # BUT exclude valid medical credentials after a comma (e.g., "E. Washington, MD")
        VALID_CREDENTIALS = {"MD", "DO", "PA", "NP", "RN", "PHD", "DNP", "APRN", "PAC"}
        if len(first_word) <= 2 and last_word.upper() in FALSE_POSITIVE_NAMES:
            # Exception: comma + credential = valid provider name
            last_clean = last_word.upper().replace("-", "")
            if not ("," in value and last_clean in VALID_CREDENTIALS):
                return True

        # Check if ends with state abbreviation mistaken for credentials
        # Full list of US state abbreviations
        US_STATE_ABBREVS = {
            "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
            "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
            "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
            "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
            "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY", "DC"
        }

        if last_word.upper() in US_STATE_ABBREVS:
            # Check for "City, STATE" pattern (address, not name)
            # Pattern: "Baltimore, MD" or "New York, NY"
            # Real credentials would be "John Smith, MD" (name + credential)
            if "," in value:
                # Split at comma to check what's before it
                before_comma = value.rsplit(",", 1)[0].strip()
                before_words = before_comma.split()

                # If only 1-2 words before comma, likely a city not a person
                # "Baltimore, MD" = 1 word → city
                # "New York, NY" = 2 words → city
                # "San Francisco, CA" = 2 words → city
                # "John Smith, MD" = 2 words → could be either, but...
                # Key insight: city names before state don't have typical name patterns

                # Simple heuristic: if 1 word before comma + state abbrev, it's a city
                if len(before_words) == 1:
                    return True

                # If 2 words and second word is a common city suffix/word, it's a city
                if len(before_words) == 2:
                    city_words = {"city", "york", "orleans", "angeles", "francisco",
                                  "diego", "antonio", "vegas", "beach", "springs",
                                  "falls", "rapids", "creek", "river", "lake", "park",
                                  "heights", "hills", "valley", "grove", "point"}
                    if before_words[1].lower() in city_words:
                        return True
            else:
                # No comma - state abbrev without comma is likely false positive
                # e.g., pattern matched "visit MD" as name ending in MD
                return True

    # Check if the value ends with a false positive fragment
    # This catches things like "visitPA" where PA is mistaken for credential
    for fp in ["visitPA", "visitMA", "visitNY"]:
        if value.endswith(fp):
            return True

    return False


# PATTERN DEFINITIONS

# Each pattern is (regex, entity_type, confidence, group_index)
# group_index is which capture group contains the value (default 0 = whole match)




# NAME PATTERNS

# === Name Components ===
# Name part: MUST start with capital letter (proper noun)
# Unicode: include common accented characters (José, François)
# FIXED: Support Irish/Scottish names like O'Connor, O'Brien, McDonald, MacArthur
# Pattern: Capital + lowercase + optional (apostrophe/hyphen + Capital + lowercase)
_NAME = r"[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ''-]*(?:[''-][A-ZÀ-ÖØ-Þa-zà-öø-ÿ][a-zà-öø-ÿ]*)?"

# Multi-part names: handles "Mary Anne", "Jean-Pierre", "van der Berg"
_NAME_PART = r"(?:[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ''-]*(?:[''-][A-ZÀ-ÖØ-Þa-zà-öø-ÿ][a-zà-öø-ÿ]*)?)"

# Use [ \t]+ (horizontal whitespace) NOT \s+ (which includes newlines)

# === Initials patterns (J. Wilson, A. Smith, R.J. Thompson) ===
# Single initial: "J. Wilson" or "J Wilson" (with optional period)
_INITIAL = r"[A-Z]\.?"
# Double initial: "R.J." or "R. J." or "RJ"
_DOUBLE_INITIAL = r"[A-Z]\.?\s*[A-Z]\.?"

# === Credential Suffixes ===
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

# Provider with label - IMPORTANT: Middle initial requires period
_MIDDLE_INITIAL = r"[A-Z]\."


# === STANDALONE NAME PATTERNS (CLINICAL CONTEXT) ===
# These patterns detect single first names in clinical/conversational contexts
# where ML models may fail. Case-sensitive _NAME prevents matching verbs.
# NOTE: NO re.I flag - _NAME must stay case-sensitive to avoid matching lowercase words.
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

# === Medicare Beneficiary Identifier (MBI) - CMS format since 2020 ===
# Format: 11 chars = C-AN-N-L-AN-N-L-AN-N-AN with optional dashes
# Pos 1: 1-9 (not 0), Pos 2,5,8: Letters (not S,L,O,I,B,Z)
# Pos 3,6,9,11: Alphanumeric (not S,L,O,I,B,Z), Pos 4,7,10: Digits
_MBI_LETTER = r'[ACDEFGHJKMNPQRTUVWXY]'
_MBI_ALNUM = r'[ACDEFGHJKMNPQRTUVWXY0-9]'
_MBI_PATTERN = rf'[1-9]{_MBI_LETTER}{_MBI_ALNUM}\d-?{_MBI_LETTER}{_MBI_ALNUM}\d-?{_MBI_LETTER}{_MBI_ALNUM}\d{_MBI_ALNUM}'

# Payer-prefixed member IDs (e.g., BCBS-987654321, UHC123456789)
_PAYER_PREFIXES = (
    r'BCBS|BlueCross|BlueShield|'
    r'UHC|UnitedHealth(?:care)?|'
    r'Aetna|Cigna|Humana|Kaiser|'
    r'Anthem|Centene|Molina|HCSC|'
    r'Tricare|TRICARE|Medicaid|Medicare|'
    r'Ambetter|Amerigroup|WellCare|'
    r'Oscar|Clover|Devoted|'
    r'Caremark|OptumRx|Express\s*Scripts'
)


# ADDRESS PATTERNS

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

# === Directional Street Addresses (no suffix required) ===
# Common format: "9820 W. Fairview", "1050 S. Vista", "4500 NE Industrial"
# The directional prefix strongly indicates address context even without street suffix
_DIRECTIONAL = r'(?:N|S|E|W|NE|NW|SE|SW|North|South|East|West|Northeast|Northwest|Southeast|Southwest)\.?'

# NOTE: European patterns (streets, postal codes, dates) are in european.py
# They only run on non-English text to avoid false positives.

# FACILITY PATTERNS

_FACILITY_PREFIX = r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}"  # 1-4 capitalized words

# === Specialty Clinics and Medical Practices ===
# Specialty names that appear in clinic/center names
_MEDICAL_SPECIALTY = (
    r'Pulmonary|Cardiology|Cardio|Cardiac|Dermatology|Derma|Gastro(?:enterology)?|'
    r'Neurology|Neuro|Oncology|Orthopedic|Ortho|Pediatric|Psych(?:iatry|ology)?|'
    r'Radiology|Rheumatology|Urology|ENT|Ophthalmology|Optometry|'
    r'Allergy|Immunology|Endocrin(?:e|ology)?|Nephrology|Hematology|'
    r'OB-?GYN|Obstetrics|Gynecology|Family\s+Medicine|Internal\s+Medicine|'
    r'Primary\s+Care|Urgent\s+Care|Sleep|Pain|Spine|Vascular|Wound|'
    r'Physical\s+Therapy|Occupational\s+Therapy|Speech\s+Therapy|Rehabilitation|Rehab'
)

# === PHARMACY CHAINS (PHI when combined with patient data) ===
# Major retail pharmacy chains - include optional store number
_PHARMACY_CHAINS = (
    r'Walgreens|CVS(?:\s+Pharmacy|\s+Health)?|Rite\s*Aid|Walmart\s+Pharmacy|'
    r'Costco\s+Pharmacy|Kroger\s+Pharmacy|Publix\s+Pharmacy|'
    r'Safeway\s+Pharmacy|Albertsons\s+Pharmacy|'
    r'Target\s+Pharmacy|Sam\'s\s+Club\s+Pharmacy|'
    r'Walgreen(?:\'s)?|Wal-?greens|'
    r'Caremark|Express\s+Scripts|OptumRx|Cigna\s+Pharmacy|'
    r'Humana\s+Pharmacy|Kaiser\s+Pharmacy|'
    r'Good\s+Neighbor\s+Pharmacy|Health\s*Mart'
)

PATTERNS: tuple[PatternDefinition, ...] = (



# === Phone Numbers ===
_p(r'\((\d{3})\)\s*(\d{3})[-.]?(\d{4})', 'PHONE', 0.90),
_p(r'\b(\d{3})[-.](\d{3})[-.](\d{4})\b', 'PHONE', 0.85),
# International formats - no leading \b since + isn't a word character
_p(r'(?:^|(?<=\s))\+1[-.\s]?(\d{3})[-.\s]?(\d{3})[-.\s]?(\d{4})\b', 'PHONE', 0.90),
_p(r'(?:^|(?<=\s))\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b', 'PHONE', 0.85),
# Labeled phone - tighter pattern: only digits, spaces, dashes, parens, plus
_p(r'(?:phone|tel|fax|call|contact)[:\s]+([()\d\s+.-]{10,20})', 'PHONE', 0.92, 1, flags=re.I),

# === OCR-Aware Phone Patterns ===
# Common OCR substitutions in phone numbers: l/I→1, O→0, S→5, B→8
# Only labeled to reduce false positives
# Phone with S for 5: "(S55) 123-4567" or "55S-1234"
_p(r'(?:phone|tel|call|contact)[:\s]+\(([S5]\d{2})\)\s*(\d{3})[-.]?(\d{4})', 'PHONE', 0.88, flags=re.I),
_p(r'(?:phone|tel|call|contact)[:\s]+\((\d[S5]\d)\)\s*(\d{3})[-.]?(\d{4})', 'PHONE', 0.88, flags=re.I),
_p(r'(?:phone|tel|call|contact)[:\s]+\((\d{2}[S5])\)\s*(\d{3})[-.]?(\d{4})', 'PHONE', 0.88, flags=re.I),
# Phone with l/I for 1: "(555) l23-4567"
_p(r'(?:phone|tel|call|contact)[:\s]+\((\d{3})\)\s*([lI1]\d{2})[-.]?(\d{4})', 'PHONE', 0.88, flags=re.I),
# Phone with B for 8: "(555) 123-456B" or "55B-1234"
_p(r'(?:phone|tel|call|contact)[:\s]+\((\d{3})\)\s*(\d{3})[-.]?(\d{3}[B8])', 'PHONE', 0.88, flags=re.I),

# === Email ===
_p(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', 'EMAIL', 0.95),
_p(r'(?:email|e-mail)[:\s]+([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})', 'EMAIL', 0.96, 1, flags=re.I),

# === Dates ===
_p(r'\b(\d{1,2})/(\d{1,2})/(\d{4})\b', 'DATE', 0.70),
_p(r'\b(\d{1,2})-(\d{1,2})-(\d{4})\b', 'DATE', 0.70),
_p(r'\b(\d{4})-(\d{1,2})-(\d{1,2})\b', 'DATE', 0.70),
# Dates with 2-digit years: "12/27/25", "01/15/24"
# Lower confidence due to ambiguity (could be scores, prices, etc.)
_p(r'\b(\d{1,2}/\d{1,2}/\d{2})\b', 'DATE', 0.65),
_p(r'\b(\d{1,2}-\d{1,2}-\d{2})\b', 'DATE', 0.65),

# Date with dots (European format): "15.03.1985" or "03.15.1985"
_p(r'(?:DOB|Date)[:\s]+(\d{1,2}\.\d{1,2}\.\d{4})', 'DATE', 0.85, 1, flags=re.I),
_p(r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b', 'DATE', 0.75, flags=re.I),
_p(r'\b\d{1,2}\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b', 'DATE', 0.75, flags=re.I),
# Edge case: "November 3., 1986" - day with period before comma/year (evasion pattern)
_p(r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}\.,\s*\d{4}\b', 'DATE', 0.78, flags=re.I),
# Abbreviated month names: "Oct 11, 1984", "Mar 19, 1988", "Jan 15th, 1980"
_p(r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}\b', 'DATE', 0.75, flags=re.I),
_p(r'\b\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{4}\b', 'DATE', 0.75, flags=re.I),
# DOB with abbreviated months
_p(r'(?:DOB|Date\s+of\s+Birth|Birth\s*date)[:\s]+((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4})', 'DATE_DOB', 0.95, 1, flags=re.I),
_p(r'(?:DOB|Date\s+of\s+Birth|Birth\s*date)[:\s]+(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})', 'DATE_DOB', 0.95, 1, flags=re.I),
_p(r'(?:admission|admit|discharge)[:\s]+(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})', 'DATE', 0.90, 1, flags=re.I),

# === Ordinal Date Formats ===
# "3rd of March, 1990", "1st of January, 2020"
_p(r'\b(\d{1,2}(?:st|nd|rd|th)\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)(?:\s*,?\s*\d{4})?)\b', 'DATE', 0.80, flags=re.I),
# "3rd of March" (without year), "22nd of December"
_p(r'\b(\d{1,2}(?:st|nd|rd|th)\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December))\b', 'DATE', 0.75, flags=re.I),
# "3rd March 1990", "1st January 2020" (ordinal without "of")
_p(r'\b(\d{1,2}(?:st|nd|rd|th)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)(?:\s*,?\s*\d{4})?)\b', 'DATE', 0.78, flags=re.I),
# "the 15th of January" (with "the")
_p(r'\b(the\s+\d{1,2}(?:st|nd|rd|th)\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December))\b', 'DATE', 0.80, flags=re.I),

# === Weekday + Date Formats ===
# "Fri, Mar 3, 2024", "Monday, January 15, 2024"
_p(r'\b((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\s*,?\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December)\.?\s+\d{1,2}\s*,?\s*\d{4})\b', 'DATE', 0.82, flags=re.I),

# === Date ranges with written months ===
# "between January 1 and January 15"
_p(r'\b((?:between|from)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2})\b', 'DATE', 0.75, flags=re.I),
_p(r'\b((?:and|to|through)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2})\b', 'DATE', 0.75, flags=re.I),
# "March 1-15, 2024" (date range with hyphen)
_p(r'\b((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}\s*[-–—]\s*\d{1,2}\s*,?\s*\d{4})\b', 'DATE', 0.78, flags=re.I),

# === Time ===
# Safe Harbor requires removal of time elements (they're part of date under HIPAA)
# Standard 12-hour: "11:30 PM", "9:42 AM", "11:30PM"
_p(r'\b(\d{1,2}:\d{2}\s*(?:AM|PM|am|pm|a\.m\.|p\.m\.))\b', 'TIME', 0.88, flags=re.I),
# With seconds: "11:30:45 PM"
_p(r'\b(\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM|am|pm|a\.m\.|p\.m\.))\b', 'TIME', 0.88, flags=re.I),
# Contextual: "at 3:30 PM", "@ 11:45"
_p(r'(?:at|@)\s*(\d{1,2}:\d{2}\s*(?:AM|PM|am|pm)?)\b', 'TIME', 0.85, 1, flags=re.I),
# Labeled: "Time: 14:30", "recorded at 2:15 PM"
_p(r'(?:time|recorded|documented|signed)[:\s]+(\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM|am|pm)?)', 'TIME', 0.90, 1, flags=re.I),

# === 24-hour time formats ===
# "14:30:00" - 24-hour with seconds (ISO style)
_p(r'\b(\d{2}:\d{2}:\d{2})\b', 'TIME', 0.82, 1),

# === ISO 8601 datetime formats ===
# "2024-03-15T14:30:00Z" - full ISO with timezone
_p(r'\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b', 'DATETIME', 0.92, 1),
# "2024-03-15 14:30:00" - ISO-like without T separator
_p(r'\b(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\b', 'DATETIME', 0.88, 1),

# === Timezone-aware times ===
# "14:30:00-05:00" - time with timezone offset
_p(r'\b(\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2})\b', 'TIME', 0.85, 1),
# "14:30:00Z" - time with Z (UTC) suffix
_p(r'\b(\d{2}:\d{2}:\d{2}Z)\b', 'TIME', 0.88, 1),

# === Clinical time contexts ===
# "Surgery began 08:00", "procedure at 14:30"
_p(r'(?:began|started|ended|completed|performed)\s+(?:at\s+)?(\d{2}:\d{2})\b', 'TIME', 0.85, 1, flags=re.I),

# === Age ===
# Standard forms: "46 years old", "46 year old"
_p(r'\b(\d{1,3})\s*(?:year|yr)s?\s*old\b', 'AGE', 0.90, 1, flags=re.I),
# Hyphenated form: "46-year-old" (common in clinical notes)
_p(r'\b(\d{1,3})[-‐‑–—]\s*(?:year|yr)s?[-‐‑–—]\s*old\b', 'AGE', 0.90, 1, flags=re.I),
# Abbreviations: "46 y/o", "46y/o", "46 yo", "46yo"
_p(r'\b(\d{1,3})\s*y/?o\b', 'AGE', 0.88, 1, flags=re.I),
# Labeled: "age 46", "aged 46"
_p(r'\b(?:age|aged)[:\s]+(\d{1,3})\b', 'AGE', 0.92, 1, flags=re.I),  # \b prevents matching "Page 123"

# === Room/Bed Numbers (facility location identifiers) ===
# "Room: 625", "Rm: 302A", "Room 101"
_p(r'(?:Room|Rm)[:\s#]+(\d{1,4}[A-Z]?)', 'ROOM', 0.88, 1, flags=re.I),
# "Bed: 2", "Bed 3A"
_p(r'(?:Bed)[:\s#]+(\d{1,2}[A-Z]?)', 'ROOM', 0.85, 1, flags=re.I),
# Combined: "Room 302, Bed 2"
_p(r'(?:Room|Rm)[:\s#]+(\d{1,4}[A-Z]?)\s*,?\s*(?:Bed)[:\s#]*(\d{1,2}[A-Z]?)', 'ROOM', 0.90, flags=re.I),

# === PROVIDER PATTERNS WITH TITLE AND CREDENTIALS ===
# These patterns capture the FULL span including Dr./Doctor prefix and credential suffixes

# Single-word provider name with Dr.: "Dr. Ali", "Dr. Singh" (common in consult notes)
# NOTE: No re.I - _NAME must stay case-sensitive to avoid matching "from", "the", etc.
_p(rf'((?:[Dd][Rr]\.?|[Dd]octor)[ \t]+{_NAME})\b', 'NAME_PROVIDER', 0.88, 1),

# Dr./Doctor + First Last: "Dr. John Smith", "Doctor Jane Doe"
# NOTE: No re.I - _NAME must stay case-sensitive to avoid matching lowercase words
_p(rf'((?:[Dd][Rr]\.?|[Dd]octor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{1,2}})\b', 'NAME_PROVIDER', 0.94, 1),

# Dr./Doctor + Initial + Last: "Dr. J. Smith", "Dr. R.J. Thompson"
_p(rf'((?:Dr\.?|Doctor)[ \t]+{_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', 0.90, 1, flags=re.I),
_p(rf'((?:Dr\.?|Doctor)[ \t]+{_DOUBLE_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', 0.90, 1, flags=re.I),

# Name + Credentials (no Dr.): "John Smith, MD", "Jane Doe, RN", "S. Roberts, DNP"
# NOTE: No re.I flag - credentials must be uppercase to avoid matching "slept" as PT, "edema" as MA
# NOTE: \b at start prevents matching mid-word like "repORT" -> "O RT"
_p(rf'\b({_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})\b', 'NAME_PROVIDER', 0.92, 1),
_p(rf'\b({_INITIAL}[ \t]+{_NAME},?\s*{_CREDENTIALS})\b', 'NAME_PROVIDER', 0.90, 1),
_p(rf'\b({_DOUBLE_INITIAL}[ \t]+{_NAME},?\s*{_CREDENTIALS})\b', 'NAME_PROVIDER', 0.90, 1),

# Dr. + Name + Credentials: "Dr. John Smith, MD" (redundant but occurs)
# NOTE: re.I kept for "Dr./Doctor" but credentials must match case
_p(rf'((?:Dr\.?|Doctor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})\b', 'NAME_PROVIDER', 0.95, 1),

# Electronic signature context (high confidence): "Electronically signed by: Joyce Kim, RN"
_p(rf'(?:Electronically\s+signed|E-signed|Authenticated|Verified|Approved)\s+(?:by)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})', 'NAME_PROVIDER', 0.96, 1, flags=re.I),
_p(rf'(?:Electronically\s+signed|E-signed|Authenticated|Verified|Approved)\s+(?:by)[:\s]+((?:Dr\.?|Doctor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PROVIDER', 0.96, 1, flags=re.I),

# Lab/clinical context: "drawn by J. Wilson" "reviewed by A. Smith MD"
_p(rf'(?:drawn|reviewed|verified|reported|signed|approved|dictated|transcribed|entered|ordered)\s+(?:by|per)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})', 'NAME_PROVIDER', 0.88, 1, flags=re.I),
_p(rf'(?:drawn|reviewed|verified|reported|signed|approved|dictated|transcribed|entered|ordered)\s+(?:by|per)[:\s]+({_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', 0.72, 1),
_p(rf'(?:drawn|reviewed|verified|reported|signed|approved|dictated|transcribed|entered|ordered)\s+(?:by|per)[:\s]+({_DOUBLE_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', 0.72, 1),

# cc: list context: "cc: Dr. M. Brown, Cardiology"
_p(rf'(?:cc|CC)[:\s]+((?:Dr\.?|Doctor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PROVIDER', 0.85, 1, flags=re.I),
_p(rf'(?:cc|CC)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})', 'NAME_PROVIDER', 0.85, 1, flags=re.I),

# Nurse/NP/PA with name: "Nurse Jane Smith", "NP John Doe"
# NOTE: \b prevents matching "Return" as "RN", colon required to prevent cross-line matching
_p(rf'\b(?:Nurse|NP|PA|RN):\s*({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PROVIDER', 0.85, 1, flags=re.I),

# Primary patterns - First Last, First Middle Last
_p(rf'(?:Provider|Attending|Referring|Ordering|Treating|Primary\s+Care|Consultant)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{1,2}})', 'NAME_PROVIDER', 0.94, 1, flags=re.I),
_p(rf'(?:Provider|Attending|Referring|Ordering|Treating|Primary\s+Care|Consultant)[:\s]+((?:Dr\.?|Doctor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PROVIDER', 0.95, 1, flags=re.I),
# With middle initial (period required): "Provider: Jonathan K. Kim"
_p(rf'(?:Provider|Attending|Referring|Ordering|Treating|Primary\s+Care)[:\s]+({_NAME}[ \t]+{_MIDDLE_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', 0.94, 1),
# Signature patterns
_p(rf'(?:Provider\s+Signature)[:\s]*({_NAME}(?:[ \t]+{_NAME}){{1,2}})', 'NAME_PROVIDER', 0.94, 1, flags=re.I),
_p(rf'(?:Provider\s+Signature)[:\s]*({_NAME}[ \t]+{_MIDDLE_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', 0.94, 1),

# School/social services staff patterns (counselors, social workers, etc.)
# These appear in pediatric notes and school records
_p(rf'(?:School\s+)?(?:Counselor|Social\s*Worker|Psychologist|Principal|Teacher)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{1,2}},?\s*{_CREDENTIALS})', 'NAME', 0.94, 1, flags=re.I),
_p(rf'(?:School\s+)?(?:Counselor|Social\s*Worker|Psychologist|Principal|Teacher)[:\s]+({_NAME}[ \t]+{_MIDDLE_INITIAL}[ \t]+{_NAME})', 'NAME', 0.92, 1, flags=re.I),
_p(rf'(?:School\s+)?(?:Counselor|Social\s*Worker|Psychologist|Principal|Teacher)[:\s]+({_NAME}[ \t]+{_MIDDLE_INITIAL}[ \t]+{_NAME},?\s*{_CREDENTIALS})', 'NAME', 0.94, 1, flags=re.I),

# Handwritten/cursive signature detection (common on IDs)
# Matches names that appear with mixed case in signature style (e.g., "Andrew Sample")
# This catches signatures that OCR extracts from ID cards
_p(r'\b([A-Z][a-z]+\s+[A-Z][a-z]+)\s*$', 'NAME', 0.75, 1),  # First Last at end of line

# ID card signature after restrictions field (e.g., "RESTR:NONE Andrew Sample 5DD:")
# On driver's licenses, signature appears after the restrictions field
_p(r'(?:RESTR|RESTRICTION)[:\s]*(?:NONE|[A-Z])\s+([A-Z][a-z]+\s+[A-Z][a-z]+)(?=\s+\d|\s*$)', 'NAME', 0.85, 1, flags=re.I),

# === ID CARD ALL-CAPS NAME PATTERNS ===
# Driver's licenses and state IDs often have names in ALL CAPS
# These patterns use positional/contextual clues to avoid false positives

# Last name after DOB on ID cards: "DOB: 01/01/1990 SMITH 2 JOHN"
# Field code 1 = last name, but may not have "1" prefix in OCR
_p(r'(?:DOB)[:\s]+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\s+([A-Z]{2,20})(?=\s+\d|\s*$)', 'NAME', 0.82, 1, flags=re.I),

# First/middle name after field code 2: "2 JOHN MICHAEL 8" or "2 ANDREW JASON 8123"
# Must be followed by field code 8 (address) which starts with digit
_p(r'\b2\s+([A-Z]{2,15}(?:\s+[A-Z]{2,15})?)\s+(?=\d{1,5}\s+[A-Z])', 'NAME', 0.80, 1),

# === INTERNATIONAL LABELED NAME PATTERNS ===
# French: Nom, Prénom (last name, first name)
_p(rf'(?:Nom|Prénom|Nom\s+de\s+famille)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1, flags=re.I),
# German: Name, Vorname, Nachname (name, first name, last name)
_p(rf'(?:Vorname|Nachname|Familienname)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1, flags=re.I),
# Spanish: Nombre, Apellido (name, surname)
_p(rf'(?:Nombre|Apellido|Apellidos)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1, flags=re.I),
# Italian: Nome, Cognome (name, surname)
_p(rf'(?:Nome|Cognome)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1, flags=re.I),
# Dutch: Naam, Voornaam, Achternaam (name, first name, last name)
_p(rf'(?:Naam|Voornaam|Achternaam)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1, flags=re.I),
# Portuguese: Nome, Sobrenome (name, surname)
_p(rf'(?:Sobrenome)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1, flags=re.I),
# Full name field (international): "Full Name:", "Complete Name:"
_p(rf'(?:Full\s+Name|Complete\s+Name|Legal\s+Name|Vollständiger\s+Name|Nom\s+complet|Nombre\s+completo)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{1,3}})', 'NAME', 0.90, 1, flags=re.I),

# === PATIENT NAME PATTERNS ===

# Patient labeled patterns - REQUIRE COLON to avoid matching "Patient reports..."
_p(rf'(?:Patient(?:\s+Name)?|Pt):\s*({_NAME}(?:[ \t]+{_NAME}){{1,3}})', 'NAME_PATIENT', 0.92, 1, flags=re.I),

# Patient without colon - REQUIRES First Last format (two+ capitalized words) to avoid false positives
# "Patient John Smith" matches, but "Patient reports" doesn't (lowercase verb)
# IMPORTANT: NO re.I flag - name parts must be Capitalized to distinguish from verbs
# Using (?i:Patient) for case-insensitive prefix only
_p(rf'\b(?i:Patient)[ \t]+({_NAME}[ \t]+{_NAME}(?:[ \t]+{_NAME})?)\b', 'NAME_PATIENT', 0.87, 1),
_p(rf'(?:Name):\s*({_NAME}(?:[ \t]+{_NAME}){{1,3}})', 'NAME_PATIENT', 0.88, 1, flags=re.I),
_p(rf'(?:RE|Re|Regarding):\s*({_NAME}(?:[ \t]+{_NAME}){{1,3}})\s*\(', 'NAME_PATIENT', 0.90, 1, flags=re.I),
# Last, First format common in referrals: "RE: Smith, John" - capture as "Smith, John"
_p(rf'(?:RE|Re|Regarding):\s*({_NAME},\s*{_NAME}(?:[ \t]+{_NAME}){{0,1}})', 'NAME_PATIENT', 0.90, 1, flags=re.I),

# Single labeled name: "Patient: John" - requires explicit colon
_p(rf'(?:Patient):\s*({_NAME})\b', 'NAME_PATIENT', 0.75, 1, flags=re.I),

# Patient names with initials: "Patient: A. Whitaker", "Patient: A. B. Smith"
_p(rf'(?:Patient(?:\s+Name)?|Pt):\s*({_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', 0.90, 1, flags=re.I),
_p(rf'(?:Patient(?:\s+Name)?|Pt):\s*({_DOUBLE_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', 0.90, 1, flags=re.I),
# Patient names with middle initial: "Patient: John A. Smith"
_p(rf'(?:Patient(?:\s+Name)?|Pt):\s*({_NAME}[ \t]+{_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', 0.92, 1, flags=re.I),

# Last, First format without RE: prefix (common in headers/lists)
# "Smith, John" - only when followed by context like DOB, MRN, or newline
_p(rf'({_NAME}),\s+({_NAME})(?=\s*(?:\(|DOB|MRN|SSN|\d{{1,2}}/|\n))', 'NAME_PATIENT', 0.72, 0),

# Last, First in prescription/order context: "prescribed to Smith, John"
_p(rf'(?:prescribed|ordered|given|administered|dispensed)\s+(?:to|for)\s+({_NAME},\s+{_NAME})', 'NAME_PATIENT', 0.75, 1, flags=re.I),

# Inline names: "the patient, John Smith, arrived" - comma-delimited name
_p(rf'(?:(?:the)\s+)?(?:patient),\s+({_NAME}(?:[ \t]+{_NAME}){{1,2}}),', 'NAME_PATIENT', 0.78, 1, flags=re.I),

# Patient patterns - Mr/Mrs/Ms/Miss indicate patient (non-provider) in clinical context
# NOTE: \b required to prevent "symptoms" matching as "Ms" + name
_p(rf'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PATIENT', 0.90, 1, flags=re.I),

# === INTERNATIONAL HONORIFIC/TITLE PATTERNS ===
# German: Herr, Frau, Fräulein
_p(rf'\b(?:Herr|Frau|Fräulein|Hr\.|Fr\.)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1),
# French: Monsieur, Madame, Mademoiselle, Docteur(e)
_p(rf'\b(?:Monsieur|Madame|Mademoiselle|M\.|Mme\.?|Mlle\.?|Docteur|Docteure|Dr\.)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1),
# Spanish: Señor, Señora, Señorita, Don, Doña
_p(rf'\b(?:Señor|Señora|Señorita|Sr\.|Sra\.|Srta\.|Don|Doña)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1),
# Italian: Signor, Signora, Signorina
_p(rf'\b(?:Signor|Signora|Signorina|Sig\.|Sig\.ra|Sig\.na)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1),
# Dutch: Meneer, Mevrouw, de heer, mevrouw (often followed by name)
_p(rf'\b(?:Meneer|Mevrouw|Mevr\.|Dhr\.|de[ \t]+heer)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1),
# Portuguese: Senhor, Senhora
_p(rf'\b(?:Senhor|Senhora|Sr\.|Sra\.)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1),
# With initials: "Mr. A. Whitaker", "Mrs. A. B. Smith"
_p(rf'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss)[ \t]+({_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', 0.90, 1, flags=re.I),
_p(rf'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss)[ \t]+({_DOUBLE_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', 0.90, 1, flags=re.I),
# With middle initial: "Mr. John A. Smith"
_p(rf'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss)[ \t]+({_NAME}[ \t]+{_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', 0.92, 1, flags=re.I),

# === RELATIVE/FAMILY NAME PATTERNS ===

# Explicit labels
_p(rf'(?:Emergency\s+Contact|Next\s+of\s+Kin|NOK)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,3}})', 'NAME_RELATIVE', 0.88, 1, flags=re.I),
_p(rf'(?:Spouse|Partner|Guardian|Caregiver)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_RELATIVE', 0.88, 1, flags=re.I),

# Relationship context: "husband John", "wife Mary", "son Michael"
# NOTE: \b required to prevent "Anderson" matching as "son", [ \t]+ prevents newline crossing
_p(rf'\b(?:husband|wife|spouse|partner|son|daughter|mother|father|brother|sister|parent|child|guardian)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_RELATIVE', 0.82, 1, flags=re.I),
# Possessive: "patient's husband John", "her mother Mary"
_p(rf'\b(?:patient\'?s?|his|her|their)[ \t]+(?:husband|wife|spouse|partner|son|daughter|mother|father|brother|sister|parent|child)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_RELATIVE', 0.85, 1, flags=re.I),
# "mother's name is Sarah", "father is John Smith"
_p(rf'\b(?:mother|father|spouse|partner|guardian)(?:\'s[ \t]+name)?[ \t]+(?:is|was)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_RELATIVE', 0.80, 1, flags=re.I),

# === SELF-IDENTIFICATION PATTERNS ===
# "my name is John Smith", "I am John Smith", "I'm John Smith"
# High confidence because explicit self-identification is very clear
_p(rf'\b(?:my\s+name\s+is|I\s+am|I\'m)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PATIENT', 0.90, 1, flags=re.I),
# "this is John Smith" (phone/intro context)
_p(rf'\bthis\s+is[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})(?:\s+speaking|\s+calling)?', 'NAME_PATIENT', 0.85, 1, flags=re.I),
_p(rf'\b{_CLINICAL_VERBS_PAST}[ \t]+({_NAME})\b', 'NAME_PATIENT', 0.82, 1),

# "spoke with John", "met with Mary", "talked to Bob"
_p(rf'\b(?i:spoke|met|talked|visited|checked|followed\s+up)[ \t]+(?i:with|to)[ \t]+({_NAME})\b', 'NAME_PATIENT', 0.80, 1),
_p(rf"\b({_NAME})'s[ \t]+{_CLINICAL_NOUNS}\b", 'NAME_PATIENT', 0.82, 1),

# NOTE: Removed aggressive standalone name patterns to improve precision:
# - "Name + verb" patterns (John said, Mary has)
# - Greeting/closing patterns (Hi John, Thanks Mary)
# - Direct address patterns (John, please...)
# - Transport patterns (bring John to)
# These caused too many false positives. Keep only labeled/contextual patterns.

# MEDICAL IDENTIFIERS

# === Medical Record Numbers ===
_p(r'(?:MRN|Medical\s+Record(?:\s+Number)?)[:\s#]+([A-Z]*-?\d{6,12}[A-Z]*)', 'MRN', 0.95, 1, flags=re.I),
_p(r'\b(MRN-\d{6,12})\b', 'MRN', 0.92, 1, flags=re.I),  # Bare MRN-1234567 format
_p(r'(?:patient\s+ID|patient\s*#|pt\s+ID)[:\s#]+([A-Z]*-?\d{6,12}[A-Z]*)', 'MRN', 0.88, 1, flags=re.I),  # "patient ID" variant
_p(r'(?:Encounter|Visit)[:\s#]+([A-Z]*\d{6,12}[A-Z]*)', 'ENCOUNTER_ID', 0.90, 1, flags=re.I),
_p(r'(?:Accession|Lab)[:\s#]+([A-Z]*\d{6,12}[A-Z]*)', 'ACCESSION_ID', 0.90, 1, flags=re.I),

# === NPI (National Provider Identifier) ===
# NPI is a 10-digit number with Luhn checksum (same algorithm as credit cards)
# Labeled: "NPI: 1234567890", "NPI# 1234567890"
_p(r'(?:NPI)[:\s#]+(\d{10})\b', 'NPI', 0.95, 1, flags=re.I),
# Contextual: "provider NPI 1234567890"
_p(r'(?:provider|physician|prescriber|ordering)\s+NPI[:\s#]*(\d{10})\b', 'NPI', 0.92, 1, flags=re.I),
# DEA number (provider controlled substance license): 2 letters + 7 digits
_p(r'(?:DEA)[:\s#]+([A-Z]{2}\d{7})\b', 'DEA', 0.95, 1, flags=re.I),

# === Health Plan IDs ===
_p(r'(?:Member\s*ID|Subscriber)[:\s#]+([A-Z0-9]{6,15})', 'MEMBER_ID', 0.88, 1, flags=re.I),
_p(r'(?:Medicaid)[:\s#]+([A-Z0-9]{8,12})', 'HEALTH_PLAN_ID', 0.88, 1, flags=re.I),

# Labeled MBI patterns (high confidence)
_p(rf'(?:Medicare\s*(?:Beneficiary\s*)?(?:ID|#|Number)?|MBI)[:\s#()]*({_MBI_PATTERN})', 'MEDICARE_ID', 0.97, 1, flags=re.I),
_p(rf'(?:Beneficiary\s*ID)[:\s#]*({_MBI_PATTERN})', 'MEDICARE_ID', 0.95, 1, flags=re.I),
# After other Medicare labels like "Medicare ID (MBI):"
_p(rf'(?:ID\s*\(MBI\))[:\s#]*({_MBI_PATTERN})', 'MEDICARE_ID', 0.96, 1, flags=re.I),
# Bare MBI pattern (moderate confidence - distinct format unlikely to be random)
_p(rf'\b({_MBI_PATTERN})\b', 'MEDICARE_ID', 0.82, 1),
_p(r'(?:RXBIN|RX\s*BIN)[:\s]+(\d{6})', 'PHARMACY_ID', 0.90, 1, flags=re.I),
_p(r'(?:RXPCN|RX\s*PCN)[:\s]+([A-Z0-9]{4,10})', 'PHARMACY_ID', 0.88, 1, flags=re.I),
_p(r'(?:Group(?:\s*(?:Number|No|#))?)[:\s#]+([A-Z0-9-]{4,15})', 'HEALTH_PLAN_ID', 0.75, 1, flags=re.I),

# Member ID with letter prefix and hyphen (e.g., BC-993812, BVH-882391)
_p(r'(?:Member\s*ID)[:\s#]+([A-Z]{2,4}-\d{5,12})', 'MEMBER_ID', 0.92, 1, flags=re.I),
# Bare insurance ID format: 2-4 letters, hyphen, 5-12 digits (contextual)
_p(r'\b([A-Z]{2,4}-\d{5,12})\b', 'HEALTH_PLAN_ID', 0.70, 1),
# Require at least one digit in the ID portion to avoid matching company names
_p(rf'(?:{_PAYER_PREFIXES})[- ]?([A-Z]*\d[A-Z0-9]{{5,14}})', 'HEALTH_PLAN_ID', 0.90, 1, flags=re.I),
_p(rf'((?:{_PAYER_PREFIXES})[- ]?[A-Z]*\d[A-Z0-9]{{5,14}})', 'HEALTH_PLAN_ID', 0.88, flags=re.I),

# === Multi-line Address (discharge summary format) ===
# Matches:
#   ADDRESS: 123 Main St
#            Springfield, IL 62701
# Captures the FULL address as a single span
_p(
    rf'ADDRESS:\s*'
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'\s*[\n\r]+\s*'  # Newline with leading whitespace on next line
    rf'{_CITY_NAME}\s*,\s*{_STATE_ABBREV}\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', 0.96, 1, flags=re.I
),

# === Multi-line Address WITHOUT label (common in forms/documents) ===
# Matches:
#   2199 Seventh Place
#            San Antonio, TX 78201
# Captures the FULL address as a single span
_p(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'\s*[\n\r]+\s*'  # Newline with leading whitespace on next line
    rf'{_CITY_NAME}\s*,\s*{_STATE_ABBREV}\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', 0.94, 1, flags=re.I
),

# === Full Address Patterns (industry standard - single span) ===
# Full address: street, optional apt, city, state, zip
# "5734 Mill Highway, Apt 773, Springfield, IL 62701"
_p(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|#|Bldg|Building|Floor|Fl)\.?\s*#?\s*[A-Za-z0-9]+)?'
    rf'\s*,\s*{_CITY_NAME}'
    rf'\s*,\s*{_STATE_ABBREV}'
    rf'\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', 0.95, 1, flags=re.I
),

# Full address without apt: "123 Main St, Springfield, IL 62701"
_p(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'\s*,\s*{_CITY_NAME}'
    rf'\s*,\s*{_STATE_ABBREV}'
    rf'\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', 0.94, 1, flags=re.I
),

# Full address without comma before state: "123 Main St, Boston MA 02101"
_p(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'\s*,\s*{_CITY_NAME}'
    rf'\s+{_STATE_ABBREV}'  # No comma, just space before state
    rf'\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', 0.93, 1, flags=re.I
),

# Address without ZIP: "123 Main St, Springfield, IL"
_p(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|#|Bldg|Building|Floor|Fl)\.?\s*#?\s*[A-Za-z0-9]+)?'
    rf'\s*,\s*{_CITY_NAME}'
    rf'\s*,\s*{_STATE_ABBREV})\b',
    'ADDRESS', 0.92, 1, flags=re.I
),

# City, State ZIP: "Springfield, IL 62701"
_p(
    rf'({_CITY_NAME}\s*,\s*{_STATE_ABBREV}\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', 0.90, 1
),

# City, State without ZIP: "Springfield, IL"
_p(
    rf'({_CITY_NAME}\s*,\s*{_STATE_ABBREV})\b(?!\s*\d)',
    'ADDRESS', 0.85, 1
),

# Street address only (no city/state): "123 Main St" or "5734 Mill Highway, Apt 773"
_p(
    rf'\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?\b'
    rf'(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|#|Bldg|Building|Floor|Fl)\.?\s*#?\s*[A-Za-z0-9]+)?',
    'ADDRESS', 0.82, flags=re.I
),
_p(
    rf'\b(\d+[A-Za-z]?\s+{_DIRECTIONAL}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b',
    'ADDRESS', 0.88, 1
),

# ID card field-labeled address: "8 123 MAIN STREET" where 8 is field number
# Matches: single digit + space + normal street address
_p(
    rf'\b\d\s+(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES}))\.?\b',
    'ADDRESS', 0.90, 1, flags=re.I
),

# All-caps street address (common in OCR from IDs): "123 MAIN STREET"
_p(
    r'\b(\d+[A-Z]?\s+[A-Z]+(?:\s+[A-Z]+)*\s+(?:STREET|ST|AVENUE|AVE|ROAD|RD|BOULEVARD|BLVD|LANE|LN|DRIVE|DR|COURT|CT|WAY|PLACE|PL|TERRACE|TER|CIRCLE|CIR|TRAIL|TRL|PARKWAY|PKWY|HIGHWAY|HWY))\b',
    'ADDRESS', 0.88, 1
),

# PO Box
_p(r'P\.?O\.?\s*Box\s+\d+', 'ADDRESS', 0.88, flags=re.I),

# Context-based location: "lives in Springfield", "from Chicago"
# NOTE: No re.I flag - _CITY_NAME requires capitalized words to avoid matching
# everything after "from" (e.g., "from Los Angeles treated" would match too much)
_p(rf'(?:[Ll]ives?\s+in|[Ff]rom|[Rr]esident\s+of|[Ll]ocated\s+in|[Bb]ased\s+in|[Bb]orn\s+in)\s+({_CITY_NAME})', 'ADDRESS', 0.80, 1),

# === ZIP Code (standalone, labeled only) ===
_p(r'(?:ZIP|Postal|Zip\s*Code)[:\s]+(\d{5}(?:-\d{4})?)', 'ZIP', 0.95, 1, flags=re.I),

# === HIPAA Safe Harbor Restricted ZIP Prefixes ===
# These 17 prefixes have populations < 20,000 and MUST be detected even without labels
# Per 45 CFR §164.514(b)(2)(i)(B), they get replaced with "000" in safe harbor output
# Ref: core/pipeline/safe_harbor.py for the transformation logic

# Vermont (036, 059)
_p(r'\b(036\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),
_p(r'\b(059\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),

# Connecticut (063)
_p(r'\b(063\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),

# New York (102)
_p(r'\b(102\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),

# Connecticut (203) - Note: area code overlap, but zip detection context helps
_p(r'\b(203\d{2}(?:-\d{4})?)\b', 'ZIP', 0.85, 1),

# Minnesota (556)
_p(r'\b(556\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),

# Guam/Pacific (692)
_p(r'\b(692\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),

# Texas (790)
_p(r'\b(790\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),

# Wyoming (821, 823, 830, 831)
_p(r'\b(821\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),
_p(r'\b(823\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),
_p(r'\b(830\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),
_p(r'\b(831\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),

# Colorado/Utah (878, 879, 884)
_p(r'\b(878\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),
_p(r'\b(879\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),
_p(r'\b(884\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),

# Nevada (890, 893)
_p(r'\b(890\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),
_p(r'\b(893\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1),
_p(rf'({_FACILITY_PREFIX}\s+(?:Hospital|Medical\s+Center|Health\s+Center|Clinic|Health\s+System|Healthcare|Specialty\s+Clinic|Regional\s+Medical))\b', 'FACILITY', 0.85, 1),
_p(rf'({_FACILITY_PREFIX}\s+(?:Memorial|General|Community|University|Regional|Veterans|Children\'s)\s+Hospital)\b', 'FACILITY', 0.88, 1),
_p(rf'({_FACILITY_PREFIX}\s+(?:Group|LLC|Ltd|Inc|Associates|Partners)\s+Hospital)\b', 'FACILITY', 0.85, 1),

# St./Saint prefixed facilities (very common in healthcare)
# High confidence to override any misclassification of "St" as ADDRESS
_p(r"(St\.?\s+[A-Z][a-z]+(?:'s)?\s+(?:Hospital|Medical\s+Center|Health\s+Center|Clinic|Health\s+System|Heart\s+Institute|Cancer\s+Center|Children's\s+Hospital))", 'FACILITY', 0.92, 1),
_p(r"(Saint\s+[A-Z][a-z]+(?:'s)?\s+(?:Hospital|Medical\s+Center|Health\s+Center|Clinic|Health\s+System|Heart\s+Institute|Cancer\s+Center|Children's\s+Hospital))", 'FACILITY', 0.92, 1),
# Generic St./Saint + Name patterns (catch-all for other facility types)
_p(r"(St\.?\s+[A-Z][a-z]+(?:'s)?(?:\s+[A-Z][a-z]+){1,3})\s+(?:Hospital|Center|Clinic|Institute|Foundation)", 'FACILITY', 0.88, 0),
_p(r"(Saint\s+[A-Z][a-z]+(?:'s)?(?:\s+[A-Z][a-z]+){1,3})\s+(?:Hospital|Center|Clinic|Institute|Foundation)", 'FACILITY', 0.88, 0),
# "[Name] Pulmonary Clinic", "[Name] Cardiology Center"
_p(rf'({_FACILITY_PREFIX}\s+(?:{_MEDICAL_SPECIALTY})\s+(?:Clinic|Center|Associates|Practice|Group|Specialists))\b', 'FACILITY', 0.90, 1, flags=re.I),

# Multi-part specialty facilities with "&": "Pulmonary & Sleep Center", "Cardiology & Vascular Associates"
_p(rf'((?:{_MEDICAL_SPECIALTY})\s+(?:&|and)\s+(?:{_MEDICAL_SPECIALTY})\s+(?:Center|Clinic|Associates|Institute|Specialists))\b', 'FACILITY', 0.92, 1, flags=re.I),

# "[Name] Pulmonary & Sleep Center" (name prefix + specialty combo)
_p(rf'({_FACILITY_PREFIX}\s+(?:{_MEDICAL_SPECIALTY})\s+(?:&|and)\s+(?:{_MEDICAL_SPECIALTY})\s+(?:Center|Clinic|Associates))\b', 'FACILITY', 0.92, 1, flags=re.I),

# Context-labeled facilities: "Clinic:", "Hospital:", "Center:" followed by name
_p(rf'(?:Clinic|Hospital|Center|Practice)[:\s]+({_FACILITY_PREFIX}(?:\s+(?:{_MEDICAL_SPECIALTY}))?(?:\s+(?:&|and)\s+[A-Z][a-z]+)*(?:\s+(?:Center|Clinic|Associates|Practice))?)', 'FACILITY', 0.90, 1, flags=re.I),

# Standalone specialty practice names: "Pulmonary Associates", "Sleep Center", "Pain Specialists"
_p(rf'\b((?:{_MEDICAL_SPECIALTY})\s+(?:Associates|Specialists|Center|Clinic|Practice|Group|Partners))\b', 'FACILITY', 0.85, 1, flags=re.I),
# Pharmacy with optional store number (e.g., "Walgreens Pharmacy #10472")
_p(rf'((?:{_PHARMACY_CHAINS})(?:\s+Pharmacy)?(?:\s*#?\d{{3,6}})?)', 'FACILITY', 0.92, 1, flags=re.I),
# "Preferred Pharmacy:" or "Pharmacy:" label followed by pharmacy name
_p(rf'(?:Preferred\s+)?Pharmacy[:\s]+((?:{_PHARMACY_CHAINS})(?:\s+Pharmacy)?(?:\s*#?\d{{3,6}})?)', 'FACILITY', 0.94, 1, flags=re.I),
# Bare pharmacy chain name when it appears alone
_p(rf'\b((?:{_PHARMACY_CHAINS})\s+Pharmacy(?:\s*#\d{{3,6}})?)(?:\s|,|$)', 'FACILITY', 0.90, 1, flags=re.I),

# NETWORK/DEVICE IDENTIFIERS
# === IP Address ===
_p(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', 'IP_ADDRESS', 0.85),
# IPv6 - full or compressed format
_p(r'\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7})\b', 'IP_ADDRESS', 0.85),  # Full
_p(r'\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,7})\b', 'IP_ADDRESS', 0.80),  # Compressed

# === MAC Address ===
_p(r'\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', 'MAC_ADDRESS', 0.90),

# === IMEI ===
_p(r'(?:IMEI)[:\s]+(\d{15})', 'IMEI', 0.95, 1, flags=re.I),

# === Device Serial Numbers (medical devices) ===
# Labeled patterns for pacemakers, insulin pumps, hearing aids, etc.
_p(r'(?:Serial(?:\s*(?:Number|No|#))?|S/N|SN)[:\s]+([A-Z0-9]{6,20})', 'DEVICE_ID', 0.90, 1, flags=re.I),
_p(r'(?:Device\s*(?:ID|Identifier|Serial))[:\s]+([A-Z0-9]{6,20})', 'DEVICE_ID', 0.92, 1, flags=re.I),
_p(r'(?:Pacemaker|ICD|Defibrillator|Pump|Implant)\s+(?:ID|Serial|S/N)[:\s]+([A-Z0-9]{6,20})', 'DEVICE_ID', 0.94, 1, flags=re.I),

# === URLs ===
_p(r'https?://[^\s<>"{}|\\^`\[\]]+', 'URL', 0.90),

# === Biometric Identifiers (Safe Harbor #16) ===
_p(r'(?:Fingerprint|Biometric|Retinal?|Iris|Voice(?:print)?|DNA)\s+(?:ID|Sample|Scan|Record|Data)[:\s#]+([A-Z0-9]{6,30})', 'BIOMETRIC_ID', 0.90, 1, flags=re.I),
_p(r'(?:Genetic|Genomic|DNA)\s+(?:Test|Sample|Analysis)\s+(?:ID|#|Number)[:\s]+([A-Z0-9]{6,20})', 'BIOMETRIC_ID', 0.88, 1, flags=re.I),

# === Photographic Image Identifiers (Safe Harbor #17) ===
_p(r'(?:Photo|Image|Picture|Photograph)\s+(?:ID|File|#)[:\s]+([A-Z0-9_-]{6,30})', 'IMAGE_ID', 0.85, 1, flags=re.I),
_p(r'(?:DICOM|Study|Series|Image)\s+(?:UID|ID)[:\s]+([0-9.]{10,64})', 'IMAGE_ID', 0.92, 1, flags=re.I),

# === Username ===
_p(r'(?:username|user|login|userid)[:\s]+([A-Za-z0-9_.-]{3,30})', 'USERNAME', 0.85, 1, flags=re.I),
# International username labels (FR: nom d'utilisateur, DE: Benutzername, ES: usuario, NL: gebruikersnaam, IT: nome utente, PT: usuário)
_p(r'(?:nom d\'utilisateur|benutzername|usuario|gebruikersnaam|nome utente|usuário|utilisateur)[:\s]+([\w._-]{3,30})', 'USERNAME', 0.85, 1, flags=re.I | re.UNICODE),
# NOTE: Removed @ mention and greeting patterns - too many false positives
# Login context: "logged in as username", "signed in as username"
# NOTE: Removed "account" - it matches account numbers, not usernames
_p(r'(?:logged\s+in\s+as|signed\s+in\s+as|profile)[:\s]+([A-Za-z0-9_.-]{3,30})', 'USERNAME', 0.82, 1, flags=re.I),

# === Password ===
# English password labels - require colon/equals separator (not just whitespace) to avoid FPs
_p(r'(?:password|passwd|pwd|passcode|pin)\s*[=:]\s*([^\s]{4,50})', 'PASSWORD', 0.90, 1, flags=re.I),
# International password labels (DE: Kennwort/Passwort, FR: mot de passe, ES: contraseña, IT: password, NL: wachtwoord, PT: senha)
_p(r'(?:kennwort|passwort|mot\s+de\s+passe|contraseña|wachtwoord|senha|parola\s+d\'ordine)[:\s]+([^\s]{4,50})', 'PASSWORD', 0.90, 1, flags=re.I | re.UNICODE),
# Authentication context: "credentials: password", "secret: xxxxx"
_p(r'(?:credential|secret|auth\s+key|api\s+key|access\s+key|secret\s+key)[:\s]+([^\s]{8,100})', 'PASSWORD', 0.88, 1, flags=re.I),
# Temp/initial password context
_p(r'(?:temporary|temp|initial|default)\s+(?:password|pwd|passcode)[:\s]+([^\s]{4,50})', 'PASSWORD', 0.92, 1, flags=re.I),
# LICENSE/CREDENTIAL/GOVERNMENT IDs
# === Driver's License - Labeled ===
_p(r'(?:Driver\'?s?\s*License|DL|DLN)[:\s#]+([A-Z0-9]{5,15})', 'DRIVER_LICENSE', 0.88, 1, flags=re.I),

# === Driver's License - State-specific formats (bare patterns) ===
# These catch DL numbers even without labels, based on known state formats

# Florida: Letter + 3-3-2-3-1 with dashes (W426-545-30-761-0)
_p(r'\b([A-Z]\d{3}-\d{3}-\d{2}-\d{3}-\d)\b', 'DRIVER_LICENSE', 0.95, 1),
# Florida without dashes (OCR may miss them): W4265453076110
_p(r'\b([A-Z]\d{12}0)\b', 'DRIVER_LICENSE', 0.85, 1),

# California: Letter + 7 digits (A1234567)
_p(r'\b([A-Z]\d{7})\b', 'DRIVER_LICENSE', 0.72, 1),

# New York: 9 digits OR Letter + 7 digits + space + 3 digits
# Note: 9 digit overlaps with SSN, so need context
_p(r'(?:DL|License)[:\s]+(\d{9})\b', 'DRIVER_LICENSE', 0.85, 1, flags=re.I),

# Pennsylvania: 8 digits
_p(r'\b(\d{8})\b(?=.*(?:PA|Pennsylvania|DL|License))', 'DRIVER_LICENSE', 0.75, 1, flags=re.I),

# Illinois: Letter + 11-12 digits (A12345678901)
_p(r'\b([A-Z]\d{11,12})\b', 'DRIVER_LICENSE', 0.82, 1),

# Ohio: 2 letters + 6 digits (AB123456) OR 8 digits
_p(r'\b([A-Z]{2}\d{6})\b', 'DRIVER_LICENSE', 0.78, 1),

# Michigan: Letter + 10-12 digits
_p(r'\b([A-Z]\d{10,12})\b', 'DRIVER_LICENSE', 0.80, 1),

# New Jersey: Letter + 14 digits
_p(r'\b([A-Z]\d{14})\b', 'DRIVER_LICENSE', 0.85, 1),

# Virginia: Letter + 8-9 digits OR 9 digits (with context)
_p(r'\b([A-Z]\d{8,9})\b', 'DRIVER_LICENSE', 0.75, 1),

# Maryland: Letter + 12 digits
# (Covered by Michigan pattern above)

# Wisconsin: Letter + 13 digits
_p(r'\b([A-Z]\d{13})\b', 'DRIVER_LICENSE', 0.82, 1),

# Washington: WDL prefix + alphanumeric (12 chars total like WDL*ABC1234D)
_p(r'\b(WDL[A-Z0-9*]{9})\b', 'DRIVER_LICENSE', 0.92, 1),

# Hawaii: H + 8 digits (H12345678)
_p(r'\b(H\d{8})\b', 'DRIVER_LICENSE', 0.85, 1),

# Colorado: 2 letters + 3-6 digits OR 9 digits (with context)
_p(r'\b([A-Z]{2}\d{3,6})\b', 'DRIVER_LICENSE', 0.72, 1),
_p(r'(?:CO|Colorado|DL)[:\s]+(\d{9})\b', 'DRIVER_LICENSE', 0.80, 1, flags=re.I),

# Nevada: 9-12 digits, often starts with X or 9
_p(r'\b(X\d{8,11})\b', 'DRIVER_LICENSE', 0.85, 1),
_p(r'(?:NV|Nevada|DL)[:\s]+(\d{9,12})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# New Hampshire: 2 digits + 3 letters + 5 digits (12ABC34567)
_p(r'\b(\d{2}[A-Z]{3}\d{5})\b', 'DRIVER_LICENSE', 0.88, 1),

# North Dakota: 3 letters + 6 digits (ABC123456)
_p(r'\b([A-Z]{3}\d{6})\b', 'DRIVER_LICENSE', 0.82, 1),

# Iowa: 3 digits + 2 letters + 4 digits (123AB4567) OR 9 digits
_p(r'\b(\d{3}[A-Z]{2}\d{4})\b', 'DRIVER_LICENSE', 0.88, 1),

# Kansas: K + 8 digits (K12345678)
_p(r'\b(K\d{8})\b', 'DRIVER_LICENSE', 0.85, 1),

# Massachusetts: S + 8 digits (S12345678)
_p(r'\b(S\d{8})\b', 'DRIVER_LICENSE', 0.85, 1),

# Arizona: Letter + 8 digits OR 9 digits with context
_p(r'(?:AZ|Arizona|DL)[:\s]+([A-Z]?\d{8,9})\b', 'DRIVER_LICENSE', 0.80, 1, flags=re.I),

# Minnesota: Letter + 12 digits
# (Covered by Illinois pattern: Letter + 11-12 digits)

# Kentucky: Letter + 8-9 digits
# (Covered by Virginia pattern: Letter + 8-9 digits)

# Louisiana: 8 digits, often starts with 00
_p(r'\b(00\d{6})\b', 'DRIVER_LICENSE', 0.80, 1),

# Indiana: 4 digits + 2 letters + 4 digits (1234AB5678) OR 10 digits
_p(r'\b(\d{4}[A-Z]{2}\d{4})\b', 'DRIVER_LICENSE', 0.88, 1),
_p(r'(?:IN|Indiana|DL)[:\s]+(\d{10})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# Oregon: 1-7 digits OR Letter + 6 digits
_p(r'\b([A-Z]\d{6})\b', 'DRIVER_LICENSE', 0.72, 1),

# Connecticut: 9 digits (with context, overlaps SSN)
_p(r'(?:CT|Connecticut|DL)[:\s]+(\d{9})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# Texas: 8 digits (with context)
_p(r'(?:TX|Texas|DL)[:\s]+(\d{8})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# Georgia: 7-9 digits (with context)
_p(r'(?:GA|Georgia|DL)[:\s]+(\d{7,9})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# Alabama: 7 digits (with context)
_p(r'(?:AL|Alabama|DL)[:\s]+(\d{7})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# Missouri: Letter + 5-10 digits OR 9 digits with context
_p(r'(?:MO|Missouri|DL)[:\s]+([A-Z]?\d{5,10})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# Tennessee: 7-9 digits (with context)
_p(r'(?:TN|Tennessee|DL)[:\s]+(\d{7,9})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# South Carolina: 5-11 digits (with context)
_p(r'(?:SC|South\s+Carolina|DL)[:\s]+(\d{5,11})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# General formats
# Letter(s) + 5-14 digits (many states)
_p(r'\b([A-Z]{1,2}\d{5,14})\b', 'DRIVER_LICENSE', 0.68, 1),

# DL with spaces (like "99 999999" from PA sample)
_p(r'(?:DL|DLN)[:\s#]+(\d{2}\s+\d{6})', 'DRIVER_LICENSE', 0.90, 1, flags=re.I),

# DL with dashes - generic (captures FL and others)
_p(r'(?:DL|DLN)[:\s#]+([A-Z]?\d{2,4}[-\s]\d{2,4}[-\s]\d{2,4}[-\s]?\d{0,4})', 'DRIVER_LICENSE', 0.92, 1, flags=re.I),

# === State ID (non-driver) ===
_p(r'(?:State\s*ID|ID\s*Card)[:\s#]+([A-Z0-9]{5,15})', 'STATE_ID', 0.88, 1, flags=re.I),

# === ID Card trailing numbers (document discriminator, inventory numbers) ===
# These appear after "ORGAN DONOR", "DD:", or at end of ID card text
_p(r'(?:ORGAN\s*DONOR|VETERAN)\s+(\d{10,15})\s*$', 'UNIQUE_ID', 0.85, 1, flags=re.I),
# Document discriminator without DD label (often at end of ID)
_p(r'(?:DD[:\s]+\d{10,15}\s+)(\d{10,15})\s*$', 'UNIQUE_ID', 0.80, 1),

# === Passport ===
_p(r'(?:Passport)[:\s#]+([A-Z0-9]{6,12})', 'PASSPORT', 0.88, 1, flags=re.I),
# US passport format: 9 digits or alphanumeric
_p(r'\b([A-Z]?\d{8,9})\b(?=.*[Pp]assport)', 'PASSPORT', 0.75, 1),

# === Medical License ===
_p(r'(?:Medical\s+License|License\s+#)[:\s]+([A-Z0-9]{5,15})', 'MEDICAL_LICENSE', 0.88, 1, flags=re.I),

# === Military IDs ===
# EDIPI (Electronic Data Interchange Personal Identifier) - 10 digits
_p(r'(?:EDIPI|DoD\s*ID|Military\s*ID)[:\s#]+(\d{10})\b', 'MILITARY_ID', 0.92, 1, flags=re.I),
# FAX NUMBERS (explicit patterns - often caught by PHONE but good to be specific)
_p(r'(?:fax|facsimile)[:\s]+([()\d\s+.-]{10,20})', 'FAX', 0.92, 1, flags=re.I),
_p(r'(?:f|fax)[:\s]*\((\d{3})\)\s*(\d{3})[-.]?(\d{4})', 'FAX', 0.90),
_p(r'(?:f|fax)[:\s]*(\d{3})[-.](\d{3})[-.](\d{4})', 'FAX', 0.88),
# PRESCRIPTION / RX NUMBERS
_p(r'(?:Rx|Rx\s*#|Prescription|Script)[:\s#]+(\d{6,12})', 'RX_NUMBER', 0.88, 1, flags=re.I),
_p(r'(?:Rx|Prescription)\s+(?:Number|No|#)[:\s]+([A-Z0-9]{6,15})', 'RX_NUMBER', 0.90, 1, flags=re.I),
_p(r'(?:Refill|Fill)\s+#[:\s]*(\d{1,3})\s+of\s+(\d{1,3})', 'RX_NUMBER', 0.75, flags=re.I),  # "Refill #2 of 5"


# FINANCIAL IDENTIFIERS

# === SSN (labeled) - higher confidence than unlabeled ===
_p(r'(?:SSN|Social\s*Security(?:\s*(?:Number|No|#))?)[:\s#]+(\d{3}[-\s]?\d{2}[-\s]?\d{4})', 'SSN', 0.96, 1, flags=re.I),
_p(r'(?:last\s*4|last\s*four)[:\s]+(\d{4})\b', 'SSN_PARTIAL', 0.80, 1, flags=re.I),
# Bare 9-digit - LOW confidence (0.70) so labeled MRN/Account patterns (0.95) win
_p(r'\b((?!000|666|9\d\d)\d{9})\b', 'SSN', 0.70),

# SSN with unusual separators (dots, middle dots, spaces around hyphens)
_p(r'(?:SSN|Social\s*Security)[:\s#]+(\d{3}[.\xb7]\d{2}[.\xb7]\d{4})', 'SSN', 0.85, 1, flags=re.I),  # dots/middle dots
_p(r'(?:SSN|Social\s*Security)[:\s#]+(\d{3}\s*-\s*\d{2}\s*-\s*\d{4})', 'SSN', 0.88, 1, flags=re.I),  # spaces around hyphens

# === ABA Routing (labeled only) ===
_p(r'(?:Routing|ABA|RTN)[:\s#]+(\d{9})\b', 'ABA_ROUTING', 0.95, 1, flags=re.I),
# Account numbers - both numeric-only and alphanumeric formats
_p(r'(?:Account)\s*(?:Number|No|#)?[:\s#]+(\d{8,17})\b', 'ACCOUNT_NUMBER', 0.88, 1, flags=re.I),
_p(r'(?:Account)\s*(?:Number|No|#)?[:\s#]+([A-Z0-9][-A-Z0-9]{5,19})', 'ACCOUNT_NUMBER', 0.85, 1, flags=re.I),

# === Certificate/License Numbers (Safe Harbor #11) ===
_p(r'(?:Certificate|Certification)\s+(?:Number|No|#)[:\s]+([A-Z0-9-]{5,20})', 'CERTIFICATE_NUMBER', 0.85, 1, flags=re.I),
# NOTE: Require at least one digit to avoid matching "Radiologist"
_p(r'(?:Board\s+Certified?|Certified)\s+#?[:\s]*([A-Z]*\d[A-Z0-9]{4,14})', 'CERTIFICATE_NUMBER', 0.80, 1, flags=re.I),

# === Additional Account Numbers (Safe Harbor #10) ===
_p(r'(?:Patient\s+)?(?:Acct)\s*(?:Number|No|#)?[:\s#]+([A-Z0-9-]{6,20})', 'ACCOUNT_NUMBER', 0.85, 1, flags=re.I),
_p(r'(?:Invoice|Billing|Statement)\s*(?:Number|No|#)?\s*[:#]\s*([A-Z0-9-]{6,20})', 'ACCOUNT_NUMBER', 0.80, 1, flags=re.I),
_p(r'(?:Claim)\s*(?:Number|No|#)?\s*[:#]\s*([A-Z0-9-]{8,20})', 'CLAIM_NUMBER', 0.88, 1, flags=re.I),

# === Unique Identifiers (Safe Harbor #18) - Catch-all ===
# Require explicit colon or # separator (not just whitespace) to avoid FPs
_p(r'(?:Case|File|Record)\s*(?:Number|No|#)?\s*[:#]\s*([A-Z0-9-]{5,20})', 'UNIQUE_ID', 0.75, 1, flags=re.I),

# === Credit Card Numbers ===
# 13-19 digits, optionally separated by spaces/dashes
# Luhn validation done in detector
_p(r'(?:Card|Credit\s*Card|CC|Payment)[:\s#]+(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7})', 'CREDIT_CARD', 0.94, 1, flags=re.I),
# Bare credit card patterns (with separators to distinguish from random numbers)
_p(r'\b(\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4})\b', 'CREDIT_CARD', 0.88, 1),
_p(r'\b(\d{4}[\s-]\d{6}[\s-]\d{5})\b', 'CREDIT_CARD', 0.88, 1),  # Amex format
# Last 4 of card
_p(r'(?:ending\s+in|last\s+4|xxxx)[:\s]*(\d{4})\b', 'CREDIT_CARD_PARTIAL', 0.82, 1, flags=re.I),
# VEHICLE IDENTIFIERS (HIPAA Required)
# === VIN (Vehicle Identification Number) ===
# 17 characters: A-Z (except I, O, Q) and 0-9
# Position 9 is check digit, position 10 is model year
# Common in accident/injury records, insurance claims
_p(r'(?:VIN|Vehicle\s*(?:ID|Identification)(?:\s*Number)?)[:\s#]+([A-HJ-NPR-Z0-9]{17})\b', 'VIN', 0.96, 1, flags=re.I),
# Bare VIN with word boundary - must be exactly 17 valid VIN characters
_p(r'\b([A-HJ-NPR-Z0-9]{17})\b', 'VIN', 0.75, 1),

# === License Plate ===
_p(r'(?:License\s*Plate|Plate\s*(?:Number|No|#)|Tag)[:\s#]+([A-Z0-9]{2,8})', 'LICENSE_PLATE', 0.88, 1, flags=re.I),

# State-specific license plate formats (high confidence)
# California: 1ABC234 (1 digit, 3 letters, 3 digits)
_p(r'\b(\d[A-Z]{3}\d{3})\b', 'LICENSE_PLATE', 0.82, 1),
# New York: ABC-1234 (3 letters, 4 digits with dash)
_p(r'\b([A-Z]{3}-\d{4})\b', 'LICENSE_PLATE', 0.85, 1),
# Texas: ABC-1234 or ABC 1234
_p(r'\b([A-Z]{3}[-\s]\d{4})\b', 'LICENSE_PLATE', 0.82, 1),
# Florida: ABC D12 or ABCD12 (letter-heavy)
_p(r'\b([A-Z]{3,4}\s?[A-Z]?\d{2})\b', 'LICENSE_PLATE', 0.75, 1),


# HEALTHCARE-SPECIFIC IDENTIFIERS
# === NDC (National Drug Code) - 5-4-2 format with dashes ===
# FDA standard drug identifier, reveals medication info
_p(r'\b(\d{5}-\d{4}-\d{2})\b', 'NDC', 0.92, 1),
# NDC with label
_p(r'(?:NDC|National\s+Drug\s+Code)[:\s#]+(\d{5}-?\d{4}-?\d{2})', 'NDC', 0.95, 1, flags=re.I),
# 10-digit NDC without dashes (some formats)
_p(r'(?:NDC)[:\s#]+(\d{10,11})\b', 'NDC', 0.88, 1, flags=re.I),

# === Room/Bed Numbers ===
# Hospital room numbers - require context
_p(r'(?:Room|Rm\.?|Unit)[:\s#]+(\d{1,4}[A-Z]?)\b', 'ROOM_NUMBER', 0.88, 1, flags=re.I),
_p(r'(?:Bed|Bay)[:\s#]+(\d{1,2}[A-Z]?)\b', 'BED_NUMBER', 0.88, 1, flags=re.I),
# Combined: "Room 412, Bed 3" or "Room 412-B"
_p(r'(?:Room|Rm\.?)\s*(\d{1,4}[-]?[A-Z]?),?\s*(?:Bed|Bay)\s*(\d{1,2}[A-Z]?)', 'ROOM_NUMBER', 0.90, flags=re.I),
# Floor + Room: "4th floor, room 412" or "Floor 4 Room 12"
_p(r'(?:Floor|Fl\.?)\s*(\d{1,2})\s*[,\s]+(?:Room|Rm\.?)\s*(\d{1,4})', 'ROOM_NUMBER', 0.85, flags=re.I),

# === Pager Numbers ===
_p(r'(?:Pager|Beeper|Pgr\.?)[:\s#]+(\d{3}[-.\s]?\d{3}[-.\s]?\d{4})', 'PAGER', 0.90, 1, flags=re.I),
_p(r'(?:Pager|Pgr\.?)[:\s#]+(\d{4,7})\b', 'PAGER', 0.85, 1, flags=re.I),  # Short pager codes

# === Extension Numbers ===
_p(r'(?:ext\.?|extension|x)[:\s#]*(\d{3,6})\b', 'PHONE_EXT', 0.85, 1, flags=re.I),
# Phone with extension: "555-1234 ext 567"
_p(r'(\d{3}[-.\s]?\d{3}[-.\s]?\d{4})\s*(?:ext\.?|x)\s*(\d{3,6})', 'PHONE', 0.90, flags=re.I),

# === Prior Authorization / Claim Numbers ===
_p(r'(?:Prior\s*Auth(?:orization)?|PA)[:\s#]+([A-Z0-9]{6,20})', 'AUTH_NUMBER', 0.90, 1, flags=re.I),
_p(r'(?:Auth(?:orization)?\s*(?:Number|No|#|Code))[:\s#]+([A-Z0-9]{6,20})', 'AUTH_NUMBER', 0.88, 1, flags=re.I),
_p(r'(?:Pre-?cert(?:ification)?)[:\s#]+([A-Z0-9]{6,20})', 'AUTH_NUMBER', 0.88, 1, flags=re.I),
# Workers comp claim
_p(r'(?:Workers?\s*Comp|WC)\s*(?:Claim)?[:\s#]+([A-Z0-9]{6,20})', 'CLAIM_NUMBER', 0.88, 1, flags=re.I),


# PHYSICAL IDENTIFIERS (with strong context to avoid FPs)
# === Blood Type ===
_p(r'(?:Blood\s*Type|Blood\s*Group|ABO)[:\s]+([ABO]{1,2}[+-])', 'BLOOD_TYPE', 0.92, 1, flags=re.I),
_p(r'(?:Type)[:\s]+([ABO]{1,2}[+-])(?:\s+blood|\s+Rh)', 'BLOOD_TYPE', 0.88, 1, flags=re.I),

# === Height (with context) ===
_p(r'(?:Height|Ht\.?)[:\s]+(\d{1,2}[\'′]\s*\d{1,2}[\"″]?)', 'HEIGHT', 0.90, 1, flags=re.I),  # 5'10" format
_p(r'(?:Height|Ht\.?)[:\s]+(\d{2,3})\s*(?:cm|in(?:ches)?)', 'HEIGHT', 0.88, 1, flags=re.I),  # metric/inches
_p(r'(?:Height|Ht\.?)[:\s]+(\d\s*ft\.?\s*\d{1,2}\s*in\.?)', 'HEIGHT', 0.88, 1, flags=re.I),  # "5 ft 10 in"

# === Weight (with context) ===
_p(r'(?:Weight|Wt\.?)[:\s]+(\d{2,3})\s*(?:lbs?|pounds?|kg|kilograms?)', 'WEIGHT', 0.88, 1, flags=re.I),
_p(r'(?:Weight|Wt\.?)[:\s]+(\d{2,3}(?:\.\d)?)\s*(?:lbs?|kg)', 'WEIGHT', 0.88, 1, flags=re.I),

# === BMI (with context) ===
_p(r'(?:BMI|Body\s*Mass\s*Index)[:\s]+(\d{2}(?:\.\d{1,2})?)', 'BMI', 0.90, 1, flags=re.I),


# GEOGRAPHIC IDENTIFIERS
# === GPS Coordinates ===
# Decimal degrees: 41.8781, -87.6298 or 41.8781° N, 87.6298° W
_p(r'(-?\d{1,3}\.\d{4,8})[,\s]+(-?\d{1,3}\.\d{4,8})', 'GPS_COORDINATES', 0.88, 0),
_p(r'(\d{1,3}\.\d{4,8})°?\s*[NS][,\s]+(\d{1,3}\.\d{4,8})°?\s*[EW]', 'GPS_COORDINATES', 0.92, flags=re.I),
# DMS format: 41°52'43"N 87°37'47"W
_p(r'(\d{1,3}°\d{1,2}[\'′]\d{1,2}[\"″]?[NS])\s*(\d{1,3}°\d{1,2}[\'′]\d{1,2}[\"″]?[EW])', 'GPS_COORDINATES', 0.90, 0),
# With label
_p(r'(?:GPS|Coordinates?|Location|Lat(?:itude)?[/,]\s*Lon(?:gitude)?)[:\s]+(.{10,40})', 'GPS_COORDINATES', 0.85, 1, flags=re.I),


# INTERNATIONAL IDENTIFIERS (with context/checksums)
# === UK NHS Number (10 digits with checksum) ===
_p(r'(?:NHS|National\s+Health)[:\s#]+(\d{3}\s?\d{3}\s?\d{4})', 'NHS_NUMBER', 0.92, 1, flags=re.I),
_p(r'(?:NHS)[:\s#]+(\d{10})\b', 'NHS_NUMBER', 0.90, 1, flags=re.I),

# === Canadian SIN (9 digits, starts with specific digits) ===
_p(r'(?:SIN|Social\s+Insurance)[:\s#]+(\d{3}[-\s]?\d{3}[-\s]?\d{3})', 'SIN', 0.92, 1, flags=re.I),
# Bare SIN with Canadian context
_p(r'(?:Canada|Canadian|CA)[^.]{0,30}(\d{3}[-\s]?\d{3}[-\s]?\d{3})', 'SIN', 0.80, 1, flags=re.I),

# === Australian TFN (Tax File Number - 8-9 digits) ===
_p(r'(?:TFN|Tax\s+File)[:\s#]+(\d{3}\s?\d{3}\s?\d{2,3})', 'TFN', 0.92, 1, flags=re.I),

# === Indian Aadhaar (12 digits with specific format) ===
_p(r'(?:Aadhaar|UIDAI|Aadhar)[:\s#]+(\d{4}\s?\d{4}\s?\d{4})', 'AADHAAR', 0.92, 1, flags=re.I),
_p(r'(?:Aadhaar|UIDAI)[:\s#]+(\d{12})\b', 'AADHAAR', 0.90, 1, flags=re.I),

# === Mexican CURP (18 alphanumeric, specific format) ===
_p(r'(?:CURP)[:\s#]+([A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d)', 'CURP', 0.95, 1, flags=re.I),

# === German Sozialversicherungsnummer (12 digits) ===
_p(r'(?:Sozialversicherungsnummer|SVNR|SV-Nummer)[:\s#]+(\d{2}\s?\d{6}\s?[A-Z]\s?\d{3})', 'SVNR', 0.92, 1, flags=re.I),


)


# VALIDATORS

def _validate_ip(ip: str) -> bool:
    """Validate IP address octets are 0-255."""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        # Non-numeric octets - invalid IP
        return False


# Invalid US area codes - these should not be detected as valid phone numbers
_INVALID_AREA_CODES = frozenset({
    '000',  # Invalid
    '555',  # Reserved for fictional use (555-0100 to 555-0199 are real directory assistance)
    '911',  # Emergency services
    '411',  # Directory assistance
    '611',  # Repair service
    '711',  # TDD relay
    '811',  # Utility locator
    '311',  # Non-emergency municipal
    '211',  # Community services
    '511',  # Traffic/road conditions
})


def _validate_phone(phone: str) -> bool:
    """
    Validate US phone number.

    Rejects:
    - Invalid area codes (000, 555, etc.)
    - All zeros (000-000-0000)
    - Sequential/repeated digits that are likely test data
    """
    # Extract digits only
    digits = ''.join(c for c in phone if c.isdigit())

    # Must have at least 10 digits for US number
    if len(digits) < 10:
        return True  # Can't validate, allow through

    # Get area code (first 3 digits for US)
    area_code = digits[:3]

    # Reject invalid area codes
    if area_code in _INVALID_AREA_CODES:
        return False

    # Reject all zeros
    if digits[:10] == '0000000000':
        return False

    # Reject sequential digits (1234567890)
    if digits[:10] == '1234567890':
        return False

    # Reject repeated digits (1111111111, 2222222222, etc.)
    if len(set(digits[:10])) == 1:
        return False

    return True


def _validate_date(month: int, day: int, year: int) -> bool:
    """
    Validate date is a real calendar date.

    Checks:
    - Month 1-12
    - Day appropriate for month (handles Feb 28/29, 30-day months)
    - Year in reasonable range (1900-2100)
    """
    # Basic year check
    if not (1900 <= year <= 2100):
        return False

    # Month check
    if not (1 <= month <= 12):
        return False

    # Days per month (non-leap year)
    days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

    # Check for leap year
    is_leap = (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
    if is_leap and month == 2:
        max_day = 29
    else:
        max_day = days_in_month[month]

    return 1 <= day <= max_day


def _validate_age(value: str) -> bool:
    """Validate age is reasonable (0-125)."""
    try:
        age = int(value)
        return 0 <= age <= 125
    except ValueError:
        # Non-numeric age value - invalid
        return False


def _validate_luhn(number: str) -> bool:
    """
    Validate a number using the Luhn algorithm.
    Used for credit cards and NPIs.
    """
    # Remove spaces and dashes
    digits = ''.join(c for c in number if c.isdigit())
    if not digits:
        return False

    total = 0
    for i, digit in enumerate(reversed(digits)):
        d = int(digit)
        if i % 2 == 1:  # Double every second digit from right
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _validate_vin(vin: str) -> bool:
    """
    Validate VIN check digit (position 9).
    """
    if len(vin) != 17:
        return False

    # Transliteration values
    trans = {
        'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
        'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
        'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
    }

    # Position weights
    weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]

    try:
        total = 0
        for i, char in enumerate(vin.upper()):
            if char.isdigit():
                value = int(char)
            elif char in trans:
                value = trans[char]
            else:
                return False  # Invalid character
            total += value * weights[i]

        check = total % 11
        check_char = 'X' if check == 10 else str(check)
        return vin[8].upper() == check_char
    except (ValueError, IndexError):
        # VIN too short or contains invalid characters
        return False


# Words that precede numbers but indicate non-SSN context
_SSN_FALSE_POSITIVE_PREFIXES = frozenset([
    'page', 'pg', 'room', 'rm', 'order', 'ref', 'reference', 'invoice',
    'confirmation', 'tracking', 'case', 'ticket', 'claim', 'check',
    'acct', 'record', 'file', 'document', 'doc',
    'no', 'num', '#', 'code', 'pin', 'serial', 'model',
    'part', 'item', 'sku', 'upc', 'isbn', 'version', 'ver',
    'batch', 'lot', 'catalog', 'product', 'unit', 'id',
    'make', 'type', 'series',  # Added for "Model ABC-123456789"
])

# Regex to find these prefixes in a wider window
_SSN_FP_PATTERN = re.compile(
    r'\b(' + '|'.join(re.escape(w) for w in _SSN_FALSE_POSITIVE_PREFIXES) + r')\b',
    re.IGNORECASE
)


def _validate_ssn_context(text: str, start: int, confidence: float) -> bool:
    """
    Check if a 9-digit number is likely NOT an SSN based on preceding context.
    
    Only applies to LOW confidence (unlabeled) SSN matches.
    Returns True if it looks like a valid SSN context, False to reject.
    """
    # Only filter low-confidence bare 9-digit matches
    if confidence > 0.75:
        return True

    # Look at the 30 characters before the match (wider window)
    prefix_start = max(0, start - 30)
    prefix = text[prefix_start:start].lower()

    # Check if any false positive word appears in the prefix
    if _SSN_FP_PATTERN.search(prefix):
        return False

    # Also check immediate prefix for separators like "# " or ": "
    immediate_prefix = prefix[-5:].strip() if len(prefix) >= 5 else prefix.strip()
    if immediate_prefix.endswith(('#', ':', '.', '-')):
        before_sep = prefix[:-1].strip()
        for fp_word in _SSN_FALSE_POSITIVE_PREFIXES:
            if before_sep.endswith(fp_word):
                return False

    return True


# DETECTOR

@register_detector
class PatternDetector(BaseDetector):
    """
    Tier 2 detector: Regex patterns with format validation.
    
    Confidence varies by pattern (0.70 - 0.96).
    Labeled patterns get higher confidence.
    """

    name = "pattern"
    tier = Tier.PATTERN

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        seen: dict[tuple[int, int, str], int] = {}  # (start, end, entity_type) -> index in spans

        for idx, pdef in enumerate(PATTERNS):
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

                # Post-validation for specific types
                if pdef.entity_type == 'IP_ADDRESS' and not _validate_ip(value):
                    continue

                # Phone validation - reject invalid area codes and test numbers
                if pdef.entity_type in ('PHONE', 'PHONE_MOBILE', 'PHONE_HOME', 'PHONE_WORK', 'FAX'):
                    if not _validate_phone(value):
                        continue

                # Date validation - check if pattern captured numeric groups
                # Uses _validate_date for proper month/day checking (e.g., rejects Feb 31)
                if pdef.entity_type in ('DATE', 'DATE_DOB') and match.lastindex and match.lastindex >= 3:
                    try:
                        g1, g2, g3 = match.group(1), match.group(2), match.group(3)
                        if g1.isdigit() and g2.isdigit() and g3.isdigit():
                            if len(g1) == 4:  # YYYY-MM-DD
                                y, m, d = int(g1), int(g2), int(g3)
                            else:  # MM/DD/YYYY or DD/MM/YYYY
                                m, d, y = int(g1), int(g2), int(g3)
                            if not _validate_date(m, d, y):
                                continue
                    except (ValueError, IndexError) as e:
                        # Date parsing failed - accept match without validation
                        # This handles edge cases where regex groups don't match expected format
                        logger.debug(
                            f"Date validation skipped for '{value}': {type(e).__name__}: {e}"
                        )

                # Age validation - reject impossible ages
                if pdef.entity_type == 'AGE' and not _validate_age(value):
                    continue

                # SSN context validation
                if pdef.entity_type == 'SSN' and not _validate_ssn_context(text, start, pdef.confidence):
                    continue

                # Credit card Luhn validation
                if pdef.entity_type == 'CREDIT_CARD' and not _validate_luhn(value):
                    continue

                # VIN validation (for low-confidence bare VIN matches)
                if pdef.entity_type == 'VIN' and pdef.confidence < 0.90:
                    if not _validate_vin(value):
                        continue

                # Name false positive filter
                if pdef.entity_type in ('NAME', 'NAME_PROVIDER', 'NAME_PATIENT', 'NAME_RELATIVE'):
                    if _is_false_positive_name(value):
                        continue

                # Deduplication: skip if same span already seen with equal or higher confidence
                key = (start, end, pdef.entity_type)
                if key in seen:
                    existing_idx = seen[key]
                    if pdef.confidence <= spans[existing_idx].confidence:
                        continue
                    # Replace existing span with higher-confidence match
                    spans[existing_idx] = Span(
                        start=start,
                        end=end,
                        text=value,
                        entity_type=pdef.entity_type,
                        confidence=pdef.confidence,
                        detector=self.name,
                        tier=self.tier,
                    )
                    continue

                span = Span(
                    start=start,
                    end=end,
                    text=value,
                    entity_type=pdef.entity_type,
                    confidence=pdef.confidence,
                    detector=self.name,
                    tier=self.tier,
                )
                seen[key] = len(spans)
                spans.append(span)

        return spans
