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

    # Transition words/adverbs that start sentences (capitalized after periods)
    "ALSO", "HENCE", "SPECIFICALLY", "ADDITIONALLY", "FURTHERMORE",
    "MOREOVER", "HOWEVER", "THEREFORE", "MEANWHILE", "CONSEQUENTLY",
    "NEVERTHELESS", "OTHERWISE", "ACCORDINGLY", "SUBSEQUENTLY",

    # Job titles, departments, roles
    "STAFF", "DEPARTMENT", "STUDENTS", "PARENTS", "CLIENT", "CLIENTS",
    "ENGINEER", "DEVELOPER", "LIAISON", "PLANNER", "MANAGER", "DIRECTOR",
    "ANALYST", "SPECIALIST", "COORDINATOR", "ADMINISTRATOR", "OFFICER",
    "CONSULTANT", "ARCHITECT", "DESIGNER", "TECHNICIAN", "ASSISTANT",
    "SUPERVISOR", "INTERN", "VOLUNTEER", "NURSE", "THERAPIST",
    "COUNSELOR", "INSTRUCTOR", "PROFESSOR", "TEACHER", "TUTOR",
    "ATTENTION", "POSITION", "OPERATIONS", "BRANDING",
    "NEUROPSYCHOLOGISTS", "NEUROPSYCHOLOGIST",
    "PARENT", "GUARDIAN", "STUDENT",
    # Additional job/role words from FP analysis
    "AGENT", "SOLICITOR", "REPRESENTATIVE", "INTEGRATION",
    "MARKETING", "RESEARCH", "DISTRICT", "INTERNAL", "EXTERNAL",
    "PRINCIPAL", "SENIOR", "JUNIOR", "LEAD", "CHIEF", "HEAD",
    "EXECUTIVE", "ASSOCIATE", "CAPTAIN", "SERGEANT", "LIEUTENANT",
    "DETECTIVE", "INSPECTOR", "DEPUTY", "GENERAL", "VICE",
    "STRATEGIC", "GLOBAL", "REGIONAL", "NATIONAL", "INTERNATIONAL",
    "COMPLIANCE", "LEGAL", "HUMAN", "PHYSICAL", "TECHNICAL",
    "DIVISION", "CORPORATE", "CENTRAL",

    # Currencies (appear capitalized in "form of X Dollar")
    "DOLLAR", "DINAR", "RIAL", "EURO", "POUND", "FRANC", "YEN",
    "WON", "PESO", "RUPEE", "LIRA", "KRONA", "KRONE", "BAHT",
    "YUAN", "RUBLE", "RAND", "RINGGIT", "SHEKEL",

    # Greeting words that shouldn't be detected as names themselves
    "HEY", "YO", "SUP",

    # Other common capitalized words
    "CRITICAL", "FORWARD", "LEGACY", "MOBILITY", "CREATIVE",
    "INFRASTRUCTURE", "TRANS",

    # Common nouns/verbs from FP analysis (detected as names at sentence start)
    "TEAM", "PLEASE", "REMEMBER", "CONSIDER", "NOTICE",
    "STRATEGIST", "MEDICINE", "GERIATRIC", "PSYCHOLOGY",
    "PEDIATRIC", "CARDIOLOGY", "ONCOLOGY", "RADIOLOGY",
    "ORTHOPEDIC", "NEUROLOGY", "DERMATOLOGY", "PATHOLOGY",
    "SCIENCES", "SCIENCE", "TECHNOLOGY", "ENGINEERING",
    "TOGETHER", "EVERYONE", "SOMEONE", "WELCOME",
    "CERTAIN", "THROUGH", "WITHIN", "WITHOUT",
    "SEVERAL", "VARIOUS", "ANOTHER", "WHETHER",
    "CONTINUE", "FOLLOWING", "REGARDING", "INCLUDING",
    "PROVIDED", "AVAILABLE", "IMPORTANT", "NECESSARY",
    "POSSIBLE", "EXPECTED", "REQUIRED", "EXISTING",
    "SCHEDULED", "APPROVED", "RECOMMENDED", "EFFECTIVE",
    "LOCATED", "ASSIGNED", "RECEIVED", "PREPARED",
    "ATTACHED", "ENCLOSED", "REFERENCE", "REFERRAL",

    # County/geographic false positives
    "COUNTY", "TOWNSHIP", "BOROUGH", "PARISH", "PROVINCE",
    "TERRITORY", "MUNICIPALITY", "PREFECTURE",
    "SAFARI", "MOZILLA", "GECKO", "WEBKIT",

    # Financial/account terms (prevent "Savings Account" -> NAME)
    "SAVINGS", "CHECKING", "INVESTMENT", "MORTGAGE", "PROPERTY",
    "LOAN", "DEPOSIT", "WITHDRAWAL", "TRANSFER", "PREMIUM",
    "BALANCE", "CREDIT", "DEBIT", "INTEREST", "DIVIDEND",

    # Common phrases/words from remaining FP analysis
    "DISTANCE", "LEARNING", "ADVOCACY", "JUSTICE",
    "HOWDY", "CURRENTLY", "YESTERDAY", "KINDLY",
    "GREETINGS", "NEITHER", "PRODUCT", "PRODUCTS",
    "ARTS", "EDUCATION", "ENGLISH", "COMPOSITION",
    "SPECIAL", "SECURITIES", "HEALTH", "ACADEMIC",
    "BITCOIN", "LITECOIN", "ETHEREUM", "CRYPTO",
    "TRANSGENDER", "NONBINARY", "FUTURES", "INTERACTIONS",
    "VERDE", "GUILDER", "KORUNA", "SHILLING",
    "DESIGNER", "SOLUTIONS", "TECHNICIAN",
    "PROGRAM", "PROGRAMMES", "INITIATIVE",

    # Gretel PII FP analysis — domain phrases detected as names
    "ROOM", "TYPE", "ACCESS", "LEVEL", "ENERGY", "UTILITIES",
    "DEFENDANT", "NUMBERS", "RECORD", "RECORDS", "SYSTEM",
    "AVIONICS", "ROTTERDAM", "NETHERLANDS", "AMSTERDAM",
    "PLAINTIFF", "HOLDER", "AUTHOR", "LOAN",
    "REASON", "MARINE", "SUMMIT", "AVIATION", "LOGISTICS",
    "INDUSTRIAL", "COMMERCIAL", "RESIDENTIAL",
    "MUNICIPAL", "REGULATORY", "JUDICIAL",

    # AI4Privacy 10k FP analysis — gender identity terms detected as names
    "CISGENDER", "TRANSEXUAL", "TRANSSEXUAL", "NEUTROIS",
    "GENDERQUEER", "GENDERFLUID", "AGENDER", "BIGENDER",
    "PANGENDER", "ANDROGYNOUS", "INTERSEX",
    # Common words/phrases detected as names at scale
    "PRODUCER", "PARTICULARLY", "NOTABLY", "LASTLY",
    "ALTERNATIVELY", "CONSEQUENTLY", "SUBSEQUENTLY",
    "ADDITIONALLY", "FURTHERMORE", "MEANWHILE",
    "PREVIOUSLY", "PRIMARILY", "ESSENTIALLY",
    "NOW", "THIS", "FORWARD", "HUMAN", "SAMPLE",
    "COLLECTION", "TERMINATION", "MEMORIAL",
    "VETERAN", "VETERANS", "PRAIRIE", "COUNTY",
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

    # If ANY word is a currency, reject (catches "Bahraini Dinar", "Singapore Dollar")
    _CURRENCY_WORDS = {
        "DOLLAR", "DINAR", "RIAL", "EURO", "POUND", "FRANC", "YEN", "WON",
        "PESO", "RUPEE", "LIRA", "KRONA", "KRONE", "BAHT", "YUAN", "RUBLE",
        "RAND", "RINGGIT", "SHEKEL", "OMANI", "BAHRAINI", "SINGAPORE",
        "ZIMBABWE", "CURRENCY",
    }
    if any(w.upper() in _CURRENCY_WORDS for w in words):
        return True

    # If ANY word is a common non-name word (job titles, departments, roles)
    # and the match has multiple words, reject
    _ROLE_WORDS = {
        "STAFF", "DEPARTMENT", "ENGINEER", "DEVELOPER", "PLANNER", "MANAGER",
        "DIRECTOR", "ANALYST", "SPECIALIST", "COORDINATOR", "NURSE", "CARE",
        "MOBILITY", "CREATIVE", "INFRASTRUCTURE", "NEUROPSYCHOLOGISTS",
        "NEUROPSYCHOLOGIST",
    }
    if len(words) >= 2 and any(w.upper() in _ROLE_WORDS for w in words):
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
    r'Row|Mews|Close|Gardens|Gdn|Estate|Estates|'
    # Additional USPS / international suffixes
    r'Brook|Brooks|Spring|Springs|Knoll|Knolls|'
    r'Mountain|Mountains|Extension|Ext|Gateway|Causeway|'
    r'Stream|Junction|Junctions|Jct|Field|Fields|'
    r'Island|Islands|Corner|Corners|Tunnel|Tun|'
    r'Cliffs?|Oval|Shoal|Shoals|Haven|Ranch|'
    r'Bypass|Ferry|Trace|Grove|Grv|'
    r'Village|Villages|Vlg|Harbor|Harbors|'
    r'Fort|Ft|Falls|Creek|Crescent|'
    r'Meadow|Meadows|Shores?|Stravenue|Spur|'
    r'Crossroad|Crossroads|Overpass|Camp|'
    r'Squares|Circles|Drives|Lanes|Roads'
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

# === Validators for international government IDs ===
# These must be defined before PATTERNS tuple since patterns reference them.


def _validate_ein(value: str) -> bool:
    """Validate US EIN campus code prefix (first 2 digits)."""
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 9:
        return False
    prefix = int(digits[:2])
    return (
        (1 <= prefix <= 6) or (10 <= prefix <= 16) or
        (20 <= prefix <= 27) or (30 <= prefix <= 38) or
        (40 <= prefix <= 48) or (50 <= prefix <= 59) or
        (60 <= prefix <= 68) or (71 <= prefix <= 77) or
        (80 <= prefix <= 88) or (90 <= prefix <= 93) or
        prefix in (98, 99)
    )


def _validate_uk_nino(value: str) -> bool:
    """Validate UK National Insurance Number prefix exclusions."""
    cleaned = value.upper().replace(' ', '')
    if len(cleaned) != 9:
        return False
    prefix = cleaned[:2]
    invalid_prefixes = {'BG', 'GB', 'NK', 'KN', 'NT', 'TN', 'ZZ'}
    return prefix not in invalid_prefixes


def _validate_es_nie(value: str) -> bool:
    """Validate Spanish NIE check letter (mod-23)."""
    letters = 'TRWAGMYFPDXBNJZSQVHLCKE'
    v = value.upper()
    if len(v) != 9:
        return False
    prefix_map = {'X': '0', 'Y': '1', 'Z': '2'}
    num_str = prefix_map.get(v[0], '') + v[1:8]
    try:
        return letters[int(num_str) % 23] == v[8]
    except (ValueError, IndexError):
        return False


def _validate_es_nif(value: str) -> bool:
    """Validate Spanish NIF check letter (mod-23)."""
    letters = 'TRWAGMYFPDXBNJZSQVHLCKE'
    v = value.upper()
    if len(v) != 9:
        return False
    try:
        return letters[int(v[:8]) % 23] == v[8]
    except (ValueError, IndexError):
        return False


def _validate_pl_pesel(value: str) -> bool:
    """Validate Polish PESEL using weighted checksum."""
    if len(value) != 11 or not value.isdigit():
        return False
    weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
    total = sum(int(d) * w for d, w in zip(value[:10], weights))
    check = (10 - (total % 10)) % 10
    return check == int(value[10])


def _validate_nhs(value: str) -> bool:
    """Validate UK NHS Number using mod-11 checksum."""
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 10:
        return False
    total = sum(int(d) * w for d, w in zip(digits[:9], range(10, 1, -1)))
    remainder = 11 - (total % 11)
    if remainder == 11:
        remainder = 0
    if remainder == 10:
        return False  # Invalid NHS number
    return remainder == int(digits[9])


# ---------------------------------------------------------------------------
# EU MULTILINGUAL VALIDATORS
# ---------------------------------------------------------------------------

def _validate_nl_bsn(value: str) -> bool:
    """Validate Dutch BSN (Burgerservicenummer) using 11-proof checksum.

    The BSN is 9 digits where:
    9*d1 + 8*d2 + 7*d3 + 6*d4 + 5*d5 + 4*d6 + 3*d7 + 2*d8 - 1*d9
    must be divisible by 11 and != 0.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 9:
        return False
    d = [int(c) for c in digits]
    total = 9*d[0] + 8*d[1] + 7*d[2] + 6*d[3] + 5*d[4] + 4*d[5] + 3*d[6] + 2*d[7] - 1*d[8]
    return total % 11 == 0 and total != 0


def _validate_fr_nir(value: str) -> bool:
    """Validate French NIR (Numero d'Inscription au Repertoire) / INSEE number.

    15 digits: sex(1) + birth_year(2) + birth_month(2) + dept(2-3) +
    commune(2-3) + order(3) + key(2).  Key = 97 - (number mod 97).
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 15:
        return False
    # Sex digit must be 1 or 2
    if digits[0] not in ('1', '2'):
        return False
    # Month 01-12 (or 20-42 for overseas/special)
    month = int(digits[3:5])
    if not (1 <= month <= 12 or 20 <= month <= 42):
        return False
    # Mod-97 key check
    number = int(digits[:13])
    key = int(digits[13:15])
    return 97 - (number % 97) == key


def _validate_de_steuer_id(value: str) -> bool:
    """Validate German Steuerliche Identifikationsnummer (Tax ID).

    11 digits: first digit != 0, exactly one digit appears twice,
    exactly one digit is missing from 0-9, last digit is a check digit.
    Uses modified ISO 7064 Mod 11,10 algorithm.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 11:
        return False
    if digits[0] == '0':
        return False
    # Check digit validation (ISO 7064 Mod 11,10)
    product = 10
    for i in range(10):
        s = (int(digits[i]) + product) % 10
        if s == 0:
            s = 10
        product = (s * 2) % 11
    check = (11 - product) % 10
    return check == int(digits[10])


def _validate_el_amka(value: str) -> bool:
    """Validate Greek AMKA (social security number).

    11 digits: DDMMYY + 5-digit serial.  Uses Luhn checksum.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 11:
        return False
    # Basic date validation (DDMMYY)
    day, month = int(digits[0:2]), int(digits[2:4])
    if not (1 <= day <= 31 and 1 <= month <= 12):
        return False
    # Luhn checksum
    total = 0
    for i, d in enumerate(digits):
        n = int(d)
        if i % 2 == 1:  # 0-indexed, so odd positions are doubled
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _validate_el_afm(value: str) -> bool:
    """Validate Greek AFM (tax identification number).

    9 digits with weighted checksum. Last digit is check digit.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 9:
        return False
    # Weights: 256, 128, 64, 32, 16, 8, 4, 2 for positions 0-7
    total = sum(int(digits[i]) * (1 << (8 - i)) for i in range(8))
    check = (total % 11) % 10
    return check == int(digits[8])


def _validate_br_cpf(value: str) -> bool:
    """Validate Brazilian CPF (Cadastro de Pessoa Fisica).

    11 digits with two check digits.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 11:
        return False
    # Reject known invalid sequences (all same digit)
    if digits == digits[0] * 11:
        return False
    # First check digit
    total = sum(int(digits[i]) * (10 - i) for i in range(9))
    remainder = (total * 10) % 11
    if remainder == 10:
        remainder = 0
    if remainder != int(digits[9]):
        return False
    # Second check digit
    total = sum(int(digits[i]) * (11 - i) for i in range(10))
    remainder = (total * 10) % 11
    if remainder == 10:
        remainder = 0
    return remainder == int(digits[10])


def _validate_br_cnpj(value: str) -> bool:
    """Validate Brazilian CNPJ (Cadastro Nacional da Pessoa Juridica).

    14 digits with two check digits.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 14:
        return False
    if digits == digits[0] * 14:
        return False
    # First check digit
    weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(int(digits[i]) * weights1[i] for i in range(12))
    remainder = total % 11
    check1 = 0 if remainder < 2 else 11 - remainder
    if check1 != int(digits[12]):
        return False
    # Second check digit
    weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(int(digits[i]) * weights2[i] for i in range(13))
    remainder = total % 11
    check2 = 0 if remainder < 2 else 11 - remainder
    return check2 == int(digits[13])


def _validate_pt_nif(value: str) -> bool:
    """Validate Portuguese NIF (Numero de Identificacao Fiscal).

    9 digits.  First digit indicates entity type (1-3: individual, 5: legal, etc.).
    Mod-11 checksum.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 9:
        return False
    # Valid first digits
    if digits[0] not in ('1', '2', '3', '5', '6', '7', '8', '9'):
        return False
    # Mod-11 checksum
    total = sum(int(digits[i]) * (9 - i) for i in range(8))
    remainder = total % 11
    check = 0 if remainder < 2 else 11 - remainder
    return check == int(digits[8])


def _validate_si_emso(value: str) -> bool:
    """Validate Slovenian EMSO (Enotna Maticna Stevilka Obcana).

    13 digits: DDMMYYY + RR + SSS + C (same as former Yugoslav JMBG).
    Uses mod-11 weighted checksum.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 13:
        return False
    # Basic date validation
    day, month = int(digits[0:2]), int(digits[2:4])
    if not (1 <= day <= 31 and 1 <= month <= 12):
        return False
    # Mod-11 checksum
    weights = [7, 6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
    total = sum(int(digits[i]) * weights[i] for i in range(12))
    remainder = total % 11
    if remainder == 0:
        check = 0
    elif remainder == 1:
        return False  # Invalid EMSO
    else:
        check = 11 - remainder
    return check == int(digits[12])


# Company name fragment: handles Mc/Mac/O' prefixes (McGlynn, O'Reilly, MacDonald)
_COMPANY_NAME = r"(?:Mc|Mac|O')?[A-Z][a-z]+"

PATTERNS: tuple[PatternDefinition, ...] = (



# === Phone Numbers ===
_p(r'\((\d{3})\)\s*(\d{3})[-.]?(\d{4})', 'PHONE', 0.90),
_p(r'\b(\d{3})[-.](\d{3})[-.](\d{4})\b', 'PHONE', 0.85),
# International formats - no leading \b since + isn't a word character
_p(r'(?:^|(?<=\s))\+1[-.\s]?(\d{3})[-.\s]?(\d{3})[-.\s]?(\d{4})\b', 'PHONE', 0.90),
_p(r'(?:^|(?<=\s))\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b', 'PHONE', 0.85),
# International: parenthesized 2-digit area code (non-US)
_p(r'\((\d{2})\)[-.\s]?\d{3,4}[-.\s]?\d{4}\b', 'PHONE', 0.82),
# European: leading-zero area code with 8-10 total digits
_p(r'\b(0\d{2,4})[-.\s]\d{3,4}[-.\s]?\d{3,5}\b', 'PHONE', 0.80),
# Labeled phone - tighter pattern: only digits, spaces, dashes, parens, plus
_p(r'(?:phone|tel|fax|call|contact)[:\s]+([()\d\s+.-]{10,20})', 'PHONE', 0.92, 1, flags=re.I),
# "Reach us at" / "Call us at" / "Contact us at" — context indicating phone
_p(r'(?:reach|call|contact)\s+(?:us|me|them)\s+at\s+([()\d\s+.-]{7,20})', 'PHONE', 0.85, 1, flags=re.I),

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
_p(r'\b(\d{1,2})/(\d{1,2})/(\d{4})\b', 'DATE', 0.80),
_p(r'\b(\d{1,2})-(\d{1,2})-(\d{4})\b', 'DATE', 0.80),
_p(r'\b(\d{4})-(\d{1,2})-(\d{1,2})\b', 'DATE', 0.80),
# Dates with 2-digit years: "12/27/25", "01/15/24"
# Lower confidence due to ambiguity (could be scores, prices, etc.)
_p(r'\b(\d{1,2}/\d{1,2}/\d{2})\b', 'DATE', 0.65),
_p(r'\b(\d{1,2}-\d{1,2}-\d{2})\b', 'DATE', 0.65),

# Date with dots (European format): "15.03.1985" or "03.15.1985"
_p(r'(?:DOB|Date)[:\s]+(\d{1,2}\.\d{1,2}\.\d{4})', 'DATE', 0.85, 1, flags=re.I),
# Standalone dot-separated date (no label prefix): "15.03.1985", "03.15.2024"
# NOTE: Handled by the 3-group capture pattern in ADDITIONAL DATE PATTERNS
# section below, which enables proper date validation (month/day checking).
_p(r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b', 'DATE', 0.82, flags=re.I),
_p(r'\b\d{1,2}\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b', 'DATE', 0.82, flags=re.I),
# Edge case: "November 3., 1986" - day with period before comma/year (evasion pattern)
_p(r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}\.,\s*\d{4}\b', 'DATE', 0.78, flags=re.I),
# Abbreviated month names: "Oct 11, 1984", "Mar 19, 1988", "Jan 15th, 1980"
_p(r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}\b', 'DATE', 0.82, flags=re.I),
_p(r'\b\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{4}\b', 'DATE', 0.82, flags=re.I),
# DOB with abbreviated months
_p(r'(?:DOB|Date\s+of\s+Birth|Birth\s*date)[:\s]+((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4})', 'DATE_DOB', 0.95, 1, flags=re.I),
_p(r'(?:DOB|Date\s+of\s+Birth|Birth\s*date)[:\s]+(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})', 'DATE_DOB', 0.95, 1, flags=re.I),
# DOB in YYYY-MM-DD format (ISO): "DOB 1976-10-31", "Date of Birth: 2001-02-15"
_p(r'(?:DOB|Date\s+of\s+Birth|Birth\s*date)[:\s]+(\d{4}[/\-]\d{1,2}[/\-]\d{1,2})', 'DATE_DOB', 0.95, 1, flags=re.I),
_p(r'(?:admission|admit|discharge)[:\s]+(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})', 'DATE', 0.90, 1, flags=re.I),

# === Ordinal Date Formats ===
# "3rd of March, 1990", "1st of January, 2020"
_p(r'\b(\d{1,2}(?:st|nd|rd|th)\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)(?:\s*,?\s*\d{4})?)\b', 'DATE', 0.80, flags=re.I),
# "3rd of March" (without year), "22nd of December"
_p(r'\b(\d{1,2}(?:st|nd|rd|th)\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December))\b', 'DATE', 0.80, flags=re.I),
# "3rd March 1990", "1st January 2020" (ordinal without "of")
_p(r'\b(\d{1,2}(?:st|nd|rd|th)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)(?:\s*,?\s*\d{4})?)\b', 'DATE', 0.78, flags=re.I),
# "the 15th of January" (with "the"), optionally with year
_p(r'\b(the\s+\d{1,2}(?:st|nd|rd|th)\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)(?:\s*,?\s*\d{4})?)\b', 'DATE', 0.80, flags=re.I),
# Legal format: "the 12th day of January, 2023"
_p(r'\b((?:the\s+)?\d{1,2}(?:st|nd|rd|th)\s+day\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)(?:\s*,?\s*\d{4})?)\b', 'DATE', 0.85, flags=re.I),

# === Weekday + Date Formats ===
# "Fri, Mar 3, 2024", "Monday, January 15, 2024"
_p(r'\b((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\s*,?\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December)\.?\s+\d{1,2}\s*,?\s*\d{4})\b', 'DATE', 0.82, flags=re.I),

# === Date ranges with written months ===
# "between January 1 and January 15"
_p(r'\b((?:between|from)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2})\b', 'DATE', 0.80, flags=re.I),
_p(r'\b((?:and|to|through)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2})\b', 'DATE', 0.80, flags=re.I),
# "March 1-15, 2024" (date range with hyphen)
_p(r'\b((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}\s*[-–—]\s*\d{1,2}\s*,?\s*\d{4})\b', 'DATE', 0.78, flags=re.I),

# === Time ===
# Safe Harbor requires removal of time elements (they're part of date under HIPAA)
# Standard 12-hour: "11:30 PM", "9:42 AM", "11:30PM"
_p(r'\b(\d{1,2}:\d{2}\s*(?:AM|PM|am|pm|a\.m\.|p\.m\.))\b', 'TIME', 0.92, flags=re.I),
# With seconds: "11:30:45 PM"
_p(r'\b(\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM|am|pm|a\.m\.|p\.m\.))\b', 'TIME', 0.92, flags=re.I),
# Contextual: "at 3:30 PM", "@ 11:45"
_p(r'(?:at|@)\s*(\d{1,2}:\d{2}\s*(?:AM|PM|am|pm)?)\b', 'TIME', 0.92, 1, flags=re.I),
# Labeled: "Time: 14:30", "recorded at 2:15 PM"
_p(r'(?:time|recorded|documented|signed)[:\s]+(\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM|am|pm)?)', 'TIME', 0.92, 1, flags=re.I),

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
# Bare HH:MM (24-hour) — "04:52", "23:15"
# 0.72 confidence: slightly above default threshold.  Bare HH:MM is somewhat
# ambiguous (scores, verse refs, ratios) but PII benchmarks show most
# bare HH:MM tokens in real documents are genuine times.  Additional guard:
# negative lookahead rejects score-like "NN:NN-NN" and ratio "NN:NN/NN".
_p(r'\b(\d{2}:\d{2})\b(?!\s*[-/]\d)', 'TIME', 0.72, 1),
# Standalone AM/PM without colon: "8 AM", "12 PM", "3pm"
_p(r'\b(\d{1,2}\s*(?:AM|PM|am|pm|a\.m\.|p\.m\.))\b', 'TIME', 0.82, 1, flags=re.I),
# "by HH:MM", "before HH:MM", "after HH:MM", "until HH:MM"
_p(r'(?:by|before|after|until|around|about)\s+(\d{1,2}:\d{2}(?:\s*(?:AM|PM|am|pm))?)\b', 'TIME', 0.85, 1, flags=re.I),
# "N o'clock" — informal time expression
_p(r"\b(\d{1,2}\s*o'?\s*clock)\b", 'TIME', 0.88, 1, flags=re.I),

# === Age ===
# Standard forms: "46 years old", "46 year old"
_p(r'\b(\d{1,3})\s*(?:year|yr)s?\s*old\b', 'AGE', 0.90, 1, flags=re.I),
# Hyphenated form: "46-year-old" (common in clinical notes)
_p(r'\b(\d{1,3})[-‐‑–—]\s*(?:year|yr)s?[-‐‑–—]\s*old\b', 'AGE', 0.90, 1, flags=re.I),
# Abbreviations: "46 y/o", "46y/o", "46 yo", "46yo"
_p(r'\b(\d{1,3})\s*y/?o\b', 'AGE', 0.88, 1, flags=re.I),
# Labeled: "age 46", "aged 46"
_p(r'\b(?:age|aged)[:\s]+(\d{1,3})\b', 'AGE', 0.92, 1, flags=re.I),  # \b prevents matching "Page 123"
# "age (X)" — parenthetical age (e.g., "your age (40)")
_p(r'\bage\s*\((\d{1,3})\)', 'AGE', 0.92, 1, flags=re.I),

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

# "Patient X" or "Patient X Y" — without colon (common in medical notes)
_p(rf'\bPatient\s+({_NAME}(?:[ \t]+{_NAME}){{0,2}})(?=[,.\s])', 'NAME_PATIENT', 0.82, 1),

# Patient patterns - Mr/Mrs/Ms/Miss indicate patient (non-provider) in clinical context
# NOTE: \b required to prevent "symptoms" matching as "Ms" + name
_p(rf'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PATIENT', 0.90, 1, flags=re.I),
# Mr./Ms./Dr. WITHOUT space before name: "Mr.Kerluke", "Ms.North"
_p(rf'\b(?:Mr|Mrs|Ms|Dr)\.({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PATIENT', 0.90, 1),

# === NAME PREFIX PATTERNS ===
# Standalone honorific prefixes: "Mr.", "Ms.", "Mrs.", "Miss", "Dr."
# These are labeled as PREFIX in AI4Privacy and map to the "names" category.
_p(r'\b(Mr\.|Mrs\.|Ms\.|Miss|Dr\.)\s', 'PREFIX', 0.75, 1),

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

# === GREETING / DIRECT ADDRESS NAME PATTERNS ===
# These patterns detect names in common conversational contexts.
# High precision because they require specific greeting words + Capitalized name.
# NOTE: NO re.I flag on _NAME to preserve proper-noun requirement.

# "Dear X" / "Dear X Y" — salutation (nearly always a name)
_p(rf'\b(?i:Dear)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.90, 1),
# "Hi X" / "Hey X" / "Hello X" — informal greeting + name
_p(rf'\b(?i:Hi|Hey|Hello)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,1}})\b', 'NAME', 0.88, 1),
# "Good Morning/Afternoon/Evening X" — formal greeting
_p(rf'\b(?i:Good\s+(?:Morning|Afternoon|Evening|Day))[,.]?[ \t]+({_NAME})\b', 'NAME', 0.88, 1),
# "Thanks X" / "Thank you X" — closing with name
_p(rf'\b(?i:Thanks|Thank\s+you)[,]?[ \t]+({_NAME})\b', 'NAME', 0.82, 1),

# "for First Last" — referring to a person (requires 2-word name)
_p(rf'\bfor[ \t]+({_NAME}[ \t]+{_NAME})\b', 'NAME', 0.80, 1),
# "of First Last" — referring to a person (requires 2-word name)
_p(rf'\bof[ \t]+({_NAME}[ \t]+{_NAME})\b', 'NAME', 0.78, 1),
# "to First Last" — writing/sending to a person (requires 2-word name)
_p(rf'\bto[ \t]+({_NAME}[ \t]+{_NAME})\b', 'NAME', 0.78, 1),
# "Contact X" — instruction to reach someone
_p(rf'\b(?i:Contact)[ \t]+({_NAME})\b', 'NAME', 0.80, 1),
# "Attention X Y" — formal address
_p(rf'\b(?i:Attention)\s+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1),
# "Connect with X" / "Requested X to" / "Appointment reminder for X"
_p(rf'\b(?i:Connect\s+with|Requested|Remind(?:er)?\s+for|Consult(?:ation)?\s+(?:reminder\s+)?for)\s+({_NAME})\b', 'NAME', 0.80, 1),
# "for X on DATE" — single name + date context (e.g., "Appointment reminder for Stephen on 10/03/1976")
_p(rf'\bfor\s+({_NAME})\s+on\s+\d', 'NAME', 0.82, 1),
# "Hello/Dear Dr./Mr./Mrs. X" — greeting + honorific + name
_p(rf'\b(?i:Hello|Dear|Hi|Hey)\s+(?:Dr\.?|Mr\.?|Mrs\.?|Ms\.?|Miss|Prof\.?)[,.]?\s+({_NAME}(?:[ \t]+{_NAME}){{0,1}})\b', 'NAME', 0.88, 1),

# Direct address at start: "Name," followed by space + lowercase continuation
# "Delta, as per..." / "Jimmie, your understanding..."
_p(rf'(?:^|[.!?]\s+)({_NAME}),[ \t]+(?=[a-z])', 'NAME', 0.82, 1, flags=re.MULTILINE),
# "Name, your/you/we/please/could/can/would/as/this/the/a/our" — strong direct address signals
_p(rf'\b({_NAME}),[ \t]+(?:your|you(?:r|\b)|we\b|I\b|please\b|could\b|can\b|would\b|as\b|this\b|the\b|a\b|an\b|our\b)', 'NAME', 0.82, 1),
# Quoted direct address: '"Name, ...' at start of quote
_p(rf'["\u201c]({_NAME}),[ \t]', 'NAME', 0.82, 1),

# === NAME PREFIX / HONORIFIC PATTERNS ===
# Standalone prefixes — entity type PREFIX (matches ai4privacy ground truth)
# Require lookahead for capitalized word (likely a name)
_p(r'\b(Mr\.?|Mrs\.?|Ms\.?|Miss|Dr\.?|Prof\.?)\b(?=[ \t]+[A-ZÀ-ÖØ-Þ])', 'PREFIX', 0.88, 1),
# Prefix WITHOUT space directly before name: "Mr.Kerluke", "Ms.North", "Dr.Feeney"
_p(r'\b(Mr|Mrs|Ms|Dr)\.(?=[A-ZÀ-ÖØ-Þ])', 'PREFIX', 0.88, 1),
# Prefix at start of greeting context: "Hello Mr.", "Dear Dr."
_p(r'(?:Hello|Dear|Hi)\s+(Mr\.?|Mrs\.?|Ms\.?|Miss|Dr\.?|Prof\.?)\b', 'PREFIX', 0.85, 1, flags=re.I),
# Standalone bare prefix (no name following) — lower confidence
# Catches "Mr." / "Mrs." / "Dr." at end of fragment or before comma/period
_p(r'\b(Mr\.|Mrs\.|Ms\.|Miss|Dr\.)\s*(?=[,;:\.\)\]\n]|$)', 'PREFIX', 0.72, 1),
# Bare prefix followed by lowercase (likely sentence continuation): "Mr. said"
_p(r'\b(Mr\.|Mrs\.|Ms\.|Dr\.)\s+(?=[a-z])', 'PREFIX', 0.68, 1),

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
# NOTE: Removed bare [A-Z]{2,4}-\d{5,12} — too greedy, was stealing
# BIOMETRIC_ID (20), MRN (15), CERTIFICATE_NUMBER (14) detections.
# Labeled patterns in additional_patterns.py (0.88) and payer-prefix patterns
# (0.90) provide sufficient coverage for health plan IDs.
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

# Ordinal street names: "78244 N 5th Street", "123 3rd Avenue", "456 E 1st St"
# Standard patterns miss these because ordinal names start with digits, not [A-Z]
_p(
    rf'(\d+[A-Za-z]?\s+(?:{_DIRECTIONAL}\s+)?\d{{1,3}}(?:st|nd|rd|th)\s+(?:{_STREET_SUFFIXES}))\.?\b',
    'ADDRESS', 0.88, 1, flags=re.I
),
# Reversed format: "StreetName Suffix NNN" — "Kuhlman Run 755", "Baker Street 221B"
# Common in UK, Australian, and some European address styles.
# Single-word street name only — avoids "The Main Street 100" FP from greedy multi-word.
_p(
    rf'\b([A-Z][a-z]{{2,}}\s+(?:{_STREET_SUFFIXES})\s+\d{{1,5}}[A-Za-z]?)\b',
    'ADDRESS', 0.80, 1, flags=re.I
),
# Directional + StreetName + NNN: "S Broadway 61915"
_p(
    rf'({_DIRECTIONAL}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+\d{{1,5}})\b',
    'ADDRESS', 0.82, 1
),

# PO Box
_p(r'P\.?O\.?\s*Box\s+\d+', 'ADDRESS', 0.88, flags=re.I),

# Building/facility number context: "building 47817", "building number 7663"
_p(r'(?:building|bldg)\.?\s+(?:number\s+|no\.?\s+|#\s*)?(\d{2,6})\b', 'ADDRESS', 0.82, 1, flags=re.I),

# Context-based location: "lives in Springfield", "from Chicago"
# NOTE: No re.I flag - _CITY_NAME requires capitalized words to avoid matching
# everything after "from" (e.g., "from Los Angeles treated" would match too much)
_p(rf'(?:[Ll]ives?\s+in|[Ff]rom|[Rr]esident\s+of|[Ll]ocated\s+in|[Bb]ased\s+in|[Bb]orn\s+in)\s+({_CITY_NAME})', 'ADDRESS', 0.80, 1),

# === ZIP Code (standalone, labeled only) ===
_p(r'(?:ZIP|Postal|Zip\s*Code)[:\s]+(\d{5}(?:-\d{4})?)', 'ZIP', 0.95, 1, flags=re.I),
# "zipcode (84272)", "postal code 48258", "zip code: 62701"
_p(r'(?:zip\s*code|zipcode|postal\s*code)\s*[:\s(]+(\d{5}(?:-\d{4})?)\)?', 'ZIP', 0.92, 1, flags=re.I),

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

# === ZIP+4 Format (standalone, distinctive format XXXXX-XXXX) ===
# The dash-separated format is highly distinctive for ZIP codes
_p(r'\b(\d{5}-\d{4})\b', 'ZIP', 0.90, 1),

# === Context-based ZIP detection ===
# 5-digit codes near geographic/area context words
_p(r'(?:from|in|near|at|to|of|around)\s+(\d{5})\b(?!\s*[-.]?\d)', 'ZIP', 0.80, 1, flags=re.I),
# "XXXXX area", "XXXXX region", "XXXXX district", "XXXXX zip"
_p(r'\b(\d{5})\s+(?:area|region|district|zone|zip)\b', 'ZIP', 0.82, 1, flags=re.I),
# Leading-zero 5-digit codes are strongly indicative of ZIPs (most numbers don't start with 0)
_p(r'\b(0\d{4})\b(?!\s*[-.]?\d)', 'ZIP', 0.78, 1),
# After address components: "Apt. 418, 82608", "Suite 480, 78830"
_p(r'(?:Apt|Suite|Ste|Unit)\.?\s*#?\s*\d+\s*,\s*(\d{5})\b', 'ZIP', 0.82, 1, flags=re.I),
# After comma-separated place/region: "Fife, 45446", "Occitanie, 42746"
_p(r'[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s*,\s*(\d{5})\b(?!\s*[-.]?\d)', 'ZIP', 0.78, 1),

# === Standalone STATE Patterns ===
# US full state names (standalone, not part of address — lower confidence)
_p(rf'\b({_STATE_FULL})\b', 'STATE', 0.75, 1),
# International state/province/region names (common in ai4privacy dataset)
_p(r'\b(Baden-Württemberg|Saxony-Anhalt|Schleswig-Holstein|Mecklenburg-Vorpommern|'
   r'North\s+Rhine-Westphalia|Rhineland-Palatinate|Lower\s+Saxony|'
   r'North\s+West\s+England|North\s+East\s+England|South\s+West\s+England|'
   r'South\s+East\s+England|East\s+Midlands|West\s+Midlands|East\s+of\s+England|'
   r'Yorkshire\s+and\s+the\s+Humber|'
   r'Bavaria|Saxony|Thuringia|Brandenburg|Saarland|Hesse|'
   r'Corsica|Brittany|Normandy|Burgundy|Provence|Alsace|Aquitaine|'
   r'Uri|Zug|Zurich|Bern|Lucerne|Basel|Geneva|Vaud|Valais|Ticino|'
   r'Aargau|Fribourg|Graubünden|Thurgau|Solothurn|Schwyz|'
   r'New\s+South\s+Wales|Queensland|Victoria|Tasmania|'
   r'South\s+Australia|Western\s+Australia|Northern\s+Territory|'
   r'British\s+Columbia|Nova\s+Scotia|New\s+Brunswick|'
   r'Prince\s+Edward\s+Island|Newfoundland)\b', 'STATE', 0.78, 1),

# Italian regions/provinces
_p(r'\b(Abruzzo|Basilicata|Calabria|Campania|Emilia-Romagna|'
   r'Friuli\s+Venezia\s+Giulia|Lazio|Liguria|Lombardy|Marche|'
   r'Molise|Piedmont|Puglia|Apulia|Sardinia|Sicily|'
   r'Trentino-Alto\s+Adige|Tuscany|Umbria|'
   r'Aosta\s+Valley|Veneto)\b', 'STATE', 0.78, 1),

# French regions
_p(r'\b(Auvergne-Rhône-Alpes|Bourgogne-Franche-Comté|'
   r'Centre-Val\s+de\s+Loire|Grand\s+Est|Hauts-de-France|'
   r'Île-de-France|Nouvelle-Aquitaine|Occitanie|'
   r'Pays\s+de\s+la\s+Loire|'
   r'Picardy|Languedoc|Champagne|Lorraine|Limousin|'
   r'Poitou-Charentes|Midi-Pyrénées)\b', 'STATE', 0.78, 1),

# Additional Swiss cantons (missing from above)
_p(r'\b(Nidwalden|Obwalden|Appenzell|Glarus|'
   r'Schaffhausen|St\.?\s*Gallen|Neuchâtel|Jura)\b', 'STATE', 0.78, 1),

# Canadian provinces and territories (full set)
_p(r'\b(Alberta|Manitoba|Ontario|Quebec|Saskatchewan|'
   r'Yukon|Nunavut|Northwest\s+Territories)\b', 'STATE', 0.78, 1),

# Spanish autonomous communities
_p(r'\b(Andalusia|Aragon|Asturias|Balearic\s+Islands|'
   r'Basque\s+Country|Canary\s+Islands|Cantabria|'
   r'Castile\s+and\s+León|Castilla-La\s+Mancha|Catalonia|'
   r'Extremadura|Galicia|La\s+Rioja|Murcia|Navarre|Valencia)\b', 'STATE', 0.78, 1),

# Dutch provinces
_p(r'\b(Drenthe|Flevoland|Friesland|Gelderland|Groningen|'
   r'Limburg|Noord-Brabant|Noord-Holland|Overijssel|'
   r'Zuid-Holland|Zeeland|Utrecht)\b', 'STATE', 0.78, 1),

# Belgian provinces/regions
_p(r'\b(Wallonia|Flanders|Antwerp|Brabant|Hainaut|'
   r'Liège|Luxembourg|Namur)\b', 'STATE', 0.78, 1),

# Mexican states
_p(r'\b(Aguascalientes|Baja\s+California\s+Sur|Baja\s+California|Campeche|'
   r'Chiapas|Chihuahua|Coahuila|Colima|Durango|Guanajuato|Guerrero|'
   r'Hidalgo|Jalisco|México|Michoacán|Morelos|Nayarit|'
   r'Nuevo\s+León|Oaxaca|Puebla|Querétaro|Quintana\s+Roo|'
   r'San\s+Luis\s+Potosí|Sinaloa|Sonora|Tabasco|Tamaulipas|'
   r'Tlaxcala|Veracruz|Yucatán|Zacatecas)\b', 'STATE', 0.78, 1),

# === Standalone COUNTY Patterns ===
# "X County" or "County X" suffix/prefix
_p(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+County)\b', 'COUNTY', 0.82, 1),
_p(r'\b(County\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b', 'COUNTY', 0.82, 1),
# UK counties/regions (shire-ending and common counties)
_p(r'\b(Bedfordshire|Berkshire|Buckinghamshire|Cambridgeshire|Cheshire|'
   r'Cornwall|Cumbria|Derbyshire|Devon|Dorset|Durham|'
   r'Essex|Gloucestershire|Hampshire|Herefordshire|Hertfordshire|'
   r'Kent|Lancashire|Leicestershire|Lincolnshire|Norfolk|'
   r'Northamptonshire|Northumberland|Nottinghamshire|Oxfordshire|'
   r'Rutland|Shropshire|Somerset|Staffordshire|Suffolk|Surrey|'
   r'Sussex|West\s+Sussex|East\s+Sussex|Warwickshire|Wiltshire|'
   r'Worcestershire|Yorkshire|North\s+Yorkshire|South\s+Yorkshire|'
   r'East\s+Yorkshire|West\s+Yorkshire|'
   r'Gwynedd|Powys|Borders|Highlands|Lothian|'
   r'Clackmannanshire|Dumfries|Fife|Angus|Perth|Argyll|Moray)\b', 'COUNTY', 0.80, 1),
# Additional UK metropolitan counties and regions
_p(r'\b(Greater\s+Manchester|Greater\s+London|West\s+Midlands|'
   r'South\s+Yorkshire|Tyne\s+and\s+Wear|Merseyside|'
   r'Avon|Cleveland|Humberside|Middlesex)\b', 'COUNTY', 0.80, 1),
# Welsh counties
_p(r'\b(West\s+Glamorgan|Mid\s+Glamorgan|South\s+Glamorgan|'
   r'Gwent|Clwyd|Dyfed|'
   r'Ceredigion|Pembrokeshire|Carmarthenshire|Swansea|'
   r'Monmouthshire|Flintshire|Wrexham|Conwy|'
   r'Anglesey|Neath\s+Port\s+Talbot)\b', 'COUNTY', 0.80, 1),
# Scottish regions and counties
_p(r'\b(Grampian|Strathclyde|Tayside|Central|'
   r'Aberdeenshire|Ayrshire|Renfrewshire|'
   r'Lanarkshire|Dunbartonshire|Stirlingshire|'
   r'Inverness|Kinross|Ross\s+and\s+Cromarty|'
   r'Caithness|Sutherland|Orkney|Shetland)\b', 'COUNTY', 0.80, 1),
# Northern Ireland counties
_p(r'\b(County\s+Down|County\s+Antrim|County\s+Armagh|'
   r'County\s+Derry|County\s+Fermanagh|County\s+Tyrone|'
   r'County\s+Londonderry)\b', 'COUNTY', 0.82, 1),
# Republic of Ireland counties
_p(r'\b(County\s+Cork|County\s+Dublin|County\s+Galway|'
   r'County\s+Kerry|County\s+Kildare|County\s+Kilkenny|'
   r'County\s+Limerick|County\s+Mayo|County\s+Meath|'
   r'County\s+Tipperary|County\s+Waterford|County\s+Wexford|'
   r'County\s+Wicklow|County\s+Donegal|County\s+Louth|'
   r'County\s+Clare|County\s+Sligo|County\s+Roscommon|'
   r'County\s+Westmeath|County\s+Offaly|County\s+Laois|'
   r'County\s+Carlow|County\s+Longford|County\s+Cavan|'
   r'County\s+Monaghan|County\s+Leitrim)\b', 'COUNTY', 0.82, 1),

# === Standalone CITY Patterns ===
# City-suffix heuristic: words ending in common city suffixes are likely city names.
# Matches Faker-generated cities (Pfefferton, Langoshburgh, Strackeview) and real cities.
_p(r'\b([A-Z][a-z]{2,}(?:ton|burgh|burg|boro|borough|ville|field|ford|port|mouth|'
   r'worth|stead|minster|chester|cester|haven|dale|berg|heim|dorf|'
   r'stad|view|side|land|wood|woods|lake|bridge|gate|shire))\b', 'CITY', 0.72, 1),

# City-prefix heuristic: "New/Port/Lake/Fort/Mount/Saint + CapitalizedWord" or compound
_p(r'\b((?:New|Port|Lake|Fort|Mount|Saint|San|Santa|Los|Las|El|Cape|Palm)\s+[A-Z][a-z]+(?:[a-z]+)?)\b',
   'CITY', 0.72, 1),

# === Standalone SECONDARY ADDRESS Patterns ===
# "Apt. 259", "Suite 786" etc. (standalone, not part of full address)
_p(r'\b((?:Apt|Suite|Ste|Unit)\.?\s*#?\s*\d{1,5}[A-Z]?)\b', 'ADDRESS', 0.80, 1, flags=re.I),

# === Standalone STREET Patterns ===
# Street names with suffix but no building number: "S Broadway", "Veterans Memorial Highway"
_p(
    rf'\b({_DIRECTIONAL}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b(?=\s+\d)',
    'ADDRESS', 0.78, 1
),
# Named street with suffix: "Wiza Spur", "Kuhlman Run", "Waters Harbors"
_p(
    rf'\b([A-Z][a-z]+\s+(?:{_STREET_SUFFIXES}))\b',
    'ADDRESS', 0.75, 1
),

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

# === Company Names ===
# "Name LLC", "Name Ltd", "Name Inc", "Name Corp", "Name Co."
_p(rf'\b((?:{_COMPANY_NAME})(?:\s+(?:{_COMPANY_NAME}))?\s+(?:LLC|Ltd\.?|Inc\.?|Corp\.?|Co\.?|PLC|GmbH|AG|S\.?A\.?))\b', 'COMPANY', 0.85, 1),
# "Name Group", "Name Partners", "Name Associates", "Name Foundation"
_p(rf'\b((?:{_COMPANY_NAME})\s+(?:Group|Partners|Associates|Foundation|Enterprises|Solutions|Industries|Holdings|Services|International|Consulting|Technologies))\b', 'COMPANY', 0.78, 1),
# "Name, Name and Name" (law firm / partnership style)
_p(rf'\b((?:{_COMPANY_NAME}),\s+(?:{_COMPANY_NAME})\s+and\s+(?:{_COMPANY_NAME}))\b', 'COMPANY', 0.80, 1),
# "Name - Name" (hyphenated company name)
_p(rf'\b((?:{_COMPANY_NAME})\s+-\s+(?:{_COMPANY_NAME}))\b', 'COMPANY', 0.72, 1),

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
# Labeled IMEI with dashes: "IMEI: 06-184755-866851-3"
_p(r'(?:IMEI)[:\s]+(\d{2}-\d{6}-\d{6}-\d)', 'IMEI', 0.95, 1, flags=re.I),
# IMEI with dashes (DD-DDDDDD-DDDDDD-D format) — confidence ≥ 0.90
# skips Luhn validation, appropriate for this distinctive format
# which does not overlap with any other entity type.  Prevents
# IMEI→PHONE misclassification when synthetic data fails Luhn.
_p(r'\b(\d{2}-\d{6}-\d{6}-\d)\b', 'IMEI', 0.91),

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
# "Username is X" — verb separator instead of colon
_p(r'(?:username|user\s*name)\s+(?:is|was|will\s+be)\s+([A-Za-z0-9_.-]{3,30})', 'USERNAME', 0.85, 1, flags=re.I),
# Login context: "logged in as username", "signed in as username"
_p(r'(?:logged\s+in\s+as|signed\s+in\s+as|profile)[:\s]+([A-Za-z0-9_.-]{3,30})', 'USERNAME', 0.82, 1, flags=re.I),
# Login details / credentials context
_p(r'(?:login|sign[- ]?in)\s+(?:details|info|credentials?)[:\s]+([A-Za-z0-9_.-]{3,30})', 'USERNAME', 0.85, 1, flags=re.I),
# "your X credentials" — username before 'credentials'
_p(r'(?:your|through\s+your|with\s+your)\s+([A-Za-z0-9_.-]{3,30})\s+credentials', 'USERNAME', 0.82, 1, flags=re.I),
# Standalone username pattern: Word_Word or Word.Word with optional trailing digits
# Highly distinctive — real words rarely have underscores or dots between parts.
# NOTE: Hyphens excluded — "Roberts-Rolfson" etc. are hyphenated surnames, not usernames.
_p(r'\b([A-Z][a-z]+(?:[_.][A-Z][a-z]+)+\d{0,3})\b', 'USERNAME', 0.80, 1),
# Simple Word_word or word_Word (mixed case with underscore)
_p(r'\b([A-Za-z][a-z]+_[A-Za-z][a-z]+(?:[-_][A-Za-z][a-z]+)*\d{0,3})\b', 'USERNAME', 0.78, 1),
# "delegating/responsibility to Username" — assignment context
_p(r'(?:delegat(?:e|ing)|responsibility|assign(?:ed|ing)?)\s+(?:\S+\s+)?to\s+([A-Z][a-z]+\d{1,4})\b', 'USERNAME', 0.80, 1),
# Bare Name+Digits usernames: "Eugenia10", "Geovany30", "Jonatan78"
# Require 3+ alpha chars + 1-3 digits, title-case (not common words)
_p(r'\b([A-Z][a-z]{2,15}\d{1,3})\b', 'USERNAME', 0.72, 1),

# === Password ===
# English password labels - require colon/equals separator (not just whitespace) to avoid FPs
_p(r'(?:password|passwd|pwd|passcode|pin|pass)\s*[=:]\s*([^\s]{4,50})', 'PASSWORD', 0.90, 1, flags=re.I),
# International password labels (DE: Kennwort/Passwort, FR: mot de passe, ES: contraseña, IT: password, NL: wachtwoord, PT: senha)
_p(r'(?:kennwort|passwort|mot\s+de\s+passe|contraseña|wachtwoord|senha|parola\s+d\'ordine)[:\s]+([^\s]{4,50})', 'PASSWORD', 0.90, 1, flags=re.I | re.UNICODE),
# Authentication context: "credentials: password", "secret: xxxxx"
_p(r'(?:credential|secret|auth\s+key|api\s+key|access\s+key|secret\s+key)[:\s]+([^\s]{8,100})', 'PASSWORD', 0.88, 1, flags=re.I),
# Temp/initial password context
_p(r'(?:temporary|temp|initial|default)\s+(?:password|pwd|passcode|pin|pass)[:\s]+([^\s]{4,50})', 'PASSWORD', 0.92, 1, flags=re.I),
# "password is XXXX" / "pin is XXXX" / "pass is XXXX" — verb separator instead of colon/equals
_p(r'(?:password|passwd|pwd|passcode|pin|pass)\s+(?:is|was|will\s+be)\s+([^\s.,;:!?)]{4,50})', 'PASSWORD', 0.88, 1, flags=re.I),
# "password for X is Y" — "for" clause between password and value
_p(r'(?:password|passwd|pwd|passcode|pin|pass)\s+(?:for\s+\S+(?:\s+\S+){0,4}?\s+)?(?:is|was|will\s+be)\s+([^\s.,;:!?)]{4,50})', 'PASSWORD', 0.86, 1, flags=re.I),
_p(r'(?:kennwort|passwort|mot\s+de\s+passe|contraseña|wachtwoord|senha)\s+(?:is|ist|est|es|é)\s+([^\s.,;:!?)]{4,50})', 'PASSWORD', 0.88, 1, flags=re.I | re.UNICODE),
# PIN with label context: "PIN code XXXX", "PIN - XXXX", "pin XXXX", "pin: XXXX"
_p(r'\bpin\s*[=:]\s*(\d{4,8})\b', 'PASSWORD', 0.88, 1, flags=re.I),
_p(r'\bpin\s+code\s+(\d{4,8})\b', 'PASSWORD', 0.90, 1, flags=re.I),
_p(r'\bpin\s*[-–]\s*(\d{4,8})\b', 'PASSWORD', 0.88, 1, flags=re.I),
_p(r'\b(?:with\s+)?pin\s+(\d{4,8})\b', 'PASSWORD', 0.82, 1, flags=re.I),
# "enter/please enter XXXX" — action verb + value (password/code context)
_p(r'\b(?:please\s+)?(?:enter|type|input)\s+([A-Za-z0-9_]{6,50})\b(?=\s+(?:to|into|on|at|for|when|as|in))', 'PASSWORD', 0.78, 1, flags=re.I),
# "confirm with XXXX" — confirmation context (often passwords/codes)
_p(r'\b(?:confirm|verify|authenticate)\s+with\s+([A-Za-z0-9_]{4,50})\b', 'PASSWORD', 0.80, 1, flags=re.I),
# "using USERNAME and PASSWORD" — second value in auth pair
_p(r'\busing\s+\S+\s+and\s+([A-Za-z0-9_]{6,50})\b', 'PASSWORD', 0.78, 1, flags=re.I),
# "remember your XXXX for" — reminder context for codes/PINs
_p(r'\b(?:remember|note|save)\s+(?:your\s+)?(\d{4,8})\b(?=\s+(?:for|as|when|to|during))', 'PASSWORD', 0.78, 1, flags=re.I),
# "passwords, with X being" — password enumeration/listing context
_p(r'(?:passwords?|passcodes?),?\s+(?:with|like|such\s+as|including)\s+([A-Za-z0-9_]{6,50})\b', 'PASSWORD', 0.82, 1, flags=re.I),
# "asking for your X" — social engineering context (password)
_p(r'(?:asking|asks)\s+for\s+your\s+([A-Za-z0-9_]{6,50})\b(?=\.\s|[\s,])', 'PASSWORD', 0.78, 1, flags=re.I),
# "password for accessing online content: X" — colon after content context
_p(r'(?:password|passcode|pwd|pass)\s+for\s+\S+(?:\s+\S+){0,4}?:\s*([^\s.,;:!?)]{4,50})', 'PASSWORD', 0.86, 1, flags=re.I),
# "use X to access" / "use X for one-time access"
_p(r'\buse\s+([A-Za-z0-9_]{6,50})\s+(?:to\s+access|for\s+(?:one-time\s+)?access)', 'PASSWORD', 0.82, 1, flags=re.I),
# "use XXXX to access" — 4-digit PIN variant
_p(r'\buse\s+(\d{4,8})\s+to\s+access\b', 'PASSWORD', 0.82, 1, flags=re.I),
# "log in and use X for" — login + use context
_p(r'(?:log\s*in|sign\s*in)\s+and\s+use\s+([A-Za-z0-9_]{6,50})\b', 'PASSWORD', 0.82, 1, flags=re.I),
# "USERNAME and PASSWORD used" — auth pair in past tense
_p(r'\b\S+\s+and\s+([A-Za-z0-9_]{6,50})\s+used\b', 'PASSWORD', 0.75, 1, flags=re.I),
# "password changed/updated to X" — password state change
_p(r'(?:password|passwd|pwd|passcode|pin|pass)\s+(?:changed|updated|modified|reset|set)\s+to\s+([^\s.,;:!?)]{4,50})', 'PASSWORD', 0.88, 1, flags=re.I),
# "password from X" — source reference ("update their password from X to something stronger")
_p(r'(?:password|passwd|pwd|passcode|pass)\s+from\s+([^\s.,;:!?)]{4,50})', 'PASSWORD', 0.85, 1, flags=re.I),
# "change/update/modify your/their X" — possessive password change context
# Require at least one digit to avoid matching common words (e.g. "change your password")
_p(r'(?:change|update|modify(?:ing)?)\s+(?:your|their|his|her|my)\s+([A-Za-z0-9_]*\d[A-Za-z0-9_]*)\b', 'PASSWORD', 0.80, 1, flags=re.I),
# "log in/sign in with X" — login-with pattern
_p(r'(?:log\s*in|sign\s*in|login)\s+with\s+([A-Za-z0-9_]{6,50})\b', 'PASSWORD', 0.82, 1, flags=re.I),
# "Log in with X" — 4-digit PIN variant
_p(r'(?:log\s*in|sign\s*in|login)\s+with\s+(\d{4,8})\b', 'PASSWORD', 0.82, 1, flags=re.I),
# "credentials are ... and X" — credential pair after "are"
_p(r'credentials\s+are\s+\S+\s+and\s+([A-Za-z0-9_]{6,50})\b', 'PASSWORD', 0.82, 1, flags=re.I),
# "USERNAME and PASSWORD to access/join" — credential pair before access verb
_p(r'\b\S+\s+and\s+([A-Za-z0-9_]{6,50})\s+to\s+(?:access|join|login|log\s*in|sign\s*in|enter|view)', 'PASSWORD', 0.80, 1, flags=re.I),
# "USERNAME & PASSWORD" — ampersand credential pair (require digit to avoid FPs)
_p(r'\b\S+\s+&\s+([A-Za-z0-9_]*\d[A-Za-z0-9_]*)\b', 'PASSWORD', 0.78, 1, flags=re.I),
# "Use X for access" / "Use X to get access" — broader access patterns
_p(r'\buse\s+([A-Za-z0-9_]{6,50})\s+(?:to\s+get\s+access|for\s+access)', 'PASSWORD', 0.82, 1, flags=re.I),
# "Use X on DATE for access" — use with intervening context before "for access"
_p(r'\buse\s+([A-Za-z0-9_]{6,50})\s+(?:\S+\s+){0,5}?for\s+access\b', 'PASSWORD', 0.78, 1, flags=re.I),
# "remember your X for" — extend from digits-only to alphanumeric
_p(r'\b(?:remember|note|save)\s+(?:your\s+)?([A-Za-z0-9_]{6,50})\b(?=\s+(?:for|as|when|to|during))', 'PASSWORD', 0.78, 1, flags=re.I),
# "share your login X" — sharing context (require "login" keyword to avoid FPs like "share your details")
_p(r'(?:share|disclose|reveal)\s+(?:your\s+)?login\s+([A-Za-z0-9_]{6,50})\b', 'PASSWORD', 0.78, 1, flags=re.I),
# "never share your X" / "do not share your X" — warning context with digit-containing value
_p(r'(?:never|do\s+not|don\'t|shouldn\'t)\s+share\s+(?:your\s+)?([A-Za-z0-9_]*\d[A-Za-z0-9_]*)\b', 'PASSWORD', 0.80, 1, flags=re.I),
# "as the/your password" — trailing password context
_p(r'\b([A-Za-z0-9_]{4,50})\s+as\s+(?:the|your|a)\s+(?:password|passcode|pin|pwd)\b', 'PASSWORD', 0.85, 1, flags=re.I),
# "gate code / access code / verification code / the code X" — code context
_p(r'(?:gate|access|security|verification|entry|door)\s+code\s*[:\s]\s*([A-Za-z0-9_]{3,50})\b', 'PASSWORD', 0.85, 1, flags=re.I),
_p(r'(?:use|enter|provide)\s+(?:the\s+)?code\s+([A-Za-z0-9_]{3,50})\b', 'PASSWORD', 0.82, 1, flags=re.I),
# "PIN is DIGITS" — ensure PIN + "is" works for digit PINs
_p(r'\bpin\s+(?:is|was|will\s+be)\s+(\d{4,8})\b', 'PASSWORD', 0.88, 1, flags=re.I),
# "PIN ... is DIGITS" — PIN with intervening words ("security pin linked to this transaction is 0442")
_p(r'\bpin\s+(?:\S+\s+){1,6}?(?:is|was)\s+(\d{4,8})\b', 'PASSWORD', 0.82, 1, flags=re.I),
# "Use X and Y" — credential pair without "using" prefix
_p(r'\b[Uu]se\s+\S+\s+and\s+([A-Za-z0-9_]{6,50})\b', 'PASSWORD', 0.78, 1, flags=re.I),
# "using your X" — using + possessive (require digit to avoid FPs like "using your profile")
_p(r'\busing\s+(?:your|their|his|her)\s+([A-Za-z0-9_]*\d[A-Za-z0-9_]*)\b', 'PASSWORD', 0.78, 1, flags=re.I),
# "username and X" — broader credential pair (any word before "and")
_p(r'(?:username|user\s*name|user\s+ID)\s+and\s+([A-Za-z0-9_]{6,50})\b', 'PASSWORD', 0.82, 1, flags=re.I),
# "the password VALUE" / "password VALUE" — bare password label before value
# Require at least one digit in value to avoid matching "password protection", "password policy"
_p(r'(?:the\s+)?(?:password|passwd|pwd|passcode)\s+([A-Za-z0-9_]*\d[A-Za-z0-9_]*)\b', 'PASSWORD', 0.82, 1, flags=re.I),
# "reliable/secure/strong password VALUE" — adjective before password
_p(r'(?:reliable|secure|strong|new|old|current|correct|wrong)\s+(?:password|passwd|pwd|passcode)\s+([A-Za-z0-9_]{6,50})\b', 'PASSWORD', 0.82, 1, flags=re.I),
# "credentials (USERNAME, PASSWORD)" — credential pair in parentheses
_p(r'credentials?\s*\(\s*\S+\s*,\s*([A-Za-z0-9_]{6,50})\s*\)', 'PASSWORD', 0.85, 1, flags=re.I),
# "encrypt it using VALUE" / "encrypt using VALUE" — encryption context
_p(r'(?:encrypt|decrypt)\s+(?:\S+\s+)?(?:using|with)\s+([A-Za-z0-9_]{6,50})\b', 'PASSWORD', 0.82, 1, flags=re.I),
# "implement VALUE" followed by auth/security context — deployment password
_p(r'\bimplement\s+([A-Za-z0-9_]*\d[A-Za-z0-9_]*)\b(?=\s+(?:and|for|to|as|in))', 'PASSWORD', 0.75, 1, flags=re.I),
# LICENSE/CREDENTIAL/GOVERNMENT IDs
# === Driver's License - Labeled ===
_p(r'(?:Driver\'?s?\s*License|DL|DLN)[:\s#]+([A-Z0-9]{5,15})', 'DRIVER_LICENSE', 0.88, 1, flags=re.I),
# "License: A1234567" / "License #: A1234567" — bare "License" keyword with value
_p(r'(?<![A-Za-z])License\s*[:#]+\s*([A-Z0-9]{5,15})\b', 'DRIVER_LICENSE', 0.82, 1, flags=re.I),

# === Driver's License - State-specific formats ===
# IMPORTANT: All standalone DL patterns (no context keyword) have been REMOVED
# because their formats overlap heavily with employee IDs, account numbers,
# license plates, and biometric IDs — causing 112+ type mismatches on Gretel
# PII 1K.  Industry best practice (Presidio, AWS Macie, Google DLP) requires
# context for DL detection.
#
# KEPT: labeled/context-required patterns (DL:, Driver's License:, state
# prefixes), very-specific-format patterns (FL dashed, interleaved
# NH/IA/IN, WDL prefix).
# REMOVED: bare [A-Z]\d{N}, [A-Z]{2}\d{6}, H\d{8}, K\d{8}, S\d{8},
# X\d{8,11}, 00\d{6}, [A-Z]{3}\d{6}, [A-Z]\d{12}0 — all conf < 0.70.

# Florida: Letter + 3-3-2-3-1 with dashes (W426-545-30-761-0)
# Very specific format — keep high confidence
_p(r'\b([A-Z]\d{3}-\d{3}-\d{2}-\d{3}-\d)\b', 'DRIVER_LICENSE', 0.95, 1),

# New York: 9 digits (with context, overlaps SSN)
_p(r'(?:DL|License)[:\s]+(\d{9})\b', 'DRIVER_LICENSE', 0.85, 1, flags=re.I),

# Pennsylvania: 8 digits — require nearby context
_p(r'(?:PA|Pennsylvania|DL|Driver.?s?\s*License)\s*[:#]?\s*(\d{8})\b', 'DRIVER_LICENSE', 0.80, 1, flags=re.I),

# Washington: WDL prefix + alphanumeric (12 chars total like WDL*ABC1234D)
# Very specific prefix — keep high confidence
_p(r'\b(WDL[A-Z0-9*]{9})\b', 'DRIVER_LICENSE', 0.92, 1),

# Colorado: with context
_p(r'(?:CO|Colorado|DL)[:\s]+([A-Z]{2}\d{3,6})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),
_p(r'(?:CO|Colorado|DL)[:\s]+(\d{9})\b', 'DRIVER_LICENSE', 0.80, 1, flags=re.I),

# Nevada: with context
_p(r'(?:NV|Nevada|DL)[:\s]+(\d{9,12})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# New Hampshire: 2 digits + 3 letters + 5 digits (12ABC34567)
# Interleaved format — specific enough to keep
_p(r'\b(\d{2}[A-Z]{3}\d{5})\b', 'DRIVER_LICENSE', 0.88, 1),

# Iowa: 3 digits + 2 letters + 4 digits (123AB4567)
# Interleaved format — specific enough to keep
_p(r'\b(\d{3}[A-Z]{2}\d{4})\b', 'DRIVER_LICENSE', 0.88, 1),

# Indiana: 4 digits + 2 letters + 4 digits (1234AB5678)
# Interleaved format — specific enough to keep
_p(r'\b(\d{4}[A-Z]{2}\d{4})\b', 'DRIVER_LICENSE', 0.88, 1),
_p(r'(?:IN|Indiana|DL)[:\s]+(\d{10})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# Arizona: with context
_p(r'(?:AZ|Arizona|DL)[:\s]+([A-Z]?\d{8,9})\b', 'DRIVER_LICENSE', 0.80, 1, flags=re.I),

# Connecticut: 9 digits (with context, overlaps SSN)
_p(r'(?:CT|Connecticut|DL)[:\s]+(\d{9})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# Texas: 8 digits (with context)
_p(r'(?:TX|Texas|DL)[:\s]+(\d{8})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# Georgia: 7-9 digits (with context)
_p(r'(?:GA|Georgia|DL)[:\s]+(\d{7,9})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# Alabama: 7 digits (with context)
_p(r'(?:AL|Alabama|DL)[:\s]+(\d{7})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# Missouri: with context
_p(r'(?:MO|Missouri|DL)[:\s]+([A-Z]?\d{5,10})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# Tennessee: 7-9 digits (with context)
_p(r'(?:TN|Tennessee|DL)[:\s]+(\d{7,9})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

# South Carolina: 5-11 digits (with context)
_p(r'(?:SC|South\s+Carolina|DL)[:\s]+(\d{5,11})\b', 'DRIVER_LICENSE', 0.78, 1, flags=re.I),

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
# Bare 9-digit - LOW confidence so labeled MRN/Account/Routing patterns win.
# At 0.65, this stays below the default 0.70 threshold, preventing bare
# 9-digit numbers from being classified as SSN when they're actually bank
# routing numbers (29 mismatches) or other IDs. Labeled SSN patterns (0.96)
# and checksum-validated SSN (Tier 4, 0.99) still catch real SSNs.
_p(r'\b((?!000|666|9\d\d)\d{9})\b', 'SSN', 0.65),

# SSN with unusual separators (dots, middle dots, spaces around hyphens)
_p(r'(?:SSN|Social\s*Security)[:\s#]+(\d{3}[.\xb7]\d{2}[.\xb7]\d{4})', 'SSN', 0.85, 1, flags=re.I),  # dots/middle dots
_p(r'(?:SSN|Social\s*Security)[:\s#]+(\d{3}\s*-\s*\d{2}\s*-\s*\d{4})', 'SSN', 0.88, 1, flags=re.I),  # spaces around hyphens
# Bare SSN with space separators: "123 45 6789" (standard 3-2-4 with spaces)
_p(r'\b(\d{3}\s\d{2}\s\d{4})\b', 'SSN', 0.72),
# European 3-3-3 SSN with context: "068 148 535" — prevents SSN→PHONE confusion
# (8 mismatches on Gretel PII 1K).  Bare 3-3-3 is too ambiguous (phone overlap),
# so require SSN/social security/NISS/BSN keyword nearby.
_p(r'(?:SSN|Social\s*Security|NISS|BSN|Sozialversicherung|NI\s*number)\s*[:\s#]+(\d{3}\s\d{3}\s\d{3})', 'SSN', 0.88, 1, flags=re.I),
# Bare SSN with dot separators (e.g., "756.2808.9893") - international format
_p(r'\b(\d{3}\.\d{2,4}\.\d{3,4})\b', 'SSN', 0.72),
# Swiss AHV/OASI numbers (756 = Swiss country prefix)
# Format: 756.XXXX.XXXX.XX (with dots) or 756XXXXXXXXXX (without dots, 11-13 digits)
_p(r'\b(756\d{8,10})\b', 'SSN', 0.82, 1),
_p(r'\b(756\.\d{4}\.\d{4}\.\d{2})\b', 'SSN', 0.88, 1),

# === US ITIN (Individual Taxpayer Identification Number) ===
# Format: 9XX-[7-8]X-XXXX (starts with 9, digits 4-5 in range 70-88, 90-92, 94-99)
_p(r'(?:ITIN|Individual\s+Taxpayer)[:\s#]+(\d{3}[-\s]?\d{2}[-\s]?\d{4})', 'ITIN', 0.92, 1, flags=re.I),
_p(r'\b(9\d{2}[-\s]?(?:7\d|8[0-8])[-\s]?\d{4})\b', 'ITIN', 0.72, 1),

# === US EIN (Employer Identification Number) ===
# Format: XX-XXXXXXX (2-digit campus code prefix + 7 digits)
_p(r'(?:EIN|Employer\s+Identification|Federal\s+(?:Tax|Employer)\s+ID)[:\s#]+(\d{2}-\d{7})', 'EIN', 0.92, 1, flags=re.I),
_p(r'(?:Tax\s+ID|TIN|Taxpayer\s+ID)[:\s#]+(\d{2}-\d{7})', 'EIN', 0.85, 1, flags=re.I),
_p(r'\b(\d{2}-\d{7})\b', 'EIN', 0.60, 1, _validate_ein),

# === UK National Insurance Number (NINO) ===
# Format: 2 letters + 6 digits + 1 letter (A-D)
_p(r'(?:NI(?:NO)?|National\s+Insurance)[:\s#]+([A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D])', 'UK_NINO', 0.95, 1, flags=re.I),
_p(r'\b([A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D])\b', 'UK_NINO', 0.82, 1, _validate_uk_nino),

# === ABA Routing ===
_p(r'(?:Routing|ABA|RTN)[:\s#]+(\d{9})\b', 'BANK_ROUTING', 0.95, 1, flags=re.I),
# Account numbers - both numeric-only and alphanumeric formats
_p(r'(?:Account)\s*(?:Number|No|#)?[:\s#]+(\d{8,17})\b', 'ACCOUNT_NUMBER', 0.88, 1, flags=re.I),
_p(r'(?:Account)\s*(?:Number|No|#)?[:\s#]+(?=[A-Z0-9]*\d)([A-Z0-9][-A-Z0-9]{5,19})', 'ACCOUNT_NUMBER', 0.85, 1, flags=re.I),
# Account number in parentheses: "Investment Account (number 48308813)"
_p(r'Account\s*\(\s*(?:number|no|#)\s+(\d{6,17})\s*\)', 'ACCOUNT_NUMBER', 0.88, 1, flags=re.I),
# "account number XXXXXXXX" with flexible whitespace
_p(r'\baccount\s+(?:number|no\.?|#)\s+(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.88, 1, flags=re.I),
# "our account number XXXXXXXX" or "use account XXXXXXXX"
_p(r'\b(?:our|your|the|use|for)\s+account\s+(?:number\s+)?(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.85, 1, flags=re.I),
# Account type names: "Checking Account", "Savings Account", etc.
# Confidence kept moderate since these are labels, not identifiers;
# they must be near an actual account number to be meaningful.
_p(r'\b((?:Checking|Savings|Investment|Personal\s+Loan|Auto\s+Loan|Home\s+Loan|Money\s+Market|Credit\s+Card)\s+Account)\b', 'ACCOUNT_NUMBER', 0.82, 1),
# 16-digit numbers with context (masked/tokenized card numbers, account identifiers)
# Lower confidence — only match when preceded by contextual words
_p(r'(?:number|identification|assigned|use)\s+(\d{16})\b', 'ACCOUNT_NUMBER', 0.78, 1, flags=re.I),
# "with number XXXXXXXX" — account with explicit number label
_p(r'(?:with\s+number)\s+(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.82, 1, flags=re.I),
# "via XXXXXXXX" or "using XXXXXXXX" near financial context
_p(r'(?:transaction|transfer|payment)\s+(?:\S+\s+)?(?:using|via)\s+(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.78, 1, flags=re.I),
# "card ending with XXXX" / "card ending in XXXX" — 16-digit (account-number labeled)
_p(r'(?:card\s+ending\s+(?:with|in))\s+(\d{16})\b', 'ACCOUNT_NUMBER', 0.82, 1, flags=re.I),
# "from XXXXXXXX" — payment source context (8-digit account)
_p(r'(?:payment|made|be\s+made)\s+from\s+(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.78, 1, flags=re.I),
# "account number is XXXXXXXX" / "changed account number is XXXXXXXX"
_p(r'account\s+number\s+is\s+(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.88, 1, flags=re.I),
# "Number: XXXXXXXX" after account-type context (e.g., "Personal Loan Account - Number: 20227980")
_p(r'Account\s*[-–—]\s*Number:\s*(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.88, 1, flags=re.I),
# "information such as XXXX" — sensitive data enumeration
_p(r'(?:information|data|details)\s+such\s+as\s+(\d{8,17})\b', 'ACCOUNT_NUMBER', 0.75, 1, flags=re.I),
# "process it through your mastercard card ending with XXXX"
_p(r'(?:through\s+your)\s+\w+\s+card\s+ending\s+with\s+(\d{16})\b', 'ACCOUNT_NUMBER', 0.80, 1, flags=re.I),
# "monitor <number>" — account monitoring context
_p(r'(?:monitor|deposit|withdraw|debit|credited?\s+to|charged?\s+to)\s+(?:the\s+)?(\d{7,17})\b', 'ACCOUNT_NUMBER', 0.78, 1, flags=re.I),
# Broader: "<number> is your account" or "account <number>"
_p(r'\b(\d{7,17})\s+(?:is\s+(?:your|the)\s+(?:account|acct))', 'ACCOUNT_NUMBER', 0.78, 1, flags=re.I),
# "routing number XXXX" / "sort code XXXX"
_p(r'(?:routing\s+number|sort\s+code|BSB)\s*[:\s#]+(\d{6,9})\b', 'ACCOUNT_NUMBER', 0.85, 1, flags=re.I),
# "reference number: XXXX" / "reference no: XXXX" — labeled reference IDs
_p(r'(?:reference\s+(?:number|no|#|id))[:\s]+(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.82, 1, flags=re.I),
# "account (No. XXXX)" / "account (no XXXX)" — parenthesized account label
_p(r'(?:account)\s*\(\s*(?:No\.?|#)\s*(\d{6,17})\s*\)', 'ACCOUNT_NUMBER', 0.88, 1, flags=re.I),
# "transaction ID: XXXX" / "transaction number: XXXX"
_p(r'(?:transaction\s+(?:ID|id|number|no|#))[:\s]+(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.85, 1, flags=re.I),
# "account number, XXXX" — comma-separated (OCR/formatting artifacts)
_p(r'account\s+number\s*,\s*(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.85, 1, flags=re.I),
# "transferred to XXXX" / "deposited into XXXX" — financial transfer targets
_p(r'(?:transferred|deposited|wired|sent)\s+(?:to|into)\s+(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.78, 1, flags=re.I),
# "Account under XXXX" / "Account ends with XXXX"
_p(r'(?:Account)\s+(?:under|ends?\s+with)\s+(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.85, 1, flags=re.I),
# "Loan Account, XXXX" / "Savings Account, XXXX" — labeled account type + number
_p(r'(?:Loan|Savings|Checking|Investment|Money\s+Market)\s+Account\s*,\s*(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.85, 1, flags=re.I),
# "case no. XXXX" — legal/administrative case numbers
_p(r'(?:case\s+(?:no|number|#))[\s.:]+(\d{6,17})\b', 'ACCOUNT_NUMBER', 0.78, 1, flags=re.I),
# "flagged XXXX as" — audit/compliance contexts
_p(r'(?:flagged|identified|marked)\s+(\d{7,17})\s+(?:as|for)\b', 'ACCOUNT_NUMBER', 0.75, 1, flags=re.I),

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
# Context-based 16-digit card number: "XXXX issued by issuer", "XXXX, issuer X"
# These may fail Luhn (synthetic data) but context makes detection reliable.
# Uses entity type CREDIT_CARD_NOLUHN to bypass Luhn validation in detect().
_p(r'\b(\d{16})\b(?=[\s,]*(?:issu(?:er|ed)|maestro|visa|mastercard|amex|american.express|discover|diners|jcb))', 'CREDIT_CARD_NOLUHN', 0.82, 1, flags=re.I),
_p(r'(?:issu(?:er|ed)\s+(?:by\s+)?(?:\w+\s+)?|via\s+)(\d{16})\b', 'CREDIT_CARD_NOLUHN', 0.82, 1, flags=re.I),
# "card XXXX" / "card number XXXX" / "card ending in XXXX" — card context before 16-digit
_p(r'(?:card|credit\s*card)\s+(?:number\s+)?(?:ending\s+(?:in|with)\s+)?(\d{16})\b', 'CREDIT_CARD_NOLUHN', 0.84, 1, flags=re.I),
# "numbers like XXXX" — near card issuer context
_p(r'(?:numbers?\s+(?:like|such\s+as|including))\s+(\d{16})\b', 'CREDIT_CARD_NOLUHN', 0.78, 1, flags=re.I),
# "digits of your card are XXXX" / "last four digits...XXXX"
_p(r'(?:digits\s+(?:of\s+)?(?:your\s+)?(?:card\s+)?(?:are|is))\s+(\d{16})\b', 'CREDIT_CARD_NOLUHN', 0.82, 1, flags=re.I),
# 16-digit number followed by "will cover" / "will be charged" / "for processing"
_p(r'\b(\d{16})\b(?=\s+(?:will\s+(?:cover|be\s+charged)|for\s+(?:processing|verification|payment)))', 'CREDIT_CARD_NOLUHN', 0.78, 1, flags=re.I),
# "charged to the company card XXXX" / "company card XXXX"
_p(r'(?:company|corporate|business)\s+card\s+(\d{16})\b', 'CREDIT_CARD_NOLUHN', 0.84, 1, flags=re.I),
# Broad: "payment via NNN, XXXX" — 16-digit after payment context
_p(r'(?:payment|paid)\s+(?:via|through|using)\s+\S+\s+(?:number\s+(?:ending\s+)?(?:in\s+)?)?(\d{16})\b', 'CREDIT_CARD_NOLUHN', 0.80, 1, flags=re.I),
# "Need your XXXX for smooth transactions" / "your XXXX for payment" — 16-digit with transaction context
_p(r'(?:need\s+)?(?:your|the)\s+(\d{16})\b(?=\s+for\s+(?:smooth\s+)?(?:transactions?|payments?|processing|verification))', 'CREDIT_CARD_NOLUHN', 0.78, 1, flags=re.I),
# "personal details like XXXX" — enumerated personal data containing 16-digit
_p(r'(?:details|data|information)\s+(?:like|such\s+as|including)\s+(\d{16})\b', 'CREDIT_CARD_NOLUHN', 0.75, 1, flags=re.I),
# "expenses on XXXX" / "expenses using XXXX" — payment context
_p(r'(?:expenses?\s+(?:on|using|with))\s+(\d{16})\b', 'CREDIT_CARD_NOLUHN', 0.80, 1, flags=re.I),
# "using XXXX" directly (when preceded by payment/done/charged context)
_p(r'(?:done|paid|charged|payment|pay)\s+(?:\S+\s+)?(?:using|on|with)\s+(\d{16})\b', 'CREDIT_CARD_NOLUHN', 0.78, 1, flags=re.I),
# "transactions involving XXXX" / "provide XXXX" in card context
_p(r'(?:transactions?\s+involving)\s+(\d{16})\b', 'CREDIT_CARD_NOLUHN', 0.78, 1, flags=re.I),
_p(r'(?:provide|share|disclose)\s+(\d{16})\b(?=\s+(?:or\s+\d|to\s+any|details))', 'CREDIT_CARD_NOLUHN', 0.75, 1, flags=re.I),
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
_p(r'\b(?!PIN|VIN)([A-Z]{3}[-\s]\d{4})\b', 'LICENSE_PLATE', 0.82, 1),
# Florida: ABC D12 or ABCD12 (letter-heavy) — labeled only to avoid FP on
# user-agent strings like "WOW64" or "MSIE 10"
_p(r'(?:License\s*Plate|Plate|Tag)[:\s#]+([A-Z]{3,4}\s?[A-Z]?\d{2})\b', 'LICENSE_PLATE', 0.80, 1, flags=re.I),
# UK: AB12CDE or AB12 CDE (2 letters, 2 digits, 3 letters)
_p(r'\b([A-Z]{2}\d{2}\s?[A-Z]{3})\b', 'LICENSE_PLATE', 0.85, 1),


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
_p(r'(?:ext\.?|extension)[:\s#]*(\d{3,6})\b', 'PHONE_EXT', 0.85, 1, flags=re.I),
# Bare "x" trigger only after a phone-like number (avoids "x100", "x1024", etc.)
_p(r'\d{4}\s*x\s*(\d{3,6})\b', 'PHONE_EXT', 0.80, 1),
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
# Bracket-enclosed: [-71.6702,-107.6572] (common in datasets and APIs)
_p(r'(\[-?\d{1,3}\.\d{1,8},-?\d{1,3}\.\d{1,8}\])', 'GPS_COORDINATE', 0.92, 1),
# Decimal degrees: 41.8781, -87.6298 or 41.8781° N, 87.6298° W
_p(r'(-?\d{1,3}\.\d{4,8})[,\s]+(-?\d{1,3}\.\d{4,8})', 'GPS_COORDINATE', 0.88, 0),
_p(r'(\d{1,3}\.\d{4,8})°?\s*[NS][,\s]+(\d{1,3}\.\d{4,8})°?\s*[EW]', 'GPS_COORDINATE', 0.92, flags=re.I),
# DMS format: 41°52'43"N 87°37'47"W
_p(r'(\d{1,3}°\d{1,2}[\'′]\d{1,2}[\"″]?[NS])\s*(\d{1,3}°\d{1,2}[\'′]\d{1,2}[\"″]?[EW])', 'GPS_COORDINATE', 0.90, 0),
# With label
_p(r'(?:GPS|Coordinates?|Location|Lat(?:itude)?[/,]\s*Lon(?:gitude)?)[:\s]+(.{10,40})', 'GPS_COORDINATE', 0.85, 1, flags=re.I),


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

# === Indian PAN (Permanent Account Number) ===
# Format: 5 letters + 4 digits + 1 letter, 4th letter encodes entity type
_p(r'(?:PAN|Permanent\s+Account)[:\s#]+([A-Z]{3}[ABCFGHJTLP][A-Z]\d{4}[A-Z])', 'IN_PAN', 0.95, 1, flags=re.I),
_p(r'\b([A-Z]{3}[ABCFGHJTLP][A-Z]\d{4}[A-Z])\b', 'IN_PAN', 0.78, 1),

# === Singapore NRIC/FIN ===
# Format: Letter (S/T/F/G/M) + 7 digits + letter
_p(r'(?:NRIC|FIN)[:\s#]+([STFGM]\d{7}[A-Z])', 'SG_NRIC_FIN', 0.92, 1, flags=re.I),
_p(r'\b([STFGM]\d{7}[A-Z])\b', 'SG_NRIC_FIN', 0.68, 1),

# === Spanish NIE (Numero de Identidad de Extranjero) ===
# Format: X/Y/Z + 7 digits + check letter
_p(r'(?:NIE)[:\s#]+([XYZ]\d{7}[A-Z])', 'ES_NIE', 0.92, 1, flags=re.I),
_p(r'\b([XYZ]\d{7}[A-Z])\b', 'ES_NIE', 0.72, 1, _validate_es_nie),

# === Spanish NIF (Numero de Identificacion Fiscal) ===
# Format: 8 digits + check letter
_p(r'(?:NIF|DNI)[:\s#]+(\d{8}[A-Z])', 'ES_NIF', 0.92, 1, flags=re.I),
_p(r'\b(\d{8}[A-Z])\b', 'ES_NIF', 0.62, 1, _validate_es_nif),

# === Polish PESEL ===
# 11 digits: YYMMDD + serial + check digit, weighted checksum
_p(r'(?:PESEL)[:\s#]+(\d{11})', 'PL_PESEL', 0.92, 1, flags=re.I),
_p(r'\b(\d{2}(?:[02468][1-9]|[13579][012])(?:0[1-9]|[12]\d|3[01])\d{5})\b', 'PL_PESEL', 0.60, 1, _validate_pl_pesel),

# === Finnish HETU (Henkilotunnus / Personal Identity Code) ===
# Format: DDMMYY + century sign + 3 digits + control char
_p(r'(?:HETU|henkilotunnus|personal\s+identity\s+code)[:\s#]+(\d{6}[+-ABCDEFYXWVU]\d{3}[0-9A-Y])', 'FI_HETU', 0.92, 1, flags=re.I),

# === Italian Fiscal Code (Codice Fiscale) ===
# 16 alphanumeric characters with complex structure
_p(r'(?:Codice\s+Fiscale|CF)[:\s#]+([A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z])', 'IT_FISCAL_CODE', 0.92, 1, flags=re.I),

# === Italian VAT (Partita IVA) ===
# 11 digits with Luhn-like checksum
_p(r'(?:P\.?\s*IVA|Partita\s+IVA)[:\s#]+(\d{11})', 'IT_VAT', 0.90, 1, flags=re.I),

# ---------------------------------------------------------------------------
# EU MULTILINGUAL PATTERNS (9-language GLiNER companion)
# ---------------------------------------------------------------------------

# === French NIR / Numero de Securite Sociale ===
# 15 digits: sex(1) + birth_year(2) + month(2) + dept(2) + commune(3) + order(3) + key(2)
_p(r'(?:NIR|INSEE|num[ée]ro\s+de\s+s[ée]curit[ée]\s+sociale|s[ée]curit[ée]\s+sociale)[:\s#]+([12]\s?\d{2}\s?\d{2}\s?\d{2,3}\s?\d{3}\s?\d{3}\s?\d{2})',
   'FR_NIR', 0.92, 1, flags=re.I),
# Bare 15-digit NIR starting with 1 or 2 (with checksum validation)
_p(r'\b([12]\d{14})\b', 'FR_NIR', 0.55, 1, _validate_fr_nir),

# === French SIRET (Business ID) ===
# 14 digits: SIREN(9) + NIC(5)
_p(r'(?:SIRET)[:\s#]+(\d{3}\s?\d{3}\s?\d{3}\s?\d{5})', 'FR_SIRET', 0.92, 1, flags=re.I),
_p(r'(?:SIREN)[:\s#]+(\d{3}\s?\d{3}\s?\d{3})', 'FR_SIRET', 0.90, 1, flags=re.I),

# === German Steuerliche Identifikationsnummer (Tax ID) ===
# 11 digits, first digit != 0, ISO 7064 Mod 11,10 checksum
_p(r'(?:Steuer[-\s]?(?:ID|Identifikationsnummer|Nr)|IdNr|St(?:euer)?[-\s]?Nr)[:\s#]+(\d{11})',
   'DE_STEUER_ID', 0.92, 1, flags=re.I),
# Bare 11-digit with checksum (lower confidence due to overlap with phone numbers)
_p(r'(?:Identifikationsnummer|Steueridentifikationsnummer)[:\s#]+(\d{11})',
   'DE_STEUER_ID', 0.88, 1, flags=re.I),

# === German Personalausweis (Identity Card Number) ===
# Format: L + 8 alphanumeric + D (since Nov 2010) or 10-digit (older format)
_p(r'(?:Personalausweis|Ausweis(?:nummer)?|Identit[aä]tskarte)[:\s#]+([CFGHJKLMNPRTVWXYZ]\d{8}[A-Z0-9])',
   'DE_PERSONALAUSWEIS', 0.90, 1, flags=re.I),

# === Dutch BSN (Burgerservicenummer) ===
# 9 digits with 11-proof checksum
_p(r'(?:BSN|Burgerservicenummer|burger\s*service\s*nummer|sofinummer|sofi[-\s]?nummer)[:\s#]+(\d{9})',
   'NL_BSN', 0.92, 1, flags=re.I),
# Bare 9 digits with checksum (lower confidence — overlaps with other 9-digit IDs)
_p(r'(?:BSN|Burgerservicenummer)[:\s]+(\d{3}[-.\s]?\d{3}[-.\s]?\d{3})',
   'NL_BSN', 0.88, 1, flags=re.I),

# === Portuguese NIF (Numero de Identificacao Fiscal) ===
# 9 digits with mod-11 checksum
_p(r'(?:NIF|N[uú]mero\s+de\s+Identifica[cç][aã]o\s+Fiscal|contribuinte)[:\s#]+(\d{9})',
   'PT_NIF', 0.92, 1, flags=re.I),
_p(r'(?:NIF|contribuinte)[:\s]+(\d{3}\s?\d{3}\s?\d{3})',
   'PT_NIF', 0.88, 1, flags=re.I),

# === Portuguese CC (Cartao de Cidadao) ===
# 12 alphanumeric characters
_p(r'(?:Cart[aã]o\s+de\s+Cidad[aã]o|CC|BI)[:\s#]+(\d{8}\s?\d\s?[A-Z]{2}\d)',
   'PT_CC', 0.90, 1, flags=re.I),

# === Brazilian CPF (Cadastro de Pessoa Fisica) ===
# 11 digits, commonly formatted as XXX.XXX.XXX-XX
_p(r'(?:CPF)[:\s#]+(\d{3}\.?\d{3}\.?\d{3}[-.]?\d{2})', 'BR_CPF', 0.92, 1, flags=re.I),
_p(r'\b(\d{3}\.\d{3}\.\d{3}-\d{2})\b', 'BR_CPF', 0.78, 1, _validate_br_cpf),

# === Brazilian CNPJ (Cadastro Nacional da Pessoa Juridica) ===
# 14 digits, commonly formatted as XX.XXX.XXX/XXXX-XX
_p(r'(?:CNPJ)[:\s#]+(\d{2}\.?\d{3}\.?\d{3}/??\d{4}[-.]?\d{2})', 'BR_CNPJ', 0.92, 1, flags=re.I),
_p(r'\b(\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2})\b', 'BR_CNPJ', 0.80, 1, _validate_br_cnpj),

# === Greek AMKA (Social Security Number) ===
# 11 digits: DDMMYY + 5-digit serial, Luhn checksum
_p(r'(?:AMKA|Α\.?Μ\.?Κ\.?Α|Αριθμ[οό]ς\s+Μητρ[ωώ]ου\s+Κοινωνικ[ηή]ς\s+Ασφ[αά]λισης)[:\s#]+(\d{11})',
   'EL_AMKA', 0.92, 1, flags=re.I),
_p(r'(?:AMKA)[:\s]+(\d{2}\d{2}\d{2}\d{5})', 'EL_AMKA', 0.88, 1, flags=re.I),

# === Greek AFM (Tax Identification Number) ===
# 9 digits with weighted checksum
_p(r'(?:AFM|Α\.?Φ\.?Μ|ΑΦΜ|Αριθμ[οό]ς\s+Φορολογικο[υύ]\s+Μητρ[ωώ]ου)[:\s#]+(\d{9})',
   'EL_AFM', 0.92, 1, flags=re.I),
_p(r'(?:AFM|ΑΦΜ)[:\s]+(\d{9})', 'EL_AFM', 0.88, 1, flags=re.I),

# === Slovenian EMSO (Enotna Maticna Stevilka Obcana) ===
# 13 digits: DDMMYYY + RR + SSS + C (mod-11 checksum)
_p(r'(?:EMŠO|EMSO|Enotna\s+Mati[cč]na\s+[SŠ]tevilka)[:\s#]+(\d{13})',
   'SI_EMSO', 0.92, 1, flags=re.I),
_p(r'(?:EMŠO|EMSO)[:\s]+(\d{13})', 'SI_EMSO', 0.88, 1, flags=re.I),

# === Slovenian Davcna Stevilka (Tax Number) ===
# 8 digits
_p(r'(?:dav[cč]na\s+[sš]tevilka|Dav[cč]na\s+[SŠ]t)[:\s#]+(\d{8})',
   'SI_DAVCNA', 0.90, 1, flags=re.I),

# === EU Country Phone Number Formats ===
# French phone: +33 or 0X XX XX XX XX
_p(r'(?:^|(?<=\s))\+33[-.\s]?\d[-.\s]?\d{2}[-.\s]?\d{2}[-.\s]?\d{2}[-.\s]?\d{2}\b',
   'PHONE', 0.88),
_p(r'(?:t[ée]l(?:[ée]phone)?|num[ée]ro)[:\s]+(0[1-9](?:[-.\s]?\d{2}){4})', 'PHONE', 0.88, 1, flags=re.I),
# German phone: +49 or 0XXX-XXXXXXX
_p(r'(?:^|(?<=\s))\+49[-.\s]?\d{2,4}[-.\s]?\d{3,8}\b', 'PHONE', 0.88),
_p(r'(?:Telefon|Tel|Rufnummer|Handy)[:\s]+(0\d{2,4}[-.\s/]?\d{3,8})', 'PHONE', 0.88, 1, flags=re.I),
# Dutch phone: +31 or 0X-XXXXXXXX
_p(r'(?:^|(?<=\s))\+31[-.\s]?\d[-.\s]?\d{3,4}[-.\s]?\d{4}\b', 'PHONE', 0.88),
_p(r'(?:telefoon|tel|bel)[:\s]+(0\d[-.\s]?\d{3,4}[-.\s]?\d{4})', 'PHONE', 0.85, 1, flags=re.I),
# Italian phone: +39 or 0XX-XXXXXXX / 3XX-XXXXXXX (mobile)
_p(r'(?:^|(?<=\s))\+39[-.\s]?\d{2,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b', 'PHONE', 0.88),
_p(r'(?:telefono|tel|cellulare)[:\s]+((?:0\d{1,3}|3\d{2})[-.\s/]?\d{3,4}[-.\s]?\d{3,4})', 'PHONE', 0.85, 1, flags=re.I),
# Portuguese phone: +351 or 9XX-XXX-XXX (mobile) / 2XX-XXX-XXX (landline)
_p(r'(?:^|(?<=\s))\+351[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{3}\b', 'PHONE', 0.88),
_p(r'(?:telefone|tel|telem[oó]vel)[:\s]+([239]\d{2}[-.\s]?\d{3}[-.\s]?\d{3})', 'PHONE', 0.85, 1, flags=re.I),
# Spanish phone: +34 or 6XX-XXX-XXX (mobile) / 9XX-XXX-XXX (landline)
_p(r'(?:^|(?<=\s))\+34[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{3}\b', 'PHONE', 0.88),
_p(r'(?:tel[ée]fono|tel|m[oó]vil)[:\s]+([69]\d{2}[-.\s]?\d{3}[-.\s]?\d{3})', 'PHONE', 0.85, 1, flags=re.I),
# Greek phone: +30 or 2X-XXXX-XXXX / 69X-XXX-XXXX (mobile)
_p(r'(?:^|(?<=\s))\+30[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b', 'PHONE', 0.88),
_p(r'(?:τηλ[εέ]φωνο|τηλ)[:\s]+((?:2\d|69\d)[-.\s]?\d{3,4}[-.\s]?\d{4})', 'PHONE', 0.85, 1, flags=re.I),
# Slovenian phone: +386 or 0X-XXX-XXXX
_p(r'(?:^|(?<=\s))\+386[-.\s]?\d{1,2}[-.\s]?\d{3}[-.\s]?\d{2,4}\b', 'PHONE', 0.88),

# === Korean RRN (Resident Registration Number) ===
# Format: YYMMDD-NNNNNNN
_p(r'(?:RRN|주민등록번호|resident\s+registration)[:\s#]+(\d{6}[-\s]\d{7})', 'KR_RRN', 0.92, 1, flags=re.I),

# === Thai National ID (TNIN) ===
# 13 digits starting with 1-8
_p(r'(?:Thai\s+(?:National\s+)?ID|TNIN|บัตรประชาชน)[:\s#]+([1-8]\d{12})', 'TH_TNIN', 0.92, 1, flags=re.I),

# === Indian GSTIN (GST Identification Number) ===
# 15 chars: 2-digit state code (01-37) + embedded PAN + registration + Z + checksum
_p(r'(?:GSTIN|GST\s+(?:No|Number|ID))[:\s#]+((?:0[1-9]|[1-3][0-7])[A-Z0-9]{10}[A-Z0-9]Z[A-Z0-9])', 'IN_GSTIN', 0.92, 1, flags=re.I),

# === Indian Voter ID (EPIC) ===
# 3 letters + 7 digits
_p(r'(?:Voter\s+ID|EPIC|elector\s+photo)[:\s#]+([A-Z]{3}\d{7})', 'IN_VOTER', 0.88, 1, flags=re.I),

# === ADDITIONAL DATE PATTERNS ===
# Bare European dot-separated dates: "15.03.1985", "03.15.1985"
# Uses 3 capture groups to enable date validation (month/day range checking).
_p(r'\b(\d{1,2})\.(\d{1,2})\.(\d{4})\b', 'DATE', 0.80),
# dd-MMM-yyyy (Oracle/DB format): "15-JAN-2024", "03-MAR-85"
_p(r'\b(\d{1,2})-(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)-(\d{2,4})\b', 'DATE', 0.80, flags=re.I),
# yyyy/mm/dd (slash variant of ISO)
_p(r'\b(\d{4})/(\d{1,2})/(\d{1,2})\b', 'DATE', 0.80),
# yyyymmdd (compact ISO, no separators) — common in Faker/DB dumps
# Anchored to 19xx/20xx century to avoid matching other 8-digit numbers.
_p(r'\b((?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))\b', 'DATE', 0.80),
# mm/yy (card expiration format, with context)
_p(r'(?:exp(?:ir(?:y|es|ation))?|valid\s+(?:thru|through|until))[:\s]+((?:0[1-9]|1[0-2])/\d{2})\b', 'DATE', 0.82, 1, flags=re.I),

# === SHORT DATE PATTERNS (M/YY or MM/YY with preposition context) ===
# Dates like "on 3/69", "by 10/17", "before 5/14" — preposition context is key
_p(r'(?:on|by|before|after|until|since|from|starting|ending|moved\s+to)\s+(\d{1,2}/\d{2})\b', 'DATE', 0.78, 1, flags=re.I),
# "birth date 9/59", "date of birth 5/05", "DOB 6/87" — DOB context
_p(r'(?:birth\s*(?:date)?|date\s+of\s+birth|DOB)[:\s]+(\d{1,2}/\d{2})\b', 'DATE_DOB', 0.82, 1, flags=re.I),
# "process by M/YY" / "initiate by M/YY" / "the process by M/YY"
_p(r'(?:process|initiate|complete|register|submit|validate)\s+(?:\S+\s+)?by\s+(\d{1,2}/\d{2})\b', 'DATE', 0.75, 1, flags=re.I),

# === AGE PATTERNS (supplementary — see also lines 884-892) ===
# Removed: bare "\d+ years?" (0.72) — too broad, matches "10 years warranty",
# "25 years of experience".  Contextual patterns handle real ages.
# Removed: duplicates of lines 884-892 (years old, year-old, age(X)).
# "of age X years" / "of age X"
_p(r'\bof\s+age\s+(\d{1,3})\b', 'AGE', 0.88, 1, flags=re.I),
# "Patient of X" / "individuals of X" — age in "of" context after person-word
_p(r'(?:patient|individual|person|child|adult|male|female)\s+of\s+(\d{1,3})\b', 'AGE', 0.82, 1, flags=re.I),
# "age group of X" — statistical/demographic
_p(r'\bage\s+group\s+of\s+(\d{1,3})\b', 'AGE', 0.88, 1, flags=re.I),
# "above/over/under X" — age threshold
_p(r'(?:individuals?|people|persons?|patients?|those)\s+(?:above|over|under|below)\s+(\d{1,3})\b', 'AGE', 0.80, 1, flags=re.I),


)


# VALIDATORS

def _validate_ip(ip: str) -> bool:
    """Validate an IPv4 or IPv6 address."""
    if ':' in ip:
        # IPv6: 3-8 groups of 1-4 hex digits separated by colons
        parts = ip.split(':')
        if len(parts) < 3 or len(parts) > 8:
            return False
        non_empty = [p for p in parts if p]
        if not all(
            len(p) <= 4 and all(c in '0123456789abcdefABCDEF' for c in p)
            for p in non_empty
        ):
            return False
        # Reject MAC-like patterns: exactly 6 groups, each exactly 2 hex chars
        # MAC addresses use colon-separated pairs (00:1A:2B:3C:4D:5E) which
        # the compressed IPv6 regex incorrectly matches.
        if len(parts) == 6 and all(len(p) == 2 for p in parts):
            return False
        return True
    # IPv4: 4 octets 0-255
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# Regex for version-string context before an IPv4 address.
# Matches "version 1.2.3.4", "v1.2.3.4", "build 1.2.3.4" etc.
# Uses \b to avoid matching inside words like "Server".
_IP_VERSION_CONTEXT = re.compile(
    r'\b(?:version|ver|build|release)\s*[=:.]?\s*$|'
    r'\bv\d*\s*[=:.]?\s*$',
    re.I,
)


def _validate_url(url: str) -> bool:
    """Validate URL has a plausible domain with at least one dot or localhost."""
    url = url.rstrip('.,;:!?)]\'"')
    try:
        after_scheme = url.split('://', 1)[1]
        domain = after_scheme.split('/')[0].split(':')[0].split('@')[-1]
    except (IndexError, ValueError):
        return False
    if '.' not in domain and domain.lower() != 'localhost':
        return False
    if '..' in domain:
        return False
    return len(domain) >= 3


def _validate_mac(value: str) -> bool:
    """Validate MAC address — reject trivial and time-like patterns."""
    parts = re.split(r'[:-]', value)
    if len(parts) != 6:
        return False
    # Reject if all groups are identical (trivial)
    if len(set(parts)) == 1:
        return False
    # Reject if all groups are pure decimal ≤ 59 (looks like time)
    if all(p.isdigit() and int(p) <= 59 for p in parts):
        return False
    return True


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


def _validate_imei(value: str) -> bool:
    """Validate an IMEI number using the Luhn algorithm.

    IMEI is 15 digits with a Luhn check digit. Rejects trivial patterns.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 15:
        return False
    if len(set(digits)) == 1:
        return False
    return _validate_luhn(digits)


def _validate_sin(value: str) -> bool:
    """Validate a Canadian Social Insurance Number.

    Checks: 9 digits, first digit 1-9, not all same digit, Luhn checksum.
    """
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) != 9:
        return False
    if digits[0] == '0':
        return False
    if len(set(digits)) == 1:
        return False
    return _validate_luhn(digits)


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
    'acct', 'account', 'record', 'file', 'document', 'doc',
    'no', 'num', '#', 'code', 'pin', 'serial', 'model',
    'part', 'item', 'sku', 'upc', 'isbn', 'version', 'ver',
    'batch', 'lot', 'catalog', 'product', 'unit', 'id',
    'make', 'type', 'series',
    # Financial context — digit sequences in financial text are rarely SSNs
    'routing', 'aba', 'rtn', 'balance', 'transaction', 'payment',
    'transfer', 'deposit', 'withdrawal', 'amount', 'total',
    'iban', 'swift', 'bic', 'bban',
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


# Entity types that represent proper nouns — the first letter of a detected
# value must be uppercase.  Used to catch IGNORECASE-broken matches where
# the regex [A-Z] class inadvertently matched lowercase text.
_PROPER_NOUN_TYPES = frozenset({
    'NAME', 'NAME_PATIENT', 'NAME_PROVIDER', 'NAME_RELATIVE',
    'FACILITY', 'EMPLOYER',
})

# Identifier entity types that must contain at least one digit.
# Pure alphabetic text like "Savings" or "Specialist" is never a real
# account number or member ID.
_IDENTIFIER_TYPES = frozenset({
    'ACCOUNT_NUMBER', 'HEALTH_PLAN_ID', 'MEMBER_ID',
})

# PASSWORD false positives — common words that appear after "password:"
# but are not actual password values (e.g., "password: protected").
_PASSWORD_FALSE_POSITIVES = frozenset({
    'protected', 'required', 'encrypted', 'enabled', 'disabled',
    'reset', 'expired', 'changed', 'updated', 'forgotten',
    'recovery', 'policy', 'manager', 'vault', 'strength',
    'complexity', 'requirements', 'authentication', 'security',
    'hash', 'hashed', 'hashing', 'salted', 'bcrypt', 'argon2',
    # Common words caught by broad contextual patterns
    'password', 'passwords', 'username', 'usernames', 'login',
    'provided', 'assigned', 'secure', 'secured', 'immediately',
    'information', 'details', 'profile', 'account', 'address',
    'contact', 'payment', 'membership', 'experience', 'success',
    'systems', 'system', 'individuals', 'academic', 'vehicle',
    'bank', 'banking', 'insights', 'settings', 'preferences',
    'credentials', 'credential', 'access', 'service', 'services',
    'number', 'code', 'previous', 'current', 'following',
    'original', 'existing', 'default', 'temporary',
})

# DRIVER_LICENSE date-like false positives — 8-digit values that look
# like YYYYMMDD dates should not be detected as driver license numbers.
_DL_DATE_PATTERN = re.compile(r'^(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])$')

# LICENSE_PLATE month-name false positives — "JAN-1990", "FEB-2005" etc.
# match the [A-Z]{3}[-\s]\d{4} plate pattern but are actually dates.
_MONTH_ABBREVS = frozenset({
    'JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN',
    'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC',
    # Date-context prefixes that match [A-Z]{3}[-\s]\d{4} plate pattern
    'DOB', 'DOD', 'DOS',  # Date of Birth/Death/Service
})

# DATE false positive context — words immediately before a bare numeric date
# that indicate the date is document metadata, not personal PII.
# Only applied to low-confidence bare patterns (≤0.70), not labeled dates.
# NOTE: Transactional words (invoice, order, receipt, confirmation,
# tracking, shipment, case, reference, ticket) deliberately excluded —
# dates in these contexts ARE personal PII (transaction dates).
_DATE_FP_PRECEDING = re.compile(
    r'(?:version|ver|rev(?:ision)?|release|build|patch|update|'
    r'edition|page|pg|section|sec|chapter|ch|item|code|'
    r'effective|published|filed|'
    r'created|modified|accessed|printed|generated|expires?|'
    r'valid\s+(?:from|until|thru|through))\s*'
    r'[#:\s.]*$',
    re.I,
)

# Single-word ADDRESS false positives — capitalized common words that
# follow "from", "lives in", etc. but are not place names.
_ADDRESS_FALSE_POSITIVES = frozenset({
    'female', 'male', 'technician', 'department', 'coordinator',
    'specialist', 'manager', 'director', 'supervisor', 'analyst',
    'consultant', 'engineer', 'assistant', 'representative',
    'administrator', 'executive', 'associate', 'officer', 'president',
    'secretary', 'treasurer', 'intern', 'volunteer', 'attorney',
    'counsel', 'nurse', 'doctor', 'therapist', 'technologist',
    'metical', 'dollar', 'euro', 'pound', 'franc', 'rupee', 'yen',
})

# Common English words that match city suffix patterns but are not cities.
# Prevents "Iceland" (-land), "Transport" (-port), "Waterford" (real city
# but also common word) etc. from being detected as standalone CITY.
_CITY_FALSE_POSITIVES = frozenset({
    'iceland', 'ireland', 'scotland', 'england', 'holland',
    'finland', 'greenland', 'swaziland', 'switzerland',
    'newfoundland', 'queensland', 'maryland', 'homeland',
    'farmland', 'woodland', 'grassland', 'marshland', 'wasteland',
    'transport', 'passport', 'airport', 'support', 'report',
    'import', 'export', 'comfort', 'effort', 'standford',
    'oxford', 'bedford', 'bradford', 'clifford', 'stratford',
    'hartford', 'crawford', 'stafford',
    'background', 'playground', 'underground',
    'highland', 'lowland', 'midland', 'overland',
    'understand', 'withstand', 'command',
    'sunderland', 'cumberland', 'northumberland',
    # Words ending in -worth, -field
    'worthwhile', 'noteworthy',
})

# Common English words that should never be detected as usernames.
# The USERNAME pattern trigger "user" is too generic and matches
# "user agent", "user feedback", "login details", etc.
_USERNAME_FALSE_POSITIVES = frozenset({
    'agent', 'agents', 'experience', 'interface', 'feedback',
    'details', 'detail', 'guide', 'manual', 'profile', 'profiles',
    'account', 'accounts', 'access', 'session', 'sessions',
    'request', 'requests', 'settings', 'preferences', 'data',
    'input', 'information', 'base', 'group', 'groups',
    'defined', 'generated', 'friendly', 'facing', 'centric',
    'name', 'names', 'level', 'space', 'story', 'stories',
    'flow', 'mode', 'role', 'roles', 'type', 'types',
    'error', 'errors', 'testing', 'test', 'validation',
    'management', 'service', 'services', 'credentials',
    'password', 'passwords', 'token', 'tokens',
    'number', 'numbers', 'holder', 'connected', 'ending',
    'expenses', 'online', 'physical', 'protected',
    'registered', 'page', 'page.', 'required', 'provided',
    'selected', 'submitted', 'approved', 'denied', 'blocked',
    'disabled', 'enabled', 'updated', 'created', 'deleted',
    # Brand names / technical terms with underscores
    'american_express', 'wi-fi', 'wi_fi', 'e-mail', 'e_mail',
    'pre-paid', 'pre_paid', 'co-pay', 'co_pay',
    # Additional FP words from benchmark analysis
    'diners_club', 'below', 'above', 'attempts', 'attempt',
    'login', 'logins', 'logout', 'signup', 'sign_up',
    'checkout', 'check_out', 'setup', 'set_up',
    'within', 'without', 'between', 'through',
    'policy', 'policies', 'report', 'reports',
    'process', 'processes', 'activity', 'activities',
})


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

                # Run pattern-specific validator (e.g., checksum, format checks)
                if pdef.validator is not None and not pdef.validator(value):
                    continue

                # IGNORECASE fix: patterns with case-insensitive flag make
                # [A-Z] match lowercase, defeating the uppercase-first-letter
                # requirement.  For proper-noun entity types, reject matches
                # where the captured text starts with a lowercase letter.
                if (pdef.pattern.flags & re.IGNORECASE
                        and pdef.entity_type in _PROPER_NOUN_TYPES
                        and value[0].isalpha()
                        and not value[0].isupper()):
                    continue

                # Post-validation for specific types
                if pdef.entity_type == 'IP_ADDRESS' and not _validate_ip(value):
                    continue

                # IPv4 context filter — reject version-string IPs
                if pdef.entity_type == 'IP_ADDRESS' and '.' in value:
                    pre_text = text[max(0, start - 20):start]
                    if _IP_VERSION_CONTEXT.search(pre_text):
                        continue

                # URL validation — reject URLs with invalid domains
                if pdef.entity_type == 'URL' and not _validate_url(value):
                    continue

                # MAC address validation — reject trivial/time-like patterns
                if pdef.entity_type == 'MAC_ADDRESS' and not _validate_mac(value):
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
                                if not _validate_date(m, d, y):
                                    continue
                            else:  # MM/DD/YYYY or DD/MM/YYYY
                                m, d, y = int(g1), int(g2), int(g3)
                                if not _validate_date(m, d, y):
                                    # Try DD/MM/YYYY interpretation
                                    d, m = int(g1), int(g2)
                                    if not _validate_date(m, d, y):
                                        continue
                    except (ValueError, IndexError) as e:
                        # Date parsing failed - accept match without validation
                        # This handles edge cases where regex groups don't match expected format
                        logger.debug(
                            f"Date validation skipped for '{value}': {type(e).__name__}: {e}"
                        )

                # DATE context false positive filter — bare numeric dates
                # preceded by document-metadata keywords are not personal PII.
                # Only applied to low-confidence bare patterns (≤0.70).
                if pdef.entity_type in ('DATE', 'DATE_DOB') and pdef.confidence <= 0.70:
                    preceding = text[max(0, start - 40):start]
                    if _DATE_FP_PRECEDING.search(preceding):
                        continue
                    # Compact YYYYMMDD dates in user-agent strings (Gecko/20100101)
                    if start >= 6 and text[start - 6:start] == 'Gecko/':
                        continue
                    if start >= 1 and text[start - 1] == '/':
                        # General: date immediately after '/' is likely a version/build token
                        before_slash = text[max(0, start - 20):start - 1].lower()
                        if any(w in before_slash for w in ('gecko', 'webkit', 'mozilla', 'chrome', 'safari', 'applewebkit')):
                            continue

                # Age validation - reject impossible ages
                if pdef.entity_type == 'AGE' and not _validate_age(value):
                    continue

                # SSN context validation
                if pdef.entity_type == 'SSN' and not _validate_ssn_context(text, start, pdef.confidence):
                    continue

                # Credit card Luhn validation (skip for CREDIT_CARD_NOLUHN)
                if pdef.entity_type == 'CREDIT_CARD' and not _validate_luhn(value):
                    continue

                # Canadian SIN validation
                if pdef.entity_type == 'SIN' and not _validate_sin(value):
                    continue

                # IMEI validation (Luhn check) — skip for labeled patterns (≥0.90)
                # where the IMEI: label provides sufficient context.
                # Synthetic datasets may not have valid Luhn check digits.
                if pdef.entity_type == 'IMEI' and pdef.confidence < 0.90 and not _validate_imei(value):
                    continue

                # NHS mod-11 checksum validation
                if pdef.entity_type == 'NHS_NUMBER' and not _validate_nhs(value):
                    continue

                # VIN validation (for low-confidence bare VIN matches)
                # Skip validation when VIN/vehicle context is nearby
                if pdef.entity_type == 'VIN' and pdef.confidence < 0.90:
                    surrounding = text[max(0, start - 60):min(len(text), end + 60)].lower()
                    has_vin_context = any(w in surrounding for w in (
                        'vin', 'vehicle', 'car', 'auto', 'motor',
                        'registration', 'registered', 'insurance', 'insured',
                        'title', 'odometer', 'mileage', 'license plate',
                        'dmv', 'dealer', 'manufacture',
                    ))
                    if not has_vin_context and not _validate_vin(value):
                        continue

                # Password false positive filter — common words after "password:"
                if pdef.entity_type == 'PASSWORD':
                    if value.lower().strip() in _PASSWORD_FALSE_POSITIVES:
                        continue

                # Driver license date-like filter — reject 8-digit YYYYMMDD dates
                if pdef.entity_type == 'DRIVER_LICENSE':
                    digits_only = ''.join(c for c in value if c.isdigit())
                    if len(digits_only) == 8 and _DL_DATE_PATTERN.match(digits_only):
                        continue

                # License plate month-name filter — "JAN-1990" etc. are dates, not plates
                if pdef.entity_type == 'LICENSE_PLATE':
                    alpha_prefix = ''.join(c for c in value if c.isalpha()).upper()
                    if alpha_prefix in _MONTH_ABBREVS:
                        continue

                # Username false positive filter — common words after "user" or "login"
                if pdef.entity_type == 'USERNAME':
                    if value.lower().strip() in _USERNAME_FALSE_POSITIVES:
                        continue

                # Identifier types must contain at least one digit — pure
                # alphabetic strings like "Savings" or "Specialist" are never
                # real account numbers or member IDs.
                # Exception: explicit account type name patterns (e.g., "Savings Account")
                if pdef.entity_type in _IDENTIFIER_TYPES and not any(c.isdigit() for c in value):
                    if not (pdef.entity_type == 'ACCOUNT_NUMBER' and 'account' in value.lower()):
                        continue

                # Address false positive filter — single common words after
                # "from"/"lives in" triggers are not place names.
                if pdef.entity_type == 'ADDRESS':
                    words = value.split()
                    if len(words) == 1 and words[0].lower() in _ADDRESS_FALSE_POSITIVES:
                        continue
                    # Suppress "Dear Dr" / "Hello Dr" matched as address
                    # ("Dr" = Drive street suffix, but preceded by greeting = Doctor)
                    val_lower = value.lower().strip()
                    if val_lower.endswith((' dr', ' dr.')):
                        before_addr = text[max(0, start - 10):start].lower().strip()
                        if before_addr.endswith(('dear', 'hello', 'hi', 'hey', 'welcome')):
                            continue

                # City false positive filter — common words matching city suffixes
                if pdef.entity_type == 'CITY' and value.lower() in _CITY_FALSE_POSITIVES:
                    continue

                # Name false positive filter
                if pdef.entity_type in ('NAME', 'NAME_PROVIDER', 'NAME_PATIENT', 'NAME_RELATIVE'):
                    if _is_false_positive_name(value):
                        continue

                # Remap internal-only entity types to canonical types
                entity_type = pdef.entity_type
                if entity_type == 'CREDIT_CARD_NOLUHN':
                    entity_type = 'CREDIT_CARD'

                # Deduplication: skip if same span already seen with equal or higher confidence
                key = (start, end, entity_type)
                if key in seen:
                    existing_idx = seen[key]
                    if pdef.confidence <= spans[existing_idx].confidence:
                        continue
                    # Replace existing span with higher-confidence match
                    spans[existing_idx] = Span(
                        start=start,
                        end=end,
                        text=value,
                        entity_type=entity_type,
                        confidence=pdef.confidence,
                        detector=self.name,
                        tier=self.tier,
                    )
                    continue

                span = Span(
                    start=start,
                    end=end,
                    text=value,
                    entity_type=entity_type,
                    confidence=pdef.confidence,
                    detector=self.name,
                    tier=self.tier,
                )
                seen[key] = len(spans)
                spans.append(span)

        return spans
