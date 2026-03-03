"""False-positive filter sets and functions for pattern detection.

Contains frozensets for rejecting common false positives (names, addresses,
usernames, cities, dates, etc.) and filter functions like
_is_false_positive_name and _is_field_name.
"""

from __future__ import annotations

import re


# FALSE POSITIVE FILTERS

# Common words/phrases that get incorrectly matched as names
# These are document headers, labels, medical terms that match NAME patterns
FALSE_POSITIVE_NAMES: frozenset[str] = frozenset({
    # Document types/headers
    "LABORATORY", "REPORT", "LICENSE", "CERTIFICATE", "DOCUMENT",
    "INSURANCE", "CARD", "STATEMENT", "RECORD", "FORM", "APPLICATION",
    "DISCHARGE", "SUMMARY", "ASSESSMENT", "EVALUATION", "CONSULTATION",
    "HISTORY", "PHYSICAL", "PROGRESS", "NOTE", "NOTES", "CHART",

    # Field labels that might match
    "MRN", "DOB", "SSN", "DOD", "DOS", "NPI", "DEA", "EXP", "ISS",
    "PATIENT", "PROVIDER", "MEMBER", "SUBSCRIBER", "INSURED",
    "FACILITY", "HOSPITAL", "CLINIC", "PHARMACY",

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
    "COMPLIANCE", "LEGAL", "TECHNICAL",
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
    "SOLUTIONS",
    "PROGRAM", "PROGRAMMES", "INITIATIVE",

    # Gretel PII FP analysis — domain phrases detected as names
    "ROOM", "ACCESS", "LEVEL", "ENERGY", "UTILITIES",
    "DEFENDANT", "NUMBERS", "RECORDS", "SYSTEM",
    "AVIONICS", "ROTTERDAM", "NETHERLANDS", "AMSTERDAM",
    "PLAINTIFF", "HOLDER", "AUTHOR",
    "REASON", "MARINE", "SUMMIT", "AVIATION", "LOGISTICS",
    "INDUSTRIAL", "COMMERCIAL", "RESIDENTIAL",
    "MUNICIPAL", "REGULATORY", "JUDICIAL",

    # AI4Privacy 10k FP analysis — gender identity terms detected as names
    "CISGENDER", "TRANSEXUAL", "TRANSSEXUAL", "NEUTROIS",
    "GENDERQUEER", "GENDERFLUID", "AGENDER", "BIGENDER",
    "PANGENDER", "ANDROGYNOUS", "INTERSEX",
    # Common words/phrases detected as names at scale
    "PRODUCER", "PARTICULARLY", "NOTABLY", "LASTLY",
    "ALTERNATIVELY",
    "PREVIOUSLY", "PRIMARILY", "ESSENTIALLY",
    "NOW", "THIS", "SAMPLE",
    "TERMINATION", "MEMORIAL",
    "VETERAN", "VETERANS", "PRAIRIE",
})

# Module-level frozensets for O(1) lookups in _is_false_positive_name
_CURRENCY_WORDS = frozenset({
    "DOLLAR", "DINAR", "RIAL", "EURO", "POUND", "FRANC", "YEN", "WON",
    "PESO", "RUPEE", "LIRA", "KRONA", "KRONE", "BAHT", "YUAN", "RUBLE",
    "RAND", "RINGGIT", "SHEKEL", "OMANI", "BAHRAINI", "SINGAPORE",
    "ZIMBABWE", "CURRENCY",
})

_ROLE_WORDS = frozenset({
    "STAFF", "DEPARTMENT", "ENGINEER", "DEVELOPER", "PLANNER", "MANAGER",
    "DIRECTOR", "ANALYST", "SPECIALIST", "COORDINATOR", "NURSE", "CARE",
    "MOBILITY", "CREATIVE", "INFRASTRUCTURE", "NEUROPSYCHOLOGISTS",
    "NEUROPSYCHOLOGIST",
})

_DOCUMENT_FIRST_WORDS = frozenset({
    "LABORATORY", "REPORT", "LICENSE", "CERTIFICATE", "DOCUMENT",
    "INSURANCE", "DISCHARGE", "SUMMARY", "ASSESSMENT", "CONSULTATION",
})

_DOCUMENT_LAST_WORDS = frozenset({
    "REPORT", "REPORTS", "FORM", "DOCUMENT", "CERTIFICATE", "LICENSE",
    "SUMMARY", "RESULTS", "HISTORY", "NOTES", "CHART",
})

_VALID_CREDENTIALS = frozenset({"MD", "DO", "PA", "NP", "RN", "PHD", "DNP", "APRN", "PAC"})

_US_STATE_ABBREVS = frozenset({
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
    "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
    "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
    "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
    "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY", "DC",
})


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
    if any(w.upper() in _CURRENCY_WORDS for w in words):
        return True

    # If ANY word is a common non-name word (job titles, departments, roles)
    # and the match has multiple words, reject
    if len(words) >= 2 and any(w.upper() in _ROLE_WORDS for w in words):
        return True

    # If first word is a common document term (not a name), likely FP
    if words and words[0].upper() in _DOCUMENT_FIRST_WORDS:
        return True

    # If last word is a common document term, likely FP (catches "Y REPORT", "RY REPORT")
    if words and words[-1].upper() in _DOCUMENT_LAST_WORDS:
        return True

    # Check for patterns that look like document text fragments
    # e.g., "Y REPORT", "A visitPA", "RY REPORT"
    # These usually have very short first words or all-caps
    if len(words) >= 2:
        first_word = words[0]
        last_word = words[-1]

        # Short first word + document term = likely fragment (e.g., "Y REPORT")
        # BUT exclude valid medical credentials after a comma (e.g., "E. Washington, MD")
        if len(first_word) <= 2 and last_word.upper() in FALSE_POSITIVE_NAMES:
            # Exception: comma + credential = valid provider name
            last_clean = last_word.upper().replace("-", "")
            if not ("," in value and last_clean in _VALID_CREDENTIALS):
                return True

        # Check if ends with state abbreviation mistaken for credentials
        if last_word.upper() in _US_STATE_ABBREVS:
            # Check for "City, STATE" pattern (address, not name)
            # Pattern: "Baltimore, MD" or "New York, NY"
            # Real credentials would be "John Smith, MD" (name + credential)
            if "," in value:
                # Split at comma to check what's before it
                before_comma = value.rsplit(",", 1)[0].strip()
                before_words = before_comma.split()

                # If only 1-2 words before comma, likely a city not a person
                # "Baltimore, MD" = 1 word -> city
                # "New York, NY" = 2 words -> city
                # "San Francisco, CA" = 2 words -> city
                # "John Smith, MD" = 2 words -> could be either, but...
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
# Only applied to low-confidence bare patterns (<=0.70), not labeled dates.
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

# Snake_case segments that indicate a field/variable name, not a username.
# If ANY segment of a snake_case identifier is in this set, it's a field name.
_FIELD_NAME_SEGMENTS = frozenset({
    'id', 'identifier', 'name', 'number', 'code', 'type', 'data',
    'date', 'time', 'timestamp', 'key', 'value', 'index', 'count',
    'rate', 'score', 'level', 'status', 'state', 'mode', 'flag',
    'color', 'colour', 'size', 'width', 'height', 'length', 'weight',
    'address', 'email', 'phone', 'url', 'path', 'file', 'dir',
    'entries', 'entry', 'record', 'records', 'field', 'fields',
    'participant', 'patient', 'user', 'unique', 'primary',
    'biometric', 'measurements', 'traits', 'phenotypic',
    'birth', 'death', 'created', 'updated', 'modified', 'deleted',
    'heart', 'blood', 'pressure', 'temperature', 'pulse',
    'eye', 'hair', 'skin', 'facial',
    'timestamped',
})


def _is_field_name(value: str) -> bool:
    """Return True if value looks like a snake_case field/variable name.

    Usernames with underscores are typically First_Last (2 segments, mixed case).
    Field names like "unique_participant_id" have 3+ all-lowercase segments, or
    contain known programming/data field terms.
    """
    if '_' not in value:
        return False

    segments = [s for s in value.split('_') if s]

    # 3+ all-lowercase segments is almost always a field name
    if len(segments) >= 3 and all(s.islower() for s in segments):
        return True

    # Any segment matching a known field-name keyword
    lower_segments = {s.lower() for s in segments}
    if lower_segments & _FIELD_NAME_SEGMENTS:
        return True

    return False


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
    # Single-word FPs from nemotron_pii benchmark (also in ML blocklist
    # but needed here for pattern-tier suppression)
    'training', 'license', 'licenses', 'licensed', 'obligations',
    'named', 'multiple', 'authenticated', 're-authenticated',
    'authorization', 'certification', 'qualification',
    'confirmation', 'verification', 'recommended',
    'implemented', 'distributed', 'administered',
})

