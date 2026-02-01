"""False positive filters for name detection."""

from typing import Set


FALSE_POSITIVE_NAMES: Set[str] = {
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

_FALSE_POSITIVE_NAMES_LOWER = {s.lower() for s in FALSE_POSITIVE_NAMES}

_DOCUMENT_TERMS_START = frozenset({
    "LABORATORY", "REPORT", "LICENSE", "CERTIFICATE", "DOCUMENT",
    "INSURANCE", "DISCHARGE", "SUMMARY", "ASSESSMENT", "CONSULTATION",
})

_DOCUMENT_TERMS_END = frozenset({
    "REPORT", "REPORTS", "FORM", "DOCUMENT", "CERTIFICATE", "LICENSE",
    "SUMMARY", "RESULTS", "HISTORY", "NOTES", "CHART",
})

_VALID_CREDENTIALS = frozenset({
    "MD", "DO", "PA", "NP", "RN", "PHD", "DNP", "APRN", "PAC"
})

_US_STATE_ABBREVS = frozenset({
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
    "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
    "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
    "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
    "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY", "DC"
})

_CITY_WORDS = frozenset({
    "city", "york", "orleans", "angeles", "francisco",
    "diego", "antonio", "vegas", "beach", "springs",
    "falls", "rapids", "creek", "river", "lake", "park",
    "heights", "hills", "valley", "grove", "point"
})


def _is_too_short(value: str, words: list) -> bool:
    if len(words) == 1 and len(words[0]) == 1:
        return True
    if len(value.replace(' ', '')) < 3:
        return True
    return False


def _all_words_are_false_positives(words: list) -> bool:
    return all(w.upper() in FALSE_POSITIVE_NAMES for w in words)


def _has_document_term_boundary(words: list) -> bool:
    if not words:
        return False
    if words[0].upper() in _DOCUMENT_TERMS_START:
        return True
    if words[-1].upper() in _DOCUMENT_TERMS_END:
        return True
    return False


def _is_fragment_with_fp_suffix(value: str, words: list) -> bool:
    if len(words) < 2:
        return False

    first_word, last_word = words[0], words[-1]

    if len(first_word) <= 2 and last_word.upper() in FALSE_POSITIVE_NAMES:
        last_clean = last_word.upper().replace("-", "")
        if not ("," in value and last_clean in _VALID_CREDENTIALS):
            return True
    return False


def _is_city_state_pattern(value: str, words: list) -> bool:
    """
    Check if value looks like a city/state pattern (e.g., "Sacramento CA").

    Returns True only when there's clear evidence of a city pattern,
    not just any string ending in a state abbreviation.
    """
    if len(words) < 2:
        return False

    last_word = words[-1]
    if last_word.upper() not in _US_STATE_ABBREVS:
        return False

    # Get words before the state abbreviation
    before_state = words[:-1]

    if "," in value:
        # With comma: "City, ST" or "City Name, ST"
        before_comma = value.rsplit(",", 1)[0].strip()
        before_words = before_comma.split()

        if len(before_words) == 1:
            return True
        if len(before_words) >= 2 and any(w.lower() in _CITY_WORDS for w in before_words):
            return True
    else:
        # Without comma: be conservative to avoid filtering real names
        # Only match single-word cities or multi-word with city indicators
        if len(before_state) == 1:
            # Single word before state - likely a city (e.g., "Sacramento CA")
            return True
        # Multi-word: only if it contains a city-like word (e.g., "New York NY")
        if any(w.lower() in _CITY_WORDS for w in before_state):
            return True

    return False


def _ends_with_fp_fragment(value: str) -> bool:
    for fp in ("visitPA", "visitMA", "visitNY"):
        if value.endswith(fp):
            return True
    return False


def is_false_positive_name(value: str) -> bool:
    """Check if a detected name is likely a false positive."""
    words = value.split()

    if _is_too_short(value, words):
        return True
    if _all_words_are_false_positives(words):
        return True
    if _has_document_term_boundary(words):
        return True
    if _is_fragment_with_fp_suffix(value, words):
        return True
    if _is_city_state_pattern(value, words):
        return True
    if _ends_with_fp_fragment(value):
        return True

    return False
