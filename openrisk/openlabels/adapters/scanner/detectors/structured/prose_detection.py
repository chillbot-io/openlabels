"""
Prose detection and value cleaning.

Rejects extracted 'values' that are actually prose sentences, not field values.
Also handles cleaning field values by removing trailing delimiters.
"""

import re


def looks_like_prose(value: str) -> bool:
    """
    Detect if extracted 'value' is actually prose, not a field value.

    Field values (names, IDs, dates) are short and structured.
    Prose has sentences, pronouns, verbs, and flows naturally.

    Returns True if this looks like prose (should be rejected).
    """
    # Empty or very short - let other validation handle
    if len(value) < 3:
        return False

    # Too long for a typical field value
    if len(value) > 60:
        return True

    # Contains sentence structure: period + space + capital
    if re.search(r'\.\s+[A-Z]', value):
        return True

    # Contains pipe delimiter (structured doc field separator)
    if '|' in value:
        return True

    # Contains prose pronouns (in the middle of text)
    if re.search(r'\s(he|she|they|his|her|their|him|them|it|its)\s', value, re.I):
        return True

    # Contains auxiliary/linking verbs (strong prose indicator)
    if re.search(
        r'\b(was|were|is|are|has|have|had|will|would|could|should|been|being)\b',
        value,
        re.I
    ):
        return True

    # Contains clinical prose verbs
    if re.search(
        r'\b(reports?|presents?|denies?|admits?|states?|feels?|feeling|'
        r'appears?|describes?|sleeps?|slept|lives?|lived)\b',
        value,
        re.I
    ):
        return True

    # Contains common prose transitions and time references
    if re.search(
        r'\b(today|yesterday|tonight|tomorrow|however|therefore|because|'
        r'although|after|before|during|while|since|until|also|then|now)\b',
        value,
        re.I
    ):
        return True

    # Contains prepositions that indicate prose
    if re.search(
        r'\b(at the|in the|on the|to the|for the|with the|from the)\b',
        value,
        re.I
    ):
        return True

    # Contains question words mid-value
    if re.search(r'\b(what|when|where|why|how|which|who)\b', value, re.I):
        return True

    # Multiple words starting lowercase after first word (prose flow)
    words = value.split()
    if len(words) >= 3:
        lowercase_count = sum(
            1 for w in words[1:]
            if w[0].islower() and w not in (
                'and', 'or', 'of', 'the', 'de', 'van', 'von', 'la', 'le'
            )
        )
        if lowercase_count >= 2:
            return True

    # Ends with common prose patterns
    if re.search(
        r'\b(well|better|worse|good|bad|okay|fine|much|very|really|'
        r'still|already|just|even|only)\s*$',
        value,
        re.I
    ):
        return True

    # Contains numbers in prose context
    if re.search(r'\b(in|for|about|approximately|around)\s+\d', value, re.I):
        return True

    # Starts with preposition
    if re.match(
        r'^(at|to|in|on|by|with|without|for|from|about|after|before|'
        r'during|through|into|onto|upon)\s+',
        value,
        re.I
    ):
        return True

    # Contains clinical symptom words
    if re.search(
        r'\b(weakness|palpitations?|dizziness|fatigue|nausea|vomiting|pain|'
        r'swelling|fever|cough|dyspnea|chest\s+pain|shortness|headache|symptoms?)\b',
        value,
        re.I
    ):
        return True

    return False


def clean_field_value(value: str, phi_type: str) -> str:
    """
    Clean extracted value by removing trailing delimiters and junk.

    Handles common structured document patterns where field separators
    bleed into the value.
    """
    # Remove trailing pipe and everything after (field delimiter)
    if '|' in value:
        value = value.split('|')[0].strip()

    # Remove trailing colons (next label starting)
    value = re.sub(r'\s*:\s*$', '', value)

    # For dates: stop at common suffixes that aren't part of the date
    if phi_type in ('DATE', 'DATE_DOB'):
        value = re.sub(r'\s*\|?\s*Age\s*:?\s*\d*\s*$', '', value, flags=re.I)
        value = re.sub(r'\s+(MRN|SSN|Sex|Gender|Room|Bed)\s*:?\s*$', '', value, flags=re.I)

    # For names: stop at common suffixes
    if phi_type in ('NAME', 'NAME_PATIENT', 'NAME_PROVIDER'):
        value = re.sub(r'\s+(DOB|MRN|SSN|ID)\s*:?\s*$', '', value, flags=re.I)
        value = re.sub(r'\s*\([^)]*$', '', value)

    return value.strip()
