"""
Structured Document Extractor

Rule-based PHI extraction for labeled documents (IDs, insurance cards, forms).
Handles 80-90% of structured documents without ML by:
1. Post-processing OCR to fix common issues
2. Detecting field labels (DOB:, NAME:, etc.)
3. Extracting values based on label semantics
4. Pattern-matching unlabeled but structured data

This runs BEFORE ML detection, providing high-confidence extractions
that take precedence in the tier system.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set

from ..types import Span
from ..constants import MAX_STRUCTURED_VALUE_LENGTH

logger = logging.getLogger(__name__)


# PROSE DETECTION
# Reject extracted "values" that are actually prose sentences, not field values.

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
    # Names: ~30 chars max, IDs: ~20, Dates: ~20, Addresses: ~60
    if len(value) > 60:
        return True
    
    # Contains sentence structure: period + space + capital (new sentence)
    if re.search(r'\.\s+[A-Z]', value):
        return True
    
    # Contains pipe delimiter (structured doc field separator, not part of value)
    # e.g., "1979-11-07 | Age: 70" - the value should stop at the pipe
    if '|' in value:
        return True
    
    # Contains prose pronouns (in the middle of text, not as the value itself)
    # Allows "He" as a standalone name but catches "He slept well"
    if re.search(r'\s(he|she|they|his|her|their|him|them|it|its)\s', value, re.I):
        return True
    
    # Contains auxiliary/linking verbs (strong prose indicator)
    if re.search(r'\b(was|were|is|are|has|have|had|will|would|could|should|been|being)\b', value, re.I):
        return True
    
    # Contains clinical prose verbs
    if re.search(r'\b(reports?|presents?|denies?|admits?|states?|feels?|feeling|appears?|describes?|sleeps?|slept|lives?|lived)\b', value, re.I):
        return True
    
    # Contains common prose transitions and time references
    if re.search(r'\b(today|yesterday|tonight|tomorrow|however|therefore|because|although|after|before|during|while|since|until|also|then|now)\b', value, re.I):
        return True
    
    # Contains prepositions that indicate prose (not addresses)
    # "at" is okay in addresses, but "at the" is prose
    if re.search(r'\b(at the|in the|on the|to the|for the|with the|from the)\b', value, re.I):
        return True
    
    # Contains question words mid-value
    if re.search(r'\b(what|when|where|why|how|which|who)\b', value, re.I):
        return True
    
    # Multiple words starting lowercase after first word (prose flow)
    # "John Smith" is fine, "John went to" is prose
    words = value.split()
    if len(words) >= 3:
        lowercase_count = sum(1 for w in words[1:] if w[0].islower() and w not in ('and', 'or', 'of', 'the', 'de', 'van', 'von', 'la', 'le'))
        if lowercase_count >= 2:
            return True
    
    # Ends with common prose patterns
    if re.search(r'\b(well|better|worse|good|bad|okay|fine|much|very|really|still|already|just|even|only)\s*$', value, re.I):
        return True
    
    # Contains numbers in prose context ("in 1-2 weeks", "for 3 days")
    if re.search(r'\b(in|for|about|approximately|around)\s+\d', value, re.I):
        return True
    
    # Starts with preposition (can't be a name or field value)
    if re.match(r'^(at|to|in|on|by|with|without|for|from|about|after|before|during|through|into|onto|upon)\s+', value, re.I):
        return True
    
    # Contains clinical symptom words (these are descriptions, not field values)
    if re.search(r'\b(weakness|palpitations?|dizziness|fatigue|nausea|vomiting|pain|swelling|fever|cough|dyspnea|chest\s+pain|shortness|headache|symptoms?)\b', value, re.I):
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
        # Remove trailing "Age: XX" or "| Age:" patterns
        value = re.sub(r'\s*\|?\s*Age\s*:?\s*\d*\s*$', '', value, flags=re.I)
        # Remove trailing field labels
        value = re.sub(r'\s+(MRN|SSN|Sex|Gender|Room|Bed)\s*:?\s*$', '', value, flags=re.I)
    
    # For names: stop at common suffixes
    if phi_type in ('NAME', 'NAME_PATIENT', 'NAME_PROVIDER'):
        # Remove trailing DOB/MRN indicators
        value = re.sub(r'\s+(DOB|MRN|SSN|ID)\s*:?\s*$', '', value, flags=re.I)
        # Remove trailing parenthetical info
        value = re.sub(r'\s*\([^)]*$', '', value)
    
    return value.strip()


# LABEL TAXONOMY
# Maps field labels found in documents to PHI entity types.
# None = recognized label but value is not PHI (skip redaction)

LABEL_TO_PHI_TYPE: Dict[str, Optional[str]] = {
    # -------------------------------------------------------------------------
    # Names
    # -------------------------------------------------------------------------
    "NAME": "NAME",
    "PATIENT": "NAME_PATIENT",
    "PATIENT NAME": "NAME_PATIENT",
    "MEMBER": "NAME",
    "MEMBER NAME": "NAME",
    "SUBSCRIBER": "NAME",
    "SUBSCRIBER NAME": "NAME",
    "INSURED": "NAME",
    "INSURED NAME": "NAME",
    "CARDHOLDER": "NAME",
    "BENEFICIARY": "NAME",
    "BENEFICIARY NAME": "NAME",
    "DEPENDENT": "NAME",
    "DEPENDENT NAME": "NAME",
    "FN": "NAME",  # First Name
    "LN": "NAME",  # Last Name
    "FIRST NAME": "NAME",
    "LAST NAME": "NAME",
    "MIDDLE NAME": "NAME",
    "FULL NAME": "NAME",
    "LEGAL NAME": "NAME",
    "MAIDEN NAME": "NAME",
    "PROVIDER": "NAME_PROVIDER",
    "PROVIDER NAME": "NAME_PROVIDER",
    "PHYSICIAN": "NAME_PROVIDER",
    "DOCTOR": "NAME_PROVIDER",
    "DR": "NAME_PROVIDER",
    "PRESCRIBER": "NAME_PROVIDER",
    "ORDERING": "NAME_PROVIDER",
    "ATTENDING": "NAME_PROVIDER",
    "PCP": "NAME_PROVIDER",
    "PRIMARY CARE": "NAME_PROVIDER",
    "EMPLOYER": "NAME",
    "EMPLOYER NAME": "NAME",
    "EMERGENCY CONTACT": "NAME",
    "CONTACT NAME": "NAME",
    "GUARDIAN": "NAME",
    "PARENT": "NAME",
    "SPOUSE": "NAME",
    
    # -------------------------------------------------------------------------
    # Dates
    # -------------------------------------------------------------------------
    "DOB": "DATE_DOB",
    "BIRTH": "DATE_DOB",
    "BIRTHDATE": "DATE_DOB",
    "DATE OF BIRTH": "DATE_DOB",
    "BORN": "DATE_DOB",
    "BD": "DATE_DOB",
    "BDAY": "DATE_DOB",
    "EXP": "DATE",
    "EXPIRATION": "DATE",
    "EXPIRY": "DATE",
    "EXPIRES": "DATE",
    "EXPIRATION DATE": "DATE",
    "VALID THRU": "DATE",
    "VALID THROUGH": "DATE",
    "ISS": "DATE",
    "ISSUED": "DATE",
    "ISSUE DATE": "DATE",
    "DATE ISSUED": "DATE",
    "EFFECTIVE": "DATE",
    "EFFECTIVE DATE": "DATE",
    "EFF DATE": "DATE",
    "START DATE": "DATE",
    "ADMIT": "DATE",
    "ADMIT DATE": "DATE",
    "ADMISSION": "DATE",
    "ADMISSION DATE": "DATE",
    "DISCHARGE": "DATE",
    "DISCHARGE DATE": "DATE",
    "DOS": "DATE",  # Date of Service
    "DATE OF SERVICE": "DATE",
    "SERVICE DATE": "DATE",
    "PROCEDURE DATE": "DATE",
    "COLLECTION DATE": "DATE",
    "SPECIMEN DATE": "DATE",
    "RESULT DATE": "DATE",
    "REPORT DATE": "DATE",
    "VISIT DATE": "DATE",
    "APPOINTMENT": "DATE",
    "SCHEDULED": "DATE",
    
    # -------------------------------------------------------------------------
    # Government/Official IDs
    # -------------------------------------------------------------------------
    "DL": "DRIVER_LICENSE",
    "DLN": "DRIVER_LICENSE",
    "LICENSE": "DRIVER_LICENSE",
    "LICENSE NO": "DRIVER_LICENSE",
    "LICENSE NUM": "DRIVER_LICENSE",
    "LICENSE NUMBER": "DRIVER_LICENSE",
    "DRIVER LICENSE": "DRIVER_LICENSE",
    "DRIVERS LICENSE": "DRIVER_LICENSE",
    "DRIVER'S LICENSE": "DRIVER_LICENSE",
    "DRIVING LICENSE": "DRIVER_LICENSE",
    "CDL": "DRIVER_LICENSE",  # Commercial DL
    "SSN": "SSN",
    "SS": "SSN",
    "SS#": "SSN",
    "SSN#": "SSN",
    "SOCIAL": "SSN",
    "SOCIAL SECURITY": "SSN",
    "SOC SEC": "SSN",
    "PASSPORT": "PASSPORT",
    "PASSPORT NO": "PASSPORT",
    "PASSPORT NUMBER": "PASSPORT",
    
    # -------------------------------------------------------------------------
    # Medical Record IDs
    # -------------------------------------------------------------------------
    "MRN": "MRN",
    "MR#": "MRN",
    "MRN#": "MRN",
    "MEDICAL RECORD": "MRN",
    "MEDICAL RECORD #": "MRN",
    "MEDICAL RECORD NO": "MRN",
    "MEDICAL RECORD NUMBER": "MRN",
    "MED REC": "MRN",
    "PATIENT ID": "MRN",
    "PATIENT NO": "MRN",
    "PATIENT NUMBER": "MRN",
    "PT ID": "MRN",
    "CHART": "MRN",
    "CHART NO": "MRN",
    "CHART NUMBER": "MRN",
    "ENCOUNTER": "ENCOUNTER_ID",
    "ENCOUNTER ID": "ENCOUNTER_ID",
    "ENCOUNTER NO": "ENCOUNTER_ID",
    "VISIT ID": "ENCOUNTER_ID",
    "VISIT NO": "ENCOUNTER_ID",
    "ACCESSION": "ACCESSION_ID",
    "ACCESSION NO": "ACCESSION_ID",
    "ACCESSION NUMBER": "ACCESSION_ID",
    "ACC": "ACCESSION_ID",
    "ACC#": "ACCESSION_ID",
    "SPECIMEN ID": "ACCESSION_ID",
    "CASE NO": "ACCESSION_ID",
    "CASE NUMBER": "ACCESSION_ID",
    "REQ": "ACCESSION_ID",  # Requisition
    "REQUISITION": "ACCESSION_ID",
    
    # -------------------------------------------------------------------------
    # Insurance/Health Plan IDs
    # -------------------------------------------------------------------------
    "MEMBER ID": "HEALTH_PLAN_ID",
    "MEMBER NO": "HEALTH_PLAN_ID",
    "MEMBER NUMBER": "HEALTH_PLAN_ID",
    "MEMBER#": "HEALTH_PLAN_ID",
    "SUBSCRIBER ID": "HEALTH_PLAN_ID",
    "SUBSCRIBER NO": "HEALTH_PLAN_ID",
    "SUBSCRIBER NUMBER": "HEALTH_PLAN_ID",
    "GROUP": "HEALTH_PLAN_ID",
    "GROUP ID": "HEALTH_PLAN_ID",
    "GROUP NO": "HEALTH_PLAN_ID",
    "GROUP NUMBER": "HEALTH_PLAN_ID",
    "GRP": "HEALTH_PLAN_ID",
    "POLICY": "HEALTH_PLAN_ID",
    "POLICY NO": "HEALTH_PLAN_ID",
    "POLICY NUMBER": "HEALTH_PLAN_ID",
    "PLAN ID": "HEALTH_PLAN_ID",
    "PLAN NO": "HEALTH_PLAN_ID",
    "INSURANCE ID": "HEALTH_PLAN_ID",
    "INSURER ID": "HEALTH_PLAN_ID",
    "PAYER ID": "HEALTH_PLAN_ID",
    "CARRIER ID": "HEALTH_PLAN_ID",
    "CONTRACT": "HEALTH_PLAN_ID",
    "CONTRACT NO": "HEALTH_PLAN_ID",
    "CERT": "HEALTH_PLAN_ID",
    "CERT NO": "HEALTH_PLAN_ID",
    "CERTIFICATE": "HEALTH_PLAN_ID",
    "CERTIFICATE NO": "HEALTH_PLAN_ID",
    "RX BIN": "HEALTH_PLAN_ID",
    "BIN": "HEALTH_PLAN_ID",
    "PCN": "HEALTH_PLAN_ID",
    "RX PCN": "HEALTH_PLAN_ID",
    "RX GRP": "HEALTH_PLAN_ID",
    "RX GROUP": "HEALTH_PLAN_ID",
    "MEDICARE": "MEDICARE_ID",
    "MEDICARE ID": "MEDICARE_ID",
    "MEDICARE NO": "MEDICARE_ID",
    "MEDICARE NUMBER": "MEDICARE_ID",
    "HICN": "MEDICARE_ID",  # Health Insurance Claim Number
    "MBI": "MEDICARE_ID",  # Medicare Beneficiary Identifier
    "MEDICAID": "HEALTH_PLAN_ID",
    "MEDICAID ID": "HEALTH_PLAN_ID",
    "MEDICAID NO": "HEALTH_PLAN_ID",
    
    # -------------------------------------------------------------------------
    # Financial/Account IDs
    # -------------------------------------------------------------------------
    "ACCOUNT": "ACCOUNT_NUMBER",
    "ACCT": "ACCOUNT_NUMBER",
    "ACCT NO": "ACCOUNT_NUMBER",
    "ACCOUNT NO": "ACCOUNT_NUMBER",
    "ACCOUNT NUMBER": "ACCOUNT_NUMBER",
    "ACCOUNT#": "ACCOUNT_NUMBER",
    "FIN": "ACCOUNT_NUMBER",  # Financial Number
    "GUARANTOR": "ACCOUNT_NUMBER",
    "BILLING": "ACCOUNT_NUMBER",
    "INVOICE": "ACCOUNT_NUMBER",
    
    # -------------------------------------------------------------------------
    # Generic IDs (lower confidence fallback)
    # -------------------------------------------------------------------------
    "ID": "ID_NUMBER",
    "ID NO": "ID_NUMBER",
    "ID NUMBER": "ID_NUMBER",
    "ID#": "ID_NUMBER",
    "NO": "ID_NUMBER",
    "NUM": "ID_NUMBER",
    "NUMBER": "ID_NUMBER",
    "#": "ID_NUMBER",
    "REF": "ID_NUMBER",
    "REF NO": "ID_NUMBER",
    "REFERENCE": "ID_NUMBER",
    "REFERENCE NO": "ID_NUMBER",
    "DD": "DOCUMENT_ID",  # Document Discriminator (on IDs)
    "DCN": "DOCUMENT_ID",  # Document Control Number
    "DOC": "DOCUMENT_ID",
    "DOC NO": "DOCUMENT_ID",
    "DOCUMENT": "DOCUMENT_ID",
    "DOCUMENT NO": "DOCUMENT_ID",
    
    # -------------------------------------------------------------------------
    # Address Components
    # -------------------------------------------------------------------------
    "ADDR": "ADDRESS",
    "ADDRESS": "ADDRESS",
    "STREET": "ADDRESS",
    "STREET ADDRESS": "ADDRESS",
    "MAILING": "ADDRESS",
    "MAILING ADDRESS": "ADDRESS",
    "HOME": "ADDRESS",
    "HOME ADDRESS": "ADDRESS",
    "RESIDENCE": "ADDRESS",
    "RESIDENTIAL": "ADDRESS",
    "CITY": "ADDRESS",
    "STATE": "ADDRESS",
    "ZIP": "ZIP",
    "ZIP CODE": "ZIP",
    "ZIPCODE": "ZIP",
    "POSTAL": "ZIP",
    "POSTAL CODE": "ZIP",
    
    # -------------------------------------------------------------------------
    # Contact Information
    # -------------------------------------------------------------------------
    "PHONE": "PHONE",
    "PH": "PHONE",
    "TEL": "PHONE",
    "TELEPHONE": "PHONE",
    "CELL": "PHONE",
    "MOBILE": "PHONE",
    "HOME PHONE": "PHONE",
    "WORK PHONE": "PHONE",
    "CONTACT": "PHONE",
    "FAX": "FAX",
    "FACSIMILE": "FAX",
    "EMAIL": "EMAIL",
    "E-MAIL": "EMAIL",
    "ELECTRONIC MAIL": "EMAIL",

    # Network identifiers
    "IP": "IP_ADDRESS",
    "IP ADDRESS": "IP_ADDRESS",
    "IP ADDR": "IP_ADDRESS",
    "CLIENT IP": "IP_ADDRESS",
    "PATIENT IP": "IP_ADDRESS",
    "SOURCE IP": "IP_ADDRESS",
    "MAC": "MAC_ADDRESS",
    "MAC ADDRESS": "MAC_ADDRESS",
    "MAC ADDR": "MAC_ADDRESS",

    # -------------------------------------------------------------------------
    # Device Identifiers (medical devices, serial numbers)
    # -------------------------------------------------------------------------
    "SERIAL": "DEVICE_ID",
    "SERIAL NO": "DEVICE_ID",
    "SERIAL NUMBER": "DEVICE_ID",
    "SN": "DEVICE_ID",
    "S/N": "DEVICE_ID",
    "UDI": "DEVICE_ID",
    "DEVICE ID": "DEVICE_ID",
    "DEVICE IDENTIFIER": "DEVICE_ID",
    "MODEL NUMBER": "DEVICE_ID",
    "MODEL NO": "DEVICE_ID",
    "LOT": "DEVICE_ID",
    "LOT NO": "DEVICE_ID",
    "LOT NUMBER": "DEVICE_ID",

    # -------------------------------------------------------------------------
    # Vehicle Identifiers
    # -------------------------------------------------------------------------
    "LICENSE PLATE": "LICENSE_PLATE",
    "PLATE": "LICENSE_PLATE",
    "PLATE NO": "LICENSE_PLATE",
    "PLATE NUMBER": "LICENSE_PLATE",
    "TAG": "LICENSE_PLATE",
    "TAG NO": "LICENSE_PLATE",
    "TAG NUMBER": "LICENSE_PLATE",
    "VEHICLE PLATE": "LICENSE_PLATE",
    "VIN": "VIN",
    "VEHICLE ID": "VIN",
    "VEHICLE IDENTIFICATION": "VIN",

    # -------------------------------------------------------------------------
    # Provider/Facility IDs
    # -------------------------------------------------------------------------
    "NPI": "NPI",
    "NPI NO": "NPI",
    "NPI NUMBER": "NPI",
    "NATIONAL PROVIDER": "NPI",
    "DEA": "DEA",
    "DEA NO": "DEA",
    "DEA NUMBER": "DEA",
    "TAX ID": "NPI",  # Often facility identifier
    "TIN": "NPI",
    "FACILITY": "FACILITY",
    "FACILITY ID": "FACILITY",
    "LOCATION": "FACILITY",
    "SITE": "FACILITY",
    "CLINIC": "FACILITY",
    "HOSPITAL": "FACILITY",
    
    # -------------------------------------------------------------------------
    # Physical Descriptors (for ID documents)
    # -------------------------------------------------------------------------
    "HGT": "PHYSICAL_DESC",
    "HEIGHT": "PHYSICAL_DESC",
    "HT": "PHYSICAL_DESC",
    "WGT": "PHYSICAL_DESC",
    "WEIGHT": "PHYSICAL_DESC",
    "WT": "PHYSICAL_DESC",
    "EYES": "PHYSICAL_DESC",
    "EYE": "PHYSICAL_DESC",
    "EYE COLOR": "PHYSICAL_DESC",
    "HAIR": "PHYSICAL_DESC",
    "HAIR COLOR": "PHYSICAL_DESC",
    "SEX": "PHYSICAL_DESC",
    "GENDER": "PHYSICAL_DESC",
    "RACE": "PHYSICAL_DESC",
    "ETHNICITY": "PHYSICAL_DESC",
    
    # -------------------------------------------------------------------------
    # Non-PHI Labels (recognized but not redacted)
    # -------------------------------------------------------------------------
    "CLASS": None,
    "VEHICLE CLASS": None,
    "RESTR": None,
    "RESTRICTIONS": None,
    "REST": None,
    "END": None,
    "ENDORSEMENTS": None,
    "ENDORSE": None,
    "ORGAN DONOR": None,
    "DONOR": None,
    "VETERAN": None,
    "VET": None,
    "DUPS": None,
    "DUPLICATES": None,
    "REAL ID": None,
    "TYPE": None,
    "CARD TYPE": None,
    "PLAN TYPE": None,
    "COPAY": None,
    "CO-PAY": None,
    "DEDUCTIBLE": None,
    "COINSURANCE": None,
    "STATUS": None,
    "ACTIVE": None,
    "RX": None,  # Just the label, not the number
    "PHARMACY": None,
    "INSTRUCTIONS": None,
    "DIRECTIONS": None,
    "SIG": None,  # Prescription instructions
    "QTY": None,
    "QUANTITY": None,
    "REFILLS": None,
    "DAYS SUPPLY": None,
}

# Compile label patterns for efficient matching
# Sort by length descending so longer matches take precedence
_SORTED_LABELS = sorted(LABEL_TO_PHI_TYPE.keys(), key=len, reverse=True)
# OCR POST-PROCESSING
@dataclass
class OCRFix:
    """A regex-based OCR correction rule."""
    pattern: re.Pattern
    replacement: str
    description: str


# OCR fixes applied in order - ORDER MATTERS
# NOTE: "Collapse multiple spaces" was REMOVED because it changes text length
# and breaks position mapping when other detectors run on the processed text.
OCR_FIXES: List[OCRFix] = [
    # -------------------------------------------------------------------------
    # PRIORITY FIXES - Run these first to preserve specific patterns
    # -------------------------------------------------------------------------
    
    # Normalize driver's license number format (4dDLN:99 → DLN: 99)
    # This must run BEFORE other splits to preserve the DLN label
    OCRFix(
        re.compile(r'\b\d+[a-z]?DLN[:\-]\s*(\S+)', re.I),
        r'DLN: \1',
        "Normalize driver's license number (4dDLN:99 → DLN: 99)"
    ),
    
    # -------------------------------------------------------------------------
    # Re-space concatenated addresses
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'(\d{1,5})([A-Z]{2,})(STREET|ST|AVENUE|AVE|ROAD|RD|DRIVE|DR|LANE|LN|BLVD|BOULEVARD|WAY|COURT|CT|CIRCLE|CIR|PLACE|PL|TERRACE|TER|TRAIL|TRL|PIKE|HWY|HIGHWAY)\b', re.I),
        r'\1 \2 \3',
        "Split concatenated street addresses (8123MAINSTREET → 8123 MAIN STREET)"
    ),
    
    # -------------------------------------------------------------------------
    # Fix CITY,STZIP format
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\b([A-Z][A-Za-z]{2,}),([A-Z]{2})(\d{5}(?:-?\d{4})?)\b'),
        r'\1, \2 \3',
        "Split CITY,STZIP (HARRISBURG,PA17101 → HARRISBURG, PA 17101)"
    ),
    
    # -------------------------------------------------------------------------
    # Split field codes like 4aISS: → 4a ISS: (but not DLN which is handled above)
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\b(\d+[a-z])((?:ISS|EXP|DOB|SEX|HGT|WGT|EYES|END|RESTR)):'),
        r'\1 \2:',
        "Split field codes (4aISS: → 4a ISS:)"
    ),
    
    # -------------------------------------------------------------------------
    # Split stuck numeric prefix + label (18EYES:BRO → 18 EYES: BRO)
    # Only for known labels to avoid breaking things like addresses
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\b(\d{1,2})(EYES|HGT|SEX|WGT|CLASS|RESTR|END):(\S+)'),
        r'\1 \2: \3',
        "Split numeric prefix from label (18EYES:BRO → 18 EYES: BRO)"
    ),
    
    # -------------------------------------------------------------------------
    # Split stuck label:value with no space (DOB:01/01/2000 → DOB: 01/01/2000)
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\b(DOB|EXP|ISS|DLN|SSN|MRN|ID|DD):(\d)'),
        r'\1: \2',
        "Add space after label colon (DOB:01 → DOB: 01)"
    ),
    
    # -------------------------------------------------------------------------
    # Fix common OCR character substitutions
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\bD0B\b'),
        'DOB',
        "Fix zero-for-O in DOB"
    ),
    
    # -------------------------------------------------------------------------
    # Split stuck document discriminator (5DD:123 → 5 DD: 123)
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\b(\d)DD:(\d+)'),
        r'\1 DD: \2',
        "Split document discriminator (5DD:123 → 5 DD: 123)"
    ),
    
    # -------------------------------------------------------------------------
    # Split single digit field code + ALL CAPS name (ID cards)
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\b(\d)([A-Z]{2,})\b'),
        r'\1 \2',
        "Split field code from name (2ANDREW → 2 ANDREW, 1SAMPLE → 1 SAMPLE)"
    ),
    
    # NOTE: "Collapse multiple spaces" rule was REMOVED
    # It was causing position mapping bugs when other detectors run on
    # processed_text but return positions that get applied to original text.
]


def post_process_ocr(text: str) -> Tuple[str, List[int]]:
    """
    Apply OCR post-processing fixes with position tracking.
    
    Returns:
        Tuple of (fixed_text, char_map) where char_map[i] gives the position
        in original text that corresponds to position i in fixed_text.
        Use char_map directly: original_pos = char_map[processed_pos]
    """
    result = text
    
    # Apply all fixes
    for fix in OCR_FIXES:
        result = fix.pattern.sub(fix.replacement, result)
    
    # Build character-level mapping from processed -> original
    # Using a simple alignment algorithm
    char_map = _build_char_map(text, result)
    
    return result, char_map


def _build_char_map(original: str, processed: str) -> List[int]:
    """
    Build a character-level map from processed positions to original positions.
    
    Uses a greedy alignment approach that handles insertions, deletions, and substitutions.
    
    Returns:
        List where char_map[processed_pos] = original_pos
    """
    if original == processed:
        return list(range(len(processed)))
    
    # Use dynamic programming to find alignment
    # But for efficiency, use a simpler greedy approach with local matching
    
    char_map = []
    orig_pos = 0
    proc_pos = 0
    
    while proc_pos < len(processed):
        if orig_pos < len(original) and processed[proc_pos] == original[orig_pos]:
            # Characters match - direct mapping
            char_map.append(orig_pos)
            orig_pos += 1
            proc_pos += 1
        elif orig_pos < len(original) and processed[proc_pos] == ' ':
            # Space in processed might be an insertion (from OCR fixes like "2ANDREW" -> "2 ANDREW")
            # Check if skipping this space aligns better
            if proc_pos + 1 < len(processed) and processed[proc_pos + 1] == original[orig_pos]:
                # This space was inserted - map it to current original position
                char_map.append(orig_pos)
                proc_pos += 1
            else:
                # Space exists in both or is a replacement
                char_map.append(orig_pos)
                orig_pos += 1
                proc_pos += 1
        elif orig_pos < len(original):
            # Characters don't match - try to find where they sync up
            # Look ahead in original for current processed char
            lookahead = original[orig_pos:orig_pos+10]
            if processed[proc_pos] in lookahead:
                # Skip chars in original until we match
                skip = lookahead.index(processed[proc_pos])
                orig_pos += skip
                char_map.append(orig_pos)
                orig_pos += 1
                proc_pos += 1
            else:
                # No match found - this char was inserted in processed
                # Map to current original position
                char_map.append(orig_pos)
                proc_pos += 1
        else:
            # Ran out of original text - map remaining to end
            char_map.append(len(original) - 1)
            proc_pos += 1
    
    return char_map


def map_processed_to_original(processed_pos: int, char_map: List[int], strict: bool = False) -> int:
    """
    Map a position in processed text back to position in original text.

    Args:
        processed_pos: Position in processed (post-OCR-fix) text
        char_map: Character map from post_process_ocr
        strict: If True, raise ValueError for out-of-bounds positions

    Returns:
        Corresponding position in original text

    Raises:
        ValueError: If strict=True and position is out of bounds
    """
    if not char_map:
        return processed_pos

    if processed_pos < 0:
        if strict:
            raise ValueError(f"Position {processed_pos} is negative")
        return 0

    if processed_pos >= len(char_map):
        if strict:
            raise ValueError(f"Position {processed_pos} exceeds char_map length {len(char_map)}")
        # Beyond end of map - return last mapped position + offset
        if char_map:
            return char_map[-1] + (processed_pos - len(char_map) + 1)
        return processed_pos

    return char_map[processed_pos]


def map_span_to_original(
    span_start: int,
    span_end: int,
    span_text: str,
    char_map: List[int],
    original_text: str
) -> Tuple[int, int]:
    """
    Map a span from processed text coordinates to original text coordinates.

    Args:
        span_start: Start position in processed text
        span_end: End position in processed text
        span_text: The text content of the span
        char_map: Character map from post_process_ocr
        original_text: The original (pre-OCR-fix) text

    Returns:
        Tuple of (original_start, original_end)

    Raises:
        ValueError: If span positions are out of bounds for the char_map
    """
    if not char_map:
        return span_start, span_end

    # Validate span positions are within char_map bounds
    if span_start < 0 or span_start >= len(char_map):
        raise ValueError(f"span_start {span_start} out of bounds for char_map of length {len(char_map)}")
    if span_end < 0 or span_end > len(char_map):
        raise ValueError(f"span_end {span_end} out of bounds for char_map of length {len(char_map)}")

    # Map start and end positions
    orig_start = map_processed_to_original(span_start, char_map)
    
    # For end position, we want the position AFTER the last character
    # So map (span_end - 1) and add 1
    if span_end > 0:
        orig_end = map_processed_to_original(span_end - 1, char_map) + 1
    else:
        orig_end = orig_start
    
    # Ensure bounds are valid
    orig_start = max(0, min(orig_start, len(original_text)))
    orig_end = max(orig_start, min(orig_end, len(original_text)))
    
    # Verify the mapping by checking if original text at this position
    # matches or is similar to span_text
    orig_text_at_pos = original_text[orig_start:orig_end]
    
    # If texts don't match well, try to find span_text in original near this position
    if not _texts_similar(orig_text_at_pos, span_text):
        # Search nearby in original
        search_start = max(0, orig_start - 20)
        search_end = min(len(original_text), orig_end + 20)
        
        # Try to find exact match first
        pos = original_text.find(span_text, search_start)
        if pos >= 0 and pos < search_end:
            return pos, pos + len(span_text)
        
        # Try to find compacted version (without spaces added by OCR fixes)
        compact = span_text.replace(' ', '')
        for i in range(search_start, min(search_end, len(original_text) - len(compact) + 1)):
            if original_text[i:].replace(' ', '').startswith(compact):
                # Found it - find the actual end position
                chars_needed = len(compact)
                end_pos = i
                while chars_needed > 0 and end_pos < len(original_text):
                    if original_text[end_pos] != ' ':
                        chars_needed -= 1
                    end_pos += 1
                return i, end_pos
    
    return orig_start, orig_end


def _texts_similar(text1: str, text2: str) -> bool:
    """Check if two texts are similar (ignoring spacing differences from OCR fixes)."""
    # Remove spaces and compare
    return text1.replace(' ', '').upper() == text2.replace(' ', '').upper()


# LABEL DETECTION

@dataclass
class DetectedLabel:
    """A field label found in text."""
    label: str  # Normalized label (uppercase, trimmed)
    label_start: int  # Position of label in text
    label_end: int  # Position after label (including colon/separator)
    phi_type: Optional[str]  # Mapped PHI type, or None if not PHI
    raw_label: str  # Original text of label


def detect_labels(text: str) -> List[DetectedLabel]:
    """
    Find field labels in text.
    
    Looks for patterns like:
    - LABEL: value (primary pattern)
    - 16 HGT: value (with numeric prefix from field codes)
    - LABEL value (only for longer, unambiguous labels)
    """
    labels = []
    
    # Pattern 1: Standard LABEL: format (GREEDY - capture full text before colon)
    # Matches: "DOB:", "DATE OF BIRTH:", "MEMBER ID:", "MEDICAL RECORD #:", etc.
    label_pattern = re.compile(
        r'\b([A-Z][A-Z0-9\s\'\-#]{0,30}?)\s*[:\-]\s*(?=\S)',
        re.IGNORECASE
    )
    
    for match in label_pattern.finditer(text):
        raw_label = match.group(1).strip()
        
        # Try to find the longest matching label in taxonomy
        # Start with full match, then try progressively shorter prefixes
        best_label = None
        best_normalized = None
        
        words = raw_label.split()
        for i in range(len(words), 0, -1):
            candidate = ' '.join(words[-i:])  # Try last N words
            normalized = normalize_label(candidate)
            
            if normalized in LABEL_TO_PHI_TYPE:
                # Found a match - prefer longer matches
                if best_label is None or len(normalized) > len(best_normalized):
                    best_label = candidate
                    best_normalized = normalized
        
        if best_normalized is None:
            continue
            
        # Skip document type labels and common false positives
        if best_normalized in ("DRIVER'S LICENSE", "DRIVER LICENSE", "LICENSE", "STREET", "USA", "STATE", "SAMPLE"):
            continue
            
        phi_type = LABEL_TO_PHI_TYPE[best_normalized]
        
        # Calculate where this specific label starts in the match
        # If we matched "MEMBER NAME:" but best is "MEMBER NAME", 
        # label_start should be at the M of MEMBER
        if best_label == raw_label:
            label_start = match.start()
        else:
            # Find where the matched portion starts
            idx = raw_label.upper().find(best_label.upper())
            if idx >= 0:
                label_start = match.start() + idx
            else:
                label_start = match.start()
        
        labels.append(DetectedLabel(
            label=best_normalized,
            label_start=label_start,
            label_end=match.end(),
            phi_type=phi_type,
            raw_label=best_label,
        ))
    
    # Pattern 2: Field code + LABEL: format (common on ID documents)
    # Matches: "16 HGT:", "4a ISS:", "5 DD:", etc.
    field_code_pattern = re.compile(
        r'\b\d+[a-z]?\s+([A-Z]{2,})\s*[:\-]\s*(?=\S)',
        re.IGNORECASE
    )
    
    for match in field_code_pattern.finditer(text):
        raw_label = match.group(1).strip()
        normalized = normalize_label(raw_label)
        
        if normalized in LABEL_TO_PHI_TYPE:
            # Check we didn't already capture this
            already_found = any(
                abs(l.label_start - match.start()) < 5
                for l in labels
            )
            if already_found:
                continue
                
            phi_type = LABEL_TO_PHI_TYPE[normalized]
            labels.append(DetectedLabel(
                label=normalized,
                label_start=match.start(1),  # Start from the label, not the field code
                label_end=match.end(),
                phi_type=phi_type,
                raw_label=raw_label,
            ))
    
    # Pattern 3: Labels without colons (contextual)
    # But only for longer, unambiguous labels to avoid false positives
    COLON_REQUIRED_LABELS = {
        "DL", "ID", "NO", "SS", "DD", "PH", "FN", "LN", "HT", "WT",
        "GRP", "BIN", "PCN", "NPI", "DEA", "DOC", "REF", "MRN", "RX",
        # These are typically part of names, not labels:
        "HOSPITAL", "CLINIC", "MEDICAL", "CENTER", "HEALTH",
        # Common words in prose that shouldn't match without colons:
        "PATIENT", "DOCTOR", "DR", "PHYSICIAN", "PROVIDER", "NURSE",
        "MEMBER", "SUBSCRIBER", "EMPLOYER", "GUARDIAN", "PARENT", "SPOUSE",
    }
    
    for known_label in _SORTED_LABELS:
        # Skip very short labels entirely
        if len(known_label) < 3:
            continue
        
        # Skip labels that require colons
        if known_label in COLON_REQUIRED_LABELS:
            continue
        
        # Skip document type labels
        if known_label in ("DRIVER'S LICENSE", "DRIVER LICENSE", "LICENSE"):
            continue
        
        # Only match if followed by what looks like a value
        pattern = re.compile(
            rf'\b({re.escape(known_label)})\s+(?=[A-Z][a-z]|[0-9])',
            re.IGNORECASE
        )
        
        for match in pattern.finditer(text):
            # Check we didn't already capture this as LABEL:
            already_found = any(
                l.label_start <= match.start() < l.label_end
                for l in labels
            )
            if already_found:
                continue
            
            # Don't match if this appears to be part of a longer phrase
            before_start = max(0, match.start() - 15)
            context_before = text[before_start:match.start()]
            if re.search(r"(DRIVER'?S?|DRIVING)\s*$", context_before, re.I):
                continue
                
            raw_label = match.group(1).strip()
            normalized = normalize_label(raw_label)
            phi_type = LABEL_TO_PHI_TYPE.get(normalized)
            
            labels.append(DetectedLabel(
                label=normalized,
                label_start=match.start(),
                label_end=match.end(),
                phi_type=phi_type,
                raw_label=raw_label,
            ))
    
    # Sort by position
    labels.sort(key=lambda l: l.label_start)
    
    # Deduplicate - keep first occurrence at each position
    seen_positions = set()
    unique_labels = []
    for label in labels:
        if label.label_start not in seen_positions:
            seen_positions.add(label.label_start)
            unique_labels.append(label)
    
    return unique_labels


def normalize_label(label: str) -> str:
    """Normalize a label for lookup."""
    # Uppercase
    normalized = label.upper().strip()
    # Remove trailing punctuation
    normalized = re.sub(r'[:\-\s]+$', '', normalized)
    # Collapse internal whitespace
    normalized = re.sub(r'\s+', ' ', normalized)
    return normalized


# VALUE EXTRACTION

# Type-specific value patterns
# These patterns define what a valid value looks like for each PHI type
VALUE_PATTERNS: Dict[str, re.Pattern] = {
    # Dates: MM/DD/YYYY, MM-DD-YYYY, etc.
    "DATE": re.compile(r'(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})'),
    "DATE_DOB": re.compile(r'(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})'),
    
    # SSN: XXX-XX-XXXX or XXXXXXXXX
    "SSN": re.compile(r'(\d{3}[\-\s]?\d{2}[\-\s]?\d{4})'),
    
    # Phone: Various formats
    "PHONE": re.compile(r'(\(?\d{3}\)?[\-\.\s]?\d{3}[\-\.\s]?\d{4})'),
    "FAX": re.compile(r'(\(?\d{3}\)?[\-\.\s]?\d{3}[\-\.\s]?\d{4})'),
    
    # Email
    "EMAIL": re.compile(r'([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})'),

    # IP Address: IPv4 format
    "IP_ADDRESS": re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'),
    # MAC Address: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
    "MAC_ADDRESS": re.compile(r'([0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2})'),

    # Device identifiers: serial numbers (SNxxxxxxxx), UDI codes, lot numbers
    "DEVICE_ID": re.compile(r'((?:SN|S/N)?\s*[A-Z0-9\-]{5,20}|\(\d{2}\)\d{14,30})'),

    # License plate: Various formats (ABC-1234, ABC1234, 123-ABC)
    "LICENSE_PLATE": re.compile(r'([A-Z]{2,3}[\-\s]?\d{3,4}|\d{3,4}[\-\s]?[A-Z]{2,3})'),

    # VIN: 17 characters
    "VIN": re.compile(r'([A-HJ-NPR-Z0-9]{17})'),

    # ZIP: 5 or 9 digit
    "ZIP": re.compile(r'(\d{5}(?:\-\d{4})?)'),
    
    # Physical descriptors (height, eye color, etc.)
    "PHYSICAL_DESC": re.compile(r"([A-Za-z0-9'\"\-]+)"),
    
    # Generic IDs: alphanumeric strings
    "MRN": re.compile(r'([A-Z]*\d[\dA-Z\-]{3,15})'),
    "HEALTH_PLAN_ID": re.compile(r'([A-Z]*\d[\dA-Z\-]{3,20})'),
    "DRIVER_LICENSE": re.compile(r'([A-Z]*\d[\dA-Z\-\s]{3,15})'),
    "MEDICARE_ID": re.compile(r'([A-Z0-9]{10,12})'),
    "ACCOUNT_NUMBER": re.compile(r'([A-Z]*\d[\dA-Z\-]{3,15})'),
    "ENCOUNTER_ID": re.compile(r'([A-Z]*\d[\dA-Z\-]{3,15})'),
    "ACCESSION_ID": re.compile(r'([A-Z]*\d[\dA-Z\-]{3,15})'),
    "DOCUMENT_ID": re.compile(r'(\d{6,20})'),
    "ID_NUMBER": re.compile(r'([A-Z]*\d[\dA-Z\-]{3,15})'),
    "NPI": re.compile(r'(\d{10})'),
    "DEA": re.compile(r'([A-Z]{2}\d{7})'),
    "PASSPORT": re.compile(r'([A-Z0-9]{6,12})'),
    
    # Names: word characters, may include comma for "Last, First" format
    # Also handles middle initials like "John Q Smith" or "John Q. Smith"
    # And prefixes like "Dr." or "Dr "
    "NAME": re.compile(r'((?:Dr\.?\s+)?[A-Z][A-Za-z\'\-]*(?:[\s,]+[A-Z][A-Za-z\'\-]*\.?){0,4})'),
    "NAME_PATIENT": re.compile(r'((?:Dr\.?\s+)?[A-Z][A-Za-z\'\-]*(?:[\s,]+[A-Z][A-Za-z\'\-]*\.?){0,4})'),
    "NAME_PROVIDER": re.compile(r'((?:Dr\.?\s+)?[A-Z][A-Za-z\'\-]*(?:[\s,]+[A-Z][A-Za-z\'\-]*\.?){0,4})'),
    
    # Address: more complex, multiple words/numbers
    "ADDRESS": re.compile(r'(\d+[^:\n]{5,50}?)(?=\s+\d{0,2}[a-z]?\s*[A-Z]{2,}:|\s{2,}|\n|$)'),
    
    # Facility names (allow periods for "St. Mary's")
    "FACILITY": re.compile(r'([A-Z][A-Za-z.\s\'\-&]+(?:Hospital|Medical|Clinic|Center|Health)?)', re.I),
}

# Generic terminator pattern - stops at next labeled field
GENERIC_TERMINATOR = re.compile(r'\s+(?:\d{0,2}[a-z]?\s+)?[A-Z]{2,}\s*[:\-]|\s{2,}|\n')


@dataclass 
class ExtractedField:
    """A field label + value pair extracted from text."""
    label: str
    phi_type: str
    value: str
    value_start: int
    value_end: int
    confidence: float


def extract_value(text: str, label: DetectedLabel, next_label: Optional[DetectedLabel] = None) -> Optional[ExtractedField]:
    """
    Extract the value following a label.
    
    Uses type-specific patterns when available, falls back to generic extraction.
    
    Args:
        text: Full document text
        label: The detected label
        next_label: The next label in sequence (if any) to bound extraction
    
    Returns:
        ExtractedField if value found, None otherwise
    """
    if label.phi_type is None:
        # Label is recognized but value is not PHI
        return None
    
    # Start extraction after label
    start = label.label_end
    
    # Skip leading whitespace
    while start < len(text) and text[start] in ' \t':
        start += 1
    
    # Find end boundary
    if next_label:
        # Don't go past next label
        max_end = next_label.label_start
    else:
        max_end = min(start + MAX_STRUCTURED_VALUE_LENGTH, len(text))
    
    # Extract candidate text
    candidate = text[start:max_end]
    
    if not candidate.strip():
        return None
    
    # Try type-specific pattern first
    value = None
    raw_value = None  # Value before stripping
    value_match_end = 0  # Position where match ended in candidate
    
    if label.phi_type in VALUE_PATTERNS:
        pattern = VALUE_PATTERNS[label.phi_type]
        match = pattern.match(candidate)
        if match:
            raw_value = match.group(1)
            value = raw_value.strip()
            value_match_end = match.end(1)
    
    # Fall back to generic extraction (up to next field or terminator)
    if value is None:
        term_match = GENERIC_TERMINATOR.search(candidate)
        if term_match:
            raw_value = candidate[:term_match.start()]
            value = raw_value.strip()
            value_match_end = term_match.start()
        else:
            # Take up to max length or end of candidate
            raw_value = candidate.rstrip()
            value = raw_value.strip()
            value_match_end = len(raw_value)
    
    if not value:
        return None
    
    # Clean the value (remove trailing delimiters, field separators)
    value = clean_field_value(value, label.phi_type)
    
    if not value:
        return None
    
    # Reject prose-like values (sentences, not field values)
    if looks_like_prose(value):
        logger.debug(f"Rejected prose-like value for {label.phi_type} ({len(value)} chars)")
        return None
    
    # Calculate exact positions in original text
    # Find where the stripped value actually starts and ends
    value_start_in_candidate = raw_value.find(value) if raw_value else 0
    actual_start = start + value_start_in_candidate
    actual_end = actual_start + len(value)
    
    # Special handling for ADDRESS: extend to include city/state/zip on next line
    # Handles multi-line addresses like:
    #   ADDRESS: 123 Main St
    #            Springfield, IL 62701
    if label.phi_type == "ADDRESS":
        # Look for city, state zip pattern on the continuation
        remaining = text[actual_end:]
        # Match: newline + optional whitespace + City, ST 12345
        multiline_continuation = re.match(
            r'(\s*\n\s*[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)',
            remaining
        )
        if multiline_continuation:
            continuation = multiline_continuation.group(1)
            value = value + continuation
            actual_end = actual_end + len(continuation)
    
    # Validate value makes sense for the PHI type
    if not validate_value(value, label.phi_type):
        return None
    
    return ExtractedField(
        label=label.label,
        phi_type=label.phi_type,
        value=value,
        value_start=actual_start,
        value_end=actual_end,
        confidence=0.92,  # High confidence for label-based extraction
    )


def validate_value(value: str, phi_type: str) -> bool:
    """
    Validate that extracted value is plausible for the PHI type.
    """
    # Empty or too short
    if len(value) < 1:
        return False
    
    # Type-specific validation
    if phi_type in ("DATE", "DATE_DOB"):
        # Should contain digits and common date separators
        if not re.search(r'\d', value):
            return False
    
    elif phi_type == "SSN":
        # Should be mostly digits, possibly with dashes
        digits = re.sub(r'\D', '', value)
        if len(digits) < 4 or len(digits) > 11:
            return False
    
    elif phi_type in ("PHONE", "FAX"):
        digits = re.sub(r'\D', '', value)
        if len(digits) < 7 or len(digits) > 15:
            return False
    
    elif phi_type == "EMAIL":
        if '@' not in value:
            return False
    
    elif phi_type == "ZIP":
        digits = re.sub(r'\D', '', value)
        if len(digits) not in (5, 9):
            return False
    
    elif phi_type in ("MRN", "HEALTH_PLAN_ID", "ACCOUNT_NUMBER", "ID_NUMBER", "DOCUMENT_ID"):
        # Should have some alphanumeric content
        if not re.search(r'[A-Za-z0-9]', value):
            return False
        # IDs should contain at least some digits (pure alpha is likely a word)
        if phi_type == "ID_NUMBER" and not re.search(r'\d', value):
            return False
        # Reject common false positive words
        fp_words = {'range', 'result', 'value', 'normal', 'test', 'level', 'type', 'class', 'code'}
        if value.lower() in fp_words:
            return False
        # Minimum length for IDs
        if len(value) < 3:
            return False
    
    elif phi_type == "NAME" or phi_type.startswith("NAME_"):
        # Should have letters
        if not re.search(r'[A-Za-z]', value):
            return False
        # Shouldn't be all digits
        if re.match(r'^[\d\s\-]+$', value):
            return False
        # Minimum length for a name (single letters are FPs)
        if len(value) < 2:
            return False
        # Single word names must start with capital (proper nouns)
        words = value.split()
        if len(words) == 1 and not value[0].isupper():
            return False
        # Reject common false positive words (document terms, not names)
        fp_words = {
            'range', 'result', 'results', 'test', 'tests', 'value', 'values',
            'normal', 'abnormal', 'positive', 'negative', 'pending', 'final',
            'report', 'chart', 'note', 'notes', 'history', 'physical',
            'loss', 'gain', 'change', 'changes', 'level', 'levels',
            'high', 'low', 'moderate', 'severe', 'mild', 'acute', 'chronic',
            'male', 'female', 'unknown', 'other', 'none', 'yes', 'no',
            'call', 'return', 'follow', 'see', 'refer', 'consult',
        }
        if value.lower() in fp_words:
            return False
    
    elif phi_type == "ADDRESS":
        # Should have some substance
        if len(value) < 5:
            return False
    
    elif phi_type == "PHYSICAL_DESC":
        # Physical descriptors should be actual descriptions (height, weight, eye color)
        # Not generic words
        if len(value) < 2:
            return False
        # Reject common false positive words
        fp_words = {'loss', 'gain', 'change', 'normal', 'abnormal', 'stable', 'unchanged'}
        if value.lower() in fp_words:
            return False
    
    elif phi_type == "DRIVER_LICENSE":
        # Should have alphanumeric content
        if not re.search(r'[A-Za-z0-9]', value):
            return False
    
    return True


# UNLABELED PATTERN DETECTION

# Pattern for street addresses (without labels)
# Matches: "123 Main Street", "8123 MAIN STREET APT 4", etc.
# Uses [ \t]+ instead of \s+ to avoid matching across newlines
STREET_PATTERN = re.compile(
    r'\b(\d{1,5}[ \t]+[A-Z][A-Za-z]+(?:[ \t]+[A-Z][A-Za-z]+)*[ \t]+'
    r'(?:STREET|ST|AVENUE|AVE|ROAD|RD|DRIVE|DR|LANE|LN|BLVD|BOULEVARD|'
    r'WAY|COURT|CT|CIRCLE|CIR|PLACE|PL|TERRACE|TER|TRAIL|TRL|PIKE|HWY|HIGHWAY)'
    r'(?:[ \t]+(?:APT|UNIT|STE|SUITE|#)[ \t]*\.?[ \t]*[A-Z0-9]*)?)\b',
    re.IGNORECASE
)

# Pattern for city, state zip (without labels)
# Matches: "HARRISBURG, PA 17101", "New York, NY 10001-1234"
CITY_STATE_ZIP_PATTERN = re.compile(
    r'\b([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)\b',
    re.IGNORECASE
)


def detect_unlabeled_addresses(text: str, existing_spans: List[Span]) -> List[Span]:
    """
    Detect addresses that don't have labels (common on ID documents).
    
    Args:
        text: Processed text
        existing_spans: Already detected spans (to avoid overlap)
    
    Returns:
        List of address spans
    """
    spans = []
    
    # Helper to check if position overlaps with existing spans
    def overlaps_existing(start: int, end: int) -> bool:
        for s in existing_spans:
            if not (end <= s.start or start >= s.end):
                return True
        return False
    
    # Detect street addresses
    for match in STREET_PATTERN.finditer(text):
        if not overlaps_existing(match.start(), match.end()):
            value = match.group(1)
            spans.append(Span(
                start=match.start(),
                end=match.start() + len(value),
                text=value,
                entity_type="ADDRESS",
                confidence=0.88,
                detector="structured",
                tier=3,
            ))
    
    # Detect city, state, zip
    for match in CITY_STATE_ZIP_PATTERN.finditer(text):
        if not overlaps_existing(match.start(), match.end()):
            spans.append(Span(
                start=match.start(),
                end=match.end(),
                text=match.group(1),
                entity_type="ADDRESS",
                confidence=0.88,
                detector="structured",
                tier=3,
            ))
    
    return spans


# MAIN EXTRACTION PIPELINE

@dataclass
class StructuredExtractionResult:
    """Result of structured document extraction."""
    spans: List[Span]
    processed_text: str  # OCR-corrected text
    labels_found: int
    fields_extracted: int


def extract_structured_phi(text: str) -> StructuredExtractionResult:
    """
    Main entry point for structured document PHI extraction.
    
    Args:
        text: OCR text from document
    
    Returns:
        StructuredExtractionResult with detected PHI spans (in original text coordinates)
    """
    # Step 1: Post-process OCR with edit tracking
    processed_text, edits = post_process_ocr(text)
    
    # Step 2: Detect labels
    labels = detect_labels(processed_text)
    
    # Step 3: Extract values for each label
    fields: List[ExtractedField] = []
    
    for i, label in enumerate(labels):
        next_label = labels[i + 1] if i + 1 < len(labels) else None
        field = extract_value(processed_text, label, next_label)
        if field:
            fields.append(field)
    
    # Step 4: Convert to spans (still in processed text coordinates)
    processed_spans = []
    for field in fields:
        span = Span(
            start=field.value_start,
            end=field.value_end,
            text=field.value,
            entity_type=field.phi_type,
            confidence=field.confidence,
            detector="structured",
            tier=3,  # STRUCTURED tier - higher than PATTERN
        )
        processed_spans.append(span)
    
    # Step 5: Detect unlabeled addresses (in processed text)
    address_spans = detect_unlabeled_addresses(processed_text, processed_spans)
    processed_spans.extend(address_spans)
    
    # Step 6: Map all spans back to original text coordinates
    original_spans = []
    for span in processed_spans:
        orig_start, orig_end = map_span_to_original(
            span.start, span.end, span.text, edits, text
        )
        
        # Get the actual text from original at mapped position
        orig_text = text[orig_start:orig_end] if orig_start < len(text) else span.text
        
        original_spans.append(Span(
            start=orig_start,
            end=orig_end,
            text=orig_text,
            entity_type=span.entity_type,
            confidence=span.confidence,
            detector=span.detector,
            tier=span.tier,
        ))
    
    logger.debug(
        f"Structured extraction: {len(labels)} labels found, "
        f"{len(fields)} fields extracted, {len(original_spans)} spans"
    )
    
    return StructuredExtractionResult(
        spans=original_spans,
        processed_text=processed_text,
        labels_found=len(labels),
        fields_extracted=len(fields),
    )
