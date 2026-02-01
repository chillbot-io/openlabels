"""
Document Templates for Healthcare Document Processing.

Provides structured parsing and field extraction for common healthcare documents:
- ID Documents (Driver's License, State ID, Passport, etc.)
- Insurance Cards (Commercial, Medicare, Medicaid)
- Claim Forms (CMS-1500, UB-04)
- Clinical Documents (Lab Requisitions, Prescriptions, etc.)

Each template defines:
- Field patterns and locations
- Validation rules (checksums, formats)
- PHI classification for each field
- OCR post-processing rules

Standards Implemented:
- AAMVA (Driver's License/State ID)
- ICAO 9303 (Passport MRZ)
- CMS MBI (Medicare Beneficiary Identifier)
- CMS-1500 / HCFA (Insurance Claims)
- UB-04 / CMS-1450 (Hospital Claims)
- NCPDP (Pharmacy)
"""

import re
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


# --- ENUMS AND BASE TYPES ---
class DocumentType(Enum):
    """Supported document types."""
    # ID Documents
    DRIVERS_LICENSE = auto()
    STATE_ID = auto()
    PASSPORT = auto()
    PASSPORT_CARD = auto()
    MILITARY_ID = auto()
    
    # Insurance Cards
    INSURANCE_COMMERCIAL = auto()
    INSURANCE_MEDICARE = auto()
    INSURANCE_MEDICAID = auto()
    INSURANCE_TRICARE = auto()
    
    # Claim Forms
    CMS_1500 = auto()
    UB_04 = auto()
    ADA_DENTAL = auto()
    
    # Clinical Documents
    LAB_REQUISITION = auto()
    PRESCRIPTION_LABEL = auto()
    PRESCRIPTION_PAD = auto()
    SUPERBILL = auto()
    
    # Other
    EOB = auto()
    CONSENT_FORM = auto()
    ADVANCE_DIRECTIVE = auto()
    
    # Fallback
    UNKNOWN = auto()


class PHICategory(Enum):
    """HIPAA Safe Harbor PHI categories."""
    NAME = "name"
    ADDRESS = "address"
    DATE = "date"  # DOB, admission, discharge, etc.
    PHONE = "phone"
    FAX = "fax"
    EMAIL = "email"
    SSN = "ssn"
    MRN = "mrn"  # Medical Record Number
    HEALTH_PLAN_ID = "health_plan_id"  # Insurance member ID
    ACCOUNT_NUMBER = "account_number"
    LICENSE_NUMBER = "license_number"  # DL, DEA, NPI
    VEHICLE_ID = "vehicle_id"
    DEVICE_ID = "device_id"
    URL = "url"
    IP_ADDRESS = "ip_address"
    BIOMETRIC = "biometric"  # Fingerprints, signatures, photos
    PHOTO = "photo"
    OTHER_UNIQUE_ID = "other_unique_id"


@dataclass
class ExtractedField:
    """A field extracted from a document."""
    name: str
    value: str
    confidence: float
    phi_category: Optional[PHICategory] = None
    bbox: Optional[Tuple[int, int, int, int]] = None  # x1, y1, x2, y2
    validated: bool = False
    validation_method: Optional[str] = None


@dataclass
class DocumentParseResult:
    """Result of parsing a document."""
    document_type: DocumentType
    confidence: float
    fields: Dict[str, ExtractedField]
    raw_text: str
    warnings: List[str] = field(default_factory=list)
    
    def get_phi_fields(self) -> Dict[str, ExtractedField]:
        """Get only fields classified as PHI."""
        return {k: v for k, v in self.fields.items() if v.phi_category}
    
    def to_clean_text(self) -> str:
        """Get text with field labels removed."""
        return '\n'.join(f.value for f in self.fields.values() if f.value)


# --- FIELD LABEL PATTERNS BY DOCUMENT TYPE ---
# AAMVA Driver's License / State ID field codes
AAMVA_FIELD_PATTERNS = [
    # Combined prefix + label patterns (most common on scanned IDs)
    (r'^4[a-d]?\s*DLN\s*:?\s*', ''),
    (r'^4[a-d]?\s*EXP\s*:?\s*', ''),
    (r'^4[a-d]?\s*ISS\s*:?\s*', ''),
    (r'^3\s*DOB\s*:?\s*', ''),
    (r'^8\s*ADD(?:RESS)?\s*:?\s*', ''),
    
    # Numeric field codes (AAMVA standard)
    (r'^DAA\s*', ''),   # Full name
    (r'^DAB\s*', ''),   # Family name
    (r'^DAC\s*', ''),   # First name
    (r'^DAD\s*', ''),   # Middle name
    (r'^DAG\s*', ''),   # Street address
    (r'^DAH\s*', ''),   # Street address line 2
    (r'^DAI\s*', ''),   # City
    (r'^DAJ\s*', ''),   # State
    (r'^DAK\s*', ''),   # ZIP
    (r'^DAQ\s*', ''),   # License number
    (r'^DAR\s*', ''),   # License class
    (r'^DAS\s*', ''),   # Endorsements
    (r'^DAT\s*', ''),   # Restrictions
    (r'^DAU\s*', ''),   # Height
    (r'^DAW\s*', ''),   # Weight
    (r'^DAY\s*', ''),   # Eye color
    (r'^DAZ\s*', ''),   # Hair color
    (r'^DBA\s*', ''),   # Expiration
    (r'^DBB\s*', ''),   # DOB
    (r'^DBC\s*', ''),   # Sex
    (r'^DBD\s*', ''),   # Issue date
    (r'^DCS\s*', ''),   # Last name
    (r'^DCT\s*', ''),   # First name
    
    # Simple numeric prefixes
    (r'^1\s+', ''),
    (r'^2\s+', ''),
    (r'^3\s+', ''),
    (r'^4[a-d]?\s+', ''),
    (r'^5\s+', ''),
    (r'^8\s+', ''),
    (r'^9[a-z]?\s+', ''),
    (r'^12\s+', ''),
    (r'^15\s*', ''),
    (r'^16\s*', ''),
    (r'^18\s*', ''),
    
    # Labeled fields
    (r'^DLN\s*:?\s*', ''),
    (r'^LIC(?:ENSE)?\s*(?:NO|NUM|#)?\s*:?\s*', ''),
    (r'^DOB\s*:?\s*', ''),
    (r'^EXP\s*:?\s*', ''),
    (r'^ISS\s*:?\s*', ''),
    (r'^SEX\s*:?\s*', ''),
    (r'^HGT\s*:?\s*', ''),
    (r'^HT\s*:?\s*', ''),
    (r'^WGT\s*:?\s*', ''),
    (r'^WT\s*:?\s*', ''),
    (r'^EYES?\s*:?\s*', ''),
    (r'^HAIR\s*:?\s*', ''),
    (r'^CLASS\s*:?\s*', ''),
    (r'^END(?:ORSEMENTS?)?\s*:?\s*', ''),
    (r'^REST(?:RICTIONS?)?\s*:?\s*', ''),
    (r'^DD\s*:?\s*', ''),
    (r'^DONOR\s*:?\s*', ''),
]

# Insurance card field patterns
INSURANCE_FIELD_PATTERNS = [
    (r'^MEMBER\s*(?:ID|#|NO|NUM)?\s*:?\s*', ''),
    (r'^SUBSCRIBER\s*(?:ID|#|NO|NUM)?\s*:?\s*', ''),
    (r'^ID\s*(?:#|NO|NUM)?\s*:?\s*', ''),
    (r'^GROUP\s*(?:#|NO|NUM)?\s*:?\s*', ''),
    (r'^GRP\s*(?:#|NO|NUM)?\s*:?\s*', ''),
    (r'^PLAN\s*(?:#|NO|NUM)?\s*:?\s*', ''),
    (r'^RX\s*(?:BIN|PCN|GRP|ID)?\s*:?\s*', ''),
    (r'^BIN\s*:?\s*', ''),
    (r'^PCN\s*:?\s*', ''),
    (r'^POLICY\s*(?:#|NO|NUM)?\s*:?\s*', ''),
    (r'^COPAY?\s*:?\s*', ''),
    (r'^DEDUCTIBLE\s*:?\s*', ''),
    (r'^EFF(?:ECTIVE)?\s*(?:DATE)?\s*:?\s*', ''),
    (r'^PAYER\s*(?:ID)?\s*:?\s*', ''),
    (r'^ISSUER\s*:?\s*', ''),
    (r'^PCP\s*:?\s*', ''),
    (r'^PRIMARY\s*CARE\s*:?\s*', ''),
]

# Medicare card field patterns
MEDICARE_FIELD_PATTERNS = [
    (r'^MBI\s*:?\s*', ''),
    (r'^MEDICARE\s*(?:BENEFICIARY)?\s*(?:ID|#|NO|NUM)?\s*:?\s*', ''),
    (r'^HICN?\s*:?\s*', ''),  # Old format
    (r'^PART\s*[A-D]\s*:?\s*', ''),
    (r'^HOSPITAL\s*:?\s*', ''),
    (r'^MEDICAL\s*:?\s*', ''),
    (r'^EFF(?:ECTIVE)?\s*:?\s*', ''),
    (r'^ENTITLED?\s*:?\s*', ''),
]

# CMS-1500 field patterns (box numbers)
CMS_1500_FIELD_PATTERNS = [
    # Patient info section
    (r'^1\.\s*', ''),   # Insurance type
    (r'^1a\.?\s*', ''), # Insured's ID
    (r'^2\.?\s*', ''),  # Patient name
    (r'^3\.?\s*', ''),  # Patient DOB/Sex
    (r'^4\.?\s*', ''),  # Insured's name
    (r'^5\.?\s*', ''),  # Patient address
    (r'^6\.?\s*', ''),  # Patient relationship
    (r'^7\.?\s*', ''),  # Insured's address
    (r'^8\.?\s*', ''),  # Reserved
    (r'^9\.?\s*', ''),  # Other insured's name
    (r'^9[a-d]\.?\s*', ''),
    (r'^10\.?\s*', ''), # Condition related to
    (r'^10[a-c]\.?\s*', ''),
    (r'^11\.?\s*', ''), # Insured's policy
    (r'^11[a-d]\.?\s*', ''),
    (r'^12\.?\s*', ''), # Patient signature
    (r'^13\.?\s*', ''), # Insured signature
    
    # Provider/service section
    (r'^14\.?\s*', ''), # Date of illness
    (r'^15\.?\s*', ''), # Other date
    (r'^16\.?\s*', ''), # Dates unable to work
    (r'^17\.?\s*', ''), # Referring provider
    (r'^17[ab]\.?\s*', ''),
    (r'^18\.?\s*', ''), # Hospitalization dates
    (r'^19\.?\s*', ''), # Additional info
    (r'^20\.?\s*', ''), # Outside lab
    (r'^21\.?\s*', ''), # Diagnosis codes
    (r'^22\.?\s*', ''), # Resubmission
    (r'^23\.?\s*', ''), # Prior authorization
    (r'^24\.?\s*', ''), # Service lines (A-J for columns)
    (r'^24[A-J]\.?\s*', ''),
    (r'^25\.?\s*', ''), # Federal Tax ID
    (r'^26\.?\s*', ''), # Patient account
    (r'^27\.?\s*', ''), # Accept assignment
    (r'^28\.?\s*', ''), # Total charge
    (r'^29\.?\s*', ''), # Amount paid
    (r'^30\.?\s*', ''), # Reserved
    (r'^31\.?\s*', ''), # Physician signature
    (r'^32\.?\s*', ''), # Service facility
    (r'^32[ab]\.?\s*', ''),
    (r'^33\.?\s*', ''), # Billing provider
    (r'^33[ab]\.?\s*', ''),
    
    # Common labels
    (r'^PATIENT\s*NAME\s*:?\s*', ''),
    (r'^INSURED\s*NAME\s*:?\s*', ''),
    (r'^ADDRESS\s*:?\s*', ''),
    (r'^CITY\s*:?\s*', ''),
    (r'^STATE\s*:?\s*', ''),
    (r'^ZIP\s*:?\s*', ''),
    (r'^TELEPHONE\s*:?\s*', ''),
    (r'^DOB\s*:?\s*', ''),
    (r'^SEX\s*:?\s*', ''),
    (r'^SSN\s*:?\s*', ''),
    (r'^DIAGNOSIS\s*:?\s*', ''),
    (r'^DX\s*:?\s*', ''),
    (r'^CPT\s*:?\s*', ''),
    (r'^ICD[- ]?10?\s*:?\s*', ''),
    (r'^NPI\s*:?\s*', ''),
    (r'^TAX\s*ID\s*:?\s*', ''),
    (r'^EIN\s*:?\s*', ''),
]

# UB-04 field patterns (form locators)
UB_04_FIELD_PATTERNS = [
    (r'^FL\s*\d+\s*:?\s*', ''),  # Form Locator prefix
    (r'^1\s*', ''),   # Provider info
    (r'^2\s*', ''),   # Pay-to info  
    (r'^3[a-b]?\s*', ''),  # Patient control #
    (r'^4\s*', ''),   # Type of bill
    (r'^5\s*', ''),   # Federal Tax #
    (r'^6\s*', ''),   # Statement dates
    (r'^7\s*', ''),   # Reserved
    (r'^8[a-b]?\s*', ''),  # Patient name/ID
    (r'^9[a-e]?\s*', ''),  # Patient address
    (r'^10\s*', ''),  # Patient DOB
    (r'^11\s*', ''),  # Patient sex
    (r'^12\s*', ''),  # Admission date
    (r'^13\s*', ''),  # Admission hour
    (r'^14\s*', ''),  # Priority
    (r'^15\s*', ''),  # Point of origin
    (r'^16\s*', ''),  # Discharge hour
    (r'^17\s*', ''),  # Patient status
    (r'^18-28\s*', ''),  # Condition codes
    (r'^29\s*', ''),  # Accident state
    (r'^30\s*', ''),  # Reserved
    (r'^31-34\s*', ''),  # Occurrence codes/dates
    (r'^35-36\s*', ''),  # Occurrence span
    (r'^37\s*', ''),  # Reserved
    (r'^38\s*', ''),  # Responsible party
    (r'^39-41\s*', ''),  # Value codes
    (r'^42\s*', ''),  # Revenue code
    (r'^43\s*', ''),  # Description
    (r'^44\s*', ''),  # HCPCS/Rates
    (r'^45\s*', ''),  # Service date
    (r'^46\s*', ''),  # Units
    (r'^47\s*', ''),  # Total charges
    (r'^48\s*', ''),  # Non-covered charges
    (r'^49\s*', ''),  # Reserved
    (r'^50[A-C]?\s*', ''),  # Payer
    (r'^51[A-C]?\s*', ''),  # Health plan ID
    (r'^52[A-C]?\s*', ''),  # Release info
    (r'^53[A-C]?\s*', ''),  # Assignment
    (r'^54[A-C]?\s*', ''),  # Prior payments
    (r'^55[A-C]?\s*', ''),  # Est amount due
    (r'^56\s*', ''),  # NPI
    (r'^57[A-C]?\s*', ''),  # Other provider ID
    (r'^58[A-C]?\s*', ''),  # Insured's name
    (r'^59[A-C]?\s*', ''),  # Patient relationship
    (r'^60[A-C]?\s*', ''),  # Insured's ID
    (r'^61[A-C]?\s*', ''),  # Insured's group name
    (r'^62[A-C]?\s*', ''),  # Insurance group #
    (r'^63[A-C]?\s*', ''),  # Treatment auth
    (r'^64[A-C]?\s*', ''),  # Document control #
    (r'^65[A-C]?\s*', ''),  # Employer name
    (r'^66\s*', ''),  # DX version
    (r'^67[A-Q]?\s*', ''),  # Principal diagnosis
    (r'^68\s*', ''),  # Reserved
    (r'^69\s*', ''),  # Admitting DX
    (r'^70[a-c]?\s*', ''),  # Patient reason DX
    (r'^71\s*', ''),  # PPS code
    (r'^72[a-c]?\s*', ''),  # ECI
    (r'^73\s*', ''),  # Reserved
    (r'^74[a-e]?\s*', ''),  # Procedures
    (r'^75\s*', ''),  # Reserved
    (r'^76\s*', ''),  # Attending provider
    (r'^77\s*', ''),  # Operating provider
    (r'^78-79\s*', ''),  # Other providers
    (r'^80\s*', ''),  # Remarks
    (r'^81[a-d]?\s*', ''),  # Code-code field
]

# Lab requisition patterns
LAB_REQUISITION_PATTERNS = [
    (r'^PATIENT\s*:?\s*', ''),
    (r'^PT\s*NAME\s*:?\s*', ''),
    (r'^ACCT\s*(?:#|NO)?\s*:?\s*', ''),
    (r'^MRN\s*:?\s*', ''),
    (r'^MEDICAL\s*RECORD\s*(?:#|NO)?\s*:?\s*', ''),
    (r'^DOB\s*:?\s*', ''),
    (r'^SEX\s*:?\s*', ''),
    (r'^COLLECTION\s*(?:DATE|TIME)?\s*:?\s*', ''),
    (r'^SPECIMEN\s*(?:ID|#|TYPE)?\s*:?\s*', ''),
    (r'^ORDERING\s*(?:PHYSICIAN|PROVIDER|MD)?\s*:?\s*', ''),
    (r'^PHYSICIAN\s*:?\s*', ''),
    (r'^NPI\s*:?\s*', ''),
    (r'^TEST\s*(?:CODE|NAME|ORDERED)?\s*:?\s*', ''),
    (r'^DIAGNOSIS\s*:?\s*', ''),
    (r'^ICD[- ]?10?\s*:?\s*', ''),
    (r'^FASTING\s*:?\s*', ''),
    (r'^PRIORITY\s*:?\s*', ''),
    (r'^STAT\s*:?\s*', ''),
]

# Prescription label patterns
PRESCRIPTION_PATTERNS = [
    (r'^RX\s*(?:#|NO|NUM)?\s*:?\s*', ''),
    (r'^PRESCRIPTION\s*(?:#|NO)?\s*:?\s*', ''),
    (r'^PATIENT\s*:?\s*', ''),
    (r'^FOR\s*:?\s*', ''),
    (r'^DR\.?\s*:?\s*', ''),
    (r'^PRESCRIBER\s*:?\s*', ''),
    (r'^PHYSICIAN\s*:?\s*', ''),
    (r'^PHARMACY\s*:?\s*', ''),
    (r'^RPH\s*:?\s*', ''),
    (r'^DATE\s*(?:FILLED|WRITTEN|RX)?\s*:?\s*', ''),
    (r'^REFILLS?\s*:?\s*', ''),
    (r'^QTY\s*:?\s*', ''),
    (r'^QUANTITY\s*:?\s*', ''),
    (r'^DAYS?\s*SUPPLY\s*:?\s*', ''),
    (r'^SIG\s*:?\s*', ''),
    (r'^DIRECTIONS?\s*:?\s*', ''),
    (r'^TAKE\s*', ''),
    (r'^NDC\s*:?\s*', ''),
    (r'^DEA\s*(?:#|NO)?\s*:?\s*', ''),
    (r'^NPI\s*:?\s*', ''),
    (r'^DISCARD\s*(?:AFTER|BY)?\s*:?\s*', ''),
    (r'^EXP(?:IRATION)?\s*:?\s*', ''),
]

# Passport MRZ patterns - these are special fixed-format lines
PASSPORT_MRZ_PATTERNS = [
    # Type + Country + Name line
    (r'^P[A-Z<]{43}$', 'mrz_line1'),
    # Number + Nationality + DOB + Sex + Expiry + Personal # line
    (r'^[A-Z0-9<]{44}$', 'mrz_line2'),
]

# EOB patterns
EOB_PATTERNS = [
    (r'^CLAIM\s*(?:#|NO|NUM)?\s*:?\s*', ''),
    (r'^SERVICE\s*DATE\s*:?\s*', ''),
    (r'^PATIENT\s*:?\s*', ''),
    (r'^MEMBER\s*:?\s*', ''),
    (r'^PROVIDER\s*:?\s*', ''),
    (r'^BILLED\s*:?\s*', ''),
    (r'^ALLOWED\s*:?\s*', ''),
    (r'^PAID\s*:?\s*', ''),
    (r'^ADJUSTMENT\s*:?\s*', ''),
    (r'^COPAY?\s*:?\s*', ''),
    (r'^DEDUCTIBLE\s*:?\s*', ''),
    (r'^COINSURANCE\s*:?\s*', ''),
    (r'^YOUR\s*RESPONSIBILITY\s*:?\s*', ''),
    (r'^PATIENT\s*RESPONSIBILITY\s*:?\s*', ''),
    (r'^REMARK\s*(?:CODE)?\s*:?\s*', ''),
    (r'^DENIAL\s*(?:CODE|REASON)?\s*:?\s*', ''),
]


# --- VALIDATION FUNCTIONS ---
def validate_luhn(number: str) -> bool:
    """
    Validate a number using the Luhn algorithm.
    Used for credit cards, some insurance IDs, etc.

    Detects:
    - All single-digit errors
    - Most transposition errors of adjacent digits

    Known limitation: Cannot detect 0↔9 transpositions (e.g., swapping 09 to 90)
    because both digits contribute the same checksum value after the doubling step.
    This is a fundamental mathematical property of Luhn, not a bug.
    """
    digits = [int(d) for d in re.sub(r'\D', '', number)]
    if not digits:
        return False
    
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    
    return checksum % 10 == 0


def validate_medicare_mbi(mbi: str) -> bool:
    """
    Validate Medicare Beneficiary Identifier (MBI) format.
    
    MBI Format (11 characters): NAAN-AAN-AANN where:
    - Position 1: Numeric 1-9 (not 0)
    - Position 2: Alpha (C) - excludes S,L,O,I,B,Z
    - Position 3: Alphanumeric (AN) - excludes S,L,O,I,B,Z
    - Position 4: Numeric 0-9
    - Position 5: Alpha (C)
    - Position 6: Alphanumeric (AN)
    - Position 7: Numeric 0-9
    - Position 8: Alpha (C)
    - Position 9: Alpha (C)
    - Position 10: Numeric 0-9
    - Position 11: Numeric 0-9
    
    Example: 1EG4-TE5-MK72
    """
    # Remove common separators
    mbi = re.sub(r'[-\s]', '', mbi.upper())
    
    if len(mbi) != 11:
        return False
    
    # Valid character sets
    alpha_chars = set('ACDEFGHJKMNPQRTUVWXY')  # Excludes S,L,O,I,B,Z
    numeric_1_9 = set('123456789')
    numeric_0_9 = set('0123456789')
    alphanumeric = alpha_chars | numeric_0_9
    
    # Position rules (0-indexed)
    rules = [
        (0, numeric_1_9),     # Position 1: 1-9
        (1, alpha_chars),     # Position 2: Alpha (C)
        (2, alphanumeric),    # Position 3: Alphanumeric (AN)
        (3, numeric_0_9),     # Position 4: Numeric
        (4, alpha_chars),     # Position 5: Alpha (C)
        (5, alphanumeric),    # Position 6: Alphanumeric (AN)
        (6, numeric_0_9),     # Position 7: Numeric
        (7, alpha_chars),     # Position 8: Alpha (C)
        (8, alpha_chars),     # Position 9: Alpha (C)
        (9, numeric_0_9),     # Position 10: Numeric
        (10, numeric_0_9),    # Position 11: Numeric
    ]
    
    for pos, allowed in rules:
        if mbi[pos] not in allowed:
            return False
    
    return True


def validate_ssn(ssn: str) -> bool:
    """
    Validate SSN format and basic rules.
    
    Rules:
    - 9 digits (with or without dashes)
    - Area number (first 3) cannot be 000, 666, or 900-999
    - Group number (middle 2) cannot be 00
    - Serial number (last 4) cannot be 0000
    """
    digits = re.sub(r'\D', '', ssn)
    
    if len(digits) != 9:
        return False
    
    area = int(digits[0:3])
    group = int(digits[3:5])
    serial = int(digits[5:9])
    
    # Invalid area numbers
    if area == 0 or area == 666 or area >= 900:
        return False
    
    # Invalid group/serial
    if group == 0 or serial == 0:
        return False
    
    return True


def validate_npi(npi: str) -> bool:
    """
    Validate National Provider Identifier.
    
    NPI is 10 digits with Luhn check digit.
    Prefix '80840' is added before Luhn calculation.
    """
    digits = re.sub(r'\D', '', npi)
    
    if len(digits) != 10:
        return False
    
    # NPI uses Luhn with prefix 80840
    prefixed = '80840' + digits
    return validate_luhn(prefixed)


def validate_dea(dea: str) -> bool:
    """
    Validate DEA Registration Number.
    
    Format: 2 letters + 6 digits + 1 check digit
    First letter: A,B,C,D,E,F,G,H,J,K,L,M,P,R,S,T,U,X (registrant type)
    Second letter: First letter of registrant's last name
    Check digit: (sum of odd positions + 2*sum of even positions) mod 10
    """
    dea = dea.upper().replace(' ', '').replace('-', '')
    
    if len(dea) != 9:
        return False
    
    # First character must be valid registrant type
    # Official codes: A,B,F,G (practitioners), M (mid-level), P,R (manufacturers/distributors)
    # Also accepting: C,D,E,H,J,K,L,S,T,U,X for broader detection
    valid_first = set('ABCDEFGHJKLMPRSTUX')  # Missing I, N, O, Q, V, W, Y, Z
    if dea[0] not in valid_first:
        return False
    
    # Second character must be alpha
    if not dea[1].isalpha():
        return False
    
    # Remaining 7 must be digits
    if not dea[2:].isdigit():
        return False
    
    # Check digit validation
    digits = [int(d) for d in dea[2:]]
    odd_sum = digits[0] + digits[2] + digits[4]
    even_sum = digits[1] + digits[3] + digits[5]
    check = (odd_sum + 2 * even_sum) % 10
    
    return check == digits[6]


def validate_date(date_str: str, formats: List[str] = None) -> Optional[datetime]:
    """
    Validate and parse a date string.
    
    Returns datetime if valid, None if invalid.
    """
    if formats is None:
        formats = [
            '%m/%d/%Y', '%m-%d-%Y', '%Y-%m-%d',
            '%m/%d/%y', '%m-%d-%y',
            '%d/%m/%Y', '%d-%m-%Y',
            '%Y%m%d', '%m%d%Y',
        ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    
    return None


def validate_passport_mrz(mrz_lines: List[str]) -> bool:
    """
    Validate passport MRZ (Machine Readable Zone).
    
    TD3 format (passport): 2 lines of 44 characters each.
    """
    if len(mrz_lines) != 2:
        return False
    
    if len(mrz_lines[0]) != 44 or len(mrz_lines[1]) != 44:
        return False
    
    # Line 1: P<COUNTRY<SURNAME<<GIVEN<NAMES<<<...
    line1 = mrz_lines[0]
    if line1[0] != 'P':
        return False
    
    # Line 2 has check digits at positions 9, 19, 43 (0-indexed)
    line2 = mrz_lines[1]
    
    # Basic format check - should be alphanumeric and <
    valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<')
    if not all(c in valid_chars for c in line1 + line2):
        return False
    
    return True


# --- DOCUMENT DETECTION ---
# Detection keywords for each document type
DOCUMENT_KEYWORDS = {
    DocumentType.DRIVERS_LICENSE: [
        r"DRIVER'?S?\s*LICENSE",
        r"\bDL\b",
        r"\bDLN\b",
        r"MOTOR\s*VEHICLE",
        r"CLASS\s*[A-Z]",
        r"ORGAN\s*DONOR",
        r"\bENDORSEMENTS?\b",
        r"\bRESTRICTIONS?\b",
    ],
    DocumentType.STATE_ID: [
        r"STATE\s*ID",
        r"IDENTIFICATION\s*CARD",
        r"ID\s*CARD",
        r"NOT\s*FOR\s*(?:FEDERAL|REAL\s*ID)",
    ],
    DocumentType.PASSPORT: [
        r"\bPASSPORT\b",
        r"UNITED\s*STATES\s*OF\s*AMERICA",
        r"NATIONALITY",
        r"MACHINE\s*READABLE",
        r"^P<",  # MRZ start
    ],
    DocumentType.MILITARY_ID: [
        r"UNIFORMED\s*SERVICES",
        r"DEPARTMENT\s*OF\s*DEFENSE",
        r"\bDOD\b",
        r"GENEVA\s*CONVENTIONS?",
        r"\bUSID\b",
    ],
    DocumentType.INSURANCE_COMMERCIAL: [
        r"\bMEMBER\s*ID\b",
        r"\bGROUP\s*(?:#|NO|NUM)",
        r"\bSUBSCRIBER\b",
        r"\bRX\s*BIN\b",
        r"\bPCN\b",
        r"\bCOPAY\b",
        r"\bDEDUCTIBLE\b",
        r"HEALTH\s*(?:PLAN|INSURANCE)",
        r"\bPPO\b",
        r"\bHMO\b",
        r"\bEPO\b",
    ],
    DocumentType.INSURANCE_MEDICARE: [
        r"\bMEDICARE\b",
        r"\bMBI\b",
        r"MEDICARE\s*BENEFICIARY",
        r"PART\s*[ABCD]",
        r"CMS\b",
        r"HEALTH\s*INSURANCE\s*CLAIM",
    ],
    DocumentType.INSURANCE_MEDICAID: [
        r"\bMEDICAID\b",
        r"STATE\s*HEALTH",
        r"CHIP\b",
        r"CHILDREN'?S?\s*HEALTH",
    ],
    DocumentType.INSURANCE_TRICARE: [
        r"\bTRICARE\b",
        r"MILITARY\s*HEALTH",
        r"\bDEERS\b",
    ],
    DocumentType.CMS_1500: [
        r"CMS[- ]?1500",
        r"HCFA[- ]?1500",
        r"HEALTH\s*INSURANCE\s*CLAIM\s*FORM",
        r"APPROVED\s*BY\s*NATIONAL",
        r"1a\.\s*INSURED'?S?\s*I\.?D",
        r"21\.\s*DIAGNOSIS",
        r"24\.\s*A\.\s*DATE",
    ],
    DocumentType.UB_04: [
        r"UB[- ]?04",
        r"CMS[- ]?1450",
        r"UNIFORM\s*BILL",
        r"FL\s*\d+",  # Form Locator references
        r"TYPE\s*OF\s*BILL",
        r"CONDITION\s*CODES?",
        r"OCCURRENCE\s*CODES?",
        r"VALUE\s*CODES?",
    ],
    DocumentType.ADA_DENTAL: [
        r"ADA\s*DENTAL",
        r"DENTAL\s*CLAIM",
        r"TOOTH\s*(?:NUMBER|SURFACE|SYSTEM)",
    ],
    DocumentType.LAB_REQUISITION: [
        r"LAB(?:ORATORY)?\s*REQ(?:UISITION)?",
        r"SPECIMEN\s*(?:ID|TYPE|COLLECTION)",
        r"COLLECTION\s*(?:DATE|TIME)",
        r"ORDERING\s*(?:PHYSICIAN|PROVIDER)",
        r"TEST\s*(?:CODE|NAME|ORDERED)",
        r"\bSTAT\b",
        r"FASTING",
    ],
    DocumentType.PRESCRIPTION_LABEL: [
        r"\bRX\s*(?:#|NO|NUM)",
        r"PRESCRIPTION",
        r"\bREFILLS?\b",
        r"\bQTY\b",
        r"DAYS?\s*SUPPLY",
        r"\bSIG\b",
        r"\bNDC\b",
        r"PHARMACY",
        r"PHARMACIST",
        r"\bRPH\b",
    ],
    DocumentType.PRESCRIPTION_PAD: [
        r"\bDEA\s*(?:#|NO)",
        r"\bNPI\b",
        r"DISPENSE\s*AS\s*WRITTEN",
        r"SUBSTITUTION",
        r"SCHEDULE\s*[II]+",
        r"CONTROLLED\s*SUBSTANCE",
    ],
    DocumentType.SUPERBILL: [
        r"SUPERBILL",
        r"ENCOUNTER\s*FORM",
        r"CHARGE\s*TICKET",
        r"OFFICE\s*VISIT",
        r"E/?M\s*CODES?",
        r"99[0-9]{3}",  # E/M CPT codes
    ],
    DocumentType.EOB: [
        r"EXPLANATION\s*OF\s*BENEFITS?",
        r"\bEOB\b",
        r"THIS\s*IS\s*NOT\s*A\s*BILL",
        r"YOUR\s*(?:PLAN|INSURANCE)\s*PAID",
        r"PATIENT\s*RESPONSIBILITY",
        r"AMOUNT\s*YOU\s*(?:OWE|MAY\s*OWE)",
    ],
    DocumentType.CONSENT_FORM: [
        r"CONSENT\s*(?:FORM|TO\s*TREAT)",
        r"HIPAA\s*(?:AUTHORIZATION|CONSENT)",
        r"RELEASE\s*OF\s*(?:INFORMATION|RECORDS)",
        r"I\s*(?:HEREBY\s*)?(?:AUTHORIZE|CONSENT)",
        r"PATIENT\s*SIGNATURE",
    ],
    DocumentType.ADVANCE_DIRECTIVE: [
        r"ADVANCE\s*DIRECTIVE",
        r"LIVING\s*WILL",
        r"HEALTH\s*CARE\s*(?:PROXY|POWER)",
        r"DNR\b",
        r"DO\s*NOT\s*RESUSCITATE",
        r"POLST\b",
        r"MOLST\b",
    ],
}


def detect_document_type(text: str, aspect_ratio: float = None) -> Tuple[DocumentType, float]:
    """
    Detect document type from OCR text and optionally image aspect ratio.
    
    Args:
        text: OCR extracted text
        aspect_ratio: width/height ratio of image (optional)
        
    Returns:
        (DocumentType, confidence)
    """
    text_upper = text.upper()
    scores = {}
    
    for doc_type, patterns in DOCUMENT_KEYWORDS.items():
        score = 0
        for pattern in patterns:
            matches = len(re.findall(pattern, text_upper, re.I | re.M))
            score += matches
        
        if score > 0:
            scores[doc_type] = score
    
    if not scores:
        return DocumentType.UNKNOWN, 0.0
    
    # Apply aspect ratio hints
    if aspect_ratio:
        # ID cards are ~1.58 (credit card format)
        if 1.4 < aspect_ratio < 1.8:
            for doc_type in [DocumentType.DRIVERS_LICENSE, DocumentType.STATE_ID,
                            DocumentType.INSURANCE_COMMERCIAL, DocumentType.INSURANCE_MEDICARE,
                            DocumentType.INSURANCE_MEDICAID]:
                if doc_type in scores:
                    scores[doc_type] *= 1.5
        
        # Letter-size forms are ~0.77 (portrait) or ~1.29 (landscape)
        if 0.7 < aspect_ratio < 0.85 or 1.2 < aspect_ratio < 1.4:
            for doc_type in [DocumentType.CMS_1500, DocumentType.UB_04,
                            DocumentType.LAB_REQUISITION, DocumentType.CONSENT_FORM]:
                if doc_type in scores:
                    scores[doc_type] *= 1.3
    
    best_type = max(scores, key=scores.get)
    max_score = scores[best_type]
    
    # Normalize confidence (cap at 1.0)
    confidence = min(1.0, max_score / 5.0)
    
    return best_type, confidence


# --- DOCUMENT-SPECIFIC PARSERS ---
class DocumentParser(ABC):
    """Base class for document-specific parsers."""
    
    @property
    @abstractmethod
    def document_type(self) -> DocumentType:
        """Return the document type this parser handles."""
        pass
    
    @property
    @abstractmethod
    def field_patterns(self) -> List[Tuple[str, str]]:
        """Return field label patterns for this document type."""
        pass
    
    @abstractmethod
    def extract_fields(self, text: str) -> Dict[str, ExtractedField]:
        """Extract structured fields from document text."""
        pass
    
    def clean_text(self, text: str) -> str:
        """Remove field labels from text."""
        result = text
        for pattern, replacement in self.field_patterns:
            # Apply per-line for ^ patterns
            if pattern.startswith('^'):
                lines = result.split('\n')
                cleaned = [re.sub(pattern, replacement, line, flags=re.I) for line in lines]
                result = '\n'.join(cleaned)
            else:
                result = re.sub(pattern, replacement, result, flags=re.I)
        
        # Clean whitespace
        result = re.sub(r'[ \t]+', ' ', result)
        result = re.sub(r'\n\s*\n', '\n', result)
        return result.strip()
    
    def parse(self, text: str) -> DocumentParseResult:
        """Parse document and return structured result."""
        fields = self.extract_fields(text)
        clean = self.clean_text(text)
        
        return DocumentParseResult(
            document_type=self.document_type,
            confidence=1.0,  # Parser was explicitly chosen
            fields=fields,
            raw_text=text,
        )


class DriversLicenseParser(DocumentParser):
    """Parser for US Driver's Licenses and State IDs."""
    
    @property
    def document_type(self) -> DocumentType:
        return DocumentType.DRIVERS_LICENSE
    
    @property
    def field_patterns(self) -> List[Tuple[str, str]]:
        return AAMVA_FIELD_PATTERNS
    
    def extract_fields(self, text: str) -> Dict[str, ExtractedField]:
        fields = {}
        text_upper = text.upper()
        
        # License number - various formats
        dl_match = re.search(r'(?:DLN|LIC|DAQ)[:\s]*([A-Z0-9][\s-]?[A-Z0-9]{5,12})', text_upper)
        if dl_match:
            fields['license_number'] = ExtractedField(
                name='License Number',
                value=dl_match.group(1).replace(' ', ''),
                confidence=0.9,
                phi_category=PHICategory.LICENSE_NUMBER,
            )
        
        # Name patterns
        name_match = re.search(r'(?:^|\n)([A-Z]+)\s*\n\s*([A-Z]+(?:\s+[A-Z\.]+)?)', text_upper)
        if name_match:
            fields['name'] = ExtractedField(
                name='Name',
                value=f"{name_match.group(1)} {name_match.group(2)}",
                confidence=0.85,
                phi_category=PHICategory.NAME,
            )
        
        # DOB
        dob_match = re.search(r'(?:DOB|DBB|3)[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})', text_upper)
        if dob_match:
            date_val = dob_match.group(1)
            fields['dob'] = ExtractedField(
                name='Date of Birth',
                value=date_val,
                confidence=0.9,
                phi_category=PHICategory.DATE,
                validated=validate_date(date_val) is not None,
                validation_method='date_format',
            )
        
        # Address
        addr_match = re.search(
            r'(\d+\s+[A-Z][A-Z0-9\s]+(?:ST|STREET|AVE|AVENUE|RD|ROAD|DR|DRIVE|LN|LANE|BLVD|CT|WAY|PL|PLACE)\.?)',
            text_upper
        )
        if addr_match:
            fields['address'] = ExtractedField(
                name='Street Address',
                value=addr_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.ADDRESS,
            )
        
        # City, State, ZIP
        csz_match = re.search(r'([A-Z][A-Z]+)\s+([A-Z]{2})\s+(\d{5}(?:-\d{4})?)', text_upper)
        if csz_match:
            fields['city'] = ExtractedField(
                name='City',
                value=csz_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.ADDRESS,
            )
            fields['state'] = ExtractedField(
                name='State',
                value=csz_match.group(2),
                confidence=0.95,
                phi_category=PHICategory.ADDRESS,
            )
            fields['zip'] = ExtractedField(
                name='ZIP Code',
                value=csz_match.group(3),
                confidence=0.9,
                phi_category=PHICategory.ADDRESS,
            )
        
        # Sex
        sex_match = re.search(r'(?:SEX|DBC|15)[:\s]*([MF])\b', text_upper)
        if sex_match:
            fields['sex'] = ExtractedField(
                name='Sex',
                value=sex_match.group(1),
                confidence=0.95,
                phi_category=None,  # Not PHI by itself
            )
        
        # Expiration
        exp_match = re.search(r'(?:EXP|DBA|4B)[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})', text_upper)
        if exp_match:
            fields['expiration'] = ExtractedField(
                name='Expiration Date',
                value=exp_match.group(1),
                confidence=0.9,
                phi_category=None,  # Not PHI
            )
        
        return fields


class InsuranceCardParser(DocumentParser):
    """Parser for commercial insurance cards."""
    
    @property
    def document_type(self) -> DocumentType:
        return DocumentType.INSURANCE_COMMERCIAL
    
    @property
    def field_patterns(self) -> List[Tuple[str, str]]:
        return INSURANCE_FIELD_PATTERNS
    
    def extract_fields(self, text: str) -> Dict[str, ExtractedField]:
        fields = {}
        text_upper = text.upper()
        
        # Member ID - most critical field
        member_match = re.search(
            r'(?:MEMBER|SUBSCRIBER|ID)[\s#:]*([A-Z0-9]{6,20})',
            text_upper
        )
        if member_match:
            fields['member_id'] = ExtractedField(
                name='Member ID',
                value=member_match.group(1),
                confidence=0.9,
                phi_category=PHICategory.HEALTH_PLAN_ID,
            )
        
        # Group number
        group_match = re.search(r'(?:GROUP|GRP)[\s#:]*([A-Z0-9]{3,15})', text_upper)
        if group_match:
            fields['group_number'] = ExtractedField(
                name='Group Number',
                value=group_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.HEALTH_PLAN_ID,
            )
        
        # RxBIN (6 digits)
        bin_match = re.search(r'(?:RX\s*)?BIN[\s:]*(\d{6})', text_upper)
        if bin_match:
            fields['rx_bin'] = ExtractedField(
                name='RxBIN',
                value=bin_match.group(1),
                confidence=0.95,
                phi_category=None,  # Not PHI - pharmacy network identifier
            )
        
        # RxPCN
        pcn_match = re.search(r'PCN[\s:]*([A-Z0-9]{3,15})', text_upper)
        if pcn_match:
            fields['rx_pcn'] = ExtractedField(
                name='RxPCN',
                value=pcn_match.group(1),
                confidence=0.85,
                phi_category=None,
            )
        
        # Member name
        name_match = re.search(
            r'(?:MEMBER|NAME|SUBSCRIBER)[\s:]*([A-Z]+(?:\s+[A-Z]\.?)?\s+[A-Z]+)',
            text_upper
        )
        if name_match:
            fields['member_name'] = ExtractedField(
                name='Member Name',
                value=name_match.group(1),
                confidence=0.8,
                phi_category=PHICategory.NAME,
            )
        
        # Payer ID (used in claims)
        payer_match = re.search(r'PAYER[\s]*(?:ID)?[\s:]*([A-Z0-9]{5,10})', text_upper)
        if payer_match:
            fields['payer_id'] = ExtractedField(
                name='Payer ID',
                value=payer_match.group(1),
                confidence=0.8,
                phi_category=None,  # Identifies payer, not patient
            )
        
        return fields


class MedicareCardParser(DocumentParser):
    """Parser for Medicare cards (red/white/blue cards and new MBI cards)."""
    
    @property
    def document_type(self) -> DocumentType:
        return DocumentType.INSURANCE_MEDICARE
    
    @property
    def field_patterns(self) -> List[Tuple[str, str]]:
        return MEDICARE_FIELD_PATTERNS
    
    def extract_fields(self, text: str) -> Dict[str, ExtractedField]:
        fields = {}
        text_upper = text.upper()
        
        # Medicare Beneficiary Identifier (MBI) - new format since 2020
        # Format: 1EG4-TE5-MK72 or 1EG4TE5MK72
        # Pattern: N-C-AN-N-C-AN-N-C-C-N-N (N=numeric, C=alpha, AN=alphanumeric)
        mbi_match = re.search(
            r'(?:MBI|MEDICARE)[\s#:]*([0-9][A-Z][A-Z0-9][0-9][A-Z][A-Z0-9][0-9][A-Z][A-Z][0-9]{2})',
            text_upper.replace('-', '').replace(' ', '')
        )
        if not mbi_match:
            # Try with separators (after positions 4 and 7)
            mbi_match = re.search(
                r'([0-9][A-Z][A-Z0-9][0-9][\s-]?[A-Z][A-Z0-9][0-9][\s-]?[A-Z]{2}[0-9]{2})',
                text_upper
            )

        if mbi_match:
            mbi_value = re.sub(r'[-\s]', '', mbi_match.group(1))
            is_valid = validate_medicare_mbi(mbi_value)
            fields['mbi'] = ExtractedField(
                name='Medicare Beneficiary Identifier',
                value=mbi_value,
                confidence=0.95 if is_valid else 0.7,
                phi_category=PHICategory.HEALTH_PLAN_ID,
                validated=is_valid,
                validation_method='mbi_format',
            )
        
        # Old HICN format (being phased out) - SSN-based
        hicn_match = re.search(r'(\d{3}[- ]?\d{2}[- ]?\d{4}[A-Z]{1,2})', text_upper)
        if hicn_match:
            fields['hicn'] = ExtractedField(
                name='HICN (Legacy)',
                value=hicn_match.group(1),
                confidence=0.8,
                phi_category=PHICategory.HEALTH_PLAN_ID,  # Contains SSN-derived info
            )
        
        # Beneficiary name
        name_match = re.search(r'(?:NAME|BENEFICIARY)[\s:]*([A-Z]+\s+[A-Z]+)', text_upper)
        if name_match:
            fields['beneficiary_name'] = ExtractedField(
                name='Beneficiary Name',
                value=name_match.group(1),
                confidence=0.8,
                phi_category=PHICategory.NAME,
            )
        
        # Effective dates
        eff_match = re.search(r'(?:EFF|EFFECTIVE)[\s:]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})', text_upper)
        if eff_match:
            fields['effective_date'] = ExtractedField(
                name='Effective Date',
                value=eff_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.DATE,
            )
        
        # Part coverage indicators
        for part in ['A', 'B', 'C', 'D']:
            part_match = re.search(rf'PART\s*{part}[\s:]*(\d{{1,2}}[/-]\d{{1,2}}[/-]\d{{2,4}})', text_upper)
            if part_match:
                fields[f'part_{part.lower()}_date'] = ExtractedField(
                    name=f'Part {part} Effective',
                    value=part_match.group(1),
                    confidence=0.85,
                    phi_category=PHICategory.DATE,
                )
        
        return fields


class CMS1500Parser(DocumentParser):
    """Parser for CMS-1500 (HCFA) insurance claim forms."""
    
    @property
    def document_type(self) -> DocumentType:
        return DocumentType.CMS_1500
    
    @property
    def field_patterns(self) -> List[Tuple[str, str]]:
        return CMS_1500_FIELD_PATTERNS
    
    def extract_fields(self, text: str) -> Dict[str, ExtractedField]:
        fields = {}
        text_upper = text.upper()
        
        # Box 1a - Insured's ID Number
        box1a_match = re.search(r'1A\.?\s*(?:INSURED\'?S?\s*I\.?D\.?)?\s*[:#]?\s*([A-Z0-9]{5,20})', text_upper)
        if box1a_match:
            fields['insured_id'] = ExtractedField(
                name='Insured ID (Box 1a)',
                value=box1a_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.HEALTH_PLAN_ID,
            )
        
        # Box 2 - Patient's Name
        box2_match = re.search(
            r'(?:2\.?\s*)?PATIENT\'?S?\s*NAME\s*[:\s]*([A-Z]+\s*,?\s*[A-Z]+(?:\s+[A-Z]\.?)?)',
            text_upper
        )
        if box2_match:
            fields['patient_name'] = ExtractedField(
                name='Patient Name (Box 2)',
                value=box2_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.NAME,
            )
        
        # Box 3 - Patient's DOB and Sex
        box3_match = re.search(r'3\.?\s*(?:DOB|BIRTH)\s*[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})', text_upper)
        if box3_match:
            fields['patient_dob'] = ExtractedField(
                name='Patient DOB (Box 3)',
                value=box3_match.group(1),
                confidence=0.9,
                phi_category=PHICategory.DATE,
            )
        
        # Box 5 - Patient's Address
        addr_match = re.search(
            r'5\.?\s*(?:PATIENT\'?S?\s*)?ADDRESS\s*[:\s]*(\d+\s+[A-Z0-9\s,]+)',
            text_upper
        )
        if addr_match:
            fields['patient_address'] = ExtractedField(
                name='Patient Address (Box 5)',
                value=addr_match.group(1)[:100],  # Limit length
                confidence=0.8,
                phi_category=PHICategory.ADDRESS,
            )
        
        # Box 5 - Phone
        phone_match = re.search(r'(?:TELEPHONE|PHONE)\s*[:\s]*\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}', text_upper)
        if phone_match:
            fields['patient_phone'] = ExtractedField(
                name='Patient Phone (Box 5)',
                value=phone_match.group(0),
                confidence=0.85,
                phi_category=PHICategory.PHONE,
            )
        
        # Box 21 - Diagnosis Codes (ICD-10)
        icd_matches = re.findall(r'[A-Z]\d{2}(?:\.[A-Z0-9]{1,4})?', text_upper)
        if icd_matches:
            fields['diagnosis_codes'] = ExtractedField(
                name='Diagnosis Codes (Box 21)',
                value=', '.join(icd_matches[:12]),  # Max 12 on form
                confidence=0.85,
                phi_category=None,  # Codes themselves aren't PHI
            )
        
        # Box 25 - Federal Tax ID / SSN
        tax_match = re.search(r'(?:25\.?\s*)?(?:TAX\s*ID|EIN|SSN)\s*[:\s]*(\d{2}[- ]?\d{7}|\d{3}[- ]?\d{2}[- ]?\d{4})', text_upper)
        if tax_match:
            value = tax_match.group(1)
            # Determine if SSN or EIN
            digits = re.sub(r'\D', '', value)
            is_ssn = len(digits) == 9 and validate_ssn(digits)
            
            fields['tax_id'] = ExtractedField(
                name='Tax ID (Box 25)',
                value=value,
                confidence=0.9,
                phi_category=PHICategory.SSN if is_ssn else None,
                validated=is_ssn if is_ssn else None,
                validation_method='ssn_format' if is_ssn else None,
            )
        
        # Box 26 - Patient Account Number
        acct_match = re.search(r'26\.?\s*(?:PATIENT\s*)?ACCT(?:OUNT)?\s*[:#]?\s*([A-Z0-9]{3,20})', text_upper)
        if acct_match:
            fields['patient_account'] = ExtractedField(
                name='Patient Account (Box 26)',
                value=acct_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.ACCOUNT_NUMBER,
            )
        
        # Box 33 - Billing Provider NPI
        npi_match = re.search(r'(?:NPI|33[AB]?\.?)\s*[:\s]*(\d{10})', text_upper)
        if npi_match:
            npi_value = npi_match.group(1)
            is_valid = validate_npi(npi_value)
            fields['billing_npi'] = ExtractedField(
                name='Billing NPI (Box 33a)',
                value=npi_value,
                confidence=0.95 if is_valid else 0.7,
                phi_category=PHICategory.LICENSE_NUMBER,
                validated=is_valid,
                validation_method='npi_luhn',
            )
        
        return fields


class UB04Parser(DocumentParser):
    """Parser for UB-04 (CMS-1450) hospital claim forms."""
    
    @property
    def document_type(self) -> DocumentType:
        return DocumentType.UB_04
    
    @property
    def field_patterns(self) -> List[Tuple[str, str]]:
        return UB_04_FIELD_PATTERNS
    
    def extract_fields(self, text: str) -> Dict[str, ExtractedField]:
        fields = {}
        text_upper = text.upper()
        
        # FL 3a - Patient Control Number (Account #)
        pcn_match = re.search(r'(?:FL\s*)?3[AB]?\.?\s*(?:PATIENT\s*CONTROL)?\s*[:#]?\s*([A-Z0-9]{5,20})', text_upper)
        if pcn_match:
            fields['patient_control'] = ExtractedField(
                name='Patient Control # (FL 3a)',
                value=pcn_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.ACCOUNT_NUMBER,
            )
        
        # FL 8 - Patient Name
        name_match = re.search(r'(?:FL\s*)?8\.?\s*(?:PATIENT\s*NAME)?\s*[:\s]*([A-Z]+\s*,?\s*[A-Z]+)', text_upper)
        if name_match:
            fields['patient_name'] = ExtractedField(
                name='Patient Name (FL 8)',
                value=name_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.NAME,
            )
        
        # FL 10 - Patient DOB
        dob_match = re.search(r'(?:FL\s*)?10\.?\s*(?:BIRTH\s*DATE|DOB)?\s*[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})', text_upper)
        if dob_match:
            fields['patient_dob'] = ExtractedField(
                name='Patient DOB (FL 10)',
                value=dob_match.group(1),
                confidence=0.9,
                phi_category=PHICategory.DATE,
            )
        
        # FL 12 - Admission Date
        admit_match = re.search(r'(?:FL\s*)?12\.?\s*(?:ADMISSION)?\s*[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})', text_upper)
        if admit_match:
            fields['admission_date'] = ExtractedField(
                name='Admission Date (FL 12)',
                value=admit_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.DATE,
            )
        
        # FL 56 - NPI
        npi_match = re.search(r'(?:FL\s*)?56\.?\s*(?:NPI)?\s*[:\s]*(\d{10})', text_upper)
        if npi_match:
            npi_value = npi_match.group(1)
            fields['provider_npi'] = ExtractedField(
                name='Provider NPI (FL 56)',
                value=npi_value,
                confidence=0.95 if validate_npi(npi_value) else 0.7,
                phi_category=PHICategory.LICENSE_NUMBER,
                validated=validate_npi(npi_value),
                validation_method='npi_luhn',
            )
        
        # FL 60 - Insured's Unique ID
        insured_match = re.search(r'(?:FL\s*)?60[A-C]?\.?\s*(?:INSURED\'?S?\s*(?:UNIQUE\s*)?ID)?\s*[:\s]*([A-Z0-9]{5,20})', text_upper)
        if insured_match:
            fields['insured_id'] = ExtractedField(
                name='Insured ID (FL 60)',
                value=insured_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.HEALTH_PLAN_ID,
            )
        
        # Medical Record Number (various locations)
        mrn_match = re.search(r'(?:MRN|MEDICAL\s*RECORD)\s*[:#]?\s*([A-Z0-9]{5,15})', text_upper)
        if mrn_match:
            fields['mrn'] = ExtractedField(
                name='Medical Record Number',
                value=mrn_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.MRN,
            )
        
        return fields


class PassportParser(DocumentParser):
    """Parser for passports including MRZ decoding."""
    
    @property
    def document_type(self) -> DocumentType:
        return DocumentType.PASSPORT
    
    @property
    def field_patterns(self) -> List[Tuple[str, str]]:
        return []  # MRZ uses special parsing
    
    def extract_fields(self, text: str) -> Dict[str, ExtractedField]:
        fields = {}
        text_upper = text.upper()
        
        # Try to find MRZ lines (2 lines of 44 chars for TD3/passport)
        mrz_pattern = r'([A-Z0-9<]{44})\s*\n\s*([A-Z0-9<]{44})'
        mrz_match = re.search(mrz_pattern, text_upper)
        
        if mrz_match:
            line1 = mrz_match.group(1)
            line2 = mrz_match.group(2)
            
            # Parse MRZ Line 1: P<USASURNAME<<GIVEN<NAMES<<<<...
            if line1[0] == 'P':
                # Extract country code (positions 2-4)
                country = line1[2:5].replace('<', '')
                fields['issuing_country'] = ExtractedField(
                    name='Issuing Country',
                    value=country,
                    confidence=0.95,
                    phi_category=None,
                )
                
                # Extract name (positions 5-43)
                name_part = line1[5:44]
                surname, given = '', ''
                if '<<' in name_part:
                    parts = name_part.split('<<', 1)
                    surname = parts[0].replace('<', ' ').strip()
                    given = parts[1].replace('<', ' ').strip() if len(parts) > 1 else ''
                
                fields['name'] = ExtractedField(
                    name='Name (MRZ)',
                    value=f"{given} {surname}".strip(),
                    confidence=0.95,
                    phi_category=PHICategory.NAME,
                )
            
            # Parse MRZ Line 2: NUMBER<NATIONALITY<<DOB<SEX<EXPIRY<...
            passport_num = line2[0:9].replace('<', '')
            fields['passport_number'] = ExtractedField(
                name='Passport Number',
                value=passport_num,
                confidence=0.95,
                phi_category=PHICategory.OTHER_UNIQUE_ID,
            )
            
            # DOB at positions 13-18 (YYMMDD)
            dob_raw = line2[13:19]
            if dob_raw.isdigit():
                dob_formatted = f"{dob_raw[2:4]}/{dob_raw[4:6]}/{dob_raw[0:2]}"
                fields['dob'] = ExtractedField(
                    name='Date of Birth',
                    value=dob_formatted,
                    confidence=0.95,
                    phi_category=PHICategory.DATE,
                )
            
            # Sex at position 20
            sex = line2[20]
            if sex in ('M', 'F'):
                fields['sex'] = ExtractedField(
                    name='Sex',
                    value=sex,
                    confidence=0.95,
                    phi_category=None,
                )
            
            # Expiry at positions 21-26 (YYMMDD)
            exp_raw = line2[21:27]
            if exp_raw.isdigit():
                fields['expiration'] = ExtractedField(
                    name='Expiration Date',
                    value=f"{exp_raw[2:4]}/{exp_raw[4:6]}/{exp_raw[0:2]}",
                    confidence=0.95,
                    phi_category=None,
                )
        
        # Also try visual zone parsing (non-MRZ text)
        if 'passport_number' not in fields:
            pn_match = re.search(r'PASSPORT\s*(?:NO|NUM|#)?\s*[:\s]*([A-Z0-9]{6,12})', text_upper)
            if pn_match:
                fields['passport_number'] = ExtractedField(
                    name='Passport Number',
                    value=pn_match.group(1),
                    confidence=0.8,
                    phi_category=PHICategory.OTHER_UNIQUE_ID,
                )
        
        return fields


class LabRequisitionParser(DocumentParser):
    """Parser for laboratory requisition forms."""
    
    @property
    def document_type(self) -> DocumentType:
        return DocumentType.LAB_REQUISITION
    
    @property
    def field_patterns(self) -> List[Tuple[str, str]]:
        return LAB_REQUISITION_PATTERNS
    
    def extract_fields(self, text: str) -> Dict[str, ExtractedField]:
        fields = {}
        text_upper = text.upper()
        
        # Patient name
        name_match = re.search(r'(?:PATIENT|PT)\s*(?:NAME)?\s*[:\s]*([A-Z]+\s*,?\s*[A-Z]+)', text_upper)
        if name_match:
            fields['patient_name'] = ExtractedField(
                name='Patient Name',
                value=name_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.NAME,
            )
        
        # MRN
        mrn_match = re.search(r'(?:MRN|MEDICAL\s*RECORD|ACCT)\s*[:#]?\s*([A-Z0-9]{5,15})', text_upper)
        if mrn_match:
            fields['mrn'] = ExtractedField(
                name='MRN/Account',
                value=mrn_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.MRN,
            )
        
        # DOB
        dob_match = re.search(r'(?:DOB|BIRTH)\s*[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})', text_upper)
        if dob_match:
            fields['dob'] = ExtractedField(
                name='Date of Birth',
                value=dob_match.group(1),
                confidence=0.9,
                phi_category=PHICategory.DATE,
            )
        
        # Collection date/time
        coll_match = re.search(r'COLLECTION\s*(?:DATE|TIME)?\s*[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})', text_upper)
        if coll_match:
            fields['collection_date'] = ExtractedField(
                name='Collection Date',
                value=coll_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.DATE,
            )
        
        # Ordering physician
        ord_match = re.search(r'(?:ORDERING|ORD)\s*(?:PHYSICIAN|PROVIDER|MD|DR)?\s*[:\s]*(?:DR\.?\s*)?([A-Z]+(?:\s+[A-Z]\.?)?\s+[A-Z]+)', text_upper)
        if ord_match:
            fields['ordering_physician'] = ExtractedField(
                name='Ordering Physician',
                value=ord_match.group(1),
                confidence=0.8,
                phi_category=PHICategory.NAME,  # Provider names can be PHI in context
            )
        
        # NPI
        npi_match = re.search(r'NPI\s*[:\s]*(\d{10})', text_upper)
        if npi_match:
            fields['npi'] = ExtractedField(
                name='NPI',
                value=npi_match.group(1),
                confidence=0.9,
                phi_category=PHICategory.LICENSE_NUMBER,
                validated=validate_npi(npi_match.group(1)),
            )
        
        return fields


class PrescriptionParser(DocumentParser):
    """Parser for prescription labels and pads."""
    
    @property
    def document_type(self) -> DocumentType:
        return DocumentType.PRESCRIPTION_LABEL
    
    @property
    def field_patterns(self) -> List[Tuple[str, str]]:
        return PRESCRIPTION_PATTERNS
    
    def extract_fields(self, text: str) -> Dict[str, ExtractedField]:
        fields = {}
        text_upper = text.upper()
        
        # Rx Number
        rx_match = re.search(r'(?:RX|PRESCRIPTION)\s*[#:]?\s*(\d{5,12})', text_upper)
        if rx_match:
            fields['rx_number'] = ExtractedField(
                name='Rx Number',
                value=rx_match.group(1),
                confidence=0.9,
                phi_category=PHICategory.OTHER_UNIQUE_ID,
            )
        
        # Patient name
        patient_match = re.search(r'(?:PATIENT|FOR)\s*[:\s]*([A-Z]+\s*,?\s*[A-Z]+)', text_upper)
        if patient_match:
            fields['patient_name'] = ExtractedField(
                name='Patient Name',
                value=patient_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.NAME,
            )
        
        # Prescriber
        prescriber_match = re.search(
            r'(?:DR\.?|PRESCRIBER|PHYSICIAN)\s*[:\s]*([A-Z]+(?:\s+[A-Z]\.?)?\s+[A-Z]+)',
            text_upper
        )
        if prescriber_match:
            fields['prescriber'] = ExtractedField(
                name='Prescriber',
                value=prescriber_match.group(1),
                confidence=0.8,
                phi_category=PHICategory.NAME,
            )
        
        # DEA Number
        dea_match = re.search(r'DEA\s*[#:]?\s*([A-Z]{2}\d{7})', text_upper)
        if dea_match:
            dea_value = dea_match.group(1)
            fields['dea_number'] = ExtractedField(
                name='DEA Number',
                value=dea_value,
                confidence=0.95 if validate_dea(dea_value) else 0.7,
                phi_category=PHICategory.LICENSE_NUMBER,
                validated=validate_dea(dea_value),
                validation_method='dea_checksum',
            )
        
        # NPI
        npi_match = re.search(r'NPI\s*[:\s]*(\d{10})', text_upper)
        if npi_match:
            npi_value = npi_match.group(1)
            fields['npi'] = ExtractedField(
                name='NPI',
                value=npi_value,
                confidence=0.95 if validate_npi(npi_value) else 0.7,
                phi_category=PHICategory.LICENSE_NUMBER,
                validated=validate_npi(npi_value),
            )
        
        # NDC (National Drug Code)
        ndc_match = re.search(r'NDC\s*[:\s]*(\d{4,5}[- ]?\d{3,4}[- ]?\d{1,2})', text_upper)
        if ndc_match:
            fields['ndc'] = ExtractedField(
                name='NDC',
                value=ndc_match.group(1),
                confidence=0.9,
                phi_category=None,  # Drug identifier, not PHI
            )
        
        # Date filled
        date_match = re.search(r'(?:DATE|FILLED)\s*[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})', text_upper)
        if date_match:
            fields['date_filled'] = ExtractedField(
                name='Date Filled',
                value=date_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.DATE,
            )
        
        return fields


class EOBParser(DocumentParser):
    """Parser for Explanation of Benefits documents."""
    
    @property
    def document_type(self) -> DocumentType:
        return DocumentType.EOB
    
    @property
    def field_patterns(self) -> List[Tuple[str, str]]:
        return EOB_PATTERNS
    
    def extract_fields(self, text: str) -> Dict[str, ExtractedField]:
        fields = {}
        text_upper = text.upper()
        
        # Claim number
        claim_match = re.search(r'CLAIM\s*[#:]?\s*([A-Z0-9]{8,20})', text_upper)
        if claim_match:
            fields['claim_number'] = ExtractedField(
                name='Claim Number',
                value=claim_match.group(1),
                confidence=0.9,
                phi_category=PHICategory.ACCOUNT_NUMBER,
            )
        
        # Patient/Member name
        member_match = re.search(r'(?:PATIENT|MEMBER)\s*[:\s]*([A-Z]+\s*,?\s*[A-Z]+)', text_upper)
        if member_match:
            fields['member_name'] = ExtractedField(
                name='Member Name',
                value=member_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.NAME,
            )
        
        # Service date
        svc_match = re.search(r'(?:SERVICE|DATE\s*OF\s*SERVICE)\s*[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})', text_upper)
        if svc_match:
            fields['service_date'] = ExtractedField(
                name='Service Date',
                value=svc_match.group(1),
                confidence=0.85,
                phi_category=PHICategory.DATE,
            )
        
        # Provider
        provider_match = re.search(r'PROVIDER\s*[:\s]*([A-Z][A-Z\s,\.]+)', text_upper)
        if provider_match:
            fields['provider'] = ExtractedField(
                name='Provider',
                value=provider_match.group(1)[:50].strip(),
                confidence=0.8,
                phi_category=PHICategory.NAME,
            )
        
        # Member ID
        id_match = re.search(r'(?:MEMBER|SUBSCRIBER)\s*(?:ID|#)\s*[:\s]*([A-Z0-9]{6,20})', text_upper)
        if id_match:
            fields['member_id'] = ExtractedField(
                name='Member ID',
                value=id_match.group(1),
                confidence=0.9,
                phi_category=PHICategory.HEALTH_PLAN_ID,
            )
        
        return fields


# --- PARSER REGISTRY AND MAIN INTERFACE ---
# Registry of all parsers
DOCUMENT_PARSERS = {
    DocumentType.DRIVERS_LICENSE: DriversLicenseParser,
    DocumentType.STATE_ID: DriversLicenseParser,  # Same format
    DocumentType.PASSPORT: PassportParser,
    DocumentType.INSURANCE_COMMERCIAL: InsuranceCardParser,
    DocumentType.INSURANCE_MEDICARE: MedicareCardParser,
    DocumentType.INSURANCE_MEDICAID: InsuranceCardParser,  # Similar format
    DocumentType.INSURANCE_TRICARE: InsuranceCardParser,
    DocumentType.CMS_1500: CMS1500Parser,
    DocumentType.UB_04: UB04Parser,
    DocumentType.LAB_REQUISITION: LabRequisitionParser,
    DocumentType.PRESCRIPTION_LABEL: PrescriptionParser,
    DocumentType.PRESCRIPTION_PAD: PrescriptionParser,
    DocumentType.EOB: EOBParser,
}


def get_parser(doc_type: DocumentType) -> Optional[DocumentParser]:
    """Get appropriate parser for document type."""
    parser_class = DOCUMENT_PARSERS.get(doc_type)
    if parser_class:
        return parser_class()
    return None


def parse_document(text: str, doc_type: Optional[DocumentType] = None, aspect_ratio: Optional[float] = None) -> DocumentParseResult:
    """
    Parse a document, auto-detecting type if not specified.
    
    Args:
        text: OCR-extracted text
        doc_type: Document type (auto-detected if not provided)
        aspect_ratio: Image width/height ratio (helps detection)
        
    Returns:
        DocumentParseResult with extracted fields and cleaned text
    """
    # Auto-detect type if not provided
    if doc_type is None:
        doc_type, confidence = detect_document_type(text, aspect_ratio)
    else:
        confidence = 1.0
    
    # Get parser
    parser = get_parser(doc_type)
    
    if parser:
        result = parser.parse(text)
        result.confidence = confidence
        return result
    
    # Fallback for unknown types
    return DocumentParseResult(
        document_type=doc_type,
        confidence=confidence,
        fields={},
        raw_text=text,
        warnings=['No parser available for document type'],
    )


def clean_document_text(text: str, doc_type: Optional[DocumentType] = None, aspect_ratio: Optional[float] = None) -> str:
    """
    Convenience function to clean document text by removing field labels.
    
    Args:
        text: OCR-extracted text
        doc_type: Document type (auto-detected if not provided)
        aspect_ratio: Image width/height ratio
        
    Returns:
        Cleaned text with field labels removed
    """
    result = parse_document(text, doc_type, aspect_ratio)
    
    parser = get_parser(result.document_type)
    if parser:
        return parser.clean_text(text)
    
    return text


def extract_phi_fields(text: str, doc_type: Optional[DocumentType] = None) -> Dict[str, ExtractedField]:
    """
    Extract only PHI-classified fields from document.
    
    Args:
        text: OCR-extracted text  
        doc_type: Document type (auto-detected if not provided)
        
    Returns:
        Dictionary of field name -> ExtractedField for PHI fields only
    """
    result = parse_document(text, doc_type)
    return result.get_phi_fields()
