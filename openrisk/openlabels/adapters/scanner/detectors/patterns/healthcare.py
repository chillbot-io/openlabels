"""Healthcare patterns: MRN, NPI, DEA, health plan IDs, NDC, facility names."""

import regex  # Use regex module for ReDoS timeout protection (CVE-READY-003)
from typing import List, Tuple
from ..constants import (
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
    CONFIDENCE_WEAK,
)

from ..pattern_registry import create_pattern_adder

HEALTHCARE_PATTERNS: List[Tuple[regex.Pattern, str, float, int]] = []
add_pattern = create_pattern_adder(HEALTHCARE_PATTERNS)


# Medical Record Numbers

add_pattern(r'(?:MRN|Medical\s+Record(?:\s+Number)?)[:\s#]+([A-Z]*-?\d{6,12}[A-Z]*)', 'MRN', CONFIDENCE_HIGH, 1, regex.I)
add_pattern(r'\b(MRN-\d{6,12})\b', 'MRN', CONFIDENCE_RELIABLE, 1, regex.I)  # Bare MRN-1234567 format
add_pattern(r'(?:patient\s+ID|patient\s*#|pt\s+ID)[:\s#]+([A-Z]*-?\d{6,12}[A-Z]*)', 'MRN', CONFIDENCE_MEDIUM_LOW, 1, regex.I)  # "patient ID" variant
add_pattern(r'(?:Encounter|Visit)[:\s#]+([A-Z]*\d{6,12}[A-Z]*)', 'ENCOUNTER_ID', CONFIDENCE_MEDIUM, 1, regex.I)
add_pattern(r'(?:Accession|Lab)[:\s#]+([A-Z]*\d{6,12}[A-Z]*)', 'ACCESSION_ID', CONFIDENCE_MEDIUM, 1, regex.I)


# NPI (National Provider Identifier)

# NPI is a 10-digit number with Luhn checksum (same algorithm as credit cards)
# Labeled: "NPI: 1234567890", "NPI# 1234567890"
add_pattern(r'(?:NPI)[:\s#]+(\d{10})\b', 'NPI', CONFIDENCE_HIGH, 1, regex.I)
# Contextual: "provider NPI 1234567890"
add_pattern(r'(?:provider|physician|prescriber|ordering)\s+NPI[:\s#]*(\d{10})\b', 'NPI', CONFIDENCE_RELIABLE, 1, regex.I)
# DEA number (provider controlled substance license): 2 letters + 7 digits
add_pattern(r'(?:DEA)[:\s#]+([A-Z]{2}\d{7})\b', 'DEA', CONFIDENCE_HIGH, 1, regex.I)


# Health Plan IDs

add_pattern(r'(?:Member\s*ID|Subscriber)[:\s#]+([A-Z0-9]{6,15})', 'MEMBER_ID', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
add_pattern(r'(?:Medicaid)[:\s#]+([A-Z0-9]{8,12})', 'HEALTH_PLAN_ID', CONFIDENCE_MEDIUM_LOW, 1, regex.I)

# === Medicare Beneficiary Identifier (MBI) - CMS format since 2020 ===
# Format: 11 chars = C-AN-N-L-AN-N-L-AN-N-AN with optional dashes
# Pos 1: 1-9 (not 0), Pos 2,5,8: Letters (not S,L,O,I,B,Z)
# Pos 3,6,9,11: Alphanumeric (not S,L,O,I,B,Z), Pos 4,7,10: Digits
_MBI_LETTER = r'[ACDEFGHJKMNPQRTUVWXY]'
_MBI_ALNUM = r'[ACDEFGHJKMNPQRTUVWXY0-9]'
_MBI_PATTERN = rf'[1-9]{_MBI_LETTER}{_MBI_ALNUM}\d-?{_MBI_LETTER}{_MBI_ALNUM}\d-?{_MBI_LETTER}{_MBI_ALNUM}\d{_MBI_ALNUM}'

# Labeled MBI patterns (high confidence)
add_pattern(rf'(?:Medicare\s*(?:Beneficiary\s*)?(?:ID|#|Number)?|MBI)[:\s#()]*({_MBI_PATTERN})', 'MEDICARE_ID', 0.97, 1, regex.I)
add_pattern(rf'(?:Beneficiary\s*ID)[:\s#]*({_MBI_PATTERN})', 'MEDICARE_ID', CONFIDENCE_HIGH, 1, regex.I)
# After other Medicare labels like "Medicare ID (MBI):"
add_pattern(rf'(?:ID\s*\(MBI\))[:\s#]*({_MBI_PATTERN})', 'MEDICARE_ID', CONFIDENCE_NEAR_CERTAIN, 1, regex.I)
# Bare MBI pattern (moderate confidence - distinct format unlikely to be random)
add_pattern(rf'\b({_MBI_PATTERN})\b', 'MEDICARE_ID', CONFIDENCE_MARGINAL, 1)

# Pharmacy-related IDs
add_pattern(r'(?:RXBIN|RX\s*BIN)[:\s]+(\d{6})', 'PHARMACY_ID', CONFIDENCE_MEDIUM, 1, regex.I)
add_pattern(r'(?:RXPCN|RX\s*PCN)[:\s]+([A-Z0-9]{4,10})', 'PHARMACY_ID', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
add_pattern(r'(?:Group(?:\s*(?:Number|No|#))?)[:\s#]+([A-Z0-9-]{4,15})', 'HEALTH_PLAN_ID', CONFIDENCE_MINIMAL, 1, regex.I)

# Member ID with letter prefix and hyphen (e.g., BC-993812, BVH-882391)
add_pattern(r'(?:Member\s*ID)[:\s#]+([A-Z]{2,4}-\d{5,12})', 'MEMBER_ID', CONFIDENCE_RELIABLE, 1, regex.I)
# Bare insurance ID format: 2-4 letters, hyphen, 5-12 digits (contextual)
add_pattern(r'\b([A-Z]{2,4}-\d{5,12})\b', 'HEALTH_PLAN_ID', CONFIDENCE_LOWEST, 1)

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
# Require at least one digit in the ID portion to avoid matching company names
add_pattern(rf'(?:{_PAYER_PREFIXES})[- ]?([A-Z]*\d[A-Z0-9]{{5,14}})', 'HEALTH_PLAN_ID', CONFIDENCE_MEDIUM, 1, regex.I)
add_pattern(rf'((?:{_PAYER_PREFIXES})[- ]?[A-Z]*\d[A-Z0-9]{{5,14}})', 'HEALTH_PLAN_ID', CONFIDENCE_MEDIUM_LOW, 0, regex.I)


# Facility Patterns

_FACILITY_PREFIX = r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}"  # 1-4 capitalized words
add_pattern(rf'({_FACILITY_PREFIX}\s+(?:Hospital|Medical\s+Center|Health\s+Center|Clinic|Health\s+System|Healthcare|Specialty\s+Clinic|Regional\s+Medical))\b', 'FACILITY', CONFIDENCE_LOW, 1)
add_pattern(rf'({_FACILITY_PREFIX}\s+(?:Memorial|General|Community|University|Regional|Veterans|Children\'s)\s+Hospital)\b', 'FACILITY', CONFIDENCE_MEDIUM_LOW, 1)
add_pattern(rf'({_FACILITY_PREFIX}\s+(?:Group|LLC|Ltd|Inc|Associates|Partners)\s+Hospital)\b', 'FACILITY', CONFIDENCE_LOW, 1)

# St./Saint prefixed facilities (very common in healthcare)
# High confidence to override any misclassification of "St" as ADDRESS
add_pattern(r"(St\.?\s+[A-Z][a-z]+(?:'s)?\s+(?:Hospital|Medical\s+Center|Health\s+Center|Clinic|Health\s+System|Heart\s+Institute|Cancer\s+Center|Children's\s+Hospital))", 'FACILITY', CONFIDENCE_RELIABLE, 1)
add_pattern(r"(Saint\s+[A-Z][a-z]+(?:'s)?\s+(?:Hospital|Medical\s+Center|Health\s+Center|Clinic|Health\s+System|Heart\s+Institute|Cancer\s+Center|Children's\s+Hospital))", 'FACILITY', CONFIDENCE_RELIABLE, 1)
# Generic St./Saint + Name patterns (catch-all for other facility types)
add_pattern(r"(St\.?\s+[A-Z][a-z]+(?:'s)?(?:\s+[A-Z][a-z]+){1,3})\s+(?:Hospital|Center|Clinic|Institute|Foundation)", 'FACILITY', CONFIDENCE_MEDIUM_LOW, 0)
add_pattern(r"(Saint\s+[A-Z][a-z]+(?:'s)?(?:\s+[A-Z][a-z]+){1,3})\s+(?:Hospital|Center|Clinic|Institute|Foundation)", 'FACILITY', CONFIDENCE_MEDIUM_LOW, 0)

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
# "[Name] Pulmonary Clinic", "[Name] Cardiology Center"
add_pattern(rf'({_FACILITY_PREFIX}\s+(?:{_MEDICAL_SPECIALTY})\s+(?:Clinic|Center|Associates|Practice|Group|Specialists))\b', 'FACILITY', CONFIDENCE_MEDIUM, 1, regex.I)

# Multi-part specialty facilities with "&": "Pulmonary & Sleep Center", "Cardiology & Vascular Associates"
add_pattern(rf'((?:{_MEDICAL_SPECIALTY})\s+(?:&|and)\s+(?:{_MEDICAL_SPECIALTY})\s+(?:Center|Clinic|Associates|Institute|Specialists))\b', 'FACILITY', CONFIDENCE_RELIABLE, 1, regex.I)

# "[Name] Pulmonary & Sleep Center" (name prefix + specialty combo)
add_pattern(rf'({_FACILITY_PREFIX}\s+(?:{_MEDICAL_SPECIALTY})\s+(?:&|and)\s+(?:{_MEDICAL_SPECIALTY})\s+(?:Center|Clinic|Associates))\b', 'FACILITY', CONFIDENCE_RELIABLE, 1, regex.I)

# Context-labeled facilities: "Clinic:", "Hospital:", "Center:" followed by name
add_pattern(rf'(?:Clinic|Hospital|Center|Practice)[:\s]+({_FACILITY_PREFIX}(?:\s+(?:{_MEDICAL_SPECIALTY}))?(?:\s+(?:&|and)\s+[A-Z][a-z]+)*(?:\s+(?:Center|Clinic|Associates|Practice))?)', 'FACILITY', CONFIDENCE_MEDIUM, 1, regex.I)

# Standalone specialty practice names: "Pulmonary Associates", "Sleep Center", "Pain Specialists"
add_pattern(rf'\b((?:{_MEDICAL_SPECIALTY})\s+(?:Associates|Specialists|Center|Clinic|Practice|Group|Partners))\b', 'FACILITY', CONFIDENCE_LOW, 1, regex.I)

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
# Pharmacy with optional store number (e.g., "Walgreens Pharmacy #10472")
add_pattern(rf'((?:{_PHARMACY_CHAINS})(?:\s+Pharmacy)?(?:\s*#?\d{{3,6}})?)', 'FACILITY', CONFIDENCE_RELIABLE, 1, regex.I)
# "Preferred Pharmacy:" or "Pharmacy:" label followed by pharmacy name
add_pattern(rf'(?:Preferred\s+)?Pharmacy[:\s]+((?:{_PHARMACY_CHAINS})(?:\s+Pharmacy)?(?:\s*#?\d{{3,6}})?)', 'FACILITY', CONFIDENCE_HIGH_MEDIUM, 1, regex.I)
# Bare pharmacy chain name when it appears alone
add_pattern(rf'\b((?:{_PHARMACY_CHAINS})\s+Pharmacy(?:\s*#\d{{3,6}})?)(?:\s|,|$)', 'FACILITY', CONFIDENCE_MEDIUM, 1, regex.I)


# Healthcare-Specific Identifiers

# === NDC (National Drug Code) - 5-4-2 format with dashes ===
# FDA standard drug identifier, reveals medication info
add_pattern(r'\b(\d{5}-\d{4}-\d{2})\b', 'NDC', CONFIDENCE_RELIABLE, 1)
# NDC with label
add_pattern(r'(?:NDC|National\s+Drug\s+Code)[:\s#]+(\d{5}-?\d{4}-?\d{2})', 'NDC', CONFIDENCE_HIGH, 1, regex.I)
# 10-digit NDC without dashes (some formats)
add_pattern(r'(?:NDC)[:\s#]+(\d{10,11})\b', 'NDC', CONFIDENCE_MEDIUM_LOW, 1, regex.I)

# === Room/Bed Numbers (healthcare context) ===
# Hospital room numbers - require context
add_pattern(r'(?:Room|Rm\.?|Unit)[:\s#]+(\d{1,4}[A-Z]?)\b', 'ROOM_NUMBER', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
add_pattern(r'(?:Bed|Bay)[:\s#]+(\d{1,2}[A-Z]?)\b', 'BED_NUMBER', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
# Combined: "Room 412, Bed 3" or "Room 412-B"
add_pattern(r'(?:Room|Rm\.?)\s*(\d{1,4}[-]?[A-Z]?),?\s*(?:Bed|Bay)\s*(\d{1,2}[A-Z]?)', 'ROOM_NUMBER', CONFIDENCE_MEDIUM, 0, regex.I)
# Floor + Room: "4th floor, room 412" or "Floor 4 Room 12"
add_pattern(r'(?:Floor|Fl\.?)\s*(\d{1,2})\s*[,\s]+(?:Room|Rm\.?)\s*(\d{1,4})', 'ROOM_NUMBER', CONFIDENCE_LOW, 0, regex.I)

# === Pager Numbers ===
add_pattern(r'(?:Pager|Beeper|Pgr\.?)[:\s#]+(\d{3}[-.\s]?\d{3}[-.\s]?\d{4})', 'PAGER', CONFIDENCE_MEDIUM, 1, regex.I)
add_pattern(r'(?:Pager|Pgr\.?)[:\s#]+(\d{4,7})\b', 'PAGER', CONFIDENCE_LOW, 1, regex.I)  # Short pager codes

# === Extension Numbers ===
add_pattern(r'(?:ext\.?|extension|x)[:\s#]*(\d{3,6})\b', 'PHONE_EXT', CONFIDENCE_LOW, 1, regex.I)
# Phone with extension: "555-1234 ext 567"
add_pattern(r'(\d{3}[-.\s]?\d{3}[-.\s]?\d{4})\s*(?:ext\.?|x)\s*(\d{3,6})', 'PHONE', CONFIDENCE_MEDIUM, 0, regex.I)

# === Prior Authorization / Claim Numbers ===
add_pattern(r'(?:Prior\s*Auth(?:orization)?|PA)[:\s#]+([A-Z0-9]{6,20})', 'AUTH_NUMBER', CONFIDENCE_MEDIUM, 1, regex.I)
add_pattern(r'(?:Auth(?:orization)?\s*(?:Number|No|#|Code))[:\s#]+([A-Z0-9]{6,20})', 'AUTH_NUMBER', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
add_pattern(r'(?:Pre-?cert(?:ification)?)[:\s#]+([A-Z0-9]{6,20})', 'AUTH_NUMBER', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
# Workers comp claim
add_pattern(r'(?:Workers?\s*Comp|WC)\s*(?:Claim)?[:\s#]+([A-Z0-9]{6,20})', 'CLAIM_NUMBER', CONFIDENCE_MEDIUM_LOW, 1, regex.I)


# Physical Identifiers (with strong context to avoid FPs)

# === Blood Type ===
add_pattern(r'(?:Blood\s*Type|Blood\s*Group|ABO)[:\s]+([ABO]{1,2}[+-])', 'BLOOD_TYPE', CONFIDENCE_RELIABLE, 1, regex.I)
add_pattern(r'(?:Type)[:\s]+([ABO]{1,2}[+-])(?:\s+blood|\s+Rh)', 'BLOOD_TYPE', CONFIDENCE_MEDIUM_LOW, 1, regex.I)

# === Height (with context) ===
add_pattern(r'(?:Height|Ht\.?)[:\s]+(\d{1,2}[\'\u2032]\s*\d{1,2}[\"\u2033]?)', 'HEIGHT', CONFIDENCE_MEDIUM, 1, regex.I)  # 5'10" format
add_pattern(r'(?:Height|Ht\.?)[:\s]+(\d{2,3})\s*(?:cm|in(?:ches)?)', 'HEIGHT', CONFIDENCE_MEDIUM_LOW, 1, regex.I)  # metric/inches
add_pattern(r'(?:Height|Ht\.?)[:\s]+(\d\s*ft\.?\s*\d{1,2}\s*in\.?)', 'HEIGHT', CONFIDENCE_MEDIUM_LOW, 1, regex.I)  # "5 ft 10 in"

# === Weight (with context) ===
add_pattern(r'(?:Weight|Wt\.?)[:\s]+(\d{2,3})\s*(?:lbs?|pounds?|kg|kilograms?)', 'WEIGHT', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
add_pattern(r'(?:Weight|Wt\.?)[:\s]+(\d{2,3}(?:\.\d)?)\s*(?:lbs?|kg)', 'WEIGHT', CONFIDENCE_MEDIUM_LOW, 1, regex.I)

# === BMI (with context) ===
add_pattern(r'(?:BMI|Body\s*Mass\s*Index)[:\s]+(\d{2}(?:\.\d{1,2})?)', 'BMI', CONFIDENCE_MEDIUM, 1, regex.I)


# Prescription / Rx Numbers

add_pattern(r'(?:Rx|Rx\s*#|Prescription|Script)[:\s#]+(\d{6,12})', 'RX_NUMBER', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
add_pattern(r'(?:Rx|Prescription)\s+(?:Number|No|#)[:\s]+([A-Z0-9]{6,15})', 'RX_NUMBER', CONFIDENCE_MEDIUM, 1, regex.I)
add_pattern(r'(?:Refill|Fill)\s+#[:\s]*(\d{1,3})\s+of\s+(\d{1,3})', 'RX_NUMBER', CONFIDENCE_MINIMAL, 0, regex.I)  # "Refill #2 of 5"


# Fax Numbers (healthcare-specific communication)

add_pattern(r'(?:fax|facsimile)[:\s]+([()\d\s+.-]{10,20})', 'FAX', CONFIDENCE_RELIABLE, 1, regex.I)
add_pattern(r'(?:f|fax)[:\s]*\((\d{3})\)\s*(\d{3})[-.]?(\d{4})', 'FAX', CONFIDENCE_MEDIUM)
add_pattern(r'(?:f|fax)[:\s]*(\d{3})[-.](\d{3})[-.](\d{4})', 'FAX', CONFIDENCE_MEDIUM_LOW)
