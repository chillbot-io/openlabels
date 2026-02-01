"""Government ID patterns: SSN, driver's license, passport, military, international IDs."""

import regex  # Use regex module for ReDoS timeout protection (CVE-READY-003)
from typing import List, Tuple
from ..constants import (
    CONFIDENCE_BORDERLINE,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_LOWEST,
    CONFIDENCE_MARGINAL,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_MEDIUM_LOW,
    CONFIDENCE_MINIMAL,
    CONFIDENCE_NEAR_CERTAIN,
    CONFIDENCE_RELIABLE,
    CONFIDENCE_SPECULATIVE,
    CONFIDENCE_VERY_LOW,
    CONFIDENCE_WEAK,
)

from ..pattern_registry import create_pattern_adder

GOVERNMENT_PATTERNS: List[Tuple[regex.Pattern, str, float, int]] = []
add_pattern = create_pattern_adder(GOVERNMENT_PATTERNS)



# --- Social Security Numbers (Ssn) ---


# === SSN (labeled) - higher confidence than unlabeled ===
add_pattern(r'(?:SSN|Social\s*Security(?:\s*(?:Number|No|#))?)[:\s#]+(\d{3}[-\s]?\d{2}[-\s]?\d{4})', 'SSN', CONFIDENCE_NEAR_CERTAIN, 1, regex.I)
add_pattern(r'(?:last\s*4|last\s*four)[:\s]+(\d{4})\b', 'SSN_PARTIAL', CONFIDENCE_WEAK, 1, regex.I)
# Bare 9-digit - LOW confidence (0.70) so labeled MRN/Account patterns (0.95) win
add_pattern(r'\b((?!000|666|9\d\d)\d{9})\b', 'SSN', CONFIDENCE_LOWEST)

# SSN with unusual separators (dots, middle dots, spaces around hyphens)
add_pattern(r'(?:SSN|Social\s*Security)[:\s#]+(\d{3}[.\xb7]\d{2}[.\xb7]\d{4})', 'SSN', CONFIDENCE_LOW, 1, regex.I)  # dots/middle dots
add_pattern(r'(?:SSN|Social\s*Security)[:\s#]+(\d{3}\s*-\s*\d{2}\s*-\s*\d{4})', 'SSN', CONFIDENCE_MEDIUM_LOW, 1, regex.I)  # spaces around hyphens


# --- Driver's License ---

# === Driver's License - Labeled ===
add_pattern(r'(?:Driver\'?s?\s*License|DL|DLN)[:\s#]+([A-Z0-9]{5,15})', 'DRIVER_LICENSE', CONFIDENCE_MEDIUM_LOW, 1, regex.I)

# === Driver's License - State-specific formats (bare patterns) ===
# These catch DL numbers even without labels, based on known state formats

# --- Florida: Letter + 3-3-2-3-1 with dashes (W426-545-30-761-0) ---
add_pattern(r'\b([A-Z]\d{3}-\d{3}-\d{2}-\d{3}-\d)\b', 'DRIVER_LICENSE', CONFIDENCE_HIGH, 1)
# Florida without dashes (OCR may miss them): W4265453076110
add_pattern(r'\b([A-Z]\d{12}0)\b', 'DRIVER_LICENSE', CONFIDENCE_LOW, 1)

# --- California: Letter + 7 digits (A1234567) ---
add_pattern(r'\b([A-Z]\d{7})\b', 'DRIVER_LICENSE', CONFIDENCE_VERY_LOW, 1)

# --- New York: 9 digits OR Letter + 7 digits + space + 3 digits ---
# Note: 9 digit overlaps with SSN, so need context
add_pattern(r'(?:DL|License)[:\s]+(\d{9})\b', 'DRIVER_LICENSE', CONFIDENCE_LOW, 1, regex.I)

# --- Pennsylvania: 8 digits ---
add_pattern(r'\b(\d{8})\b(?=.*(?:PA|Pennsylvania|DL|License))', 'DRIVER_LICENSE', CONFIDENCE_MINIMAL, 1, regex.I)

# --- Illinois: Letter + 11-12 digits (A12345678901) ---
add_pattern(r'\b([A-Z]\d{11,12})\b', 'DRIVER_LICENSE', CONFIDENCE_MARGINAL, 1)

# --- Ohio: 2 letters + 6 digits (AB123456) OR 8 digits ---
add_pattern(r'\b([A-Z]{2}\d{6})\b', 'DRIVER_LICENSE', CONFIDENCE_BORDERLINE, 1)

# --- Michigan: Letter + 10-12 digits ---
add_pattern(r'\b([A-Z]\d{10,12})\b', 'DRIVER_LICENSE', CONFIDENCE_WEAK, 1)

# --- New Jersey: Letter + 14 digits ---
add_pattern(r'\b([A-Z]\d{14})\b', 'DRIVER_LICENSE', CONFIDENCE_LOW, 1)

# --- Virginia: Letter + 8-9 digits OR 9 digits (with context) ---
add_pattern(r'\b([A-Z]\d{8,9})\b', 'DRIVER_LICENSE', CONFIDENCE_MINIMAL, 1)

# --- Maryland: Letter + 12 digits ---
# (Covered by Michigan pattern above)

# --- Wisconsin: Letter + 13 digits ---
add_pattern(r'\b([A-Z]\d{13})\b', 'DRIVER_LICENSE', CONFIDENCE_MARGINAL, 1)

# --- Washington: WDL prefix + alphanumeric (12 chars total like WDL*ABC1234D) ---
add_pattern(r'\b(WDL[A-Z0-9*]{9})\b', 'DRIVER_LICENSE', CONFIDENCE_RELIABLE, 1)

# --- Hawaii: H + 8 digits (H12345678) ---
add_pattern(r'\b(H\d{8})\b', 'DRIVER_LICENSE', CONFIDENCE_LOW, 1)

# --- Colorado: 2 letters + 3-6 digits OR 9 digits (with context) ---
add_pattern(r'\b([A-Z]{2}\d{3,6})\b', 'DRIVER_LICENSE', CONFIDENCE_VERY_LOW, 1)
add_pattern(r'(?:CO|Colorado|DL)[:\s]+(\d{9})\b', 'DRIVER_LICENSE', CONFIDENCE_WEAK, 1, regex.I)

# --- Nevada: 9-12 digits, often starts with X or 9 ---
add_pattern(r'\b(X\d{8,11})\b', 'DRIVER_LICENSE', CONFIDENCE_LOW, 1)
add_pattern(r'(?:NV|Nevada|DL)[:\s]+(\d{9,12})\b', 'DRIVER_LICENSE', CONFIDENCE_BORDERLINE, 1, regex.I)

# --- New Hampshire: 2 digits + 3 letters + 5 digits (12ABC34567) ---
add_pattern(r'\b(\d{2}[A-Z]{3}\d{5})\b', 'DRIVER_LICENSE', CONFIDENCE_MEDIUM_LOW, 1)

# --- North Dakota: 3 letters + 6 digits (ABC123456) ---
add_pattern(r'\b([A-Z]{3}\d{6})\b', 'DRIVER_LICENSE', CONFIDENCE_MARGINAL, 1)

# --- Iowa: 3 digits + 2 letters + 4 digits (123AB4567) OR 9 digits ---
add_pattern(r'\b(\d{3}[A-Z]{2}\d{4})\b', 'DRIVER_LICENSE', CONFIDENCE_MEDIUM_LOW, 1)

# --- Kansas: K + 8 digits (K12345678) ---
add_pattern(r'\b(K\d{8})\b', 'DRIVER_LICENSE', CONFIDENCE_LOW, 1)

# --- Massachusetts: S + 8 digits (S12345678) ---
add_pattern(r'\b(S\d{8})\b', 'DRIVER_LICENSE', CONFIDENCE_LOW, 1)

# --- Arizona: Letter + 8 digits OR 9 digits with context ---
add_pattern(r'(?:AZ|Arizona|DL)[:\s]+([A-Z]?\d{8,9})\b', 'DRIVER_LICENSE', CONFIDENCE_WEAK, 1, regex.I)

# --- Minnesota: Letter + 12 digits ---
# (Covered by Illinois pattern: Letter + 11-12 digits)

# --- Kentucky: Letter + 8-9 digits ---
# (Covered by Virginia pattern: Letter + 8-9 digits)

# --- Louisiana: 8 digits, often starts with 00 ---
add_pattern(r'\b(00\d{6})\b', 'DRIVER_LICENSE', CONFIDENCE_WEAK, 1)

# --- Indiana: 4 digits + 2 letters + 4 digits (1234AB5678) OR 10 digits ---
add_pattern(r'\b(\d{4}[A-Z]{2}\d{4})\b', 'DRIVER_LICENSE', CONFIDENCE_MEDIUM_LOW, 1)
add_pattern(r'(?:IN|Indiana|DL)[:\s]+(\d{10})\b', 'DRIVER_LICENSE', CONFIDENCE_BORDERLINE, 1, regex.I)

# --- Oregon: 1-7 digits OR Letter + 6 digits ---
add_pattern(r'\b([A-Z]\d{6})\b', 'DRIVER_LICENSE', CONFIDENCE_VERY_LOW, 1)

# --- Connecticut: 9 digits (with context, overlaps SSN) ---
add_pattern(r'(?:CT|Connecticut|DL)[:\s]+(\d{9})\b', 'DRIVER_LICENSE', CONFIDENCE_BORDERLINE, 1, regex.I)

# --- Texas: 8 digits (with context) ---
add_pattern(r'(?:TX|Texas|DL)[:\s]+(\d{8})\b', 'DRIVER_LICENSE', CONFIDENCE_BORDERLINE, 1, regex.I)

# --- Georgia: 7-9 digits (with context) ---
add_pattern(r'(?:GA|Georgia|DL)[:\s]+(\d{7,9})\b', 'DRIVER_LICENSE', CONFIDENCE_BORDERLINE, 1, regex.I)

# --- Alabama: 7 digits (with context) ---
add_pattern(r'(?:AL|Alabama|DL)[:\s]+(\d{7})\b', 'DRIVER_LICENSE', CONFIDENCE_BORDERLINE, 1, regex.I)

# --- Missouri: Letter + 5-10 digits OR 9 digits with context ---
add_pattern(r'(?:MO|Missouri|DL)[:\s]+([A-Z]?\d{5,10})\b', 'DRIVER_LICENSE', CONFIDENCE_BORDERLINE, 1, regex.I)

# --- Tennessee: 7-9 digits (with context) ---
add_pattern(r'(?:TN|Tennessee|DL)[:\s]+(\d{7,9})\b', 'DRIVER_LICENSE', CONFIDENCE_BORDERLINE, 1, regex.I)

# --- South Carolina: 5-11 digits (with context) ---
add_pattern(r'(?:SC|South\s+Carolina|DL)[:\s]+(\d{5,11})\b', 'DRIVER_LICENSE', CONFIDENCE_BORDERLINE, 1, regex.I)

# --- General formats ---
# Letter(s) + 5-14 digits (many states)
add_pattern(r'\b([A-Z]{1,2}\d{5,14})\b', 'DRIVER_LICENSE', CONFIDENCE_SPECULATIVE, 1)

# DL with spaces (like "99 999999" from PA sample)
add_pattern(r'(?:DL|DLN)[:\s#]+(\d{2}\s+\d{6})', 'DRIVER_LICENSE', CONFIDENCE_MEDIUM, 1, regex.I)

# DL with dashes - generic (captures FL and others)
add_pattern(r'(?:DL|DLN)[:\s#]+([A-Z]?\d{2,4}[-\s]\d{2,4}[-\s]\d{2,4}[-\s]?\d{0,4})', 'DRIVER_LICENSE', CONFIDENCE_RELIABLE, 1, regex.I)



# --- State Id (Non-Driver) ---


add_pattern(r'(?:State\s*ID|ID\s*Card)[:\s#]+([A-Z0-9]{5,15})', 'STATE_ID', CONFIDENCE_MEDIUM_LOW, 1, regex.I)

# === ID Card trailing numbers (document discriminator, inventory numbers) ===
# These appear after "ORGAN DONOR", "DD:", or at end of ID card text
add_pattern(r'(?:ORGAN\s*DONOR|VETERAN)\s+(\d{10,15})\s*$', 'UNIQUE_ID', CONFIDENCE_LOW, 1, regex.I)
# Document discriminator without DD label (often at end of ID)
add_pattern(r'(?:DD[:\s]+\d{10,15}\s+)(\d{10,15})\s*$', 'UNIQUE_ID', CONFIDENCE_WEAK, 1)



# --- Passport ---


add_pattern(r'(?:Passport)[:\s#]+([A-Z0-9]{6,12})', 'PASSPORT', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
# US passport format: 9 digits or alphanumeric
add_pattern(r'\b([A-Z]?\d{8,9})\b(?=.*[Pp]assport)', 'PASSPORT', CONFIDENCE_MINIMAL, 1)



# --- Medical License ---


add_pattern(r'(?:Medical\s+License|License\s+#)[:\s]+([A-Z0-9]{5,15})', 'MEDICAL_LICENSE', CONFIDENCE_MEDIUM_LOW, 1, regex.I)



# --- Military Ids ---


# EDIPI (Electronic Data Interchange Personal Identifier) - 10 digits
add_pattern(r'(?:EDIPI|DoD\s*ID|Military\s*ID)[:\s#]+(\d{10})\b', 'MILITARY_ID', CONFIDENCE_RELIABLE, 1, regex.I)


# --- International Identifiers ---

# === UK NHS Number (10 digits with checksum) ===
add_pattern(r'(?:NHS|National\s+Health)[:\s#]+(\d{3}\s?\d{3}\s?\d{4})', 'NHS_NUMBER', CONFIDENCE_RELIABLE, 1, regex.I)
add_pattern(r'(?:NHS)[:\s#]+(\d{10})\b', 'NHS_NUMBER', CONFIDENCE_MEDIUM, 1, regex.I)

# === Canadian SIN (9 digits, starts with specific digits) ===
add_pattern(r'(?:SIN|Social\s+Insurance)[:\s#]+(\d{3}[-\s]?\d{3}[-\s]?\d{3})', 'SIN', CONFIDENCE_RELIABLE, 1, regex.I)
# Bare SIN with Canadian context (require word boundary for CA to avoid matching "Call")
add_pattern(r'(?:\bCanada\b|\bCanadian\b|\bCA\b)[^.]{0,30}(\d{3}[-\s]?\d{3}[-\s]?\d{3})', 'SIN', CONFIDENCE_WEAK, 1, regex.I)

# === Australian TFN (Tax File Number - 8-9 digits) ===
add_pattern(r'(?:TFN|Tax\s+File)[:\s#]+(\d{3}\s?\d{3}\s?\d{2,3})', 'TFN', CONFIDENCE_RELIABLE, 1, regex.I)

# === Indian Aadhaar (12 digits with specific format) ===
add_pattern(r'(?:Aadhaar|UIDAI|Aadhar)[:\s#]+(\d{4}\s?\d{4}\s?\d{4})', 'AADHAAR', CONFIDENCE_RELIABLE, 1, regex.I)
add_pattern(r'(?:Aadhaar|UIDAI)[:\s#]+(\d{12})\b', 'AADHAAR', CONFIDENCE_MEDIUM, 1, regex.I)

# === Mexican CURP (18 alphanumeric, specific format) ===
add_pattern(r'(?:CURP)[:\s#]+([A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d)', 'CURP', CONFIDENCE_HIGH, 1, regex.I)

# === German Sozialversicherungsnummer (12 digits) ===
add_pattern(r'(?:Sozialversicherungsnummer|SVNR|SV-Nummer)[:\s#]+(\d{2}\s?\d{6}\s?[A-Z]\s?\d{3})', 'SVNR', CONFIDENCE_RELIABLE, 1, regex.I)
