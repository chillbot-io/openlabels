"""Credentials patterns: IP addresses, MAC, IMEI, serial numbers, URLs, usernames."""

import regex  # Use regex module for ReDoS timeout protection (CVE-READY-003)
from typing import List, Tuple
from ..constants import (
    CONFIDENCE_HIGH_MEDIUM,
    CONFIDENCE_LOW,
    CONFIDENCE_MARGINAL,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_MEDIUM_LOW,
    CONFIDENCE_RELIABLE,
    CONFIDENCE_WEAK,
)

from ..pattern_registry import create_pattern_adder

CREDENTIALS_PATTERNS: List[Tuple[regex.Pattern, str, float, int]] = []
add_pattern = create_pattern_adder(CREDENTIALS_PATTERNS)


# IP Addresses

add_pattern(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', 'IP_ADDRESS', CONFIDENCE_LOW)
# IPv6 - full or compressed format
add_pattern(r'\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7})\b', 'IP_ADDRESS', CONFIDENCE_LOW)  # Full
add_pattern(r'\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,7})\b', 'IP_ADDRESS', CONFIDENCE_WEAK)  # Compressed


# MAC Address

add_pattern(r'\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', 'MAC_ADDRESS', CONFIDENCE_MEDIUM)


# IMEI

add_pattern(r'(?:IMEI)[:\s]+(\d{15})', 'IMEI', CONFIDENCE_HIGH_MEDIUM, 1, regex.I)


# Device Serial Numbers (medical devices)

# Labeled patterns for pacemakers, insulin pumps, hearing aids, etc.
add_pattern(r'(?:Serial(?:\s*(?:Number|No|#))?|S/N|SN)[:\s]+([A-Z0-9]{6,20})', 'DEVICE_ID', CONFIDENCE_MEDIUM, 1, regex.I)
add_pattern(r'(?:Device\s*(?:ID|Identifier|Serial))[:\s]+([A-Z0-9]{6,20})', 'DEVICE_ID', CONFIDENCE_RELIABLE, 1, regex.I)
add_pattern(r'(?:Pacemaker|ICD|Defibrillator|Pump|Implant)\s+(?:ID|Serial|S/N)[:\s]+([A-Z0-9]{6,20})', 'DEVICE_ID', CONFIDENCE_HIGH_MEDIUM, 1, regex.I)


# URLs

add_pattern(r'https?://[^\s<>"{}|\\^`\[\]]+', 'URL', CONFIDENCE_MEDIUM)


# Biometric Identifiers (Safe Harbor #16)

add_pattern(r'(?:Fingerprint|Biometric|Retinal?|Iris|Voice(?:print)?|DNA)\s+(?:ID|Sample|Scan|Record|Data)[:\s#]+([A-Z0-9]{6,30})', 'BIOMETRIC_ID', CONFIDENCE_MEDIUM, 1, regex.I)
add_pattern(r'(?:Genetic|Genomic|DNA)\s+(?:Test|Sample|Analysis)\s+(?:ID|#|Number)[:\s]+([A-Z0-9]{6,20})', 'BIOMETRIC_ID', CONFIDENCE_MEDIUM_LOW, 1, regex.I)


# Photographic Image Identifiers (Safe Harbor #17)

add_pattern(r'(?:Photo|Image|Picture|Photograph)\s+(?:ID|File|#)[:\s]+([A-Z0-9_-]{6,30})', 'IMAGE_ID', CONFIDENCE_LOW, 1, regex.I)
add_pattern(r'(?:DICOM|Study|Series|Image)\s+(?:UID|ID)[:\s]+([0-9.]{10,64})', 'IMAGE_ID', CONFIDENCE_RELIABLE, 1, regex.I)


# Username

add_pattern(r'(?:username|user|login|userid)[:\s]+([A-Za-z0-9_.-]{3,30})', 'USERNAME', CONFIDENCE_LOW, 1, regex.I)
# International username labels (FR: nom d'utilisateur, DE: Benutzername, ES: usuario, NL: gebruikersnaam, IT: nome utente, PT: usuario)
add_pattern(r"(?:nom d'utilisateur|benutzername|usuario|gebruikersnaam|nome utente|usu\u00e1rio|utilisateur)[:\s]+([\\w._-]{3,30})", 'USERNAME', CONFIDENCE_LOW, 1, regex.I | regex.UNICODE)
# NOTE: Removed @ mention and greeting patterns - too many false positives
# Login context: "logged in as username", "signed in as username"
# NOTE: Removed "account" - it matches account numbers, not usernames
add_pattern(r'(?:logged\s+in\s+as|signed\s+in\s+as|profile)[:\s]+([A-Za-z0-9_.-]{3,30})', 'USERNAME', CONFIDENCE_MARGINAL, 1, regex.I)


# Password

# English password labels - require colon/equals separator (not just whitespace) to avoid FPs
add_pattern(r'(?:password|passwd|pwd|passcode|pin)\s*[=:]\s*([^\s]{4,50})', 'PASSWORD', CONFIDENCE_MEDIUM, 1, regex.I)
# International password labels (DE: Kennwort/Passwort, FR: mot de passe, ES: contrasena, IT: password, NL: wachtwoord, PT: senha)
add_pattern(r"(?:kennwort|passwort|mot\s+de\s+passe|contrase\u00f1a|wachtwoord|senha|parola\s+d'ordine)[:\s]+([^\s]{4,50})", 'PASSWORD', CONFIDENCE_MEDIUM, 1, regex.I | regex.UNICODE)
# Authentication context: "credentials: password", "secret: xxxxx"
add_pattern(r'(?:credential|secret|auth\s+key|api\s+key|access\s+key|secret\s+key)[:\s]+([^\s]{8,100})', 'PASSWORD', CONFIDENCE_MEDIUM_LOW, 1, regex.I)
# Temp/initial password context
add_pattern(r'(?:temporary|temp|initial|default)\s+(?:password|pwd|passcode)[:\s]+([^\s]{4,50})', 'PASSWORD', CONFIDENCE_RELIABLE, 1, regex.I)
