"""Canonical label mappings for ML detectors.

Maps model output labels to OpenLabels entity type taxonomy.
Used by both PyTorch (ml.py) and ONNX (ml_onnx.py) detectors.
"""

from typing import Dict

# Stanford PHI-BERT label mappings
# Model outputs: PATIENT, DATE, PHONE, HCW, VENDOR, MRN, AGE, etc.
PHI_BERT_LABELS: Dict[str, str] = {
    # Names
    "PATIENT": "NAME_PATIENT",
    "HCW": "NAME_PROVIDER",  # Healthcare Worker
    "NAME": "NAME",
    # Dates
    "DATE": "DATE",
    "AGE": "AGE",
    # Identifiers
    "ID": "MRN",
    "MRN": "MRN",
    "PHONE": "PHONE",
    # Context-only (will be filtered)
    "VENDOR": "FACILITY",
}

# Custom PII-BERT label mappings (AI4Privacy trained)
# Uses BIO tagging scheme: B- = beginning, I- = inside
PII_BERT_LABELS: Dict[str, str] = {
    # Names
    "B-NAME": "NAME",
    "I-NAME": "NAME",
    # Dates
    "B-DOB": "DATE_DOB",
    "I-DOB": "DATE_DOB",
    # Identifiers
    "B-SSN": "SSN",
    "I-SSN": "SSN",
    "B-LICENSE": "DRIVER_LICENSE",
    "I-LICENSE": "DRIVER_LICENSE",
    "B-PASSPORT": "PASSPORT",
    "I-PASSPORT": "PASSPORT",
    "B-VIN": "VIN",
    "I-VIN": "VIN",
    # Contact
    "B-PHONE": "PHONE",
    "I-PHONE": "PHONE",
    "B-EMAIL": "EMAIL",
    "I-EMAIL": "EMAIL",
    "B-URL": "URL",
    "I-URL": "URL",
    "B-IP": "IP_ADDRESS",
    "I-IP": "IP_ADDRESS",
    "B-MAC": "MAC_ADDRESS",
    "I-MAC": "MAC_ADDRESS",
    # Location
    "B-ADDRESS": "ADDRESS",
    "I-ADDRESS": "ADDRESS",
    # Financial
    "B-CREDIT_CARD": "CREDIT_CARD",
    "I-CREDIT_CARD": "CREDIT_CARD",
    "B-ACCOUNT": "ACCOUNT_NUMBER",
    "I-ACCOUNT": "ACCOUNT_NUMBER",
    "B-IBAN": "IBAN",
    "I-IBAN": "IBAN",
}
