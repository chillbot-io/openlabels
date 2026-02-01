"""
Label taxonomy for structured documents.

Maps field labels found in documents (DOB:, NAME:, MRN:, etc.)
to PHI entity types. None values indicate recognized non-PHI labels.
"""

import re
from typing import Dict, Optional


# Maps field labels found in documents to PHI entity types
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
SORTED_LABELS = sorted(LABEL_TO_PHI_TYPE.keys(), key=len, reverse=True)


def normalize_label(label: str) -> str:
    """Normalize a label for lookup."""
    # Uppercase
    normalized = label.upper().strip()
    # Remove trailing punctuation
    normalized = re.sub(r'[:\-\s]+$', '', normalized)
    # Collapse internal whitespace
    normalized = re.sub(r'\s+', ' ', normalized)
    return normalized
