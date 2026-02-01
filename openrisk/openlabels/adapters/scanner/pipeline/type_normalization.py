"""
Entity type normalization and compatibility.

Maps detector-specific entity labels to canonical OpenLabels types.
Handles compatibility checks for deduplication.
"""

from typing import Dict, List, Set


# Groups of entity types that are semantically equivalent for dedup purposes
COMPATIBLE_TYPE_GROUPS: List[Set[str]] = [
    {"NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE", "NAME_FAMILY"},
    {"ADDRESS", "STREET", "STREET_ADDRESS", "CITY", "STATE", "ZIP", "LOCATION"},
    {"DATE", "DOB", "DATE_DOB", "DATE_ADMISSION", "DATE_DISCHARGE"},
    {"PHONE", "FAX", "PHONE_MOBILE", "PHONE_HOME", "PHONE_WORK"},
    {"SSN", "SSN_PARTIAL"},
    {"MRN", "PATIENT_ID", "MEDICAL_RECORD"},
    {"HEALTH_PLAN_ID", "MEMBER_ID", "INSURANCE_ID"},
    {"EMPLOYER", "ORGANIZATION", "COMPANY", "COMPANYNAME"},
]

# Precompute type -> group_id mapping for O(1) compatibility checks
_TYPE_TO_GROUP: Dict[str, int] = {}
for _group_id, _group in enumerate(COMPATIBLE_TYPE_GROUPS):
    for _entity_type in _group:
        _TYPE_TO_GROUP[_entity_type] = _group_id


def types_compatible(t1: str, t2: str) -> bool:
    """
    Check if two entity types are semantically compatible for dedup.

    Uses precomputed group mapping for O(1) lookup instead of O(g) iteration.
    """
    if t1 == t2:
        return True
    # Check prefix match (NAME matches NAME_PATIENT)
    if t1.startswith(t2) or t2.startswith(t1):
        return True
    # O(1) group compatibility check
    g1 = _TYPE_TO_GROUP.get(t1)
    g2 = _TYPE_TO_GROUP.get(t2)
    return g1 is not None and g1 == g2


# Type normalization map - different detectors emit different labels
# Sources: i2b2 2014, AI4Privacy, Stanford PHI-BERT, custom PII-BERT
TYPE_NORMALIZE: Dict[str, str] = {
    # === NAMES ===
    "PERSON": "NAME",
    "PER": "NAME",
    "PATIENT": "NAME_PATIENT",
    "DOCTOR": "NAME_PROVIDER",
    "PHYSICIAN": "NAME_PROVIDER",
    "NURSE": "NAME_PROVIDER",
    "STAFF": "NAME_PROVIDER",
    "HCW": "NAME_PROVIDER",  # Healthcare Worker (Stanford PHI-BERT)
    "RELATIVE": "NAME_RELATIVE",
    "FAMILY": "NAME_RELATIVE",
    # AI4Privacy name components
    "FIRSTNAME": "NAME",
    "LASTNAME": "NAME",
    "MIDDLENAME": "NAME",
    "PREFIX": "NAME",
    "SUFFIX": "NAME",
    "FULLNAME": "NAME",
    # i2b2 specific
    "USERNAME": "USERNAME",

    # === LOCATIONS ===
    "GPE": "ADDRESS",
    "LOC": "ADDRESS",
    "STREET_ADDRESS": "ADDRESS",
    "STREET": "ADDRESS",
    "CITY": "ADDRESS",
    "STATE": "ADDRESS",
    "COUNTRY": "ADDRESS",
    "COUNTY": "ADDRESS",
    "LOCATION-OTHER": "ADDRESS",
    "LOCATION_OTHER": "ADDRESS",
    "SECONDARYADDRESS": "ADDRESS",  # AI4Privacy - apt/suite/unit
    "BUILDINGNUMBER": "ADDRESS",    # AI4Privacy
    "ZIPCODE": "ADDRESS",
    "LOCATION_ZIP": "ADDRESS",
    "ZIP_CODE": "ADDRESS",
    "ZIP": "ADDRESS",
    "POSTCODE": "ADDRESS",
    "GPS": "GPS_COORDINATE",
    "COORDINATE": "GPS_COORDINATE",
    "COORDINATES": "GPS_COORDINATE",
    "LATITUDE": "GPS_COORDINATE",
    "LONGITUDE": "GPS_COORDINATE",
    "NEARBYGPSCOORDINATE": "GPS_COORDINATE",  # AI4Privacy

    # === IDENTIFIERS ===
    "ID": "MRN",  # Stanford PHI-BERT generic ID label
    "US_SSN": "SSN",
    "SOCIAL_SECURITY": "SSN",
    "SOCIALSECURITYNUMBER": "SSN",
    "SSN_PARTIAL": "SSN",
    "UKNINUMBER": "SSN",  # UK National Insurance - treat as SSN equivalent
    "MEDICAL_RECORD": "MRN",
    "MEDICALRECORD": "MRN",
    "HEALTHPLAN": "HEALTH_PLAN_ID",
    "HEALTH_PLAN": "HEALTH_PLAN_ID",
    "MEMBERID": "HEALTH_PLAN_ID",
    "MEMBER_ID": "HEALTH_PLAN_ID",
    # Financial
    "CREDIT_CARD_NUMBER": "CREDIT_CARD",
    "CREDITCARDNUMBER": "CREDIT_CARD",
    "CREDITCARD": "CREDIT_CARD",
    "CC": "CREDIT_CARD",
    "IBAN_CODE": "IBAN",
    "IBANCODE": "IBAN",
    "ACCOUNTNUMBER": "ACCOUNT_NUMBER",
    "BANK_ACCOUNT": "ACCOUNT_NUMBER",
    "BITCOINADDRESS": "ACCOUNT_NUMBER",
    "LITECOINADDRESS": "ACCOUNT_NUMBER",  # AI4Privacy
    "ETHEREUMADDRESS": "ACCOUNT_NUMBER",  # AI4Privacy
    "BIC": "ACCOUNT_NUMBER",
    "SWIFT": "ACCOUNT_NUMBER",
    "ROUTING": "ABA_ROUTING",
    "ROUTING_NUMBER": "ABA_ROUTING",
    "BANK_ROUTING": "ABA_ROUTING",
    # Licenses
    "US_DRIVER_LICENSE": "DRIVER_LICENSE",
    "DRIVER_LICENSE_NUMBER": "DRIVER_LICENSE",
    "DRIVERSLICENSE": "DRIVER_LICENSE",
    "LICENSE": "DRIVER_LICENSE",
    "US_PASSPORT": "PASSPORT",
    "PASSPORT_NUMBER": "PASSPORT",
    "PASSPORTNUMBER": "PASSPORT",
    "ACCOUNT": "ACCOUNT_NUMBER",
    # Provider identifiers
    "NATIONAL_PROVIDER_IDENTIFIER": "NPI",
    "PROVIDER_NPI": "NPI",
    "DEA_NUMBER": "DEA",
    "PRESCRIBER_DEA": "DEA",

    # === CONTACT ===
    "PHONE_NUMBER": "PHONE",
    "PHONENUMBER": "PHONE",
    "US_PHONE_NUMBER": "PHONE",
    "TELEPHONE": "PHONE",
    "TEL": "PHONE",
    "MOBILE": "PHONE",
    "CELL": "PHONE",
    "EMAIL_ADDRESS": "EMAIL",
    "EMAILADDRESS": "EMAIL",
    "FAX_NUMBER": "FAX",
    "FAXNUMBER": "FAX",
    "PAGER": "PHONE",
    "PAGER_NUMBER": "PHONE",

    # === NETWORK/DEVICE ===
    "IP": "IP_ADDRESS",
    "IPADDRESS": "IP_ADDRESS",
    "IPV4": "IP_ADDRESS",
    "IPV6": "IP_ADDRESS",
    "MAC": "MAC_ADDRESS",
    "MACADDRESS": "MAC_ADDRESS",
    "IMEI": "DEVICE_ID",
    "DEVICE": "DEVICE_ID",
    "BIOID": "DEVICE_ID",
    "USERAGENT": "DEVICE_ID",
    "USER_AGENT": "DEVICE_ID",
    "PHONEIMEI": "DEVICE_ID",  # AI4Privacy

    # === DATES ===
    "DATE_TIME": "DATE",
    "DATETIME": "DATE",
    "TIME": "DATE",
    "BIRTHDAY": "DATE_DOB",
    "DOB": "DATE_DOB",
    "DATEOFBIRTH": "DATE_DOB",
    "DATE_OF_BIRTH": "DATE_DOB",
    "BIRTH_DATE": "DATE_DOB",
    "BIRTHDATE": "DATE_DOB",
    "BIRTH_YEAR": "BIRTH_YEAR",
    "YEAR_OF_BIRTH": "BIRTH_YEAR",

    # === VEHICLES ===
    "VEHICLEVIN": "VIN",
    "VEHICLE_VIN": "VIN",
    "VEHICLE_IDENTIFICATION": "VIN",
    "VEHICLEVRM": "LICENSE_PLATE",
    "VEHICLE_PLATE": "LICENSE_PLATE",
    "PLATE_NUMBER": "LICENSE_PLATE",
    "VEHICLE": "VIN",

    # === PROFESSIONAL (i2b2) ===
    "PROFESSION": "PROFESSION",
    "OCCUPATION": "PROFESSION",
    "JOB": "PROFESSION",
    "JOB_TITLE": "PROFESSION",
    "JOBTITLE": "PROFESSION",
    "JOBAREA": "PROFESSION",    # AI4Privacy
    "JOBTYPE": "PROFESSION",    # AI4Privacy

    # === EMPLOYER (companies/organizations) ===
    "COMPANYNAME": "EMPLOYER",
    "COMPANY": "EMPLOYER",
    "ORG": "EMPLOYER",
    "ORGANIZATION": "EMPLOYER",

    # === CLINICAL (context-only, filtered before output) ===
    "HOSPITAL": "FACILITY",
    "VENDOR": "FACILITY",

    # === MEDICATION ===
    "DRUG": "MEDICATION",
    "MEDICINE": "MEDICATION",
    "RX": "MEDICATION",
}


def normalize_type(entity_type: str) -> str:
    """Normalize entity type to canonical form."""
    return TYPE_NORMALIZE.get(entity_type, entity_type)
