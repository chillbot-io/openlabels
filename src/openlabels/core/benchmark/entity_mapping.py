"""Entity type mapping between ai4privacy dataset labels and OpenLabels types.

The ai4privacy pii-masking-400k dataset uses its own entity type naming
convention.  This module provides a canonical mapping to OpenLabels entity
types (defined in ``openlabels.core.types``).

Entity types that do not correspond to anything OpenLabels detects are
collected in ``UNMAPPED_TYPES`` and are excluded from scoring.
"""

from __future__ import annotations

# ── ai4privacy label  ->  OpenLabels entity_type ──────────────────────
AI4PRIVACY_TO_OPENLABELS: dict[str, str] = {
    # Names
    "FIRSTNAME": "FIRSTNAME",
    "LASTNAME": "LASTNAME",
    "MIDDLENAME": "MIDDLENAME",
    "PREFIX": "PREFIX",
    "SUFFIX": "SUFFIX",
    "FULLNAME": "NAME",

    # Dates / Time
    "DATE": "DATE",
    "DOB": "DATE_DOB",
    "DATEOFBIRTH": "DATE_DOB",
    "TIME": "TIME",

    # Age
    "AGE": "AGE",

    # Location
    "CITY": "CITY",
    "STATE": "STATE",
    "COUNTY": "COUNTY",
    "COUNTRY": "COUNTRY",
    "ZIPCODE": "ZIP",
    "STREETADDRESS": "ADDRESS",
    "STREET": "ADDRESS",
    "BUILDINGNUMBER": "ADDRESS",
    "SECONDARYADDRESS": "ADDRESS",

    # Contact
    "EMAIL": "EMAIL",
    "PHONENUMBER": "PHONE",
    "URL": "URL",
    "USERNAME": "USERNAME",

    # Government IDs
    "SSN": "SSN",
    "SOCIALSECURITYNUMBER": "SSN",
    "DRIVERSLICENSE": "DRIVER_LICENSE",
    "PASSPORT": "PASSPORT",
    "IDCARD": "STATE_ID",
    "TAXNUMBER": "TAX_ID",
    "NATIONALID": "STATE_ID",
    "UKNINUMBER": "UKNINUMBER",
    "SIN": "SIN",

    # Financial
    "CREDITCARDNUMBER": "CREDIT_CARD",
    "IBAN": "IBAN",
    "BIC": "SWIFT_BIC",
    "ACCOUNTNAME": "ACCOUNT_NUMBER",
    "ACCOUNTNUM": "ACCOUNT_NUMBER",
    "ACCOUNTNUMBER": "ACCOUNT_NUMBER",
    "BITCOINADDRESS": "BITCOIN_ADDRESS",
    "ETHEREUMADDRESS": "ETHEREUM_ADDRESS",
    "LITECOINADDRESS": "LITECOIN_ADDRESS",
    "PIN": "PASSWORD",
    "MASKEDNUMBER": "ACCOUNT_NUMBER",
    "POLICYNUM": "ACCOUNT_NUMBER",

    # Professional
    "COMPANY": "COMPANY",
    "COMPANYNAME": "COMPANY",

    # Network / Device
    "IP": "IP_ADDRESS",
    "IPADDRESS": "IP_ADDRESS",
    "IPV4": "IP_ADDRESS",
    "IPV6": "IP_ADDRESS",
    "IMEI": "IMEI",
    "PHONEIMEI": "IMEI",
    "MACADDRESS": "MAC_ADDRESS",

    # Vehicle
    "VEHICLEVRM": "LICENSE_PLATE",
    "VEHICLEVIN": "VIN",

    # Password / Secret
    "PASSWORD": "PASSWORD",

    # Misc
    "NEARBYGPSCOORDINATE": "GPS_COORDINATE",
}

# Entity types the ai4privacy dataset uses that OpenLabels does not detect
# and should be excluded from evaluation scoring.  These are checked BEFORE
# the mapping dict, so nothing listed here should also appear in the dict.
UNMAPPED_TYPES: frozenset[str] = frozenset({
    # Demographic – not PII in most frameworks
    "GENDER",
    "SEX",
    # Monetary values – not PII
    "AMOUNT",
    "CURRENCY",
    "CURRENCYSYMBOL",
    "CURRENCYCODE",
    "CURRENCYNAME",
    # Credit-card metadata (issuer name, expiry, CVV) – too generic to detect
    "CREDITCARDISSUER",
    "CREDITCARDEXPIRY",
    "CREDITCARDCVV",
    # Job/profession titles – not PII
    "JOBTITLE",
    "JOBTYPE",
    "JOBAREA",
    "JOBTITLE_DESCRIPTOR",
    "JOBDESCRIPTOR",
    # Financial scores / amounts
    "CREDITRATING",
    "CREDRATING",
    "SALARY",
    "BALANCE",
    # Bank brand names
    "BANKNAME",
    # Directional / demographic
    "ORDINALDIRECTION",
    "NATIONALITY",
    # Browser user-agent strings
    "USERAGENT",
    # Physical attributes
    "HEIGHT",
    "WEIGHT",
    "EYECOLOR",
    "HAIRCOLOR",
})

# Coarse grouping for per-category metrics.
# Maps OpenLabels entity types to a human-readable category.
EVAL_CATEGORIES: dict[str, str] = {
    "NAME": "names",
    "FIRSTNAME": "names",
    "LASTNAME": "names",
    "MIDDLENAME": "names",
    "PREFIX": "names",
    "SUFFIX": "names",

    "SSN": "government_ids",
    "DRIVER_LICENSE": "government_ids",
    "PASSPORT": "government_ids",
    "STATE_ID": "government_ids",
    "TAX_ID": "government_ids",
    "UKNINUMBER": "government_ids",
    "SIN": "government_ids",

    "CREDIT_CARD": "financial",
    "IBAN": "financial",
    "SWIFT_BIC": "financial",
    "ACCOUNT_NUMBER": "financial",
    "BITCOIN_ADDRESS": "financial",
    "ETHEREUM_ADDRESS": "financial",
    "LITECOIN_ADDRESS": "financial",

    "EMAIL": "contact",
    "PHONE": "contact",
    "PHONE_EXT": "contact",
    "URL": "contact",
    "USERNAME": "contact",

    "ADDRESS": "locations",
    "CITY": "locations",
    "STATE": "locations",
    "COUNTY": "locations",
    "COUNTRY": "locations",
    "ZIP": "locations",
    "GPS_COORDINATE": "locations",
    "GPS_COORDINATES": "locations",
    "LOCATION_OTHER": "locations",

    "DATE": "dates",
    "DATE_DOB": "dates",
    "TIME": "dates",
    "AGE": "dates",

    "IP_ADDRESS": "network",
    "MAC_ADDRESS": "network",
    "IMEI": "network",

    "VIN": "vehicle",
    "LICENSE_PLATE": "vehicle",

    "PASSWORD": "secrets",

    "JOB_TITLE": "professional",
    "COMPANY": "professional",
}


def map_entity_type(ai4privacy_label: str) -> str | None:
    """Map an ai4privacy label to an OpenLabels entity type.

    Returns ``None`` if the label has no meaningful OpenLabels counterpart
    (i.e. it is in ``UNMAPPED_TYPES``).
    """
    upper = ai4privacy_label.upper().replace(" ", "").replace("-", "")
    if upper in UNMAPPED_TYPES:
        return None
    return AI4PRIVACY_TO_OPENLABELS.get(upper, upper)


def get_eval_category(entity_type: str) -> str:
    """Return the evaluation category for an OpenLabels entity type."""
    return EVAL_CATEGORIES.get(entity_type, "other")
