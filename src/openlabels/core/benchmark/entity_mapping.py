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
    # Names — bundled 1k uses FIRSTNAME/LASTNAME; HF 400k uses GIVENNAME/SURNAME
    "FIRSTNAME": "FIRSTNAME",
    "GIVENNAME": "FIRSTNAME",
    "LASTNAME": "LASTNAME",
    "SURNAME": "LASTNAME",
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

    # Location — HF 400k uses BUILDINGNUM alongside BUILDINGNUMBER
    "CITY": "CITY",
    "STATE": "STATE",
    "COUNTY": "COUNTY",
    "COUNTRY": "COUNTRY",
    "ZIPCODE": "ZIP",
    "ZIP": "ZIP",
    "STREETADDRESS": "ADDRESS",
    "STREET": "ADDRESS",
    "BUILDINGNUMBER": "ADDRESS",
    "BUILDINGNUM": "ADDRESS",
    "SECONDARYADDRESS": "ADDRESS",

    # Contact — HF 400k uses TELEPHONENUM alongside PHONENUMBER
    "EMAIL": "EMAIL",
    "PHONENUMBER": "PHONE",
    "TELEPHONENUM": "PHONE",
    "URL": "URL",
    "USERNAME": "USERNAME",

    # Government IDs — HF 400k uses SOCIALNUM, DRIVERLICENSENUM, IDCARDNUM, TAXNUM
    "SSN": "SSN",
    "SOCIALSECURITYNUMBER": "SSN",
    "SOCIALNUM": "SSN",
    "DRIVERSLICENSE": "DRIVER_LICENSE",
    "DRIVERLICENSENUM": "DRIVER_LICENSE",
    "PASSPORT": "PASSPORT",
    "PASSPORTNUM": "PASSPORT",       # HF 400k uses PASSPORTNUM
    "IDCARD": "STATE_ID",
    "IDCARDNUM": "STATE_ID",
    "TAXNUMBER": "TAX_ID",
    "TAXNUM": "TAX_ID",
    "NATIONALID": "STATE_ID",
    "UKNINUMBER": "UKNINUMBER",
    "SIN": "SIN",

    # Financial — HF 400k may use CREDITCARDNUM alongside CREDITCARDNUMBER
    "CREDITCARDNUMBER": "CREDIT_CARD",
    "CREDITCARDNUM": "CREDIT_CARD",
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
    "MASKNUM": "ACCOUNT_NUMBER",      # HF 400k short form
    "POLICYNUM": "ACCOUNT_NUMBER",
    "BANK_ROUTING": "BANK_ROUTING",
    "BANKROUTING": "BANK_ROUTING",

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
    "MAC": "MAC_ADDRESS",
    "MACADDRESS": "MAC_ADDRESS",

    # Vehicle
    "VEHICLEVRM": "LICENSE_PLATE",
    "VEHICLEVIN": "VIN",

    # Password / Secret
    "PASSWORD": "PASSWORD",

    # Misc
    "NEARBYGPSCOORDINATE": "GPS_COORDINATE",
}

# Predicted entity types to exclude from scoring.
# When a gold label is unmapped (e.g. JOBTITLE), the corresponding predicted
# OpenLabels type (JOB_TITLE) should also be excluded — otherwise every
# detection counts as a spurious FP even though the benchmark considers
# the underlying text non-PII.
UNMAPPED_PRED_TYPES: frozenset[str] = frozenset({
    "JOB_TITLE",      # Not PII — job titles don't identify individuals
    "COMPANY",        # Not PII — company names don't identify individuals
    "EMPLOYER",       # Not PII — same as COMPANY
    "HEIGHT",         # ai4privacy HEIGHT is in UNMAPPED_TYPES (not scored)
    "WEIGHT",         # ai4privacy WEIGHT is in UNMAPPED_TYPES (not scored)
    "GENDER",         # ai4privacy GENDER is in UNMAPPED_TYPES (not scored)
    "ETHNICITY",      # No gold labels in ai4privacy (pure FP)
    "NATIONALITY",    # ai4privacy NATIONALITY is in UNMAPPED_TYPES (not scored)
    "FACILITY",       # ai4privacy has no FACILITY gold labels
    # Gretel PII 1K analysis: these predicted types have 0 gold labels and
    # generate pure false positives.
    "NAME_PATIENT",   # PHI model type; ai4privacy uses FIRSTNAME/LASTNAME (18 FP)
    "NAME_PROVIDER",  # PHI model type; ai4privacy uses FIRSTNAME/LASTNAME (18 FP)
    "PHONE_EXT",      # No gold labels in ai4privacy/gretel (6 FP)
    "BED_NUMBER",     # No gold labels in ai4privacy/gretel (1 FP)
    # ai4privacy 400k analysis: these predicted types have 0 gold labels
    # and generate pure false positives.
    "UNIQUE_ID",      # No gold labels in ai4privacy 400k (pure FP)
    "TRACKING_NUMBER",  # No gold labels in ai4privacy 400k (pure FP)
})

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
    "NAME_PATIENT": "names",
    "NAME_PROVIDER": "names",
    "NAME_RELATIVE": "names",
    "FIRSTNAME": "names",
    "LASTNAME": "names",
    "MIDDLENAME": "names",
    "PREFIX": "names",
    "SUFFIX": "names",
    "PERSON": "names",
    "PATIENT": "names",
    "FULLNAME": "names",

    "SSN": "government_ids",
    "DRIVER_LICENSE": "government_ids",
    "PASSPORT": "government_ids",
    "STATE_ID": "government_ids",
    "TAX_ID": "government_ids",
    "UKNINUMBER": "government_ids",
    "UK_NINO": "government_ids",
    "NHS_NUMBER": "government_ids",
    "ITIN": "government_ids",
    "EIN": "government_ids",
    "IN_PAN": "government_ids",
    "SG_NRIC_FIN": "government_ids",
    "ES_NIE": "government_ids",
    "ES_NIF": "government_ids",
    "PL_PESEL": "government_ids",
    "FI_HETU": "government_ids",
    "IT_FISCAL_CODE": "government_ids",
    "IT_VAT": "government_ids",
    "KR_RRN": "government_ids",
    "TH_TNIN": "government_ids",
    "IN_GSTIN": "government_ids",
    "IN_VOTER": "government_ids",
    "AADHAAR": "government_ids",
    "TFN": "government_ids",
    "SIN": "government_ids",
    "MRN": "government_ids",
    "NPI": "government_ids",
    "DEA": "government_ids",
    "MEDICAL_LICENSE": "government_ids",
    "CURP": "government_ids",
    "SVNR": "government_ids",
    "DOD_CONTRACT": "government_ids",
    "CERTIFICATE_NUMBER": "government_ids",
    "UNIQUE_ID": "government_ids",
    "ENCOUNTER_ID": "government_ids",
    "ACCESSION_ID": "government_ids",
    "CAGE_CODE": "government_ids",
    "UEI": "government_ids",
    "DUNS_NUMBER": "government_ids",
    "GSA_CONTRACT": "government_ids",
    "CLASSIFICATION_LEVEL": "government_ids",
    "CLASSIFICATION_MARKING": "government_ids",
    "SCI_MARKING": "government_ids",
    "DISSEMINATION_CONTROL": "government_ids",
    "CLEARANCE_LEVEL": "government_ids",
    "ITAR_MARKING": "government_ids",
    "EAR_MARKING": "government_ids",

    "CREDIT_CARD": "financial",
    "IBAN": "financial",
    "SWIFT_BIC": "financial",
    "ACCOUNT_NUMBER": "financial",
    "HEALTH_PLAN_ID": "financial",
    "MEMBER_ID": "financial",
    "CLAIM_NUMBER": "financial",
    "AUTH_NUMBER": "financial",
    "BANK_ROUTING": "financial",
    "ABA_ROUTING": "financial",
    "RX_NUMBER": "financial",
    "BITCOIN_ADDRESS": "financial",
    "ETHEREUM_ADDRESS": "financial",
    "LITECOIN_ADDRESS": "financial",
    "SOLANA_ADDRESS": "financial",
    "MONERO_ADDRESS": "financial",
    "POLKADOT_ADDRESS": "financial",
    "CARDANO_ADDRESS": "financial",
    "DOGECOIN_ADDRESS": "financial",
    "XRP_ADDRESS": "financial",
    "CRYPTO_SEED_PHRASE": "financial",
    "CUSIP": "financial",
    "ISIN": "financial",
    "SEDOL": "financial",
    "FIGI": "financial",
    "LEI": "financial",

    "EMAIL": "contact",
    "PHONE": "contact",
    "PHONE_HOME": "contact",
    "PHONE_MOBILE": "contact",
    "PHONE_WORK": "contact",
    "FAX": "contact",
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
    "ROOM": "locations",
    "ROOM_NUMBER": "locations",
    "BED_NUMBER": "locations",

    "DATE": "dates",
    "DATE_DOB": "dates",
    "DATETIME": "dates",
    "TIME": "dates",
    "AGE": "dates",

    "IP_ADDRESS": "network",
    "MAC_ADDRESS": "network",
    "IMEI": "network",
    "DEVICE_ID": "network",
    "BIOMETRIC_ID": "network",
    "IMAGE_ID": "network",

    "VIN": "vehicle",
    "LICENSE_PLATE": "vehicle",

    "PASSWORD": "secrets",
    "API_KEY": "secrets",
    "SECRET": "secrets",
    "PRIVATE_KEY": "secrets",
    "JWT": "secrets",
    "BEARER_TOKEN": "secrets",
    "BASIC_AUTH": "secrets",
    "DATABASE_URL": "secrets",
    "AWS_ACCESS_KEY": "secrets",
    "AWS_SECRET_KEY": "secrets",
    "GITHUB_TOKEN": "secrets",
    "GITLAB_TOKEN": "secrets",
    "SLACK_TOKEN": "secrets",
    "SLACK_WEBHOOK": "secrets",
    "STRIPE_KEY": "secrets",
    "GOOGLE_API_KEY": "secrets",
    "GOOGLE_OAUTH_TOKEN": "secrets",
    "DISCORD_TOKEN": "secrets",
    "VAULT_TOKEN": "secrets",
    "ATLASSIAN_TOKEN": "secrets",
    "OPENAI_KEY": "secrets",
    "ANTHROPIC_KEY": "secrets",

    "JOB_TITLE": "professional",
    "COMPANY": "professional",
    "EMPLOYER": "professional",
    "FACILITY": "professional",
    "EMPLOYEE_ID": "professional",
    "PHARMACY_ID": "professional",

    "GENDER": "demographics",
    "ETHNICITY": "demographics",
    "NATIONALITY": "demographics",
    "HEIGHT": "demographics",
    "WEIGHT": "demographics",
}


import logging as _logging

_logger = _logging.getLogger(__name__)

# Track labels that fall through the mapping (not explicitly mapped, not
# unmapped).  These are returned as-is and almost always indicate a missing
# entry in AI4PRIVACY_TO_OPENLABELS — the detector pipeline never produces
# them, so they create guaranteed false negatives.
_warned_passthrough: set[str] = set()


def map_entity_type(ai4privacy_label: str) -> str | None:
    """Map an ai4privacy label to an OpenLabels entity type.

    Returns ``None`` if the label has no meaningful OpenLabels counterpart
    (i.e. it is in ``UNMAPPED_TYPES``).

    Labels that are neither in the mapping dict nor in UNMAPPED_TYPES are
    returned as-is (uppercased) and a warning is logged once per label.
    These passthrough labels almost always indicate a gap in the mapping
    that needs to be fixed — they become gold spans with entity types that
    no detector ever produces, causing guaranteed false negatives.
    """
    upper = ai4privacy_label.upper().replace(" ", "").replace("-", "")
    if upper in UNMAPPED_TYPES:
        return None
    mapped = AI4PRIVACY_TO_OPENLABELS.get(upper)
    if mapped is not None:
        return mapped
    # Label is not in the mapping dict.  Return as-is but warn — this is
    # almost certainly a bug that creates phantom gold entities.
    if upper and upper not in _warned_passthrough:
        _warned_passthrough.add(upper)
        _logger.warning(
            "ai4privacy label %r is not in AI4PRIVACY_TO_OPENLABELS and not "
            "in UNMAPPED_TYPES — passing through as %r.  This likely creates "
            "false negatives.  Add it to the mapping or to UNMAPPED_TYPES.",
            ai4privacy_label,
            upper,
        )
    return upper


def get_eval_category(entity_type: str) -> str:
    """Return the evaluation category for an OpenLabels entity type."""
    return EVAL_CATEGORIES.get(entity_type, "other")


def audit_labels(
    labels: list[str],
) -> dict[str, list[str]]:
    """Audit a list of ai4privacy labels for mapping coverage.

    Returns a dict with keys:
    - ``"mapped"``: Labels correctly mapped to OpenLabels types.
    - ``"unmapped"``: Labels explicitly excluded from scoring.
    - ``"passthrough"``: Labels NOT in the mapping — these create
      guaranteed false negatives and need to be added.

    Run this on the unique labels from your dataset to find gaps::

        >>> from collections import Counter
        >>> raw_labels = [ann["label"] for sample in dataset for ann in sample["privacy_mask"]]
        >>> report = audit_labels(list(set(raw_labels)))
        >>> print("NEEDS FIXING:", report["passthrough"])
    """
    mapped: list[str] = []
    unmapped: list[str] = []
    passthrough: list[str] = []

    for label in labels:
        upper = label.upper().replace(" ", "").replace("-", "")
        if upper in UNMAPPED_TYPES:
            unmapped.append(label)
        elif upper in AI4PRIVACY_TO_OPENLABELS:
            mapped.append(label)
        else:
            passthrough.append(label)

    return {
        "mapped": sorted(mapped),
        "unmapped": sorted(unmapped),
        "passthrough": sorted(passthrough),
    }
