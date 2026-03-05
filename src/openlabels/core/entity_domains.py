"""
Unified Entity Domain Taxonomy.

Single source of truth for entity type classification. Every entity type gets
one or more semantic domain tags from a fixed vocabulary. Domain compositions
map to compliance frameworks, replacing the disjoint category systems in
scorer.py, gliner_label_selector.py, and loader.py.

Usage::

    from openlabels.core.entity_domains import (
        EntityDomain,
        get_domains,
        get_all_domains,
        evaluate_compositions,
        get_compliance_frameworks,
        get_max_score_multiplier,
    )

    # Single entity lookup
    domains = get_domains("MRN")  # frozenset({IDENTIFIER, MEDICAL})

    # Batch evaluation
    entities = {"MRN": 3, "NAME": 5, "PHONE": 2, "DIAGNOSIS": 4}
    compositions = evaluate_compositions(entities)
    multiplier, rules = get_max_score_multiplier(entities)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .policies.schema import PolicyCategory, RiskLevel
from .types import normalize_entity_type

__all__ = [
    "EntityDomain",
    "ComplianceComposition",
    "ENTITY_DOMAIN_REGISTRY",
    "COMPLIANCE_COMPOSITIONS",
    "get_domains",
    "get_all_domains",
    "evaluate_compositions",
    "get_compliance_frameworks",
    "get_max_score_multiplier",
]


# ---------------------------------------------------------------------------
# Domain enum
# ---------------------------------------------------------------------------

class EntityDomain(str, Enum):
    """Semantic domains an entity type can belong to."""

    IDENTIFIER = "identifier"       # Uniquely identifies a person/entity
    MEDICAL = "medical"             # Healthcare/clinical context
    FINANCIAL = "financial"         # Banking, payments, securities
    CREDENTIAL = "credential"       # Secrets, tokens, passwords
    CONTACT = "contact"             # Communication endpoints
    LOCATION = "location"           # Geographic information
    TEMPORAL = "temporal"           # Dates, times, ages
    BIOMETRIC = "biometric"         # Physical/behavioral characteristics
    GOVERNMENT = "government"       # Government-issued identifiers
    CLASSIFICATION = "classification"  # Security markings & clearances
    VEHICLE = "vehicle"             # Vehicle identifiers
    PROFESSIONAL = "professional"   # Employment/organizational
    NETWORK = "network"             # Digital infrastructure (IPs, MACs)
    DEMOGRAPHIC = "demographic"     # Gender, ethnicity, nationality


# ---------------------------------------------------------------------------
# Entity → Domain registry
# ---------------------------------------------------------------------------

_ID = EntityDomain.IDENTIFIER
_MED = EntityDomain.MEDICAL
_FIN = EntityDomain.FINANCIAL
_CRED = EntityDomain.CREDENTIAL
_CON = EntityDomain.CONTACT
_LOC = EntityDomain.LOCATION
_TMP = EntityDomain.TEMPORAL
_BIO = EntityDomain.BIOMETRIC
_GOV = EntityDomain.GOVERNMENT
_CLS = EntityDomain.CLASSIFICATION
_VEH = EntityDomain.VEHICLE
_PRO = EntityDomain.PROFESSIONAL
_NET = EntityDomain.NETWORK
_DEM = EntityDomain.DEMOGRAPHIC

ENTITY_DOMAIN_REGISTRY: dict[str, frozenset[EntityDomain]] = {
    # --- Names ---
    "NAME":            frozenset({_ID}),
    "FIRSTNAME":       frozenset({_ID}),
    "LASTNAME":        frozenset({_ID}),
    "MIDDLENAME":      frozenset({_ID}),
    "PREFIX":          frozenset({_ID}),
    "SUFFIX":          frozenset({_ID}),
    "FULLNAME":        frozenset({_ID}),
    "NAME_PATIENT":    frozenset({_ID, _MED}),
    "NAME_PROVIDER":   frozenset({_ID, _MED}),
    "NAME_RELATIVE":   frozenset({_ID}),

    # --- Government IDs ---
    "SSN":             frozenset({_ID, _GOV}),
    "SSN_PARTIAL":     frozenset({_ID, _GOV}),
    "PASSPORT":        frozenset({_ID, _GOV}),
    "DRIVER_LICENSE":  frozenset({_ID, _GOV}),
    "STATE_ID":        frozenset({_ID, _GOV}),
    "MILITARY_ID":     frozenset({_ID, _GOV}),
    "TAX_ID":          frozenset({_ID, _GOV}),
    "ITIN":            frozenset({_ID, _GOV}),
    "EIN":             frozenset({_ID, _GOV}),

    # --- International Government IDs ---
    "UK_NINO":         frozenset({_ID, _GOV}),
    "NHS_NUMBER":      frozenset({_ID, _GOV, _MED}),
    "IN_PAN":          frozenset({_ID, _GOV}),
    "SG_NRIC_FIN":     frozenset({_ID, _GOV}),
    "ES_NIE":          frozenset({_ID, _GOV}),
    "ES_NIF":          frozenset({_ID, _GOV}),
    "PL_PESEL":        frozenset({_ID, _GOV}),
    "FI_HETU":         frozenset({_ID, _GOV}),
    "IT_FISCAL_CODE":  frozenset({_ID, _GOV}),
    "KR_RRN":          frozenset({_ID, _GOV}),
    "TH_TNIN":         frozenset({_ID, _GOV}),
    "IN_GSTIN":        frozenset({_ID, _GOV, _FIN}),
    "IN_VOTER":        frozenset({_ID, _GOV}),
    "IT_VAT":          frozenset({_ID, _GOV, _FIN}),
    "FR_NIR":          frozenset({_ID, _GOV}),
    "FR_SIRET":        frozenset({_ID, _GOV, _FIN}),
    "DE_STEUER_ID":    frozenset({_ID, _GOV}),
    "DE_PERSONALAUSWEIS": frozenset({_ID, _GOV}),
    "NL_BSN":          frozenset({_ID, _GOV}),
    "PT_NIF":          frozenset({_ID, _GOV}),
    "PT_CC":           frozenset({_ID, _GOV}),
    "BR_CPF":          frozenset({_ID, _GOV}),
    "BR_CNPJ":         frozenset({_ID, _GOV, _FIN}),
    "EL_AMKA":         frozenset({_ID, _GOV}),
    "EL_AFM":          frozenset({_ID, _GOV}),
    "SI_EMSO":         frozenset({_ID, _GOV}),
    "SI_DAVCNA":       frozenset({_ID, _GOV}),
    "SIN":             frozenset({_ID, _GOV}),
    "SIN_CA":          frozenset({_ID, _GOV}),
    "AADHAAR":         frozenset({_ID, _GOV}),
    "TFN":             frozenset({_ID, _GOV}),
    "CURP":            frozenset({_ID, _GOV}),
    "SVNR":            frozenset({_ID, _GOV}),

    # --- Medical IDs ---
    "MRN":             frozenset({_ID, _MED}),
    "NPI":             frozenset({_ID, _MED}),
    "DEA":             frozenset({_ID, _MED}),
    "MEDICAL_LICENSE":       frozenset({_ID, _MED}),
    "HEALTH_PLAN_ID":        frozenset({_ID, _MED}),
    "MEDICARE_ID":           frozenset({_ID, _MED}),
    "ENCOUNTER_ID":          frozenset({_ID, _MED}),
    "ACCESSION_ID":          frozenset({_ID, _MED}),
    "PHARMACY_ID":           frozenset({_ID, _MED}),
    "NDC":                   frozenset({_MED}),
    "MBI":                   frozenset({_ID, _MED}),

    # --- Medical context (analytics only, not redacted) ---
    "DIAGNOSIS":       frozenset({_MED}),
    "MEDICATION":      frozenset({_MED}),
    "LAB_TEST":        frozenset({_MED}),
    "PROCEDURE":       frozenset({_MED}),
    "DRUG":            frozenset({_MED}),
    "PAYER":           frozenset({_MED}),
    "PRESCRIPTION":    frozenset({_MED}),
    "RX_NUMBER":       frozenset({_MED, _ID}),
    "BLOOD_TYPE":      frozenset({_MED, _BIO}),
    "BMI":             frozenset({_MED, _BIO}),
    "AUTH_NUMBER":     frozenset({_ID, _MED}),

    # --- Financial (Traditional) ---
    "CREDIT_CARD":     frozenset({_FIN, _ID}),
    "CREDIT_CARD_PARTIAL": frozenset({_FIN}),
    "ACCOUNT_NUMBER":  frozenset({_FIN, _ID}),
    "IBAN":            frozenset({_FIN, _ID}),
    "SWIFT_BIC":       frozenset({_FIN}),
    "BANK_ROUTING":    frozenset({_FIN}),

    # --- Financial (Securities) ---
    "CUSIP":           frozenset({_FIN}),
    "ISIN":            frozenset({_FIN}),
    "SEDOL":           frozenset({_FIN}),
    "FIGI":            frozenset({_FIN}),
    "LEI":             frozenset({_FIN, _ID}),

    # --- Cryptocurrency ---
    "BITCOIN_ADDRESS":   frozenset({_FIN, _ID}),
    "ETHEREUM_ADDRESS":  frozenset({_FIN, _ID}),
    "SOLANA_ADDRESS":    frozenset({_FIN, _ID}),
    "MONERO_ADDRESS":    frozenset({_FIN, _ID}),
    "CARDANO_ADDRESS":   frozenset({_FIN, _ID}),
    "LITECOIN_ADDRESS":  frozenset({_FIN, _ID}),
    "DOGECOIN_ADDRESS":  frozenset({_FIN, _ID}),
    "XRP_ADDRESS":       frozenset({_FIN, _ID}),
    "POLKADOT_ADDRESS":  frozenset({_FIN, _ID}),
    "CRYPTO_SEED_PHRASE": frozenset({_FIN, _CRED}),

    # --- Credentials & Secrets (Cloud) ---
    "AWS_ACCESS_KEY":    frozenset({_CRED}),
    "AWS_SECRET_KEY":    frozenset({_CRED}),
    "AWS_SESSION_TOKEN": frozenset({_CRED}),
    "AZURE_STORAGE_KEY": frozenset({_CRED}),
    "AZURE_CONNECTION_STRING": frozenset({_CRED}),
    "AZURE_SAS_TOKEN":   frozenset({_CRED}),
    "GOOGLE_API_KEY":    frozenset({_CRED}),
    "GOOGLE_OAUTH_ID":   frozenset({_CRED}),
    "GOOGLE_OAUTH_SECRET": frozenset({_CRED}),
    "GOOGLE_OAUTH_TOKEN": frozenset({_CRED}),
    "FIREBASE_KEY":      frozenset({_CRED}),

    # --- Credentials & Secrets (Code repos) ---
    "GITHUB_TOKEN":    frozenset({_CRED}),
    "GITLAB_TOKEN":    frozenset({_CRED}),
    "NPM_TOKEN":       frozenset({_CRED}),
    "PYPI_TOKEN":      frozenset({_CRED}),
    "NUGET_KEY":       frozenset({_CRED}),

    # --- Credentials & Secrets (Communication) ---
    "SLACK_TOKEN":     frozenset({_CRED}),
    "SLACK_WEBHOOK":   frozenset({_CRED}),
    "DISCORD_TOKEN":   frozenset({_CRED}),
    "DISCORD_WEBHOOK": frozenset({_CRED}),
    "TWILIO_ACCOUNT_SID": frozenset({_CRED}),
    "TWILIO_KEY":      frozenset({_CRED}),
    "TWILIO_TOKEN":    frozenset({_CRED}),
    "SENDGRID_KEY":    frozenset({_CRED}),
    "MAILCHIMP_KEY":   frozenset({_CRED}),

    # --- Credentials & Secrets (Payment) ---
    "STRIPE_KEY":      frozenset({_CRED, _FIN}),
    "SQUARE_TOKEN":    frozenset({_CRED, _FIN}),
    "SQUARE_SECRET":   frozenset({_CRED, _FIN}),
    "SHOPIFY_TOKEN":   frozenset({_CRED}),
    "SHOPIFY_KEY":     frozenset({_CRED}),
    "SHOPIFY_SECRET":  frozenset({_CRED}),

    # --- Credentials & Secrets (Infra/DevOps) ---
    "HEROKU_KEY":      frozenset({_CRED}),
    "DATADOG_KEY":     frozenset({_CRED}),
    "NEWRELIC_KEY":    frozenset({_CRED}),
    "DATABASE_URL":    frozenset({_CRED}),
    "VAULT_TOKEN":     frozenset({_CRED}),
    "ATLASSIAN_TOKEN": frozenset({_CRED}),
    "GRAFANA_KEY":     frozenset({_CRED}),
    "LINEAR_KEY":      frozenset({_CRED}),
    "DOPPLER_TOKEN":   frozenset({_CRED}),
    "OPENAI_KEY":      frozenset({_CRED}),
    "ANTHROPIC_KEY":   frozenset({_CRED}),
    "VERCEL_TOKEN":    frozenset({_CRED}),
    "SUPABASE_KEY":    frozenset({_CRED}),
    "PLANETSCALE_TOKEN": frozenset({_CRED}),

    # --- Credentials & Secrets (Auth) ---
    "PASSWORD":        frozenset({_CRED}),
    "API_KEY":         frozenset({_CRED}),
    "SECRET":          frozenset({_CRED}),
    "PRIVATE_KEY":     frozenset({_CRED}),
    "JWT":             frozenset({_CRED}),
    "BASIC_AUTH":      frozenset({_CRED}),
    "BEARER_TOKEN":    frozenset({_CRED}),

    # --- Contact ---
    "PHONE":           frozenset({_CON}),
    "PHONE_EXT":       frozenset({_CON}),
    "EMAIL":           frozenset({_CON}),
    "FAX":             frozenset({_CON}),
    "PAGER":           frozenset({_CON}),
    "URL":             frozenset({_CON}),
    "USERNAME":        frozenset({_CON, _ID}),

    # --- Locations ---
    "ADDRESS":         frozenset({_LOC, _CON}),
    "CITY":            frozenset({_LOC}),
    "STATE":           frozenset({_LOC}),
    "ZIP":             frozenset({_LOC}),
    "COUNTRY":         frozenset({_LOC}),
    "COUNTY":          frozenset({_LOC}),
    "GPS_COORDINATE":  frozenset({_LOC}),
    "ROOM":            frozenset({_LOC}),
    "BED_NUMBER":      frozenset({_LOC}),
    "LOCATION_OTHER":  frozenset({_LOC}),

    # --- Temporal ---
    "DATE":            frozenset({_TMP}),
    "DATE_DOB":        frozenset({_TMP, _ID}),
    "DATETIME":        frozenset({_TMP}),
    "TIME":            frozenset({_TMP}),
    "AGE":             frozenset({_TMP, _DEM}),
    "DATE_RANGE":      frozenset({_TMP}),
    "BIRTH_YEAR":      frozenset({_TMP, _ID}),

    # --- Network & Device ---
    "IP_ADDRESS":      frozenset({_NET}),
    "MAC_ADDRESS":     frozenset({_NET}),
    "DEVICE_ID":       frozenset({_NET, _ID}),
    "IMEI":            frozenset({_NET, _ID}),
    "BIOMETRIC_ID":    frozenset({_BIO, _ID}),
    "FINGERPRINT":     frozenset({_BIO, _ID}),
    "DNA_ID":          frozenset({_BIO, _ID}),
    "IMAGE_ID":        frozenset({_BIO, _ID}),
    "PHOTO_ID":        frozenset({_BIO, _ID}),
    "DICOM_UID":       frozenset({_MED, _NET}),
    "CERTIFICATE_NUMBER": frozenset({_ID}),
    "CLAIM_NUMBER":    frozenset({_ID}),

    # --- Vehicle ---
    "VIN":             frozenset({_VEH, _ID}),
    "LICENSE_PLATE":   frozenset({_VEH, _ID}),

    # --- Professional/Organizational ---
    "COMPANY":         frozenset({_PRO}),
    "EMPLOYER":        frozenset({_PRO}),
    "EMPLOYEE_ID":     frozenset({_PRO, _ID}),
    "JOB_TITLE":       frozenset({_PRO}),
    "FACILITY":        frozenset({_PRO}),
    "ORGANIZATION":    frozenset({_PRO}),
    "HOSPITAL":        frozenset({_PRO, _MED}),
    "VENDOR":          frozenset({_PRO}),

    # --- Government Classification ---
    "CLASSIFICATION_LEVEL":   frozenset({_CLS}),
    "CLASSIFICATION_MARKING": frozenset({_CLS}),
    "SCI_MARKING":            frozenset({_CLS}),
    "DISSEMINATION_CONTROL":  frozenset({_CLS}),
    "CLEARANCE_LEVEL":        frozenset({_CLS}),
    "ITAR_MARKING":           frozenset({_CLS}),
    "EAR_MARKING":            frozenset({_CLS}),
    "CAGE_CODE":              frozenset({_GOV, _ID}),
    "UEI":                    frozenset({_GOV, _ID}),
    "DUNS_NUMBER":            frozenset({_GOV, _ID}),
    "DOD_CONTRACT":           frozenset({_GOV}),
    "GSA_CONTRACT":           frozenset({_GOV}),

    # --- Demographics ---
    "GENDER":          frozenset({_DEM}),
    "ETHNICITY":       frozenset({_DEM}),
    "NATIONALITY":     frozenset({_DEM}),
    "HEIGHT":          frozenset({_DEM, _BIO}),
    "WEIGHT":          frozenset({_DEM, _BIO}),

    # --- Document/Tracking ---
    "DOCUMENT_ID":     frozenset({_ID}),
    "ID_NUMBER":       frozenset({_ID}),
    "TRACKING_NUMBER": frozenset({_ID}),
    "SHIPMENT_ID":     frozenset({_ID}),
    "UNIQUE_ID":       frozenset({_ID}),

    # --- Other / catch-all ---
    "RELATIVE":        frozenset({_ID}),
    "FAMILY":          frozenset({_ID}),
    "ID":              frozenset({_ID}),

    # --- Variant spellings not covered by _ENTITY_ALIASES ---
    # These are in KNOWN_ENTITY_TYPES but don't have alias mappings,
    # so they normalize to themselves and need explicit registry entries.

    # Financial variants
    "ACCOUNT":         frozenset({_FIN, _ID}),
    "BANK_ACCOUNT":    frozenset({_FIN, _ID}),
    "BIC":             frozenset({_FIN}),
    "IBAN_CODE":       frozenset({_FIN, _ID}),
    "SWIFT":           frozenset({_FIN}),

    # Medical ID variants
    "HEALTHPLAN":      frozenset({_ID, _MED}),
    "HEALTH_PLAN":     frozenset({_ID, _MED}),
    "MEMBERID":        frozenset({_ID, _MED}),
    "MEMBER_ID":       frozenset({_ID, _MED}),

    # Government ID variants
    "DOD_ID":          frozenset({_ID, _GOV}),
    "EDIPI":           frozenset({_ID, _GOV}),
    "STATEID":         frozenset({_ID, _GOV}),
    "TIN":             frozenset({_ID, _GOV}),
    "UKNINUMBER":      frozenset({_ID, _GOV}),

    # Name/person variants
    "NURSE":           frozenset({_ID, _MED}),
    "STAFF":           frozenset({_ID, _MED}),

    # Location variants
    "GPE":             frozenset({_LOC}),
    "LOC":             frozenset({_LOC}),
    "GPS_COORDINATES": frozenset({_LOC}),
    "LATITUDE":        frozenset({_LOC}),
    "LONGITUDE":       frozenset({_LOC}),
    "ROOM_NUMBER":     frozenset({_LOC}),

    # Network/device variants
    "BIOID":           frozenset({_BIO, _ID}),
    "DEVICE":          frozenset({_NET, _ID}),
    "MAC":             frozenset({_NET}),
    "MACADDRESS":      frozenset({_NET}),
    "USERAGENT":       frozenset({_NET}),

    # Vehicle variants
    "VEHICLEVIN":      frozenset({_VEH, _ID}),
    "VEHICLEVRM":      frozenset({_VEH, _ID}),
    "VEHICLE_VIN":     frozenset({_VEH, _ID}),
    "VEHICLE_IDENTIFICATION": frozenset({_VEH, _ID}),
    "VEHICLE_PLATE":   frozenset({_VEH, _ID}),
    "PLATE_NUMBER":    frozenset({_VEH, _ID}),

    # Professional variants
    "COMPANYNAME":     frozenset({_PRO}),
    "ORG":             frozenset({_PRO}),
    "JOB":             frozenset({_PRO}),
    "PROFESSION":      frozenset({_PRO}),

    # Contact variants
    "PAGER_NUMBER":    frozenset({_CON}),
}

# Sentinel for unknown entity types
_EMPTY_DOMAINS: frozenset[EntityDomain] = frozenset()


# ---------------------------------------------------------------------------
# Compliance compositions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ComplianceComposition:
    """A domain combination that implies a compliance framework."""

    name: str
    required_domains: frozenset[EntityDomain]
    implies_framework: PolicyCategory
    risk_level: RiskLevel
    score_multiplier: float
    description: str
    excluded_domains: frozenset[EntityDomain] = frozenset()

    def matches(self, present_domains: set[EntityDomain]) -> bool:
        """Check if this composition matches the given domain set."""
        if not self.required_domains.issubset(present_domains):
            return False
        if self.excluded_domains and self.excluded_domains.intersection(present_domains):
            return False
        return True


COMPLIANCE_COMPOSITIONS: list[ComplianceComposition] = [
    # HIPAA: Medical data + any identifier = PHI
    ComplianceComposition(
        name="hipaa_phi",
        required_domains=frozenset({EntityDomain.MEDICAL, EntityDomain.IDENTIFIER}),
        implies_framework=PolicyCategory.HIPAA,
        risk_level=RiskLevel.CRITICAL,
        score_multiplier=2.0,
        description="Protected Health Information: medical data linked to an individual identifier",
    ),
    # HIPAA: Medical + contact info
    ComplianceComposition(
        name="hipaa_phi_contact",
        required_domains=frozenset({EntityDomain.MEDICAL, EntityDomain.CONTACT}),
        implies_framework=PolicyCategory.HIPAA,
        risk_level=RiskLevel.HIGH,
        score_multiplier=1.4,
        description="Medical data combined with contact information",
    ),
    # PCI-DSS: Financial identifiers
    ComplianceComposition(
        name="pci_dss",
        required_domains=frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),
        implies_framework=PolicyCategory.PCI_DSS,
        risk_level=RiskLevel.CRITICAL,
        score_multiplier=1.8,
        description="Payment card or financial account identifiers",
    ),
    # Identity theft: Government ID + financial
    ComplianceComposition(
        name="identity_theft",
        required_domains=frozenset({EntityDomain.GOVERNMENT, EntityDomain.FINANCIAL}),
        implies_framework=PolicyCategory.PII,
        risk_level=RiskLevel.CRITICAL,
        score_multiplier=1.8,
        description="Government identity combined with financial data enables identity theft",
    ),
    # Full identity package
    ComplianceComposition(
        name="full_identity",
        required_domains=frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT, EntityDomain.FINANCIAL}),
        implies_framework=PolicyCategory.PII,
        risk_level=RiskLevel.CRITICAL,
        score_multiplier=2.2,
        description="Complete identity package: government ID + personal identifier + financial data",
    ),
    # GDPR special categories: biometric data
    ComplianceComposition(
        name="gdpr_biometric",
        required_domains=frozenset({EntityDomain.BIOMETRIC, EntityDomain.IDENTIFIER}),
        implies_framework=PolicyCategory.GDPR,
        risk_level=RiskLevel.HIGH,
        score_multiplier=1.5,
        description="Biometric data linked to individual — GDPR Article 9 special category",
    ),
    # GDPR special categories: health data
    ComplianceComposition(
        name="gdpr_health",
        required_domains=frozenset({EntityDomain.MEDICAL, EntityDomain.IDENTIFIER}),
        implies_framework=PolicyCategory.GDPR,
        risk_level=RiskLevel.HIGH,
        score_multiplier=1.5,
        description="Health data linked to individual — GDPR Article 9 special category",
    ),
    # Credentials are always high-risk on their own
    ComplianceComposition(
        name="credential_exposure",
        required_domains=frozenset({EntityDomain.CREDENTIAL}),
        implies_framework=PolicyCategory.SOC2,
        risk_level=RiskLevel.CRITICAL,
        score_multiplier=1.5,
        description="Exposed credentials, secrets, or API keys",
    ),
    # Classified data: fires for security classification markings
    ComplianceComposition(
        name="classified_data",
        required_domains=frozenset({EntityDomain.CLASSIFICATION}),
        implies_framework=PolicyCategory.CUSTOM,
        risk_level=RiskLevel.CRITICAL,
        score_multiplier=2.5,
        description="Government classification markings detected",
    ),
    # GLBA: Personal identifier + financial
    ComplianceComposition(
        name="glba",
        required_domains=frozenset({EntityDomain.IDENTIFIER, EntityDomain.FINANCIAL}),
        implies_framework=PolicyCategory.GLBA,
        risk_level=RiskLevel.HIGH,
        score_multiplier=1.6,
        description="Personal identifier combined with financial data — Gramm-Leach-Bliley Act",
    ),
    # General PII: Identifier + contact
    ComplianceComposition(
        name="pii_contact",
        required_domains=frozenset({EntityDomain.IDENTIFIER, EntityDomain.CONTACT}),
        implies_framework=PolicyCategory.PII,
        risk_level=RiskLevel.MEDIUM,
        score_multiplier=1.2,
        description="Personal identifier combined with contact information",
    ),
]


# ---------------------------------------------------------------------------
# Public API — lookups
# ---------------------------------------------------------------------------

def get_domains(entity_type: str) -> frozenset[EntityDomain]:
    """Get domain tags for an entity type.

    Normalizes the entity type (uppercase, alias resolution) before lookup.
    Returns empty frozenset for unknown types.
    """
    normalized = normalize_entity_type(entity_type)
    return ENTITY_DOMAIN_REGISTRY.get(normalized, _EMPTY_DOMAINS)


def get_all_domains(
    entities: dict[str, int] | Iterable[str],
) -> set[EntityDomain]:
    """Get the union of all domains present across a set of entity types."""
    if isinstance(entities, dict):
        entity_types: Iterable[str] = entities.keys()
    else:
        entity_types = entities

    present: set[EntityDomain] = set()
    for entity_type in entity_types:
        present |= get_domains(entity_type)
    return present


# ---------------------------------------------------------------------------
# Public API — composition
# ---------------------------------------------------------------------------

def evaluate_compositions(
    entities: dict[str, int] | Iterable[str],
) -> list[ComplianceComposition]:
    """Return all compliance compositions that fire for the given entity types.

    Results are sorted by score_multiplier descending (highest-impact first).
    """
    present_domains = get_all_domains(entities)

    matched: list[ComplianceComposition] = []
    for comp in COMPLIANCE_COMPOSITIONS:
        if comp.matches(present_domains):
            matched.append(comp)

    return sorted(matched, key=lambda c: c.score_multiplier, reverse=True)


def get_compliance_frameworks(
    entities: dict[str, int] | Iterable[str],
) -> set[PolicyCategory]:
    """Return set of compliance frameworks implied by entity domain compositions."""
    return {c.implies_framework for c in evaluate_compositions(entities)}


def get_max_score_multiplier(
    entities: dict[str, int] | Iterable[str],
) -> tuple[float, list[str]]:
    """Return (max_multiplier, [composition_names]).

    Drop-in replacement for ``get_co_occurrence_multiplier`` in scorer.py.
    When multiple compositions share the same max multiplier, all their names
    are returned.
    """
    compositions = evaluate_compositions(entities)
    if not compositions:
        return 1.0, []

    max_mult = compositions[0].score_multiplier  # already sorted desc
    names = [c.name for c in compositions if c.score_multiplier == max_mult]
    return max_mult, names
