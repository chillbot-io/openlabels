# Unified Entity Domain Taxonomy — Implementation Blueprint

> **Status:** PROPOSED
> **Author:** Claude (architecture session)
> **Date:** 2026-03-04
> **Scope:** Replace three disjoint category systems with a single domain-tagged taxonomy

---

## 1. Problem Statement

OpenLabels currently maintains **three independent category systems** that classify the same entity types into different groupings, using different vocabularies, for different purposes — with no shared source of truth.

| System | File | Categories | Purpose |
|--------|------|-----------|---------|
| **Scoring categories** | `core/scoring/scorer.py:161-242` | 7 risk-based categories (`direct_identifier`, `health_info`, `financial`, `credential`, `contact`, `quasi_identifier`, `classification_marking`) | Co-occurrence multipliers for risk scoring |
| **Content categories** | `core/detectors/gliner_label_selector.py:17-28` | 8 detection-routing categories (`GENERAL`, `MEDICAL`, `FINANCIAL`, `PERSONAL_ID`, `CONTACT`, `TECHNICAL`, `GOVERNMENT`, `VEHICLE`) | Label selection for GLiNER inference |
| **Policy triggers** | `core/policies/loader.py:33-490` | 9 hardcoded entity lists per compliance framework | Compliance framework matching |

Additionally, `core/benchmark/entity_mapping.py:187-350` defines an **11-category evaluation taxonomy** (`names`, `government_ids`, `financial`, `contact`, `locations`, `dates`, `network`, `vehicle`, `secrets`, `professional`, `demographics`) used only for benchmark scoring.

### Consequences of the current design

1. **Entity types fall through cracks.** GLiNER detects 41 entity labels, but `ENTITY_CATEGORIES` in the scorer only maps ~63 types. Types like `DEVICE_ID`, `IMEI`, `COMPANY`, `JOB_TITLE`, `COUNTRY`, `BIOMETRIC_ID` resolve to `"unknown"` category, which means co-occurrence rules never fire for them.

2. **Policy triggers use different names than detectors produce.** The HIPAA policy triggers on `medical_record_number` but detectors emit `MRN`. The engine lowercases both sides for comparison, but the entity lists were written with different conventions — some use natural language (`person_name`), others use canonical types (`SSN`).

3. **Composition logic is duplicated.** The co-occurrence rules in `scorer.py` encode `{direct_identifier, health_info} → hipaa_phi` with a 2.0x multiplier. The HIPAA policy pack in `loader.py` independently encodes `[person_name, diagnosis]` as a combination trigger. These express the same domain knowledge but can drift independently.

4. **`categories` is computed but discarded.** `ScoringResult.categories` is populated by `scorer.py:396` but never persisted to the database, never exposed in API responses, and never used by the policy engine. It's wasted computation.

5. **No audit trail for compliance reasoning.** When the API returns `has_phi: true`, there's no way for the consumer to understand *why* — which domain composition produced that conclusion.

---

## 2. Proposed Design

### 2.1 Core Concept: Domain Tags

Every entity type gets one or more **domain tags** from a fixed vocabulary. Domain tags describe *what kind of information* the entity represents, not how sensitive it is (that's what weights are for).

```python
class EntityDomain(str, Enum):
    """Semantic domains an entity type can belong to."""

    IDENTIFIER = "identifier"          # Uniquely identifies a person/entity
    MEDICAL = "medical"                # Healthcare/clinical context
    FINANCIAL = "financial"            # Banking, payments, securities
    CREDENTIAL = "credential"          # Secrets, tokens, passwords
    CONTACT = "contact"                # Communication endpoints
    LOCATION = "location"              # Geographic information
    TEMPORAL = "temporal"              # Dates, times, ages
    BIOMETRIC = "biometric"            # Physical/behavioral characteristics
    GOVERNMENT = "government"          # Government-issued or classified
    VEHICLE = "vehicle"                # Vehicle identifiers
    PROFESSIONAL = "professional"      # Employment/organizational
    NETWORK = "network"                # Digital infrastructure (IPs, MACs)
    DEMOGRAPHIC = "demographic"        # Gender, ethnicity, nationality
```

13 domains. Every entity type gets tagged with 1-3 of these.

### 2.2 The Unified Registry

A single `ENTITY_DOMAIN_REGISTRY` replaces all three category systems:

```python
ENTITY_DOMAIN_REGISTRY: dict[str, frozenset[EntityDomain]] = {
    # --- Names ---
    "NAME":            frozenset({EntityDomain.IDENTIFIER}),
    "FIRSTNAME":       frozenset({EntityDomain.IDENTIFIER}),
    "LASTNAME":        frozenset({EntityDomain.IDENTIFIER}),
    "MIDDLENAME":      frozenset({EntityDomain.IDENTIFIER}),
    "NAME_PATIENT":    frozenset({EntityDomain.IDENTIFIER, EntityDomain.MEDICAL}),
    "NAME_PROVIDER":   frozenset({EntityDomain.IDENTIFIER, EntityDomain.MEDICAL}),

    # --- Government IDs ---
    "SSN":             frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "PASSPORT":        frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "DRIVER_LICENSE":  frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "STATE_ID":        frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "MILITARY_ID":     frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "TAX_ID":          frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "ITIN":            frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "EIN":             frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),

    # --- International Government IDs ---
    "UK_NINO":         frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "NHS_NUMBER":      frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT, EntityDomain.MEDICAL}),
    "IN_PAN":          frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "SG_NRIC_FIN":     frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "ES_NIE":          frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "ES_NIF":          frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "PL_PESEL":        frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "FI_HETU":         frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "IT_FISCAL_CODE":  frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "KR_RRN":          frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "TH_TNIN":         frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "IN_GSTIN":        frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT, EntityDomain.FINANCIAL}),
    "IN_VOTER":        frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "IT_VAT":          frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT, EntityDomain.FINANCIAL}),
    "FR_NIR":          frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "FR_SIRET":        frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT, EntityDomain.FINANCIAL}),
    "DE_STEUER_ID":    frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "DE_PERSONALAUSWEIS": frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "NL_BSN":          frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "PT_NIF":          frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "PT_CC":           frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "BR_CPF":          frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "BR_CNPJ":         frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT, EntityDomain.FINANCIAL}),
    "EL_AMKA":         frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "EL_AFM":          frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "SI_EMSO":         frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),
    "SI_DAVCNA":       frozenset({EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}),

    # --- Medical IDs ---
    "MRN":             frozenset({EntityDomain.IDENTIFIER, EntityDomain.MEDICAL}),
    "NPI":             frozenset({EntityDomain.IDENTIFIER, EntityDomain.MEDICAL}),
    "DEA":             frozenset({EntityDomain.IDENTIFIER, EntityDomain.MEDICAL}),
    "MEDICAL_LICENSE":       frozenset({EntityDomain.IDENTIFIER, EntityDomain.MEDICAL}),
    "HEALTH_PLAN_ID":        frozenset({EntityDomain.IDENTIFIER, EntityDomain.MEDICAL}),
    "MEDICARE_ID":           frozenset({EntityDomain.IDENTIFIER, EntityDomain.MEDICAL}),
    "ENCOUNTER_ID":          frozenset({EntityDomain.IDENTIFIER, EntityDomain.MEDICAL}),
    "ACCESSION_ID":          frozenset({EntityDomain.IDENTIFIER, EntityDomain.MEDICAL}),
    "PHARMACY_ID":           frozenset({EntityDomain.IDENTIFIER, EntityDomain.MEDICAL}),

    # --- Medical context (NOT redacted, analytics only) ---
    "DIAGNOSIS":       frozenset({EntityDomain.MEDICAL}),
    "MEDICATION":      frozenset({EntityDomain.MEDICAL}),
    "LAB_TEST":        frozenset({EntityDomain.MEDICAL}),
    "PROCEDURE":       frozenset({EntityDomain.MEDICAL}),
    "DRUG":            frozenset({EntityDomain.MEDICAL}),
    "RX_NUMBER":       frozenset({EntityDomain.MEDICAL, EntityDomain.IDENTIFIER}),
    "BLOOD_TYPE":      frozenset({EntityDomain.MEDICAL, EntityDomain.BIOMETRIC}),

    # --- Financial (Traditional) ---
    "CREDIT_CARD":     frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),
    "ACCOUNT_NUMBER":  frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),
    "IBAN":            frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),
    "SWIFT_BIC":       frozenset({EntityDomain.FINANCIAL}),
    "BANK_ROUTING":    frozenset({EntityDomain.FINANCIAL}),
    "ABA_ROUTING":     frozenset({EntityDomain.FINANCIAL}),

    # --- Financial (Securities) ---
    "CUSIP":           frozenset({EntityDomain.FINANCIAL}),
    "ISIN":            frozenset({EntityDomain.FINANCIAL}),
    "SEDOL":           frozenset({EntityDomain.FINANCIAL}),
    "FIGI":            frozenset({EntityDomain.FINANCIAL}),
    "LEI":             frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),

    # --- Cryptocurrency ---
    "BITCOIN_ADDRESS":   frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),
    "ETHEREUM_ADDRESS":  frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),
    "SOLANA_ADDRESS":    frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),
    "MONERO_ADDRESS":    frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),
    "CARDANO_ADDRESS":   frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),
    "LITECOIN_ADDRESS":  frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),
    "DOGECOIN_ADDRESS":  frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),
    "XRP_ADDRESS":       frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),
    "POLKADOT_ADDRESS":  frozenset({EntityDomain.FINANCIAL, EntityDomain.IDENTIFIER}),
    "CRYPTO_SEED_PHRASE": frozenset({EntityDomain.FINANCIAL, EntityDomain.CREDENTIAL}),

    # --- Credentials & Secrets (Cloud) ---
    "AWS_ACCESS_KEY":    frozenset({EntityDomain.CREDENTIAL}),
    "AWS_SECRET_KEY":    frozenset({EntityDomain.CREDENTIAL}),
    "AWS_SESSION_TOKEN": frozenset({EntityDomain.CREDENTIAL}),
    "AZURE_STORAGE_KEY": frozenset({EntityDomain.CREDENTIAL}),
    "AZURE_CONNECTION_STRING": frozenset({EntityDomain.CREDENTIAL}),
    "AZURE_SAS_TOKEN":   frozenset({EntityDomain.CREDENTIAL}),
    "GOOGLE_API_KEY":    frozenset({EntityDomain.CREDENTIAL}),
    "GOOGLE_OAUTH_TOKEN": frozenset({EntityDomain.CREDENTIAL}),
    "FIREBASE_KEY":      frozenset({EntityDomain.CREDENTIAL}),

    # --- Credentials & Secrets (Code repos) ---
    "GITHUB_TOKEN":    frozenset({EntityDomain.CREDENTIAL}),
    "GITLAB_TOKEN":    frozenset({EntityDomain.CREDENTIAL}),
    "NPM_TOKEN":       frozenset({EntityDomain.CREDENTIAL}),
    "PYPI_TOKEN":      frozenset({EntityDomain.CREDENTIAL}),
    "NUGET_KEY":       frozenset({EntityDomain.CREDENTIAL}),

    # --- Credentials & Secrets (Communication) ---
    "SLACK_TOKEN":     frozenset({EntityDomain.CREDENTIAL}),
    "SLACK_WEBHOOK":   frozenset({EntityDomain.CREDENTIAL}),
    "DISCORD_TOKEN":   frozenset({EntityDomain.CREDENTIAL}),
    "DISCORD_WEBHOOK": frozenset({EntityDomain.CREDENTIAL}),
    "TWILIO_KEY":      frozenset({EntityDomain.CREDENTIAL}),
    "TWILIO_TOKEN":    frozenset({EntityDomain.CREDENTIAL}),
    "SENDGRID_KEY":    frozenset({EntityDomain.CREDENTIAL}),
    "MAILCHIMP_KEY":   frozenset({EntityDomain.CREDENTIAL}),

    # --- Credentials & Secrets (Payment) ---
    "STRIPE_KEY":      frozenset({EntityDomain.CREDENTIAL, EntityDomain.FINANCIAL}),
    "SQUARE_TOKEN":    frozenset({EntityDomain.CREDENTIAL, EntityDomain.FINANCIAL}),
    "SQUARE_SECRET":   frozenset({EntityDomain.CREDENTIAL, EntityDomain.FINANCIAL}),
    "SHOPIFY_TOKEN":   frozenset({EntityDomain.CREDENTIAL}),
    "SHOPIFY_KEY":     frozenset({EntityDomain.CREDENTIAL}),
    "SHOPIFY_SECRET":  frozenset({EntityDomain.CREDENTIAL}),

    # --- Credentials & Secrets (Infra/DevOps) ---
    "HEROKU_KEY":      frozenset({EntityDomain.CREDENTIAL}),
    "DATADOG_KEY":     frozenset({EntityDomain.CREDENTIAL}),
    "NEWRELIC_KEY":    frozenset({EntityDomain.CREDENTIAL}),
    "DATABASE_URL":    frozenset({EntityDomain.CREDENTIAL}),
    "VAULT_TOKEN":     frozenset({EntityDomain.CREDENTIAL}),
    "ATLASSIAN_TOKEN": frozenset({EntityDomain.CREDENTIAL}),
    "GRAFANA_KEY":     frozenset({EntityDomain.CREDENTIAL}),
    "LINEAR_KEY":      frozenset({EntityDomain.CREDENTIAL}),
    "DOPPLER_TOKEN":   frozenset({EntityDomain.CREDENTIAL}),
    "OPENAI_KEY":      frozenset({EntityDomain.CREDENTIAL}),
    "ANTHROPIC_KEY":   frozenset({EntityDomain.CREDENTIAL}),
    "VERCEL_TOKEN":    frozenset({EntityDomain.CREDENTIAL}),
    "SUPABASE_KEY":    frozenset({EntityDomain.CREDENTIAL}),
    "PLANETSCALE_TOKEN": frozenset({EntityDomain.CREDENTIAL}),

    # --- Credentials & Secrets (Auth) ---
    "PASSWORD":        frozenset({EntityDomain.CREDENTIAL}),
    "API_KEY":         frozenset({EntityDomain.CREDENTIAL}),
    "SECRET":          frozenset({EntityDomain.CREDENTIAL}),
    "PRIVATE_KEY":     frozenset({EntityDomain.CREDENTIAL}),
    "JWT":             frozenset({EntityDomain.CREDENTIAL}),
    "BASIC_AUTH":      frozenset({EntityDomain.CREDENTIAL}),
    "BEARER_TOKEN":    frozenset({EntityDomain.CREDENTIAL}),

    # --- Contact ---
    "PHONE":           frozenset({EntityDomain.CONTACT}),
    "EMAIL":           frozenset({EntityDomain.CONTACT}),
    "FAX":             frozenset({EntityDomain.CONTACT}),
    "PAGER":           frozenset({EntityDomain.CONTACT}),
    "URL":             frozenset({EntityDomain.CONTACT}),
    "USERNAME":        frozenset({EntityDomain.CONTACT, EntityDomain.IDENTIFIER}),

    # --- Locations ---
    "ADDRESS":         frozenset({EntityDomain.LOCATION, EntityDomain.CONTACT}),
    "CITY":            frozenset({EntityDomain.LOCATION}),
    "STATE":           frozenset({EntityDomain.LOCATION}),
    "ZIP":             frozenset({EntityDomain.LOCATION}),
    "COUNTRY":         frozenset({EntityDomain.LOCATION}),
    "COUNTY":          frozenset({EntityDomain.LOCATION}),
    "GPS_COORDINATE":  frozenset({EntityDomain.LOCATION}),
    "ROOM":            frozenset({EntityDomain.LOCATION}),
    "LOCATION_OTHER":  frozenset({EntityDomain.LOCATION}),

    # --- Temporal ---
    "DATE":            frozenset({EntityDomain.TEMPORAL}),
    "DATE_DOB":        frozenset({EntityDomain.TEMPORAL, EntityDomain.IDENTIFIER}),
    "DATETIME":        frozenset({EntityDomain.TEMPORAL}),
    "TIME":            frozenset({EntityDomain.TEMPORAL}),
    "AGE":             frozenset({EntityDomain.TEMPORAL, EntityDomain.DEMOGRAPHIC}),

    # --- Network & Device ---
    "IP_ADDRESS":      frozenset({EntityDomain.NETWORK}),
    "MAC_ADDRESS":     frozenset({EntityDomain.NETWORK}),
    "DEVICE_ID":       frozenset({EntityDomain.NETWORK, EntityDomain.IDENTIFIER}),
    "IMEI":            frozenset({EntityDomain.NETWORK, EntityDomain.IDENTIFIER}),
    "BIOMETRIC_ID":    frozenset({EntityDomain.BIOMETRIC, EntityDomain.IDENTIFIER}),
    "FINGERPRINT":     frozenset({EntityDomain.BIOMETRIC, EntityDomain.IDENTIFIER}),
    "DNA_ID":          frozenset({EntityDomain.BIOMETRIC, EntityDomain.IDENTIFIER}),
    "DICOM_UID":       frozenset({EntityDomain.MEDICAL, EntityDomain.NETWORK}),

    # --- Vehicle ---
    "VIN":             frozenset({EntityDomain.VEHICLE, EntityDomain.IDENTIFIER}),
    "LICENSE_PLATE":   frozenset({EntityDomain.VEHICLE, EntityDomain.IDENTIFIER}),

    # --- Professional/Organizational ---
    "COMPANY":         frozenset({EntityDomain.PROFESSIONAL}),
    "EMPLOYER":        frozenset({EntityDomain.PROFESSIONAL}),
    "EMPLOYEE_ID":     frozenset({EntityDomain.PROFESSIONAL, EntityDomain.IDENTIFIER}),
    "JOB_TITLE":       frozenset({EntityDomain.PROFESSIONAL}),
    "FACILITY":        frozenset({EntityDomain.PROFESSIONAL}),
    "ORGANIZATION":    frozenset({EntityDomain.PROFESSIONAL}),
    "HOSPITAL":        frozenset({EntityDomain.PROFESSIONAL, EntityDomain.MEDICAL}),

    # --- Government Classification ---
    "CLASSIFICATION_LEVEL":   frozenset({EntityDomain.GOVERNMENT}),
    "CLASSIFICATION_MARKING": frozenset({EntityDomain.GOVERNMENT}),
    "SCI_MARKING":            frozenset({EntityDomain.GOVERNMENT}),
    "DISSEMINATION_CONTROL":  frozenset({EntityDomain.GOVERNMENT}),
    "CLEARANCE_LEVEL":        frozenset({EntityDomain.GOVERNMENT}),
    "ITAR_MARKING":           frozenset({EntityDomain.GOVERNMENT}),
    "EAR_MARKING":            frozenset({EntityDomain.GOVERNMENT}),
    "CAGE_CODE":              frozenset({EntityDomain.GOVERNMENT, EntityDomain.IDENTIFIER}),
    "UEI":                    frozenset({EntityDomain.GOVERNMENT, EntityDomain.IDENTIFIER}),
    "DUNS_NUMBER":            frozenset({EntityDomain.GOVERNMENT, EntityDomain.IDENTIFIER}),
    "DOD_CONTRACT":           frozenset({EntityDomain.GOVERNMENT}),
    "GSA_CONTRACT":           frozenset({EntityDomain.GOVERNMENT}),

    # --- Demographics ---
    "GENDER":          frozenset({EntityDomain.DEMOGRAPHIC}),
    "ETHNICITY":       frozenset({EntityDomain.DEMOGRAPHIC}),
    "NATIONALITY":     frozenset({EntityDomain.DEMOGRAPHIC}),
    "HEIGHT":          frozenset({EntityDomain.DEMOGRAPHIC, EntityDomain.BIOMETRIC}),
    "WEIGHT":          frozenset({EntityDomain.DEMOGRAPHIC, EntityDomain.BIOMETRIC}),

    # --- Document/Tracking ---
    "DOCUMENT_ID":     frozenset({EntityDomain.IDENTIFIER}),
    "TRACKING_NUMBER": frozenset({EntityDomain.IDENTIFIER}),
    "UNIQUE_ID":       frozenset({EntityDomain.IDENTIFIER}),
    "CERTIFICATE_NUMBER": frozenset({EntityDomain.IDENTIFIER}),
    "CLAIM_NUMBER":    frozenset({EntityDomain.IDENTIFIER}),
}
```

### 2.3 Compliance Composition Rules

Domain compositions map to compliance frameworks. This replaces both `CO_OCCURRENCE_RULES` in `scorer.py` and the hardcoded entity lists in `loader.py`.

```python
@dataclass(frozen=True)
class ComplianceComposition:
    """A domain combination that implies a compliance framework."""
    name: str                                # Human-readable label
    required_domains: frozenset[EntityDomain] # ALL must be present
    implies_framework: PolicyCategory         # Which framework this triggers
    risk_level: RiskLevel                     # Risk when triggered
    score_multiplier: float                   # For risk scoring
    description: str                          # Audit-friendly explanation

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
    # HIPAA: Medical + contact info (can reach the patient)
    ComplianceComposition(
        name="hipaa_phi_contact",
        required_domains=frozenset({EntityDomain.MEDICAL, EntityDomain.CONTACT}),
        implies_framework=PolicyCategory.HIPAA,
        risk_level=RiskLevel.HIGH,
        score_multiplier=1.4,
        description="Medical data combined with contact information",
    ),
    # PCI-DSS: Financial identifiers (card numbers, account numbers)
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
    # Full identity package: ID + identifier + financial
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
    # Classified data
    ComplianceComposition(
        name="classified_data",
        required_domains=frozenset({EntityDomain.GOVERNMENT}),
        implies_framework=PolicyCategory.CUSTOM,
        risk_level=RiskLevel.CRITICAL,
        score_multiplier=2.5,
        description="Government classification markings detected",
        # NOTE: Only fires when CLASSIFICATION_LEVEL/MARKING entities present,
        # since only those types have GOVERNMENT without IDENTIFIER
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
```

### 2.4 Key Design Properties

**Multi-tagging enables composition.** An `MRN` is both `{IDENTIFIER, MEDICAL}` — so by its mere presence, the `hipaa_phi` composition fires. No need for explicit combination triggers listing `[MRN, ...]`. The domain tags carry the compliance semantics intrinsically.

**Single entity can trigger compositions.** Because `NHS_NUMBER` is tagged `{IDENTIFIER, GOVERNMENT, MEDICAL}`, a document containing only NHS numbers automatically matches the `hipaa_phi` composition (has both MEDICAL and IDENTIFIER domains). This is correct — a list of NHS numbers *is* PHI.

**Backward-compatible with existing scoring.** The `score_multiplier` field on compositions replaces the current `CO_OCCURRENCE_RULES` multipliers. Same numbers, cleaner derivation.

**Human-readable audit trail.** Every composition has a `description` that can appear in API responses and compliance reports: *"Protected Health Information: medical data linked to an individual identifier"*.

---

## 3. New Module: `entity_domains.py`

### 3.1 File Location

```
src/openlabels/core/entity_domains.py
```

This lives alongside `types.py` in the core module, not inside scoring or policies.

### 3.2 Public API

```python
# --- Lookups ---
def get_domains(entity_type: str) -> frozenset[EntityDomain]:
    """Get domain tags for an entity type. Returns empty frozenset for unknown types."""

def get_all_domains(entities: dict[str, int] | Iterable[str]) -> set[EntityDomain]:
    """Get the union of all domains present across a set of entity types."""

# --- Composition ---
def evaluate_compositions(entities: dict[str, int] | Iterable[str]) -> list[ComplianceComposition]:
    """Return all compliance compositions that fire for the given entity types."""

def get_compliance_frameworks(entities: dict[str, int] | Iterable[str]) -> set[PolicyCategory]:
    """Return set of compliance frameworks implied by entity domain compositions."""

def get_max_score_multiplier(entities: dict[str, int] | Iterable[str]) -> tuple[float, list[str]]:
    """Return (max_multiplier, [composition_names]) — drop-in for get_co_occurrence_multiplier."""

# --- Detection routing ---
def get_content_categories(text: str, sample_size: int = 5000) -> set[EntityDomain]:
    """Profile text content and return active domains for detection routing.
    Replaces ContentCategory enum + profile_content() for GLiNER label selection."""

def get_gliner_labels_for_domains(domains: set[EntityDomain]) -> list[str]:
    """Map active domains to GLiNER labels. Replaces CATEGORY_LABELS dict."""

# --- Backward compatibility ---
def get_legacy_category(entity_type: str) -> str:
    """Map entity type to legacy scorer category name. For migration period only."""

LEGACY_CATEGORY_MAP: dict[EntityDomain, str] = {
    EntityDomain.IDENTIFIER: "direct_identifier",     # approximate
    EntityDomain.MEDICAL: "health_info",
    EntityDomain.FINANCIAL: "financial",
    EntityDomain.CREDENTIAL: "credential",
    EntityDomain.CONTACT: "contact",
    EntityDomain.GOVERNMENT: "classification_marking", # for classification-only entities
    # IDENTIFIER without GOVERNMENT = "quasi_identifier"
}
```

### 3.3 Composition Evaluation Logic

```python
def evaluate_compositions(
    entities: dict[str, int] | Iterable[str],
) -> list[ComplianceComposition]:
    """
    1. Collect the union of all domains across detected entity types
    2. For each ComplianceComposition, check if required_domains ⊆ present_domains
    3. Return all matching compositions, sorted by score_multiplier descending
    """
    if isinstance(entities, dict):
        entity_types = entities.keys()
    else:
        entity_types = entities

    present_domains: set[EntityDomain] = set()
    for entity_type in entity_types:
        present_domains |= get_domains(normalize_entity_type(entity_type))

    matched = []
    for comp in COMPLIANCE_COMPOSITIONS:
        if comp.required_domains.issubset(present_domains):
            matched.append(comp)

    return sorted(matched, key=lambda c: c.score_multiplier, reverse=True)
```

---

## 4. Migration Plan: Consumer-by-Consumer

### 4.1 Scorer (`core/scoring/scorer.py`)

**Current state:**
- `ENTITY_CATEGORIES` dict (63 entries) — maps entity types → 7 category strings
- `CO_OCCURRENCE_RULES` list (7 rules) — maps category sets → multipliers
- `get_categories()`, `get_co_occurrence_multiplier()` functions

**Migration:**
1. Replace `ENTITY_CATEGORIES` with import from `entity_domains.get_domains()`
2. Replace `CO_OCCURRENCE_RULES` with `COMPLIANCE_COMPOSITIONS` from `entity_domains`
3. Replace `get_co_occurrence_multiplier()` with `entity_domains.get_max_score_multiplier()`
4. Replace `get_categories()` with `entity_domains.get_all_domains()`
5. Update `ScoringResult.categories` type from `set[str]` to `set[str]` (domain names as strings for serialization)
6. **Keep** `ENTITY_WEIGHTS` in scorer — weights are risk-specific, not domain-specific

**Compatibility bridge (temporary):**
```python
# scorer.py — during migration
from .entity_domains import get_all_domains, get_max_score_multiplier

def get_categories(entities: dict[str, int]) -> set[str]:
    """DEPRECATED: Use entity_domains.get_all_domains() instead."""
    return {d.value for d in get_all_domains(entities)}

def get_co_occurrence_multiplier(entities: dict[str, int]) -> tuple[float, list[str]]:
    """DEPRECATED: Use entity_domains.get_max_score_multiplier() instead."""
    return get_max_score_multiplier(entities)
```

**ScoringResult changes:**
- `categories: set[str]` — now populated with domain names (`"medical"`, `"identifier"`) instead of legacy names (`"health_info"`, `"direct_identifier"`)
- `co_occurrence_rules: list[str]` — now populated with composition names (`"hipaa_phi"`) instead of legacy names (already `"hipaa_phi"`, no change)
- **NEW:** `compliance_compositions: list[dict]` — optional, populated with `[{"name": "hipaa_phi", "description": "...", "framework": "HIPAA"}]` for audit trail

**Impact on downstream:**
- `categories` field is currently **never persisted** (confirmed by scorer consumers research). No DB migration needed.
- `co_occurrence_rules` is persisted in `ScanResult.co_occurrence_rules` (JSONB). Rule names stay the same (`hipaa_phi`, `identity_theft`, etc.) so no DB migration needed.

### 4.2 GLiNER Label Selector (`core/detectors/gliner_label_selector.py`)

**Current state:**
- `ContentCategory` Flag enum (8 values)
- `_CATEGORY_PATTERNS` dict — keyword regex → category activation
- `_CATEGORY_LABELS` dict — category → GLiNER labels
- `profile_content()` → `ContentProfile(categories, selected_labels, category_scores)`

**Migration:**
1. Replace `ContentCategory` enum with `EntityDomain` enum
2. Replace `_CATEGORY_PATTERNS` with domain-keyed patterns
3. Replace `_CATEGORY_LABELS` with `entity_domains.get_gliner_labels_for_domains()`
4. `profile_content()` returns domains instead of ContentCategory flags
5. `ContentProfile.categories` becomes `set[EntityDomain]` instead of `ContentCategory` flag

**Key mapping:**
```
ContentCategory.GENERAL     → Always active (no domain equivalent needed)
ContentCategory.MEDICAL     → EntityDomain.MEDICAL
ContentCategory.FINANCIAL   → EntityDomain.FINANCIAL
ContentCategory.PERSONAL_ID → EntityDomain.GOVERNMENT (+ IDENTIFIER)
ContentCategory.CONTACT     → EntityDomain.CONTACT
ContentCategory.TECHNICAL   → EntityDomain.CREDENTIAL (+ NETWORK)
ContentCategory.GOVERNMENT  → EntityDomain.GOVERNMENT
ContentCategory.VEHICLE     → EntityDomain.VEHICLE
```

**Keyword patterns stay the same** — just re-keyed from `ContentCategory` to `EntityDomain`. The actual regex content doesn't change.

**GLiNER label routing stays the same** — just derived from domains instead of ContentCategory. The `GLINER_LABEL_MAP` in `gliner.py` is unaffected (it maps natural-language labels to canonical entity types, which is orthogonal to domains).

### 4.3 Policy Engine (`core/policies/engine.py` + `loader.py`)

**Current state:**
- 9 hardcoded policy packs in `loader.py` with `any_of` and `combinations` trigger lists
- Entity types listed as lowercase natural-language strings
- Engine evaluates triggers by intersecting entity types

**Migration — Two phases:**

**Phase 1 (non-breaking):** Add domain-based trigger evaluation alongside existing entity-list triggers.

```python
# schema.py — extend PolicyTrigger
@dataclass
class PolicyTrigger:
    any_of: list[str] = ...                    # Existing: entity type lists
    all_of: list[str] = ...                    # Existing
    combinations: list[list[str]] = ...        # Existing
    # NEW: domain-based triggers
    domain_any_of: list[str] = ...             # Fire if ANY domain present
    domain_all_of: list[str] = ...             # Fire if ALL domains present
    domain_combinations: list[list[str]] = ... # Multiple domain AND conditions
    ...
```

```python
# engine.py — extend evaluate()
def _evaluate_domain_triggers(self, ctx, policy):
    """Evaluate domain-based triggers."""
    present_domains = get_all_domains(ctx.entity_types)
    # ... same intersection logic as entity triggers, but on domains
```

**Phase 2 (after validation):** Migrate built-in policy packs from entity-list triggers to domain triggers.

```python
# loader.py — HIPAA before:
PolicyTrigger(
    any_of=["medical_record_number", "mrn", "health_insurance_id", ...],
    combinations=[["person_name", "diagnosis"], ...],
)

# HIPAA after:
PolicyTrigger(
    domain_all_of=["medical", "identifier"],  # Any medical + identifier combo = PHI
)
```

This is dramatically simpler. The 10-item `any_of` list and 9-item `combinations` list collapse to a single 2-domain condition — because the domain tags already encode the relationship.

**Custom user policies (YAML/JSON) are unaffected** — they continue using entity-list triggers. Domain triggers are opt-in.

### 4.4 Benchmark Entity Mapping (`core/benchmark/entity_mapping.py`)

**Current state:**
- `EVAL_CATEGORIES` dict — 11 benchmark categories with 116+ entity types
- `get_eval_category()` function

**Migration:**
- **No changes required.** Evaluation categories serve a different purpose (benchmark reporting granularity) and don't need to align with compliance domains.
- If desired later: derive `EVAL_CATEGORIES` from domain tags using a domain-to-eval-category mapping. But this is cosmetic, not functional.

### 4.5 Database & API Layer

**Current state:**
- `ScanResult` stores `co_occurrence_rules` (JSONB), `risk_score`, `risk_tier`, `content_score`, `exposure_multiplier`
- `ResultDetailResponse` exposes `co_occurrence_rules` in API
- `categories` from `ScoringResult` is **never stored or exposed**

**Migration:**

**Schema addition** (new column on `ScanResult`):
```python
# models.py
detected_domains: Mapped[list[str] | None] = mapped_column(JSONB)  # ["medical", "identifier", "contact"]
compliance_compositions: Mapped[list[dict] | None] = mapped_column(JSONB)  # [{"name": "hipaa_phi", "framework": "HIPAA", "description": "..."}]
```

**API response extension:**
```python
# routes/results.py
class ResultDetailResponse(ResultResponse):
    ...
    detected_domains: list[str] | None = None          # NEW
    compliance_compositions: list[dict] | None = None   # NEW
```

**Migration script:** Alembic migration adding two nullable JSONB columns. No data backfill needed — new scans populate them, old results show `null`.

### 4.6 FileClassification & Processor (`core/processor.py`)

**Current state:**
- `FileClassification` stores `co_occurrence_rules: list[str]`
- `FileProcessor.process_file()` calls `score()` and extracts fields

**Migration:**
```python
# processor.py — extend FileClassification
@dataclass
class FileClassification:
    ...
    co_occurrence_rules: list[str] = field(default_factory=list)
    detected_domains: list[str] = field(default_factory=list)                # NEW
    compliance_compositions: list[dict] = field(default_factory=list)        # NEW
```

```python
# processor.py — in process_file()
from .entity_domains import evaluate_compositions, get_all_domains

domains = get_all_domains(detection_result.entity_counts)
compositions = evaluate_compositions(detection_result.entity_counts)

result.detected_domains = sorted(d.value for d in domains)
result.compliance_compositions = [
    {"name": c.name, "framework": c.implies_framework.value,
     "description": c.description, "multiplier": c.score_multiplier}
    for c in compositions
]
```

### 4.7 Report Generation (`server/routes/reporting.py` + `cli/commands/report.py`)

**New report capabilities enabled:**
- "Why was this flagged as PHI?" → compliance_compositions includes `{"name": "hipaa_phi", "description": "Protected Health Information: medical data linked to an individual identifier"}`
- Domain breakdown: `detected_domains: ["medical", "identifier", "contact"]`
- Compliance framework summary: `frameworks: ["HIPAA", "GDPR", "PII"]` derived from compositions

**CLI report output (text format):**
```
File: /data/patient_records.csv
  Risk: 92 (CRITICAL)
  Domains: medical, identifier, contact
  Compliance: HIPAA (hipaa_phi), GDPR (gdpr_health), PII (pii_contact)
  Entities: MRN (5), NAME (12), PHONE (3), DIAGNOSIS (8)
```

---

## 5. File-by-File Change Manifest

### New Files

| File | Purpose |
|------|---------|
| `src/openlabels/core/entity_domains.py` | **Single source of truth** — EntityDomain enum, ENTITY_DOMAIN_REGISTRY, ComplianceComposition, all lookup/evaluation functions |
| `tests/core/test_entity_domains.py` | Tests for domain lookups, composition evaluation, GLiNER label mapping, backward compatibility |
| `alembic/versions/xxx_add_domain_columns.py` | Migration adding `detected_domains` and `compliance_compositions` JSONB columns to `scan_results` |

### Modified Files

| File | Lines Affected | Change Description |
|------|---------------|-------------------|
| `core/scoring/scorer.py` | 161-304 | Replace `ENTITY_CATEGORIES`, `CO_OCCURRENCE_RULES`, `get_category()`, `get_categories()`, `get_co_occurrence_multiplier()` with thin wrappers around `entity_domains` |
| `core/scoring/__init__.py` | 3-29 | Update re-exports: add `get_domains`, `evaluate_compositions`, keep deprecated wrappers |
| `core/__init__.py` | 62-68 | Add `entity_domains` exports to package public API |
| `core/types.py` | 489-511 | Extend `ScoringResult` with `detected_domains` and `compliance_compositions` fields |
| `core/detectors/gliner_label_selector.py` | 17-283 | Replace `ContentCategory` with `EntityDomain`, re-key patterns and labels |
| `core/detectors/gliner.py` | 350-367 | Update `_select_labels()` to work with new `profile_content()` return type |
| `core/policies/schema.py` | 62-94 | Extend `PolicyTrigger` with `domain_any_of`, `domain_all_of`, `domain_combinations` |
| `core/policies/engine.py` | 190-275 | Add `_evaluate_domain_triggers()` method alongside existing trigger evaluation |
| `core/policies/loader.py` | 33-490 | (Phase 2) Migrate built-in policy packs to domain-based triggers |
| `core/processor.py` | 149-190, 322-331 | Add `detected_domains`, `compliance_compositions` to `FileClassification`; populate in `process_file()` |
| `server/models.py` | 376-454 | Add `detected_domains`, `compliance_compositions` JSONB columns to `ScanResult` |
| `server/routes/results.py` | 66-73 | Add fields to `ResultDetailResponse` |
| `jobs/tasks/scan.py` | 1074-1086 | Pass `detected_domains`, `compliance_compositions` through to DB |

### Test Files Modified

| File | Change |
|------|--------|
| `tests/core/test_scorer.py` | Update category assertions to use domain names; add composition tests |
| `tests/core/detectors/test_gliner_label_selector.py` | Update ContentCategory → EntityDomain assertions |
| `tests/core/policies/test_engine.py` | Add domain-trigger evaluation tests |
| `tests/core/policies/test_policy_evaluation.py` | Add domain-based composition trigger tests |

---

## 6. Rollout Strategy

### Phase 1: Foundation (non-breaking)
1. Create `entity_domains.py` with full registry, composition rules, and all functions
2. Write comprehensive tests for `entity_domains.py`
3. Add `detected_domains` and `compliance_compositions` to `FileClassification`, `ScanResult`, and API responses (nullable)
4. Wire `entity_domains.evaluate_compositions()` into `FileProcessor.process_file()` to populate new fields
5. **Do NOT change** scorer, label selector, or policy engine yet — they continue using their own systems

**Validation:** New fields appear in API responses for new scans. Old scans show `null`. All existing tests pass unchanged.

### Phase 2: Scorer Migration
1. Replace `ENTITY_CATEGORIES` + `CO_OCCURRENCE_RULES` in scorer with thin wrappers around `entity_domains`
2. Update `ScoringResult.categories` to contain domain names instead of legacy category names
3. Deprecate `get_category()`, `get_categories()`, `get_co_occurrence_multiplier()` — keep as wrappers

**Validation:** Scoring results stay numerically identical (same weights, same multipliers). Category names change but are never persisted. Co-occurrence rule names stay the same.

### Phase 3: Label Selector Migration
1. Replace `ContentCategory` enum with `EntityDomain` in `gliner_label_selector.py`
2. Re-key `_CATEGORY_PATTERNS` and `_CATEGORY_LABELS` from ContentCategory → EntityDomain
3. Update `profile_content()` return type
4. Update GLiNER detector's `_select_labels()` call

**Validation:** GLiNER receives the same labels for the same input text. Detection results unchanged.

### Phase 4: Policy Engine Enhancement
1. Add `domain_any_of`, `domain_all_of`, `domain_combinations` to `PolicyTrigger`
2. Add `_evaluate_domain_triggers()` to `PolicyEngine`
3. Migrate built-in policy packs to use domain triggers (dramatically simpler configs)
4. Custom user policies continue using entity-list triggers (backward compatible)

**Validation:** Built-in policies fire on the same inputs. Custom policies unaffected.

### Phase 5: Cleanup
1. Remove deprecated wrapper functions from scorer
2. Remove `ENTITY_CATEGORIES` and `CO_OCCURRENCE_RULES` constants
3. Remove `ContentCategory` enum (replaced by EntityDomain)

---

## 7. Invariants & Constraints

### Must Hold True After Migration

1. **Scoring parity.** For any `entities: dict[str, int]`, `score(entities).score` must produce the same numerical result before and after migration. Weights don't change. Multipliers don't change (same numbers, derived differently).

2. **Detection parity.** GLiNER receives the same labels for the same input text. The label selection is re-keyed but functionally identical.

3. **Policy parity.** Built-in policies fire on the same entity combinations. Domain triggers are equivalent to the existing entity-list triggers, just expressed differently.

4. **No DB migration for existing data.** New columns are nullable. Old scans keep working. No backfill required.

5. **Custom policies unaffected.** User-defined YAML/JSON policies continue using entity-list triggers. Domain triggers are additive.

6. **Every entity type in `KNOWN_ENTITY_TYPES` has domain tags.** If an entity type is detected, it must have a domain mapping. Unknown types default to `frozenset()` (empty domains).

### Design Constraints

1. **Domain tags are semantic, not risk-based.** "How sensitive is this?" is answered by `ENTITY_WEIGHTS`. "What kind of data is this?" is answered by domains. Don't conflate them.

2. **Compositions are order-independent.** `{MEDICAL, IDENTIFIER}` fires regardless of which entity was detected first. This matches the current co-occurrence behavior.

3. **Multi-tagging is the core value.** An entity type like `NHS_NUMBER` being tagged `{IDENTIFIER, GOVERNMENT, MEDICAL}` is what enables single-entity composition triggers. If you flatten to single tags, you lose the compositional power.

4. **13 domains max.** Don't proliferate domains. If a new category is needed, first check if an existing domain combination expresses it. Domains should be orthogonal axes, not a flat list.

---

## 8. Example Walkthrough

### Input
```python
entities = {"MRN": 3, "NAME": 5, "PHONE": 2, "DIAGNOSIS": 4}
```

### Domain Resolution
```python
MRN       → {MEDICAL, IDENTIFIER}
NAME      → {IDENTIFIER}
PHONE     → {CONTACT}
DIAGNOSIS → {MEDICAL}

present_domains = {MEDICAL, IDENTIFIER, CONTACT}
```

### Composition Evaluation
```python
hipaa_phi:       {MEDICAL, IDENTIFIER} ⊆ {MEDICAL, IDENTIFIER, CONTACT}  → FIRES (2.0x, CRITICAL)
hipaa_phi_contact: {MEDICAL, CONTACT} ⊆ {MEDICAL, IDENTIFIER, CONTACT}   → FIRES (1.4x, HIGH)
pii_contact:     {IDENTIFIER, CONTACT} ⊆ {MEDICAL, IDENTIFIER, CONTACT}  → FIRES (1.2x, MEDIUM)

max_multiplier = 2.0 (from hipaa_phi)
triggered_rules = ["hipaa_phi"]  # highest multiplier wins, same as current behavior
```

### Output
```python
ScoringResult(
    score=92,
    tier=RiskTier.CRITICAL,
    categories={"medical", "identifier", "contact"},
    co_occurrence_rules=["hipaa_phi"],
    co_occurrence_multiplier=2.0,
    detected_domains=["contact", "identifier", "medical"],
    compliance_compositions=[
        {"name": "hipaa_phi", "framework": "HIPAA", "description": "Protected Health Information: ..."},
        {"name": "hipaa_phi_contact", "framework": "HIPAA", "description": "Medical data combined with contact information"},
        {"name": "pii_contact", "framework": "PII", "description": "Personal identifier combined with contact information"},
    ],
)
```

### API Response (ResultDetailResponse)
```json
{
  "risk_score": 92,
  "risk_tier": "CRITICAL",
  "entity_counts": {"MRN": 3, "NAME": 5, "PHONE": 2, "DIAGNOSIS": 4},
  "co_occurrence_rules": ["hipaa_phi"],
  "detected_domains": ["contact", "identifier", "medical"],
  "compliance_compositions": [
    {
      "name": "hipaa_phi",
      "framework": "HIPAA",
      "description": "Protected Health Information: medical data linked to an individual identifier"
    },
    {
      "name": "hipaa_phi_contact",
      "framework": "HIPAA",
      "description": "Medical data combined with contact information"
    },
    {
      "name": "pii_contact",
      "framework": "PII",
      "description": "Personal identifier combined with contact information"
    }
  ]
}
```

This gives the API consumer everything they need: *what* was found (entity_counts), *what it means* (domains), *why it matters* (compositions with human-readable descriptions), and *what frameworks apply* (HIPAA, PII).

---

## 9. Open Questions

1. **Should compositions use "highest wins" or "all matching"?** Current co-occurrence rules use highest-multiplier-wins. The blueprint proposes returning *all* matching compositions (for audit trail) but still using the highest multiplier for scoring. This is a superset of current behavior.

2. **Should domain tags be persisted on individual Spans?** Currently `Span.entity_type` is the canonical type. Adding `Span.domains: frozenset[EntityDomain]` would let downstream consumers inspect domains per-entity. Cost: slight memory increase per span. Benefit: richer per-span metadata for filtering/routing.

3. **Should `ENTITY_WEIGHTS` move to `entity_domains.py`?** Weights are risk-specific and currently live in scorer.py. They could live alongside domain tags in the registry. Argument for: single source of truth per entity type. Argument against: weights are a scoring concern, not a domain concern.

4. **Should the `classified_data` composition require `CLASSIFICATION_LEVEL` or `CLASSIFICATION_MARKING` specifically, rather than the broad `GOVERNMENT` domain?** Currently it fires on any `GOVERNMENT`-only entity, but most government entities also have `IDENTIFIER` (SSN, passport, etc.) which would route them to other compositions first. Only classification markings have `GOVERNMENT` without `IDENTIFIER`. This implicit behavior is correct but subtle.

5. **Should custom user policies support domain triggers in YAML?** If so, the YAML loader needs to parse `domain_any_of`, `domain_all_of`, etc. This is additive and non-breaking, but adds surface area to the policy schema.
