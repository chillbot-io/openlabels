"""
Core data types for OpenLabels detection engine.

This module defines the fundamental types used throughout the detection system:
- Span: A detected entity with position, type, and confidence
- Tier: Detection authority hierarchy
- Entity types: Comprehensive list of detectable entities

These types are used by all detectors and the scoring engine.
"""

import logging
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any, Dict, FrozenSet, List, Optional, Set

__all__ = [
    # Enums
    "Tier",
    "RiskTier",
    "ExposureLevel",
    # Constants
    "KNOWN_ENTITY_TYPES",
    "CLINICAL_CONTEXT_TYPES",
    # Functions
    "validate_entity_type",
    "is_clinical_context_type",
    "normalize_entity_type",
    # Data classes
    "SpanContext",
    "Span",
    "DetectionResult",
    "ScoringResult",
]

logger = logging.getLogger(__name__)


class Tier(IntEnum):
    """
    Detection authority hierarchy. Higher tier = higher authority.

    When multiple detectors find the same entity at the same position,
    the detection with the higher tier takes precedence.
    """
    ML = 1          # Machine learning models (PHI-BERT, PII-BERT)
    PATTERN = 2     # Regex patterns with validation
    STRUCTURED = 3  # Label-based extraction (DOB:, NAME:, etc.)
    CHECKSUM = 4    # Algorithmically validated (Luhn, mod-97, etc.)

    @classmethod
    def from_value(cls, value: int) -> "Tier":
        """Convert int to Tier with validation."""
        if value not in (1, 2, 3, 4):
            raise ValueError(f"Invalid Tier value: {value}. Must be 1-4.")
        return cls(value)


class RiskTier(Enum):
    """Risk tier classification for files."""
    MINIMAL = "MINIMAL"   # Score 0-10
    LOW = "LOW"           # Score 11-30
    MEDIUM = "MEDIUM"     # Score 31-54
    HIGH = "HIGH"         # Score 55-79
    CRITICAL = "CRITICAL" # Score 80-100


class ExposureLevel(Enum):
    """File exposure/accessibility level."""
    PRIVATE = "PRIVATE"     # Only owner can access
    INTERNAL = "INTERNAL"   # Specific users/groups
    ORG_WIDE = "ORG_WIDE"   # All organization members
    PUBLIC = "PUBLIC"       # Publicly accessible


# =============================================================================
# ENTITY TYPES
# =============================================================================

# Known entity types - used for validation
# Categories: Names, Dates, Locations, IDs, Contact, Financial, Medical, Secrets, Government
# Sources: HIPAA Safe Harbor, i2b2 2014, AI4Privacy, Stanford PHI-BERT, custom detectors
KNOWN_ENTITY_TYPES: FrozenSet[str] = frozenset([
    # --- NAMES ---
    "NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
    "PERSON", "PER", "PATIENT", "DOCTOR", "PHYSICIAN", "NURSE", "STAFF",
    "FIRSTNAME", "LASTNAME", "MIDDLENAME", "PREFIX", "SUFFIX", "FULLNAME",

    # --- DATES & TIME ---
    "DATE", "DATE_DOB", "DATE_TIME", "DATETIME", "TIME",
    "BIRTHDAY", "DOB", "DATEOFBIRTH", "DATE_OF_BIRTH", "BIRTH_DATE", "BIRTHDATE",
    "BIRTH_YEAR", "YEAR_OF_BIRTH", "DATE_RANGE",

    # --- AGE ---
    "AGE",

    # --- LOCATIONS ---
    "ADDRESS", "ZIP", "CITY", "STATE", "COUNTRY", "COUNTY",
    "GPS_COORDINATE", "LATITUDE", "LONGITUDE", "COORDINATE", "COORDINATES",
    "GPE", "LOC", "STREET_ADDRESS", "STREET", "ZIPCODE", "LOCATION_ZIP",
    "ZIP_CODE", "POSTCODE", "LOCATION_OTHER",
    "ROOM", "ROOM_NUMBER",

    # --- IDENTIFIERS - Government ---
    "SSN", "SSN_PARTIAL", "US_SSN", "SOCIAL_SECURITY", "SOCIALSECURITYNUMBER",
    "UKNINUMBER", "SIN", "SIN_CA",  # UK/Canada National Insurance
    "DRIVER_LICENSE", "LICENSE", "US_DRIVER_LICENSE", "DRIVERSLICENSE",
    "STATE_ID", "STATEID",
    "PASSPORT", "US_PASSPORT", "PASSPORT_NUMBER",
    "MILITARY_ID", "EDIPI", "DOD_ID",
    "TAX_ID", "TIN", "EIN", "ITIN",

    # --- IDENTIFIERS - Medical ---
    "MRN", "MEDICAL_RECORD", "MEDICALRECORD",
    "NPI", "DEA", "MEDICAL_LICENSE",
    "ENCOUNTER_ID", "ACCESSION_ID",
    "HEALTH_PLAN_ID", "HEALTHPLAN", "HEALTH_PLAN", "MEMBERID", "MEMBER_ID",
    "MEDICARE_ID", "MBI", "PHARMACY_ID", "NDC",

    # --- IDENTIFIERS - Vehicle ---
    "VIN", "VEHICLEVIN", "VEHICLE_VIN", "VEHICLE_IDENTIFICATION",
    "LICENSE_PLATE", "VEHICLEVRM", "VEHICLE_PLATE", "PLATE_NUMBER",

    # --- CONTACT ---
    "PHONE", "PHONE_NUMBER", "PHONENUMBER", "US_PHONE_NUMBER", "TELEPHONE",
    "EMAIL", "EMAIL_ADDRESS", "EMAILADDRESS",
    "FAX", "FAX_NUMBER", "FAXNUMBER",
    "PAGER", "PAGER_NUMBER",
    "URL", "USERNAME",

    # --- NETWORK & DEVICE ---
    "IP_ADDRESS", "IP", "IPADDRESS", "IPV4", "IPV6",
    "MAC_ADDRESS", "MAC", "MACADDRESS",
    "DEVICE_ID", "IMEI", "DEVICE", "BIOID", "USERAGENT",
    "BIOMETRIC_ID", "FINGERPRINT", "DNA_ID",
    "IMAGE_ID", "PHOTO_ID", "DICOM_UID",
    "CERTIFICATE_NUMBER", "CLAIM_NUMBER",

    # --- FINANCIAL - Traditional ---
    "CREDIT_CARD", "CREDIT_CARD_NUMBER", "CREDITCARDNUMBER", "CC",
    "CREDIT_CARD_PARTIAL",
    "ACCOUNT_NUMBER", "ACCOUNT", "BANK_ACCOUNT",
    "IBAN", "IBAN_CODE",
    "ABA_ROUTING", "ROUTING", "ROUTING_NUMBER",
    "BIC", "SWIFT", "SWIFT_BIC",

    # --- FINANCIAL - Securities ---
    "CUSIP", "ISIN", "SEDOL", "FIGI", "LEI",

    # --- CRYPTOCURRENCY ---
    "BITCOIN_ADDRESS", "ETHEREUM_ADDRESS", "CRYPTO_SEED_PHRASE",
    "SOLANA_ADDRESS", "CARDANO_ADDRESS", "LITECOIN_ADDRESS",
    "DOGECOIN_ADDRESS", "XRP_ADDRESS",

    # --- SECRETS - Cloud Providers ---
    "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SESSION_TOKEN",
    "AZURE_STORAGE_KEY", "AZURE_CONNECTION_STRING", "AZURE_SAS_TOKEN",
    "GOOGLE_API_KEY", "GOOGLE_OAUTH_ID", "GOOGLE_OAUTH_SECRET",
    "FIREBASE_KEY",

    # --- SECRETS - Code Repositories ---
    "GITHUB_TOKEN", "GITLAB_TOKEN", "NPM_TOKEN", "PYPI_TOKEN", "NUGET_KEY",

    # --- SECRETS - Communication Services ---
    "SLACK_TOKEN", "SLACK_WEBHOOK",
    "DISCORD_TOKEN", "DISCORD_WEBHOOK",
    "TWILIO_ACCOUNT_SID", "TWILIO_KEY", "TWILIO_TOKEN",
    "SENDGRID_KEY", "MAILCHIMP_KEY",

    # --- SECRETS - Payment & E-Commerce ---
    "STRIPE_KEY", "SQUARE_TOKEN", "SQUARE_SECRET",
    "SHOPIFY_TOKEN", "SHOPIFY_KEY", "SHOPIFY_SECRET",

    # --- SECRETS - Infrastructure ---
    "HEROKU_KEY", "DATADOG_KEY", "NEWRELIC_KEY", "DATABASE_URL",

    # --- SECRETS - Authentication ---
    "PRIVATE_KEY", "JWT", "BASIC_AUTH", "BEARER_TOKEN",
    "PASSWORD", "API_KEY", "SECRET",

    # --- GOVERNMENT - Classification ---
    "CLASSIFICATION_LEVEL", "CLASSIFICATION_MARKING",
    "SCI_MARKING", "DISSEMINATION_CONTROL",

    # --- GOVERNMENT - Contracts & Identifiers ---
    "CAGE_CODE", "DUNS_NUMBER", "UEI",
    "DOD_CONTRACT", "GSA_CONTRACT",
    "CLEARANCE_LEVEL", "ITAR_MARKING", "EAR_MARKING",

    # --- PROFESSIONAL ---
    "PROFESSION", "OCCUPATION", "JOB", "JOB_TITLE",

    # --- MEDICAL (context-only) ---
    "DRUG", "MEDICATION", "LAB_TEST", "DIAGNOSIS", "PROCEDURE", "PAYER",
    "RX_NUMBER", "PRESCRIPTION", "BLOOD_TYPE",

    # --- FACILITY / ORGANIZATION ---
    "FACILITY", "HOSPITAL", "ORG", "ORGANIZATION", "VENDOR",
    "COMPANYNAME", "COMPANY", "EMPLOYER",

    # --- DOCUMENT & TRACKING ---
    "DOCUMENT_ID", "ID_NUMBER", "TRACKING_NUMBER", "SHIPMENT_ID",

    # --- OTHER ---
    "RELATIVE", "FAMILY", "UNIQUE_ID", "HCW", "ID",
])


# Clinical entity types - detected for context/analytics but NOT redacted
CLINICAL_CONTEXT_TYPES: FrozenSet[str] = frozenset([
    "LAB_TEST",
    "DIAGNOSIS",
    "MEDICATION",
    "DRUG",
    "PROCEDURE",
    "PAYER",
    "PHYSICAL_DESC",
])


# Entity type aliases for normalization
_ENTITY_ALIASES: Dict[str, str] = {
    # SSN variants
    "US_SSN": "SSN",
    "SOCIAL_SECURITY": "SSN",
    "SOCIALSECURITYNUMBER": "SSN",
    # Name variants
    "PER": "NAME",
    "PERSON": "NAME",
    "PATIENT": "NAME_PATIENT",
    "DOCTOR": "NAME_PROVIDER",
    "PHYSICIAN": "NAME_PROVIDER",
    "HCW": "NAME_PROVIDER",
    # Date variants
    "DOB": "DATE_DOB",
    "BIRTHDAY": "DATE_DOB",
    "DATEOFBIRTH": "DATE_DOB",
    "DATE_OF_BIRTH": "DATE_DOB",
    "BIRTH_DATE": "DATE_DOB",
    "BIRTHDATE": "DATE_DOB",
    # Credit card variants
    "CC": "CREDIT_CARD",
    "CREDITCARD": "CREDIT_CARD",
    "CREDITCARDNUMBER": "CREDIT_CARD",
    "CREDIT_CARD_NUMBER": "CREDIT_CARD",
    # Phone variants
    "TELEPHONE": "PHONE",
    "TEL": "PHONE",
    "MOBILE": "PHONE",
    "CELL": "PHONE",
    "PHONENUMBER": "PHONE",
    "PHONE_NUMBER": "PHONE",
    "US_PHONE_NUMBER": "PHONE",
    # Email variants
    "EMAILADDRESS": "EMAIL",
    "EMAIL_ADDRESS": "EMAIL",
    # Address variants
    "STREET_ADDRESS": "ADDRESS",
    "STREET": "ADDRESS",
    # IP variants
    "IP": "IP_ADDRESS",
    "IPADDRESS": "IP_ADDRESS",
    "IPV4": "IP_ADDRESS",
    "IPV6": "IP_ADDRESS",
    # Medical record variants
    "MEDICAL_RECORD": "MRN",
    "MEDICALRECORD": "MRN",
    # Driver's license variants
    "LICENSE": "DRIVER_LICENSE",
    "US_DRIVER_LICENSE": "DRIVER_LICENSE",
    "DRIVERSLICENSE": "DRIVER_LICENSE",
    # Passport variants
    "US_PASSPORT": "PASSPORT",
    "PASSPORT_NUMBER": "PASSPORT",
    # Zip code variants
    "ZIPCODE": "ZIP",
    "ZIP_CODE": "ZIP",
    "POSTCODE": "ZIP",
    "LOCATION_ZIP": "ZIP",
}


def validate_entity_type(entity_type: str) -> bool:
    """Check if an entity type is known."""
    return entity_type.upper() in KNOWN_ENTITY_TYPES


def is_clinical_context_type(entity_type: str) -> bool:
    """Check if an entity type is clinical context (not PHI)."""
    return entity_type.upper() in CLINICAL_CONTEXT_TYPES


def normalize_entity_type(entity_type: str) -> str:
    """
    Normalize entity type to canonical form.

    Args:
        entity_type: Raw entity type string

    Returns:
        Canonical uppercase entity type
    """
    upper = entity_type.upper()
    return _ENTITY_ALIASES.get(upper, upper)


# =============================================================================
# SPAN DATA CLASSES
# =============================================================================

@dataclass(frozen=True)
class SpanContext:
    """Contextual metadata about where a span was detected.

    Attributes:
        source_page: PDF/DOCX page number (1-indexed)
        source_sheet: Excel sheet name
        source_section: Document section heading
        source_cell: Excel cell reference (e.g., "B12")
        surrounding_text: ~50 chars before/after for context
        extraction_method: How text was obtained ("text", "ocr", "metadata", "embedded")
    """
    source_page: int | None = None
    source_sheet: str | None = None
    source_section: str | None = None
    source_cell: str | None = None
    surrounding_text: str | None = None
    extraction_method: str | None = None


@dataclass
class Span:
    """
    A detected entity span with metadata.

    Attributes:
        start: Start character position (0-indexed)
        end: End character position (exclusive)
        text: The actual text detected
        entity_type: Type of entity (SSN, EMAIL, etc.)
        confidence: Detection confidence (0.0-1.0)
        detector: Name of the detector that found this
        tier: Authority tier of the detector
    """
    start: int
    end: int
    text: str
    entity_type: str
    confidence: float
    detector: str
    tier: Tier

    # Optional metadata
    context: SpanContext | None = None  # Extraction context (page, sheet, cell, etc.)
    needs_review: bool = False
    review_reason: Optional[str] = None
    coref_anchor_value: Optional[str] = None  # Link to coreference anchor for entity grouping

    def __post_init__(self) -> None:
        """Validate span attributes."""
        if self.start < 0:
            raise ValueError(f"Invalid span: start={self.start} cannot be negative")
        if self.start >= self.end:
            raise ValueError(f"Invalid span: start={self.start} >= end={self.end}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Invalid confidence: {self.confidence}")

        # Validate text length matches span
        expected_len = self.end - self.start
        if len(self.text) != expected_len:
            raise ValueError(
                f"Invalid span: text length {len(self.text)} != span length {expected_len}"
            )

        # Convert int tier to enum if needed
        if isinstance(self.tier, int) and not isinstance(self.tier, Tier):
            self.tier = Tier.from_value(self.tier)

        # Warn on unknown entity types
        if not validate_entity_type(self.entity_type):
            logger.warning(
                f"Unknown entity type: {self.entity_type}. "
                "Consider adding to KNOWN_ENTITY_TYPES."
            )

    def overlaps(self, other: 'Span') -> bool:
        """Check if this span overlaps with another."""
        return not (self.end <= other.start or other.end <= self.start)

    def contains(self, other: 'Span') -> bool:
        """Check if this span fully contains another."""
        return self.start <= other.start and self.end >= other.end

    def __len__(self) -> int:
        return self.end - self.start

    def __repr__(self) -> str:
        """Safe repr that doesn't expose sensitive text."""
        return (
            f"Span(start={self.start}, end={self.end}, "
            f"entity_type={self.entity_type!r}, confidence={self.confidence:.2f}, "
            f"detector={self.detector!r}, tier={self.tier.name})"
        )

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for serialization."""
        d: dict[str, object] = {
            "start": self.start,
            "end": self.end,
            "text": self.text,
            "entity_type": self.entity_type,
            "confidence": self.confidence,
            "detector": self.detector,
            "tier": self.tier.value,
        }
        if self.context is not None:
            from dataclasses import asdict
            d["context"] = asdict(self.context)
        return d


# =============================================================================
# RESULT DATA CLASSES
# =============================================================================

@dataclass
class DetectionResult:
    """Result of running detection on text."""
    spans: List[Span]
    entity_counts: Dict[str, int]
    processing_time_ms: float
    detectors_used: List[str]
    text_length: int
    policy_result: Optional[Any] = None  # Optional[PolicyResult] -- avoids circular import

    def __repr__(self) -> str:
        return (
            f"DetectionResult(spans={len(self.spans)}, "
            f"entity_counts={self.entity_counts}, "
            f"processing_time_ms={self.processing_time_ms:.2f})"
        )


@dataclass
class ScoringResult:
    """Complete scoring result for a file."""
    score: int                        # Final risk score (0-100)
    tier: RiskTier                    # Risk tier classification
    content_score: float              # Pre-exposure score
    exposure_multiplier: float        # Applied exposure multiplier
    co_occurrence_multiplier: float   # Applied co-occurrence multiplier
    co_occurrence_rules: List[str]    # Which rules triggered
    categories: Set[str]              # Entity categories present
    exposure: str                     # Exposure level used

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for serialization."""
        return {
            'score': self.score,
            'tier': self.tier.value,
            'content_score': self.content_score,
            'exposure_multiplier': self.exposure_multiplier,
            'co_occurrence_multiplier': self.co_occurrence_multiplier,
            'co_occurrence_rules': self.co_occurrence_rules,
            'categories': list(self.categories),
            'exposure': self.exposure,
        }
