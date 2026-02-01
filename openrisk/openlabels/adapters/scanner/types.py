"""Core data types for the OpenLabels Scanner."""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Dict, Any

__all__ = [
    # Enums
    "Tier",
    # Constants
    "KNOWN_ENTITY_TYPES",
    "CLINICAL_CONTEXT_TYPES",
    # Functions
    "validate_entity_type",
    "is_clinical_context_type",
    # Data classes
    "Span",
    "DetectionResult",
]


class Tier(IntEnum):
    """Detection authority hierarchy. Higher tier = higher authority."""
    ML = 1
    PATTERN = 2
    STRUCTURED = 3  # Label-based extraction (DOB:, NAME:, etc.)
    CHECKSUM = 4    # Algorithmically validated (Luhn, etc.)

    @classmethod
    def from_value(cls, value: int) -> "Tier":
        """Convert int to Tier with validation."""
        if value not in (1, 2, 3, 4):
            raise ValueError(f"Invalid Tier value: {value}. Must be 1-4.")
        return cls(value)


# Known entity types - used for validation
# Categories: Names, Dates, Locations, IDs, Contact, Financial, Medical, Secrets, Government, Other
KNOWN_ENTITY_TYPES = frozenset([
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
    "ZIP_CODE", "POSTCODE", "LOCATION-OTHER", "LOCATION_OTHER",
    "ROOM", "ROOM_NUMBER",

    # --- IDENTIFIERS - Government ---
    "SSN", "SSN_PARTIAL", "US_SSN", "SOCIAL_SECURITY", "SOCIALSECURITYNUMBER",
    "UKNINUMBER",
    "DRIVER_LICENSE", "LICENSE", "US_DRIVER_LICENSE", "DRIVERSLICENSE", "DRIVER_LICENSE_NUMBER",
    "STATE_ID", "STATEID",
    "PASSPORT", "US_PASSPORT", "PASSPORT_NUMBER", "PASSPORTNUMBER",
    "MILITARY_ID", "EDIPI", "DOD_ID",

    # --- IDENTIFIERS - Medical ---
    "MRN", "MEDICAL_RECORD", "MEDICALRECORD",
    "NPI", "DEA", "MEDICAL_LICENSE",
    "ENCOUNTER_ID", "ACCESSION_ID",
    "HEALTH_PLAN_ID", "HEALTHPLAN", "HEALTH_PLAN", "MEMBERID", "MEMBER_ID",
    "MEDICARE_ID", "PHARMACY_ID",

    # --- IDENTIFIERS - Vehicle ---
    "VIN", "VEHICLEVIN", "VEHICLE_VIN", "VEHICLE_IDENTIFICATION", "VEHICLE",
    "LICENSE_PLATE", "VEHICLEVRM", "VEHICLE_PLATE", "PLATE_NUMBER",

    # --- CONTACT ---
    "PHONE", "PHONE_NUMBER", "PHONENUMBER", "US_PHONE_NUMBER", "TELEPHONE", "TEL", "MOBILE", "CELL",
    "EMAIL", "EMAIL_ADDRESS", "EMAILADDRESS",
    "FAX", "FAX_NUMBER", "FAXNUMBER",
    "PAGER", "PAGER_NUMBER",
    "URL",
    "USERNAME",

    # --- NETWORK & DEVICE ---
    "IP_ADDRESS", "IP", "IPADDRESS", "IPV4", "IPV6",
    "MAC_ADDRESS", "MAC", "MACADDRESS",
    "DEVICE_ID", "IMEI", "DEVICE", "BIOID", "USERAGENT", "USER_AGENT",
    "BIOMETRIC_ID", "FINGERPRINT", "RETINAL", "IRIS", "VOICEPRINT", "DNA_ID",
    "IMAGE_ID", "PHOTO_ID", "DICOM_UID",
    "CERTIFICATE_NUMBER", "CERTIFICATION",
    "CLAIM_NUMBER",

    # --- FINANCIAL - Traditional ---
    "CREDIT_CARD", "CREDIT_CARD_NUMBER", "CREDITCARDNUMBER", "CREDITCARD", "CC",
    "CREDIT_CARD_PARTIAL",
    "ACCOUNT_NUMBER", "ACCOUNT", "ACCOUNTNUMBER", "BANK_ACCOUNT",
    "IBAN", "IBAN_CODE", "IBANCODE",
    "ABA_ROUTING", "ROUTING", "ROUTING_NUMBER",
    "BIC", "SWIFT", "SWIFT_BIC",

    # --- FINANCIAL - Securities ---
    "CUSIP", "ISIN", "SEDOL", "FIGI", "LEI",

    # --- CRYPTOCURRENCY ---
    "BITCOIN_ADDRESS", "BITCOINADDRESS",
    "ETHEREUM_ADDRESS",
    "CRYPTO_SEED_PHRASE",
    "SOLANA_ADDRESS",
    "CARDANO_ADDRESS",
    "LITECOIN_ADDRESS",
    "DOGECOIN_ADDRESS",
    "XRP_ADDRESS",

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
    "STRIPE_KEY",
    "SQUARE_TOKEN", "SQUARE_SECRET",
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

    # --- GOVERNMENT - Security & Export ---
    "CLEARANCE_LEVEL", "ITAR_MARKING", "EAR_MARKING",

    # --- PROFESSIONAL ---
    "PROFESSION", "OCCUPATION", "JOB", "JOB_TITLE", "JOBTITLE",

    # --- MEDICAL (context types) ---
    "DRUG", "MEDICATION", "LAB_TEST", "DIAGNOSIS", "PROCEDURE", "PAYER",
    "RX_NUMBER", "PRESCRIPTION", "SCRIPT",

    # --- FACILITY / ORGANIZATION ---
    "FACILITY", "HOSPITAL", "ORG", "ORGANIZATION", "VENDOR",
    "COMPANYNAME", "COMPANY", "EMPLOYER",

    # --- OTHER ---
    "HCW", "ID",
    "PHYSICAL_DESC",
    "DOCUMENT_ID", "ID_NUMBER",
    "TRACKING_NUMBER", "SHIPMENT_ID",
    "RELATIVE", "FAMILY",
    "UNIQUE_ID",
])


# Clinical entity types - detected for context but NOT sensitive PII/PHI
# These are medical vocabulary, not patient identifiers
CLINICAL_CONTEXT_TYPES = frozenset([
    "LAB_TEST",
    "DIAGNOSIS",
    "MEDICATION",
    "DRUG",
    "PROCEDURE",
    "PAYER",
    "PHYSICAL_DESC",
])


def validate_entity_type(entity_type: str) -> bool:
    """Check if an entity type is known. LOW-003: normalizes to uppercase."""
    return entity_type.strip().upper() in KNOWN_ENTITY_TYPES


def is_clinical_context_type(entity_type: str) -> bool:
    """Check if an entity type is clinical context (not PHI). LOW-003: normalizes to uppercase."""
    return entity_type.strip().upper() in CLINICAL_CONTEXT_TYPES


@dataclass
class Span:
    """A detected PII/PHI span with metadata."""
    start: int
    end: int
    text: str
    entity_type: str
    confidence: float
    detector: str
    tier: Tier
    # Optional fields for pipeline processing
    safe_harbor_value: str = None  # Replacement token for redaction
    needs_review: bool = False  # Flag for LLM verification
    review_reason: str = None  # Why review is needed
    coref_anchor_value: str = None  # Links repeated mentions to anchor
    token: str = None  # Assigned token for consistent replacement

    def __post_init__(self):
        if self.start < 0:
            raise ValueError(f"Invalid span: start={self.start} cannot be negative")
        if self.start >= self.end:
            raise ValueError(f"Invalid span: start={self.start} >= end={self.end}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Invalid confidence: {self.confidence}")
        expected_len = self.end - self.start
        if len(self.text) != expected_len:
            raise ValueError(
                f"Invalid span: text length {len(self.text)} != span length {expected_len}"
            )
        if isinstance(self.tier, int) and not isinstance(self.tier, Tier):
            self.tier = Tier.from_value(self.tier)
        self.entity_type = self.entity_type.strip().upper()  # LOW-003: canonical form
        if not validate_entity_type(self.entity_type):
            import logging
            logging.getLogger(__name__).warning(
                f"Unknown entity type: {self.entity_type}. "
                "Consider adding to KNOWN_ENTITY_TYPES."
            )

    def overlaps(self, other: 'Span') -> bool:
        """Check if this span overlaps with another."""
        return not (self.end <= other.start or other.end <= self.start)

    def __len__(self) -> int:
        return self.end - self.start

    def __repr__(self) -> str:
        return (
            f"Span(start={self.start}, end={self.end}, "
            f"entity_type={self.entity_type!r}, confidence={self.confidence:.2f}, "
            f"detector={self.detector!r}, tier={self.tier.name})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "start": self.start,
            "end": self.end,
            "text": self.text,
            "entity_type": self.entity_type,
            "confidence": self.confidence,
            "detector": self.detector,
            "tier": self.tier.name,
        }
        if self.token:
            result["token"] = self.token
        return result


@dataclass
class DetectionResult:
    """
    Result of scanning content for PII/PHI.

    Includes information about detector execution status to enable
    callers to understand if results may be incomplete or degraded.

    Attributes:
        text: The scanned text
        spans: Detected PII/PHI spans
        processing_time_ms: Time taken for detection
        detectors_used: Names of detectors that ran successfully
        detectors_failed: Names of detectors that failed (Issue 3.3)
        warnings: Warning messages from detection pipeline (Issue 3.2)
        degraded: True if results may have reduced accuracy (Issue 3.2)
        all_detectors_failed: True if no detectors succeeded (Issue 3.3)
    """
    text: str
    spans: List[Span]
    processing_time_ms: float
    detectors_used: List[str] = field(default_factory=list)

    # Error visibility and observability
    detectors_failed: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    degraded: bool = False
    all_detectors_failed: bool = False

    @property
    def entity_counts(self) -> Dict[str, int]:
        """Count of entities by type."""
        counts: Dict[str, int] = {}
        for span in self.spans:
            counts[span.entity_type] = counts.get(span.entity_type, 0) + 1
        return counts

    @property
    def has_pii(self) -> bool:
        """Check if any PII/PHI was detected."""
        return len(self.spans) > 0

    @property
    def is_reliable(self) -> bool:
        """
        Check if detection results are reliable.

        Returns False if:
        - All detectors failed
        - Detection is in degraded mode
        """
        return not self.all_detectors_failed and not self.degraded

    def __repr__(self) -> str:
        status = ""
        if self.all_detectors_failed:
            status = ", ALL_FAILED"
        elif self.degraded:
            status = ", DEGRADED"
        return (
            f"DetectionResult(spans={len(self.spans)}, "
            f"entities={self.entity_counts}, "
            f"processing_time_ms={self.processing_time_ms:.2f}{status})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "text": self.text,
            "spans": [s.to_dict() for s in self.spans],
            "entity_counts": self.entity_counts,
            "processing_time_ms": self.processing_time_ms,
            "detectors_used": self.detectors_used,
        }
        # Include failure info only if there are issues
        if self.detectors_failed:
            result["detectors_failed"] = self.detectors_failed
        if self.warnings:
            result["warnings"] = self.warnings
        if self.degraded:
            result["degraded"] = self.degraded
        if self.all_detectors_failed:
            result["all_detectors_failed"] = self.all_detectors_failed
        return result
