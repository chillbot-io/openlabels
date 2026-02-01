"""Core data types for ScrubIQ."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum, Enum
from typing import Optional, List, Dict, Any

__all__ = [
    # Enums
    "Tier",
    "PrivacyMode",
    "ReviewReason",
    "AuditEventType",
    # Constants
    "KNOWN_ENTITY_TYPES",
    "CLINICAL_CONTEXT_TYPES",
    # Functions
    "validate_entity_type",
    "is_clinical_context_type",
    # Data classes
    "Span",
    "Mention",
    "Entity",
    "TokenEntry",
    "AuditEntry",
    "ReviewItem",
    "UploadResult",
    # Result types
    "RedactionResult",
    "RestorationResult",
    "ChatResult",
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


class PrivacyMode(Enum):
    """Display mode for PHI in restored text."""
    REDACTED = "redacted"
    SAFE_HARBOR = "safe_harbor"
    RESEARCH = "research"


class ReviewReason(Enum):
    """Why a detection needs human review."""
    LOW_CONFIDENCE = "low_confidence"
    AMBIGUOUS_CONTEXT = "ambiguous_context"
    ALLOWLIST_EDGE = "allowlist_edge"
    COREF_UNCERTAIN = "coref_uncertain"
    ML_ONLY = "ml_only"
    NEW_PATTERN = "new_pattern"


class AuditEventType(Enum):
    """Audit log event types."""
    SESSION_START = "SESSION_START"
    SESSION_END = "SESSION_END"
    SESSION_UNLOCK = "SESSION_UNLOCK"
    SESSION_LOCK = "SESSION_LOCK"
    PHI_DETECTED = "PHI_DETECTED"
    PHI_REDACTED = "PHI_REDACTED"
    PHI_RESTORED = "PHI_RESTORED"
    IMAGE_REDACTED = "IMAGE_REDACTED"  # Visual PHI redaction in image
    FILE_PROCESSED = "FILE_PROCESSED"  # File upload processing complete
    REVIEW_APPROVED = "REVIEW_APPROVED"
    REVIEW_REJECTED = "REVIEW_REJECTED"
    ERROR = "ERROR"
    CHAIN_FORK = "CHAIN_FORK"  # Hash chain recovery: forked after corruption


# IV3: Known entity types - used for validation
# Categories: Names, Dates, Locations, IDs, Contact, Financial, Medical, Secrets, Government, Other
# Sources: HIPAA Safe Harbor, i2b2 2014, AI4Privacy, Stanford PHI-BERT, custom detectors
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
    "ROOM", "ROOM_NUMBER",  # Hospital room numbers
    
    # --- IDENTIFIERS - Government ---
    "SSN", "SSN_PARTIAL", "US_SSN", "SOCIAL_SECURITY", "SOCIALSECURITYNUMBER",
    "UKNINUMBER",  # UK National Insurance Number
    "DRIVER_LICENSE", "LICENSE", "US_DRIVER_LICENSE", "DRIVERSLICENSE", "DRIVER_LICENSE_NUMBER",
    "STATE_ID", "STATEID",  # Non-driver state ID
    "PASSPORT", "US_PASSPORT", "PASSPORT_NUMBER", "PASSPORTNUMBER",
    "MILITARY_ID", "EDIPI", "DOD_ID",  # Military identifiers
    
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
    "BIOMETRIC_ID", "FINGERPRINT", "RETINAL", "IRIS", "VOICEPRINT", "DNA_ID",  # Safe Harbor #16
    "IMAGE_ID", "PHOTO_ID", "DICOM_UID",  # Safe Harbor #17
    "CERTIFICATE_NUMBER", "CERTIFICATION",  # Safe Harbor #11
    "CLAIM_NUMBER",  # Insurance claims
    
    # --- FINANCIAL - Traditional ---
    "CREDIT_CARD", "CREDIT_CARD_NUMBER", "CREDITCARDNUMBER", "CREDITCARD", "CC",
    "CREDIT_CARD_PARTIAL",
    "ACCOUNT_NUMBER", "ACCOUNT", "ACCOUNTNUMBER", "BANK_ACCOUNT",
    "IBAN", "IBAN_CODE", "IBANCODE",
    "ABA_ROUTING", "ROUTING", "ROUTING_NUMBER",
    "BIC", "SWIFT", "SWIFT_BIC",
    
    # --- FINANCIAL - Securities (from financial.py) ---
    "CUSIP",        # Committee on Uniform Securities Identification (9 chars)
    "ISIN",         # International Securities Identification Number (12 chars)
    "SEDOL",        # Stock Exchange Daily Official List (7 chars, UK)
    "FIGI",         # Financial Instrument Global Identifier (12 chars)
    "LEI",          # Legal Entity Identifier (20 chars)
    
    # --- CRYPTOCURRENCY (from financial.py) ---
    "BITCOIN_ADDRESS", "BITCOINADDRESS",
    "ETHEREUM_ADDRESS",
    "CRYPTO_SEED_PHRASE",
    "SOLANA_ADDRESS",
    "CARDANO_ADDRESS",
    "LITECOIN_ADDRESS",
    "DOGECOIN_ADDRESS",
    "XRP_ADDRESS",
    
    # --- SECRETS - Cloud Providers (from secrets.py) ---
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_STORAGE_KEY",
    "AZURE_CONNECTION_STRING",
    "AZURE_SAS_TOKEN",
    "GOOGLE_API_KEY",
    "GOOGLE_OAUTH_ID",
    "GOOGLE_OAUTH_SECRET",
    "FIREBASE_KEY",
    
    # --- SECRETS - Code Repositories (from secrets.py) ---
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "NUGET_KEY",
    
    # --- SECRETS - Communication Services (from secrets.py) ---
    "SLACK_TOKEN",
    "SLACK_WEBHOOK",
    "DISCORD_TOKEN",
    "DISCORD_WEBHOOK",
    "TWILIO_ACCOUNT_SID",
    "TWILIO_KEY",
    "TWILIO_TOKEN",
    "SENDGRID_KEY",
    "MAILCHIMP_KEY",
    
    # --- SECRETS - Payment & E-Commerce (from secrets.py) ---
    "STRIPE_KEY",
    "SQUARE_TOKEN",
    "SQUARE_SECRET",
    "SHOPIFY_TOKEN",
    "SHOPIFY_KEY",
    "SHOPIFY_SECRET",
    
    # --- SECRETS - Infrastructure (from secrets.py) ---
    "HEROKU_KEY",
    "DATADOG_KEY",
    "NEWRELIC_KEY",
    "DATABASE_URL",
    
    # --- SECRETS - Authentication (from secrets.py) ---
    "PRIVATE_KEY",
    "JWT",
    "BASIC_AUTH",
    "BEARER_TOKEN",
    "PASSWORD",
    "API_KEY",
    "SECRET",
    
    # --- GOVERNMENT - Classification (from government.py) ---
    "CLASSIFICATION_LEVEL",     # TOP SECRET, SECRET, CONFIDENTIAL, etc.
    "CLASSIFICATION_MARKING",   # Full markings with caveats (TS//SCI//NOFORN)
    "SCI_MARKING",              # Sensitive Compartmented Information
    "DISSEMINATION_CONTROL",    # NOFORN, REL TO, ORCON, FOUO, etc.
    
    # --- GOVERNMENT - Contracts & Identifiers (from government.py) ---
    "CAGE_CODE",        # Commercial and Government Entity Code (5 chars)
    "DUNS_NUMBER",      # Data Universal Numbering System (9 digits, deprecated)
    "UEI",              # Unique Entity Identifier (12 chars, replaced DUNS)
    "DOD_CONTRACT",     # DoD contract numbers
    "GSA_CONTRACT",     # GSA schedule contract numbers
    
    # --- GOVERNMENT - Security & Export (from government.py) ---
    "CLEARANCE_LEVEL",  # Security clearance references
    "ITAR_MARKING",     # International Traffic in Arms Regulations
    "EAR_MARKING",      # Export Administration Regulations
    
    # --- PROFESSIONAL (i2b2) ---
    "PROFESSION", "OCCUPATION", "JOB", "JOB_TITLE", "JOBTITLE",
    
    # --- MEDICAL (context-only but still valid types) ---
    "DRUG", "MEDICATION", "LAB_TEST", "DIAGNOSIS", "PROCEDURE", "PAYER",
    "RX_NUMBER", "PRESCRIPTION", "SCRIPT",  # Prescription numbers
    
    # --- FACILITY / ORGANIZATION ---
    "FACILITY", "HOSPITAL", "ORG", "ORGANIZATION", "VENDOR",
    "COMPANYNAME", "COMPANY", "EMPLOYER",
    
    # --- STANFORD PHI-BERT SPECIFIC ---
    "HCW",  # Healthcare Worker
    "ID",   # Generic identifier
    
    # --- PHYSICAL DESCRIPTORS (from IDs) ---
    "PHYSICAL_DESC",  # Height, weight, eye color, sex, etc.
    
    # --- DOCUMENT IDS ---
    "DOCUMENT_ID", "ID_NUMBER",  # Document discriminator, generic IDs
    
    # --- SHIPPING / LOGISTICS ---
    "TRACKING_NUMBER", "SHIPMENT_ID",

    # --- OTHER ---
    "RELATIVE", "FAMILY",
    "UNIQUE_ID",
])


# Clinical entity types - detected for context/analytics but NOT redacted
# These are medical vocabulary, not patient identifiers
# The dictionary detector outputs these, but they should be excluded from redaction
CLINICAL_CONTEXT_TYPES = frozenset([
    "LAB_TEST",      # Laboratory tests (CBC, BMP, etc.)
    "DIAGNOSIS",     # ICD codes, condition names
    "MEDICATION",    # Drug names (not PHI unless tied to specific patient context)
    "DRUG",          # Alias for medication
    "PROCEDURE",     # CPT codes, procedure names
    "PAYER",         # Insurance company names (Blue Cross, etc.)
    "PHYSICAL_DESC", # Height, weight, sex, eye color - not PHI under Safe Harbor
])


def validate_entity_type(entity_type: str) -> bool:
    """Check if an entity type is known.

    Returns True if the entity type is in KNOWN_ENTITY_TYPES, False otherwise.
    Unknown types trigger a warning but are not rejected.
    """
    return entity_type in KNOWN_ENTITY_TYPES


def is_clinical_context_type(entity_type: str) -> bool:
    """Check if an entity type is clinical context (not PHI).

    Clinical context types are detected for analytics but should NOT be redacted.
    """
    return entity_type in CLINICAL_CONTEXT_TYPES


@dataclass
class Span:
    """A detected PHI/PII span with metadata."""
    start: int
    end: int
    text: str
    entity_type: str
    confidence: float
    detector: str
    tier: Tier
    safe_harbor_value: Optional[str] = None
    needs_review: bool = False
    review_reason: Optional[str] = None
    coref_anchor_value: Optional[str] = None  # For coref: original anchor text to share token
    token: Optional[str] = None  # The assigned token e.g. [NAME_1] - set during tokenization

    def __post_init__(self):
        # Enhanced validation
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
        # Validate tier is a proper Tier enum value
        if isinstance(self.tier, int) and not isinstance(self.tier, Tier):
            self.tier = Tier.from_value(self.tier)
        # IV3: Warn on unknown entity types (don't reject - could be new detector)
        if not validate_entity_type(self.entity_type):
            import logging
            logging.getLogger(__name__).warning(
                f"Unknown entity type: {self.entity_type}. "
                "Consider adding to KNOWN_ENTITY_TYPES."
            )

    def overlaps(self, other: 'Span') -> bool:
        return not (self.end <= other.start or other.end <= self.start)

    def __len__(self) -> int:
        return self.end - self.start

    def __repr__(self) -> str:
        """Safe repr that doesn't expose PHI text."""
        return (
            f"Span(start={self.start}, end={self.end}, "
            f"entity_type={self.entity_type!r}, confidence={self.confidence}, "
            f"detector={self.detector!r}, tier={self.tier})"
        )


@dataclass
class Mention:
    """
    A single occurrence of PHI in text (Phase 2 entity identity refactor).

    Mentions are grouped into Entities by the EntityResolver. Multiple mentions
    may refer to the same real-world entity (e.g., "John Smith", "John", "he").

    The key insight is that semantic_role (patient, provider, relative) is
    metadata about HOW the entity is referenced, not WHO the entity is.
    "John" as a patient and "John" as a provider are the SAME person.

    Attributes:
        span: The detected Span with position and text
        semantic_role: Role context ("patient", "provider", "relative", "unknown")
        confidence: Detection confidence (inherited from span)
        source: Detector that found this mention
        entity_id: UUID of the Entity this mention refers to (set by EntityResolver)
    """
    span: "Span"
    semantic_role: str = "unknown"  # patient, provider, relative, unknown
    confidence: float = 0.0
    source: str = ""
    entity_id: Optional[str] = None

    def __post_init__(self):
        # Default confidence from span if not set
        if self.confidence == 0.0 and self.span:
            self.confidence = self.span.confidence
        # Default source from span detector
        if not self.source and self.span:
            self.source = self.span.detector
        # Validate semantic role
        valid_roles = {"patient", "provider", "relative", "unknown"}
        if self.semantic_role not in valid_roles:
            self.semantic_role = "unknown"

    @property
    def text(self) -> str:
        """Get the mention text."""
        return self.span.text if self.span else ""

    @property
    def entity_type(self) -> str:
        """Get the base entity type (without role suffix)."""
        if not self.span:
            return ""
        etype = self.span.entity_type
        # Strip role suffix to get base type
        for suffix in ("_PATIENT", "_PROVIDER", "_RELATIVE"):
            if etype.endswith(suffix):
                return "NAME"  # Base type for names
        return etype

    def __repr__(self) -> str:
        """Safe repr without PHI."""
        return (
            f"Mention(start={self.span.start}, end={self.span.end}, "
            f"role={self.semantic_role!r}, entity_id={self.entity_id!r})"
        )


@dataclass
class Entity:
    """
    A real-world entity referenced by one or more mentions (Phase 2).

    The Entity represents the actual person, organization, or identifier.
    Multiple mentions in text may refer to the same Entity:
    - "John Smith" and "John" → same Entity
    - "John" as patient and "John" as provider → same Entity (role is context, not identity)
    - "he" (pronoun resolved to "John") → same Entity

    The entity_id is the primary key for token lookup, NOT (value, entity_type).
    This fixes the core architectural flaw where semantic role affected identity.

    Attributes:
        id: UUID for this entity (used as token key)
        entity_type: Base type ("NAME", "SSN", "DATE", etc.)
        canonical_value: Best/longest representation of this entity
        mentions: All mentions that refer to this entity
        token: The assigned token (e.g., "[NAME_1]") - set during tokenization
        metadata: Non-PHI metadata (gender, confidence, etc.)
    """
    id: str  # UUID
    entity_type: str  # Base type: "NAME", "SSN", "DATE", etc.
    canonical_value: str  # Best representation (e.g., "John Smith" over "John")
    mentions: List["Mention"] = field(default_factory=list)
    token: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_mention(self, mention: "Mention") -> None:
        """Add a mention to this entity."""
        mention.entity_id = self.id
        self.mentions.append(mention)
        # Update canonical value if this mention is longer/better
        if len(mention.text) > len(self.canonical_value):
            self.canonical_value = mention.text

    @property
    def all_values(self) -> List[str]:
        """Get all text values for this entity."""
        return [m.text for m in self.mentions]

    @property
    def roles(self) -> set:
        """Get all semantic roles for this entity."""
        return {m.semantic_role for m in self.mentions}

    @property
    def highest_confidence(self) -> float:
        """Get highest confidence among all mentions."""
        if not self.mentions:
            return 0.0
        return max(m.confidence for m in self.mentions)

    def __repr__(self) -> str:
        """Safe repr without PHI."""
        return (
            f"Entity(id={self.id!r}, type={self.entity_type!r}, "
            f"mentions={len(self.mentions)}, token={self.token!r})"
        )


@dataclass
class TokenEntry:
    """A stored token mapping."""
    token: str
    entity_type: str
    original_value: str
    safe_harbor_value: str
    session_id: str
    created_at: datetime = field(default_factory=datetime.now)

    def __repr__(self) -> str:
        """Safe repr that doesn't expose PHI (original_value, safe_harbor_value)."""
        return (
            f"TokenEntry(token={self.token!r}, entity_type={self.entity_type!r}, "
            f"session_id={self.session_id!r})"
        )


@dataclass
class AuditEntry:
    """A single audit log entry."""
    sequence: int
    event_type: AuditEventType
    timestamp: datetime
    session_id: str
    data: Dict[str, Any]
    prev_hash: str
    entry_hash: str


@dataclass
class ReviewItem:
    """An item flagged for human review.
    
    M2 FIX: Does not store original PHI text - only token reference.
    """
    id: str
    token: str  # e.g., [NAME_1] - the token that was assigned
    entity_type: str
    confidence: float
    reason: ReviewReason
    context: str  # Redacted context
    suggested_action: str
    # Removed 'span' field which contained original PHI
    created_at: datetime = field(default_factory=datetime.now)
    decision: Optional[str] = None
    decided_at: Optional[datetime] = None


@dataclass
class UploadResult:
    """Result of processing an uploaded file."""
    job_id: str
    filename: str
    original_text: str
    redacted_text: str
    spans: List[Span]
    pages: int = 1
    processing_time_ms: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class RedactionResult:
    """Result of redacting text.
    
    NOTE: Original text intentionally NOT stored here (C2 FIX).
    Use input_hash for correlation if needed.
    """
    redacted: str
    spans: List["Span"]
    tokens_created: List[str]
    needs_review: List[dict]
    processing_time_ms: float
    input_hash: str = ""  # SHA256 hash for correlation (first 32 chars)
    normalized_input: str = ""  # Normalized text (spans reference this)

    def __repr__(self) -> str:
        """Safe repr that doesn't expose PHI in normalized_input."""
        return (
            f"RedactionResult(redacted=<{len(self.redacted)} chars>, "
            f"spans={len(self.spans)}, tokens={len(self.tokens_created)}, "
            f"processing_time_ms={self.processing_time_ms:.2f})"
        )


@dataclass
class RestorationResult:
    """Result of restoring tokens."""
    original: str
    restored: str
    tokens_found: List[str]
    tokens_unknown: List[str]

    def __repr__(self) -> str:
        """Safe repr that doesn't expose PHI in original/restored text."""
        return (
            f"RestorationResult(original=<{len(self.original)} chars>, "
            f"restored=<{len(self.restored)} chars>, "
            f"tokens_found={len(self.tokens_found)}, tokens_unknown={len(self.tokens_unknown)})"
        )


@dataclass
class ChatResult:
    """Result of end-to-end chat."""
    request_text: str
    redacted_request: str
    response_text: str
    restored_response: str
    model: str
    provider: str
    tokens_used: int
    latency_ms: float
    spans: List["Span"]  # Detected PHI spans in user message
    conversation_id: Optional[str] = None
    error: Optional[str] = None
    normalized_input: str = ""  # Normalized text (spans reference this)

    def __repr__(self) -> str:
        """Safe repr that doesn't expose PHI in request/response text."""
        return (
            f"ChatResult(model={self.model!r}, provider={self.provider!r}, "
            f"tokens_used={self.tokens_used}, latency_ms={self.latency_ms:.2f}, "
            f"spans={len(self.spans)}, error={self.error!r})"
        )
