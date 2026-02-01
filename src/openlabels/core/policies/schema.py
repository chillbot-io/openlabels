"""
Schema definitions for policy packs.

Policy packs are YAML/JSON files that define:
- What entity types trigger the policy
- How entities can be combined (AND/OR logic)
- Risk levels and compliance requirements
- Retention and handling requirements
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class RiskLevel(str, Enum):
    """Risk levels for classified data."""

    MINIMAL = "minimal"      # Public data, no restrictions
    LOW = "low"              # Internal use, basic controls
    MEDIUM = "medium"        # Confidential, access controls required
    HIGH = "high"            # Sensitive, encryption required
    CRITICAL = "critical"    # Highly regulated, full audit trail


class PolicyCategory(str, Enum):
    """Regulatory/compliance categories."""

    # US Regulations
    HIPAA = "hipaa"          # Health data
    FERPA = "ferpa"          # Education records
    GLBA = "glba"            # Financial data
    SOX = "sox"              # Financial reporting
    COPPA = "coppa"          # Children's data

    # State/Regional US
    CCPA = "ccpa"            # California
    CPRA = "cpra"            # California (updated)
    NYDFS = "nydfs"          # New York financial
    SHIELD = "shield"        # New York (broader)

    # International
    GDPR = "gdpr"            # EU
    LGPD = "lgpd"            # Brazil
    PIPEDA = "pipeda"        # Canada
    POPIA = "popia"          # South Africa
    PDPA = "pdpa"            # Singapore

    # Industry
    PCI_DSS = "pci_dss"      # Payment cards
    SOC2 = "soc2"            # Service organizations
    ISO27001 = "iso27001"    # Information security

    # General
    PII = "pii"              # Personal identifiable information
    PHI = "phi"              # Protected health information
    CUSTOM = "custom"        # User-defined


@dataclass
class PolicyTrigger:
    """
    Defines when a policy is triggered.

    Supports:
    - any_of: Triggered if ANY of these entity types are present
    - all_of: Triggered only if ALL of these entity types are present
    - combinations: List of all_of conditions (OR between them)
    - min_confidence: Minimum confidence threshold for matches
    - min_count: Minimum number of matches required
    """

    # Simple triggers - any single entity type
    any_of: list[str] = field(default_factory=list)

    # Combination triggers - all must be present
    all_of: list[str] = field(default_factory=list)

    # Multiple combination options (OR between combinations)
    combinations: list[list[str]] = field(default_factory=list)

    # Thresholds
    min_confidence: float = 0.5
    min_count: int = 1

    # Exclusions - don't trigger if these are the only matches
    exclude_if_only: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Check if trigger has no conditions."""
        return not self.any_of and not self.all_of and not self.combinations


@dataclass
class DataSubjectRights:
    """GDPR-style data subject rights that apply to this policy."""

    access: bool = False          # Right to access data
    rectification: bool = False   # Right to correct data
    erasure: bool = False         # Right to deletion
    portability: bool = False     # Right to data portability
    restriction: bool = False     # Right to restrict processing
    objection: bool = False       # Right to object to processing


@dataclass
class RetentionPolicy:
    """Data retention requirements."""

    max_days: Optional[int] = None          # Maximum retention period
    min_days: Optional[int] = None          # Minimum retention (legal hold)
    review_frequency_days: Optional[int] = None  # Required review frequency
    auto_delete: bool = False               # Auto-delete after max_days


@dataclass
class HandlingRequirements:
    """Security and handling requirements for matched data."""

    encryption_required: bool = False
    encryption_at_rest: bool = False
    encryption_in_transit: bool = False
    tokenization_required: bool = False
    masking_required: bool = False
    audit_access: bool = False
    access_logging: bool = False
    mfa_required: bool = False
    geographic_restrictions: list[str] = field(default_factory=list)  # Allowed regions
    prohibited_regions: list[str] = field(default_factory=list)        # Blocked regions


@dataclass
class PolicyPack:
    """
    A complete policy pack definition.

    Example YAML:
    ```yaml
    name: HIPAA PHI
    version: "1.0"
    category: phi
    description: Protected Health Information under HIPAA

    triggers:
      any_of:
        - medical_record_number
        - health_insurance_id
        - diagnosis_code
      combinations:
        - [person_name, date_of_birth, medical_facility]
        - [person_name, diagnosis]

    risk_level: critical

    handling:
      encryption_required: true
      audit_access: true

    retention:
      min_days: 2555  # 7 years
    ```
    """

    # Identity
    name: str
    version: str = "1.0"
    description: str = ""

    # Classification
    category: PolicyCategory = PolicyCategory.CUSTOM
    risk_level: RiskLevel = RiskLevel.HIGH

    # Trigger conditions
    triggers: PolicyTrigger = field(default_factory=PolicyTrigger)

    # Special category triggers (e.g., GDPR Article 9 special categories)
    special_category_triggers: PolicyTrigger = field(default_factory=PolicyTrigger)

    # Requirements
    handling: HandlingRequirements = field(default_factory=HandlingRequirements)
    retention: RetentionPolicy = field(default_factory=RetentionPolicy)
    data_subject_rights: DataSubjectRights = field(default_factory=DataSubjectRights)

    # Jurisdiction
    jurisdictions: list[str] = field(default_factory=list)  # e.g., ["US", "EU"]

    # Metadata
    enabled: bool = True
    priority: int = 0  # Higher = evaluated first
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Ensure category is enum
        if isinstance(self.category, str):
            self.category = PolicyCategory(self.category.lower())
        if isinstance(self.risk_level, str):
            self.risk_level = RiskLevel(self.risk_level.lower())


@dataclass
class EntityMatch:
    """An entity that matched during classification (input to policy engine)."""

    entity_type: str
    value: str
    confidence: float
    start: int
    end: int
    source: str = ""  # "ner", "regex", "hyperscan"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyMatch:
    """Details about how a policy was triggered."""

    policy_name: str
    trigger_type: str  # "any_of", "all_of", "combination"
    matched_entities: list[str]  # Entity types that triggered
    matched_values: list[str]    # Actual values (redacted for logging)


@dataclass
class PolicyResult:
    """
    Result of evaluating policies against classified data.

    Contains all matched policies and the combined requirements.
    """

    # Matched policies
    matches: list[PolicyMatch] = field(default_factory=list)

    # Combined risk level (highest of all matched)
    risk_level: RiskLevel = RiskLevel.MINIMAL

    # All triggered categories
    categories: set[PolicyCategory] = field(default_factory=set)

    # Combined handling requirements
    handling: HandlingRequirements = field(default_factory=HandlingRequirements)

    # Most restrictive retention
    retention: RetentionPolicy = field(default_factory=RetentionPolicy)

    # Combined data subject rights
    data_subject_rights: DataSubjectRights = field(default_factory=DataSubjectRights)

    # All jurisdictions that apply
    jurisdictions: set[str] = field(default_factory=set)

    # Summary flags
    has_phi: bool = False
    has_pii: bool = False
    has_pci: bool = False
    has_gdpr_special: bool = False

    @property
    def is_sensitive(self) -> bool:
        """Check if any sensitive data policies matched."""
        return len(self.matches) > 0

    @property
    def requires_encryption(self) -> bool:
        """Check if encryption is required by any matched policy."""
        return self.handling.encryption_required

    @property
    def policy_names(self) -> list[str]:
        """Get names of all matched policies."""
        return [m.policy_name for m in self.matches]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "risk_level": self.risk_level.value,
            "categories": [c.value for c in self.categories],
            "policies": self.policy_names,
            "has_phi": self.has_phi,
            "has_pii": self.has_pii,
            "has_pci": self.has_pci,
            "has_gdpr_special": self.has_gdpr_special,
            "requires_encryption": self.requires_encryption,
            "jurisdictions": list(self.jurisdictions),
        }
