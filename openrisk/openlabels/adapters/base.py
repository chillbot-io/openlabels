"""
OpenLabels Adapter Protocol.

All adapters implement this interface and produce normalized output
that can be fed into the scoring engine.
"""

from typing import Protocol, List, Any, Optional, Tuple, Dict
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ExposureLevel(Enum):
    """
    Normalized exposure levels across all platforms.

    Levels:
        PRIVATE (0): Only owner or explicitly named principals
        INTERNAL (1): Same organization/tenant, requires authentication
        ORG_WIDE (2): Overly broad access (all authenticated, large groups)
        PUBLIC (3): Anonymous access, no authentication required

    For detailed platform-specific permission mappings (AWS S3, GCS, Azure,
    NTFS, NFS, M365), see docs/exposure-level-mappings.md
    """
    PRIVATE = 0
    INTERNAL = 1
    ORG_WIDE = 2
    PUBLIC = 3


# Valid exposure level names
VALID_EXPOSURE_LEVELS = frozenset({"PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"})


def normalize_exposure_level(exposure) -> str:
    """
    Normalize exposure level to canonical UPPERCASE string.

    Accepts:
        - ExposureLevel enum member
        - String (case-insensitive)

    Returns:
        Canonical UPPERCASE string: "PRIVATE", "INTERNAL", "ORG_WIDE", or "PUBLIC"

    Raises:
        ValueError: If exposure is not a valid level

    Examples:
        >>> normalize_exposure_level(ExposureLevel.PRIVATE)
        'PRIVATE'
        >>> normalize_exposure_level("public")
        'PUBLIC'
        >>> normalize_exposure_level("org_wide")
        'ORG_WIDE'
    """
    if isinstance(exposure, ExposureLevel):
        return exposure.name

    if isinstance(exposure, str):
        normalized = exposure.strip().upper()
        if normalized in VALID_EXPOSURE_LEVELS:
            return normalized
        raise ValueError(
            f"Invalid exposure level: '{exposure}'. "
            f"Valid levels: {sorted(VALID_EXPOSURE_LEVELS)}"
        )

    raise TypeError(
        f"Exposure must be string or ExposureLevel enum, got {type(exposure).__name__}"
    )


@dataclass
class Entity:
    """A detected entity with metadata."""
    type: str                       # Canonical entity type (e.g., "SSN", "CREDIT_CARD")
    count: int                      # Number of occurrences
    confidence: float               # Detection confidence (0.0-1.0)
    source: str                     # Which adapter detected this
    positions: List[Tuple[int, int]] = field(default_factory=list)  # [(start, end), ...]


@dataclass
class NormalizedContext:
    """
    Normalized file/object context across all platforms.

    Used by the scoring engine to apply exposure multipliers and
    additional context adjustments to the risk score.

    Exposure field is validated and normalized to uppercase.
    Accepts ExposureLevel enum or case-insensitive string.
    """
    # Exposure factors
    exposure: str = "PRIVATE"       # PRIVATE, INTERNAL, ORG_WIDE, PUBLIC
    cross_account_access: bool = False    # Access from other accounts/tenants
    anonymous_access: bool = False        # Anonymous/public access

    # Protection factors
    encryption: str = "none"        # none, platform, customer_managed
    versioning: bool = False        # Object versioning enabled
    access_logging: bool = False    # Access logging enabled
    retention_policy: bool = False  # Retention/immutability policy

    # Staleness
    last_modified: Optional[str] = None   # ISO timestamp
    last_accessed: Optional[str] = None   # ISO timestamp (if available)
    staleness_days: int = 0               # Days since last modified

    # Classification source
    has_classification: bool = False      # Has external classification
    classification_source: str = "none"   # macie, dlp, purview, scanner, none

    # File info
    path: str = ""                  # File path or object key
    owner: Optional[str] = None     # Owner identifier
    size_bytes: int = 0             # File size
    file_type: str = ""             # MIME type or extension
    is_archive: bool = False        # Whether this is a compressed archive

    def __post_init__(self):
        """Validate and normalize exposure level."""
        self.exposure = normalize_exposure_level(self.exposure)


@dataclass
class NormalizedInput:
    """Standard input to the OpenLabels scorer."""
    entities: List[Entity]
    context: NormalizedContext


class Adapter(Protocol):
    """
    All adapters implement this interface.

    Adapters extract entities and context from various sources:
    - Cloud DLP services (Macie, GCP DLP, Purview)
    - Local scanners
    - Other classification tools (Presidio, etc.)
    """

    def extract(self, source: Any, metadata: Any) -> NormalizedInput:
        """
        Extract entities and context from a source.

        Args:
            source: The detection results (findings, classifications, etc.)
            metadata: Platform-specific metadata (S3, GCS, Blob, filesystem)

        Returns:
            NormalizedInput ready for scoring
        """
        ...



# --- Helper Functions ---


def calculate_staleness_days(last_modified: Optional[str]) -> int:
    """Calculate days since last modification."""
    if not last_modified:
        return 0
    try:
        if isinstance(last_modified, str):
            # Parse ISO format
            if 'T' in last_modified:
                dt = datetime.fromisoformat(last_modified.replace('Z', '+00:00'))
            else:
                dt = datetime.fromisoformat(last_modified)
        else:
            dt = last_modified
        delta = datetime.now(dt.tzinfo) - dt
        return max(0, delta.days)
    except (ValueError, TypeError, AttributeError) as e:
        logger.debug(f"Could not calculate staleness from '{last_modified}': {e}")
        return 0


ARCHIVE_EXTENSIONS = frozenset({'.zip', '.tar', '.gz', '.tgz', '.tar.gz', '.7z', '.rar', '.bz2'})


def is_archive(filename: str) -> bool:
    """Check if file is an archive based on extension."""
    filename_lower = filename.lower()
    return any(filename_lower.endswith(ext) for ext in ARCHIVE_EXTENSIONS)


class EntityAggregator:
    """
    Utility for aggregating detected entities by type.

    Handles the common pattern across all adapters:
    - Aggregate counts (sum)
    - Aggregate confidence (max)
    - Track positions (optional)
    - Convert to List[Entity]

    Usage:
        >>> agg = EntityAggregator(source="macie")
        >>> agg.add("SSN", count=5, confidence=0.95)
        >>> agg.add("SSN", count=3, confidence=0.85)  # Aggregates with existing
        >>> agg.add("EMAIL", count=2, confidence=0.90)
        >>> entities = agg.to_entities()
        >>> # Returns [Entity(type="SSN", count=8, confidence=0.95, source="macie"), ...]
    """

    def __init__(self, source: str):
        """
        Initialize aggregator.

        Args:
            source: Source identifier for entities (e.g., "macie", "dlp", "nfs")
        """
        self.source = source
        self._data: Dict[str, Dict[str, Any]] = {}

    def add(
        self,
        entity_type: str,
        count: int = 1,
        confidence: float = 0.8,
        positions: Optional[List[Tuple[int, int]]] = None,
    ) -> None:
        """
        Add an entity detection to the aggregator.

        Args:
            entity_type: Canonical entity type (should already be normalized)
            count: Number of occurrences to add
            confidence: Detection confidence (0.0-1.0)
            positions: Optional list of (start, end) positions
        """
        if not entity_type:
            return

        if entity_type not in self._data:
            self._data[entity_type] = {
                "count": 0,
                "confidence": 0.0,
                "positions": [],
            }

        self._data[entity_type]["count"] += count
        self._data[entity_type]["confidence"] = max(
            self._data[entity_type]["confidence"], confidence
        )
        if positions:
            self._data[entity_type]["positions"].extend(positions)

    def to_entities(self) -> List[Entity]:
        """
        Convert aggregated data to list of Entity objects.

        Returns:
            List of Entity objects, one per unique entity type
        """
        return [
            Entity(
                type=entity_type,
                count=data["count"],
                confidence=data["confidence"],
                source=self.source,
                positions=data["positions"],
            )
            for entity_type, data in self._data.items()
        ]

    def __len__(self) -> int:
        """Return number of unique entity types."""
        return len(self._data)
