"""
OpenLabels Core Types.

Centralized type definitions for the OpenLabels system.
Import from here for convenient access to all core types.

This module re-exports types from their source modules and
adds additional utility types used across the system.

Usage:
    from openlabels.core.types import (
        Entity, NormalizedContext, NormalizedInput, ExposureLevel,
        ScoringResult, RiskTier, Label, LabelSet, ScanTrigger,
    )
"""

from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# Re-exports from source modules
from ..adapters.base import (
    Entity,
    NormalizedContext,
    NormalizedInput,
    ExposureLevel,
    Adapter,
    calculate_staleness_days,
    is_archive,
)

# From scorer - Scoring results
from .scorer import ScoringResult, RiskTier

# From labels - Label data model
from .labels import Label, LabelSet, VirtualLabelPointer

# From triggers - Scan triggers
from .triggers import ScanTrigger


@dataclass
class ScanResult:
    """
    Complete result from scanning a file or object.

    Combines the scoring result with the source label set and metadata.

    Note: Clarified optional vs required fields:
    - score: Optional[int] - None means not scanned, 0 means minimal risk
    - Use was_scanned property to check if file was successfully scanned
    - Use has_error property to check if an error occurred
    """
    # File/object info (path is REQUIRED)
    path: str
    size_bytes: int = 0
    file_type: str = ""

    # Scoring (Note: score is Optional - None means not scanned)
    score: Optional[int] = None
    tier: Optional[str] = None
    scoring_result: Optional[ScoringResult] = None

    # Labels
    label_set: Optional[LabelSet] = None
    entities: List[Entity] = field(default_factory=list)

    # Context
    context: Optional[NormalizedContext] = None

    # Scan metadata
    scan_triggers: List[ScanTrigger] = field(default_factory=list)
    scan_duration_ms: float = 0
    scanner_version: str = ""
    scanned_at: str = ""

    # Content verification
    content_hash: Optional[str] = None  # Quick hash for detecting file changes

    # Errors (if any)
    error: Optional[str] = None

    @property
    def was_scanned(self) -> bool:
        """
        Check if file was successfully scanned (Note).

        Returns True only if:
        - A score was computed (score is not None)
        - No error occurred

        Use this to distinguish between "minimal risk" (score=0) and
        "not scanned" (score=None).
        """
        return self.score is not None and self.error is None

    @property
    def has_error(self) -> bool:
        """Check if an error occurred during scanning (Note)."""
        return self.error is not None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "file_type": self.file_type,
            "score": self.score,
            "tier": self.tier,
            "entities": [
                {
                    "type": e.type,
                    "count": e.count,
                    "confidence": e.confidence,
                    "source": e.source,
                }
                for e in self.entities
            ],
            "context": {
                "exposure": self.context.exposure if self.context else "PRIVATE",
                "encryption": self.context.encryption if self.context else "none",
            } if self.context else None,
            "scan_triggers": [t.value for t in self.scan_triggers],
            "scan_duration_ms": self.scan_duration_ms,
            "scanned_at": self.scanned_at,
            "content_hash": self.content_hash,
            "error": self.error,
        }


@dataclass
class FilterCriteria:
    """
    Criteria for filtering scan results.

    Used by find(), quarantine(), and other batch operations.
    """
    # Score filters
    min_score: Optional[int] = None
    max_score: Optional[int] = None
    tier: Optional[str] = None  # CRITICAL, HIGH, MEDIUM, LOW, MINIMAL

    # Exposure filters
    exposure: Optional[str] = None  # PUBLIC, ORG_WIDE, INTERNAL, PRIVATE

    # Entity filters
    has_entity: Optional[str] = None  # Entity type (e.g., "SSN")
    entity_types: Optional[List[str]] = None  # List of types

    # Time filters (ISO timestamps or duration strings)
    modified_after: Optional[str] = None
    modified_before: Optional[str] = None
    accessed_after: Optional[str] = None

    # Protection filters
    encryption: Optional[str] = None  # none, platform, customer_managed

    # File filters
    path_pattern: Optional[str] = None  # Glob pattern
    file_type: Optional[str] = None  # MIME type or extension
    min_size: Optional[int] = None
    max_size: Optional[int] = None

    # Custom filter expression
    filter_expr: Optional[str] = None  # Query language expression

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {k: v for k, v in {
            "min_score": self.min_score,
            "max_score": self.max_score,
            "tier": self.tier,
            "exposure": self.exposure,
            "has_entity": self.has_entity,
            "entity_types": self.entity_types,
            "modified_after": self.modified_after,
            "modified_before": self.modified_before,
            "accessed_after": self.accessed_after,
            "encryption": self.encryption,
            "path_pattern": self.path_pattern,
            "file_type": self.file_type,
            "min_size": self.min_size,
            "max_size": self.max_size,
            "filter_expr": self.filter_expr,
        }.items() if v is not None}


@dataclass
class OperationResult:
    """
    Result of a batch operation (quarantine, move, delete, etc.).
    """
    success: bool
    operation: str  # "quarantine", "move", "delete", "encrypt", "restrict"
    source_path: str
    dest_path: Optional[str] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TreeNode:
    """
    A node in the risk tree for heatmap visualization.
    """
    name: str
    path: str
    is_directory: bool = True

    # Aggregate stats (for directories)
    total_files: int = 0
    total_size: int = 0
    max_score: int = 0
    avg_score: float = 0.0
    score_distribution: Dict[str, int] = field(default_factory=dict)  # tier -> count

    # File info (for files)
    score: Optional[int] = None
    tier: Optional[str] = None
    entities: List[str] = field(default_factory=list)  # Entity types found

    # Children (for directories)
    children: List["TreeNode"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "name": self.name,
            "path": self.path,
            "is_directory": self.is_directory,
        }
        if self.is_directory:
            result.update({
                "total_files": self.total_files,
                "total_size": self.total_size,
                "max_score": self.max_score,
                "avg_score": round(self.avg_score, 1),
                "score_distribution": self.score_distribution,
                "children": [c.to_dict() for c in self.children],
            })
        else:
            result.update({
                "score": self.score,
                "tier": self.tier,
                "entities": self.entities,
            })
        return result


class ReportFormat(Enum):
    """Supported report output formats."""
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    JSONL = "jsonl"  # JSON Lines (one object per line)
    MARKDOWN = "markdown"


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    format: ReportFormat = ReportFormat.JSON
    include_entities: bool = True
    include_context: bool = True
    include_positions: bool = False  # Entity positions in content
    group_by: Optional[str] = None  # "tier", "path", "entity_type"
    sort_by: str = "score"  # "score", "path", "tier", "date"
    sort_descending: bool = True
    limit: Optional[int] = None
    title: str = "OpenLabels Risk Report"


# Type aliases
PathLike = Union[str, Path]

# Entity list type
EntityList = List[Entity]

# Score range tuple
ScoreRange = Tuple[int, int]


__all__ = [
    # Re-exported from adapters.base
    "Entity",
    "NormalizedContext",
    "NormalizedInput",
    "ExposureLevel",
    "Adapter",
    "calculate_staleness_days",
    "is_archive",
    # Re-exported from scorer
    "ScoringResult",
    "RiskTier",
    # Re-exported from labels
    "Label",
    "LabelSet",
    "VirtualLabelPointer",
    # Re-exported from triggers
    "ScanTrigger",
    # New types
    "ScanResult",
    "FilterCriteria",
    "OperationResult",
    "TreeNode",
    "ReportFormat",
    "ReportConfig",
    # Type aliases
    "PathLike",
    "EntityList",
    "ScoreRange",
]
