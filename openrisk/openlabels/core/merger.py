"""
OpenLabels Entity Merger.

Merges entities from multiple adapter inputs using conservative union.

The merger implements a "defense in depth" approach:
- When multiple adapters detect the same entity type, take the MAX count
- When multiple adapters have different confidence, take the MAX confidence
- This ensures no sensitive data is underreported

Merge Strategies:
- CONSERVATIVE_UNION: Max count and max confidence per type (default)
- SUM_COUNTS: Sum counts, max confidence (for aggregate reporting)
- FIRST_WINS: First adapter's values take precedence

Example:
    >>> from openlabels.core.merger import merge_inputs, MergeStrategy
    >>>
    >>> macie_input = macie_adapter.extract(findings, metadata)
    >>> scanner_input = scanner_adapter.extract(content)
    >>> merged_entities, avg_confidence = merge_inputs(
    ...     [macie_input, scanner_input],
    ...     strategy=MergeStrategy.CONSERVATIVE_UNION
    ... )
"""

from enum import Enum
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field

from ..adapters.base import Entity, NormalizedInput, NormalizedContext, ExposureLevel
from .constants import CONFIDENCE_WHEN_NO_SPANS, DEFAULT_CONFIDENCE_THRESHOLD
from .entity_types import normalize_entity_type


class MergeStrategy(Enum):
    """Entity merge strategies."""
    CONSERVATIVE_UNION = "conservative_union"  # Max count, max confidence
    SUM_COUNTS = "sum_counts"                  # Sum counts, max confidence
    FIRST_WINS = "first_wins"                  # First adapter wins


@dataclass
class MergedEntity:
    """
    Result of merging an entity type across multiple sources.
    """
    type: str
    count: int
    confidence: float
    sources: List[str]  # Which adapters detected this
    positions: List[Tuple[int, int]] = field(default_factory=list)


@dataclass
class MergeResult:
    """
    Complete result of merging multiple adapter inputs.
    """
    entities: List[MergedEntity]
    entity_counts: Dict[str, int]  # {type: count} for scorer
    average_confidence: float
    exposure: str  # Highest exposure from inputs
    sources: Set[str]  # All sources that contributed

    # Original inputs preserved for reference
    input_count: int

    def get_entity(self, entity_type: str) -> Optional[MergedEntity]:
        """Get merged entity by type."""
        entity_type = entity_type.upper()
        for e in self.entities:
            if e.type.upper() == entity_type:
                return e
        return None

    def has_entity(self, entity_type: str) -> bool:
        """Check if an entity type was detected."""
        return self.get_entity(entity_type) is not None



# --- Merge Functions ---


def merge_inputs(
    inputs: List[NormalizedInput],
    strategy: MergeStrategy = MergeStrategy.CONSERVATIVE_UNION,
) -> Tuple[Dict[str, int], float]:
    """
    Merge entities from multiple adapter inputs.

    This is the simple interface that returns just entity counts and confidence,
    compatible with the scorer.

    Args:
        inputs: List of NormalizedInput from adapters
        strategy: Merge strategy to use

    Returns:
        Tuple of (entity_counts dict, average_confidence)

    Example:
        >>> entities, confidence = merge_inputs([macie_input, dlp_input])
        >>> result = score(entities, exposure="PUBLIC", confidence=confidence)
    """
    result = merge_inputs_full(inputs, strategy)
    return result.entity_counts, result.average_confidence


def merge_inputs_full(
    inputs: List[NormalizedInput],
    strategy: MergeStrategy = MergeStrategy.CONSERVATIVE_UNION,
) -> MergeResult:
    """
    Merge entities from multiple adapter inputs with full detail.

    This is the comprehensive interface that returns the complete MergeResult
    with all metadata preserved.

    Args:
        inputs: List of NormalizedInput from adapters
        strategy: Merge strategy to use

    Returns:
        MergeResult with merged entities, counts, confidence, and metadata
    """
    if not inputs:
        return MergeResult(
            entities=[],
            entity_counts={},
            average_confidence=CONFIDENCE_WHEN_NO_SPANS,
            exposure="PRIVATE",
            sources=set(),
            input_count=0,
        )

    # Track merged data
    merged: Dict[str, Dict] = {}  # {type: {count, confidence, sources, positions}}
    sources: Set[str] = set()

    for inp in inputs:
        for entity in inp.entities:
            entity_type = entity.type.upper()  # Normalize to uppercase
            sources.add(entity.source)

            if entity_type not in merged:
                merged[entity_type] = {
                    "count": entity.count,
                    "confidence": entity.confidence,
                    "sources": [entity.source],
                    "positions": list(entity.positions) if entity.positions else [],
                }
            else:
                existing = merged[entity_type]

                # Apply merge strategy
                if strategy == MergeStrategy.CONSERVATIVE_UNION:
                    existing["count"] = max(existing["count"], entity.count)
                    existing["confidence"] = max(existing["confidence"], entity.confidence)
                elif strategy == MergeStrategy.SUM_COUNTS:
                    existing["count"] += entity.count
                    existing["confidence"] = max(existing["confidence"], entity.confidence)
                elif strategy == MergeStrategy.FIRST_WINS:
                    pass  # Keep first values

                # Always merge sources and positions
                if entity.source not in existing["sources"]:
                    existing["sources"].append(entity.source)
                if entity.positions:
                    existing["positions"].extend(entity.positions)

    # Build MergedEntity list
    merged_entities = [
        MergedEntity(
            type=etype,
            count=data["count"],
            confidence=data["confidence"],
            sources=data["sources"],
            positions=data["positions"],
        )
        for etype, data in merged.items()
    ]

    entity_counts = {
        normalize_entity_type(etype): data["count"]
        for etype, data in merged.items()
    }

    # Calculate average confidence
    if merged:
        avg_confidence = sum(
            data["confidence"] for data in merged.values()
        ) / len(merged)
    else:
        avg_confidence = CONFIDENCE_WHEN_NO_SPANS

    # Get highest exposure
    exposure = get_highest_exposure(inputs)

    return MergeResult(
        entities=merged_entities,
        entity_counts=entity_counts,
        average_confidence=avg_confidence,
        exposure=exposure,
        sources=sources,
        input_count=len(inputs),
    )


def merge_entities(
    entity_lists: List[List[Entity]],
    strategy: MergeStrategy = MergeStrategy.CONSERVATIVE_UNION,
) -> List[MergedEntity]:
    """
    Merge multiple lists of entities directly.

    Lower-level interface when you have raw Entity lists instead of
    NormalizedInput objects.

    Args:
        entity_lists: List of Entity lists to merge
        strategy: Merge strategy to use

    Returns:
        List of MergedEntity
    """
    merged: Dict[str, Dict] = {}

    for entities in entity_lists:
        for entity in entities:
            entity_type = entity.type.upper()

            if entity_type not in merged:
                merged[entity_type] = {
                    "count": entity.count,
                    "confidence": entity.confidence,
                    "sources": [entity.source],
                    "positions": list(entity.positions) if entity.positions else [],
                }
            else:
                existing = merged[entity_type]

                if strategy == MergeStrategy.CONSERVATIVE_UNION:
                    existing["count"] = max(existing["count"], entity.count)
                    existing["confidence"] = max(existing["confidence"], entity.confidence)
                elif strategy == MergeStrategy.SUM_COUNTS:
                    existing["count"] += entity.count
                    existing["confidence"] = max(existing["confidence"], entity.confidence)
                elif strategy == MergeStrategy.FIRST_WINS:
                    pass

                if entity.source not in existing["sources"]:
                    existing["sources"].append(entity.source)
                if entity.positions:
                    existing["positions"].extend(entity.positions)

    return [
        MergedEntity(
            type=etype,
            count=data["count"],
            confidence=data["confidence"],
            sources=data["sources"],
            positions=data["positions"],
        )
        for etype, data in merged.items()
    ]



# --- Exposure Helpers ---


EXPOSURE_ORDER = ["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"]


def get_highest_exposure(inputs: List[NormalizedInput]) -> str:
    """
    Get the highest (most exposed) exposure level from inputs.

    PUBLIC > ORG_WIDE > INTERNAL > PRIVATE

    Args:
        inputs: List of NormalizedInput from adapters

    Returns:
        Highest exposure level string
    """
    if not inputs:
        return "PRIVATE"

    highest_idx = 0
    for inp in inputs:
        exposure = _normalize_exposure(inp.context.exposure)
        if exposure in EXPOSURE_ORDER:
            idx = EXPOSURE_ORDER.index(exposure)
            highest_idx = max(highest_idx, idx)

    return EXPOSURE_ORDER[highest_idx]


def _normalize_exposure(exposure) -> str:
    """Normalize exposure to uppercase string."""
    if isinstance(exposure, ExposureLevel):
        return exposure.name
    if isinstance(exposure, str):
        return exposure.upper()
    return "PRIVATE"


def merge_contexts(contexts: List[NormalizedContext]) -> NormalizedContext:
    """
    Merge multiple contexts, taking most-exposed/least-protected values.

    This implements a "worst case" merge - if any context indicates
    high exposure or low protection, the merged result reflects that.

    Args:
        contexts: List of contexts to merge

    Returns:
        Merged NormalizedContext
    """
    if not contexts:
        return NormalizedContext(exposure="PRIVATE")

    if len(contexts) == 1:
        return contexts[0]

    # Start with first context as base
    merged = NormalizedContext(
        exposure=_normalize_exposure(contexts[0].exposure),
        cross_account_access=contexts[0].cross_account_access,
        anonymous_access=contexts[0].anonymous_access,
        encryption=contexts[0].encryption,
        versioning=contexts[0].versioning,
        access_logging=contexts[0].access_logging,
        retention_policy=contexts[0].retention_policy,
        last_modified=contexts[0].last_modified,
        last_accessed=contexts[0].last_accessed,
        staleness_days=contexts[0].staleness_days,
        has_classification=contexts[0].has_classification,
        classification_source=contexts[0].classification_source,
        path=contexts[0].path,
        owner=contexts[0].owner,
        size_bytes=contexts[0].size_bytes,
        file_type=contexts[0].file_type,
        is_archive=contexts[0].is_archive,
    )

    # Merge remaining contexts
    for ctx in contexts[1:]:
        # Take highest exposure
        ctx_exp = _normalize_exposure(ctx.exposure)
        merged_exp = _normalize_exposure(merged.exposure)
        if EXPOSURE_ORDER.index(ctx_exp) > EXPOSURE_ORDER.index(merged_exp):
            merged.exposure = ctx_exp

        # Take worst case for risk indicators
        merged.cross_account_access = merged.cross_account_access or ctx.cross_account_access
        merged.anonymous_access = merged.anonymous_access or ctx.anonymous_access

        # Take least protection for encryption
        encryption_order = ["none", "platform", "customer_managed"]
        if encryption_order.index(ctx.encryption) < encryption_order.index(merged.encryption):
            merged.encryption = ctx.encryption

        # Take best case for protection features
        merged.versioning = merged.versioning or ctx.versioning
        merged.access_logging = merged.access_logging or ctx.access_logging
        merged.retention_policy = merged.retention_policy or ctx.retention_policy

        # Take most recent dates
        if ctx.last_modified and (not merged.last_modified or ctx.last_modified > merged.last_modified):
            merged.last_modified = ctx.last_modified
        if ctx.last_accessed and (not merged.last_accessed or ctx.last_accessed > merged.last_accessed):
            merged.last_accessed = ctx.last_accessed

        # Take max staleness
        merged.staleness_days = max(merged.staleness_days, ctx.staleness_days)

        # Any classification is good
        merged.has_classification = merged.has_classification or ctx.has_classification
        if ctx.classification_source != "none":
            merged.classification_source = ctx.classification_source

    return merged



# --- Utility Functions ---


def deduplicate_positions(positions: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """
    Remove duplicate and overlapping position ranges.

    Args:
        positions: List of (start, end) tuples

    Returns:
        Deduplicated and merged positions
    """
    if not positions:
        return []

    # Sort by start position
    sorted_pos = sorted(set(positions))

    merged = [sorted_pos[0]]
    for current in sorted_pos[1:]:
        prev = merged[-1]
        if current[0] <= prev[1]:
            # Overlapping - merge
            merged[-1] = (prev[0], max(prev[1], current[1]))
        else:
            merged.append(current)

    return merged


def entities_to_counts(entities: List[Entity]) -> Dict[str, int]:
    """
    Convert Entity list to simple type->count dict.

    Args:
        entities: List of Entity objects

    Returns:
        Dict mapping entity type to total count
    """
    counts: Dict[str, int] = {}
    for e in entities:
        etype = normalize_entity_type(e.type)
        counts[etype] = counts.get(etype, 0) + e.count
    return counts


def counts_to_entities(
    counts: Dict[str, int],
    source: str = "merged",
    confidence: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> List[Entity]:
    """
    Convert type->count dict back to Entity list.

    Args:
        counts: Dict mapping entity type to count
        source: Source to set on entities
        confidence: Confidence to set on entities

    Returns:
        List of Entity objects
    """
    return [
        Entity(
            type=etype.upper(),
            count=count,
            confidence=confidence,
            source=source,
        )
        for etype, count in counts.items()
    ]



# --- Exports ---


__all__ = [
    "MergeStrategy",
    "MergedEntity",
    "MergeResult",
    "merge_inputs",
    "merge_inputs_full",
    "merge_entities",
    "get_highest_exposure",
    "merge_contexts",
    "deduplicate_positions",
    "entities_to_counts",
    "counts_to_entities",
    "EXPOSURE_ORDER",
]
