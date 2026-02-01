"""Dashboard data models (Qt-independent)."""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class HeatmapNode:
    """Node in the hierarchical heatmap data structure."""
    name: str
    path: str  # Full path to this node
    entity_counts: Dict[str, int] = field(default_factory=dict)
    total_score: int = 0
    file_count: int = 0
    children: Dict[str, "HeatmapNode"] = field(default_factory=dict)

    def add_entity(self, entity_type: str, count: int = 1):
        """Add entity counts."""
        self.entity_counts[entity_type] = self.entity_counts.get(entity_type, 0) + count

    def get_intensity(self, entity_type: str, max_count: int) -> float:
        """Get intensity (0-1) for an entity type."""
        if max_count <= 0:
            return 0.0
        count = self.entity_counts.get(entity_type, 0)
        return min(1.0, count / max_count)

    @property
    def total_entities(self) -> int:
        """Total entity count across all types."""
        return sum(self.entity_counts.values())
