"""Entity proximity analysis for co-occurrence-based confidence boosting.

After detection, groups entities that appear near each other in the
document into "clusters".  Entities within a proximity window form
clusters that likely relate to the same person or record.

Within each cluster, low-confidence entities can receive a small
confidence boost when they co-occur with high-confidence related
entities (e.g. a NAME near a high-confidence SSN is more likely real).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..types import Span, normalize_entity_type

logger = logging.getLogger(__name__)

# Default proximity window (characters).
DEFAULT_PROXIMITY_CHARS = 500

# Relationship map: entity type → set of types that provide boosting context.
_BOOST_RELATIONSHIPS: dict[str, set[str]] = {
    "NAME": {"SSN", "MRN", "DATE_DOB", "PHONE", "EMAIL", "ADDRESS", "DRIVER_LICENSE"},
    "FIRSTNAME": {"SSN", "MRN", "DATE_DOB", "PHONE", "EMAIL"},
    "LASTNAME": {"SSN", "MRN", "DATE_DOB", "PHONE", "EMAIL"},
    "SSN": {"NAME", "FIRSTNAME", "LASTNAME", "DATE_DOB", "ADDRESS"},
    "ADDRESS": {"NAME", "PHONE", "EMAIL", "SSN"},
    "MRN": {"NAME", "DATE_DOB", "PHONE"},
    "DATE_DOB": {"NAME", "SSN", "MRN"},
}

# Maximum confidence boost a span can receive.
MAX_CONFIDENCE_BOOST = 0.10

# Minimum confidence of the "anchor" entity for it to provide a boost.
# Set to 0.40 so calibrated ML spans (range [0.10, 0.50]) with high raw
# confidence can serve as anchors.  PATTERN spans (floor 0.50) and
# CHECKSUM spans (floor 0.90) always exceed this threshold.
MIN_ANCHOR_CONFIDENCE = 0.40


@dataclass
class EntityCluster:
    """A cluster of entities that co-occur within a proximity window."""

    id: int
    spans: list[Span] = field(default_factory=list)
    entity_types: set[str] = field(default_factory=set)

    @property
    def has_identifier(self) -> bool:
        """Whether cluster contains a direct identifier."""
        identifiers = {"SSN", "MRN", "DRIVER_LICENSE", "PASSPORT", "CREDIT_CARD"}
        return bool(self.entity_types & identifiers)

    @property
    def has_name(self) -> bool:
        """Whether cluster contains a person name."""
        name_types = {"NAME", "FIRSTNAME", "LASTNAME", "NAME_PATIENT", "NAME_PROVIDER"}
        return bool(self.entity_types & name_types)


@dataclass
class ProximityResult:
    """Result of proximity analysis."""

    clusters: list[EntityCluster]
    boosted_spans: list[Span]
    boost_count: int
    original_span_count: int


def analyze_proximity(
    spans: list[Span],
    proximity_chars: int = DEFAULT_PROXIMITY_CHARS,
    enable_boosting: bool = True,
) -> ProximityResult:
    """Analyze entity proximity and optionally boost confidence.

    Algorithm:
        1. Sort spans by position.
        2. Sweep through: each span joins the current cluster if it
           starts within *proximity_chars* of the previous span's end.
        3. Within each cluster, boost low-confidence entities that
           co-occur with high-confidence related entities.

    Args:
        spans: Detected spans (already deduplicated).
        proximity_chars: Max gap between spans to cluster them.
        enable_boosting: Whether to apply confidence boosting.

    Returns:
        ProximityResult with clusters and (optionally) boosted spans.
    """
    if not spans:
        return ProximityResult([], [], 0, 0)

    sorted_spans = sorted(spans, key=lambda s: s.start)

    # --- Build clusters ---
    clusters: list[EntityCluster] = []
    current = EntityCluster(id=0)
    current.spans.append(sorted_spans[0])
    current.entity_types.add(normalize_entity_type(sorted_spans[0].entity_type))

    for span in sorted_spans[1:]:
        prev = current.spans[-1]
        gap = span.start - prev.end

        if gap > proximity_chars:
            clusters.append(current)
            current = EntityCluster(id=len(clusters))

        current.spans.append(span)
        current.entity_types.add(normalize_entity_type(span.entity_type))

    clusters.append(current)

    # --- Optional confidence boosting ---
    boosted_spans = list(sorted_spans)
    boost_count = 0

    if enable_boosting:
        span_to_idx = {id(s): i for i, s in enumerate(boosted_spans)}

        for cluster in clusters:
            if len(cluster.spans) < 2:
                continue

            # Find high-confidence anchors in this cluster
            anchors: dict[str, float] = {}
            for s in cluster.spans:
                norm = normalize_entity_type(s.entity_type)
                if s.confidence >= MIN_ANCHOR_CONFIDENCE:
                    anchors[norm] = max(anchors.get(norm, 0.0), s.confidence)

            if not anchors:
                continue

            # Boost eligible spans
            for s in cluster.spans:
                norm = normalize_entity_type(s.entity_type)
                boost_sources = _BOOST_RELATIONSHIPS.get(norm, set())
                if not boost_sources:
                    continue

                # Find strongest relevant anchor
                best_anchor_conf = 0.0
                for source_type in boost_sources:
                    if source_type in anchors:
                        best_anchor_conf = max(best_anchor_conf, anchors[source_type])

                if best_anchor_conf < MIN_ANCHOR_CONFIDENCE or s.confidence >= 0.90:
                    continue

                boost = min(MAX_CONFIDENCE_BOOST, best_anchor_conf * 0.10)
                new_confidence = min(1.0, s.confidence + boost)

                if new_confidence > s.confidence:
                    idx = span_to_idx.get(id(s))
                    if idx is not None:
                        boosted_spans[idx] = Span(
                            start=s.start,
                            end=s.end,
                            text=s.text,
                            entity_type=s.entity_type,
                            confidence=new_confidence,
                            detector=s.detector,
                            tier=s.tier,
                            context=s.context,
                            needs_review=s.needs_review,
                            review_reason=s.review_reason,
                            coref_anchor_value=s.coref_anchor_value,
                        )
                        boost_count += 1

    return ProximityResult(
        clusters=clusters,
        boosted_spans=boosted_spans,
        boost_count=boost_count,
        original_span_count=len(spans),
    )
