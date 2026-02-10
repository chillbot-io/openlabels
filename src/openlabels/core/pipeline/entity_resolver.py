"""
Entity resolution for grouping mentions by identity.

Groups detected spans that refer to the same real-world entity.
Uses multi-sieve approach for high precision.

Example:
    "John Smith" detected at positions 10, 50, 100
    "Mr. Smith" detected at position 200
    "John" detected at position 300

    After resolution:
    - All 5 mentions grouped under entity_id "abc123"
    - Canonical form: "John Smith" (longest/first)

Sieves (applied in order):
1. Exact match: Same normalized text → same entity
2. Partial name match: "Smith" matches "John Smith" if multi-word
3. Coreference links: Use coref_anchor_value from pronoun resolution
"""

import uuid
from dataclasses import dataclass, field

from ..types import Span

# Entity types that should only match exactly (isolated)
ISOLATED_TYPES: set[str] = frozenset({
    "SSN",
    "MRN",
    "CREDIT_CARD",
    "ACCOUNT_NUMBER",
    "DRIVER_LICENSE",
    "PASSPORT",
    "PHONE",
    "EMAIL",
    "IP_ADDRESS",
})

# Entity types that represent person names
NAME_TYPES: set[str] = frozenset({
    "NAME",
    "NAME_PATIENT",
    "NAME_PROVIDER",
    "NAME_RELATIVE",
    "PERSON",
})


@dataclass
class Mention:
    """A single mention of an entity in text."""
    span: Span
    normalized_text: str
    words: set[str]


@dataclass
class Entity:
    """A resolved entity with all its mentions."""
    id: str
    entity_type: str
    canonical_value: str
    mentions: list[Mention] = field(default_factory=list)
    semantic_role: str | None = None  # patient, provider, etc.

    @property
    def count(self) -> int:
        return len(self.mentions)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "entity_type": self.entity_type,
            "canonical_value": self.canonical_value,
            "count": self.count,
            "positions": [(m.span.start, m.span.end) for m in self.mentions],
        }


class EntityResolver:
    """
    Multi-sieve entity resolution.

    Groups mentions referring to the same real-world entity.
    Uses union-find for efficient grouping.

    Usage:
        resolver = EntityResolver()
        entities = resolver.resolve(spans)
        for entity in entities:
            print(f"{entity.canonical_value}: {entity.count} mentions")
    """

    def __init__(self, min_confidence: float = 0.70):
        """
        Initialize the resolver.

        Args:
            min_confidence: Minimum confidence for a span to be considered
        """
        self.min_confidence = min_confidence

    def resolve(self, spans: list[Span]) -> list[Entity]:
        """
        Resolve entity mentions into grouped entities.

        Args:
            spans: Detected spans from detection engine

        Returns:
            List of Entity objects with grouped mentions
        """
        if not spans:
            return []

        # Filter by confidence
        eligible = [s for s in spans if s.confidence >= self.min_confidence]
        if not eligible:
            return []

        # Convert to mentions
        mentions = [self._to_mention(s) for s in eligible]

        # Apply sieves
        groups = self._apply_sieves(mentions)

        # Convert groups to entities
        entities = self._groups_to_entities(groups, mentions)

        return entities

    def _to_mention(self, span: Span) -> Mention:
        """Convert a Span to a Mention."""
        normalized = self._normalize_text(span.text)
        words = self._get_words(normalized, span.entity_type)
        return Mention(span=span, normalized_text=normalized, words=words)

    def _normalize_text(self, text: str) -> str:
        """Normalize text for matching."""
        return text.lower().strip()

    def _get_words(self, text: str, entity_type: str) -> set[str]:
        """Extract words from text, excluding titles."""
        if entity_type not in NAME_TYPES:
            return set()

        titles = {"dr", "mr", "mrs", "ms", "prof", "rev", "jr", "sr", "ii", "iii", "iv"}
        words = set(text.replace(".", "").split())
        return words - titles

    def _apply_sieves(self, mentions: list[Mention]) -> dict[int, int]:
        """
        Apply sieves to group mentions.

        Returns:
            Dict mapping mention index to group ID (union-find parent)
        """
        n = len(mentions)
        parent = list(range(n))  # Union-find

        def find(x: int) -> int:
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x: int, y: int) -> None:
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        # Index by normalized text and coref anchors
        text_index: dict[str, list[int]] = {}
        coref_index: dict[str, list[int]] = {}
        word_index: dict[str, list[int]] = {}

        for i, m in enumerate(mentions):
            # Index by normalized text
            if m.normalized_text not in text_index:
                text_index[m.normalized_text] = []
            text_index[m.normalized_text].append(i)

            # Index by coref anchor
            if m.span.coref_anchor_value:
                anchor = m.span.coref_anchor_value.lower()
                if anchor not in coref_index:
                    coref_index[anchor] = []
                coref_index[anchor].append(i)

            # Index by words (for NAME types)
            for word in m.words:
                if len(word) >= 2:
                    if word not in word_index:
                        word_index[word] = []
                    word_index[word].append(i)

        # Sieve 1: Exact string match
        for indices in text_index.values():
            if len(indices) > 1:
                for i in range(1, len(indices)):
                    union(indices[0], indices[i])

        # Sieve 2: Partial name match (conservative)
        for word, indices in word_index.items():
            if len(indices) > 1:
                # Only merge if at least one is multi-word
                multi_word = [i for i in indices if len(mentions[i].words) > 1]
                single_word = [i for i in indices if len(mentions[i].words) == 1]

                # Multi-word names can absorb single-word partials
                if multi_word and single_word:
                    for si in single_word:
                        union(multi_word[0], si)

                # Multi-word names with overlapping words
                for i in range(len(multi_word)):
                    for j in range(i + 1, len(multi_word)):
                        mi, mj = mentions[multi_word[i]], mentions[multi_word[j]]
                        if mi.words & mj.words:  # Shared words
                            union(multi_word[i], multi_word[j])

        # Sieve 3: Coreference links
        for anchor, indices in coref_index.items():
            # Find mentions that match the anchor text
            if anchor in text_index:
                anchor_indices = text_index[anchor]
                for i in indices:
                    for ai in anchor_indices:
                        union(i, ai)

        return {i: find(i) for i in range(n)}

    def _groups_to_entities(
        self,
        groups: dict[int, int],
        mentions: list[Mention]
    ) -> list[Entity]:
        """Convert union-find groups to Entity objects."""
        # Group mentions by their root
        grouped: dict[int, list[int]] = {}
        for i, root in groups.items():
            if root not in grouped:
                grouped[root] = []
            grouped[root].append(i)

        entities = []
        for indices in grouped.values():
            group_mentions = [mentions[i] for i in indices]

            # Find canonical form (longest text, or first occurrence)
            canonical = max(
                group_mentions,
                key=lambda m: (len(m.span.text), -m.span.start)
            )

            # Determine entity type (use highest-tier mention's type)
            best_mention = max(group_mentions, key=lambda m: m.span.tier.value)

            entity = Entity(
                id=str(uuid.uuid4()),
                entity_type=best_mention.span.entity_type,
                canonical_value=canonical.span.text,
                mentions=group_mentions,
            )
            entities.append(entity)

        # Sort by first occurrence
        entities.sort(key=lambda e: min(m.span.start for m in e.mentions))
        return entities


def resolve_entities(spans: list[Span], min_confidence: float = 0.70) -> list[Entity]:
    """
    Convenience function to resolve entities.

    Args:
        spans: Detected spans
        min_confidence: Minimum confidence threshold

    Returns:
        List of resolved entities
    """
    resolver = EntityResolver(min_confidence=min_confidence)
    return resolver.resolve(spans)


def get_entity_counts(entities: list[Entity]) -> dict[str, int]:
    """
    Get entity counts by type.

    Args:
        entities: Resolved entities

    Returns:
        Dict mapping entity type to unique entity count
    """
    counts: dict[str, int] = {}
    for entity in entities:
        etype = entity.entity_type
        counts[etype] = counts.get(etype, 0) + 1
    return counts
