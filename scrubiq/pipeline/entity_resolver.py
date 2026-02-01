"""Entity Resolution: Group mentions that refer to the same real-world entity.

Phase 2 of the architecture refactor. Fixes the core identity problem where
entity_type was incorrectly used as part of the identity key.

Key Insight:
    Semantic role (patient, provider, relative) is METADATA about how an
    entity is referenced, NOT part of the entity's identity. "John" detected
    as NAME_PATIENT and NAME_PROVIDER should receive the SAME token because
    they refer to the SAME person.

Resolution Algorithm (Multi-Sieve):
    Sieve 1: Exact string match (case-insensitive)
    Sieve 2: Partial name match ("John" in "John Smith")
    Sieve 3: Coreference links (pronouns linked by FastCoref)
    Sieve 4: Cross-message persistence (known entities from previous messages)

Pipeline Position:
    Detect → Merge → Coref → EntityResolve → Tokenize
                                   ↑
                          You are here

The EntityResolver outputs a list of Entity objects, each with a UUID.
The tokenizer then uses entity_id (not entity_type) as the lookup key.
"""

import logging
import uuid
from typing import List, Dict, Set, Optional, Tuple

from ..types import Span, Mention, Entity
from ..constants import NAME_ENTITY_TYPES, is_name_entity_type


logger = logging.getLogger(__name__)

# Re-export for backwards compatibility (used in this module and others)
NAME_TYPES = NAME_ENTITY_TYPES

# Types that should always get separate entities (identifiers, not names)
ISOLATED_TYPES = frozenset([
    "SSN", "SSN_PARTIAL",
    "MRN", "NPI", "DEA",
    "CREDIT_CARD", "ACCOUNT_NUMBER", "IBAN",
    "DRIVER_LICENSE", "PASSPORT", "STATE_ID",
    "EMAIL", "PHONE", "FAX",
    "IP_ADDRESS", "MAC_ADDRESS",
    "VIN", "LICENSE_PLATE",
    "API_KEY", "SECRET", "PASSWORD",
])

# Title prefixes to strip for matching (case-insensitive)
NAME_PREFIXES = frozenset(["mr", "mrs", "ms", "miss", "dr", "prof", "sr", "jr"])


def _normalize_name(text: str) -> str:
    """Normalize name for comparison (lowercase, strip titles)."""
    text = text.lower().strip()
    parts = text.split()
    # Remove common prefixes
    if parts and parts[0].rstrip('.') in NAME_PREFIXES:
        parts = parts[1:]
    return " ".join(parts)


def _get_name_words(text: str) -> Set[str]:
    """Extract significant words from a name."""
    normalized = _normalize_name(text)
    words = set(normalized.replace(".", "").split())
    # Remove single-char words and common titles
    words = {w for w in words if len(w) >= 2 and w not in NAME_PREFIXES}
    return words


def _infer_semantic_role(entity_type: str) -> str:
    """Infer semantic role from entity type suffix."""
    if entity_type.endswith("_PATIENT"):
        return "patient"
    elif entity_type.endswith("_PROVIDER"):
        return "provider"
    elif entity_type.endswith("_RELATIVE"):
        return "relative"
    return "unknown"


def _get_base_type(entity_type: str) -> str:
    """Get base entity type without role suffix."""
    for suffix in ("_PATIENT", "_PROVIDER", "_RELATIVE"):
        if entity_type.endswith(suffix):
            return "NAME"
    return entity_type


def _is_name_type(entity_type: str) -> bool:
    """Check if entity type is a name type.

    Uses centralized is_name_entity_type from constants.
    """
    return is_name_entity_type(entity_type)


class EntityResolver:
    """
    Groups mentions that refer to the same real-world entity.

    Uses a multi-sieve approach for increasing precision:
    1. Exact match: Same normalized text → same entity
    2. Partial name: Word overlap → same entity (e.g., "Smith" and "John Smith")
    3. Coref links: Pronouns linked via coref_anchor_value → same entity
    4. Known entities: Match against previously identified entities

    The resolver outputs Entity objects with UUIDs. The tokenizer then uses
    entity_id as the lookup key instead of (value, entity_type).
    """

    def __init__(
        self,
        known_entities: Optional[Dict[str, Tuple[str, str]]] = None,
        enable_partial_match: bool = True,
        min_word_length: int = 2,
    ):
        """
        Initialize the resolver.

        Args:
            known_entities: Dict of known entities from previous messages.
                           Format: {entity_id: (canonical_value, entity_type)}
            enable_partial_match: Enable partial name matching (Sieve 2)
            min_word_length: Minimum word length for partial matching
        """
        self.known_entities = known_entities or {}
        self.enable_partial_match = enable_partial_match
        self.min_word_length = min_word_length

        # Build reverse index for known entities: value -> entity_id
        self._known_by_value: Dict[str, str] = {}
        self._known_by_words: Dict[str, Set[str]] = {}  # word -> set of entity_ids

        for eid, (value, etype) in self.known_entities.items():
            norm_value = _normalize_name(value)
            self._known_by_value[norm_value] = eid
            # Index by words for partial matching
            for word in _get_name_words(value):
                if word not in self._known_by_words:
                    self._known_by_words[word] = set()
                self._known_by_words[word].add(eid)

    def resolve(self, spans: List[Span]) -> List[Entity]:
        """
        Resolve spans into entities.

        Args:
            spans: Non-overlapping spans from merge/coref stages

        Returns:
            List of Entity objects, each with a unique ID and linked mentions
        """
        if not spans:
            return []

        # Convert spans to mentions
        mentions = self._spans_to_mentions(spans)

        # Apply sieves in order
        entities = self._apply_sieves(mentions)

        # Log resolution results
        if entities:
            logger.debug(
                f"EntityResolver: {len(spans)} spans → {len(entities)} entities "
                f"({len(spans) - len(entities)} merged)"
            )

        return entities

    def _spans_to_mentions(self, spans: List[Span]) -> List[Mention]:
        """Convert spans to mentions with semantic role metadata."""
        mentions = []
        for span in spans:
            role = _infer_semantic_role(span.entity_type)
            mention = Mention(
                span=span,
                semantic_role=role,
                confidence=span.confidence,
                source=span.detector,
            )
            mentions.append(mention)
        return mentions

    def _apply_sieves(self, mentions: List[Mention]) -> List[Entity]:
        """Apply resolution sieves using union-find for grouping."""
        if not mentions:
            return []

        n = len(mentions)

        # Union-Find structure to group mentions
        parent = list(range(n))
        rank = [0] * n

        def find(x: int) -> int:
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x: int, y: int) -> None:
            px, py = find(x), find(y)
            if px == py:
                return
            if rank[px] < rank[py]:
                px, py = py, px
            parent[py] = px
            if rank[px] == rank[py]:
                rank[px] += 1

        # Index mentions by various keys for efficient lookup
        by_normalized: Dict[str, List[int]] = {}
        by_coref_anchor: Dict[str, List[int]] = {}
        by_words: Dict[str, List[int]] = {}

        for i, mention in enumerate(mentions):
            norm = _normalize_name(mention.text)
            if norm not in by_normalized:
                by_normalized[norm] = []
            by_normalized[norm].append(i)

            if mention.span.coref_anchor_value:
                anchor_norm = _normalize_name(mention.span.coref_anchor_value)
                if anchor_norm not in by_coref_anchor:
                    by_coref_anchor[anchor_norm] = []
                by_coref_anchor[anchor_norm].append(i)

            if _is_name_type(mention.span.entity_type):
                for word in _get_name_words(mention.text):
                    if word not in by_words:
                        by_words[word] = []
                    by_words[word].append(i)

        # Sieve 1: Exact string match - merge mentions with same normalized text
        # NOTE: ISOLATED_TYPES (SSN, MRN, etc.) SHOULD be merged on exact match!
        # The same SSN value appearing twice must get the same token.
        # "Isolated" means they don't participate in partial/word-based matching,
        # NOT that they should never be merged with identical values.
        for norm_value, indices in by_normalized.items():
            if len(indices) < 2:
                continue
            # For all types (including ISOLATED_TYPES), merge on exact match
            first = indices[0]
            for other in indices[1:]:
                # Only merge if types are compatible (same base type)
                first_base = _get_base_type(mentions[first].span.entity_type)
                other_base = _get_base_type(mentions[other].span.entity_type)
                if first_base == other_base:
                    union(first, other)

        # Sieve 2: Partial name match - merge NAME types where one is a subset of another
        # Conservative approach to avoid merging different people who share names:
        #   - Only merge multi-word names where one is a subset (e.g., "John Smith" + "Dr. John Smith")
        #   - Single-word names need explicit coref evidence (handled in Sieve 3)
        #   - This prevents merging "Maria" (guardian) with "Maria Rodriguez" (patient)
        if self.enable_partial_match:
            # Build word sets for each name mention
            mention_words: Dict[int, Set[str]] = {}
            for i, mention in enumerate(mentions):
                if _is_name_type(mention.span.entity_type):
                    mention_words[i] = _get_name_words(mention.text)

            # Check pairs - only merge multi-word names where one is a proper subset
            name_indices = list(mention_words.keys())
            for i, idx_a in enumerate(name_indices):
                words_a = mention_words[idx_a]
                for idx_b in name_indices[i+1:]:
                    words_b = mention_words[idx_b]
                    # Only merge if BOTH names have words
                    if not words_a or not words_b:
                        continue

                    # Conservative rule: Only merge via subset if the smaller name
                    # has at least 2 words. This prevents single-name merges like
                    # "Maria" + "Maria Rodriguez" (could be different people).
                    # Single-word names should only merge via exact match (Sieve 1)
                    # or explicit coreference (Sieve 3).
                    smaller = words_a if len(words_a) <= len(words_b) else words_b
                    larger = words_b if len(words_a) <= len(words_b) else words_a

                    if len(smaller) >= 2 and smaller.issubset(larger):
                        # Multi-word subset: "John Smith" ⊂ "Dr. John A. Smith" → merge
                        union(idx_a, idx_b)

        # Sieve 3: Coreference links - merge pronouns with their anchors
        for anchor_norm, pronoun_indices in by_coref_anchor.items():
            if anchor_norm in by_normalized:
                anchor_indices = by_normalized[anchor_norm]
                if anchor_indices:
                    anchor_idx = anchor_indices[0]
                    for pronoun_idx in pronoun_indices:
                        union(anchor_idx, pronoun_idx)

        # Sieve 4: Known entity matching
        # Conservative approach: Only match against known entities if:
        #   1. Exact match (always safe), OR
        #   2. Partial match with multi-word mention (at least 2 words)
        # This prevents "Maria" from matching known "Maria Rodriguez"
        known_matches: Dict[str, List[int]] = {}  # entity_id -> mention indices
        for i, mention in enumerate(mentions):
            if not _is_name_type(mention.span.entity_type):
                continue
            norm = _normalize_name(mention.text)
            if norm in self._known_by_value:
                # Exact match - safe to use known entity
                eid = self._known_by_value[norm]
                if eid not in known_matches:
                    known_matches[eid] = []
                known_matches[eid].append(i)
            elif self.enable_partial_match:
                words = _get_name_words(mention.text)
                # Only do partial matching for multi-word names (at least 2 words)
                # Single-word names are too ambiguous (could be any "Maria")
                if len(words) < 2:
                    continue

                candidate_eids: Set[str] = set()
                for word in words:
                    if word in self._known_by_words:
                        candidate_eids.update(self._known_by_words[word])
                if candidate_eids:
                    # Select best match based on maximum word overlap
                    best_eid = None
                    best_overlap = 0
                    for eid in candidate_eids:
                        # Count how many words from the mention match this entity
                        eid_words = self._known_by_words.keys()
                        entity_words = {w for w in eid_words if eid in self._known_by_words.get(w, set())}
                        overlap = len(words & entity_words)
                        if overlap > best_overlap:
                            best_overlap = overlap
                            best_eid = eid
                    if best_eid is None:
                        best_eid = list(candidate_eids)[0]  # Fallback to first if no overlap found
                    if best_eid not in known_matches:
                        known_matches[best_eid] = []
                    known_matches[best_eid].append(i)

        # Collect groups from union-find
        groups: Dict[int, List[int]] = {}
        for i in range(n):
            root = find(i)
            if root not in groups:
                groups[root] = []
            groups[root].append(i)

        # Create entities from groups
        entities: List[Entity] = []
        processed: Set[int] = set()

        # First, create entities for known entity matches
        for eid, indices in known_matches.items():
            if not indices:
                continue
            # Find all mentions in the same group as these indices
            all_indices: Set[int] = set()
            for i in indices:
                root = find(i)
                all_indices.update(groups.get(root, [i]))

            # Mark as processed
            processed.update(all_indices)

            # Create entity with known ID
            canon_value, etype = self.known_entities[eid]
            entity = Entity(
                id=eid,
                entity_type=_get_base_type(etype),
                canonical_value=canon_value,
            )
            for i in sorted(all_indices):
                entity.add_mention(mentions[i])
            entities.append(entity)

        # Then create entities for remaining groups
        for root, indices in groups.items():
            if any(i in processed for i in indices):
                continue

            entity = self._create_entity_from_indices(mentions, indices)
            entities.append(entity)

        return entities

    def _create_entity_from_indices(
        self,
        mentions: List[Mention],
        indices: List[int],
    ) -> Entity:
        """Create an entity from multiple mention indices."""
        entity_id = str(uuid.uuid4())

        # Find best canonical value (longest text)
        best_idx = max(indices, key=lambda i: len(mentions[i].text))
        canonical = mentions[best_idx].text
        base_type = _get_base_type(mentions[best_idx].span.entity_type)

        entity = Entity(
            id=entity_id,
            entity_type=base_type,
            canonical_value=canonical,
        )

        for i in indices:
            entity.add_mention(mentions[i])

        return entity


def resolve_entities(
    spans: List[Span],
    known_entities: Optional[Dict[str, Tuple[str, str]]] = None,
) -> List[Entity]:
    """
    Convenience function to resolve spans into entities.

    Args:
        spans: Non-overlapping spans from merge/coref stages
        known_entities: Known entities from previous messages
                       Format: {entity_id: (canonical_value, entity_type)}

    Returns:
        List of resolved Entity objects
    """
    resolver = EntityResolver(known_entities=known_entities)
    return resolver.resolve(spans)
