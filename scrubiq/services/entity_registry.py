"""EntityRegistry: Single source of truth for entity identity.

This is the ONLY component that decides "who is who". All other components
(TokenStore, ConversationContext, coref) defer to this registry.

Design Principles:
    1. Single authority: Only EntityRegistry creates entity_ids
    2. Explicit confidence: Merge decisions have measurable confidence
    3. Role-aware: Semantic role conflicts block automatic merging
    4. Review integration: Uncertain merges go to review queue
    5. No silent merges: Dangerous fuzzy matching requires evidence

Merge Policy:
    - EXACT match (case-insensitive, normalized): 0.99 confidence, auto-merge
    - COREF link (pronoun with anchor): 0.95 confidence, auto-merge
    - Multi-word subset (2+ words): 0.85 confidence, merge + flag
    - Single-word overlap: 0.40 confidence, BLOCKED without more evidence
    - Role conflict (patient vs provider): -0.50 penalty

Usage:
    registry = EntityRegistry(store)

    # Register a mention - registry decides if it's new or existing entity
    entity_id = registry.register(
        text="John Smith",
        entity_type="NAME",
        span=span,
        context={"semantic_role": "patient", "sentence_idx": 0}
    )

    # Get entity info
    entity = registry.get_entity(entity_id)
"""

import logging
import threading
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any

from ..types import Span


logger = logging.getLogger(__name__)


class MergeConfidence(Enum):
    """Confidence levels for entity merge decisions."""
    EXACT = 0.99       # Exact normalized match
    COREF = 0.95       # Coreference link (pronoun to anchor)
    SUBSET_MULTI = 0.85  # Multi-word name is subset of another
    KNOWN_EXACT = 0.90   # Matches known entity exactly
    KNOWN_PARTIAL = 0.75  # Partial match to known entity (flagged)
    WORD_OVERLAP = 0.60   # Word overlap (requires review)
    SINGLE_WORD = 0.40    # Single word match (BLOCKED)

    # Thresholds
    AUTO_MERGE = 0.90     # Auto-merge without review
    FLAG_MERGE = 0.70     # Merge but flag for review
    BLOCK = 0.50          # Do not merge, create separate entity


class MergePenalty(Enum):
    """Penalties applied to merge confidence."""
    ROLE_CONFLICT = 0.50      # patient vs provider same name
    SENTENCE_DISTANCE_5 = 0.20  # 5+ sentences apart
    DIFFERENT_CONVERSATION = 0.10
    TYPE_MISMATCH = 0.30      # Different base entity types


@dataclass
class EntityCandidate:
    """A proposed entity mention to be registered."""
    text: str
    entity_type: str
    span: Span
    evidence_type: str = "detection"  # detection, coref, partial_name
    evidence_strength: float = 1.0
    context: Dict[str, Any] = field(default_factory=dict)
    # context may include: semantic_role, sentence_idx, conversation_id, etc.


@dataclass
class RegisteredEntity:
    """An entity tracked by the registry."""
    id: str  # UUID
    entity_type: str  # Base type (NAME, SSN, etc.)
    canonical_value: str  # Best/longest representation
    normalized_value: str  # For matching
    words: Set[str]  # For partial matching
    mentions: List[Dict[str, Any]] = field(default_factory=list)
    # Each mention: {text, start, end, role, confidence, conversation_id}
    roles: Set[str] = field(default_factory=set)  # All semantic roles seen
    created_at: float = 0.0

    def has_conflicting_role(self, role: str) -> bool:
        """Check if adding this role would conflict with existing roles."""
        if role == "unknown" or not self.roles:
            return False
        # patient and provider are conflicting
        if role == "patient" and "provider" in self.roles:
            return True
        if role == "provider" and "patient" in self.roles:
            return True
        return False


@dataclass
class MergeCandidate:
    """A potential merge flagged for review."""
    candidate_entity_id: str
    target_entity_id: str
    confidence: float
    reason: str
    evidence: Dict[str, Any] = field(default_factory=dict)


# Name prefixes to strip for matching
NAME_PREFIXES = frozenset(["mr", "mrs", "ms", "miss", "dr", "prof", "sr", "jr", "rev"])

# Types eligible for partial/fuzzy matching
NAME_TYPES = frozenset([
    "NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
    "PERSON", "PER",
])

# Types that only merge on exact match (no partial matching)
ISOLATED_TYPES = frozenset([
    "SSN", "SSN_PARTIAL", "MRN", "NPI", "DEA",
    "CREDIT_CARD", "ACCOUNT_NUMBER", "IBAN",
    "DRIVER_LICENSE", "PASSPORT", "STATE_ID",
    "EMAIL", "PHONE", "FAX",
    "IP_ADDRESS", "MAC_ADDRESS",
    "VIN", "LICENSE_PLATE",
    "API_KEY", "SECRET", "PASSWORD",
    "DATE", "DATE_DOB", "ADDRESS", "ZIP",
])


def _normalize_value(text: str, entity_type: str) -> str:
    """Normalize value for matching."""
    text = text.lower().strip()

    # For names, strip titles
    if entity_type in NAME_TYPES or _get_base_type(entity_type) in NAME_TYPES:
        parts = text.split()
        if parts and parts[0].rstrip('.') in NAME_PREFIXES:
            parts = parts[1:]
        text = " ".join(parts)

    return text


def _get_words(text: str) -> Set[str]:
    """Extract significant words from text."""
    words = set(text.lower().replace(".", "").split())
    # Remove single-char and common prefixes
    words = {w for w in words if len(w) >= 2 and w not in NAME_PREFIXES}
    return words


def _get_base_type(entity_type: str) -> str:
    """Get base entity type without role suffix."""
    for suffix in ("_PATIENT", "_PROVIDER", "_RELATIVE"):
        if entity_type.endswith(suffix):
            return "NAME"
    return entity_type


def _infer_role(entity_type: str) -> str:
    """Infer semantic role from entity type."""
    if entity_type.endswith("_PATIENT"):
        return "patient"
    elif entity_type.endswith("_PROVIDER"):
        return "provider"
    elif entity_type.endswith("_RELATIVE"):
        return "relative"
    return "unknown"


class EntityRegistry:
    """
    Single source of truth for entity identity.

    All entity_id creation and merge decisions happen here.
    TokenStore and other components only reference entity_ids from this registry.
    """

    def __init__(
        self,
        review_callback: Optional[callable] = None,
        auto_merge_threshold: float = 0.90,
        flag_merge_threshold: float = 0.70,
    ):
        """
        Initialize the registry.

        Args:
            review_callback: Optional callback for flagged merges.
                            Signature: callback(MergeCandidate) -> bool (approve/reject)
            auto_merge_threshold: Confidence threshold for auto-merge (default 0.90)
            flag_merge_threshold: Confidence threshold for merge-with-flag (default 0.70)
        """
        self._lock = threading.RLock()
        self._review_callback = review_callback
        self._auto_merge_threshold = auto_merge_threshold
        self._flag_merge_threshold = flag_merge_threshold

        # Entity storage
        self._entities: Dict[str, RegisteredEntity] = {}

        # Indexes for efficient lookup
        self._by_normalized: Dict[str, Set[str]] = {}  # normalized_value -> entity_ids
        self._by_word: Dict[str, Set[str]] = {}  # word -> entity_ids
        self._by_type: Dict[str, Set[str]] = {}  # entity_type -> entity_ids

        # Review queue for uncertain merges
        self._review_queue: List[MergeCandidate] = []

    def register(self, candidate: EntityCandidate) -> str:
        """
        Register a mention and return its entity_id.

        This is the ONLY way to get an entity_id. The registry decides
        whether to create a new entity or merge with an existing one.

        Args:
            candidate: The mention to register

        Returns:
            entity_id (UUID string)
        """
        with self._lock:
            base_type = _get_base_type(candidate.entity_type)
            normalized = _normalize_value(candidate.text, candidate.entity_type)
            role = candidate.context.get("semantic_role") or _infer_role(candidate.entity_type)

            # Find potential merge targets
            merge_candidates = self._find_merge_candidates(candidate, normalized, base_type)

            if not merge_candidates:
                # No candidates - create new entity
                return self._create_entity(candidate, normalized, base_type, role)

            # Select best match and compute confidence
            best_entity, confidence, reason = self._select_best_match(
                candidate, merge_candidates, normalized, role
            )

            # Apply merge policy
            if confidence >= self._auto_merge_threshold:
                # High confidence - merge automatically
                return self._merge_into(candidate, best_entity, role)

            elif confidence >= self._flag_merge_threshold:
                # Medium confidence - merge but flag for review
                entity_id = self._merge_into(candidate, best_entity, role)
                self._flag_for_review(candidate, best_entity, confidence, reason)
                return entity_id

            else:
                # Low confidence - create new entity, queue potential merge
                entity_id = self._create_entity(candidate, normalized, base_type, role)
                self._queue_potential_merge(entity_id, best_entity, confidence, reason)
                return entity_id

    def _find_merge_candidates(
        self,
        candidate: EntityCandidate,
        normalized: str,
        base_type: str,
    ) -> List[Tuple[RegisteredEntity, float, str]]:
        """
        Find entities this candidate might merge with.

        Returns list of (entity, base_confidence, reason) tuples.
        """
        candidates = []

        # 1. Exact normalized match - highest confidence
        if normalized in self._by_normalized:
            for eid in self._by_normalized[normalized]:
                entity = self._entities[eid]
                if _get_base_type(entity.entity_type) == base_type:
                    candidates.append((
                        entity,
                        MergeConfidence.EXACT.value,
                        "exact_match"
                    ))

        # 2. Coreference anchor - high confidence
        if candidate.span.coref_anchor_value:
            anchor_norm = _normalize_value(
                candidate.span.coref_anchor_value,
                candidate.entity_type
            )
            if anchor_norm in self._by_normalized:
                for eid in self._by_normalized[anchor_norm]:
                    entity = self._entities[eid]
                    if _get_base_type(entity.entity_type) == base_type:
                        # Avoid duplicates
                        if not any(e.id == eid for e, _, _ in candidates):
                            candidates.append((
                                entity,
                                MergeConfidence.COREF.value,
                                "coref_anchor"
                            ))

        # 3. Word-based matching (only for NAME types, not ISOLATED)
        if base_type in NAME_TYPES and base_type not in ISOLATED_TYPES:
            words = _get_words(candidate.text)
            if words:
                candidate_eids: Set[str] = set()
                for word in words:
                    if word in self._by_word:
                        candidate_eids.update(self._by_word[word])

                for eid in candidate_eids:
                    # Skip if already found via exact/coref
                    if any(e.id == eid for e, _, _ in candidates):
                        continue

                    entity = self._entities[eid]
                    if _get_base_type(entity.entity_type) != base_type:
                        continue

                    # Calculate word overlap
                    overlap = words & entity.words
                    if not overlap:
                        continue

                    # Determine match type and confidence
                    smaller = words if len(words) <= len(entity.words) else entity.words
                    larger = entity.words if len(words) <= len(entity.words) else words

                    if smaller.issubset(larger):
                        if len(smaller) >= 2:
                            # Multi-word subset - decent confidence
                            candidates.append((
                                entity,
                                MergeConfidence.SUBSET_MULTI.value,
                                "multi_word_subset"
                            ))
                        else:
                            # Single word subset - LOW confidence, likely blocked
                            candidates.append((
                                entity,
                                MergeConfidence.SINGLE_WORD.value,
                                "single_word_match"
                            ))
                    else:
                        # Partial overlap
                        overlap_ratio = len(overlap) / max(len(words), len(entity.words))
                        if overlap_ratio >= 0.5:
                            candidates.append((
                                entity,
                                MergeConfidence.WORD_OVERLAP.value * overlap_ratio,
                                f"word_overlap_{len(overlap)}"
                            ))

        return candidates

    def _select_best_match(
        self,
        candidate: EntityCandidate,
        matches: List[Tuple[RegisteredEntity, float, str]],
        normalized: str,
        role: str,
    ) -> Tuple[RegisteredEntity, float, str]:
        """
        Select best match, applying penalties for conflicts.

        Returns (best_entity, adjusted_confidence, reason).
        """
        best_entity = None
        best_score = 0.0
        best_reason = ""

        for entity, base_score, reason in matches:
            score = base_score

            # CRITICAL: Role conflict penalty
            # "Maria" as patient and "Maria" as provider are probably different people
            if role in ("patient", "provider"):
                if entity.has_conflicting_role(role):
                    score -= MergePenalty.ROLE_CONFLICT.value
                    reason += "+role_conflict"
                    logger.debug(
                        f"Role conflict penalty: {candidate.text} ({role}) "
                        f"vs entity {entity.id} (roles: {entity.roles})"
                    )

            # Sentence distance penalty (if available)
            if "sentence_idx" in candidate.context:
                # Check distance to entity's mentions
                candidate_sent = candidate.context["sentence_idx"]
                for mention in entity.mentions:
                    if "sentence_idx" in mention:
                        dist = abs(candidate_sent - mention["sentence_idx"])
                        if dist >= 5:
                            score -= MergePenalty.SENTENCE_DISTANCE_5.value
                            reason += "+distant"
                            break

            # Type mismatch penalty
            if _get_base_type(entity.entity_type) != _get_base_type(candidate.entity_type):
                score -= MergePenalty.TYPE_MISMATCH.value
                reason += "+type_mismatch"

            if score > best_score:
                best_score = score
                best_entity = entity
                best_reason = reason

        return best_entity, best_score, best_reason

    def _create_entity(
        self,
        candidate: EntityCandidate,
        normalized: str,
        base_type: str,
        role: str,
    ) -> str:
        """Create a new entity for this candidate."""
        import time

        entity_id = str(uuid.uuid4())
        words = _get_words(candidate.text) if base_type in NAME_TYPES else set()

        entity = RegisteredEntity(
            id=entity_id,
            entity_type=base_type,
            canonical_value=candidate.text,
            normalized_value=normalized,
            words=words,
            roles={role} if role != "unknown" else set(),
            created_at=time.time(),
        )

        # Add initial mention
        entity.mentions.append({
            "text": candidate.text,
            "start": candidate.span.start,
            "end": candidate.span.end,
            "role": role,
            "confidence": candidate.span.confidence,
            "conversation_id": candidate.context.get("conversation_id"),
            "sentence_idx": candidate.context.get("sentence_idx"),
        })

        # Store and index
        self._entities[entity_id] = entity
        self._index_entity(entity)

        logger.debug(f"Created new entity {entity_id} for '{candidate.text}' ({base_type})")
        return entity_id

    def _merge_into(
        self,
        candidate: EntityCandidate,
        target: RegisteredEntity,
        role: str,
    ) -> str:
        """Merge candidate into existing entity."""
        # Add mention
        target.mentions.append({
            "text": candidate.text,
            "start": candidate.span.start,
            "end": candidate.span.end,
            "role": role,
            "confidence": candidate.span.confidence,
            "conversation_id": candidate.context.get("conversation_id"),
            "sentence_idx": candidate.context.get("sentence_idx"),
        })

        # Update roles
        if role != "unknown":
            target.roles.add(role)

        # Update canonical value if this is longer
        if len(candidate.text) > len(target.canonical_value):
            old_normalized = target.normalized_value
            target.canonical_value = candidate.text
            target.normalized_value = _normalize_value(candidate.text, target.entity_type)

            # Re-index if normalized changed
            if target.normalized_value != old_normalized:
                self._reindex_entity(target, old_normalized)

        # Update words
        if target.entity_type in NAME_TYPES:
            new_words = _get_words(candidate.text)
            target.words.update(new_words)
            for word in new_words:
                if word not in self._by_word:
                    self._by_word[word] = set()
                self._by_word[word].add(target.id)

        logger.debug(f"Merged '{candidate.text}' into entity {target.id}")
        return target.id

    def _index_entity(self, entity: RegisteredEntity) -> None:
        """Add entity to lookup indexes."""
        # By normalized value
        if entity.normalized_value not in self._by_normalized:
            self._by_normalized[entity.normalized_value] = set()
        self._by_normalized[entity.normalized_value].add(entity.id)

        # By words
        for word in entity.words:
            if word not in self._by_word:
                self._by_word[word] = set()
            self._by_word[word].add(entity.id)

        # By type
        if entity.entity_type not in self._by_type:
            self._by_type[entity.entity_type] = set()
        self._by_type[entity.entity_type].add(entity.id)

    def _reindex_entity(self, entity: RegisteredEntity, old_normalized: str) -> None:
        """Re-index entity after normalized value change."""
        # Remove from old normalized index
        if old_normalized in self._by_normalized:
            self._by_normalized[old_normalized].discard(entity.id)
            if not self._by_normalized[old_normalized]:
                del self._by_normalized[old_normalized]

        # Add to new normalized index
        if entity.normalized_value not in self._by_normalized:
            self._by_normalized[entity.normalized_value] = set()
        self._by_normalized[entity.normalized_value].add(entity.id)

    def _flag_for_review(
        self,
        candidate: EntityCandidate,
        target: RegisteredEntity,
        confidence: float,
        reason: str,
    ) -> None:
        """Flag a merge for human review."""
        merge_candidate = MergeCandidate(
            candidate_entity_id="",  # Already merged
            target_entity_id=target.id,
            confidence=confidence,
            reason=f"auto_merged_flagged:{reason}",
            evidence={
                "candidate_text": candidate.text,
                "target_canonical": target.canonical_value,
                "confidence": confidence,
            }
        )
        self._review_queue.append(merge_candidate)

        if self._review_callback:
            try:
                self._review_callback(merge_candidate)
            except Exception as e:
                logger.warning(f"Review callback failed: {e}")

    def _queue_potential_merge(
        self,
        new_entity_id: str,
        potential_target: RegisteredEntity,
        confidence: float,
        reason: str,
    ) -> None:
        """Queue a potential merge that was blocked due to low confidence."""
        merge_candidate = MergeCandidate(
            candidate_entity_id=new_entity_id,
            target_entity_id=potential_target.id,
            confidence=confidence,
            reason=f"blocked:{reason}",
            evidence={
                "new_entity_id": new_entity_id,
                "target_canonical": potential_target.canonical_value,
                "confidence": confidence,
            }
        )
        self._review_queue.append(merge_candidate)
        logger.debug(
            f"Queued potential merge: {new_entity_id} -> {potential_target.id} "
            f"(confidence={confidence:.2f}, reason={reason})"
        )

    # --- Public Query API ---

    def get_entity(self, entity_id: str) -> Optional[RegisteredEntity]:
        """Get entity by ID."""
        with self._lock:
            return self._entities.get(entity_id)

    def get_entity_id_by_value(
        self,
        text: str,
        entity_type: str,
    ) -> Optional[str]:
        """
        Find entity ID by exact value match.

        This is for lookup only - does NOT create entities.
        Use register() to create/merge entities.
        """
        with self._lock:
            normalized = _normalize_value(text, entity_type)
            base_type = _get_base_type(entity_type)

            if normalized in self._by_normalized:
                for eid in self._by_normalized[normalized]:
                    entity = self._entities[eid]
                    if _get_base_type(entity.entity_type) == base_type:
                        return eid
            return None

    def get_all_entities(self) -> List[RegisteredEntity]:
        """Get all registered entities."""
        with self._lock:
            return list(self._entities.values())

    def get_entities_by_type(self, entity_type: str) -> List[RegisteredEntity]:
        """Get all entities of a specific type."""
        with self._lock:
            base_type = _get_base_type(entity_type)
            if base_type in self._by_type:
                return [self._entities[eid] for eid in self._by_type[base_type]]
            return []

    def get_review_queue(self) -> List[MergeCandidate]:
        """Get pending merge reviews."""
        with self._lock:
            return list(self._review_queue)

    def approve_merge(self, candidate_entity_id: str, target_entity_id: str) -> bool:
        """
        Manually approve a blocked merge.

        Moves all mentions from candidate entity to target entity,
        then deletes the candidate entity.
        """
        with self._lock:
            if candidate_entity_id not in self._entities:
                return False
            if target_entity_id not in self._entities:
                return False

            candidate = self._entities[candidate_entity_id]
            target = self._entities[target_entity_id]

            # Move mentions
            for mention in candidate.mentions:
                target.mentions.append(mention)
                role = mention.get("role", "unknown")
                if role != "unknown":
                    target.roles.add(role)

            # Update canonical if candidate is longer
            if len(candidate.canonical_value) > len(target.canonical_value):
                old_norm = target.normalized_value
                target.canonical_value = candidate.canonical_value
                target.normalized_value = candidate.normalized_value
                self._reindex_entity(target, old_norm)

            # Merge words
            target.words.update(candidate.words)
            for word in candidate.words:
                if word in self._by_word:
                    self._by_word[word].add(target.id)

            # Remove candidate from indexes and storage
            self._remove_from_indexes(candidate)
            del self._entities[candidate_entity_id]

            # Remove from review queue
            self._review_queue = [
                m for m in self._review_queue
                if m.candidate_entity_id != candidate_entity_id
            ]

            logger.info(f"Approved merge: {candidate_entity_id} -> {target_entity_id}")
            return True

    def reject_merge(self, candidate_entity_id: str, target_entity_id: str) -> bool:
        """Reject a potential merge (keep entities separate)."""
        with self._lock:
            # Just remove from review queue
            before = len(self._review_queue)
            self._review_queue = [
                m for m in self._review_queue
                if not (m.candidate_entity_id == candidate_entity_id and
                       m.target_entity_id == target_entity_id)
            ]
            removed = before - len(self._review_queue)
            if removed:
                logger.info(f"Rejected merge: {candidate_entity_id} -> {target_entity_id}")
            return removed > 0

    def _remove_from_indexes(self, entity: RegisteredEntity) -> None:
        """Remove entity from all indexes."""
        # From normalized
        if entity.normalized_value in self._by_normalized:
            self._by_normalized[entity.normalized_value].discard(entity.id)

        # From words
        for word in entity.words:
            if word in self._by_word:
                self._by_word[word].discard(entity.id)

        # From type
        if entity.entity_type in self._by_type:
            self._by_type[entity.entity_type].discard(entity.id)

    def clear(self) -> None:
        """Clear all registry state."""
        with self._lock:
            self._entities.clear()
            self._by_normalized.clear()
            self._by_word.clear()
            self._by_type.clear()
            self._review_queue.clear()

    def export_known_entities(self) -> Dict[str, Tuple[str, str]]:
        """
        Export entities in format compatible with EntityResolver.

        Returns: {entity_id: (canonical_value, entity_type)}
        """
        with self._lock:
            return {
                eid: (entity.canonical_value, entity.entity_type)
                for eid, entity in self._entities.items()
            }

    def import_known_entities(
        self,
        known: Dict[str, Tuple[str, str]],
    ) -> None:
        """
        Import known entities (e.g., from previous conversation).

        Args:
            known: {entity_id: (canonical_value, entity_type)}
        """
        with self._lock:
            import time

            for eid, (value, etype) in known.items():
                if eid in self._entities:
                    continue  # Already exists

                base_type = _get_base_type(etype)
                normalized = _normalize_value(value, etype)
                words = _get_words(value) if base_type in NAME_TYPES else set()

                entity = RegisteredEntity(
                    id=eid,
                    entity_type=base_type,
                    canonical_value=value,
                    normalized_value=normalized,
                    words=words,
                    created_at=time.time(),
                )

                self._entities[eid] = entity
                self._index_entity(entity)

            logger.debug(f"Imported {len(known)} known entities")

    def __len__(self) -> int:
        """Number of entities in registry."""
        return len(self._entities)

    def __contains__(self, entity_id: str) -> bool:
        """Check if entity exists."""
        return entity_id in self._entities
