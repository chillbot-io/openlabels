"""Zero-PHI entity tracking graph.

Entity tracking is symbol table management, not ML. The graph is just
a symbol table with edges. All PHI lives in TokenStore (encrypted).

Graph stores ONLY:
- Tokens (e.g., [NAME_1])
- Entity IDs (UUIDs from EntityResolver, Phase 2)
- Edges between tokens
- Focus slots (for pronoun resolution)
- Counters
- Non-PHI metadata (type, gender, roles)

Phase 2 Update:
    Added entity_id tracking. Each token now optionally has an entity_id
    that uniquely identifies the real-world entity across all its mentions.
    This allows tracking entity identity separately from token identity.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field

from ..storage.tokens import TokenStore


logger = logging.getLogger(__name__)


@dataclass
class EntityGraph:
    """
    Zero-PHI entity tracking.
    
    The token IS the UUID. TokenStore handles all PHI. Graph holds tokens only.
    
    Usage:
        graph = EntityGraph(session_id, token_store)
        
        # Register entities (PHI goes to store, graph gets token)
        t1 = graph.register("John Smith", "NAME", {"gender": "M"})  # → [NAME_1]
        t2 = graph.register("Acme Corp", "ORG")                      # → [ORG_1]
        t3 = graph.register("$200k", "SALARY")                       # → [SALARY_1]
        
        # Link entities
        graph.link(t1, t2, "works_at")
        graph.link(t1, t3, "earns")
        
        # Resolve pronouns
        graph.resolve_pronoun("he")   # → [NAME_1] (last male)
        graph.resolve_pronoun("they") # → [ORG_1] (last org)
        
        # Traverse relationships
        graph.traverse(t1, "earns")   # → [SALARY_1]
    """
    
    session_id: str
    token_store: TokenStore
    
    # === CLEAN - tokens only, no PHI ===
    tokens: Set[str] = field(default_factory=set)
    edges: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)
    
    # Focus slots for pronoun resolution
    focus: Dict[str, Optional[str]] = field(default_factory=lambda: {
        "PERSON": None,
        "ORG": None,
        "AMOUNT": None,
        "LOCATION": None,
    })
    
    # Token metadata (non-PHI only: type, gender, is_org, entity_id, roles)
    token_metadata: Dict[str, dict] = field(default_factory=dict)

    # Phase 2: Entity ID tracking
    # Maps entity_id -> token for reverse lookup
    entity_to_token: Dict[str, str] = field(default_factory=dict)

    # Turn counter for recency tracking
    current_turn: int = 0
    
    # --- REGISTRATION - PHI goes to store, graph gets token ---
    def register(
        self, 
        text: str, 
        entity_type: str, 
        metadata: Optional[dict] = None
    ) -> str:
        """
        Register entity. TokenStore handles PHI matching.
        PHI never touches graph.
        
        Args:
            text: The PHI text (passed directly to TokenStore)
            entity_type: Entity type (NAME, SSN, etc.)
            metadata: Optional non-PHI metadata (gender, is_org, etc.)
            
        Returns:
            Token string like [NAME_1]
        """
        # TokenStore does the matching - PHI never touches graph
        token = self.token_store.get_or_create(
            value=text,
            entity_type=entity_type,
        )
        
        # Graph just tracks the token (no PHI)
        if token not in self.tokens:
            self.tokens.add(token)
            self.token_metadata[token] = {
                "type": entity_type,
                "turn_registered": self.current_turn,
                **(self._extract_safe_metadata(metadata) if metadata else {})
            }
        
        # Update focus slots
        self._update_focus(token, entity_type)
        
        return token
    
    def _extract_safe_metadata(self, metadata: dict) -> dict:
        """Extract only non-PHI metadata."""
        safe_keys = {
            "gender", "is_org", "detector", "confidence", "is_plural",
            "entity_id", "roles",  # Phase 2: entity identity tracking
        }
        return {k: v for k, v in metadata.items() if k in safe_keys}
    
    # --- FOCUS / SLOTS - for pronoun resolution ---
    def _update_focus(self, token: str, entity_type: str) -> None:
        """Update conversation focus slots based on entity type."""
        slot = self._type_to_slot(entity_type)
        if slot:
            self.focus[slot] = token
    
    def _type_to_slot(self, entity_type: str) -> Optional[str]:
        """Map entity type to focus slot."""
        mapping = {
            # Person names
            "NAME": "PERSON",
            "NAME_PATIENT": "PERSON",
            "NAME_PROVIDER": "PERSON",
            "NAME_RELATIVE": "PERSON",
            "PERSON": "PERSON",
            # Organizations
            "ORG": "ORG",
            "ORGANIZATION": "ORG",
            "EMPLOYER": "ORG",
            "FACILITY": "ORG",
            # Amounts
            "SALARY": "AMOUNT",
            "AMOUNT": "AMOUNT",
            "ACCOUNT_NUMBER": "AMOUNT",
            "CREDIT_CARD": "AMOUNT",
            # Locations
            "ADDRESS": "LOCATION",
            "CITY": "LOCATION",
            "STATE": "LOCATION",
            "ZIP": "LOCATION",
            "GPS_COORDINATE": "LOCATION",
        }
        return mapping.get(entity_type)
    
    def resolve_pronoun(self, pronoun: str) -> Optional[str]:
        """
        Resolve pronoun to token using focus slots and gender.
        
        Args:
            pronoun: The pronoun to resolve (he, she, they, it, etc.)
            
        Returns:
            Token if resolved, None otherwise
        """
        p = pronoun.lower().strip()
        
        # Male pronouns
        if p in ("he", "him", "his", "himself"):
            return self._find_by_gender("M")
        
        # Female pronouns
        if p in ("she", "her", "hers", "herself"):
            return self._find_by_gender("F")
        
        # Neutral/plural - could be person or org
        if p in ("they", "them", "their", "theirs", "themselves"):
            # Check if we have a plural entity or org
            org = self.focus.get("ORG")
            person = self.focus.get("PERSON")
            
            # Prefer org for "they" if recent
            if org and self._is_recent(org):
                return org
            return person or org
        
        # It/its - usually org or thing
        if p in ("it", "its", "itself"):
            return self.focus.get("ORG") or self.focus.get("AMOUNT")
        
        # Location references
        if p in ("there", "here"):
            return self.focus.get("LOCATION")
        
        return None
    
    def _find_by_gender(self, gender: str) -> Optional[str]:
        """Find person token by gender."""
        # Check focused person first
        person = self.focus.get("PERSON")
        if person and self.token_metadata.get(person, {}).get("gender") == gender:
            return person
        
        # Search all person tokens for gender match
        for token, meta in self.token_metadata.items():
            if meta.get("type") in ("NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE", "PERSON"):
                if meta.get("gender") == gender:
                    return token
        
        # Fallback to focus anyway (better than nothing)
        return person
    
    def _is_recent(self, token: str) -> bool:
        """Check if token was registered in current or previous turn."""
        meta = self.token_metadata.get(token, {})
        turn = meta.get("turn_registered", 0)
        return self.current_turn - turn <= 1
    
    def get_focus(self, slot: str) -> Optional[str]:
        """Get current focus for slot."""
        return self.focus.get(slot)
    
    def set_focus(self, slot: str, token: str) -> None:
        """Manually set focus slot."""
        if token in self.tokens:
            self.focus[slot] = token
    
    # --- EDGES - relationships between entities ---
    def link(self, source: str, target: str, relation: str) -> None:
        """
        Create directed relationship between entities.
        
        Args:
            source: Source token (e.g., [NAME_1])
            target: Target token (e.g., [ORG_1])
            relation: Relationship type (e.g., "works_at", "earns", "lives_at")
        """
        if source not in self.tokens or target not in self.tokens:
            logger.warning(f"Cannot link unknown tokens: {source} -> {target}")
            return
        
        if source not in self.edges:
            self.edges[source] = []
        
        edge = (relation, target)
        if edge not in self.edges[source]:
            self.edges[source].append(edge)
    
    def unlink(self, source: str, target: str, relation: str) -> bool:
        """Remove a relationship. Returns True if removed."""
        if source not in self.edges:
            return False
        
        edge = (relation, target)
        if edge in self.edges[source]:
            self.edges[source].remove(edge)
            return True
        return False
    
    def traverse(self, token: str, relation: str) -> Optional[str]:
        """
        Follow relationship edge from token.
        
        Args:
            token: Starting token
            relation: Relationship to follow
            
        Returns:
            Target token if edge exists, None otherwise
        """
        for rel, target in self.edges.get(token, []):
            if rel == relation:
                return target
        return None
    
    def traverse_all(self, token: str, relation: str) -> List[str]:
        """Get all targets for a relationship (if multiple)."""
        return [target for rel, target in self.edges.get(token, []) if rel == relation]
    
    def related(self, token: str) -> List[Tuple[str, str]]:
        """Get all relationships for a token."""
        return self.edges.get(token, [])
    
    def find_by_relation(self, relation: str, target: str) -> List[str]:
        """Find all tokens that have a specific relation to target."""
        results = []
        for source, edges in self.edges.items():
            for rel, tgt in edges:
                if rel == relation and tgt == target:
                    results.append(source)
        return results
    
    # --- TURN MANAGEMENT ---
    def advance_turn(self) -> None:
        """Advance to next conversation turn."""
        self.current_turn += 1
    
    # --- QUERIES ---
    def get_metadata(self, token: str) -> Optional[dict]:
        """Get metadata for token."""
        return self.token_metadata.get(token)
    
    def get_type(self, token: str) -> Optional[str]:
        """Get entity type for token."""
        meta = self.token_metadata.get(token)
        return meta.get("type") if meta else None
    
    def get_tokens_by_type(self, entity_type: str) -> List[str]:
        """Get all tokens of a specific type."""
        return [
            token for token, meta in self.token_metadata.items()
            if meta.get("type") == entity_type
        ]
    
    def get_all_people(self) -> List[str]:
        """Get all person tokens."""
        person_types = {"NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE", "PERSON"}
        return [
            token for token, meta in self.token_metadata.items()
            if meta.get("type") in person_types
        ]

    # --- PHASE 2: ENTITY ID OPERATIONS ---

    def register_entity(
        self,
        token: str,
        entity_id: str,
        entity_type: str,
        metadata: Optional[dict] = None,
    ) -> None:
        """
        Register a token with its entity_id (Phase 2).

        This is called after EntityResolver has grouped mentions and
        the tokenizer has assigned tokens to entities.

        Args:
            token: The assigned token (e.g., [NAME_1])
            entity_id: UUID from EntityResolver
            entity_type: Base entity type
            metadata: Optional non-PHI metadata
        """
        # Track the token
        self.tokens.add(token)

        # Map entity_id to token
        self.entity_to_token[entity_id] = token

        # Store metadata with entity_id
        self.token_metadata[token] = {
            "type": entity_type,
            "turn_registered": self.current_turn,
            "entity_id": entity_id,
            **(self._extract_safe_metadata(metadata) if metadata else {})
        }

        # Update focus slots
        self._update_focus(token, entity_type)

    def get_token_by_entity_id(self, entity_id: str) -> Optional[str]:
        """Get token for an entity_id (Phase 2)."""
        return self.entity_to_token.get(entity_id)

    def get_entity_id(self, token: str) -> Optional[str]:
        """Get entity_id for a token (Phase 2)."""
        meta = self.token_metadata.get(token)
        return meta.get("entity_id") if meta else None

    def get_all_entity_ids(self) -> List[str]:
        """Get all registered entity_ids (Phase 2)."""
        return list(self.entity_to_token.keys())

    # --- SERIALIZATION - zero PHI, safe to store ---
    def to_dict(self) -> dict:
        """
        Serialize graph state. Contains NO PHI.

        Safe to store in session, log, or transmit.
        """
        return {
            "session_id": self.session_id,
            "tokens": list(self.tokens),
            "edges": {k: v for k, v in self.edges.items()},
            "focus": self.focus,
            "token_metadata": self.token_metadata,
            "entity_to_token": self.entity_to_token,  # Phase 2
            "current_turn": self.current_turn,
        }
    
    @classmethod
    def from_dict(cls, data: dict, token_store: TokenStore) -> "EntityGraph":
        """
        Restore graph from serialized state.
        
        Args:
            data: Serialized graph data
            token_store: TokenStore instance for the session
            
        Returns:
            Restored EntityGraph
        """
        graph = cls(
            session_id=data["session_id"],
            token_store=token_store,
        )
        graph.tokens = set(data.get("tokens", []))
        graph.edges = data.get("edges", {})
        graph.focus = data.get("focus", {
            "PERSON": None,
            "ORG": None,
            "AMOUNT": None,
            "LOCATION": None,
        })
        graph.token_metadata = data.get("token_metadata", {})
        graph.entity_to_token = data.get("entity_to_token", {})  # Phase 2
        graph.current_turn = data.get("current_turn", 0)
        return graph
    
    # --- UTILITIES ---
    def __len__(self) -> int:
        """Number of entities tracked."""
        return len(self.tokens)
    
    def __contains__(self, token: str) -> bool:
        """Check if token is tracked."""
        return token in self.tokens
    
    def clear(self) -> None:
        """Clear all graph state (tokens remain in TokenStore)."""
        self.tokens.clear()
        self.edges.clear()
        self.focus = {
            "PERSON": None,
            "ORG": None,
            "AMOUNT": None,
            "LOCATION": None,
        }
        self.token_metadata.clear()
        self.entity_to_token.clear()  # Phase 2
        self.current_turn = 0
