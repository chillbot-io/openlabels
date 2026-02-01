"""Conversation-scoped context for pronoun resolution and salience tracking.

This is NOT an entity resolution system. It does NOT decide "who is who".
That's EntityRegistry's job.

ConversationContext tracks:
    - What tokens have been mentioned recently (for salience)
    - Focus slots (most recent entity of each type for pronoun hints)
    - Turn numbers (for recency calculations)

Usage:
    context = ConversationContext(session_id, conversation_id)

    # After EntityRegistry resolves identity and TokenStore assigns token:
    context.observe(token="[NAME_1]", entity_type="NAME", metadata={"gender": "M"})

    # Coref can ask for hints:
    focused_person = context.get_focus("PERSON")  # -> "[NAME_1]"
    recent_names = context.get_recent("NAME", max_turns_back=2)  # -> ["[NAME_1]", "[NAME_2]"]

    # Advance turn for multi-message conversations:
    context.advance_turn()
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any


logger = logging.getLogger(__name__)


# Focus slot mapping - entity types to focus categories
TYPE_TO_SLOT = {
    # Person names
    "NAME": "PERSON",
    "NAME_PATIENT": "PERSON",
    "NAME_PROVIDER": "PERSON",
    "NAME_RELATIVE": "PERSON",
    "PERSON": "PERSON",
    "PER": "PERSON",
    # Organizations
    "ORG": "ORG",
    "ORGANIZATION": "ORG",
    "EMPLOYER": "ORG",
    "FACILITY": "ORG",
    "COMPANY": "ORG",
    # Locations
    "ADDRESS": "LOCATION",
    "CITY": "LOCATION",
    "STATE": "LOCATION",
    "ZIP": "LOCATION",
    "GPS_COORDINATE": "LOCATION",
    "LOCATION": "LOCATION",
    # Dates
    "DATE": "DATE",
    "DATE_DOB": "DATE",
    "DOB": "DATE",
}


@dataclass
class MentionRecord:
    """Record of a token mention for recency tracking."""
    token: str
    entity_type: str
    turn: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConversationContext:
    """
    Conversation-scoped context for pronoun resolution hints.

    NOT an identity system. Does NOT decide who is who.
    Just tracks what's been mentioned recently for coref hints.

    Thread-safe for concurrent access.
    """

    session_id: str
    conversation_id: str

    # Recent mentions for salience tracking
    # Stored as (token, entity_type, turn, metadata)
    _recent_mentions: List[MentionRecord] = field(default_factory=list)

    # Focus slots - most recently mentioned entity of each category
    # {"PERSON": "[NAME_1]", "ORG": "[ORG_1]", "LOCATION": "[ADDRESS_1]"}
    _focus: Dict[str, str] = field(default_factory=dict)

    # Token metadata (non-PHI only: type, gender, is_plural, entity_id)
    _token_metadata: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # All tokens seen in this conversation
    _tokens: Set[str] = field(default_factory=set)

    # Current turn number
    current_turn: int = 0

    # Max mentions to keep (prevents unbounded growth)
    _max_mentions: int = 100

    def observe(
        self,
        token: str,
        entity_type: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record that a token was mentioned.

        Called AFTER EntityRegistry has resolved identity and
        TokenStore has assigned a token. This just observes.

        Args:
            token: The token string (e.g., "[NAME_1]")
            entity_type: Entity type (e.g., "NAME", "NAME_PATIENT")
            metadata: Optional non-PHI metadata (gender, is_plural, entity_id)
        """
        # Track the token
        self._tokens.add(token)

        # Record mention
        record = MentionRecord(
            token=token,
            entity_type=entity_type,
            turn=self.current_turn,
            metadata=metadata or {},
        )
        self._recent_mentions.append(record)

        # Prune old mentions if needed
        if len(self._recent_mentions) > self._max_mentions:
            self._recent_mentions = self._recent_mentions[-self._max_mentions:]

        # Update token metadata
        safe_metadata = self._extract_safe_metadata(metadata) if metadata else {}
        if token not in self._token_metadata:
            self._token_metadata[token] = {
                "type": entity_type,
                "turn_first_seen": self.current_turn,
            }
        self._token_metadata[token].update(safe_metadata)
        self._token_metadata[token]["turn_last_seen"] = self.current_turn

        # Update focus slot
        slot = TYPE_TO_SLOT.get(entity_type)
        if slot:
            self._focus[slot] = token

    def _extract_safe_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Extract only non-PHI metadata."""
        safe_keys = {
            "gender",
            "is_plural",
            "is_org",
            "entity_id",
            "confidence",
            "detector",
            "semantic_role",
        }
        return {k: v for k, v in metadata.items() if k in safe_keys}

    def get_focus(self, slot: str) -> Optional[str]:
        """
        Get most recently mentioned token for a focus slot.

        Args:
            slot: Focus slot ("PERSON", "ORG", "LOCATION", "DATE")

        Returns:
            Token string or None
        """
        return self._focus.get(slot)

    def get_recent(
        self,
        entity_type: str,
        max_turns_back: int = 2,
    ) -> List[str]:
        """
        Get tokens of a type mentioned in recent turns.

        Args:
            entity_type: Entity type to filter by
            max_turns_back: How many turns back to look

        Returns:
            List of token strings, most recent first
        """
        cutoff = self.current_turn - max_turns_back
        recent = []
        seen = set()

        # Iterate in reverse (most recent first)
        for record in reversed(self._recent_mentions):
            if record.turn < cutoff:
                break
            if record.entity_type == entity_type or self._base_type(record.entity_type) == entity_type:
                if record.token not in seen:
                    recent.append(record.token)
                    seen.add(record.token)

        return recent

    def _base_type(self, entity_type: str) -> str:
        """Get base type without role suffix."""
        for suffix in ("_PATIENT", "_PROVIDER", "_RELATIVE"):
            if entity_type.endswith(suffix):
                return "NAME"
        return entity_type

    def get_token_metadata(self, token: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a token."""
        return self._token_metadata.get(token)

    def get_gender(self, token: str) -> Optional[str]:
        """Get gender for a person token (M, F, or None)."""
        meta = self._token_metadata.get(token)
        return meta.get("gender") if meta else None

    def get_recent_by_gender(self, gender: str, max_turns_back: int = 2) -> Optional[str]:
        """
        Get most recent person token with specified gender.

        Args:
            gender: "M" or "F"
            max_turns_back: How many turns back to look

        Returns:
            Token string or None
        """
        cutoff = self.current_turn - max_turns_back
        person_types = {"NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE", "PERSON"}

        for record in reversed(self._recent_mentions):
            if record.turn < cutoff:
                break
            if record.entity_type in person_types or self._base_type(record.entity_type) in person_types:
                meta = self._token_metadata.get(record.token, {})
                if meta.get("gender") == gender:
                    return record.token

        return None

    def get_all_tokens(self) -> Set[str]:
        """Get all tokens seen in this conversation."""
        return self._tokens.copy()

    def advance_turn(self) -> None:
        """Advance to next conversation turn."""
        self.current_turn += 1

    def clear(self) -> None:
        """Clear all context state."""
        self._recent_mentions.clear()
        self._focus.clear()
        self._token_metadata.clear()
        self._tokens.clear()
        self.current_turn = 0

    # --- Serialization ---

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize context state. Contains NO PHI (only tokens).

        Safe to store in session, log, or transmit.
        """
        return {
            "session_id": self.session_id,
            "conversation_id": self.conversation_id,
            "recent_mentions": [
                {
                    "token": r.token,
                    "entity_type": r.entity_type,
                    "turn": r.turn,
                    "metadata": r.metadata,
                }
                for r in self._recent_mentions
            ],
            "focus": dict(self._focus),
            "token_metadata": dict(self._token_metadata),
            "tokens": list(self._tokens),
            "current_turn": self.current_turn,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConversationContext":
        """Restore context from serialized state."""
        context = cls(
            session_id=data["session_id"],
            conversation_id=data["conversation_id"],
        )
        context._recent_mentions = [
            MentionRecord(
                token=m["token"],
                entity_type=m["entity_type"],
                turn=m["turn"],
                metadata=m.get("metadata", {}),
            )
            for m in data.get("recent_mentions", [])
        ]
        context._focus = dict(data.get("focus", {}))
        context._token_metadata = dict(data.get("token_metadata", {}))
        context._tokens = set(data.get("tokens", []))
        context.current_turn = data.get("current_turn", 0)
        return context

    def __len__(self) -> int:
        """Number of tokens tracked."""
        return len(self._tokens)

    def __contains__(self, token: str) -> bool:
        """Check if token has been observed."""
        return token in self._tokens
