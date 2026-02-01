"""Conversation management mixin for ScrubIQ."""

import logging
from typing import List, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..storage import Conversation, Message

logger = logging.getLogger(__name__)


class ConversationMixin:
    """
    Conversation CRUD operations.

    Requires these attributes on the class:
        _require_unlock: Callable
        _conversations: ConversationStore
        _current_conversation_id: Optional[str]
        _store: Optional[TokenStore]
        _entity_graph: Optional[EntityGraph]
        _db: Database
        _keys: KeyManager
        _conversation_lock: threading.Lock  # For thread safety
    """

    def create_conversation(self, title: str = "New conversation") -> "Conversation":
        """Create a new conversation with token store and entity graph."""
        from ..storage import TokenStore
        from ..pipeline.entity_graph import EntityGraph

        self._require_unlock()

        # SECURITY: Clear redaction cache when changing conversations (PHI isolation)
        self._clear_redaction_cache()

        # SECURITY: Use lock to prevent race conditions on state initialization
        with self._conversation_lock:
            conv = self._conversations.create(title=title)
            self._current_conversation_id = conv.id

            # Create token store scoped to this conversation
            self._store = TokenStore(self._db, self._keys, conv.id)

            # Create entity graph for pronoun resolution and relationship tracking
            self._entity_graph = EntityGraph(
                session_id=conv.id,
                token_store=self._store,
            )

        return conv

    def list_conversations(self, limit: int = 50, offset: int = 0) -> List["Conversation"]:
        """List conversations, most recent first."""
        self._require_unlock()
        return self._conversations.list(limit=limit, offset=offset)

    def get_conversation(
        self,
        conv_id: str,
        include_messages: bool = True,
    ) -> Optional["Conversation"]:
        """Get a conversation by ID."""
        self._require_unlock()
        return self._conversations.get(conv_id, include_messages=include_messages)

    def update_conversation(self, conv_id: str, title: str) -> bool:
        """Update conversation title."""
        self._require_unlock()
        return self._conversations.update(conv_id, title=title)

    def delete_conversation(self, conv_id: str) -> bool:
        """Delete a conversation and its messages and tokens."""
        self._require_unlock()

        # SECURITY: Use lock to prevent race conditions on state changes
        with self._conversation_lock:
            # Delete tokens associated with this conversation (uses DB's internal lock)
            self._db.execute("DELETE FROM tokens WHERE session_id = ?", (conv_id,))
            self._db.conn.commit()

            # Clear entity graph and cache if deleting current conversation
            if self._current_conversation_id == conv_id:
                self._entity_graph = None
                self._store = None
                self._current_conversation_id = None
                # SECURITY: Clear redaction cache (PHI isolation)
                self._clear_redaction_cache()

            # Delete the conversation (messages deleted via CASCADE)
            return self._conversations.delete(conv_id)

    def set_current_conversation(self, conv_id: str) -> bool:
        """Switch to an existing conversation (for token scoping)."""
        from ..storage import TokenStore
        from ..pipeline.entity_graph import EntityGraph

        self._require_unlock()

        conv = self._conversations.get(conv_id, include_messages=False)
        if not conv:
            return False

        # SECURITY: Clear redaction cache when changing conversations (PHI isolation)
        self._clear_redaction_cache()

        # SECURITY: Use lock to prevent race conditions on state changes
        with self._conversation_lock:
            self._current_conversation_id = conv_id
            self._store = TokenStore(self._db, self._keys, conv_id)

            # Create fresh entity graph for this conversation
            # Note: Graph state is not persisted - it rebuilds from token store
            self._entity_graph = EntityGraph(
                session_id=conv_id,
                token_store=self._store,
            )

            # Optionally: rebuild graph from existing tokens
            # This re-populates focus slots and metadata from token store
            self._rebuild_entity_graph_from_store()

        return True

    def _rebuild_entity_graph_from_store(self):
        """
        Rebuild entity graph state from token store.

        Called when switching to an existing conversation to restore
        pronoun resolution capability.

        NOTE: Must be called within _conversation_lock context.
        """
        if self._entity_graph is None or self._store is None:
            return

        try:
            # Get all name tokens from store
            name_mappings = self._store.get_name_token_mappings()

            for token, (value, entity_type) in name_mappings.items():
                if token not in self._entity_graph.tokens:
                    self._entity_graph.tokens.add(token)

                    # Infer gender for focus/pronoun resolution
                    metadata = {"type": entity_type, "turn": 0}

                    try:
                        from ..pipeline.gender import infer_gender, is_name_entity_type
                        if is_name_entity_type(entity_type):
                            gender = infer_gender(value)
                            if gender:
                                metadata["gender"] = gender
                    except ImportError:
                        pass

                    self._entity_graph.token_metadata[token] = metadata
                    self._entity_graph._update_focus(token, entity_type)

        except Exception as e:
            logger.warning(f"Failed to rebuild entity graph: {e}")

    def add_message(
        self,
        conv_id: str,
        role: str,
        content: str,
        redacted_content: Optional[str] = None,
        normalized_content: Optional[str] = None,
        spans: Optional[List[Dict]] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> "Message":
        """Add a message to a conversation."""
        self._require_unlock()
        
        # Advance entity graph turn for user messages
        if role == "user" and hasattr(self, '_entity_graph') and self._entity_graph:
            self._entity_graph.advance_turn()
        
        return self._conversations.add_message(
            conv_id=conv_id,
            role=role,
            content=content,
            redacted_content=redacted_content,
            normalized_content=normalized_content,
            spans=spans,
            model=model,
            provider=provider,
        )

    def get_messages(
        self,
        conv_id: str,
        limit: int = 100,
        before_id: Optional[str] = None,
    ) -> List["Message"]:
        """Get messages from a conversation."""
        self._require_unlock()
        return self._conversations.get_messages(
            conv_id=conv_id,
            limit=limit,
            before_id=before_id,
        )
