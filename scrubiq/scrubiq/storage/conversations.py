"""Conversation and message persistence.

Stores chat conversations with their messages in SQLite.
Tokens are scoped to conversation_id for proper isolation.
"""

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List

from .database import Database


logger = logging.getLogger(__name__)


@dataclass
class Message:
    """A chat message."""
    id: str
    conversation_id: str
    role: str  # 'user', 'assistant', 'system'
    content: str
    redacted_content: Optional[str] = None
    normalized_content: Optional[str] = None  # Full combined message for span alignment
    spans: Optional[List[dict]] = None  # Span info for redaction panel
    model: Optional[str] = None
    provider: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Conversation:
    """A conversation with messages."""
    id: str
    title: str
    created_at: datetime
    updated_at: datetime
    messages: List[Message] = field(default_factory=list)
    message_count: int = 0


class ConversationStore:
    """
    Manages conversation and message persistence.
    
    Conversations are independent of session - they persist across
    app restarts and re-authentication.
    """

    def __init__(self, db: Database):
        self._db = db

    def create(self, title: str = "New conversation") -> Conversation:
        """Create a new conversation."""
        conv_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        
        self._db.execute("""
            INSERT INTO conversations (id, title, created_at, updated_at)
            VALUES (?, ?, ?, ?)
        """, (conv_id, title, now, now))
        self._db.conn.commit()
        
        return Conversation(
            id=conv_id,
            title=title,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
            messages=[],
            message_count=0,
        )

    def get(self, conv_id: str, include_messages: bool = True) -> Optional[Conversation]:
        """Get a conversation by ID, optionally with messages."""
        row = self._db.fetchone("""
            SELECT id, title, created_at, updated_at,
                   (SELECT COUNT(*) FROM messages WHERE conversation_id = c.id) as message_count
            FROM conversations c
            WHERE id = ?
        """, (conv_id,))
        
        if not row:
            return None
        
        conv = Conversation(
            id=row["id"],
            title=row["title"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            message_count=row["message_count"],
        )
        
        if include_messages:
            conv.messages = self.get_messages(conv_id)
        
        return conv

    def list(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Conversation]:
        """List conversations, most recent first."""
        rows = self._db.fetchall("""
            SELECT c.id, c.title, c.created_at, c.updated_at,
                   (SELECT COUNT(*) FROM messages WHERE conversation_id = c.id) as message_count
            FROM conversations c
            ORDER BY c.updated_at DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        
        return [
            Conversation(
                id=row["id"],
                title=row["title"],
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                message_count=row["message_count"],
            )
            for row in rows
        ]

    def update(self, conv_id: str, title: Optional[str] = None) -> bool:
        """Update conversation metadata."""
        if title is None:
            return False
        
        now = datetime.now(timezone.utc).isoformat()
        cursor = self._db.execute("""
            UPDATE conversations
            SET title = ?, updated_at = ?
            WHERE id = ?
        """, (title, now, conv_id))
        self._db.conn.commit()
        
        return cursor.rowcount > 0

    def delete(self, conv_id: str) -> bool:
        """Delete a conversation and all its messages.
        
        Note: Tokens associated with this conversation should also be deleted.
        The caller (core.py) should handle token cleanup.
        """
        cursor = self._db.execute("""
            DELETE FROM conversations WHERE id = ?
        """, (conv_id,))
        self._db.conn.commit()
        
        return cursor.rowcount > 0

    def touch(self, conv_id: str) -> None:
        """Update the updated_at timestamp."""
        now = datetime.now(timezone.utc).isoformat()
        self._db.execute("""
            UPDATE conversations SET updated_at = ? WHERE id = ?
        """, (now, conv_id))
        self._db.conn.commit()
    # Messages
    def add_message(
        self,
        conv_id: str,
        role: str,
        content: str,
        redacted_content: Optional[str] = None,
        normalized_content: Optional[str] = None,
        spans: Optional[List[dict]] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> Message:
        """Add a message to a conversation."""
        msg_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        
        # Serialize spans to JSON
        spans_json = json.dumps(spans) if spans else None
        
        with self._db.transaction():
            self._db.conn.execute("""
                INSERT INTO messages 
                    (id, conversation_id, role, content, redacted_content, normalized_content, spans_json, model, provider, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (msg_id, conv_id, role, content, redacted_content, normalized_content, spans_json, model, provider, now))
            
            # Update conversation timestamp
            self._db.conn.execute("""
                UPDATE conversations SET updated_at = ? WHERE id = ?
            """, (now, conv_id))
        
        return Message(
            id=msg_id,
            conversation_id=conv_id,
            role=role,
            content=content,
            redacted_content=redacted_content,
            normalized_content=normalized_content,
            spans=spans,
            model=model,
            provider=provider,
            created_at=datetime.fromisoformat(now),
        )

    def get_messages(
        self,
        conv_id: str,
        limit: Optional[int] = None,
    ) -> List[Message]:
        """Get messages for a conversation, oldest first."""
        if limit:
            rows = self._db.fetchall("""
                SELECT id, conversation_id, role, content, redacted_content, normalized_content, spans_json,
                       model, provider, created_at
                FROM messages
                WHERE conversation_id = ?
                ORDER BY created_at ASC
                LIMIT ?
            """, (conv_id, limit))
        else:
            rows = self._db.fetchall("""
                SELECT id, conversation_id, role, content, redacted_content, normalized_content, spans_json,
                       model, provider, created_at
                FROM messages
                WHERE conversation_id = ?
                ORDER BY created_at ASC
            """, (conv_id,))
        
        messages = []
        for row in rows:
            # Parse spans from JSON
            spans = None
            if row["spans_json"]:
                try:
                    spans = json.loads(row["spans_json"])
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse spans_json for message {row['id']}")
            
            messages.append(Message(
                id=row["id"],
                conversation_id=row["conversation_id"],
                role=row["role"],
                content=row["content"],
                redacted_content=row["redacted_content"],
                normalized_content=row["normalized_content"],
                spans=spans,
                model=row["model"],
                provider=row["provider"],
                created_at=datetime.fromisoformat(row["created_at"]),
            ))
        
        return messages

    def delete_message(self, msg_id: str) -> bool:
        """Delete a specific message."""
        cursor = self._db.execute("""
            DELETE FROM messages WHERE id = ?
        """, (msg_id,))
        self._db.conn.commit()
        
        return cursor.rowcount > 0

    def count(self) -> int:
        """Count total conversations."""
        row = self._db.fetchone("SELECT COUNT(*) as n FROM conversations")
        return row["n"] if row else 0
