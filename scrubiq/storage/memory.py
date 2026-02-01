"""Memory storage and retrieval for Claude-like recall.

Implements:
1. Extracted memories (facts derived from conversations)
2. Full-text search across messages (FTS5)
3. Recent conversation context
"""

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Tuple

from .database import Database
from ..constants import DEFAULT_ANTHROPIC_FAST_MODEL

logger = logging.getLogger(__name__)


# --- PHI VALIDATION - Prevent raw PHI from being stored in memories ---
# Patterns for obvious PHI that should NEVER appear in stored memories
_PHI_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # SSN - various formats
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "SSN"),
    (re.compile(r'\b\d{3}\s\d{2}\s\d{4}\b'), "SSN"),
    (re.compile(r'\b\d{9}\b(?=.*(?:ssn|social|security))', re.I), "SSN"),
    
    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "EMAIL"),
    
    # Credit card numbers (basic Luhn-checkable patterns)
    (re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'), "CREDIT_CARD"),
    
    # Phone numbers (US formats)
    (re.compile(r'\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), "PHONE"),
    
    # MRN patterns
    (re.compile(r'\bMRN[:\s#]*\d{6,12}\b', re.I), "MRN"),
]


def _contains_raw_phi(text: str) -> Optional[str]:
    """
    Check if text contains obvious raw PHI.
    
    Returns the PHI type if found, None otherwise.
    Used to prevent accidental storage of unredacted PHI in memories.
    """
    for pattern, phi_type in _PHI_PATTERNS:
        if pattern.search(text):
            return phi_type
    return None


def _validate_memory_fact(fact: str) -> None:
    """
    Validate that a memory fact is valid and doesn't contain raw PHI.
    
    Raises:
        ValueError: If fact is empty, whitespace-only, or contains raw PHI
    
    Memories should only contain tokenized references like [SSN_1], not raw values.
    """
    # Check for empty or whitespace-only facts
    if not fact or not fact.strip():
        raise ValueError("Memory fact cannot be empty or whitespace-only")
    
    # Check for raw PHI
    phi_type = _contains_raw_phi(fact)
    if phi_type:
        raise ValueError(
            f"Memory fact contains raw {phi_type}. "
            f"Facts must use tokens (e.g., [SSN_1]) instead of raw PHI values."
        )


@dataclass
class Memory:
    """An extracted memory/fact from a conversation."""
    id: str
    conversation_id: str
    entity_token: Optional[str]  # e.g., [PATIENT_1] or None for general facts
    fact: str  # The extracted fact (uses tokens, no PHI)
    category: str  # medical, preference, action, relationship
    confidence: float
    source_message_id: Optional[str]  # Which message this was extracted from
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "conversation_id": self.conversation_id,
            "entity_token": self.entity_token,
            "fact": self.fact,
            "category": self.category,
            "confidence": self.confidence,
            "source_message_id": self.source_message_id,
            "created_at": self.created_at.isoformat(),
        }


@dataclass 
class SearchResult:
    """A search result from FTS or memory query."""
    content: str
    conversation_id: str
    conversation_title: str
    role: str
    relevance: float
    created_at: datetime


class MemoryStore:
    """
    Claude-like memory system.
    
    Features:
    - Store extracted facts/memories from conversations
    - Full-text search across message content
    - Recent conversation context retrieval
    """
    
    def __init__(self, db: Database):
        self._db = db
        self._ensure_fts()
    
    def _ensure_fts(self):
        """Ensure FTS5 virtual table exists and is synced."""
        # Check if FTS table exists
        row = self._db.fetchone("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='messages_fts'
        """)
        
        if not row:
            logger.info("Creating FTS5 index for messages...")
            self._db.conn.executescript("""
                -- Create FTS5 virtual table for message search
                CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                    redacted_content,
                    content='messages',
                    content_rowid='rowid'
                );
                
                -- Triggers to keep FTS in sync
                CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
                    INSERT INTO messages_fts(rowid, redacted_content) 
                    VALUES (NEW.rowid, NEW.redacted_content);
                END;
                
                CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
                    INSERT INTO messages_fts(messages_fts, rowid, redacted_content) 
                    VALUES('delete', OLD.rowid, OLD.redacted_content);
                END;
                
                CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
                    INSERT INTO messages_fts(messages_fts, rowid, redacted_content) 
                    VALUES('delete', OLD.rowid, OLD.redacted_content);
                    INSERT INTO messages_fts(rowid, redacted_content) 
                    VALUES (NEW.rowid, NEW.redacted_content);
                END;
            """)
            
            # Populate FTS with existing messages
            self._db.conn.execute("""
                INSERT INTO messages_fts(rowid, redacted_content)
                SELECT rowid, redacted_content FROM messages 
                WHERE redacted_content IS NOT NULL
            """)
            self._db.conn.commit()
            logger.info("FTS5 index created and populated")
    
    # --- MEMORY CRUD ---
    def add_memory(
        self,
        conversation_id: str,
        fact: str,
        category: str = "general",
        entity_token: Optional[str] = None,
        confidence: float = 0.9,
        source_message_id: Optional[str] = None,
    ) -> Memory:
        """Store an extracted memory.

        Raises:
            ValueError: If fact contains raw PHI (must use tokens instead)
            ValueError: If confidence is outside [0, 1] range
        """
        # SECURITY: Validate no raw PHI in fact
        _validate_memory_fact(fact)

        # Validate confidence bounds
        if not 0 <= confidence <= 1:
            raise ValueError(f"confidence must be between 0 and 1, got {confidence}")
        
        memory_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        
        self._db.execute("""
            INSERT INTO memories (id, conversation_id, entity_token, fact, category, 
                                  confidence, source_message_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (memory_id, conversation_id, entity_token, fact, category, 
              confidence, source_message_id, now))
        self._db.conn.commit()
        
        return Memory(
            id=memory_id,
            conversation_id=conversation_id,
            entity_token=entity_token,
            fact=fact,
            category=category,
            confidence=confidence,
            source_message_id=source_message_id,
            created_at=datetime.fromisoformat(now),
        )
    
    def add_memories_batch(self, memories: List[Dict[str, Any]]) -> int:
        """Store multiple memories at once.
        
        Raises:
            ValueError: If any fact contains raw PHI
        """
        if not memories:
            return 0
        
        # SECURITY: Validate no raw PHI in any fact
        for m in memories:
            _validate_memory_fact(m["fact"])
        
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                str(uuid.uuid4()),
                m["conversation_id"],
                m.get("entity_token"),
                m["fact"],
                m.get("category", "general"),
                m.get("confidence", 0.9),
                m.get("source_message_id"),
                now,
            )
            for m in memories
        ]
        
        self._db.executemany("""
            INSERT INTO memories (id, conversation_id, entity_token, fact, category,
                                  confidence, source_message_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
        self._db.conn.commit()
        
        return len(rows)
    
    def get_memories(
        self,
        entity_token: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 50,
        min_confidence: float = 0.7,
    ) -> List[Memory]:
        """Get memories, optionally filtered by entity or category."""
        conditions = ["confidence >= ?"]
        params: List[Any] = [min_confidence]
        
        if entity_token:
            conditions.append("entity_token = ?")
            params.append(entity_token)
        
        if category:
            conditions.append("category = ?")
            params.append(category)
        
        params.append(limit)
        
        rows = self._db.fetchall(f"""
            SELECT id, conversation_id, entity_token, fact, category, 
                   confidence, source_message_id, created_at
            FROM memories
            WHERE {' AND '.join(conditions)}
            ORDER BY created_at DESC
            LIMIT ?
        """, tuple(params))
        
        return [
            Memory(
                id=row["id"],
                conversation_id=row["conversation_id"],
                entity_token=row["entity_token"],
                fact=row["fact"],
                category=row["category"],
                confidence=row["confidence"],
                source_message_id=row["source_message_id"],
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]
    
    def get_memories_for_context(self, limit: int = 10) -> List[Memory]:
        """Get recent high-confidence memories for LLM context injection."""
        rows = self._db.fetchall("""
            SELECT DISTINCT m.id, m.conversation_id, m.entity_token, m.fact, 
                   m.category, m.confidence, m.source_message_id, m.created_at
            FROM memories m
            WHERE m.confidence >= 0.8
            ORDER BY m.created_at DESC
            LIMIT ?
        """, (limit,))
        
        return [
            Memory(
                id=row["id"],
                conversation_id=row["conversation_id"],
                entity_token=row["entity_token"],
                fact=row["fact"],
                category=row["category"],
                confidence=row["confidence"],
                source_message_id=row["source_message_id"],
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]
    
    def delete_memory(self, memory_id: str) -> bool:
        """Delete a specific memory."""
        cursor = self._db.execute("DELETE FROM memories WHERE id = ?", (memory_id,))
        self._db.conn.commit()
        return cursor.rowcount > 0
    
    def delete_memories_for_conversation(self, conversation_id: str) -> int:
        """Delete all memories from a conversation."""
        cursor = self._db.execute(
            "DELETE FROM memories WHERE conversation_id = ?", 
            (conversation_id,)
        )
        self._db.conn.commit()
        return cursor.rowcount
    
    # --- FULL-TEXT SEARCH ---
    def search_messages(
        self,
        query: str,
        exclude_conversation_id: Optional[str] = None,
        limit: int = 10,
    ) -> List[SearchResult]:
        """
        Full-text search across message content.
        
        Uses SQLite FTS5 with BM25 ranking.
        """
        if not query.strip():
            return []
        
        # Escape special FTS5 characters
        safe_query = self._escape_fts_query(query)
        
        if exclude_conversation_id:
            rows = self._db.fetchall("""
                SELECT 
                    m.redacted_content,
                    m.conversation_id,
                    c.title as conversation_title,
                    m.role,
                    m.created_at,
                    bm25(messages_fts) as rank
                FROM messages_fts fts
                JOIN messages m ON fts.rowid = m.rowid
                JOIN conversations c ON m.conversation_id = c.id
                WHERE messages_fts MATCH ?
                  AND m.conversation_id != ?
                  AND m.redacted_content IS NOT NULL
                ORDER BY rank
                LIMIT ?
            """, (safe_query, exclude_conversation_id, limit))
        else:
            rows = self._db.fetchall("""
                SELECT 
                    m.redacted_content,
                    m.conversation_id,
                    c.title as conversation_title,
                    m.role,
                    m.created_at,
                    bm25(messages_fts) as rank
                FROM messages_fts fts
                JOIN messages m ON fts.rowid = m.rowid
                JOIN conversations c ON m.conversation_id = c.id
                WHERE messages_fts MATCH ?
                  AND m.redacted_content IS NOT NULL
                ORDER BY rank
                LIMIT ?
            """, (safe_query, limit))
        
        return [
            SearchResult(
                content=row["redacted_content"],
                conversation_id=row["conversation_id"],
                conversation_title=row["conversation_title"],
                role=row["role"],
                relevance=-row["rank"],  # BM25 returns negative scores, lower is better
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]
    
    def _escape_fts_query(self, query: str) -> str:
        """Escape special FTS5 characters and format query."""
        # Remove FTS5 special characters
        special_chars = '"*^():-'
        for char in special_chars:
            query = query.replace(char, ' ')
        
        # Split into words and wrap in quotes for exact matching
        words = query.split()
        if not words:
            return '""'
        
        # Use OR between words for broader matching
        return ' OR '.join(f'"{word}"' for word in words if word)
    
    # --- RECENT CONTEXT ---
    def get_recent_context(
        self,
        exclude_conversation_id: Optional[str] = None,
        limit: int = 5,
    ) -> List[Dict[str, str]]:
        """
        Get recent messages from other conversations for context.
        
        Returns messages in format ready for LLM injection.
        """
        if exclude_conversation_id:
            rows = self._db.fetchall("""
                SELECT m.redacted_content, m.role
                FROM messages m
                JOIN conversations c ON m.conversation_id = c.id
                WHERE m.conversation_id != ?
                  AND m.redacted_content IS NOT NULL
                  AND m.role IN ('user', 'assistant')
                ORDER BY m.created_at DESC
                LIMIT ?
            """, (exclude_conversation_id, limit))
        else:
            rows = self._db.fetchall("""
                SELECT m.redacted_content, m.role
                FROM messages m
                WHERE m.redacted_content IS NOT NULL
                  AND m.role IN ('user', 'assistant')
                ORDER BY m.created_at DESC
                LIMIT ?
            """, (limit,))
        
        return [
            {"role": row["role"], "content": row["redacted_content"]}
            for row in rows
        ]
    
    # --- STATISTICS ---
    def count_memories(self) -> int:
        """Count total memories."""
        row = self._db.fetchone("SELECT COUNT(*) as n FROM memories")
        return row["n"] if row else 0
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        total = self.count_memories()
        
        by_category = self._db.fetchall("""
            SELECT category, COUNT(*) as count
            FROM memories
            GROUP BY category
            ORDER BY count DESC
        """)
        
        by_entity = self._db.fetchall("""
            SELECT entity_token, COUNT(*) as count
            FROM memories
            WHERE entity_token IS NOT NULL
            GROUP BY entity_token
            ORDER BY count DESC
            LIMIT 10
        """)
        
        return {
            "total": total,
            "by_category": {row["category"]: row["count"] for row in by_category},
            "top_entities": {row["entity_token"]: row["count"] for row in by_entity},
        }


class MemoryExtractor:
    """
    Background job to extract memories from conversations.
    
    Uses LLM to analyze conversations and extract structured facts.
    """
    
    EXTRACTION_PROMPT = """Analyze this conversation and extract key facts that would be useful to remember for future conversations.

The conversation uses tokens like [PATIENT_1], [DATE_1], [SSN_1] to represent redacted PHI. Use these tokens in your extracted facts.

Extract facts in these categories:
- medical: Diagnoses, medications, allergies, procedures, lab results
- preference: User preferences, communication style, requests
- action: Pending tasks, follow-ups, scheduled items
- relationship: Relationships between entities (e.g., "[PATIENT_1] is [PATIENT_2]'s mother")
- context: Important background information

Return JSON only, no other text:
{
    "facts": [
        {
            "entity_token": "[PATIENT_1]" or null for general facts,
            "fact": "has type 2 diabetes diagnosed in [DATE_1]",
            "category": "medical",
            "confidence": 0.95
        }
    ]
}

Rules:
- Use tokens from the conversation, never invent new ones
- Keep facts concise (under 100 characters)
- Only extract facts explicitly stated or strongly implied
- Confidence should reflect how certain the fact is (0.5-1.0)
- Skip trivial or obvious facts

Conversation:
{conversation}"""

    def __init__(self, memory_store: MemoryStore, llm_client):
        self._memory = memory_store
        self._llm = llm_client
    
    async def extract_from_conversation(
        self,
        conversation_id: str,
        messages: List[Dict[str, str]],
    ) -> List[Memory]:
        """
        Extract memories from a conversation.
        
        Args:
            conversation_id: The conversation to extract from
            messages: List of {"role": str, "content": str} dicts (redacted content)
        
        Returns:
            List of extracted Memory objects
        """
        if not messages or not self._llm:
            return []
        
        # Build conversation text
        conversation_text = "\n".join(
            f"{m['role'].capitalize()}: {m['content']}"
            for m in messages
            if m.get('content')
        )
        
        if len(conversation_text) < 50:
            return []  # Too short to extract meaningful facts
        
        try:
            response = self._llm.chat(
                messages=[{
                    "role": "user",
                    "content": self.EXTRACTION_PROMPT.format(conversation=conversation_text[:8000])
                }],
                model=DEFAULT_ANTHROPIC_FAST_MODEL,
            )
            
            if not response.success or not response.text:
                logger.warning(f"Memory extraction failed: {response.error}")
                return []
            
            # Parse JSON response
            facts = self._parse_extraction(response.text)
            
            # Store memories
            memories = []
            for fact in facts:
                if fact.get("fact") and len(fact["fact"]) > 5:
                    memory = self._memory.add_memory(
                        conversation_id=conversation_id,
                        fact=fact["fact"],
                        category=fact.get("category", "general"),
                        entity_token=fact.get("entity_token"),
                        confidence=fact.get("confidence", 0.8),
                    )
                    memories.append(memory)
            
            logger.info(f"Extracted {len(memories)} memories from conversation {conversation_id[:8]}")
            return memories
            
        except Exception as e:
            logger.error(f"Memory extraction error: {e}")
            return []
    
    def _parse_extraction(self, text: str) -> List[Dict[str, Any]]:
        """Parse LLM extraction response."""
        # Try to find JSON in response
        text = text.strip()
        
        # Handle markdown code blocks
        if "```json" in text:
            start = text.index("```json") + 7
            end = text.index("```", start)
            text = text[start:end].strip()
        elif "```" in text:
            start = text.index("```") + 3
            end = text.index("```", start)
            text = text[start:end].strip()
        
        try:
            data = json.loads(text)
            return data.get("facts", [])
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse extraction JSON: {e}")
            return []
