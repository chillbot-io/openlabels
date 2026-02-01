"""Tests for memory storage module.

Tests MemoryStore, Memory dataclass, PHI validation, and search functionality.
"""

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

import pytest

# Set up environment for unencrypted testing
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"

from scrubiq.storage.database import Database
from scrubiq.storage.conversations import ConversationStore
from scrubiq.storage.memory import (
    MemoryStore,
    Memory,
    SearchResult,
    MemoryExtractor,
    _contains_raw_phi,
    _validate_memory_fact,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def db_and_stores():
    """Create a database, conversation store, and memory store."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.connect()

        conv_store = ConversationStore(db)
        memory_store = MemoryStore(db)

        yield db, conv_store, memory_store

        db.close()


# =============================================================================
# MEMORY DATACLASS TESTS
# =============================================================================

class TestMemoryDataclass:
    """Tests for Memory dataclass."""

    def test_create_memory(self):
        """Can create Memory."""
        now = datetime.now(timezone.utc)
        memory = Memory(
            id="mem-123",
            conversation_id="conv-456",
            entity_token="[PATIENT_1]",
            fact="has diabetes",
            category="medical",
            confidence=0.95,
            source_message_id="msg-789",
            created_at=now,
        )

        assert memory.id == "mem-123"
        assert memory.fact == "has diabetes"
        assert memory.category == "medical"
        assert memory.confidence == 0.95

    def test_memory_to_dict(self):
        """Memory.to_dict() returns dict representation."""
        now = datetime.now(timezone.utc)
        memory = Memory(
            id="mem-123",
            conversation_id="conv-456",
            entity_token="[PATIENT_1]",
            fact="has diabetes",
            category="medical",
            confidence=0.95,
            source_message_id=None,
            created_at=now,
        )

        d = memory.to_dict()

        assert d["id"] == "mem-123"
        assert d["fact"] == "has diabetes"
        assert d["entity_token"] == "[PATIENT_1]"
        assert "created_at" in d


class TestSearchResultDataclass:
    """Tests for SearchResult dataclass."""

    def test_create_search_result(self):
        """Can create SearchResult."""
        result = SearchResult(
            content="The patient has diabetes",
            conversation_id="conv-123",
            conversation_title="Medical Review",
            role="assistant",
            relevance=0.95,
            created_at=datetime.now(timezone.utc),
        )

        assert result.content == "The patient has diabetes"
        assert result.relevance == 0.95


# =============================================================================
# PHI VALIDATION TESTS
# =============================================================================

class TestPHIValidation:
    """Tests for PHI validation functions."""

    def test_contains_ssn(self):
        """Detects SSN in text."""
        assert _contains_raw_phi("SSN: 123-45-6789") == "SSN"
        assert _contains_raw_phi("SSN: 123 45 6789") == "SSN"

    def test_contains_email(self):
        """Detects email in text."""
        assert _contains_raw_phi("Contact: john@example.com") == "EMAIL"

    def test_contains_credit_card(self):
        """Detects credit card in text."""
        assert _contains_raw_phi("Card: 4111-1111-1111-1111") == "CREDIT_CARD"
        assert _contains_raw_phi("Card: 4111111111111111") == "CREDIT_CARD"

    def test_contains_phone(self):
        """Detects phone number in text."""
        assert _contains_raw_phi("Phone: (555) 123-4567") == "PHONE"
        assert _contains_raw_phi("Call 555-123-4567") == "PHONE"

    def test_contains_mrn(self):
        """Detects MRN in text."""
        assert _contains_raw_phi("MRN: 12345678") == "MRN"
        assert _contains_raw_phi("MRN#123456789") == "MRN"

    def test_no_phi_returns_none(self):
        """Returns None for text without PHI."""
        assert _contains_raw_phi("[PATIENT_1] has diabetes") is None
        assert _contains_raw_phi("The treatment was effective") is None

    def test_validate_memory_fact_empty_raises(self):
        """Empty fact raises ValueError."""
        with pytest.raises(ValueError, match="empty"):
            _validate_memory_fact("")

    def test_validate_memory_fact_whitespace_raises(self):
        """Whitespace-only fact raises ValueError."""
        with pytest.raises(ValueError, match="empty"):
            _validate_memory_fact("   ")

    def test_validate_memory_fact_with_ssn_raises(self):
        """Fact with SSN raises ValueError."""
        with pytest.raises(ValueError, match="raw SSN"):
            _validate_memory_fact("Patient SSN is 123-45-6789")

    def test_validate_memory_fact_with_email_raises(self):
        """Fact with email raises ValueError."""
        with pytest.raises(ValueError, match="raw EMAIL"):
            _validate_memory_fact("Contact patient at john@example.com")

    def test_validate_memory_fact_valid_passes(self):
        """Valid fact (with tokens) passes validation."""
        # Should not raise
        _validate_memory_fact("[PATIENT_1] has diabetes diagnosed in [DATE_1]")


# =============================================================================
# MEMORY STORE ADD TESTS
# =============================================================================

class TestMemoryStoreAdd:
    """Tests for MemoryStore.add_memory method."""

    def test_add_memory(self, db_and_stores):
        """add_memory() creates a new memory."""
        db, conv_store, memory_store = db_and_stores

        conv = conv_store.create()
        memory = memory_store.add_memory(
            conversation_id=conv.id,
            fact="[PATIENT_1] has type 2 diabetes",
            category="medical",
            entity_token="[PATIENT_1]",
            confidence=0.95,
        )

        assert memory is not None
        assert memory.id is not None
        assert memory.fact == "[PATIENT_1] has type 2 diabetes"
        assert memory.category == "medical"

    def test_add_memory_validates_phi(self, db_and_stores):
        """add_memory() rejects raw PHI."""
        db, conv_store, memory_store = db_and_stores

        conv = conv_store.create()

        with pytest.raises(ValueError, match="raw SSN"):
            memory_store.add_memory(
                conversation_id=conv.id,
                fact="Patient SSN is 123-45-6789",
            )

    def test_add_memory_validates_confidence(self, db_and_stores):
        """add_memory() validates confidence range."""
        db, conv_store, memory_store = db_and_stores

        conv = conv_store.create()

        with pytest.raises(ValueError, match="between 0 and 1"):
            memory_store.add_memory(
                conversation_id=conv.id,
                fact="Valid fact",
                confidence=1.5,
            )

    def test_add_memories_batch(self, db_and_stores):
        """add_memories_batch() adds multiple memories."""
        db, conv_store, memory_store = db_and_stores

        conv = conv_store.create()
        memories = [
            {"conversation_id": conv.id, "fact": "Fact 1", "category": "general"},
            {"conversation_id": conv.id, "fact": "Fact 2", "category": "medical"},
            {"conversation_id": conv.id, "fact": "Fact 3", "category": "action"},
        ]

        count = memory_store.add_memories_batch(memories)

        assert count == 3
        assert memory_store.count_memories() == 3

    def test_add_memories_batch_empty(self, db_and_stores):
        """add_memories_batch() handles empty list."""
        db, conv_store, memory_store = db_and_stores

        count = memory_store.add_memories_batch([])

        assert count == 0

    def test_add_memories_batch_validates_phi(self, db_and_stores):
        """add_memories_batch() validates all facts."""
        db, conv_store, memory_store = db_and_stores

        conv = conv_store.create()
        memories = [
            {"conversation_id": conv.id, "fact": "Valid fact"},
            {"conversation_id": conv.id, "fact": "SSN: 123-45-6789"},  # Invalid
        ]

        with pytest.raises(ValueError, match="raw SSN"):
            memory_store.add_memories_batch(memories)


# =============================================================================
# MEMORY STORE GET TESTS
# =============================================================================

class TestMemoryStoreGet:
    """Tests for MemoryStore.get_memories method."""

    def test_get_memories_all(self, db_and_stores):
        """get_memories() returns all memories."""
        db, conv_store, memory_store = db_and_stores

        conv = conv_store.create()
        memory_store.add_memory(conv.id, "Fact 1")
        memory_store.add_memory(conv.id, "Fact 2")
        memory_store.add_memory(conv.id, "Fact 3")

        memories = memory_store.get_memories()

        assert len(memories) == 3

    def test_get_memories_by_entity(self, db_and_stores):
        """get_memories() filters by entity_token."""
        db, conv_store, memory_store = db_and_stores

        conv = conv_store.create()
        memory_store.add_memory(conv.id, "Fact 1", entity_token="[PATIENT_1]")
        memory_store.add_memory(conv.id, "Fact 2", entity_token="[PATIENT_1]")
        memory_store.add_memory(conv.id, "Fact 3", entity_token="[PATIENT_2]")

        memories = memory_store.get_memories(entity_token="[PATIENT_1]")

        assert len(memories) == 2

    def test_get_memories_by_category(self, db_and_stores):
        """get_memories() filters by category."""
        db, conv_store, memory_store = db_and_stores

        conv = conv_store.create()
        memory_store.add_memory(conv.id, "Medical fact", category="medical")
        memory_store.add_memory(conv.id, "Action item", category="action")
        memory_store.add_memory(conv.id, "Another medical", category="medical")

        memories = memory_store.get_memories(category="medical")

        assert len(memories) == 2

    def test_get_memories_by_min_confidence(self, db_and_stores):
        """get_memories() filters by min_confidence."""
        db, conv_store, memory_store = db_and_stores

        conv = conv_store.create()
        memory_store.add_memory(conv.id, "High conf", confidence=0.95)
        memory_store.add_memory(conv.id, "Medium conf", confidence=0.75)
        memory_store.add_memory(conv.id, "Low conf", confidence=0.5)

        memories = memory_store.get_memories(min_confidence=0.8)

        assert len(memories) == 1

    def test_get_memories_limit(self, db_and_stores):
        """get_memories() respects limit."""
        db, conv_store, memory_store = db_and_stores

        conv = conv_store.create()
        for i in range(10):
            memory_store.add_memory(conv.id, f"Fact {i}")

        memories = memory_store.get_memories(limit=5)

        assert len(memories) == 5


# =============================================================================
# MEMORY STORE DELETE TESTS
# =============================================================================

class TestMemoryStoreDelete:
    """Tests for MemoryStore delete methods."""

    def test_delete_memory(self, db_and_stores):
        """delete_memory() removes specific memory."""
        db, conv_store, memory_store = db_and_stores

        conv = conv_store.create()
        memory = memory_store.add_memory(conv.id, "To be deleted")

        result = memory_store.delete_memory(memory.id)

        assert result is True
        assert memory_store.count_memories() == 0

    def test_delete_memory_nonexistent(self, db_and_stores):
        """delete_memory() returns False for nonexistent ID."""
        db, conv_store, memory_store = db_and_stores

        result = memory_store.delete_memory("nonexistent")

        assert result is False

    def test_delete_memories_for_conversation(self, db_and_stores):
        """delete_memories_for_conversation() removes all conversation memories."""
        db, conv_store, memory_store = db_and_stores

        conv1 = conv_store.create()
        conv2 = conv_store.create()

        memory_store.add_memory(conv1.id, "Conv1 fact 1")
        memory_store.add_memory(conv1.id, "Conv1 fact 2")
        memory_store.add_memory(conv2.id, "Conv2 fact")

        count = memory_store.delete_memories_for_conversation(conv1.id)

        assert count == 2
        assert memory_store.count_memories() == 1


# =============================================================================
# MEMORY STORE CONTEXT TESTS
# =============================================================================

class TestMemoryStoreContext:
    """Tests for context retrieval methods."""

    def test_get_memories_for_context(self, db_and_stores):
        """get_memories_for_context() returns high-confidence memories."""
        db, conv_store, memory_store = db_and_stores

        conv = conv_store.create()
        memory_store.add_memory(conv.id, "High conf 1", confidence=0.9)
        memory_store.add_memory(conv.id, "High conf 2", confidence=0.85)
        memory_store.add_memory(conv.id, "Low conf", confidence=0.5)

        memories = memory_store.get_memories_for_context(limit=10)

        # Only >= 0.8 confidence
        assert len(memories) == 2


# =============================================================================
# MEMORY STORE STATISTICS TESTS
# =============================================================================

class TestMemoryStoreStatistics:
    """Tests for statistics methods."""

    def test_count_memories(self, db_and_stores):
        """count_memories() returns correct count."""
        db, conv_store, memory_store = db_and_stores

        assert memory_store.count_memories() == 0

        conv = conv_store.create()
        memory_store.add_memory(conv.id, "Fact 1")
        memory_store.add_memory(conv.id, "Fact 2")

        assert memory_store.count_memories() == 2

    def test_get_memory_stats(self, db_and_stores):
        """get_memory_stats() returns statistics."""
        db, conv_store, memory_store = db_and_stores

        conv = conv_store.create()
        memory_store.add_memory(conv.id, "Med 1", category="medical", entity_token="[P1]")
        memory_store.add_memory(conv.id, "Med 2", category="medical", entity_token="[P1]")
        memory_store.add_memory(conv.id, "Action", category="action", entity_token="[P2]")

        stats = memory_store.get_memory_stats()

        assert stats["total"] == 3
        assert stats["by_category"]["medical"] == 2
        assert stats["by_category"]["action"] == 1
        assert "[P1]" in stats["top_entities"]


# =============================================================================
# FTS SEARCH TESTS
# =============================================================================

class TestFTSSearch:
    """Tests for full-text search functionality."""

    def test_search_messages_empty_query(self, db_and_stores):
        """search_messages() returns empty for empty query."""
        db, conv_store, memory_store = db_and_stores

        results = memory_store.search_messages("")

        assert results == []

    def test_search_messages_whitespace_query(self, db_and_stores):
        """search_messages() returns empty for whitespace query."""
        db, conv_store, memory_store = db_and_stores

        results = memory_store.search_messages("   ")

        assert results == []

    def test_escape_fts_query(self, db_and_stores):
        """_escape_fts_query() escapes special characters."""
        db, conv_store, memory_store = db_and_stores

        # Test with special characters
        escaped = memory_store._escape_fts_query('test "query" with*special')

        # Should remove special chars and quote words
        assert '"' in escaped or "test" in escaped

    def test_escape_fts_query_empty(self, db_and_stores):
        """_escape_fts_query() handles empty after escaping."""
        db, conv_store, memory_store = db_and_stores

        escaped = memory_store._escape_fts_query('***')

        # Should return something safe for FTS5
        assert escaped == '""'


# =============================================================================
# RECENT CONTEXT TESTS
# =============================================================================

class TestRecentContext:
    """Tests for recent context retrieval."""

    def test_get_recent_context_empty(self, db_and_stores):
        """get_recent_context() returns empty for no messages."""
        db, conv_store, memory_store = db_and_stores

        context = memory_store.get_recent_context()

        assert context == []


# =============================================================================
# MEMORY EXTRACTOR TESTS
# =============================================================================

class TestMemoryExtractor:
    """Tests for MemoryExtractor class."""

    def test_extractor_creation(self, db_and_stores):
        """Can create MemoryExtractor."""
        db, conv_store, memory_store = db_and_stores

        mock_llm = MagicMock()
        extractor = MemoryExtractor(memory_store, mock_llm)

        assert extractor is not None

    def test_parse_extraction_valid_json(self, db_and_stores):
        """_parse_extraction() parses valid JSON."""
        db, conv_store, memory_store = db_and_stores

        mock_llm = MagicMock()
        extractor = MemoryExtractor(memory_store, mock_llm)

        json_text = '{"facts": [{"entity_token": "[PATIENT_1]", "fact": "has diabetes", "category": "medical", "confidence": 0.9}]}'
        facts = extractor._parse_extraction(json_text)

        assert len(facts) == 1
        assert facts[0]["fact"] == "has diabetes"

    def test_parse_extraction_markdown_code_block(self, db_and_stores):
        """_parse_extraction() handles markdown code blocks."""
        db, conv_store, memory_store = db_and_stores

        mock_llm = MagicMock()
        extractor = MemoryExtractor(memory_store, mock_llm)

        markdown_text = '''```json
{"facts": [{"fact": "test fact"}]}
```'''
        facts = extractor._parse_extraction(markdown_text)

        assert len(facts) == 1
        assert facts[0]["fact"] == "test fact"

    def test_parse_extraction_invalid_json(self, db_and_stores):
        """_parse_extraction() returns empty for invalid JSON."""
        db, conv_store, memory_store = db_and_stores

        mock_llm = MagicMock()
        extractor = MemoryExtractor(memory_store, mock_llm)

        facts = extractor._parse_extraction("not valid json")

        assert facts == []

    @pytest.mark.asyncio
    async def test_extract_from_conversation_empty_messages(self, db_and_stores):
        """extract_from_conversation() handles empty messages."""
        db, conv_store, memory_store = db_and_stores

        mock_llm = MagicMock()
        extractor = MemoryExtractor(memory_store, mock_llm)

        conv = conv_store.create()
        memories = await extractor.extract_from_conversation(conv.id, [])

        assert memories == []

    @pytest.mark.asyncio
    async def test_extract_from_conversation_no_llm(self, db_and_stores):
        """extract_from_conversation() handles no LLM."""
        db, conv_store, memory_store = db_and_stores

        extractor = MemoryExtractor(memory_store, None)

        conv = conv_store.create()
        messages = [{"role": "user", "content": "Hello"}]
        memories = await extractor.extract_from_conversation(conv.id, messages)

        assert memories == []

    @pytest.mark.asyncio
    async def test_extract_from_conversation_short_text(self, db_and_stores):
        """extract_from_conversation() skips very short conversations."""
        db, conv_store, memory_store = db_and_stores

        mock_llm = MagicMock()
        extractor = MemoryExtractor(memory_store, mock_llm)

        conv = conv_store.create()
        messages = [{"role": "user", "content": "Hi"}]
        memories = await extractor.extract_from_conversation(conv.id, messages)

        assert memories == []
        # LLM should not be called
        mock_llm.chat.assert_not_called()


# =============================================================================
# FTS INITIALIZATION TESTS
# =============================================================================

class TestFTSInitialization:
    """Tests for FTS5 initialization."""

    def test_fts_table_created(self, db_and_stores):
        """FTS5 virtual table is created."""
        db, conv_store, memory_store = db_and_stores

        # Check FTS table exists
        row = db.fetchone(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='messages_fts'"
        )

        assert row is not None

    def test_fts_triggers_created(self, db_and_stores):
        """FTS triggers are created."""
        db, conv_store, memory_store = db_and_stores

        triggers = db.fetchall(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        )
        trigger_names = [t["name"] for t in triggers]

        assert "messages_ai" in trigger_names  # After insert
        assert "messages_ad" in trigger_names  # After delete
        assert "messages_au" in trigger_names  # After update
