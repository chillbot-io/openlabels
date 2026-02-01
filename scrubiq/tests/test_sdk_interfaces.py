"""
Comprehensive tests for SDK interfaces and methods.

Tests cover:
1. ConversationsInterface - all methods (create, list, get, delete, search)
2. ReviewInterface - all methods (pending, count, approve, reject)
3. MemoryInterface - all methods (search, get_for_entity, get_all, add, delete, count, stats)
4. AuditInterface - all methods (recent, verify, export)

HARDCORE: No weak tests, no skips, thorough assertions.
"""

import json
import os
import sys
import pytest
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

# Set up environment for testing
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"

# Pre-mock storage modules
_mock_storage = MagicMock()
_mock_storage.Database = MagicMock()
_mock_storage.TokenStore = MagicMock()
_mock_storage.AuditLog = MagicMock()
_mock_storage.ConversationStore = MagicMock()
_mock_storage.Conversation = MagicMock()
_mock_storage.Message = MagicMock()
_mock_storage.MemoryStore = MagicMock()
_mock_storage.MemoryExtractor = MagicMock()
_mock_storage.ImageStore = MagicMock()

for mod_name in [
    "scrubiq.storage",
    "scrubiq.storage.tokens",
    "scrubiq.storage.database",
    "scrubiq.storage.audit",
    "scrubiq.storage.images",
    "scrubiq.storage.conversations",
    "scrubiq.storage.memory",
]:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = _mock_storage


# =============================================================================
# CONVERSATIONS INTERFACE TESTS
# =============================================================================

class TestConversationsInterface:
    """Comprehensive tests for ConversationsInterface."""

    @pytest.fixture
    def mock_interface(self):
        """Create ConversationsInterface with mocked redactor."""
        from scrubiq.sdk import ConversationsInterface

        redactor = MagicMock()
        return ConversationsInterface(redactor)

    # --- create() tests ---

    def test_create_returns_dict_with_all_fields(self, mock_interface):
        """create() should return dict with id, title, created_at."""
        mock_conv = MagicMock()
        mock_conv.id = "conv_abc123"
        mock_conv.title = "Test Conversation"
        mock_conv.created_at = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        mock_interface._redactor._cr.create_conversation.return_value = mock_conv

        result = mock_interface.create("Test Conversation")

        assert result["id"] == "conv_abc123"
        assert result["title"] == "Test Conversation"
        assert result["created_at"] == "2024-01-15T10:30:00+00:00"
        mock_interface._redactor._cr.create_conversation.assert_called_once_with("Test Conversation")

    def test_create_with_default_title(self, mock_interface):
        """create() should use default title."""
        mock_conv = MagicMock()
        mock_conv.id = "conv_1"
        mock_conv.title = "New conversation"
        mock_conv.created_at = datetime.now(timezone.utc)
        mock_interface._redactor._cr.create_conversation.return_value = mock_conv

        result = mock_interface.create()

        mock_interface._redactor._cr.create_conversation.assert_called_with("New conversation")

    def test_create_result_is_json_serializable(self, mock_interface):
        """create() result should be JSON serializable."""
        mock_conv = MagicMock()
        mock_conv.id = "conv_1"
        mock_conv.title = "Test"
        mock_conv.created_at = datetime.now(timezone.utc)
        mock_interface._redactor._cr.create_conversation.return_value = mock_conv

        result = mock_interface.create("Test")

        json_str = json.dumps(result)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["id"] == "conv_1"

    # --- list() tests ---

    def test_list_returns_list_of_dicts(self, mock_interface):
        """list() should return list of conversation dicts."""
        mock_convs = [
            MagicMock(id="c1", title="Conv 1", created_at=datetime(2024, 1, 15, tzinfo=timezone.utc)),
            MagicMock(id="c2", title="Conv 2", created_at=datetime(2024, 1, 16, tzinfo=timezone.utc)),
            MagicMock(id="c3", title="Conv 3", created_at=datetime(2024, 1, 17, tzinfo=timezone.utc)),
        ]
        mock_interface._redactor._cr.list_conversations.return_value = mock_convs

        result = mock_interface.list()

        assert len(result) == 3
        assert all(isinstance(c, dict) for c in result)
        assert result[0]["id"] == "c1"
        assert result[1]["title"] == "Conv 2"

    def test_list_with_limit_and_offset(self, mock_interface):
        """list() should pass limit and offset to underlying method."""
        mock_interface._redactor._cr.list_conversations.return_value = []

        mock_interface.list(limit=25, offset=50)

        mock_interface._redactor._cr.list_conversations.assert_called_with(limit=25, offset=50)

    def test_list_empty_returns_empty_list(self, mock_interface):
        """list() should return empty list when no conversations."""
        mock_interface._redactor._cr.list_conversations.return_value = []

        result = mock_interface.list()

        assert result == []
        assert isinstance(result, list)

    def test_list_result_contains_created_at_iso_format(self, mock_interface):
        """list() results should have created_at in ISO format."""
        dt = datetime(2024, 6, 15, 14, 30, 45, tzinfo=timezone.utc)
        mock_interface._redactor._cr.list_conversations.return_value = [
            MagicMock(id="c1", title="Test", created_at=dt)
        ]

        result = mock_interface.list()

        assert result[0]["created_at"] == "2024-06-15T14:30:45+00:00"

    # --- get() tests ---

    def test_get_found_returns_full_conversation(self, mock_interface):
        """get() should return full conversation with messages when found."""
        mock_messages = [
            MagicMock(role="user", redacted_content="Hello [NAME_1]",
                     created_at=datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc)),
            MagicMock(role="assistant", redacted_content="Hi! How can I help?",
                     created_at=datetime(2024, 1, 15, 10, 1, tzinfo=timezone.utc)),
        ]
        mock_conv = MagicMock(
            id="conv_123",
            title="Test Conversation",
            created_at=datetime(2024, 1, 15, 9, 0, tzinfo=timezone.utc),
            messages=mock_messages
        )
        mock_interface._redactor._cr.get_conversation.return_value = mock_conv

        result = mock_interface.get("conv_123")

        assert result is not None
        assert result["id"] == "conv_123"
        assert result["title"] == "Test Conversation"
        assert len(result["messages"]) == 2
        assert result["messages"][0]["role"] == "user"
        assert result["messages"][0]["content"] == "Hello [NAME_1]"
        assert result["messages"][1]["role"] == "assistant"

    def test_get_not_found_returns_none(self, mock_interface):
        """get() should return None when conversation not found."""
        mock_interface._redactor._cr.get_conversation.return_value = None

        result = mock_interface.get("nonexistent_id")

        assert result is None
        mock_interface._redactor._cr.get_conversation.assert_called_with("nonexistent_id")

    def test_get_with_no_messages(self, mock_interface):
        """get() should handle conversation with no messages."""
        mock_conv = MagicMock(
            id="conv_empty",
            title="Empty",
            created_at=datetime.now(timezone.utc),
            messages=None
        )
        mock_interface._redactor._cr.get_conversation.return_value = mock_conv

        result = mock_interface.get("conv_empty")

        assert result is not None
        assert result["messages"] == []

    def test_get_with_empty_messages_list(self, mock_interface):
        """get() should handle conversation with empty messages list."""
        mock_conv = MagicMock(
            id="conv_empty",
            title="Empty",
            created_at=datetime.now(timezone.utc),
            messages=[]
        )
        mock_interface._redactor._cr.get_conversation.return_value = mock_conv

        result = mock_interface.get("conv_empty")

        assert result["messages"] == []

    # --- delete() tests ---

    def test_delete_success_returns_true(self, mock_interface):
        """delete() should return True on successful deletion."""
        mock_interface._redactor._cr.delete_conversation.return_value = True

        result = mock_interface.delete("conv_to_delete")

        assert result is True
        mock_interface._redactor._cr.delete_conversation.assert_called_once_with("conv_to_delete")

    def test_delete_not_found_returns_false(self, mock_interface):
        """delete() should return False when conversation not found."""
        mock_interface._redactor._cr.delete_conversation.return_value = False

        result = mock_interface.delete("nonexistent")

        assert result is False

    # --- search() tests ---

    def test_search_returns_matching_results(self, mock_interface):
        """search() should return matching conversations."""
        mock_results = [
            {"id": "c1", "title": "Matching conv", "snippet": "...search term..."},
            {"id": "c2", "title": "Another match", "snippet": "...term found..."},
        ]
        mock_interface._redactor._cr.search_conversations.return_value = mock_results

        result = mock_interface.search("search term")

        assert len(result) == 2
        assert result[0]["id"] == "c1"
        mock_interface._redactor._cr.search_conversations.assert_called_with("search term", limit=10)

    def test_search_with_custom_limit(self, mock_interface):
        """search() should respect limit parameter."""
        mock_interface._redactor._cr.search_conversations.return_value = []

        mock_interface.search("query", limit=5)

        mock_interface._redactor._cr.search_conversations.assert_called_with("query", limit=5)

    def test_search_empty_query(self, mock_interface):
        """search() should handle empty query."""
        mock_interface._redactor._cr.search_conversations.return_value = []

        result = mock_interface.search("")

        assert result == []

    def test_search_no_results(self, mock_interface):
        """search() should return empty list when no matches."""
        mock_interface._redactor._cr.search_conversations.return_value = []

        result = mock_interface.search("xyznonexistent")

        assert result == []


# =============================================================================
# REVIEW INTERFACE TESTS
# =============================================================================

class TestReviewInterface:
    """Comprehensive tests for ReviewInterface."""

    @pytest.fixture
    def mock_interface(self):
        """Create ReviewInterface with mocked redactor."""
        from scrubiq.sdk import ReviewInterface

        redactor = MagicMock()
        return ReviewInterface(redactor)

    # --- pending property tests ---

    def test_pending_returns_list_of_review_items(self, mock_interface):
        """pending should return list of ReviewItem objects."""
        from scrubiq.sdk import ReviewItem

        mock_interface._redactor._cr.get_pending_reviews.return_value = [
            {
                "id": "rev_1",
                "token": "[NAME_1]",
                "type": "NAME",
                "confidence": 0.55,
                "reason": "low_confidence",
                "context_redacted": "Patient [NAME_1] was admitted...",
                "suggested": "review",
            },
            {
                "id": "rev_2",
                "token": "[ORG_1]",
                "type": "ORG",
                "confidence": 0.62,
                "reason": "ambiguous_context",
                "context_redacted": "Referred to [ORG_1] for...",
                "suggested": "approve",
            },
        ]

        result = mock_interface.pending

        assert len(result) == 2
        assert all(isinstance(item, ReviewItem) for item in result)
        assert result[0].id == "rev_1"
        assert result[0].token == "[NAME_1]"
        assert result[0].type == "NAME"
        assert result[0].confidence == 0.55
        assert result[0].reason == "low_confidence"
        assert result[0].context == "Patient [NAME_1] was admitted..."
        assert result[0].suggested_action == "review"

    def test_pending_empty_returns_empty_list(self, mock_interface):
        """pending should return empty list when no pending reviews."""
        mock_interface._redactor._cr.get_pending_reviews.return_value = []

        result = mock_interface.pending

        assert result == []
        assert isinstance(result, list)

    def test_pending_review_item_to_dict(self, mock_interface):
        """ReviewItems from pending should be serializable."""
        mock_interface._redactor._cr.get_pending_reviews.return_value = [
            {
                "id": "rev_1",
                "token": "[NAME_1]",
                "type": "NAME",
                "confidence": 0.6,
                "reason": "low_confidence",
                "context_redacted": "Context...",
                "suggested": "review",
            }
        ]

        result = mock_interface.pending
        d = result[0].to_dict()

        assert d["id"] == "rev_1"
        assert d["token"] == "[NAME_1]"
        json_str = json.dumps(d)
        assert isinstance(json_str, str)

    # --- count property tests ---

    def test_count_returns_integer(self, mock_interface):
        """count should return number of pending reviews."""
        mock_interface._redactor._cr.get_review_count.return_value = 42

        result = mock_interface.count

        assert result == 42
        assert isinstance(result, int)

    def test_count_zero_when_empty(self, mock_interface):
        """count should return 0 when no pending reviews."""
        mock_interface._redactor._cr.get_review_count.return_value = 0

        result = mock_interface.count

        assert result == 0

    # --- approve() tests ---

    def test_approve_success_returns_true(self, mock_interface):
        """approve() should return True on success."""
        mock_interface._redactor._cr.approve_review.return_value = True

        result = mock_interface.approve("rev_123")

        assert result is True
        mock_interface._redactor._cr.approve_review.assert_called_once_with("rev_123")

    def test_approve_not_found_returns_false(self, mock_interface):
        """approve() should return False when item not found."""
        mock_interface._redactor._cr.approve_review.return_value = False

        result = mock_interface.approve("nonexistent")

        assert result is False

    # --- reject() tests ---

    def test_reject_success_returns_true(self, mock_interface):
        """reject() should return True on success."""
        mock_interface._redactor._cr.reject_review.return_value = True

        result = mock_interface.reject("rev_123")

        assert result is True
        mock_interface._redactor._cr.reject_review.assert_called_once_with("rev_123")

    def test_reject_not_found_returns_false(self, mock_interface):
        """reject() should return False when item not found."""
        mock_interface._redactor._cr.reject_review.return_value = False

        result = mock_interface.reject("nonexistent")

        assert result is False


# =============================================================================
# MEMORY INTERFACE TESTS
# =============================================================================

class TestMemoryInterface:
    """Comprehensive tests for MemoryInterface."""

    @pytest.fixture
    def mock_interface(self):
        """Create MemoryInterface with mocked redactor."""
        from scrubiq.sdk import MemoryInterface

        redactor = MagicMock()
        return MemoryInterface(redactor)

    @pytest.fixture
    def mock_interface_with_store(self, mock_interface):
        """Create MemoryInterface with a mocked memory store."""
        mock_store = MagicMock()
        mock_interface._redactor._cr._memory = mock_store
        return mock_interface, mock_store

    # --- _get_memory_store() tests ---

    def test_get_memory_store_returns_store_when_exists(self, mock_interface):
        """_get_memory_store should return store when available."""
        mock_store = MagicMock()
        mock_interface._redactor._cr._memory = mock_store

        result = mock_interface._get_memory_store()

        assert result is mock_store

    def test_get_memory_store_returns_none_when_no_memory_attr(self, mock_interface):
        """_get_memory_store should return None when _memory attr missing."""
        del mock_interface._redactor._cr._memory

        result = mock_interface._get_memory_store()

        assert result is None

    def test_get_memory_store_returns_none_when_memory_is_none(self, mock_interface):
        """_get_memory_store should return None when _memory is None."""
        mock_interface._redactor._cr._memory = None

        result = mock_interface._get_memory_store()

        assert result is None

    # --- search() tests ---

    def test_search_returns_formatted_results(self, mock_interface_with_store):
        """search() should return properly formatted results."""
        interface, store = mock_interface_with_store

        mock_results = [
            MagicMock(
                content="[NAME_1] mentioned they prefer mornings",
                conversation_id="conv_1",
                conversation_title="Morning chat",
                role="user",
                relevance=0.95,
                created_at=datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc)
            ),
            MagicMock(
                content="[NAME_1] takes medication daily",
                conversation_id="conv_2",
                conversation_title="Medical discussion",
                role="assistant",
                relevance=0.82,
                created_at=datetime(2024, 1, 16, 14, 0, tzinfo=timezone.utc)
            ),
        ]
        store.search_messages.return_value = mock_results

        result = interface.search("mornings", limit=5)

        assert len(result) == 2
        assert result[0]["content"] == "[NAME_1] mentioned they prefer mornings"
        assert result[0]["conversation_id"] == "conv_1"
        assert result[0]["role"] == "user"
        assert result[0]["relevance"] == 0.95
        assert "2024-01-15" in result[0]["created_at"]
        store.search_messages.assert_called_with("mornings", limit=5)

    def test_search_returns_empty_when_no_store(self, mock_interface):
        """search() should return empty list when no memory store."""
        mock_interface._redactor._cr._memory = None

        result = interface = mock_interface.search("query")

        assert result == []

    def test_search_handles_string_created_at(self, mock_interface_with_store):
        """search() should handle created_at as string."""
        interface, store = mock_interface_with_store

        mock_result = MagicMock(
            content="Test",
            conversation_id="c1",
            conversation_title="Title",
            role="user",
            relevance=0.9,
            created_at="2024-01-15T10:30:00Z"  # String, not datetime
        )
        store.search_messages.return_value = [mock_result]

        result = interface.search("test")

        assert result[0]["created_at"] == "2024-01-15T10:30:00Z"

    def test_search_empty_query(self, mock_interface_with_store):
        """search() should handle empty query."""
        interface, store = mock_interface_with_store
        store.search_messages.return_value = []

        result = interface.search("")

        assert result == []

    # --- get_for_entity() tests ---

    def test_get_for_entity_returns_memories(self, mock_interface_with_store):
        """get_for_entity() should return memories for specific entity."""
        interface, store = mock_interface_with_store

        mock_memories = [
            MagicMock(to_dict=lambda: {"fact": "[NAME_1] is 65 years old", "category": "medical"}),
            MagicMock(to_dict=lambda: {"fact": "[NAME_1] has diabetes", "category": "medical"}),
        ]
        store.get_memories.return_value = mock_memories

        result = interface.get_for_entity("[NAME_1]", limit=10)

        assert len(result) == 2
        store.get_memories.assert_called_with(entity_token="[NAME_1]", limit=10)

    def test_get_for_entity_no_store_returns_empty(self, mock_interface):
        """get_for_entity() should return empty list when no store."""
        mock_interface._redactor._cr._memory = None

        result = mock_interface.get_for_entity("[NAME_1]")

        assert result == []

    # --- get_all() tests ---

    def test_get_all_returns_all_memories(self, mock_interface_with_store):
        """get_all() should return all memories."""
        interface, store = mock_interface_with_store

        mock_memories = [
            MagicMock(to_dict=lambda: {"id": "m1", "fact": "Fact 1"}),
            MagicMock(to_dict=lambda: {"id": "m2", "fact": "Fact 2"}),
            MagicMock(to_dict=lambda: {"id": "m3", "fact": "Fact 3"}),
        ]
        store.get_memories.return_value = mock_memories

        result = interface.get_all(limit=50)

        assert len(result) == 3
        store.get_memories.assert_called_with(category=None, limit=50)

    def test_get_all_with_category_filter(self, mock_interface_with_store):
        """get_all() should filter by category."""
        interface, store = mock_interface_with_store
        store.get_memories.return_value = []

        interface.get_all(limit=20, category="medical")

        store.get_memories.assert_called_with(category="medical", limit=20)

    def test_get_all_no_store_returns_empty(self, mock_interface):
        """get_all() should return empty list when no store."""
        mock_interface._redactor._cr._memory = None

        result = mock_interface.get_all()

        assert result == []

    # --- add() tests ---

    def test_add_memory_success(self, mock_interface_with_store):
        """add() should return True on success."""
        interface, store = mock_interface_with_store
        interface._redactor._cr._current_conversation_id = "conv_123"

        result = interface.add(
            fact="[NAME_1] prefers tea over coffee",
            entity_token="[NAME_1]",
            category="preference",
            confidence=0.9
        )

        assert result is True
        store.add_memory.assert_called_once_with(
            conversation_id="conv_123",
            fact="[NAME_1] prefers tea over coffee",
            category="preference",
            entity_token="[NAME_1]",
            confidence=0.9
        )

    def test_add_memory_with_defaults(self, mock_interface_with_store):
        """add() should use default values."""
        interface, store = mock_interface_with_store
        interface._redactor._cr._current_conversation_id = "conv_1"

        interface.add(fact="Simple fact")

        store.add_memory.assert_called_with(
            conversation_id="conv_1",
            fact="Simple fact",
            category="general",
            entity_token=None,
            confidence=0.9
        )

    def test_add_memory_no_conversation_uses_sdk(self, mock_interface_with_store):
        """add() should use 'sdk' as conversation_id when none set."""
        interface, store = mock_interface_with_store
        interface._redactor._cr._current_conversation_id = None

        interface.add(fact="Test fact")

        call_args = store.add_memory.call_args
        assert call_args.kwargs["conversation_id"] == "sdk"

    def test_add_memory_failure_returns_false(self, mock_interface_with_store):
        """add() should return False on failure."""
        interface, store = mock_interface_with_store
        interface._redactor._cr._current_conversation_id = "conv_1"
        store.add_memory.side_effect = Exception("Database error")

        result = interface.add(fact="Test")

        assert result is False

    def test_add_no_store_returns_false(self, mock_interface):
        """add() should return False when no store."""
        mock_interface._redactor._cr._memory = None

        result = mock_interface.add(fact="Test")

        assert result is False

    # --- delete() tests ---

    def test_delete_success(self, mock_interface_with_store):
        """delete() should return True on success."""
        interface, store = mock_interface_with_store
        store.delete_memory.return_value = True

        result = interface.delete("mem_123")

        assert result is True
        store.delete_memory.assert_called_once_with("mem_123")

    def test_delete_not_found(self, mock_interface_with_store):
        """delete() should return False when not found."""
        interface, store = mock_interface_with_store
        store.delete_memory.return_value = False

        result = interface.delete("nonexistent")

        assert result is False

    def test_delete_no_store_returns_false(self, mock_interface):
        """delete() should return False when no store."""
        mock_interface._redactor._cr._memory = None

        result = mock_interface.delete("mem_123")

        assert result is False

    # --- count property tests ---

    def test_count_returns_memory_count(self, mock_interface_with_store):
        """count should return number of memories."""
        interface, store = mock_interface_with_store
        store.count_memories.return_value = 156

        result = interface.count

        assert result == 156

    def test_count_no_store_returns_zero(self, mock_interface):
        """count should return 0 when no store."""
        mock_interface._redactor._cr._memory = None

        result = mock_interface.count

        assert result == 0

    # --- stats property tests ---

    def test_stats_returns_memory_stats(self, mock_interface_with_store):
        """stats should return memory statistics."""
        interface, store = mock_interface_with_store
        mock_stats = {
            "total": 156,
            "by_category": {
                "medical": 89,
                "preference": 45,
                "general": 22,
            },
            "by_entity": {
                "[NAME_1]": 78,
                "[NAME_2]": 45,
            }
        }
        store.get_memory_stats.return_value = mock_stats

        result = interface.stats

        assert result["total"] == 156
        assert result["by_category"]["medical"] == 89

    def test_stats_no_store_returns_empty_dict(self, mock_interface):
        """stats should return empty dict when no store."""
        mock_interface._redactor._cr._memory = None

        result = mock_interface.stats

        assert result == {}


# =============================================================================
# AUDIT INTERFACE TESTS
# =============================================================================

class TestAuditInterface:
    """Comprehensive tests for AuditInterface."""

    @pytest.fixture
    def mock_interface(self):
        """Create AuditInterface with mocked redactor."""
        from scrubiq.sdk import AuditInterface

        redactor = MagicMock()
        return AuditInterface(redactor)

    # --- recent() tests ---

    def test_recent_returns_entries(self, mock_interface):
        """recent() should return list of audit entries."""
        mock_entries = [
            {"sequence": 1, "event": "SESSION_UNLOCK", "timestamp": "2024-01-15T10:00:00Z", "data": {}},
            {"sequence": 2, "event": "REDACT", "timestamp": "2024-01-15T10:01:00Z", "data": {"spans": 3}},
            {"sequence": 3, "event": "RESTORE", "timestamp": "2024-01-15T10:02:00Z", "data": {"tokens": 2}},
        ]
        mock_interface._redactor._cr.get_audit_entries.return_value = mock_entries

        result = mock_interface.recent(limit=100)

        assert len(result) == 3
        assert result[0]["event"] == "SESSION_UNLOCK"
        assert result[1]["sequence"] == 2
        mock_interface._redactor._cr.get_audit_entries.assert_called_with(limit=100)

    def test_recent_with_default_limit(self, mock_interface):
        """recent() should use default limit of 100."""
        mock_interface._redactor._cr.get_audit_entries.return_value = []

        mock_interface.recent()

        mock_interface._redactor._cr.get_audit_entries.assert_called_with(limit=100)

    def test_recent_empty_returns_empty_list(self, mock_interface):
        """recent() should return empty list when no entries."""
        mock_interface._redactor._cr.get_audit_entries.return_value = []

        result = mock_interface.recent()

        assert result == []

    # --- verify() tests ---

    def test_verify_chain_valid(self, mock_interface):
        """verify() should return True when chain is valid."""
        mock_interface._redactor._cr.verify_audit_chain.return_value = (True, None)

        result = mock_interface.verify()

        assert result is True

    def test_verify_chain_invalid(self, mock_interface):
        """verify() should return False when chain is invalid."""
        mock_interface._redactor._cr.verify_audit_chain.return_value = (False, "Hash mismatch at sequence 42")

        result = mock_interface.verify()

        assert result is False

    # --- export() tests ---

    def test_export_json_format(self, mock_interface):
        """export() should return JSON string for json format."""
        mock_entries = [
            {"sequence": 1, "event": "REDACT", "timestamp": "2024-01-15T10:00:00Z", "data": {}},
            {"sequence": 2, "event": "RESTORE", "timestamp": "2024-01-15T11:00:00Z", "data": {}},
        ]
        mock_interface._redactor._cr.get_audit_entries.return_value = mock_entries

        result = mock_interface.export(
            start="2024-01-01T00:00:00",
            end="2024-12-31T23:59:59",
            format="json"
        )

        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert len(parsed) == 2

    def test_export_csv_format(self, mock_interface):
        """export() should return CSV string for csv format."""
        mock_entries = [
            {"sequence": 1, "event": "REDACT", "timestamp": "2024-01-15T10:00:00Z", "data": {"spans": 5}},
            {"sequence": 2, "event": "RESTORE", "timestamp": "2024-01-15T11:00:00Z", "data": {}},
        ]
        mock_interface._redactor._cr.get_audit_entries.return_value = mock_entries

        result = mock_interface.export(
            start="2024-01-01T00:00:00",
            end="2024-12-31T23:59:59",
            format="csv"
        )

        lines = result.split("\n")
        assert lines[0] == "sequence,event,timestamp,data"
        assert "1,REDACT,2024-01-15T10:00:00Z" in lines[1]

    def test_export_filters_by_date_range(self, mock_interface):
        """export() should filter entries by date range."""
        mock_entries = [
            {"sequence": 1, "event": "OLD", "timestamp": "2023-01-15T10:00:00Z", "data": {}},
            {"sequence": 2, "event": "IN_RANGE", "timestamp": "2024-06-15T10:00:00Z", "data": {}},
            {"sequence": 3, "event": "FUTURE", "timestamp": "2025-01-15T10:00:00Z", "data": {}},
        ]
        mock_interface._redactor._cr.get_audit_entries.return_value = mock_entries

        result = mock_interface.export(
            start="2024-01-01T00:00:00",
            end="2024-12-31T23:59:59",
            format="json"
        )

        parsed = json.loads(result)
        assert len(parsed) == 1
        assert parsed[0]["event"] == "IN_RANGE"

    def test_export_empty_result(self, mock_interface):
        """export() should handle empty date range."""
        mock_interface._redactor._cr.get_audit_entries.return_value = []

        result = mock_interface.export(
            start="2024-01-01T00:00:00",
            end="2024-01-02T00:00:00",
            format="json"
        )

        parsed = json.loads(result)
        assert parsed == []

    def test_export_csv_escapes_data(self, mock_interface):
        """export() CSV should properly escape data field."""
        mock_entries = [
            {"sequence": 1, "event": "TEST", "timestamp": "2024-06-15T10:00:00Z",
             "data": {"key": "value with, comma"}},
        ]
        mock_interface._redactor._cr.get_audit_entries.return_value = mock_entries

        result = mock_interface.export(
            start="2024-01-01T00:00:00",
            end="2024-12-31T23:59:59",
            format="csv"
        )

        # Should have the data wrapped in quotes
        assert '"{' in result


# =============================================================================
# TOKENS INTERFACE ADDITIONAL TESTS
# =============================================================================

class TestTokensInterfaceExtended:
    """Extended tests for TokensInterface edge cases."""

    @pytest.fixture
    def mock_interface(self):
        """Create TokensInterface with mocked redactor."""
        from scrubiq.sdk import TokensInterface

        redactor = MagicMock()
        redactor._cr.get_tokens.return_value = [
            {"token": "[NAME_1]", "type": "NAME", "original": "John Smith", "confidence": 0.95},
            {"token": "[SSN_1]", "type": "SSN", "original": "123-45-6789", "confidence": 0.99},
            {"token": "[DOB_1]", "type": "DOB", "original": "1985-03-15", "confidence": 0.92},
        ]
        redactor._cr.get_token_count.return_value = 3
        return TokensInterface(redactor)

    def test_lookup_returns_safe_harbor_if_present(self, mock_interface):
        """lookup() should include safe_harbor value if present."""
        mock_interface._redactor._cr.get_tokens.return_value = [
            {"token": "[DOB_1]", "type": "DOB", "original": "1985-03-15", "safe_harbor": "1985"}
        ]

        result = mock_interface.lookup("[DOB_1]")

        assert result["safe_harbor"] == "1985"

    def test_lookup_returns_none_for_safe_harbor_if_missing(self, mock_interface):
        """lookup() should return None for safe_harbor if not present."""
        mock_interface._redactor._cr.get_tokens.return_value = [
            {"token": "[NAME_1]", "type": "NAME", "original": "John"}
        ]

        result = mock_interface.lookup("[NAME_1]")

        assert result["safe_harbor"] is None

    def test_entities_returns_all_entity_fields(self, mock_interface):
        """entities() should return Entity objects with all fields."""
        from scrubiq.sdk import Entity

        mock_interface._redactor._cr.get_tokens.return_value = [
            {"token": "[NAME_1]", "type": "NAME", "original": "John", "confidence": 0.95},
        ]

        entities = mock_interface.entities()

        assert len(entities) == 1
        assert isinstance(entities[0], Entity)
        assert entities[0].text == "John"
        assert entities[0].type == "NAME"
        assert entities[0].token == "[NAME_1]"
        assert entities[0].confidence == 0.95
        assert entities[0].start == 0  # Position not tracked
        assert entities[0].end == 0

    def test_entities_handles_missing_confidence(self, mock_interface):
        """entities() should use default confidence if missing."""
        mock_interface._redactor._cr.get_tokens.return_value = [
            {"token": "[NAME_1]", "type": "NAME", "original": "John"},  # No confidence
        ]

        entities = mock_interface.entities()

        assert entities[0].confidence == 1.0  # Default

    def test_map_handles_missing_fields(self, mock_interface):
        """map() should handle tokens with missing fields."""
        mock_interface._redactor._cr.get_tokens.return_value = [
            {"token": "[NAME_1]", "original": "John"},  # Missing type
            {"original": "Jane"},  # Missing token
        ]

        mapping = mock_interface.map()

        assert mapping.get("[NAME_1]") == "John"
        assert mapping.get("") == "Jane"  # Empty string for missing token
