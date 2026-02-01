"""Tests for conversation storage module.

Tests ConversationStore, Conversation, and Message dataclasses.
"""

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Set up environment for unencrypted testing
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"

from scrubiq.storage.database import Database
from scrubiq.storage.conversations import (
    ConversationStore,
    Conversation,
    Message,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def db_and_store():
    """Create a database and conversation store."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.connect()

        store = ConversationStore(db)

        yield db, store

        db.close()


# =============================================================================
# CONVERSATION DATACLASS TESTS
# =============================================================================

class TestConversationDataclass:
    """Tests for Conversation dataclass."""

    def test_create_conversation(self):
        """Can create Conversation."""
        now = datetime.now(timezone.utc)
        conv = Conversation(
            id="conv-123",
            title="Test Conversation",
            created_at=now,
            updated_at=now,
        )

        assert conv.id == "conv-123"
        assert conv.title == "Test Conversation"
        assert conv.messages == []
        assert conv.message_count == 0

    def test_conversation_with_messages(self):
        """Conversation can have messages."""
        now = datetime.now(timezone.utc)
        msg = Message(
            id="msg-1",
            conversation_id="conv-123",
            role="user",
            content="Hello",
        )
        conv = Conversation(
            id="conv-123",
            title="Test",
            created_at=now,
            updated_at=now,
            messages=[msg],
            message_count=1,
        )

        assert len(conv.messages) == 1
        assert conv.message_count == 1


# =============================================================================
# MESSAGE DATACLASS TESTS
# =============================================================================

class TestMessageDataclass:
    """Tests for Message dataclass."""

    def test_create_message(self):
        """Can create Message."""
        msg = Message(
            id="msg-1",
            conversation_id="conv-123",
            role="user",
            content="Hello world",
        )

        assert msg.id == "msg-1"
        assert msg.conversation_id == "conv-123"
        assert msg.role == "user"
        assert msg.content == "Hello world"

    def test_message_optional_fields(self):
        """Message has optional fields."""
        msg = Message(
            id="msg-1",
            conversation_id="conv-123",
            role="assistant",
            content="Hello",
            redacted_content="[NAME_1]",
            normalized_content="Full message",
            spans=[{"start": 0, "end": 4}],
            model="claude-3",
            provider="anthropic",
        )

        assert msg.redacted_content == "[NAME_1]"
        assert msg.normalized_content == "Full message"
        assert msg.spans == [{"start": 0, "end": 4}]
        assert msg.model == "claude-3"
        assert msg.provider == "anthropic"


# =============================================================================
# CONVERSATION STORE CREATE TESTS
# =============================================================================

class TestConversationStoreCreate:
    """Tests for ConversationStore.create method."""

    def test_create_conversation(self, db_and_store):
        """create() creates a new conversation."""
        db, store = db_and_store

        conv = store.create(title="My Chat")

        assert conv is not None
        assert conv.id is not None
        assert conv.title == "My Chat"
        assert conv.message_count == 0

    def test_create_with_default_title(self, db_and_store):
        """create() uses default title."""
        db, store = db_and_store

        conv = store.create()

        assert conv.title == "New conversation"

    def test_create_sets_timestamps(self, db_and_store):
        """create() sets created_at and updated_at."""
        db, store = db_and_store

        conv = store.create()

        # Verify timestamps are set (they're parsed from ISO format)
        assert conv.created_at is not None
        assert conv.updated_at is not None
        # Timestamps should be recent (within the last minute)
        now = datetime.now(timezone.utc)
        # Handle both naive and aware datetimes
        created_utc = conv.created_at.replace(tzinfo=timezone.utc) if conv.created_at.tzinfo is None else conv.created_at
        assert (now - created_utc).total_seconds() < 60


# =============================================================================
# CONVERSATION STORE GET TESTS
# =============================================================================

class TestConversationStoreGet:
    """Tests for ConversationStore.get method."""

    def test_get_returns_conversation(self, db_and_store):
        """get() returns conversation by ID."""
        db, store = db_and_store

        created = store.create(title="Test")
        fetched = store.get(created.id)

        assert fetched is not None
        assert fetched.id == created.id
        assert fetched.title == "Test"

    def test_get_nonexistent_returns_none(self, db_and_store):
        """get() returns None for nonexistent ID."""
        db, store = db_and_store

        result = store.get("nonexistent-id")

        assert result is None

    def test_get_includes_messages(self, db_and_store):
        """get() includes messages by default."""
        db, store = db_and_store

        conv = store.create()
        store.add_message(conv.id, "user", "Hello")
        store.add_message(conv.id, "assistant", "Hi there!")

        fetched = store.get(conv.id)

        assert len(fetched.messages) == 2

    def test_get_without_messages(self, db_and_store):
        """get() can exclude messages."""
        db, store = db_and_store

        conv = store.create()
        store.add_message(conv.id, "user", "Hello")

        fetched = store.get(conv.id, include_messages=False)

        assert fetched.messages == []


# =============================================================================
# CONVERSATION STORE LIST TESTS
# =============================================================================

class TestConversationStoreList:
    """Tests for ConversationStore.list method."""

    def test_list_returns_conversations(self, db_and_store):
        """list() returns conversations."""
        db, store = db_and_store

        store.create(title="Conv 1")
        store.create(title="Conv 2")
        store.create(title="Conv 3")

        convs = store.list()

        assert len(convs) == 3

    def test_list_ordered_by_updated_at(self, db_and_store):
        """list() orders by updated_at descending."""
        db, store = db_and_store

        conv1 = store.create(title="First")
        conv2 = store.create(title="Second")
        conv3 = store.create(title="Third")

        # Update conv1 to make it most recent
        store.touch(conv1.id)

        convs = store.list()

        # Most recently updated should be first
        assert convs[0].id == conv1.id

    def test_list_with_limit(self, db_and_store):
        """list() respects limit."""
        db, store = db_and_store

        for i in range(10):
            store.create(title=f"Conv {i}")

        convs = store.list(limit=5)

        assert len(convs) == 5

    def test_list_with_offset(self, db_and_store):
        """list() respects offset."""
        db, store = db_and_store

        for i in range(10):
            store.create(title=f"Conv {i}")

        convs = store.list(limit=5, offset=5)

        assert len(convs) == 5


# =============================================================================
# CONVERSATION STORE UPDATE TESTS
# =============================================================================

class TestConversationStoreUpdate:
    """Tests for ConversationStore.update method."""

    def test_update_title(self, db_and_store):
        """update() changes title."""
        db, store = db_and_store

        conv = store.create(title="Old Title")
        result = store.update(conv.id, title="New Title")

        assert result is True

        fetched = store.get(conv.id)
        assert fetched.title == "New Title"

    def test_update_none_title_returns_false(self, db_and_store):
        """update() with None title returns False."""
        db, store = db_and_store

        conv = store.create()
        result = store.update(conv.id, title=None)

        assert result is False

    def test_update_nonexistent_returns_false(self, db_and_store):
        """update() returns False for nonexistent ID."""
        db, store = db_and_store

        result = store.update("nonexistent", title="New")

        assert result is False


# =============================================================================
# CONVERSATION STORE DELETE TESTS
# =============================================================================

class TestConversationStoreDelete:
    """Tests for ConversationStore.delete method."""

    def test_delete_conversation(self, db_and_store):
        """delete() removes conversation."""
        db, store = db_and_store

        conv = store.create()
        result = store.delete(conv.id)

        assert result is True
        assert store.get(conv.id) is None

    def test_delete_cascades_to_messages(self, db_and_store):
        """delete() removes associated messages."""
        db, store = db_and_store

        conv = store.create()
        store.add_message(conv.id, "user", "Hello")
        store.add_message(conv.id, "assistant", "Hi")

        store.delete(conv.id)

        # Messages should be deleted (cascade)
        messages = store.get_messages(conv.id)
        assert messages == []

    def test_delete_nonexistent_returns_false(self, db_and_store):
        """delete() returns False for nonexistent ID."""
        db, store = db_and_store

        result = store.delete("nonexistent")

        assert result is False


# =============================================================================
# CONVERSATION STORE TOUCH TESTS
# =============================================================================

class TestConversationStoreTouch:
    """Tests for ConversationStore.touch method."""

    def test_touch_updates_timestamp(self, db_and_store):
        """touch() updates updated_at timestamp."""
        db, store = db_and_store

        conv = store.create()
        original_updated = store.get(conv.id).updated_at

        # Touch after a small delay
        import time
        time.sleep(0.01)

        store.touch(conv.id)

        fetched = store.get(conv.id)
        assert fetched.updated_at > original_updated


# =============================================================================
# MESSAGE ADD TESTS
# =============================================================================

class TestAddMessage:
    """Tests for ConversationStore.add_message method."""

    def test_add_message(self, db_and_store):
        """add_message() creates message."""
        db, store = db_and_store

        conv = store.create()
        msg = store.add_message(conv.id, "user", "Hello world")

        assert msg is not None
        assert msg.id is not None
        assert msg.conversation_id == conv.id
        assert msg.role == "user"
        assert msg.content == "Hello world"

    def test_add_message_with_redacted_content(self, db_and_store):
        """add_message() stores redacted content."""
        db, store = db_and_store

        conv = store.create()
        msg = store.add_message(
            conv.id, "user",
            content="Hi, I'm John",
            redacted_content="Hi, I'm [NAME_1]"
        )

        assert msg.redacted_content == "Hi, I'm [NAME_1]"

    def test_add_message_with_spans(self, db_and_store):
        """add_message() stores spans as JSON."""
        db, store = db_and_store

        conv = store.create()
        spans = [{"start": 0, "end": 4, "type": "NAME"}]
        msg = store.add_message(
            conv.id, "user",
            content="John is here",
            spans=spans
        )

        assert msg.spans == spans

    def test_add_message_updates_conversation_timestamp(self, db_and_store):
        """add_message() updates conversation's updated_at."""
        db, store = db_and_store

        conv = store.create()
        original_updated = store.get(conv.id).updated_at

        import time
        time.sleep(0.01)

        store.add_message(conv.id, "user", "Hello")

        fetched = store.get(conv.id)
        assert fetched.updated_at > original_updated


# =============================================================================
# MESSAGE GET TESTS
# =============================================================================

class TestGetMessages:
    """Tests for ConversationStore.get_messages method."""

    def test_get_messages_empty(self, db_and_store):
        """get_messages() returns empty list for new conversation."""
        db, store = db_and_store

        conv = store.create()
        messages = store.get_messages(conv.id)

        assert messages == []

    def test_get_messages_returns_all(self, db_and_store):
        """get_messages() returns all messages."""
        db, store = db_and_store

        conv = store.create()
        store.add_message(conv.id, "user", "Hello")
        store.add_message(conv.id, "assistant", "Hi!")
        store.add_message(conv.id, "user", "How are you?")

        messages = store.get_messages(conv.id)

        assert len(messages) == 3

    def test_get_messages_ordered_by_created_at(self, db_and_store):
        """get_messages() orders by created_at ascending."""
        db, store = db_and_store

        conv = store.create()
        store.add_message(conv.id, "user", "First")
        store.add_message(conv.id, "assistant", "Second")
        store.add_message(conv.id, "user", "Third")

        messages = store.get_messages(conv.id)

        assert messages[0].content == "First"
        assert messages[1].content == "Second"
        assert messages[2].content == "Third"

    def test_get_messages_with_limit(self, db_and_store):
        """get_messages() respects limit."""
        db, store = db_and_store

        conv = store.create()
        for i in range(10):
            store.add_message(conv.id, "user", f"Message {i}")

        messages = store.get_messages(conv.id, limit=5)

        assert len(messages) == 5

    def test_get_messages_parses_spans(self, db_and_store):
        """get_messages() parses spans from JSON."""
        db, store = db_and_store

        conv = store.create()
        spans = [{"start": 0, "end": 4, "type": "NAME"}]
        store.add_message(conv.id, "user", "John", spans=spans)

        messages = store.get_messages(conv.id)

        assert messages[0].spans == spans


# =============================================================================
# MESSAGE DELETE TESTS
# =============================================================================

class TestDeleteMessage:
    """Tests for ConversationStore.delete_message method."""

    def test_delete_message(self, db_and_store):
        """delete_message() removes specific message."""
        db, store = db_and_store

        conv = store.create()
        msg1 = store.add_message(conv.id, "user", "First")
        msg2 = store.add_message(conv.id, "assistant", "Second")

        result = store.delete_message(msg1.id)

        assert result is True

        messages = store.get_messages(conv.id)
        assert len(messages) == 1
        assert messages[0].id == msg2.id

    def test_delete_nonexistent_message_returns_false(self, db_and_store):
        """delete_message() returns False for nonexistent ID."""
        db, store = db_and_store

        result = store.delete_message("nonexistent")

        assert result is False


# =============================================================================
# COUNT TESTS
# =============================================================================

class TestCount:
    """Tests for ConversationStore.count method."""

    def test_count_empty(self, db_and_store):
        """count() returns 0 for empty store."""
        db, store = db_and_store

        assert store.count() == 0

    def test_count_after_create(self, db_and_store):
        """count() returns correct count."""
        db, store = db_and_store

        store.create()
        store.create()
        store.create()

        assert store.count() == 3


# =============================================================================
# MESSAGE COUNT TESTS
# =============================================================================

class TestMessageCount:
    """Tests for message_count field."""

    def test_message_count_in_get(self, db_and_store):
        """get() includes message_count."""
        db, store = db_and_store

        conv = store.create()
        store.add_message(conv.id, "user", "1")
        store.add_message(conv.id, "assistant", "2")
        store.add_message(conv.id, "user", "3")

        fetched = store.get(conv.id)

        assert fetched.message_count == 3

    def test_message_count_in_list(self, db_and_store):
        """list() includes message_count."""
        db, store = db_and_store

        conv = store.create()
        store.add_message(conv.id, "user", "Hello")
        store.add_message(conv.id, "assistant", "Hi")

        convs = store.list()

        assert convs[0].message_count == 2


# =============================================================================
# ROLE VALIDATION TESTS
# =============================================================================

class TestRoleValidation:
    """Tests for message role validation."""

    def test_valid_roles(self, db_and_store):
        """Valid roles are accepted."""
        db, store = db_and_store

        conv = store.create()

        msg1 = store.add_message(conv.id, "user", "Hello")
        msg2 = store.add_message(conv.id, "assistant", "Hi")
        msg3 = store.add_message(conv.id, "system", "Context")

        assert msg1.role == "user"
        assert msg2.role == "assistant"
        assert msg3.role == "system"

    def test_invalid_role_raises(self, db_and_store):
        """Invalid role raises error."""
        db, store = db_and_store

        conv = store.create()

        # The database constraint should reject invalid roles
        with pytest.raises(Exception):
            store.add_message(conv.id, "invalid_role", "Hello")
