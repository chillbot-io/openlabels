"""Tests for conversation management mixin.

Tests for ConversationMixin class.
"""

import sys
import threading
from unittest.mock import MagicMock, patch, call

import pytest

from scrubiq.mixins.conversation import ConversationMixin


# =============================================================================
# FIXTURES FOR MOCKING STORAGE IMPORTS
# =============================================================================

@pytest.fixture
def mock_storage_modules():
    """Mock storage and pipeline modules to avoid SQLCipher requirement."""
    # Create mock modules
    mock_storage = MagicMock()
    mock_storage.TokenStore = MagicMock()

    mock_entity_graph = MagicMock()
    mock_entity_graph.EntityGraph = MagicMock()

    mock_pipeline = MagicMock()
    mock_pipeline.entity_graph = mock_entity_graph

    mock_gender = MagicMock()
    mock_gender.infer_gender = MagicMock(return_value=None)
    mock_gender.is_name_entity_type = MagicMock(return_value=False)
    mock_pipeline.gender = mock_gender

    # Save originals
    originals = {}
    for mod_name in ["scrubiq.storage", "scrubiq.pipeline.entity_graph", "scrubiq.pipeline.gender"]:
        originals[mod_name] = sys.modules.get(mod_name)

    # Patch
    sys.modules["scrubiq.storage"] = mock_storage
    sys.modules["scrubiq.pipeline.entity_graph"] = mock_entity_graph
    sys.modules["scrubiq.pipeline.gender"] = mock_gender

    yield {
        "TokenStore": mock_storage.TokenStore,
        "EntityGraph": mock_entity_graph.EntityGraph,
    }

    # Restore
    for mod_name, original in originals.items():
        if original is not None:
            sys.modules[mod_name] = original
        elif mod_name in sys.modules:
            del sys.modules[mod_name]


# =============================================================================
# TEST CLASS SETUP
# =============================================================================

class MockConversationMixin(ConversationMixin):
    """Mock class using ConversationMixin for testing."""

    def __init__(self):
        self._unlocked = True
        self._conversations = MagicMock()
        self._current_conversation_id = None
        self._store = None
        self._entity_graph = None
        self._db = MagicMock()
        self._keys = MagicMock()
        self._conversation_lock = threading.Lock()

    def _require_unlock(self):
        if not self._unlocked:
            raise RuntimeError("Session locked")

    def _clear_redaction_cache(self):
        """Mock cache clearing."""
        pass


# =============================================================================
# CREATE_CONVERSATION TESTS
# =============================================================================

class TestCreateConversation:
    """Tests for create_conversation method."""

    def test_creates_conversation(self, mock_storage_modules):
        """Creates conversation with title."""
        mixin = MockConversationMixin()
        mock_conv = MagicMock()
        mock_conv.id = "conv-123"
        mixin._conversations.create.return_value = mock_conv

        result = mixin.create_conversation(title="Test Chat")

        mixin._conversations.create.assert_called_once_with(title="Test Chat")
        assert result.id == "conv-123"

    def test_sets_current_conversation_id(self, mock_storage_modules):
        """Sets _current_conversation_id."""
        mixin = MockConversationMixin()
        mock_conv = MagicMock()
        mock_conv.id = "conv-456"
        mixin._conversations.create.return_value = mock_conv

        mixin.create_conversation()

        assert mixin._current_conversation_id == "conv-456"

    def test_creates_token_store(self, mock_storage_modules):
        """Creates TokenStore scoped to conversation."""
        mixin = MockConversationMixin()
        mock_conv = MagicMock()
        mock_conv.id = "conv-789"
        mixin._conversations.create.return_value = mock_conv

        mixin.create_conversation()

        mock_storage_modules["TokenStore"].assert_called_once_with(
            mixin._db, mixin._keys, "conv-789"
        )
        assert mixin._store is not None

    def test_creates_entity_graph(self, mock_storage_modules):
        """Creates EntityGraph for pronoun resolution."""
        mixin = MockConversationMixin()
        mock_conv = MagicMock()
        mock_conv.id = "conv-abc"
        mixin._conversations.create.return_value = mock_conv

        mixin.create_conversation()

        mock_storage_modules["EntityGraph"].assert_called_once()
        call_kwargs = mock_storage_modules["EntityGraph"].call_args[1]
        assert call_kwargs["session_id"] == "conv-abc"

    def test_clears_redaction_cache(self, mock_storage_modules):
        """Clears redaction cache for PHI isolation."""
        mixin = MockConversationMixin()
        mixin._clear_redaction_cache = MagicMock()
        mock_conv = MagicMock()
        mock_conv.id = "conv-123"
        mixin._conversations.create.return_value = mock_conv

        mixin.create_conversation()

        mixin._clear_redaction_cache.assert_called_once()

    def test_default_title(self, mock_storage_modules):
        """Uses default title 'New conversation'."""
        mixin = MockConversationMixin()
        mock_conv = MagicMock()
        mock_conv.id = "id"
        mixin._conversations.create.return_value = mock_conv

        mixin.create_conversation()

        mixin._conversations.create.assert_called_once_with(title="New conversation")

    def test_requires_unlock(self, mock_storage_modules):
        """Raises when session is locked."""
        mixin = MockConversationMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.create_conversation()


# =============================================================================
# LIST_CONVERSATIONS TESTS
# =============================================================================

class TestListConversations:
    """Tests for list_conversations method."""

    def test_returns_conversations(self):
        """Returns list of conversations."""
        mixin = MockConversationMixin()
        mock_convs = [MagicMock(), MagicMock()]
        mixin._conversations.list.return_value = mock_convs

        result = mixin.list_conversations()

        assert result == mock_convs

    def test_passes_limit_and_offset(self):
        """Passes limit and offset to store."""
        mixin = MockConversationMixin()
        mixin._conversations.list.return_value = []

        mixin.list_conversations(limit=25, offset=10)

        mixin._conversations.list.assert_called_once_with(limit=25, offset=10)

    def test_default_parameters(self):
        """Uses default limit=50, offset=0."""
        mixin = MockConversationMixin()
        mixin._conversations.list.return_value = []

        mixin.list_conversations()

        mixin._conversations.list.assert_called_once_with(limit=50, offset=0)

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockConversationMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.list_conversations()


# =============================================================================
# GET_CONVERSATION TESTS
# =============================================================================

class TestGetConversation:
    """Tests for get_conversation method."""

    def test_returns_conversation(self):
        """Returns conversation by ID."""
        mixin = MockConversationMixin()
        mock_conv = MagicMock()
        mixin._conversations.get.return_value = mock_conv

        result = mixin.get_conversation("conv-123")

        assert result == mock_conv

    def test_passes_include_messages(self):
        """Passes include_messages parameter."""
        mixin = MockConversationMixin()
        mixin._conversations.get.return_value = MagicMock()

        mixin.get_conversation("conv-123", include_messages=False)

        mixin._conversations.get.assert_called_once_with(
            "conv-123", include_messages=False
        )

    def test_default_include_messages_true(self):
        """Default include_messages is True."""
        mixin = MockConversationMixin()
        mixin._conversations.get.return_value = MagicMock()

        mixin.get_conversation("conv-123")

        mixin._conversations.get.assert_called_once_with(
            "conv-123", include_messages=True
        )

    def test_returns_none_when_not_found(self):
        """Returns None when conversation not found."""
        mixin = MockConversationMixin()
        mixin._conversations.get.return_value = None

        result = mixin.get_conversation("nonexistent")

        assert result is None

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockConversationMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.get_conversation("conv-123")


# =============================================================================
# UPDATE_CONVERSATION TESTS
# =============================================================================

class TestUpdateConversation:
    """Tests for update_conversation method."""

    def test_updates_title(self):
        """Updates conversation title."""
        mixin = MockConversationMixin()
        mixin._conversations.update.return_value = True

        result = mixin.update_conversation("conv-123", title="New Title")

        mixin._conversations.update.assert_called_once_with("conv-123", title="New Title")
        assert result is True

    def test_returns_false_on_failure(self):
        """Returns False when update fails."""
        mixin = MockConversationMixin()
        mixin._conversations.update.return_value = False

        result = mixin.update_conversation("conv-123", title="Title")

        assert result is False

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockConversationMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.update_conversation("conv-123", title="Title")


# =============================================================================
# DELETE_CONVERSATION TESTS
# =============================================================================

class TestDeleteConversation:
    """Tests for delete_conversation method."""

    def test_deletes_tokens(self):
        """Deletes tokens associated with conversation."""
        mixin = MockConversationMixin()
        mixin._conversations.delete.return_value = True

        mixin.delete_conversation("conv-123")

        mixin._db.execute.assert_called_once()
        call_args = mixin._db.execute.call_args[0]
        assert "DELETE FROM tokens" in call_args[0]
        assert call_args[1] == ("conv-123",)

    def test_commits_token_deletion(self):
        """Commits token deletion transaction."""
        mixin = MockConversationMixin()
        mixin._conversations.delete.return_value = True

        mixin.delete_conversation("conv-123")

        mixin._db.conn.commit.assert_called_once()

    def test_deletes_conversation(self):
        """Deletes conversation via store."""
        mixin = MockConversationMixin()
        mixin._conversations.delete.return_value = True

        result = mixin.delete_conversation("conv-123")

        mixin._conversations.delete.assert_called_once_with("conv-123")
        assert result is True

    def test_clears_state_when_current(self):
        """Clears entity graph and store when deleting current conversation."""
        mixin = MockConversationMixin()
        mixin._current_conversation_id = "conv-123"
        mixin._entity_graph = MagicMock()
        mixin._store = MagicMock()
        mixin._clear_redaction_cache = MagicMock()
        mixin._conversations.delete.return_value = True

        mixin.delete_conversation("conv-123")

        assert mixin._entity_graph is None
        assert mixin._store is None
        assert mixin._current_conversation_id is None
        mixin._clear_redaction_cache.assert_called_once()

    def test_does_not_clear_state_when_different(self):
        """Does not clear state when deleting different conversation."""
        mixin = MockConversationMixin()
        mixin._current_conversation_id = "conv-other"
        mixin._entity_graph = MagicMock()
        mixin._store = MagicMock()
        mixin._conversations.delete.return_value = True

        mixin.delete_conversation("conv-123")

        assert mixin._entity_graph is not None
        assert mixin._store is not None
        assert mixin._current_conversation_id == "conv-other"

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockConversationMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.delete_conversation("conv-123")


# =============================================================================
# SET_CURRENT_CONVERSATION TESTS
# =============================================================================

class TestSetCurrentConversation:
    """Tests for set_current_conversation method."""

    def test_returns_true_on_success(self, mock_storage_modules):
        """Returns True when conversation exists."""
        mixin = MockConversationMixin()
        mock_conv = MagicMock()
        mixin._conversations.get.return_value = mock_conv

        result = mixin.set_current_conversation("conv-123")

        assert result is True

    def test_returns_false_when_not_found(self, mock_storage_modules):
        """Returns False when conversation not found."""
        mixin = MockConversationMixin()
        mixin._conversations.get.return_value = None

        result = mixin.set_current_conversation("nonexistent")

        assert result is False

    def test_sets_current_conversation_id(self, mock_storage_modules):
        """Sets _current_conversation_id."""
        mixin = MockConversationMixin()
        mock_conv = MagicMock()
        mixin._conversations.get.return_value = mock_conv

        mixin.set_current_conversation("conv-456")

        assert mixin._current_conversation_id == "conv-456"

    def test_creates_token_store(self, mock_storage_modules):
        """Creates new TokenStore for conversation."""
        mixin = MockConversationMixin()
        mock_conv = MagicMock()
        mixin._conversations.get.return_value = mock_conv

        mixin.set_current_conversation("conv-789")

        mock_storage_modules["TokenStore"].assert_called_once_with(
            mixin._db, mixin._keys, "conv-789"
        )

    def test_creates_entity_graph(self, mock_storage_modules):
        """Creates new EntityGraph for conversation."""
        mixin = MockConversationMixin()
        mock_conv = MagicMock()
        mixin._conversations.get.return_value = mock_conv

        mixin.set_current_conversation("conv-abc")

        mock_storage_modules["EntityGraph"].assert_called_once()
        call_kwargs = mock_storage_modules["EntityGraph"].call_args[1]
        assert call_kwargs["session_id"] == "conv-abc"

    def test_clears_redaction_cache(self, mock_storage_modules):
        """Clears redaction cache for PHI isolation."""
        mixin = MockConversationMixin()
        mixin._clear_redaction_cache = MagicMock()
        mock_conv = MagicMock()
        mixin._conversations.get.return_value = mock_conv

        mixin.set_current_conversation("conv-123")

        mixin._clear_redaction_cache.assert_called_once()

    def test_rebuilds_entity_graph(self, mock_storage_modules):
        """Calls _rebuild_entity_graph_from_store."""
        mixin = MockConversationMixin()
        mixin._rebuild_entity_graph_from_store = MagicMock()
        mock_conv = MagicMock()
        mixin._conversations.get.return_value = mock_conv

        mixin.set_current_conversation("conv-123")

        mixin._rebuild_entity_graph_from_store.assert_called_once()

    def test_requires_unlock(self, mock_storage_modules):
        """Raises when session is locked."""
        mixin = MockConversationMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.set_current_conversation("conv-123")


# =============================================================================
# _REBUILD_ENTITY_GRAPH_FROM_STORE TESTS
# =============================================================================

class TestRebuildEntityGraphFromStore:
    """Tests for _rebuild_entity_graph_from_store method."""

    def test_does_nothing_when_no_entity_graph(self):
        """Returns early when _entity_graph is None."""
        mixin = MockConversationMixin()
        mixin._entity_graph = None
        mixin._store = MagicMock()

        # Should not raise
        mixin._rebuild_entity_graph_from_store()

    def test_does_nothing_when_no_store(self):
        """Returns early when _store is None."""
        mixin = MockConversationMixin()
        mixin._entity_graph = MagicMock()
        mixin._store = None

        # Should not raise
        mixin._rebuild_entity_graph_from_store()

    def test_populates_tokens_from_store(self):
        """Populates entity graph tokens from store."""
        mixin = MockConversationMixin()
        mixin._entity_graph = MagicMock()
        mixin._entity_graph.tokens = set()
        mixin._entity_graph.token_metadata = {}
        mixin._store = MagicMock()
        mixin._store.get_name_token_mappings.return_value = {
            "[NAME_1]": ("John", "NAME"),
            "[NAME_2]": ("Jane", "NAME_PROVIDER"),
        }

        mixin._rebuild_entity_graph_from_store()

        assert "[NAME_1]" in mixin._entity_graph.tokens
        assert "[NAME_2]" in mixin._entity_graph.tokens

    def test_updates_focus(self):
        """Calls _update_focus for each token."""
        mixin = MockConversationMixin()
        mixin._entity_graph = MagicMock()
        mixin._entity_graph.tokens = set()
        mixin._entity_graph.token_metadata = {}
        mixin._store = MagicMock()
        mixin._store.get_name_token_mappings.return_value = {
            "[NAME_1]": ("John", "NAME"),
        }

        mixin._rebuild_entity_graph_from_store()

        mixin._entity_graph._update_focus.assert_called_once_with("[NAME_1]", "NAME")

    def test_handles_store_error(self):
        """Logs warning on store error."""
        mixin = MockConversationMixin()
        mixin._entity_graph = MagicMock()
        mixin._entity_graph.tokens = set()
        mixin._store = MagicMock()
        mixin._store.get_name_token_mappings.side_effect = Exception("DB error")

        # Should not raise, just log warning
        mixin._rebuild_entity_graph_from_store()


# =============================================================================
# ADD_MESSAGE TESTS
# =============================================================================

class TestAddMessage:
    """Tests for add_message method."""

    def test_adds_message(self):
        """Adds message to conversation."""
        mixin = MockConversationMixin()
        mock_message = MagicMock()
        mixin._conversations.add_message.return_value = mock_message

        result = mixin.add_message(
            conv_id="conv-123",
            role="user",
            content="Hello",
        )

        assert result == mock_message

    def test_passes_all_parameters(self):
        """Passes all parameters to store."""
        mixin = MockConversationMixin()
        mixin._conversations.add_message.return_value = MagicMock()

        mixin.add_message(
            conv_id="conv-123",
            role="assistant",
            content="Hi there",
            redacted_content="Hi [NAME_1]",
            normalized_content="Hi there",
            spans=[{"start": 0, "end": 5}],
            model="claude-3",
            provider="anthropic",
        )

        mixin._conversations.add_message.assert_called_once_with(
            conv_id="conv-123",
            role="assistant",
            content="Hi there",
            redacted_content="Hi [NAME_1]",
            normalized_content="Hi there",
            spans=[{"start": 0, "end": 5}],
            model="claude-3",
            provider="anthropic",
        )

    def test_advances_turn_for_user_messages(self):
        """Advances entity graph turn for user messages."""
        mixin = MockConversationMixin()
        mixin._entity_graph = MagicMock()
        mixin._conversations.add_message.return_value = MagicMock()

        mixin.add_message(conv_id="conv-123", role="user", content="Hello")

        mixin._entity_graph.advance_turn.assert_called_once()

    def test_does_not_advance_turn_for_assistant(self):
        """Does not advance turn for assistant messages."""
        mixin = MockConversationMixin()
        mixin._entity_graph = MagicMock()
        mixin._conversations.add_message.return_value = MagicMock()

        mixin.add_message(conv_id="conv-123", role="assistant", content="Hi")

        mixin._entity_graph.advance_turn.assert_not_called()

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockConversationMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.add_message("conv-123", "user", "Hello")


# =============================================================================
# GET_MESSAGES TESTS
# =============================================================================

class TestGetMessages:
    """Tests for get_messages method."""

    def test_returns_messages(self):
        """Returns messages from conversation."""
        mixin = MockConversationMixin()
        mock_messages = [MagicMock(), MagicMock()]
        mixin._conversations.get_messages.return_value = mock_messages

        result = mixin.get_messages("conv-123")

        assert result == mock_messages

    def test_passes_parameters(self):
        """Passes all parameters to store."""
        mixin = MockConversationMixin()
        mixin._conversations.get_messages.return_value = []

        mixin.get_messages("conv-123", limit=50, before_id="msg-456")

        mixin._conversations.get_messages.assert_called_once_with(
            conv_id="conv-123",
            limit=50,
            before_id="msg-456",
        )

    def test_default_parameters(self):
        """Uses default limit=100, before_id=None."""
        mixin = MockConversationMixin()
        mixin._conversations.get_messages.return_value = []

        mixin.get_messages("conv-123")

        mixin._conversations.get_messages.assert_called_once_with(
            conv_id="conv-123",
            limit=100,
            before_id=None,
        )

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockConversationMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.get_messages("conv-123")
