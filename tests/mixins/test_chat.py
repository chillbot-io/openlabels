"""Tests for chat mixin.

Tests for ChatMixin class.
"""

import sys
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

# Pre-patch logging_utils to avoid PHI logger issues
mock_logging_utils = MagicMock()
mock_logging_utils.get_phi_safe_logger = MagicMock(return_value=MagicMock())
sys.modules["scrubiq.logging_utils"] = mock_logging_utils

from scrubiq.mixins.chat import ChatMixin
from scrubiq.types import ChatResult, PrivacyMode, RedactionResult


# =============================================================================
# TEST CLASS SETUP
# =============================================================================

class MockChatMixin(ChatMixin):
    """Mock class using ChatMixin for testing."""

    def __init__(self):
        self._unlocked = True
        self._conversations = MagicMock()
        self._llm_client = None
        self._gateway = None
        self._llm_loading = False
        self._memory = None
        self._current_conversation_id = None

    def _require_unlock(self):
        if not self._unlocked:
            raise RuntimeError("Session locked")

    def redact(self, text):
        return MagicMock(
            redacted=f"[REDACTED]{text}",
            spans=[],
            tokens_created=[],
            normalized_input=text,
        )

    def restore(self, text, mode):
        return MagicMock(
            restored=text,
            tokens_found=[],
            tokens_unknown=[],
        )

    def create_conversation(self, title="New conversation"):
        mock_conv = MagicMock()
        mock_conv.id = "new-conv-id"
        self._current_conversation_id = mock_conv.id
        return mock_conv

    def set_current_conversation(self, conv_id):
        self._current_conversation_id = conv_id
        return True


# =============================================================================
# _GET_MEMORY_CONTEXT TESTS
# =============================================================================

class TestGetMemoryContext:
    """Tests for _get_memory_context method."""

    def test_returns_empty_when_no_memory(self):
        """Returns empty string when _memory is None."""
        mixin = MockChatMixin()
        mixin._memory = None

        result = mixin._get_memory_context()

        assert result == ""

    def test_returns_empty_when_no_memories(self):
        """Returns empty string when no memories found."""
        mixin = MockChatMixin()
        mixin._memory = MagicMock()
        mixin._memory.get_memories_for_context.return_value = []

        result = mixin._get_memory_context()

        assert result == ""

    def test_formats_memories_with_tokens(self):
        """Formats memories with entity tokens."""
        mixin = MockChatMixin()
        mixin._memory = MagicMock()

        mock_mem = MagicMock()
        mock_mem.entity_token = "[NAME_1]"
        mock_mem.fact = "is a software engineer"
        mixin._memory.get_memories_for_context.return_value = [mock_mem]

        result = mixin._get_memory_context()

        assert "[NAME_1]: is a software engineer" in result
        assert "Relevant information" in result

    def test_formats_memories_without_tokens(self):
        """Formats memories without entity tokens."""
        mixin = MockChatMixin()
        mixin._memory = MagicMock()

        mock_mem = MagicMock()
        mock_mem.entity_token = None
        mock_mem.fact = "User prefers dark mode"
        mixin._memory.get_memories_for_context.return_value = [mock_mem]

        result = mixin._get_memory_context()

        assert "- User prefers dark mode" in result

    def test_handles_exception(self):
        """Returns empty string on exception."""
        mixin = MockChatMixin()
        mixin._memory = MagicMock()
        mixin._memory.get_memories_for_context.side_effect = Exception("Error")

        result = mixin._get_memory_context()

        assert result == ""


# =============================================================================
# _GET_CROSS_CONVERSATION_CONTEXT TESTS
# =============================================================================

class TestGetCrossConversationContext:
    """Tests for _get_cross_conversation_context method."""

    def test_uses_memory_store_if_available(self):
        """Uses memory store get_recent_context if available."""
        mixin = MockChatMixin()
        mixin._memory = MagicMock()
        mixin._memory.get_recent_context.return_value = [
            {"role": "user", "content": "Hello"}
        ]

        result = mixin._get_cross_conversation_context()

        mixin._memory.get_recent_context.assert_called_once()
        assert len(result) == 1

    def test_excludes_conversation_id(self):
        """Passes exclude_conversation_id to memory store."""
        mixin = MockChatMixin()
        mixin._memory = MagicMock()
        mixin._memory.get_recent_context.return_value = []

        mixin._get_cross_conversation_context(exclude_conv_id="conv-123")

        mixin._memory.get_recent_context.assert_called_once()
        call_kwargs = mixin._memory.get_recent_context.call_args[1]
        assert call_kwargs["exclude_conversation_id"] == "conv-123"

    def test_falls_back_to_conversations(self):
        """Falls back to direct conversation query when no memory."""
        mixin = MockChatMixin()
        mixin._memory = None

        mock_conv = MagicMock()
        mock_conv.id = "conv-1"
        mixin._conversations.list.return_value = [mock_conv]

        mock_msg = MagicMock()
        mock_msg.redacted_content = "Hello"
        mock_msg.role = "user"
        mixin._conversations.get_messages.return_value = [mock_msg]

        result = mixin._get_cross_conversation_context()

        assert len(result) == 1
        assert result[0]["content"] == "Hello"

    def test_returns_empty_when_no_conversations(self):
        """Returns empty list when no conversations store."""
        mixin = MockChatMixin()
        mixin._memory = None
        mixin._conversations = None

        result = mixin._get_cross_conversation_context()

        assert result == []

    def test_handles_exception(self):
        """Returns empty list on exception."""
        mixin = MockChatMixin()
        mixin._memory = MagicMock()
        mixin._memory.get_recent_context.side_effect = Exception("Error")

        result = mixin._get_cross_conversation_context()

        assert result == []


# =============================================================================
# _BUILD_LLM_MESSAGES TESTS
# =============================================================================

class TestBuildLLMMessages:
    """Tests for _build_llm_messages method."""

    def test_includes_system_prompt(self):
        """Includes system prompt as first message."""
        mixin = MockChatMixin()
        mixin._conversations = None

        result = mixin._build_llm_messages(None, "Hello")

        assert result[0]["role"] == "system"
        assert len(result[0]["content"]) > 0

    def test_includes_new_message(self):
        """Includes new message as last user message."""
        mixin = MockChatMixin()
        mixin._conversations = None

        result = mixin._build_llm_messages(None, "Test message")

        assert result[-1]["role"] == "user"
        assert result[-1]["content"] == "Test message"

    def test_includes_conversation_history(self):
        """Includes conversation history when conv_id provided."""
        mixin = MockChatMixin()

        mock_msg1 = MagicMock()
        mock_msg1.redacted_content = "Previous message"
        mock_msg1.role = "user"

        mock_msg2 = MagicMock()
        mock_msg2.redacted_content = "Previous response"
        mock_msg2.role = "assistant"

        mixin._conversations.get_messages.return_value = [mock_msg1, mock_msg2]

        result = mixin._build_llm_messages("conv-123", "New message")

        # System + 2 history + 1 new = 4
        assert len(result) == 4
        assert result[1]["content"] == "Previous message"
        assert result[2]["content"] == "Previous response"

    def test_adds_memory_context(self):
        """Adds memory context to system prompt."""
        mixin = MockChatMixin()
        mixin._memory = MagicMock()
        mock_mem = MagicMock()
        mock_mem.entity_token = "[NAME_1]"
        mock_mem.fact = "likes Python"
        mixin._memory.get_memories_for_context.return_value = [mock_mem]
        mixin._conversations = None

        result = mixin._build_llm_messages(None, "Test")

        assert "[NAME_1]" in result[0]["content"]


# =============================================================================
# GENERATE_TITLE TESTS
# =============================================================================

class TestGenerateTitle:
    """Tests for generate_title method."""

    def test_truncates_when_no_llm(self):
        """Truncates user message when no LLM available."""
        mixin = MockChatMixin()
        mixin._llm_client = None

        result = mixin.generate_title("This is a very long message")

        assert result == "This is a very long message"

    def test_uses_llm_for_title(self):
        """Uses LLM to generate title when available."""
        mixin = MockChatMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True

        mock_response = MagicMock()
        mock_response.success = True
        mock_response.text = "Generated Title"
        mixin._llm_client.chat.return_value = mock_response

        result = mixin.generate_title("Hello world")

        assert result == "Generated Title"

    def test_cleans_up_title(self):
        """Cleans up LLM quirks from title."""
        mixin = MockChatMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True

        mock_response = MagicMock()
        mock_response.success = True
        mock_response.text = '"Title: Testing Chat."'
        mixin._llm_client.chat.return_value = mock_response

        result = mixin.generate_title("Hello")

        assert result == "Testing Chat"

    def test_falls_back_on_error(self):
        """Falls back to truncated message on LLM error."""
        mixin = MockChatMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True
        mixin._llm_client.chat.side_effect = Exception("API error")

        result = mixin.generate_title("Short message")

        assert result == "Short message"

    def test_falls_back_on_empty_response(self):
        """Falls back when LLM returns empty response."""
        mixin = MockChatMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True

        mock_response = MagicMock()
        mock_response.success = True
        mock_response.text = ""
        mixin._llm_client.chat.return_value = mock_response

        result = mixin.generate_title("Test message")

        assert result == "Test message"

    def test_respects_max_length(self):
        """Respects max_length parameter."""
        mixin = MockChatMixin()
        mixin._llm_client = None

        result = mixin.generate_title(
            "This is a very long message that needs truncating",
            max_length=20,
        )

        assert len(result) <= 20


# =============================================================================
# CHAT TESTS
# =============================================================================

class TestChat:
    """Tests for chat method."""

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockChatMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.chat("Hello")

    def test_raises_when_models_loading(self):
        """Raises when models are loading."""
        mixin = MockChatMixin()
        mixin._llm_loading = True

        with pytest.raises(RuntimeError, match="MODELS_LOADING"):
            mixin.chat("Hello")

    def test_creates_conversation_when_none(self):
        """Creates new conversation when no conversation_id provided."""
        mixin = MockChatMixin()
        mixin.create_conversation = MagicMock()
        mock_conv = MagicMock()
        mock_conv.id = "new-conv"
        mixin.create_conversation.return_value = mock_conv
        mixin._llm_client = None
        mixin._gateway = None

        result = mixin.chat("Hello")

        mixin.create_conversation.assert_called_once()
        assert result.conversation_id == "new-conv"

    def test_sets_conversation_when_provided(self):
        """Sets current conversation when conversation_id provided."""
        mixin = MockChatMixin()
        mixin.set_current_conversation = MagicMock(return_value=True)
        mixin._llm_client = None
        mixin._gateway = None

        result = mixin.chat("Hello", conversation_id="existing-conv")

        mixin.set_current_conversation.assert_called_once_with("existing-conv")

    def test_redacts_user_message(self):
        """Redacts user message before LLM call."""
        mixin = MockChatMixin()
        mixin.redact = MagicMock()
        mixin.redact.return_value = MagicMock(
            redacted="[NAME_1] said hello",
            spans=[],
            tokens_created=["[NAME_1]"],
            normalized_input="John said hello",
        )
        mixin._llm_client = None
        mixin._gateway = None

        result = mixin.chat("John said hello")

        mixin.redact.assert_called_once_with("John said hello")
        assert result.redacted_request == "[NAME_1] said hello"

    def test_calls_llm_client(self):
        """Calls LLM client when available."""
        mixin = MockChatMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True

        mock_response = MagicMock()
        mock_response.success = True
        mock_response.text = "LLM response"
        mock_response.model = "claude-3"
        mock_response.provider = "anthropic"
        mock_response.tokens_used = 100
        mock_response.latency_ms = 500
        mock_response.error = None
        mixin._llm_client.chat.return_value = mock_response

        result = mixin.chat("Hello")

        # LLM is called twice: once for chat, once for title generation
        assert mixin._llm_client.chat.call_count >= 1
        assert result.response_text == "LLM response"

    def test_calls_gateway_when_no_llm_client(self):
        """Calls gateway when LLM client not available."""
        mixin = MockChatMixin()
        mixin._llm_client = None
        mixin._gateway = MagicMock()

        mock_gw_response = MagicMock()
        mock_gw_response.success = True
        mock_gw_response.text = "Gateway response"
        mock_gw_response.model = "claude-3"
        mock_gw_response.tokens_used = 50
        mock_gw_response.latency_ms = 300
        mock_gw_response.error = None
        mixin._gateway.chat.return_value = mock_gw_response

        result = mixin.chat("Hello")

        mixin._gateway.chat.assert_called_once()
        assert result.response_text == "Gateway response"

    def test_returns_error_when_no_provider(self):
        """Returns error when no LLM provider configured."""
        mixin = MockChatMixin()
        mixin._llm_client = None
        mixin._gateway = None

        result = mixin.chat("Hello")

        assert result.error is not None
        assert "No LLM provider" in result.error

    def test_restores_tokens_in_response(self):
        """Restores tokens in LLM response."""
        mixin = MockChatMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True

        mock_response = MagicMock()
        mock_response.success = True
        mock_response.text = "Hello [NAME_1]"
        mock_response.model = "claude-3"
        mock_response.provider = "anthropic"
        mock_response.tokens_used = 100
        mock_response.latency_ms = 500
        mock_response.error = None
        mixin._llm_client.chat.return_value = mock_response

        mixin.restore = MagicMock()
        mixin.restore.return_value = MagicMock(
            restored="Hello John",
            tokens_found=["[NAME_1]"],
            tokens_unknown=[],
        )

        result = mixin.chat("Hello")

        mixin.restore.assert_called_once_with("Hello [NAME_1]", PrivacyMode.RESEARCH)
        assert result.restored_response == "Hello John"

    def test_stores_messages_in_conversation(self):
        """Stores user and assistant messages in conversation."""
        mixin = MockChatMixin()
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True

        mock_response = MagicMock()
        mock_response.success = True
        mock_response.text = "Response"
        mock_response.model = "claude-3"
        mock_response.provider = "anthropic"
        mock_response.tokens_used = 100
        mock_response.latency_ms = 500
        mock_response.error = None
        mixin._llm_client.chat.return_value = mock_response

        mixin.chat("Hello")

        # Should have 2 calls: user message and assistant message
        assert mixin._conversations.add_message.call_count == 2

    def test_generates_title_for_new_conversation(self):
        """Generates title for new conversations."""
        mixin = MockChatMixin()
        mixin.generate_title = MagicMock(return_value="Chat Title")
        mixin._llm_client = MagicMock()
        mixin._llm_client.is_available.return_value = True

        mock_response = MagicMock()
        mock_response.success = True
        mock_response.text = "Response"
        mock_response.model = "claude-3"
        mock_response.provider = "anthropic"
        mock_response.tokens_used = 100
        mock_response.latency_ms = 500
        mock_response.error = None
        mixin._llm_client.chat.return_value = mock_response

        mixin.chat("Hello")

        mixin.generate_title.assert_called_once()
        mixin._conversations.update.assert_called()

    def test_returns_chat_result(self):
        """Returns ChatResult with all fields."""
        mixin = MockChatMixin()
        mixin._llm_client = None
        mixin._gateway = None

        result = mixin.chat("Hello")

        assert isinstance(result, ChatResult)
        assert result.request_text == "Hello"
        assert result.conversation_id is not None


# =============================================================================
# SEARCH_CONVERSATIONS TESTS
# =============================================================================

class TestSearchConversations:
    """Tests for search_conversations method."""

    def test_returns_empty_when_no_memory(self):
        """Returns empty list when no memory store."""
        mixin = MockChatMixin()
        mixin._memory = None

        result = mixin.search_conversations("query")

        assert result == []

    def test_searches_memory(self):
        """Searches memory store with query."""
        mixin = MockChatMixin()
        mixin._memory = MagicMock()

        mock_result = MagicMock()
        mock_result.content = "Found content"
        mock_result.conversation_id = "conv-123"
        mock_result.conversation_title = "Title"
        mock_result.role = "user"
        mock_result.relevance = 0.95
        mock_result.created_at.isoformat.return_value = "2024-01-01T00:00:00"
        mixin._memory.search_messages.return_value = [mock_result]

        result = mixin.search_conversations("query")

        assert len(result) == 1
        assert result[0]["content"] == "Found content"
        assert result[0]["relevance"] == 0.95

    def test_excludes_current_conversation(self):
        """Excludes current conversation when exclude_current=True."""
        mixin = MockChatMixin()
        mixin._memory = MagicMock()
        mixin._memory.search_messages.return_value = []
        mixin._current_conversation_id = "current-conv"

        mixin.search_conversations("query", exclude_current=True)

        call_kwargs = mixin._memory.search_messages.call_args[1]
        assert call_kwargs["exclude_conversation_id"] == "current-conv"

    def test_respects_limit(self):
        """Passes limit to memory store."""
        mixin = MockChatMixin()
        mixin._memory = MagicMock()
        mixin._memory.search_messages.return_value = []

        mixin.search_conversations("query", limit=5)

        call_kwargs = mixin._memory.search_messages.call_args[1]
        assert call_kwargs["limit"] == 5

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockChatMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.search_conversations("query")


# =============================================================================
# EXTRACT_MEMORIES_FROM_CONVERSATION TESTS
# =============================================================================

class TestExtractMemoriesFromConversation:
    """Tests for extract_memories_from_conversation method."""

    def test_returns_zero_when_no_extractor(self):
        """Returns 0 when no memory extractor."""
        import asyncio
        mixin = MockChatMixin()

        result = asyncio.get_event_loop().run_until_complete(
            mixin.extract_memories_from_conversation("conv-123")
        )

        assert result == 0

    def test_returns_zero_when_no_conversation(self):
        """Returns 0 when conversation not found."""
        import asyncio
        mixin = MockChatMixin()
        mixin._memory_extractor = MagicMock()
        mixin._conversations.get.return_value = None

        result = asyncio.get_event_loop().run_until_complete(
            mixin.extract_memories_from_conversation("nonexistent")
        )

        assert result == 0

    def test_extracts_memories(self):
        """Extracts memories from conversation messages."""
        import asyncio
        mixin = MockChatMixin()
        mixin._memory_extractor = MagicMock()
        mixin._memory_extractor.extract_from_conversation = AsyncMock(
            return_value=[MagicMock(), MagicMock()]
        )

        mock_conv = MagicMock()
        mock_msg = MagicMock()
        mock_msg.role = "user"
        mock_msg.redacted_content = "Hello"
        mock_conv.messages = [mock_msg]
        mixin._conversations.get.return_value = mock_conv

        result = asyncio.get_event_loop().run_until_complete(
            mixin.extract_memories_from_conversation("conv-123")
        )

        assert result == 2
        mixin._memory_extractor.extract_from_conversation.assert_called_once()

    def test_requires_unlock(self):
        """Raises when session is locked."""
        import asyncio
        mixin = MockChatMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            asyncio.get_event_loop().run_until_complete(
                mixin.extract_memories_from_conversation("conv-123")
            )
