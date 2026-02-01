"""Tests for conversations API routes.

Tests conversation CRUD and message management endpoints.

Note: These tests require SQLCipher and FastAPI to be installed.
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

try:
    from scrubiq.api.routes import conversations as routes_conversations
    SCRUBIQ_AVAILABLE = True
except (ImportError, RuntimeError):
    SCRUBIQ_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not SCRUBIQ_AVAILABLE,
    reason="ScrubIQ package not available (missing SQLCipher or other dependencies)"
)

from fastapi import FastAPI
from fastapi.testclient import TestClient


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def mock_conversation():
    """Create a mock conversation."""
    conv = MagicMock()
    conv.id = "conv-123"
    conv.title = "Test Conversation"
    conv.created_at = datetime(2024, 1, 15, 10, 30, 0)
    conv.updated_at = datetime(2024, 1, 15, 11, 0, 0)
    conv.message_count = 2
    conv.messages = []
    return conv


@pytest.fixture
def mock_message():
    """Create a mock message."""
    msg = MagicMock()
    msg.id = "msg-456"
    msg.conversation_id = "conv-123"
    msg.role = "user"
    msg.content = "Hello there"
    msg.redacted_content = "Hello there"
    msg.normalized_content = "Hello there"
    msg.spans = []
    msg.model = None
    msg.provider = None
    msg.created_at = datetime(2024, 1, 15, 10, 30, 0)
    return msg


@pytest.fixture
def mock_scrubiq(mock_conversation, mock_message):
    """Create a mock ScrubIQ instance."""
    mock = MagicMock()

    # Conversations
    mock.list_conversations.return_value = [mock_conversation]
    mock.get_conversation.return_value = mock_conversation
    mock.create_conversation.return_value = mock_conversation
    mock.update_conversation.return_value = True
    mock.delete_conversation.return_value = True

    # Messages
    mock.add_message.return_value = mock_message
    mock.delete_message.return_value = True

    return mock


@pytest.fixture
def client(mock_scrubiq):
    """Create test client with mocked dependencies."""
    from scrubiq.api.routes.conversations import router
    from scrubiq.api.dependencies import require_unlocked
    from scrubiq.api.errors import register_error_handlers

    app = FastAPI()
    app.include_router(router)
    register_error_handlers(app)

    app.dependency_overrides[require_unlocked] = lambda: mock_scrubiq

    with patch("scrubiq.api.routes.conversations.check_rate_limit"):
        yield TestClient(app, raise_server_exceptions=False)


# =============================================================================
# LIST CONVERSATIONS TESTS
# =============================================================================

class TestListConversations:
    """Tests for GET /conversations endpoint."""

    def test_list_success(self, client, mock_scrubiq):
        """List conversations returns conversation list."""
        response = client.get("/conversations")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 1

    def test_list_conversation_structure(self, client):
        """Listed conversations have correct structure."""
        response = client.get("/conversations")

        assert response.status_code == 200
        conv = response.json()[0]
        assert conv["id"] == "conv-123"
        assert conv["title"] == "Test Conversation"
        assert "created_at" in conv
        assert "updated_at" in conv
        assert conv["message_count"] == 2

    def test_list_with_limit(self, client, mock_scrubiq):
        """List respects limit parameter."""
        client.get("/conversations?limit=10")

        mock_scrubiq.list_conversations.assert_called_once()
        call_kwargs = mock_scrubiq.list_conversations.call_args[1]
        assert call_kwargs["limit"] == 10

    def test_list_with_offset(self, client, mock_scrubiq):
        """List respects offset parameter."""
        client.get("/conversations?offset=20")

        call_kwargs = mock_scrubiq.list_conversations.call_args[1]
        assert call_kwargs["offset"] == 20

    def test_list_limit_validation(self, client):
        """List validates limit parameter range."""
        response = client.get("/conversations?limit=0")
        assert response.status_code == 422

        response = client.get("/conversations?limit=10000")
        assert response.status_code == 422


# =============================================================================
# CREATE CONVERSATION TESTS
# =============================================================================

class TestCreateConversation:
    """Tests for POST /conversations endpoint."""

    def test_create_success(self, client, mock_scrubiq):
        """Create conversation returns new conversation."""
        response = client.post("/conversations", json={"title": "New Chat"})

        assert response.status_code == 201
        assert response.json()["id"] == "conv-123"

    def test_create_with_title(self, client, mock_scrubiq):
        """Create uses provided title."""
        client.post("/conversations", json={"title": "My Custom Title"})

        mock_scrubiq.create_conversation.assert_called_once_with(title="My Custom Title")

    def test_create_default_title(self, client, mock_scrubiq):
        """Create uses default title when none provided."""
        client.post("/conversations", json={})

        mock_scrubiq.create_conversation.assert_called_once_with(title="New conversation")

    def test_create_returns_201(self, client):
        """Create returns 201 status code."""
        response = client.post("/conversations", json={})

        assert response.status_code == 201

    def test_create_response_structure(self, client):
        """Created conversation has correct structure."""
        response = client.post("/conversations", json={})

        assert response.status_code == 201
        conv = response.json()
        assert "id" in conv
        assert "title" in conv
        assert "created_at" in conv
        assert "message_count" in conv


# =============================================================================
# GET CONVERSATION TESTS
# =============================================================================

class TestGetConversation:
    """Tests for GET /conversations/{conv_id} endpoint."""

    def test_get_success(self, client, mock_scrubiq, mock_conversation, mock_message):
        """Get conversation returns conversation with messages."""
        mock_conversation.messages = [mock_message]
        mock_scrubiq.get_conversation.return_value = mock_conversation

        response = client.get("/conversations/conv-123")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "conv-123"
        assert "messages" in data

    def test_get_includes_messages(self, client, mock_scrubiq, mock_conversation, mock_message):
        """Get conversation includes message list."""
        mock_conversation.messages = [mock_message]
        mock_scrubiq.get_conversation.return_value = mock_conversation

        response = client.get("/conversations/conv-123")

        assert response.status_code == 200
        messages = response.json()["messages"]
        assert len(messages) == 1
        assert messages[0]["id"] == "msg-456"

    def test_get_not_found(self, client, mock_scrubiq):
        """Get returns 404 for unknown conversation."""
        mock_scrubiq.get_conversation.return_value = None

        response = client.get("/conversations/unknown-id")

        assert response.status_code == 404
        assert "CONVERSATION_NOT_FOUND" in response.json()["error_code"]

    def test_get_message_structure(self, client, mock_scrubiq, mock_conversation, mock_message):
        """Message in response has correct structure."""
        mock_conversation.messages = [mock_message]
        mock_scrubiq.get_conversation.return_value = mock_conversation

        response = client.get("/conversations/conv-123")

        msg = response.json()["messages"][0]
        assert "id" in msg
        assert "conversation_id" in msg
        assert "role" in msg
        assert "content" in msg
        assert "created_at" in msg


# =============================================================================
# UPDATE CONVERSATION TESTS
# =============================================================================

class TestUpdateConversation:
    """Tests for PATCH /conversations/{conv_id} endpoint."""

    def test_update_success(self, client, mock_scrubiq):
        """Update conversation returns updated conversation."""
        response = client.patch("/conversations/conv-123", json={"title": "New Title"})

        assert response.status_code == 200
        mock_scrubiq.update_conversation.assert_called_once_with("conv-123", title="New Title")

    def test_update_not_found(self, client, mock_scrubiq):
        """Update returns 404 for unknown conversation."""
        mock_scrubiq.update_conversation.return_value = False

        response = client.patch("/conversations/unknown-id", json={"title": "New"})

        assert response.status_code == 404

    def test_update_requires_title(self, client):
        """Update requires title field."""
        response = client.patch("/conversations/conv-123", json={})

        assert response.status_code == 422

    def test_update_title_validation(self, client):
        """Update validates title length."""
        response = client.patch("/conversations/conv-123", json={"title": ""})

        assert response.status_code == 422


# =============================================================================
# DELETE CONVERSATION TESTS
# =============================================================================

class TestDeleteConversation:
    """Tests for DELETE /conversations/{conv_id} endpoint."""

    def test_delete_success(self, client, mock_scrubiq):
        """Delete conversation succeeds."""
        response = client.delete("/conversations/conv-123")

        assert response.status_code == 200
        assert response.json()["success"] is True
        mock_scrubiq.delete_conversation.assert_called_once_with("conv-123")

    def test_delete_not_found(self, client, mock_scrubiq):
        """Delete returns 404 for unknown conversation."""
        mock_scrubiq.delete_conversation.return_value = False

        response = client.delete("/conversations/unknown-id")

        assert response.status_code == 404


# =============================================================================
# ADD MESSAGE TESTS
# =============================================================================

class TestAddMessage:
    """Tests for POST /conversations/{conv_id}/messages endpoint."""

    def test_add_message_success(self, client, mock_scrubiq, mock_conversation):
        """Add message returns new message."""
        mock_scrubiq.get_conversation.return_value = mock_conversation

        response = client.post(
            "/conversations/conv-123/messages",
            json={"role": "user", "content": "Hello"},
        )

        assert response.status_code == 201

    def test_add_message_calls_scrubiq(self, client, mock_scrubiq, mock_conversation):
        """Add message calls ScrubIQ.add_message."""
        mock_scrubiq.get_conversation.return_value = mock_conversation

        client.post(
            "/conversations/conv-123/messages",
            json={"role": "user", "content": "Hello"},
        )

        mock_scrubiq.add_message.assert_called_once()
        call_kwargs = mock_scrubiq.add_message.call_args[1]
        assert call_kwargs["conv_id"] == "conv-123"
        assert call_kwargs["role"] == "user"
        assert call_kwargs["content"] == "Hello"

    def test_add_message_conversation_not_found(self, client, mock_scrubiq):
        """Add message returns 404 for unknown conversation."""
        mock_scrubiq.get_conversation.return_value = None

        response = client.post(
            "/conversations/unknown-id/messages",
            json={"role": "user", "content": "Hello"},
        )

        assert response.status_code == 404

    def test_add_message_role_validation(self, client, mock_scrubiq, mock_conversation):
        """Add message validates role field."""
        mock_scrubiq.get_conversation.return_value = mock_conversation

        response = client.post(
            "/conversations/conv-123/messages",
            json={"role": "admin", "content": "Hello"},
        )

        assert response.status_code == 422

    def test_add_message_valid_roles(self, client, mock_scrubiq, mock_conversation):
        """Add message accepts valid roles."""
        mock_scrubiq.get_conversation.return_value = mock_conversation

        for role in ["user", "assistant", "system"]:
            response = client.post(
                "/conversations/conv-123/messages",
                json={"role": role, "content": "Test"},
            )
            assert response.status_code == 201


# =============================================================================
# DELETE MESSAGE TESTS
# =============================================================================

class TestDeleteMessage:
    """Tests for DELETE /conversations/{conv_id}/messages/{msg_id} endpoint."""

    def test_delete_message_success(self, client, mock_scrubiq):
        """Delete message succeeds."""
        response = client.delete("/conversations/conv-123/messages/msg-456")

        assert response.status_code == 200
        assert response.json()["success"] is True
        mock_scrubiq.delete_message.assert_called_once_with("msg-456")

    def test_delete_message_not_found(self, client, mock_scrubiq):
        """Delete message returns 404 for unknown message."""
        mock_scrubiq.delete_message.return_value = False

        response = client.delete("/conversations/conv-123/messages/unknown-msg")

        assert response.status_code == 404
        assert "MESSAGE_NOT_FOUND" in response.json()["error_code"]
