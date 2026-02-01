"""Tests for memory and search routes.

Tests conversation search and memory management endpoints.

Note: These tests require SQLCipher and FastAPI to be installed.
"""

from datetime import datetime
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

try:
    from scrubiq.api.routes import memory as routes_memory
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
def mock_memory():
    """Create mock memory object."""
    mem = MagicMock()
    mem.id = "mem-123"
    mem.conversation_id = "conv-123"
    mem.entity_token = "[NAME_1]"
    mem.fact = "User prefers dark mode"
    mem.category = "preference"
    mem.confidence = 0.95
    mem.source_message_id = "msg-456"
    mem.created_at = datetime(2024, 1, 15, 10, 30, 0)
    return mem


@pytest.fixture
def mock_scrubiq(mock_memory):
    """Create a mock ScrubIQ instance."""
    mock = MagicMock()
    mock._current_conversation_id = "conv-123"

    # Memory system
    mock._memory = MagicMock()
    mock._memory.get_memories.return_value = [mock_memory]
    mock._memory.add_memory.return_value = mock_memory
    mock._memory.delete_memory.return_value = True
    mock._memory.delete_memories_for_conversation.return_value = 5
    mock._memory.get_memory_stats.return_value = {
        "total": 100,
        "by_category": {"preference": 30, "general": 70},
        "top_entities": {"[NAME_1]": 15, "[ORG_1]": 10},
    }

    # Search
    mock.search_conversations.return_value = [
        {
            "content": "Hello there",
            "conversation_id": "conv-123",
            "conversation_title": "Test Chat",
            "role": "user",
            "relevance": 0.95,
            "created_at": "2024-01-15T10:30:00",
        },
    ]

    # Memory extraction
    mock.extract_memories_from_conversation = AsyncMock(return_value=3)

    return mock


@pytest.fixture
def client(mock_scrubiq):
    """Create test client with mocked dependencies."""
    from scrubiq.api.routes.memory import router
    from scrubiq.api.dependencies import require_unlocked
    from scrubiq.api.errors import register_error_handlers

    app = FastAPI()
    app.include_router(router)
    register_error_handlers(app)

    app.dependency_overrides[require_unlocked] = lambda: mock_scrubiq

    with patch("scrubiq.api.routes.memory.check_rate_limit"):
        yield TestClient(app, raise_server_exceptions=False)


# =============================================================================
# SEARCH ENDPOINT TESTS
# =============================================================================

class TestSearchEndpoint:
    """Tests for GET /search endpoint."""

    def test_search_success(self, client, mock_scrubiq):
        """Search returns matching results."""
        response = client.get("/search?q=hello")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 1

    def test_search_result_structure(self, client):
        """Search results have correct structure."""
        response = client.get("/search?q=hello")

        assert response.status_code == 200
        result = response.json()[0]
        assert result["content"] == "Hello there"
        assert result["conversation_id"] == "conv-123"
        assert result["role"] == "user"
        assert result["relevance"] == 0.95

    def test_search_requires_query(self, client):
        """Search requires query parameter."""
        response = client.get("/search")

        assert response.status_code == 422

    def test_search_query_min_length(self, client):
        """Search query must be at least 2 characters."""
        response = client.get("/search?q=x")

        assert response.status_code == 422

    def test_search_with_limit(self, client, mock_scrubiq):
        """Search respects limit parameter."""
        client.get("/search?q=hello&limit=5")

        mock_scrubiq.search_conversations.assert_called_once()
        call_kwargs = mock_scrubiq.search_conversations.call_args[1]
        assert call_kwargs["limit"] == 5

    def test_search_exclude_current(self, client, mock_scrubiq):
        """Search can exclude current conversation."""
        client.get("/search?q=hello&exclude_current=false")

        call_kwargs = mock_scrubiq.search_conversations.call_args[1]
        assert call_kwargs["exclude_current"] is False


# =============================================================================
# LIST MEMORIES TESTS
# =============================================================================

class TestListMemories:
    """Tests for GET /memories endpoint."""

    def test_list_success(self, client, mock_scrubiq):
        """List memories returns memory list."""
        response = client.get("/memories")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 1

    def test_list_memory_structure(self, client):
        """Listed memories have correct structure."""
        response = client.get("/memories")

        assert response.status_code == 200
        mem = response.json()[0]
        assert mem["id"] == "mem-123"
        assert mem["fact"] == "User prefers dark mode"
        assert mem["category"] == "preference"
        assert mem["confidence"] == 0.95

    def test_list_filter_by_entity(self, client, mock_scrubiq):
        """List can filter by entity token."""
        client.get("/memories?entity_token=[NAME_1]")

        call_kwargs = mock_scrubiq._memory.get_memories.call_args[1]
        assert call_kwargs["entity_token"] == "[NAME_1]"

    def test_list_filter_by_category(self, client, mock_scrubiq):
        """List can filter by category."""
        client.get("/memories?category=preference")

        call_kwargs = mock_scrubiq._memory.get_memories.call_args[1]
        assert call_kwargs["category"] == "preference"

    def test_list_filter_by_confidence(self, client, mock_scrubiq):
        """List can filter by minimum confidence."""
        client.get("/memories?min_confidence=0.9")

        call_kwargs = mock_scrubiq._memory.get_memories.call_args[1]
        assert call_kwargs["min_confidence"] == 0.9

    def test_list_empty_when_no_memory_system(self, client, mock_scrubiq):
        """List returns empty when memory not available."""
        mock_scrubiq._memory = None

        response = client.get("/memories")

        assert response.status_code == 200
        assert response.json() == []


# =============================================================================
# CREATE MEMORY TESTS
# =============================================================================

class TestCreateMemory:
    """Tests for POST /memories endpoint."""

    def test_create_success(self, client, mock_scrubiq):
        """Create memory succeeds."""
        response = client.post("/memories", json={
            "fact": "User likes pizza",
            "category": "preference",
        })

        assert response.status_code == 201

    def test_create_calls_add_memory(self, client, mock_scrubiq):
        """Create calls memory.add_memory."""
        client.post("/memories", json={
            "fact": "User likes pizza",
            "category": "preference",
            "confidence": 0.9,
        })

        mock_scrubiq._memory.add_memory.assert_called_once()
        call_kwargs = mock_scrubiq._memory.add_memory.call_args[1]
        assert call_kwargs["fact"] == "User likes pizza"
        assert call_kwargs["category"] == "preference"
        assert call_kwargs["confidence"] == 0.9

    def test_create_with_entity_token(self, client, mock_scrubiq):
        """Create can associate with entity token."""
        client.post("/memories", json={
            "fact": "User lives in NYC",
            "entity_token": "[NAME_1]",
        })

        call_kwargs = mock_scrubiq._memory.add_memory.call_args[1]
        assert call_kwargs["entity_token"] == "[NAME_1]"

    def test_create_requires_fact(self, client):
        """Create requires fact field."""
        response = client.post("/memories", json={})

        assert response.status_code == 422

    def test_create_fact_min_length(self, client):
        """Create validates fact minimum length."""
        response = client.post("/memories", json={"fact": "hi"})

        assert response.status_code == 422

    def test_create_service_unavailable(self, client, mock_scrubiq):
        """Create returns 503 when memory not available."""
        mock_scrubiq._memory = None

        response = client.post("/memories", json={"fact": "Some fact here"})

        assert response.status_code == 503


# =============================================================================
# DELETE MEMORY TESTS
# =============================================================================

class TestDeleteMemory:
    """Tests for DELETE /memories/{memory_id} endpoint."""

    def test_delete_success(self, client, mock_scrubiq):
        """Delete memory succeeds."""
        response = client.delete("/memories/mem-123")

        assert response.status_code == 200
        assert response.json()["success"] is True
        mock_scrubiq._memory.delete_memory.assert_called_once_with("mem-123")

    def test_delete_not_found(self, client, mock_scrubiq):
        """Delete returns 404 for unknown memory."""
        mock_scrubiq._memory.delete_memory.return_value = False

        response = client.delete("/memories/unknown-mem")

        assert response.status_code == 404
        assert "MEMORY_NOT_FOUND" in response.json()["error_code"]

    def test_delete_service_unavailable(self, client, mock_scrubiq):
        """Delete returns 503 when memory not available."""
        mock_scrubiq._memory = None

        response = client.delete("/memories/mem-123")

        assert response.status_code == 503


# =============================================================================
# CLEAR MEMORIES TESTS
# =============================================================================

class TestClearMemories:
    """Tests for DELETE /memories endpoint."""

    def test_clear_requires_conversation_id(self, client):
        """Clear requires conversation_id parameter."""
        response = client.delete("/memories")

        assert response.status_code == 400
        assert "MISSING_FIELD" in response.json()["error_code"]

    def test_clear_for_conversation(self, client, mock_scrubiq):
        """Clear deletes memories for conversation."""
        response = client.delete("/memories?conversation_id=conv-123")

        assert response.status_code == 200
        assert response.json()["deleted"] == 5
        mock_scrubiq._memory.delete_memories_for_conversation.assert_called_once_with("conv-123")

    def test_clear_service_unavailable(self, client, mock_scrubiq):
        """Clear returns 503 when memory not available."""
        mock_scrubiq._memory = None

        response = client.delete("/memories?conversation_id=conv-123")

        assert response.status_code == 503


# =============================================================================
# MEMORY STATS TESTS
# =============================================================================

class TestMemoryStats:
    """Tests for GET /memories/stats endpoint."""

    def test_stats_success(self, client, mock_scrubiq):
        """Stats returns memory statistics."""
        response = client.get("/memories/stats")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 100

    def test_stats_by_category(self, client):
        """Stats includes category breakdown."""
        response = client.get("/memories/stats")

        data = response.json()
        assert data["by_category"]["preference"] == 30
        assert data["by_category"]["general"] == 70

    def test_stats_top_entities(self, client):
        """Stats includes top entities."""
        response = client.get("/memories/stats")

        data = response.json()
        assert data["top_entities"]["[NAME_1]"] == 15

    def test_stats_empty_when_no_memory(self, client, mock_scrubiq):
        """Stats returns empty when memory not available."""
        mock_scrubiq._memory = None

        response = client.get("/memories/stats")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0


# =============================================================================
# EXTRACT MEMORIES TESTS
# =============================================================================

class TestExtractMemories:
    """Tests for POST /memories/extract/{conversation_id} endpoint."""

    def test_extract_success(self, client, mock_scrubiq):
        """Extract memories succeeds."""
        response = client.post("/memories/extract/conv-123")

        assert response.status_code == 200
        data = response.json()
        assert data["conversation_id"] == "conv-123"
        assert data["memories_extracted"] == 3

    def test_extract_calls_method(self, client, mock_scrubiq):
        """Extract calls extract_memories_from_conversation."""
        client.post("/memories/extract/conv-456")

        mock_scrubiq.extract_memories_from_conversation.assert_called_once_with("conv-456")
