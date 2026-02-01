"""Comprehensive tests for api/routes/memory.py to achieve 80%+ coverage."""

import pytest
from unittest.mock import Mock, MagicMock, patch


class TestMemoryConstants:
    """Tests for memory module constants."""

    def test_search_rate_limit(self):
        """SEARCH_RATE_LIMIT should be defined."""
        from scrubiq.api.routes.memory import SEARCH_RATE_LIMIT

        assert SEARCH_RATE_LIMIT > 0

    def test_memory_rate_limit(self):
        """MEMORY_RATE_LIMIT should be defined."""
        from scrubiq.api.routes.memory import MEMORY_RATE_LIMIT

        assert MEMORY_RATE_LIMIT > 0


class TestMemorySchemas:
    """Tests for memory-related schemas."""

    def test_memory_response_schema(self):
        """MemoryResponse schema should exist and have required fields."""
        from scrubiq.api.routes.memory import MemoryResponse

        resp = MemoryResponse(
            id="mem1",
            conversation_id="conv1",
            entity_token="[NAME_1]",
            fact="User's name is John",
            category="identity",
            confidence=0.9,
            source_message_id="msg1",
            created_at="2024-01-01T00:00:00"
        )
        assert resp.id == "mem1"
        assert resp.fact == "User's name is John"

    def test_memory_response_optional_fields(self):
        """MemoryResponse should handle optional fields."""
        from scrubiq.api.routes.memory import MemoryResponse

        resp = MemoryResponse(
            id="mem1",
            conversation_id="conv1",
            entity_token=None,
            fact="General fact",
            category="general",
            confidence=0.8,
            source_message_id=None,
            created_at="2024-01-01T00:00:00"
        )
        assert resp.entity_token is None

    def test_memory_create_schema(self):
        """MemoryCreate schema should exist and validate."""
        from scrubiq.api.routes.memory import MemoryCreate

        req = MemoryCreate(fact="Test fact")
        assert req.fact == "Test fact"
        assert req.category == "general"  # Default
        assert req.confidence == 0.9  # Default

    def test_memory_create_validation(self):
        """MemoryCreate should validate fact length."""
        from scrubiq.api.routes.memory import MemoryCreate
        from pydantic import ValidationError

        # Too short
        with pytest.raises(ValidationError):
            MemoryCreate(fact="Hi")  # < 5 chars

    def test_search_result_schema(self):
        """SearchResult schema should exist."""
        from scrubiq.api.routes.memory import SearchResult

        result = SearchResult(
            content="Test message content",
            conversation_id="conv1",
            conversation_title="Test Conv",
            role="user",
            relevance=0.95,
            created_at="2024-01-01T00:00:00"
        )
        assert result.relevance == 0.95

    def test_memory_stats_schema(self):
        """MemoryStats schema should exist."""
        from scrubiq.api.routes.memory import MemoryStats

        stats = MemoryStats(
            total=100,
            by_category={"general": 50, "identity": 30},
            top_entities={"[NAME_1]": 10}
        )
        assert stats.total == 100

    def test_extract_result_schema(self):
        """ExtractResult schema should exist."""
        from scrubiq.api.routes.memory import ExtractResult

        result = ExtractResult(
            conversation_id="conv1",
            memories_extracted=5
        )
        assert result.memories_extracted == 5


class TestMemoryRouterRegistration:
    """Tests for memory router configuration."""

    def test_router_has_tag(self):
        """Router should have memory tag."""
        from scrubiq.api.routes.memory import router

        assert "memory" in router.tags

    def test_router_routes_exist(self):
        """Router should have expected routes."""
        from scrubiq.api.routes.memory import router

        paths = [getattr(r, 'path', '') for r in router.routes]
        assert '/search' in paths
        assert '/memories' in paths
        assert '/memories/stats' in paths


class TestSearchRoute:
    """Tests for GET /search route."""

    def test_route_exists(self):
        """GET /search route should exist."""
        from scrubiq.api.routes.memory import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/search' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestListMemoriesRoute:
    """Tests for GET /memories route."""

    def test_route_exists(self):
        """GET /memories route should exist."""
        from scrubiq.api.routes.memory import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/memories' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestCreateMemoryRoute:
    """Tests for POST /memories route."""

    def test_route_exists(self):
        """POST /memories route should exist."""
        from scrubiq.api.routes.memory import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/memories' and
                  'POST' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestDeleteMemoryRoute:
    """Tests for DELETE /memories/{memory_id} route."""

    def test_route_exists(self):
        """DELETE /memories/{memory_id} route should exist."""
        from scrubiq.api.routes.memory import router

        routes = [r for r in router.routes
                  if '/memories/{memory_id}' in getattr(r, 'path', '') and
                  'DELETE' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestClearMemoriesRoute:
    """Tests for DELETE /memories route."""

    def test_route_exists(self):
        """DELETE /memories route should exist."""
        from scrubiq.api.routes.memory import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/memories' and
                  'DELETE' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestMemoryStatsRoute:
    """Tests for GET /memories/stats route."""

    def test_route_exists(self):
        """GET /memories/stats route should exist."""
        from scrubiq.api.routes.memory import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/memories/stats' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestExtractMemoriesRoute:
    """Tests for POST /memories/extract/{conversation_id} route."""

    def test_route_exists(self):
        """POST /memories/extract/{conversation_id} route should exist."""
        from scrubiq.api.routes.memory import router

        routes = [r for r in router.routes
                  if '/memories/extract/' in getattr(r, 'path', '') and
                  'POST' in getattr(r, 'methods', set())]
        assert len(routes) > 0
