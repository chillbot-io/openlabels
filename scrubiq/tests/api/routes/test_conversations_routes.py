"""Comprehensive tests for api/routes/conversations.py to achieve 80%+ coverage."""

import pytest
from unittest.mock import Mock, MagicMock, patch


class TestConversationsConstants:
    """Tests for conversations module constants."""

    def test_conversation_read_rate_limit(self):
        """CONVERSATION_READ_RATE_LIMIT should be defined."""
        from scrubiq.api.routes.conversations import CONVERSATION_READ_RATE_LIMIT

        assert CONVERSATION_READ_RATE_LIMIT > 0

    def test_conversation_rate_limit(self):
        """CONVERSATION_RATE_LIMIT should be defined."""
        from scrubiq.api.routes.conversations import CONVERSATION_RATE_LIMIT

        assert CONVERSATION_RATE_LIMIT > 0

    def test_message_rate_limit(self):
        """MESSAGE_RATE_LIMIT should be defined."""
        from scrubiq.api.routes.conversations import MESSAGE_RATE_LIMIT

        assert MESSAGE_RATE_LIMIT > 0

    def test_read_more_permissive(self):
        """Read rate limit should be more permissive than write."""
        from scrubiq.api.routes.conversations import (
            CONVERSATION_READ_RATE_LIMIT,
            CONVERSATION_RATE_LIMIT,
        )

        assert CONVERSATION_READ_RATE_LIMIT >= CONVERSATION_RATE_LIMIT


class TestConvertSpansHelper:
    """Tests for _convert_spans helper function."""

    def test_convert_empty_list(self):
        """Empty list should return None."""
        from scrubiq.api.routes.conversations import _convert_spans

        result = _convert_spans([])
        assert result is None

    def test_convert_none(self):
        """None should return None."""
        from scrubiq.api.routes.conversations import _convert_spans

        result = _convert_spans(None)
        assert result is None

    def test_convert_valid_spans(self):
        """Valid spans should be converted."""
        from scrubiq.api.routes.conversations import _convert_spans

        spans = [
            {"start": 0, "end": 10, "text": "John Smith", "entity_type": "NAME",
             "confidence": 0.9, "detector": "ml", "token": "[NAME_1]"}
        ]
        result = _convert_spans(spans)

        assert result is not None
        assert len(result) == 1
        assert result[0].start == 0
        assert result[0].end == 10
        assert result[0].text == "John Smith"

    def test_convert_missing_fields(self):
        """Missing optional fields should use defaults."""
        from scrubiq.api.routes.conversations import _convert_spans

        spans = [{}]  # Empty dict
        result = _convert_spans(spans)

        assert result is not None
        assert len(result) == 1
        assert result[0].start == 0
        assert result[0].end == 0
        assert result[0].entity_type == "UNKNOWN"


class TestConversationsRouterRegistration:
    """Tests for conversations router configuration."""

    def test_router_has_tag(self):
        """Router should have conversations tag."""
        from scrubiq.api.routes.conversations import router

        assert "conversations" in router.tags

    def test_router_routes_exist(self):
        """Router should have expected routes."""
        from scrubiq.api.routes.conversations import router

        paths = [getattr(r, 'path', '') for r in router.routes]
        assert '/conversations' in paths
        assert '/conversations/{conv_id}' in paths
        assert '/conversations/{conv_id}/messages' in paths


class TestListConversationsRoute:
    """Tests for GET /conversations route."""

    def test_route_exists(self):
        """GET /conversations route should exist."""
        from scrubiq.api.routes.conversations import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/conversations' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestCreateConversationRoute:
    """Tests for POST /conversations route."""

    def test_route_exists(self):
        """POST /conversations route should exist."""
        from scrubiq.api.routes.conversations import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/conversations' and
                  'POST' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestGetConversationRoute:
    """Tests for GET /conversations/{conv_id} route."""

    def test_route_exists(self):
        """GET /conversations/{conv_id} route should exist."""
        from scrubiq.api.routes.conversations import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/conversations/{conv_id}' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestUpdateConversationRoute:
    """Tests for PATCH /conversations/{conv_id} route."""

    def test_route_exists(self):
        """PATCH /conversations/{conv_id} route should exist."""
        from scrubiq.api.routes.conversations import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/conversations/{conv_id}' and
                  'PATCH' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestDeleteConversationRoute:
    """Tests for DELETE /conversations/{conv_id} route."""

    def test_route_exists(self):
        """DELETE /conversations/{conv_id} route should exist."""
        from scrubiq.api.routes.conversations import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/conversations/{conv_id}' and
                  'DELETE' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestAddMessageRoute:
    """Tests for POST /conversations/{conv_id}/messages route."""

    def test_route_exists(self):
        """POST /conversations/{conv_id}/messages route should exist."""
        from scrubiq.api.routes.conversations import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/conversations/{conv_id}/messages' and
                  'POST' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestDeleteMessageRoute:
    """Tests for DELETE /conversations/{conv_id}/messages/{msg_id} route."""

    def test_route_exists(self):
        """DELETE /conversations/{conv_id}/messages/{msg_id} route should exist."""
        from scrubiq.api.routes.conversations import router

        routes = [r for r in router.routes
                  if '/messages/{msg_id}' in getattr(r, 'path', '') and
                  'DELETE' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestConversationSchemas:
    """Tests for conversation-related schemas."""

    def test_conversation_create_schema(self):
        """ConversationCreate schema should exist."""
        from scrubiq.api.routes.schemas import ConversationCreate

        req = ConversationCreate(title="Test")
        assert req.title == "Test"

    def test_conversation_update_schema(self):
        """ConversationUpdate schema should exist."""
        from scrubiq.api.routes.schemas import ConversationUpdate

        req = ConversationUpdate(title="Updated")
        assert req.title == "Updated"

    def test_conversation_response_schema(self):
        """ConversationResponse schema should exist."""
        from scrubiq.api.routes.schemas import ConversationResponse

        resp = ConversationResponse(
            id="123",
            title="Test",
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
            message_count=0
        )
        assert resp.id == "123"

    def test_message_create_schema(self):
        """MessageCreate schema should exist."""
        from scrubiq.api.routes.schemas import MessageCreate

        req = MessageCreate(role="user", content="Hello")
        assert req.role == "user"
        assert req.content == "Hello"

    def test_message_response_schema(self):
        """MessageResponse schema should exist."""
        from scrubiq.api.routes.schemas import MessageResponse

        resp = MessageResponse(
            id="msg1",
            conversation_id="conv1",
            role="user",
            content="Hello",
            created_at="2024-01-01T00:00:00"
        )
        assert resp.id == "msg1"
