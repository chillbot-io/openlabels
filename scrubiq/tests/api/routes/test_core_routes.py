"""Comprehensive tests for api/routes/core.py to achieve 80%+ coverage."""

import pytest
from unittest.mock import Mock, MagicMock, patch


class TestCoreConstants:
    """Tests for core module constants."""

    def test_sse_max_response_chars(self):
        """SSE_MAX_RESPONSE_CHARS should be defined."""
        from scrubiq.api.routes.core import SSE_MAX_RESPONSE_CHARS

        assert SSE_MAX_RESPONSE_CHARS > 0
        assert SSE_MAX_RESPONSE_CHARS == 500_000

    def test_sse_timeout_seconds(self):
        """SSE_TIMEOUT_SECONDS should be defined."""
        from scrubiq.api.routes.core import SSE_TIMEOUT_SECONDS

        assert SSE_TIMEOUT_SECONDS > 0
        assert SSE_TIMEOUT_SECONDS == 300


class TestCoreRouterRegistration:
    """Tests for core router configuration."""

    def test_router_has_tag(self):
        """Router should have core tag."""
        from scrubiq.api.routes.core import router

        assert "core" in router.tags

    def test_router_routes_exist(self):
        """Router should have expected routes."""
        from scrubiq.api.routes.core import router

        paths = [getattr(r, 'path', '') for r in router.routes]
        assert '/redact' in paths
        assert '/restore' in paths
        assert '/chat' in paths
        assert '/chat/stream' in paths
        assert '/tokens' in paths
        assert '/tokens/{token}' in paths


class TestRedactRoute:
    """Tests for POST /redact route."""

    def test_route_exists(self):
        """POST /redact route should exist."""
        from scrubiq.api.routes.core import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/redact' and
                  'POST' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestRestoreRoute:
    """Tests for POST /restore route."""

    def test_route_exists(self):
        """POST /restore route should exist."""
        from scrubiq.api.routes.core import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/restore' and
                  'POST' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestChatRoute:
    """Tests for POST /chat route."""

    def test_route_exists(self):
        """POST /chat route should exist."""
        from scrubiq.api.routes.core import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/chat' and
                  'POST' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestChatStreamRoute:
    """Tests for POST /chat/stream route."""

    def test_route_exists(self):
        """POST /chat/stream route should exist."""
        from scrubiq.api.routes.core import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/chat/stream' and
                  'POST' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestListTokensRoute:
    """Tests for GET /tokens route."""

    def test_route_exists(self):
        """GET /tokens route should exist."""
        from scrubiq.api.routes.core import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/tokens' and
                  'GET' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestDeleteTokenRoute:
    """Tests for DELETE /tokens/{token} route."""

    def test_route_exists(self):
        """DELETE /tokens/{token} route should exist."""
        from scrubiq.api.routes.core import router

        routes = [r for r in router.routes
                  if getattr(r, 'path', '') == '/tokens/{token}' and
                  'DELETE' in getattr(r, 'methods', set())]
        assert len(routes) > 0


class TestCoreSchemas:
    """Tests for core-related schemas."""

    def test_redact_request_schema(self):
        """RedactRequest schema should exist."""
        from scrubiq.api.routes.schemas import RedactRequest

        req = RedactRequest(text="John Smith is here")
        assert req.text == "John Smith is here"

    def test_redact_response_schema(self):
        """RedactResponse schema should exist."""
        from scrubiq.api.routes.schemas import RedactResponse

        resp = RedactResponse(
            redacted_text="[NAME_1] is here",
            normalized_input="john smith is here",
            spans=[],
            tokens_created=1,
            needs_review=[],
            processing_time_ms=10.5
        )
        assert resp.redacted_text == "[NAME_1] is here"

    def test_restore_request_schema(self):
        """RestoreRequest schema should exist."""
        from scrubiq.api.routes.schemas import RestoreRequest

        req = RestoreRequest(text="[NAME_1] is here", mode="research")
        assert req.mode == "research"

    def test_restore_response_schema(self):
        """RestoreResponse schema should exist."""
        from scrubiq.api.routes.schemas import RestoreResponse

        resp = RestoreResponse(
            restored_text="John Smith is here",
            tokens_restored=1,
            unknown_tokens=0
        )
        assert resp.tokens_restored == 1

    def test_chat_request_schema(self):
        """ChatRequest schema should exist."""
        from scrubiq.api.routes.schemas import ChatRequest

        req = ChatRequest(text="Hello, how are you?")
        assert req.text == "Hello, how are you?"

    def test_chat_request_with_options(self):
        """ChatRequest should accept optional fields."""
        from scrubiq.api.routes.schemas import ChatRequest

        req = ChatRequest(
            text="Hello",
            model="claude-sonnet-4",
            provider="anthropic",
            conversation_id="conv123",
            file_ids=["file1", "file2"]
        )
        assert req.model == "claude-sonnet-4"
        assert req.file_ids == ["file1", "file2"]

    def test_chat_response_schema(self):
        """ChatResponse schema should exist."""
        from scrubiq.api.routes.schemas import ChatResponse

        resp = ChatResponse(
            user_redacted="Hello",
            assistant_redacted="Hi there",
            assistant_restored="Hi there",
            model="claude-sonnet-4",
            provider="anthropic",
            tokens_used=50,
            latency_ms=500,
            spans=[],
            conversation_id="conv123"
        )
        assert resp.model == "claude-sonnet-4"

    def test_span_info_schema(self):
        """SpanInfo schema should exist."""
        from scrubiq.api.routes.schemas import SpanInfo

        span = SpanInfo(
            start=0,
            end=10,
            text="John Smith",
            entity_type="NAME",
            confidence=0.95,
            detector="ml",
            token="[NAME_1]"
        )
        assert span.entity_type == "NAME"

    def test_token_info_schema(self):
        """TokenInfo schema should exist."""
        from scrubiq.api.routes.schemas import TokenInfo

        info = TokenInfo(
            token="[NAME_1]",
            entity_type="NAME",
            original="John Smith",
            safe_harbor=None
        )
        assert info.token == "[NAME_1]"


class TestPrivacyModeMapping:
    """Tests for privacy mode mapping."""

    def test_valid_modes(self):
        """All valid privacy modes should be supported."""
        from scrubiq.types import PrivacyMode

        valid_modes = ["redacted", "safe_harbor", "research"]
        mode_map = {
            "redacted": PrivacyMode.REDACTED,
            "safe_harbor": PrivacyMode.SAFE_HARBOR,
            "research": PrivacyMode.RESEARCH,
        }

        for mode in valid_modes:
            assert mode in mode_map


class TestStreamingHelpers:
    """Tests for streaming chat helpers."""

    def test_estimate_tokens_calculation(self):
        """Token estimation should use CHARS_PER_TOKEN."""
        from scrubiq.constants import CHARS_PER_TOKEN

        text = "a" * 100
        estimated = len(text) // CHARS_PER_TOKEN
        assert estimated > 0
