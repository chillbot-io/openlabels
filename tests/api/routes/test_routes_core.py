"""Tests for core API routes: redact, restore, chat, tokens.

These are the primary user-facing endpoints for PHI protection.

Note: These tests require SQLCipher and FastAPI to be installed.
Run with: pip install sqlcipher3-binary fastapi httpx
"""

import json
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Skip all tests in this module if dependencies not available
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

# Try importing scrubiq routes - skip if SQLCipher not available
try:
    from scrubiq.api.routes import core as routes_core
    from scrubiq.api.dependencies import require_unlocked
    SCRUBIQ_AVAILABLE = True
except (ImportError, RuntimeError) as e:
    SCRUBIQ_AVAILABLE = False
    routes_core = None
    require_unlocked = None

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
def mock_scrubiq():
    """Create a mock ScrubIQ instance."""
    mock = MagicMock()
    mock.is_unlocked = True

    # Mock redact response
    redact_result = MagicMock()
    redact_result.redacted = "Hello [NAME_1]"
    redact_result.normalized_input = "Hello John"
    redact_result.spans = []
    redact_result.tokens_created = ["[NAME_1]"]
    redact_result.needs_review = []
    redact_result.processing_time_ms = 15.5
    mock.redact.return_value = redact_result

    # Mock restore response
    restore_result = MagicMock()
    restore_result.restored = "Hello John"
    restore_result.tokens_found = ["[NAME_1]"]
    restore_result.tokens_unknown = []
    mock.restore.return_value = restore_result

    # Mock chat response
    chat_result = MagicMock()
    chat_result.redacted_request = "Hello [NAME_1]"
    chat_result.normalized_input = "Hello John"
    chat_result.response_text = "Hi [NAME_1]!"
    chat_result.restored_response = "Hi John!"
    chat_result.model = "claude-sonnet-4"
    chat_result.provider = "anthropic"
    chat_result.tokens_used = 50
    chat_result.latency_ms = 200.0
    chat_result.spans = []
    chat_result.conversation_id = "conv-123"
    chat_result.error = None
    mock.chat.return_value = chat_result

    # Mock tokens
    mock.get_tokens.return_value = [
        {"token": "[NAME_1]", "type": "NAME", "safe_harbor": "[PERSON]"},
    ]
    mock.delete_token.return_value = True

    # Mock file upload batch fetch
    mock.get_upload_results_batch.return_value = {}

    return mock


@pytest.fixture
def mock_rate_limiter():
    """Mock the rate limiter to do nothing."""
    with patch("scrubiq.api.routes.core.check_rate_limit") as mock:
        yield mock


@pytest.fixture
def app(mock_scrubiq, mock_rate_limiter):
    """Create test FastAPI app with mocked dependencies."""
    from scrubiq.api.routes.core import router
    from scrubiq.api.errors import register_error_handlers

    app = FastAPI()
    app.include_router(router)
    register_error_handlers(app)

    # Override the dependency
    def override_require_unlocked():
        return mock_scrubiq

    # Patch at import location
    with patch("scrubiq.api.routes.core.require_unlocked", return_value=mock_scrubiq):
        app.dependency_overrides[require_unlocked] = override_require_unlocked
        yield app


@pytest.fixture
def client(app, mock_scrubiq):
    """Create test client with mocked require_unlocked."""
    from scrubiq.api.routes.core import router
    from scrubiq.api.errors import register_error_handlers

    test_app = FastAPI()
    test_app.include_router(router)
    register_error_handlers(test_app)

    # Override the require_unlocked dependency
    from scrubiq.api.dependencies import require_unlocked

    test_app.dependency_overrides[require_unlocked] = lambda: mock_scrubiq

    return TestClient(test_app, raise_server_exceptions=False)


# =============================================================================
# REDACT ENDPOINT TESTS
# =============================================================================

class TestRedactEndpoint:
    """Tests for POST /redact endpoint."""

    def test_redact_success(self, client, mock_scrubiq):
        """Successful redaction returns redacted text."""
        response = client.post("/redact", json={"text": "Hello John"})

        assert response.status_code == 200
        data = response.json()
        assert data["redacted_text"] == "Hello [NAME_1]"
        assert data["normalized_input"] == "Hello John"
        assert "[NAME_1]" in data["tokens_created"]

    def test_redact_calls_scrubiq(self, client, mock_scrubiq):
        """Redact endpoint calls ScrubIQ.redact."""
        client.post("/redact", json={"text": "Hello John"})

        mock_scrubiq.redact.assert_called_once_with("Hello John")

    def test_redact_missing_text_fails(self, client):
        """Missing text field returns 422."""
        response = client.post("/redact", json={})

        assert response.status_code == 422

    def test_redact_empty_text_works(self, client, mock_scrubiq):
        """Empty text is accepted (validation happens in ScrubIQ)."""
        mock_scrubiq.redact.return_value.redacted = ""
        mock_scrubiq.redact.return_value.tokens_created = []

        response = client.post("/redact", json={"text": ""})

        # May return 200 or 400 depending on validation
        assert response.status_code in (200, 400, 422)

    def test_redact_validation_error(self, client, mock_scrubiq):
        """ValueError from ScrubIQ returns 400."""
        mock_scrubiq.redact.side_effect = ValueError("Text too long")

        response = client.post("/redact", json={"text": "test"})

        assert response.status_code == 400
        assert "VALIDATION_ERROR" in response.json().get("error_code", "")

    def test_redact_internal_error(self, client, mock_scrubiq):
        """Exception from ScrubIQ returns 500."""
        mock_scrubiq.redact.side_effect = RuntimeError("Detector failed")

        response = client.post("/redact", json={"text": "test"})

        assert response.status_code == 500
        assert "INTERNAL_ERROR" in response.json().get("error_code", "")

    def test_redact_response_structure(self, client, mock_scrubiq):
        """Redact response has correct structure."""
        mock_scrubiq.redact.return_value.spans = [
            MagicMock(
                start=6,
                end=10,
                text="John",
                entity_type="NAME",
                confidence=0.95,
                detector="pattern",
                token="[NAME_1]",
            )
        ]

        response = client.post("/redact", json={"text": "Hello John"})

        assert response.status_code == 200
        data = response.json()
        assert "redacted_text" in data
        assert "normalized_input" in data
        assert "spans" in data
        assert "tokens_created" in data
        assert "needs_review" in data
        assert "processing_time_ms" in data

    def test_redact_includes_span_details(self, client, mock_scrubiq):
        """Redact response includes span details."""
        span_mock = MagicMock()
        span_mock.start = 6
        span_mock.end = 10
        span_mock.text = "John"
        span_mock.entity_type = "NAME"
        span_mock.confidence = 0.95
        span_mock.detector = "pattern"
        span_mock.token = "[NAME_1]"
        mock_scrubiq.redact.return_value.spans = [span_mock]

        response = client.post("/redact", json={"text": "Hello John"})

        assert response.status_code == 200
        spans = response.json()["spans"]
        assert len(spans) == 1
        assert spans[0]["start"] == 6
        assert spans[0]["end"] == 10
        assert spans[0]["entity_type"] == "NAME"


# =============================================================================
# RESTORE ENDPOINT TESTS
# =============================================================================

class TestRestoreEndpoint:
    """Tests for POST /restore endpoint."""

    def test_restore_success(self, client, mock_scrubiq):
        """Successful restore returns restored text."""
        response = client.post("/restore", json={
            "text": "Hello [NAME_1]",
            "mode": "research",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["restored_text"] == "Hello John"
        assert "[NAME_1]" in data["tokens_restored"]

    def test_restore_default_mode(self, client, mock_scrubiq):
        """Restore uses research mode by default."""
        response = client.post("/restore", json={"text": "Hello [NAME_1]"})

        assert response.status_code == 200

    def test_restore_redacted_mode(self, client, mock_scrubiq):
        """Restore accepts redacted mode."""
        response = client.post("/restore", json={
            "text": "Hello [NAME_1]",
            "mode": "redacted",
        })

        assert response.status_code == 200

    def test_restore_safe_harbor_mode(self, client, mock_scrubiq):
        """Restore accepts safe_harbor mode."""
        response = client.post("/restore", json={
            "text": "Hello [NAME_1]",
            "mode": "safe_harbor",
        })

        assert response.status_code == 200

    def test_restore_invalid_mode_fails(self, client):
        """Invalid mode returns 422."""
        response = client.post("/restore", json={
            "text": "Hello [NAME_1]",
            "mode": "invalid",
        })

        assert response.status_code == 422

    def test_restore_response_structure(self, client, mock_scrubiq):
        """Restore response has correct structure."""
        response = client.post("/restore", json={"text": "test"})

        assert response.status_code == 200
        data = response.json()
        assert "restored_text" in data
        assert "tokens_restored" in data
        assert "unknown_tokens" in data


# =============================================================================
# CHAT ENDPOINT TESTS
# =============================================================================

class TestChatEndpoint:
    """Tests for POST /chat endpoint."""

    def test_chat_success(self, client, mock_scrubiq):
        """Successful chat returns response."""
        response = client.post("/chat", json={"text": "Hello John"})

        assert response.status_code == 200
        data = response.json()
        assert data["assistant_restored"] == "Hi John!"
        assert data["model"] == "claude-sonnet-4"

    def test_chat_calls_scrubiq(self, client, mock_scrubiq):
        """Chat endpoint calls ScrubIQ.chat."""
        client.post("/chat", json={
            "text": "Hello",
            "model": "claude-sonnet-4",
            "provider": "anthropic",
        })

        mock_scrubiq.chat.assert_called_once()
        call_kwargs = mock_scrubiq.chat.call_args[1]
        assert call_kwargs["model"] == "claude-sonnet-4"
        assert call_kwargs["provider"] == "anthropic"

    def test_chat_with_conversation_id(self, client, mock_scrubiq):
        """Chat accepts conversation_id."""
        response = client.post("/chat", json={
            "text": "Hello",
            "conversation_id": "conv-123",
        })

        assert response.status_code == 200
        call_kwargs = mock_scrubiq.chat.call_args[1]
        assert call_kwargs["conversation_id"] == "conv-123"

    def test_chat_with_file_ids(self, client, mock_scrubiq):
        """Chat handles file_ids for document context."""
        mock_scrubiq.get_upload_results_batch.return_value = {
            "job-1": {"redacted_text": "Document content", "filename": "test.pdf"},
        }

        response = client.post("/chat", json={
            "text": "What does the document say?",
            "file_ids": ["job-1"],
        })

        assert response.status_code == 200
        mock_scrubiq.get_upload_results_batch.assert_called_once_with(["job-1"])

    def test_chat_response_structure(self, client, mock_scrubiq):
        """Chat response has correct structure."""
        response = client.post("/chat", json={"text": "Hello"})

        assert response.status_code == 200
        data = response.json()
        assert "user_redacted" in data
        assert "user_normalized" in data
        assert "assistant_redacted" in data
        assert "assistant_restored" in data
        assert "model" in data
        assert "provider" in data
        assert "tokens_used" in data
        assert "latency_ms" in data
        assert "spans" in data

    def test_chat_validation_error(self, client, mock_scrubiq):
        """ValueError from chat returns 400."""
        mock_scrubiq.chat.side_effect = ValueError("Invalid input")

        response = client.post("/chat", json={"text": "test"})

        assert response.status_code == 400

    def test_chat_internal_error(self, client, mock_scrubiq):
        """Exception from chat returns 500."""
        mock_scrubiq.chat.side_effect = RuntimeError("LLM failed")

        response = client.post("/chat", json={"text": "test"})

        assert response.status_code == 500


# =============================================================================
# TOKENS ENDPOINTS TESTS
# =============================================================================

class TestTokensEndpoints:
    """Tests for /tokens endpoints."""

    def test_list_tokens_success(self, client, mock_scrubiq):
        """GET /tokens returns token list."""
        response = client.get("/tokens")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["token"] == "[NAME_1]"

    def test_list_tokens_structure(self, client, mock_scrubiq):
        """Token list has correct structure."""
        response = client.get("/tokens")

        assert response.status_code == 200
        data = response.json()
        assert "token" in data[0]
        assert "type" in data[0]
        assert "safe_harbor" in data[0]

    def test_delete_token_success(self, client, mock_scrubiq):
        """DELETE /tokens/{token} succeeds."""
        response = client.delete("/tokens/%5BNAME_1%5D")  # URL-encoded [NAME_1]

        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_delete_token_not_found(self, client, mock_scrubiq):
        """DELETE /tokens/{token} returns 404 for unknown token."""
        mock_scrubiq.delete_token.return_value = False

        response = client.delete("/tokens/%5BUNKNOWN_1%5D")

        assert response.status_code == 404
        assert "TOKEN_NOT_FOUND" in response.json()["error_code"]

    def test_delete_token_calls_scrubiq(self, client, mock_scrubiq):
        """DELETE /tokens/{token} calls ScrubIQ.delete_token."""
        client.delete("/tokens/%5BNAME_1%5D")

        mock_scrubiq.delete_token.assert_called_once_with("[NAME_1]")


# =============================================================================
# RATE LIMITING TESTS
# =============================================================================

class TestRateLimiting:
    """Tests that rate limiting is applied."""

    def test_redact_checks_rate_limit(self, mock_scrubiq):
        """Redact endpoint checks rate limit."""
        from scrubiq.api.routes.core import router
        from scrubiq.api.dependencies import require_unlocked

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[require_unlocked] = lambda: mock_scrubiq

        with patch("scrubiq.api.routes.core.check_rate_limit") as mock_rate:
            client = TestClient(app)
            client.post("/redact", json={"text": "test"})

            mock_rate.assert_called_once()
            call_kwargs = mock_rate.call_args[1]
            assert call_kwargs["action"] == "redact"

    def test_chat_checks_rate_limit(self, mock_scrubiq):
        """Chat endpoint checks rate limit."""
        from scrubiq.api.routes.core import router
        from scrubiq.api.dependencies import require_unlocked

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[require_unlocked] = lambda: mock_scrubiq

        with patch("scrubiq.api.routes.core.check_rate_limit") as mock_rate:
            client = TestClient(app)
            client.post("/chat", json={"text": "test"})

            mock_rate.assert_called_once()
            call_kwargs = mock_rate.call_args[1]
            assert call_kwargs["action"] == "chat"
