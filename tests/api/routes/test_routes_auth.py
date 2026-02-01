"""Tests for auth API routes: status, providers.

Tests authentication status and provider listing endpoints.

Note: These tests require SQLCipher and FastAPI to be installed.
"""

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

try:
    from scrubiq.api.routes import auth as routes_auth
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
def mock_scrubiq():
    """Create a mock ScrubIQ instance."""
    mock = MagicMock()
    mock.list_llm_providers.return_value = ["anthropic", "openai"]
    mock.list_llm_models.return_value = {
        "anthropic": ["claude-sonnet-4", "claude-haiku-4"],
        "openai": ["gpt-4"],
    }
    return mock


@pytest.fixture
def mock_api_key_service():
    """Create a mock API key service."""
    mock = MagicMock()
    mock.has_any_keys.return_value = True
    return mock


@pytest.fixture
def mock_pool():
    """Create a mock instance pool."""
    mock = MagicMock()
    mock.get_stats.return_value = {"current_size": 1}
    return mock


@pytest.fixture
def client(mock_scrubiq, mock_api_key_service, mock_pool):
    """Create test client with mocked dependencies."""
    from scrubiq.api.routes.auth import router
    from scrubiq.api.dependencies import require_api_key
    from scrubiq.api.errors import register_error_handlers

    app = FastAPI()
    app.include_router(router)
    register_error_handlers(app)

    # Override dependencies
    app.dependency_overrides[require_api_key] = lambda: mock_scrubiq

    with patch("scrubiq.api.routes.auth.get_api_key_service", return_value=mock_api_key_service):
        with patch("scrubiq.api.routes.auth.get_pool", return_value=mock_pool):
            with patch("scrubiq.api.routes.auth.ScrubIQ") as MockScrubIQ:
                MockScrubIQ.is_preload_complete.return_value = True
                yield TestClient(app, raise_server_exceptions=False)


# =============================================================================
# STATUS ENDPOINT TESTS
# =============================================================================

class TestStatusEndpoint:
    """Tests for GET /status endpoint."""

    def test_status_success(self, client):
        """Status endpoint returns system status."""
        response = client.get("/status")

        assert response.status_code == 200
        data = response.json()
        assert "initialized" in data
        assert "unlocked" in data
        assert "models_ready" in data

    def test_status_initialized_when_keys_exist(self, client, mock_api_key_service):
        """initialized is True when API keys exist."""
        mock_api_key_service.has_any_keys.return_value = True

        response = client.get("/status")

        assert response.status_code == 200
        assert response.json()["initialized"] is True

    def test_status_not_initialized_when_no_keys(self, mock_scrubiq, mock_pool):
        """initialized is False when no API keys exist."""
        from scrubiq.api.routes.auth import router
        from scrubiq.api.errors import register_error_handlers

        app = FastAPI()
        app.include_router(router)
        register_error_handlers(app)

        mock_service = MagicMock()
        mock_service.has_any_keys.return_value = False

        with patch("scrubiq.api.routes.auth.get_api_key_service", return_value=mock_service):
            with patch("scrubiq.api.routes.auth.get_pool", return_value=mock_pool):
                with patch("scrubiq.api.routes.auth.ScrubIQ") as MockScrubIQ:
                    MockScrubIQ.is_preload_complete.return_value = True
                    test_client = TestClient(app)
                    response = test_client.get("/status")

        assert response.json()["initialized"] is False
        assert response.json()["is_new_vault"] is True

    def test_status_unlocked_when_instances_active(self, client, mock_pool):
        """unlocked is True when pool has active instances."""
        mock_pool.get_stats.return_value = {"current_size": 3}

        response = client.get("/status")

        assert response.status_code == 200
        assert response.json()["unlocked"] is True

    def test_status_locked_when_no_instances(self, mock_scrubiq, mock_api_key_service):
        """unlocked is False when pool has no instances."""
        from scrubiq.api.routes.auth import router
        from scrubiq.api.errors import register_error_handlers

        app = FastAPI()
        app.include_router(router)
        register_error_handlers(app)

        mock_pool = MagicMock()
        mock_pool.get_stats.return_value = {"current_size": 0}

        with patch("scrubiq.api.routes.auth.get_api_key_service", return_value=mock_api_key_service):
            with patch("scrubiq.api.routes.auth.get_pool", return_value=mock_pool):
                with patch("scrubiq.api.routes.auth.ScrubIQ") as MockScrubIQ:
                    MockScrubIQ.is_preload_complete.return_value = True
                    test_client = TestClient(app)
                    response = test_client.get("/status")

        assert response.json()["unlocked"] is False

    def test_status_models_ready(self, client):
        """models_ready reflects preload status."""
        response = client.get("/status")

        assert response.status_code == 200
        assert response.json()["models_ready"] is True
        assert response.json()["preload_complete"] is True

    def test_status_models_loading(self, mock_scrubiq, mock_api_key_service, mock_pool):
        """models_loading is True when preload incomplete."""
        from scrubiq.api.routes.auth import router
        from scrubiq.api.errors import register_error_handlers

        app = FastAPI()
        app.include_router(router)
        register_error_handlers(app)

        with patch("scrubiq.api.routes.auth.get_api_key_service", return_value=mock_api_key_service):
            with patch("scrubiq.api.routes.auth.get_pool", return_value=mock_pool):
                with patch("scrubiq.api.routes.auth.ScrubIQ") as MockScrubIQ:
                    MockScrubIQ.is_preload_complete.return_value = False
                    test_client = TestClient(app)
                    response = test_client.get("/status")

        assert response.json()["models_loading"] is True
        assert response.json()["models_ready"] is False

    def test_status_handles_pool_error(self, mock_api_key_service):
        """Status handles pool RuntimeError gracefully."""
        from scrubiq.api.routes.auth import router
        from scrubiq.api.errors import register_error_handlers

        app = FastAPI()
        app.include_router(router)
        register_error_handlers(app)

        with patch("scrubiq.api.routes.auth.get_api_key_service", return_value=mock_api_key_service):
            with patch("scrubiq.api.routes.auth.get_pool", side_effect=RuntimeError("Pool not ready")):
                with patch("scrubiq.api.routes.auth.ScrubIQ") as MockScrubIQ:
                    MockScrubIQ.is_preload_complete.return_value = True
                    test_client = TestClient(app)
                    response = test_client.get("/status")

        # Should still return 200 with unlocked=False
        assert response.status_code == 200
        assert response.json()["unlocked"] is False

    def test_status_response_structure(self, client):
        """Status response has all required fields."""
        response = client.get("/status")

        assert response.status_code == 200
        data = response.json()
        required_fields = [
            "initialized", "unlocked", "timeout_remaining",
            "tokens_count", "review_pending", "models_ready",
            "models_loading", "preload_complete", "is_new_vault",
            "vault_needs_upgrade",
        ]
        for field in required_fields:
            assert field in data, f"Missing field: {field}"


# =============================================================================
# PROVIDERS ENDPOINT TESTS
# =============================================================================

class TestProvidersEndpoint:
    """Tests for GET /providers endpoint."""

    def test_providers_success(self, client, mock_scrubiq):
        """Providers endpoint returns available providers."""
        with patch("scrubiq.api.routes.auth.check_rate_limit"):
            response = client.get("/providers")

        assert response.status_code == 200
        data = response.json()
        assert "available" in data
        assert "models" in data

    def test_providers_lists_available(self, client, mock_scrubiq):
        """Providers includes list of available providers."""
        with patch("scrubiq.api.routes.auth.check_rate_limit"):
            response = client.get("/providers")

        assert response.status_code == 200
        assert "anthropic" in response.json()["available"]
        assert "openai" in response.json()["available"]

    def test_providers_includes_models(self, client, mock_scrubiq):
        """Providers includes models per provider."""
        with patch("scrubiq.api.routes.auth.check_rate_limit"):
            response = client.get("/providers")

        assert response.status_code == 200
        models = response.json()["models"]
        assert "anthropic" in models
        assert "claude-sonnet-4" in models["anthropic"]

    def test_providers_calls_scrubiq_methods(self, client, mock_scrubiq):
        """Providers endpoint calls ScrubIQ methods."""
        with patch("scrubiq.api.routes.auth.check_rate_limit"):
            client.get("/providers")

        mock_scrubiq.list_llm_providers.assert_called_once()
        mock_scrubiq.list_llm_models.assert_called_once()

    def test_providers_requires_auth(self, mock_api_key_service, mock_pool):
        """Providers endpoint requires API key auth."""
        from scrubiq.api.routes.auth import router
        from scrubiq.api.errors import register_error_handlers

        app = FastAPI()
        app.include_router(router)
        register_error_handlers(app)

        # Don't override the require_api_key dependency
        with patch("scrubiq.api.routes.auth.get_api_key_service", return_value=mock_api_key_service):
            with patch("scrubiq.api.routes.auth.get_pool", return_value=mock_pool):
                with patch("scrubiq.api.routes.auth.ScrubIQ"):
                    test_client = TestClient(app, raise_server_exceptions=False)
                    response = test_client.get("/providers")

        # Should fail without auth
        assert response.status_code in (401, 500)  # 500 if service not initialized
