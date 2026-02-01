"""Tests for admin API routes: health, greeting, audit status.

Tests administrative and monitoring endpoints.

Note: These tests require SQLCipher and FastAPI to be installed.
"""

from datetime import date
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

try:
    from scrubiq.api.routes import admin as routes_admin
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
    mock.is_unlocked = True
    mock._db = MagicMock()
    mock._db.conn = MagicMock()
    mock._models_loading = False
    mock._detectors = MagicMock()
    mock._llm_loading = False
    mock._llm_client = MagicMock()
    mock._llm_client.is_available.return_value = True
    mock._ocr_engine = MagicMock()
    mock._ocr_engine.is_available = True
    mock.has_llm = True

    # Mock audit
    mock._audit = MagicMock()
    mock._audit.get_retention_status.return_value = {
        "total_entries": 1000,
        "oldest_entry": "2024-01-01T00:00:00",
        "entries_past_retention": 0,
        "retention_days": 2190,
        "estimated_size_mb": 5.2,
    }
    mock._audit.verify_chain.return_value = (True, None)

    return mock


@pytest.fixture
def client(mock_scrubiq):
    """Create test client with mocked dependencies."""
    from scrubiq.api.routes.admin import router
    from scrubiq.api.dependencies import require_api_key
    from scrubiq.api.errors import register_error_handlers

    app = FastAPI()
    app.include_router(router)
    register_error_handlers(app)

    app.dependency_overrides[require_api_key] = lambda: mock_scrubiq

    with patch("scrubiq.api.routes.admin.check_rate_limit"):
        yield TestClient(app, raise_server_exceptions=False)


# =============================================================================
# HEALTH ENDPOINT TESTS
# =============================================================================

class TestHealthEndpoint:
    """Tests for GET /health endpoint."""

    def test_health_returns_ok(self, client):
        """Health endpoint returns ok status."""
        response = client.get("/health")

        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_health_no_version_info(self, client):
        """Health endpoint does not expose version (security)."""
        response = client.get("/health")

        assert response.status_code == 200
        assert "version" not in response.json()

    def test_health_no_auth_required(self, mock_scrubiq):
        """Health endpoint works without auth."""
        from scrubiq.api.routes.admin import router
        from scrubiq.api.errors import register_error_handlers

        app = FastAPI()
        app.include_router(router)
        register_error_handlers(app)
        # No dependency overrides

        with patch("scrubiq.api.routes.admin.limiter", None):
            with patch("scrubiq.api.routes.admin.SLOWAPI_AVAILABLE", False):
                test_client = TestClient(app)
                response = test_client.get("/health")

        assert response.status_code == 200


# =============================================================================
# SECURITY.TXT ENDPOINT TESTS
# =============================================================================

class TestSecurityTxtEndpoint:
    """Tests for GET /.well-known/security.txt endpoint."""

    def test_security_txt_returns_text(self, client):
        """Security.txt returns plain text."""
        response = client.get("/.well-known/security.txt")

        assert response.status_code == 200
        assert response.headers["content-type"] == "text/plain; charset=utf-8"

    def test_security_txt_contains_contact(self, client):
        """Security.txt contains Contact field."""
        response = client.get("/.well-known/security.txt")

        assert "Contact:" in response.text

    def test_security_txt_contains_policy(self, client):
        """Security.txt contains Policy field."""
        response = client.get("/.well-known/security.txt")

        assert "Policy:" in response.text

    def test_security_txt_references_github(self, client):
        """Security.txt references GitHub for reporting."""
        response = client.get("/.well-known/security.txt")

        assert "github.com" in response.text


# =============================================================================
# DETAILED HEALTH ENDPOINT TESTS
# =============================================================================

class TestDetailedHealthEndpoint:
    """Tests for GET /health/detailed endpoint."""

    def test_detailed_health_success(self, client, mock_scrubiq):
        """Detailed health returns component status."""
        response = client.get("/health/detailed")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "components" in data

    def test_detailed_health_includes_version(self, client):
        """Detailed health includes version info."""
        response = client.get("/health/detailed")

        assert response.status_code == 200
        assert "version" in response.json()

    def test_detailed_health_includes_python_version(self, client):
        """Detailed health includes Python version."""
        response = client.get("/health/detailed")

        assert response.status_code == 200
        assert "python_version" in response.json()

    def test_detailed_health_components(self, client):
        """Detailed health includes all components."""
        response = client.get("/health/detailed")

        assert response.status_code == 200
        components = response.json()["components"]
        assert "database" in components
        assert "encryption" in components
        assert "detectors" in components
        assert "llm" in components
        assert "ocr" in components

    def test_detailed_health_database_ok(self, client, mock_scrubiq):
        """Database status is ok when connected."""
        response = client.get("/health/detailed")

        assert response.json()["components"]["database"] == "ok"

    def test_detailed_health_database_error(self, client, mock_scrubiq):
        """Database status is error when not connected."""
        mock_scrubiq._db = None

        response = client.get("/health/detailed")

        assert response.json()["components"]["database"] == "error"

    def test_detailed_health_encryption_ok(self, client, mock_scrubiq):
        """Encryption status is ok when unlocked."""
        response = client.get("/health/detailed")

        assert response.json()["components"]["encryption"] == "ok"

    def test_detailed_health_encryption_locked(self, client, mock_scrubiq):
        """Encryption status is locked when not unlocked."""
        mock_scrubiq.is_unlocked = False

        response = client.get("/health/detailed")

        assert response.json()["components"]["encryption"] == "locked"

    def test_detailed_health_detectors_loading(self, client, mock_scrubiq):
        """Detector status is loading when models loading."""
        mock_scrubiq._models_loading = True

        response = client.get("/health/detailed")

        assert response.json()["components"]["detectors"] == "loading"

    def test_detailed_health_llm_unavailable(self, client, mock_scrubiq):
        """LLM status is unavailable when not available."""
        mock_scrubiq._llm_client.is_available.return_value = False

        response = client.get("/health/detailed")

        assert response.json()["components"]["llm"] == "unavailable"

    def test_detailed_health_ready_flag(self, client, mock_scrubiq):
        """Ready flag is True when all systems go."""
        response = client.get("/health/detailed")

        assert response.json()["ready"] is True

    def test_detailed_health_not_ready_when_loading(self, client, mock_scrubiq):
        """Ready flag is False when models loading."""
        mock_scrubiq._models_loading = True

        response = client.get("/health/detailed")

        assert response.json()["ready"] is False


# =============================================================================
# GREETING ENDPOINT TESTS
# =============================================================================

class TestGreetingEndpoint:
    """Tests for GET /greeting endpoint."""

    def test_greeting_returns_greeting(self, client, mock_scrubiq):
        """Greeting endpoint returns a greeting."""
        # Mock the LLM response
        mock_response = MagicMock()
        mock_response.success = True
        mock_response.text = "Hello! How can I help you today?"
        mock_scrubiq._llm_client.chat.return_value = mock_response

        response = client.get("/greeting")

        assert response.status_code == 200
        assert "greeting" in response.json()
        assert len(response.json()["greeting"]) > 0

    def test_greeting_has_cached_flag(self, client, mock_scrubiq):
        """Greeting response includes cached flag."""
        mock_response = MagicMock()
        mock_response.success = True
        mock_response.text = "Hello there!"
        mock_scrubiq._llm_client.chat.return_value = mock_response

        response = client.get("/greeting")

        assert response.status_code == 200
        assert "cached" in response.json()

    def test_greeting_fallback_on_llm_error(self, client, mock_scrubiq):
        """Greeting uses fallback when LLM fails."""
        mock_scrubiq._llm_client.chat.side_effect = Exception("LLM error")

        response = client.get("/greeting")

        assert response.status_code == 200
        # Should return one of the default greetings
        greeting = response.json()["greeting"]
        assert len(greeting) > 0

    def test_greeting_fallback_when_no_llm(self, client, mock_scrubiq):
        """Greeting uses fallback when no LLM available."""
        mock_scrubiq.has_llm = False

        response = client.get("/greeting")

        assert response.status_code == 200
        assert len(response.json()["greeting"]) > 0


# =============================================================================
# AUDIT STATUS ENDPOINT TESTS
# =============================================================================

class TestAuditStatusEndpoint:
    """Tests for GET /audit/status endpoint."""

    def test_audit_status_success(self, client, mock_scrubiq):
        """Audit status returns retention info."""
        response = client.get("/audit/status")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    def test_audit_status_includes_counts(self, client, mock_scrubiq):
        """Audit status includes entry counts."""
        response = client.get("/audit/status")

        assert response.status_code == 200
        data = response.json()
        assert data["total_entries"] == 1000
        assert data["entries_past_retention"] == 0

    def test_audit_status_includes_retention(self, client, mock_scrubiq):
        """Audit status includes retention days."""
        response = client.get("/audit/status")

        assert response.status_code == 200
        assert response.json()["retention_days"] == 2190

    def test_audit_status_chain_integrity(self, client, mock_scrubiq):
        """Audit status includes chain integrity."""
        response = client.get("/audit/status")

        assert response.status_code == 200
        assert response.json()["chain_integrity"] == "valid"
        assert response.json()["chain_error"] is None

    def test_audit_status_chain_broken(self, client, mock_scrubiq):
        """Audit status reports broken chain."""
        mock_scrubiq._audit.verify_chain.return_value = (False, "Hash mismatch at entry 50")

        response = client.get("/audit/status")

        assert response.status_code == 200
        assert response.json()["chain_integrity"] == "broken"
        assert "Hash mismatch" in response.json()["chain_error"]

    def test_audit_status_not_initialized(self, client, mock_scrubiq):
        """Audit status handles uninitialized audit."""
        mock_scrubiq._audit = None

        response = client.get("/audit/status")

        assert response.status_code == 200
        assert response.json()["status"] == "not_initialized"

    def test_audit_status_includes_size(self, client, mock_scrubiq):
        """Audit status includes estimated size."""
        response = client.get("/audit/status")

        assert response.status_code == 200
        assert response.json()["estimated_size_mb"] == 5.2

    def test_audit_status_includes_oldest_entry(self, client, mock_scrubiq):
        """Audit status includes oldest entry date."""
        response = client.get("/audit/status")

        assert response.status_code == 200
        assert response.json()["oldest_entry"] == "2024-01-01T00:00:00"
