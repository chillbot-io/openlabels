"""Tests for the Settings API routes (api/settings.py).

Tests cover:
- GET /settings - retrieve current settings
- PUT /settings - update settings
- GET /settings/entity-types - list available entity types
- GET /settings/providers - list LLM providers
- GET /settings/allowlist - get allowlist entries
- POST /settings/allowlist - update allowlist (add/remove/set)
- GET /settings/thresholds - get detection thresholds
- PUT /settings/thresholds - update thresholds
- Rate limiting
- Authentication requirements
- Input validation
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from fastapi import FastAPI
from fastapi.testclient import TestClient


# --- Fixtures ---

@pytest.fixture
def mock_config():
    """Create a mock config object with default settings."""
    config = MagicMock()
    config.confidence_threshold = 0.85
    config.safe_harbor_enabled = True
    config.coref_enabled = True
    config.entity_types = None
    config.exclude_types = None
    config.allowlist = {"safe_value_1", "safe_value_2"}
    config.review_threshold = 0.7
    config.device = "auto"
    config.llm_provider = "anthropic"
    config.llm_model = "claude-sonnet-4"
    config.type_thresholds = {}
    return config


@pytest.fixture
def mock_credential_result(mock_config):
    """Create a mock credential result (cr) from require_api_key."""
    cr = MagicMock()
    cr.is_unlocked = True
    cr.config = mock_config
    return cr


@pytest.fixture
def mock_locked_credential_result(mock_config):
    """Create a mock locked credential result."""
    cr = MagicMock()
    cr.is_unlocked = False
    cr.config = mock_config
    return cr


@pytest.fixture
def test_app(mock_credential_result):
    """Create test app with mocked dependencies."""
    from scrubiq.api.settings import router

    app = FastAPI()
    app.include_router(router)

    # Mock the require_api_key dependency
    def override_require_api_key():
        return mock_credential_result

    # Mock rate limiting
    with patch("scrubiq.api.settings.check_rate_limit"):
        from scrubiq.api.dependencies import require_api_key
        app.dependency_overrides[require_api_key] = override_require_api_key

        yield TestClient(app), mock_credential_result


@pytest.fixture
def test_app_locked(mock_locked_credential_result):
    """Create test app with locked session."""
    from scrubiq.api.settings import router

    app = FastAPI()
    app.include_router(router)

    def override_require_api_key():
        return mock_locked_credential_result

    with patch("scrubiq.api.settings.check_rate_limit"):
        from scrubiq.api.dependencies import require_api_key
        app.dependency_overrides[require_api_key] = override_require_api_key

        yield TestClient(app)


# --- GET /settings Tests ---

class TestGetSettings:
    """Tests for GET /settings endpoint."""

    def test_get_settings_returns_current_config(self, test_app):
        """Should return current configuration settings."""
        client, cr = test_app

        response = client.get("/settings")

        assert response.status_code == 200
        data = response.json()

        assert data["confidence_threshold"] == 0.85
        assert data["safe_harbor"] is True
        assert data["coreference"] is True
        assert data["device"] == "auto"
        assert data["llm_provider"] == "anthropic"
        assert data["llm_model"] == "claude-sonnet-4"

    def test_get_settings_includes_allowlist(self, test_app):
        """Should include allowlist entries."""
        client, cr = test_app

        response = client.get("/settings")

        assert response.status_code == 200
        data = response.json()

        # Allowlist should be a list
        assert isinstance(data["allowlist"], list)
        assert len(data["allowlist"]) == 2

    def test_get_settings_requires_unlocked_session(self, test_app_locked):
        """Should require unlocked session."""
        client = test_app_locked

        response = client.get("/settings")

        assert response.status_code == 401

    def test_get_settings_handles_missing_attributes(self, test_app):
        """Should handle missing config attributes gracefully."""
        client, cr = test_app

        # Remove some attributes to test defaults
        del cr.config.confidence_threshold
        del cr.config.llm_model

        response = client.get("/settings")

        assert response.status_code == 200
        data = response.json()

        # Should use defaults from SettingsResponse
        assert data["confidence_threshold"] == 0.85  # Default
        assert data["llm_model"] == "claude-sonnet-4"  # Default


# --- PUT /settings Tests ---

class TestUpdateSettings:
    """Tests for PUT /settings endpoint."""

    def test_update_confidence_threshold(self, test_app):
        """Should update confidence threshold."""
        client, cr = test_app

        response = client.put("/settings", json={"confidence_threshold": 0.9})

        assert response.status_code == 200
        assert cr.config.confidence_threshold == 0.9

    def test_update_safe_harbor(self, test_app):
        """Should update safe harbor setting."""
        client, cr = test_app

        response = client.put("/settings", json={"safe_harbor": False})

        assert response.status_code == 200
        assert cr.config.safe_harbor_enabled is False

    def test_update_coreference(self, test_app):
        """Should update coreference setting."""
        client, cr = test_app

        response = client.put("/settings", json={"coreference": False})

        assert response.status_code == 200
        assert cr.config.coref_enabled is False

    def test_update_device(self, test_app):
        """Should update device setting."""
        client, cr = test_app

        response = client.put("/settings", json={"device": "cuda"})

        assert response.status_code == 200
        assert cr.config.device == "cuda"

    def test_update_device_rejects_invalid(self, test_app):
        """Should reject invalid device values."""
        client, cr = test_app

        response = client.put("/settings", json={"device": "invalid"})

        assert response.status_code == 400
        assert "invalid device" in response.json()["detail"].lower()

    def test_update_llm_provider(self, test_app):
        """Should update LLM provider."""
        client, cr = test_app

        response = client.put("/settings", json={"llm_provider": "openai"})

        assert response.status_code == 200
        assert cr.config.llm_provider == "openai"

    def test_update_llm_provider_rejects_invalid(self, test_app):
        """Should reject invalid LLM provider."""
        client, cr = test_app

        response = client.put("/settings", json={"llm_provider": "invalid"})

        assert response.status_code == 400
        assert "invalid provider" in response.json()["detail"].lower()

    def test_update_entity_types(self, test_app):
        """Should update entity types filter."""
        client, cr = test_app

        with patch("scrubiq.api.settings.KNOWN_ENTITY_TYPES", {"NAME", "SSN", "EMAIL"}):
            response = client.put("/settings", json={"entity_types": ["NAME", "SSN"]})

            assert response.status_code == 200
            assert cr.config.entity_types == ["NAME", "SSN"]

    def test_update_entity_types_rejects_unknown(self, test_app):
        """Should reject unknown entity types."""
        client, cr = test_app

        with patch("scrubiq.api.settings.KNOWN_ENTITY_TYPES", {"NAME", "SSN"}):
            response = client.put("/settings", json={"entity_types": ["NAME", "UNKNOWN_TYPE"]})

            assert response.status_code == 400
            assert "unknown entity types" in response.json()["detail"].lower()

    def test_update_multiple_settings(self, test_app):
        """Should update multiple settings at once."""
        client, cr = test_app

        response = client.put("/settings", json={
            "confidence_threshold": 0.75,
            "safe_harbor": False,
            "device": "cpu",
        })

        assert response.status_code == 200
        assert cr.config.confidence_threshold == 0.75
        assert cr.config.safe_harbor_enabled is False
        assert cr.config.device == "cpu"

    def test_update_settings_requires_unlocked_session(self, test_app_locked):
        """Should require unlocked session."""
        client = test_app_locked

        response = client.put("/settings", json={"confidence_threshold": 0.9})

        assert response.status_code == 401

    def test_update_returns_updated_settings(self, test_app):
        """Should return the updated settings in response."""
        client, cr = test_app

        response = client.put("/settings", json={"confidence_threshold": 0.95})

        assert response.status_code == 200
        data = response.json()
        assert data["confidence_threshold"] == 0.95


# --- GET /settings/entity-types Tests ---

class TestGetEntityTypes:
    """Tests for GET /settings/entity-types endpoint."""

    def test_get_entity_types_returns_list(self, test_app):
        """Should return list of entity types."""
        client, _ = test_app

        with patch("scrubiq.api.settings.KNOWN_ENTITY_TYPES", {"NAME", "SSN", "EMAIL", "PHONE"}):
            response = client.get("/settings/entity-types")

            assert response.status_code == 200
            data = response.json()

            assert "types" in data
            assert isinstance(data["types"], list)
            assert len(data["types"]) == 4

    def test_get_entity_types_sorted(self, test_app):
        """Entity types should be sorted alphabetically."""
        client, _ = test_app

        with patch("scrubiq.api.settings.KNOWN_ENTITY_TYPES", {"ZEBRA", "ALPHA", "BETA"}):
            response = client.get("/settings/entity-types")

            assert response.status_code == 200
            data = response.json()

            assert data["types"] == ["ALPHA", "BETA", "ZEBRA"]

    def test_get_entity_types_includes_categories(self, test_app):
        """Should include categorized entity types."""
        client, _ = test_app

        response = client.get("/settings/entity-types")

        assert response.status_code == 200
        data = response.json()

        assert "categories" in data
        assert isinstance(data["categories"], dict)


# --- GET /settings/providers Tests ---

class TestGetProviders:
    """Tests for GET /settings/providers endpoint."""

    def test_get_providers_returns_dict(self, test_app):
        """Should return dict of providers."""
        client, _ = test_app

        with patch("scrubiq.api.settings.AnthropicClient") as mock_anthropic:
            with patch("scrubiq.api.settings.OpenAIClient") as mock_openai:
                mock_anthropic.return_value.list_models.return_value = ["claude-3", "claude-sonnet-4"]
                mock_anthropic.return_value.is_available.return_value = True
                mock_openai.return_value.list_models.return_value = ["gpt-4", "gpt-4o"]
                mock_openai.return_value.is_available.return_value = False

                response = client.get("/settings/providers")

                assert response.status_code == 200
                data = response.json()

                assert "providers" in data
                assert "anthropic" in data["providers"]
                assert "openai" in data["providers"]

    def test_get_providers_includes_availability(self, test_app):
        """Should include availability status for each provider."""
        client, _ = test_app

        with patch("scrubiq.api.settings.AnthropicClient") as mock_anthropic:
            with patch("scrubiq.api.settings.OpenAIClient") as mock_openai:
                mock_anthropic.return_value.list_models.return_value = []
                mock_anthropic.return_value.is_available.return_value = True
                mock_openai.return_value.list_models.return_value = []
                mock_openai.return_value.is_available.return_value = False

                response = client.get("/settings/providers")

                assert response.status_code == 200
                data = response.json()

                assert data["providers"]["anthropic"]["available"] is True
                assert data["providers"]["openai"]["available"] is False


# --- GET /settings/allowlist Tests ---

class TestGetAllowlist:
    """Tests for GET /settings/allowlist endpoint."""

    def test_get_allowlist_returns_list(self, test_app):
        """Should return list of allowlist entries."""
        client, cr = test_app
        cr.config.allowlist = {"entry1", "entry2", "entry3"}

        response = client.get("/settings/allowlist")

        assert response.status_code == 200
        data = response.json()

        assert isinstance(data, list)
        assert len(data) == 3

    def test_get_allowlist_sorted(self, test_app):
        """Allowlist entries should be sorted."""
        client, cr = test_app
        cr.config.allowlist = {"zebra", "alpha", "beta"}

        response = client.get("/settings/allowlist")

        assert response.status_code == 200
        data = response.json()

        assert data == ["alpha", "beta", "zebra"]

    def test_get_allowlist_requires_unlocked(self, test_app_locked):
        """Should require unlocked session."""
        client = test_app_locked

        response = client.get("/settings/allowlist")

        assert response.status_code == 401


# --- POST /settings/allowlist Tests ---

class TestUpdateAllowlist:
    """Tests for POST /settings/allowlist endpoint."""

    def test_add_to_allowlist(self, test_app):
        """Should add entries to allowlist."""
        client, cr = test_app
        cr.config.allowlist = {"existing"}

        response = client.post("/settings/allowlist", json={
            "action": "add",
            "values": ["new1", "new2"]
        })

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "new1" in cr.config.allowlist
        assert "new2" in cr.config.allowlist
        assert "existing" in cr.config.allowlist

    def test_remove_from_allowlist(self, test_app):
        """Should remove entries from allowlist."""
        client, cr = test_app
        cr.config.allowlist = {"entry1", "entry2", "entry3"}

        response = client.post("/settings/allowlist", json={
            "action": "remove",
            "values": ["entry1", "entry2"]
        })

        assert response.status_code == 200
        assert "entry1" not in cr.config.allowlist
        assert "entry2" not in cr.config.allowlist
        assert "entry3" in cr.config.allowlist

    def test_set_allowlist(self, test_app):
        """Should replace entire allowlist."""
        client, cr = test_app
        cr.config.allowlist = {"old1", "old2"}

        response = client.post("/settings/allowlist", json={
            "action": "set",
            "values": ["new1", "new2", "new3"]
        })

        assert response.status_code == 200
        assert cr.config.allowlist == {"new1", "new2", "new3"}

    def test_invalid_action_rejected(self, test_app):
        """Should reject invalid action."""
        client, cr = test_app

        response = client.post("/settings/allowlist", json={
            "action": "invalid",
            "values": ["test"]
        })

        assert response.status_code == 422  # Pydantic validation error

    def test_allowlist_max_entries_limit(self, test_app):
        """Should enforce max entries limit."""
        client, cr = test_app
        cr.config.allowlist = set()

        from scrubiq.api.settings import MAX_ALLOWLIST_ENTRIES

        # Try to add more than max entries
        values = [f"entry{i}" for i in range(MAX_ALLOWLIST_ENTRIES + 10)]

        response = client.post("/settings/allowlist", json={
            "action": "set",
            "values": values
        })

        # 422 = Pydantic validation, 400 = manual validation - accept either
        assert response.status_code in (400, 422)

    def test_allowlist_entry_length_limit(self, test_app):
        """Should enforce max entry length limit."""
        client, cr = test_app

        from scrubiq.api.settings import MAX_ALLOWLIST_VALUE_LENGTH

        long_value = "x" * (MAX_ALLOWLIST_VALUE_LENGTH + 10)

        response = client.post("/settings/allowlist", json={
            "action": "add",
            "values": [long_value]
        })

        assert response.status_code == 400
        assert "max length" in response.json()["detail"].lower()

    def test_allowlist_batch_size_limit(self, test_app):
        """Should enforce max batch size limit."""
        client, cr = test_app

        from scrubiq.api.settings import MAX_ALLOWLIST_BATCH_SIZE

        values = [f"entry{i}" for i in range(MAX_ALLOWLIST_BATCH_SIZE + 10)]

        response = client.post("/settings/allowlist", json={
            "action": "add",
            "values": values
        })

        # Should be rejected by Pydantic validation
        assert response.status_code == 422

    def test_allowlist_requires_unlocked(self, test_app_locked):
        """Should require unlocked session."""
        client = test_app_locked

        response = client.post("/settings/allowlist", json={
            "action": "add",
            "values": ["test"]
        })

        assert response.status_code == 401


# --- GET /settings/thresholds Tests ---

class TestGetThresholds:
    """Tests for GET /settings/thresholds endpoint."""

    def test_get_thresholds(self, test_app):
        """Should return threshold settings."""
        client, cr = test_app
        cr.config.confidence_threshold = 0.85
        cr.config.review_threshold = 0.7
        cr.config.type_thresholds = {"NAME": 0.9, "SSN": 0.95}

        response = client.get("/settings/thresholds")

        assert response.status_code == 200
        data = response.json()

        assert data["global"] == 0.85
        assert data["review"] == 0.7
        assert data["per_type"] == {"NAME": 0.9, "SSN": 0.95}

    def test_get_thresholds_requires_unlocked(self, test_app_locked):
        """Should require unlocked session."""
        client = test_app_locked

        response = client.get("/settings/thresholds")

        assert response.status_code == 401


# --- PUT /settings/thresholds Tests ---

class TestUpdateThresholds:
    """Tests for PUT /settings/thresholds endpoint."""

    def test_update_global_threshold(self, test_app):
        """Should update global threshold."""
        client, cr = test_app

        response = client.put("/settings/thresholds", json={"global": 0.9})

        assert response.status_code == 200
        assert cr.config.confidence_threshold == 0.9

    def test_update_review_threshold(self, test_app):
        """Should update review threshold."""
        client, cr = test_app

        response = client.put("/settings/thresholds", json={"review": 0.6})

        assert response.status_code == 200
        assert cr.config.review_threshold == 0.6

    def test_update_per_type_thresholds(self, test_app):
        """Should update per-type thresholds."""
        client, cr = test_app
        cr.config.type_thresholds = {}

        with patch("scrubiq.api.settings.KNOWN_ENTITY_TYPES", {"NAME", "SSN", "EMAIL"}):
            response = client.put("/settings/thresholds", json={
                "per_type": {"NAME": 0.9, "SSN": 0.95}
            })

            assert response.status_code == 200
            assert cr.config.type_thresholds["NAME"] == 0.9
            assert cr.config.type_thresholds["SSN"] == 0.95

    def test_update_threshold_rejects_out_of_range(self, test_app):
        """Should reject thresholds outside 0-1 range."""
        client, cr = test_app

        # Test > 1
        response = client.put("/settings/thresholds", json={"global": 1.5})
        assert response.status_code == 400

        # Test < 0
        response = client.put("/settings/thresholds", json={"review": -0.1})
        assert response.status_code == 400

    def test_update_threshold_rejects_unknown_entity_type(self, test_app):
        """Should reject unknown entity types in per_type."""
        client, cr = test_app

        with patch("scrubiq.api.settings.KNOWN_ENTITY_TYPES", {"NAME", "SSN"}):
            response = client.put("/settings/thresholds", json={
                "per_type": {"UNKNOWN_TYPE": 0.9}
            })

            assert response.status_code == 400
            assert "unknown entity type" in response.json()["detail"].lower()

    def test_update_thresholds_requires_unlocked(self, test_app_locked):
        """Should require unlocked session."""
        client = test_app_locked

        response = client.put("/settings/thresholds", json={"global": 0.9})

        assert response.status_code == 401


# --- Entity Type Categorization Tests ---

class TestEntityTypeCategorization:
    """Tests for entity type categorization logic."""

    def test_categorize_secrets_cloud(self):
        """Cloud secrets should be categorized correctly."""
        from scrubiq.api.settings import _categorize_entity_types

        with patch("scrubiq.api.settings.KNOWN_ENTITY_TYPES", {"AWS_ACCESS_KEY", "AZURE_CLIENT_ID"}):
            categories = _categorize_entity_types()

            assert "secrets_cloud" in categories
            assert "AWS_ACCESS_KEY" in categories["secrets_cloud"]

    def test_categorize_financial(self):
        """Financial entity types should be categorized correctly."""
        from scrubiq.api.settings import _categorize_entity_types

        with patch("scrubiq.api.settings.KNOWN_ENTITY_TYPES", {"CREDIT_CARD", "CUSIP", "BITCOIN_ADDRESS"}):
            categories = _categorize_entity_types()

            # Credit card -> financial_payment
            # CUSIP -> financial_securities
            # Bitcoin -> cryptocurrency
            assert any("CREDIT_CARD" in types for types in categories.values())
            assert any("CUSIP" in types for types in categories.values())

    def test_categorize_uncategorized_to_fallback(self):
        """Uncategorized types should go to a fallback category."""
        from scrubiq.api.settings import _categorize_entity_types

        with patch("scrubiq.api.settings.KNOWN_ENTITY_TYPES", {"COMPLETELY_UNKNOWN_TYPE"}):
            categories = _categorize_entity_types()

            # Unknown types go to 'contact' category as the default fallback
            found = False
            for category, types in categories.items():
                if "COMPLETELY_UNKNOWN_TYPE" in types:
                    found = True
                    break
            assert found, f"COMPLETELY_UNKNOWN_TYPE not found in any category: {categories}"

    def test_empty_categories_excluded(self):
        """Empty categories should not be included."""
        from scrubiq.api.settings import _categorize_entity_types

        with patch("scrubiq.api.settings.KNOWN_ENTITY_TYPES", {"NAME"}):
            categories = _categorize_entity_types()

            # Should not have empty categories
            for category, types in categories.items():
                assert len(types) > 0


# --- Rate Limiting Tests ---

class TestSettingsRateLimiting:
    """Tests for settings route rate limiting."""

    def test_get_settings_calls_rate_limit(self, mock_credential_result):
        """GET /settings should check rate limit."""
        from scrubiq.api.settings import router

        app = FastAPI()
        app.include_router(router)

        def override_require_api_key():
            return mock_credential_result

        with patch("scrubiq.api.settings.check_rate_limit") as mock_rate_limit:
            from scrubiq.api.dependencies import require_api_key
            app.dependency_overrides[require_api_key] = override_require_api_key

            client = TestClient(app)
            client.get("/settings")

            mock_rate_limit.assert_called_once()
            call_kwargs = mock_rate_limit.call_args
            assert call_kwargs[1]["action"] == "settings_read"

    def test_put_settings_calls_write_rate_limit(self, mock_credential_result):
        """PUT /settings should check write rate limit."""
        from scrubiq.api.settings import router

        app = FastAPI()
        app.include_router(router)

        def override_require_api_key():
            return mock_credential_result

        with patch("scrubiq.api.settings.check_rate_limit") as mock_rate_limit:
            from scrubiq.api.dependencies import require_api_key
            app.dependency_overrides[require_api_key] = override_require_api_key

            client = TestClient(app)
            client.put("/settings", json={"confidence_threshold": 0.9})

            # Should have at least one call with 'settings_write' action
            # (may also have 'settings_read' call for return value)
            assert mock_rate_limit.call_count >= 1
            write_calls = [
                call for call in mock_rate_limit.call_args_list
                if call[1].get("action") == "settings_write"
            ]
            assert len(write_calls) >= 1
