"""Tests for configuration management routes.

Tests configuration CRUD and import/export endpoints.

Note: These tests require SQLCipher and FastAPI to be installed.
"""

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

try:
    from scrubiq.api.routes import config as routes_config
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
def mock_setting_metadata():
    """Create mock setting metadata."""
    meta = MagicMock()
    meta.key = "detection.min_confidence"
    meta.category = MagicMock()
    meta.category.value = "detection"
    meta.description = "Minimum confidence threshold"
    meta.value_type = "float"
    meta.default = 0.8
    meta.current = 0.9
    meta.allowed_values = None
    meta.min_value = 0.0
    meta.max_value = 1.0
    meta.requires_restart = False
    meta.runtime_editable = True
    return meta


@pytest.fixture
def mock_config_provider(mock_setting_metadata):
    """Create mock config provider."""
    mock = MagicMock()

    mock.get_all_with_metadata.return_value = {
        "detection.min_confidence": {
            "category": "detection",
            "description": "Minimum confidence threshold",
            "type": "float",
            "default": 0.8,
            "current": 0.9,
            "allowed_values": None,
            "min_value": 0.0,
            "max_value": 1.0,
            "requires_restart": False,
            "runtime_editable": True,
        },
    }

    mock.get_categories.return_value = ["detection", "llm", "storage"]
    mock.get_metadata.return_value = mock_setting_metadata
    mock.export_to_dict.return_value = {"detection.min_confidence": 0.9}

    return mock


@pytest.fixture
def mock_scrubiq():
    """Create mock ScrubIQ instance."""
    return MagicMock()


@pytest.fixture
def client(mock_scrubiq, mock_config_provider):
    """Create test client with mocked dependencies."""
    from scrubiq.api.routes.config import router, init_config_provider
    from scrubiq.api.dependencies import require_unlocked
    from scrubiq.api.errors import register_error_handlers

    app = FastAPI()
    app.include_router(router)
    register_error_handlers(app)

    app.dependency_overrides[require_unlocked] = lambda: mock_scrubiq

    with patch("scrubiq.api.routes.config.get_config_provider", return_value=mock_config_provider):
        with patch("scrubiq.api.routes.config.check_rate_limit"):
            yield TestClient(app, raise_server_exceptions=False)


# =============================================================================
# LIST SETTINGS TESTS
# =============================================================================

class TestListSettings:
    """Tests for GET /config endpoint."""

    def test_list_success(self, client, mock_config_provider):
        """List settings returns all settings."""
        response = client.get("/config")

        assert response.status_code == 200
        data = response.json()
        assert "detection.min_confidence" in data

    def test_list_setting_structure(self, client):
        """Listed settings have correct structure."""
        response = client.get("/config")

        assert response.status_code == 200
        setting = response.json()["detection.min_confidence"]
        assert setting["key"] == "detection.min_confidence"
        assert setting["category"] == "detection"
        assert setting["type"] == "float"
        assert "default" in setting
        assert "current" in setting
        assert "requires_restart" in setting
        assert "runtime_editable" in setting

    def test_list_filter_by_category(self, client, mock_config_provider):
        """List settings can filter by category."""
        response = client.get("/config?category=detection")

        assert response.status_code == 200
        # All settings should be in detection category
        for key, setting in response.json().items():
            assert setting["category"] == "detection"

    def test_list_invalid_category(self, client, mock_config_provider):
        """List settings returns 400 for invalid category."""
        from scrubiq.services import SettingCategory

        # Mock SettingCategory to raise ValueError
        with patch("scrubiq.api.routes.config.SettingCategory", side_effect=ValueError):
            response = client.get("/config?category=invalid")

        assert response.status_code == 400


# =============================================================================
# LIST CATEGORIES TESTS
# =============================================================================

class TestListCategories:
    """Tests for GET /config/categories endpoint."""

    def test_list_categories_success(self, client, mock_config_provider):
        """List categories returns category list."""
        response = client.get("/config/categories")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert "detection" in data
        assert "llm" in data


# =============================================================================
# GET SETTING TESTS
# =============================================================================

class TestGetSetting:
    """Tests for GET /config/{key} endpoint."""

    def test_get_success(self, client, mock_config_provider):
        """Get setting returns setting details."""
        response = client.get("/config/detection.min_confidence")

        assert response.status_code == 200
        data = response.json()
        assert data["key"] == "detection.min_confidence"
        assert data["current"] == 0.9

    def test_get_not_found(self, client, mock_config_provider):
        """Get setting returns 404 for unknown key."""
        mock_config_provider.get_metadata.return_value = None

        response = client.get("/config/unknown.setting")

        assert response.status_code == 404

    def test_get_nested_key(self, client, mock_config_provider):
        """Get setting supports dot notation keys."""
        response = client.get("/config/detection.min_confidence")

        assert response.status_code == 200
        mock_config_provider.get_metadata.assert_called()


# =============================================================================
# UPDATE SETTING TESTS
# =============================================================================

class TestUpdateSetting:
    """Tests for PUT /config/{key} endpoint."""

    def test_update_success(self, client, mock_config_provider):
        """Update setting succeeds."""
        response = client.put(
            "/config/detection.min_confidence",
            json={"value": 0.85},
        )

        assert response.status_code == 200
        mock_config_provider.set.assert_called_once_with("detection.min_confidence", 0.85)

    def test_update_returns_updated_setting(self, client, mock_config_provider):
        """Update returns updated setting metadata."""
        response = client.put(
            "/config/detection.min_confidence",
            json={"value": 0.85},
        )

        assert response.status_code == 200
        data = response.json()
        assert "key" in data
        assert "current" in data

    def test_update_not_found(self, client, mock_config_provider):
        """Update returns 404 for unknown key."""
        mock_config_provider.get_metadata.return_value = None

        response = client.put("/config/unknown.setting", json={"value": 1})

        assert response.status_code == 404

    def test_update_runtime_error(self, client, mock_config_provider):
        """Update returns 400 for runtime error."""
        mock_config_provider.set.side_effect = RuntimeError("Not editable")

        response = client.put(
            "/config/detection.min_confidence",
            json={"value": 0.5},
        )

        assert response.status_code == 400

    def test_update_validation_error(self, client, mock_config_provider):
        """Update returns 400 for validation error."""
        mock_config_provider.set.side_effect = ValueError("Value out of range")

        response = client.put(
            "/config/detection.min_confidence",
            json={"value": 99.9},
        )

        assert response.status_code == 400


# =============================================================================
# EXPORT CONFIG TESTS
# =============================================================================

class TestExportConfig:
    """Tests for GET /config/export endpoint."""

    def test_export_success(self, client, mock_config_provider):
        """Export returns all settings."""
        response = client.get("/config/export")

        assert response.status_code == 200
        data = response.json()
        assert "settings" in data
        assert "detection.min_confidence" in data["settings"]

    def test_export_calls_provider(self, client, mock_config_provider):
        """Export calls config provider export."""
        client.get("/config/export")

        mock_config_provider.export_to_dict.assert_called_once()


# =============================================================================
# IMPORT CONFIG TESTS
# =============================================================================

class TestImportConfig:
    """Tests for POST /config/import endpoint."""

    def test_import_success(self, client, mock_config_provider):
        """Import updates settings."""
        response = client.post(
            "/config/import",
            json={"settings": {"detection.min_confidence": 0.95}},
        )

        assert response.status_code == 200
        data = response.json()
        assert "updated" in data
        assert "failed" in data

    def test_import_returns_updated_list(self, client, mock_config_provider):
        """Import returns list of updated keys."""
        response = client.post(
            "/config/import",
            json={"settings": {"detection.min_confidence": 0.95}},
        )

        assert response.status_code == 200
        assert "detection.min_confidence" in response.json()["updated"]

    def test_import_handles_failures(self, client, mock_config_provider):
        """Import reports failed settings."""
        mock_config_provider.set.side_effect = ValueError("Invalid")

        response = client.post(
            "/config/import",
            json={"settings": {"bad.setting": "value"}},
        )

        assert response.status_code == 200
        assert "bad.setting" in response.json()["failed"]


# =============================================================================
# RESET SETTING TESTS
# =============================================================================

class TestResetSetting:
    """Tests for POST /config/reset/{key} endpoint."""

    def test_reset_success(self, client, mock_config_provider, mock_setting_metadata):
        """Reset setting to default succeeds."""
        response = client.post("/config/reset/detection.min_confidence")

        assert response.status_code == 200
        # Should set to default value
        mock_config_provider.set.assert_called_once_with(
            "detection.min_confidence",
            mock_setting_metadata.default,
        )

    def test_reset_not_found(self, client, mock_config_provider):
        """Reset returns 404 for unknown key."""
        mock_config_provider.get_metadata.return_value = None

        response = client.post("/config/reset/unknown.setting")

        assert response.status_code == 404

    def test_reset_returns_updated_setting(self, client, mock_config_provider):
        """Reset returns updated setting metadata."""
        response = client.post("/config/reset/detection.min_confidence")

        assert response.status_code == 200
        data = response.json()
        assert "key" in data
        assert "default" in data
