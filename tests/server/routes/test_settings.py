"""
Comprehensive tests for settings API endpoints.

Tests focus on:
- Azure AD configuration updates
- Scan configuration updates
- Entity detection configuration
- Settings reset functionality
- Authentication requirements
- HTMX response headers
"""

import pytest


class TestUpdateAzureSettings:
    """Tests for POST /api/settings/azure endpoint."""

    async def test_update_azure_settings_returns_htmx_trigger(self, test_client):
        """Azure settings update should return empty HTML body with HX-Trigger header."""
        response = await test_client.post(
            "/api/settings/azure",
            data={
                "tenant_id": "test-tenant-123",
                "client_id": "test-client-456",
                "client_secret": "test-secret-789",
            },
        )
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert response.text == ""
        assert "HX-Trigger" in response.headers
        assert "Azure settings updated" in response.headers["HX-Trigger"]
        assert "success" in response.headers["HX-Trigger"]

    async def test_update_azure_settings_with_empty_secret(self, test_client):
        """Azure settings update with empty secret should still succeed with HTMX trigger."""
        response = await test_client.post(
            "/api/settings/azure",
            data={
                "tenant_id": "test-tenant-123",
                "client_id": "test-client-456",
                "client_secret": "",
            },
        )
        assert response.status_code == 200
        assert "HX-Trigger" in response.headers
        assert "Azure settings updated" in response.headers["HX-Trigger"]

    async def test_update_azure_settings_with_defaults(self, test_client):
        """Azure settings update with no data should succeed with HTMX trigger."""
        response = await test_client.post(
            "/api/settings/azure",
            data={},
        )
        assert response.status_code == 200
        assert "HX-Trigger" in response.headers
        assert "Azure settings updated" in response.headers["HX-Trigger"]


class TestUpdateScanSettings:
    """Tests for POST /api/settings/scan endpoint."""

    async def test_update_scan_settings_returns_htmx_trigger(self, test_client):
        """Scan settings update should return HX-Trigger header."""
        response = await test_client.post(
            "/api/settings/scan",
            data={
                "max_file_size_mb": "100",
                "concurrent_files": "10",
            },
        )
        assert response.status_code == 200
        assert response.text == ""
        assert "HX-Trigger" in response.headers
        assert "Scan settings updated" in response.headers["HX-Trigger"]
        assert "success" in response.headers["HX-Trigger"]

    async def test_update_scan_settings_with_ocr_enabled(self, test_client):
        """Scan settings update with OCR enabled should return HTMX trigger."""
        response = await test_client.post(
            "/api/settings/scan",
            data={
                "max_file_size_mb": "100",
                "concurrent_files": "10",
                "enable_ocr": "on",
            },
        )
        assert response.status_code == 200
        assert "HX-Trigger" in response.headers
        assert "Scan settings updated" in response.headers["HX-Trigger"]

    async def test_update_scan_settings_with_defaults(self, test_client):
        """Scan settings update with no data should use defaults and return HTMX trigger."""
        response = await test_client.post(
            "/api/settings/scan",
            data={},
        )
        assert response.status_code == 200
        assert "HX-Trigger" in response.headers
        assert "Scan settings updated" in response.headers["HX-Trigger"]



class TestUpdateEntitySettings:
    """Tests for POST /api/settings/entities endpoint."""

    async def test_update_entity_settings_returns_htmx_trigger(self, test_client):
        """Entity settings update should return HX-Trigger header."""
        response = await test_client.post(
            "/api/settings/entities",
            data={
                "entities": ["SSN"],
            },
        )
        assert response.status_code == 200
        assert response.text == ""
        assert "HX-Trigger" in response.headers
        assert "Entity detection settings updated" in response.headers["HX-Trigger"]
        assert "success" in response.headers["HX-Trigger"]

    async def test_update_entity_settings_with_empty_list(self, test_client):
        """Entity settings update with empty list should still return HTMX trigger."""
        response = await test_client.post(
            "/api/settings/entities",
            data={},
        )
        assert response.status_code == 200
        assert "HX-Trigger" in response.headers
        assert "Entity detection settings updated" in response.headers["HX-Trigger"]



class TestResetSettings:
    """Tests for POST /api/settings/reset endpoint."""

    async def test_reset_settings_returns_htmx_trigger(self, test_client):
        """Settings reset should return empty HTML body with HX-Trigger header."""
        response = await test_client.post("/api/settings/reset")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert response.text == ""
        assert "HX-Trigger" in response.headers
        assert "Settings reset to defaults" in response.headers["HX-Trigger"]
        assert "success" in response.headers["HX-Trigger"]



class TestSettingsResponseFormat:
    """Tests for settings response format consistency."""

    async def test_all_settings_return_empty_content(self, test_client):
        """All settings endpoints should return empty content body."""
        # Azure settings
        response = await test_client.post(
            "/api/settings/azure",
            data={"tenant_id": "test", "client_id": "test"},
        )
        assert response.status_code == 200
        assert response.text == ""

        # Scan settings
        response = await test_client.post(
            "/api/settings/scan",
            data={"max_file_size_mb": "100", "concurrent_files": "10"},
        )
        assert response.status_code == 200
        assert response.text == ""

        # Entity settings
        response = await test_client.post(
            "/api/settings/entities",
            data={},
        )
        assert response.status_code == 200
        assert response.text == ""

        # Reset
        response = await test_client.post("/api/settings/reset")
        assert response.status_code == 200
        assert response.text == ""

    async def test_htmx_trigger_contains_notify_event(self, test_client):
        """HX-Trigger should contain notify event with message and type."""
        response = await test_client.post("/api/settings/reset")
        assert response.status_code == 200

        trigger = response.headers.get("HX-Trigger", "")
        assert "notify" in trigger
        assert "message" in trigger
        assert "type" in trigger
