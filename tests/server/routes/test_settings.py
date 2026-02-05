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
from unittest.mock import patch


class TestUpdateAzureSettings:
    """Tests for POST /api/settings/azure endpoint."""

    async def test_update_azure_settings_returns_200(self, test_client):
        """Azure settings update should return 200 with success trigger."""
        response = await test_client.post(
            "/api/settings/azure",
            data={
                "tenant_id": "test-tenant-123",
                "client_id": "test-client-456",
                "client_secret": "test-secret-789",
            },
        )
        assert response.status_code == 200

    async def test_update_azure_settings_returns_htmx_trigger(self, test_client):
        """Azure settings update should return HX-Trigger header."""
        response = await test_client.post(
            "/api/settings/azure",
            data={
                "tenant_id": "test-tenant-123",
                "client_id": "test-client-456",
                "client_secret": "test-secret-789",
            },
        )
        assert response.status_code == 200
        assert "HX-Trigger" in response.headers
        assert "Azure settings updated" in response.headers["HX-Trigger"]
        assert "success" in response.headers["HX-Trigger"]

    async def test_update_azure_settings_with_empty_secret(self, test_client):
        """Azure settings update should work with empty secret (no change)."""
        response = await test_client.post(
            "/api/settings/azure",
            data={
                "tenant_id": "test-tenant-123",
                "client_id": "test-client-456",
                "client_secret": "",
            },
        )
        assert response.status_code == 200

    async def test_update_azure_settings_with_defaults(self, test_client):
        """Azure settings update should work with default empty values."""
        response = await test_client.post(
            "/api/settings/azure",
            data={},
        )
        assert response.status_code == 200

    async def test_update_azure_settings_returns_html_response(self, test_client):
        """Azure settings update should return HTML response type."""
        response = await test_client.post(
            "/api/settings/azure",
            data={
                "tenant_id": "test-tenant",
                "client_id": "test-client",
            },
        )
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")


class TestUpdateScanSettings:
    """Tests for POST /api/settings/scan endpoint."""

    async def test_update_scan_settings_returns_200(self, test_client):
        """Scan settings update should return 200."""
        response = await test_client.post(
            "/api/settings/scan",
            data={
                "max_file_size_mb": "50",
                "concurrent_files": "5",
            },
        )
        assert response.status_code == 200

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
        assert "HX-Trigger" in response.headers
        assert "Scan settings updated" in response.headers["HX-Trigger"]
        assert "success" in response.headers["HX-Trigger"]

    async def test_update_scan_settings_with_ocr_enabled(self, test_client):
        """Scan settings update should handle OCR checkbox enabled."""
        response = await test_client.post(
            "/api/settings/scan",
            data={
                "max_file_size_mb": "100",
                "concurrent_files": "10",
                "enable_ocr": "on",
            },
        )
        assert response.status_code == 200

    async def test_update_scan_settings_with_ocr_disabled(self, test_client):
        """Scan settings update should handle OCR checkbox disabled (not sent)."""
        response = await test_client.post(
            "/api/settings/scan",
            data={
                "max_file_size_mb": "100",
                "concurrent_files": "10",
            },
        )
        assert response.status_code == 200

    async def test_update_scan_settings_with_defaults(self, test_client):
        """Scan settings update should work with default values."""
        response = await test_client.post(
            "/api/settings/scan",
            data={},
        )
        assert response.status_code == 200

    async def test_update_scan_settings_with_large_file_size(self, test_client):
        """Scan settings update should accept large file size limits."""
        response = await test_client.post(
            "/api/settings/scan",
            data={
                "max_file_size_mb": "1000",
                "concurrent_files": "50",
            },
        )
        assert response.status_code == 200

    async def test_update_scan_settings_with_small_values(self, test_client):
        """Scan settings update should accept small values."""
        response = await test_client.post(
            "/api/settings/scan",
            data={
                "max_file_size_mb": "1",
                "concurrent_files": "1",
            },
        )
        assert response.status_code == 200


class TestUpdateEntitySettings:
    """Tests for POST /api/settings/entities endpoint."""

    async def test_update_entity_settings_returns_200(self, test_client):
        """Entity settings update should return 200."""
        response = await test_client.post(
            "/api/settings/entities",
            data={
                "entities": ["SSN", "CREDIT_CARD", "EMAIL"],
            },
        )
        assert response.status_code == 200

    async def test_update_entity_settings_returns_htmx_trigger(self, test_client):
        """Entity settings update should return HX-Trigger header."""
        response = await test_client.post(
            "/api/settings/entities",
            data={
                "entities": ["SSN"],
            },
        )
        assert response.status_code == 200
        assert "HX-Trigger" in response.headers
        assert "Entity detection settings updated" in response.headers["HX-Trigger"]
        assert "success" in response.headers["HX-Trigger"]

    async def test_update_entity_settings_with_empty_list(self, test_client):
        """Entity settings update should accept empty entity list."""
        response = await test_client.post(
            "/api/settings/entities",
            data={},
        )
        assert response.status_code == 200

    async def test_update_entity_settings_with_multiple_entities(self, test_client):
        """Entity settings update should accept multiple entities."""
        response = await test_client.post(
            "/api/settings/entities",
            data={
                "entities": [
                    "SSN",
                    "CREDIT_CARD",
                    "EMAIL",
                    "PHONE",
                    "ADDRESS",
                    "NAME",
                ],
            },
        )
        assert response.status_code == 200


class TestResetSettings:
    """Tests for POST /api/settings/reset endpoint."""

    async def test_reset_settings_returns_200(self, test_client):
        """Settings reset should return 200."""
        response = await test_client.post("/api/settings/reset")
        assert response.status_code == 200

    async def test_reset_settings_returns_htmx_trigger(self, test_client):
        """Settings reset should return HX-Trigger header."""
        response = await test_client.post("/api/settings/reset")
        assert response.status_code == 200
        assert "HX-Trigger" in response.headers
        assert "Settings reset to defaults" in response.headers["HX-Trigger"]
        assert "success" in response.headers["HX-Trigger"]

    async def test_reset_settings_returns_html_response(self, test_client):
        """Settings reset should return HTML response type."""
        response = await test_client.post("/api/settings/reset")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")


class TestSettingsAuthentication:
    """Tests for authentication requirements on settings endpoints."""

    async def test_azure_settings_accessible_when_authenticated(self, test_client):
        """Azure settings endpoint should succeed with authenticated user."""
        # test_client fixture provides authenticated admin user
        response = await test_client.post(
            "/api/settings/azure",
            data={"tenant_id": "test", "client_id": "test"},
        )
        assert response.status_code == 200, \
            f"Expected 200 for authenticated settings request, got {response.status_code}"

    async def test_scan_settings_accessible_when_authenticated(self, test_client):
        """Scan settings endpoint should succeed with authenticated user."""
        response = await test_client.post(
            "/api/settings/scan",
            data={"max_file_size_mb": "100", "concurrent_files": "10"},
        )
        assert response.status_code == 200, \
            f"Expected 200 for authenticated settings request, got {response.status_code}"

    async def test_entity_settings_accessible_when_authenticated(self, test_client):
        """Entity settings endpoint should succeed with authenticated user."""
        response = await test_client.post(
            "/api/settings/entities",
            data={"entities": ["SSN"]},
        )
        assert response.status_code == 200, \
            f"Expected 200 for authenticated settings request, got {response.status_code}"

    async def test_reset_settings_accessible_when_authenticated(self, test_client):
        """Settings reset endpoint should succeed with authenticated user."""
        response = await test_client.post("/api/settings/reset")
        assert response.status_code == 200, \
            f"Expected 200 for authenticated settings request, got {response.status_code}"


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
