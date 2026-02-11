"""
Tests for SIEM export API endpoints.

Tests focus on:
- Trigger SIEM export
- Test SIEM connections
- Get SIEM status
- Error handling when SIEM is disabled
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestTriggerSIEMExport:
    """Tests for POST /api/v1/export/siem endpoint."""

    async def test_returns_400_when_siem_disabled(self, test_client, test_db):
        """Should return 400 when SIEM export is not enabled."""
        mock_settings = MagicMock()
        mock_settings.siem_export.enabled = False

        with patch("openlabels.server.routes.export.get_settings", return_value=mock_settings):
            response = await test_client.post(
                "/api/v1/export/siem",
                json={},
            )
        assert response.status_code == 400
        assert "not enabled" in response.json()["message"]

    async def test_returns_404_for_unknown_adapter(self, test_client, test_db):
        """Should return 404 when specified adapter is not configured."""
        mock_settings = MagicMock()
        mock_settings.siem_export.enabled = True

        mock_adapters = [MagicMock()]
        mock_adapters[0].format_name.return_value = "splunk"

        with patch("openlabels.server.routes.export.get_settings", return_value=mock_settings), \
             patch("openlabels.export.setup.build_adapters_from_settings", return_value=mock_adapters):
            response = await test_client.post(
                "/api/v1/export/siem",
                json={"adapter": "nonexistent"},
            )

        assert response.status_code == 404
        assert "not configured" in response.json()["message"]

    async def test_returns_export_response_structure(self, test_client, test_db):
        """Should return exported counts, total_records, and adapters."""
        mock_settings = MagicMock()
        mock_settings.siem_export.enabled = True
        mock_settings.siem_export.export_record_types = None
        mock_settings.siem_export.mode = "batch"

        mock_engine = AsyncMock()
        mock_engine.export_full = AsyncMock(return_value={"splunk": 5})
        mock_engine.adapter_names = ["splunk"]

        mock_adapters = [MagicMock()]
        mock_adapters[0].format_name.return_value = "splunk"

        with patch("openlabels.server.routes.export.get_settings", return_value=mock_settings), \
             patch("openlabels.export.setup.build_adapters_from_settings", return_value=mock_adapters), \
             patch("openlabels.export.engine.ExportEngine", return_value=mock_engine), \
             patch("openlabels.export.engine.scan_result_to_export_records", return_value=[]), \
             patch("openlabels.server.db.get_session_context") as mock_ctx:
            # Mock the async context manager for DB session
            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = []
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            response = await test_client.post(
                "/api/v1/export/siem",
                json={},
            )

        assert response.status_code == 200
        data = response.json()
        assert "exported" in data
        assert "total_records" in data
        assert "adapters" in data


class TestTestSIEMConnections:
    """Tests for POST /api/v1/export/siem/test endpoint."""

    async def test_returns_400_when_siem_disabled(self, test_client, test_db):
        """Should return 400 when SIEM export is not enabled."""
        mock_settings = MagicMock()
        mock_settings.siem_export.enabled = False

        with patch("openlabels.server.routes.export.get_settings", return_value=mock_settings):
            response = await test_client.post("/api/v1/export/siem/test")

        assert response.status_code == 400
        assert "not enabled" in response.json()["message"]

    async def test_returns_400_when_no_adapters(self, test_client, test_db):
        """Should return 400 when no SIEM adapters are configured."""
        mock_settings = MagicMock()
        mock_settings.siem_export.enabled = True

        with patch("openlabels.server.routes.export.get_settings", return_value=mock_settings), \
             patch("openlabels.export.setup.build_adapters_from_settings", return_value=[]):
            response = await test_client.post("/api/v1/export/siem/test")

        assert response.status_code == 400
        assert "No SIEM adapters" in response.json()["message"]

    async def test_returns_connection_results(self, test_client, test_db):
        """Should return test results for each adapter."""
        mock_settings = MagicMock()
        mock_settings.siem_export.enabled = True

        mock_engine = AsyncMock()
        mock_engine.test_connections = AsyncMock(return_value={"splunk": True})

        mock_adapters = [MagicMock()]

        with patch("openlabels.server.routes.export.get_settings", return_value=mock_settings), \
             patch("openlabels.export.setup.build_adapters_from_settings", return_value=mock_adapters), \
             patch("openlabels.export.engine.ExportEngine", return_value=mock_engine):
            response = await test_client.post("/api/v1/export/siem/test")

        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        assert data["results"]["splunk"] is True


class TestSIEMExportStatus:
    """Tests for GET /api/v1/export/siem/status endpoint."""

    async def test_returns_status_when_disabled(self, test_client, test_db):
        """Should return status with enabled=false."""
        mock_settings = MagicMock()
        mock_settings.siem_export.enabled = False
        mock_settings.siem_export.mode = "batch"

        with patch("openlabels.server.routes.export.get_settings", return_value=mock_settings), \
             patch("openlabels.export.setup.build_adapters_from_settings", return_value=[]):
            response = await test_client.get("/api/v1/export/siem/status")

        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is False
        assert data["mode"] == "batch"
        assert data["adapters"] == []
        assert "cursors" in data

    async def test_returns_status_with_adapters(self, test_client, test_db):
        """Should list configured adapter names."""
        mock_settings = MagicMock()
        mock_settings.siem_export.enabled = True
        mock_settings.siem_export.mode = "streaming"

        mock_adapter = MagicMock()
        mock_adapter.format_name.return_value = "splunk_hec"

        with patch("openlabels.server.routes.export.get_settings", return_value=mock_settings), \
             patch("openlabels.export.setup.build_adapters_from_settings", return_value=[mock_adapter]):
            response = await test_client.get("/api/v1/export/siem/status")

        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True
        assert data["mode"] == "streaming"
        assert "splunk_hec" in data["adapters"]
