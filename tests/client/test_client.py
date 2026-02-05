"""
Comprehensive tests for OpenLabels Python SDK client.

Tests cover API client initialization, authentication, request construction,
response handling, and error cases.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from openlabels.client.client import OpenLabelsClient


class TestClientInitialization:
    """Tests for client initialization."""

    def test_default_base_url(self):
        """Default base_url should be localhost:8000."""
        client = OpenLabelsClient()
        assert client.base_url == "http://localhost:8000"

    def test_custom_base_url(self):
        """Custom base_url should be accepted."""
        client = OpenLabelsClient("https://api.example.com")
        assert client.base_url == "https://api.example.com"

    def test_base_url_trailing_slash_stripped(self):
        """Trailing slash should be stripped from base_url."""
        client = OpenLabelsClient("https://api.example.com/")
        assert client.base_url == "https://api.example.com"

    def test_multiple_trailing_slashes_handled(self):
        """Multiple trailing slashes should be handled."""
        client = OpenLabelsClient("https://api.example.com///")
        # rstrip('/') removes all trailing slashes
        assert not client.base_url.endswith("/")

    def test_token_stored(self):
        """Token should be stored."""
        client = OpenLabelsClient(token="test-token")
        assert client.token == "test-token"

    def test_no_token_by_default(self):
        """No token by default."""
        client = OpenLabelsClient()
        assert client.token is None


class TestHeaders:
    """Tests for request header generation."""

    def test_headers_without_token(self):
        """Headers without token should only have Content-Type."""
        client = OpenLabelsClient()
        headers = client._headers()
        assert headers["Content-Type"] == "application/json"
        assert "Authorization" not in headers

    def test_headers_with_token(self):
        """Headers with token should include Authorization."""
        client = OpenLabelsClient(token="my-token")
        headers = client._headers()
        assert headers["Content-Type"] == "application/json"
        assert headers["Authorization"] == "Bearer my-token"

    def test_empty_token_treated_as_none(self):
        """Empty string token should not add Authorization header."""
        client = OpenLabelsClient(token="")
        headers = client._headers()
        # Empty string is falsy, so no Authorization header
        assert "Authorization" not in headers


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Successful health check."""
        client = OpenLabelsClient("http://test")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {"status": "healthy"}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            result = await client.health()

            assert result == {"status": "healthy"}
            mock_instance.get.assert_called_once()
            call_kwargs = mock_instance.get.call_args
            assert "http://test/health" in str(call_kwargs)

    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        """Health check with server error."""
        client = OpenLabelsClient("http://test")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Server Error",
                request=MagicMock(),
                response=MagicMock(status_code=500),
            )

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            with pytest.raises(httpx.HTTPStatusError):
                await client.health()


class TestScansEndpoints:
    """Tests for scan-related endpoints."""

    @pytest.mark.asyncio
    async def test_create_scan(self):
        """Create scan should POST to /api/scans."""
        client = OpenLabelsClient("http://test", token="test-token")
        target_id = uuid4()

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {"id": str(uuid4()), "status": "pending"}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            result = await client.create_scan(target_id, name="Test Scan")

            mock_instance.post.assert_called_once()
            call_kwargs = mock_instance.post.call_args
            assert "http://test/api/v1/scans" in str(call_kwargs)
            # Verify JSON body
            json_body = call_kwargs[1]["json"]
            assert json_body["target_id"] == str(target_id)
            assert json_body["name"] == "Test Scan"

    @pytest.mark.asyncio
    async def test_create_scan_includes_auth_header(self):
        """Create scan should include Authorization header."""
        client = OpenLabelsClient("http://test", token="secret-token")
        target_id = uuid4()

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            await client.create_scan(target_id)

            call_kwargs = mock_instance.post.call_args
            headers = call_kwargs[1]["headers"]
            assert headers["Authorization"] == "Bearer secret-token"

    @pytest.mark.asyncio
    async def test_list_scans_default_params(self):
        """List scans with default parameters."""
        client = OpenLabelsClient("http://test")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {"items": [], "total": 0}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            result = await client.list_scans()

            call_kwargs = mock_instance.get.call_args
            params = call_kwargs[1]["params"]
            assert params["page"] == 1
            assert params["limit"] == 50
            assert "status" not in params

    @pytest.mark.asyncio
    async def test_list_scans_with_filters(self):
        """List scans with status filter."""
        client = OpenLabelsClient("http://test")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {"items": [], "total": 0}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            await client.list_scans(status="running", page=2, limit=10)

            call_kwargs = mock_instance.get.call_args
            params = call_kwargs[1]["params"]
            assert params["status"] == "running"
            assert params["page"] == 2
            assert params["limit"] == 10

    @pytest.mark.asyncio
    async def test_get_scan(self):
        """Get scan by ID."""
        client = OpenLabelsClient("http://test")
        scan_id = uuid4()

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {"id": str(scan_id), "status": "completed"}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            result = await client.get_scan(scan_id)

            mock_instance.get.assert_called_once()
            assert f"/api/v1/scans/{scan_id}" in str(mock_instance.get.call_args)

    @pytest.mark.asyncio
    async def test_cancel_scan(self):
        """Cancel scan should DELETE."""
        client = OpenLabelsClient("http://test")
        scan_id = uuid4()

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.delete.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            await client.cancel_scan(scan_id)

            mock_instance.delete.assert_called_once()
            assert f"/api/v1/scans/{scan_id}" in str(mock_instance.delete.call_args)


class TestResultsEndpoints:
    """Tests for results endpoints."""

    @pytest.mark.asyncio
    async def test_list_results_default(self):
        """List results with defaults."""
        client = OpenLabelsClient("http://test")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {"items": []}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            await client.list_results()

            call_kwargs = mock_instance.get.call_args
            assert "/api/v1/results" in str(call_kwargs)

    @pytest.mark.asyncio
    async def test_list_results_with_filters(self):
        """List results with job_id and risk_tier filters."""
        client = OpenLabelsClient("http://test")
        job_id = uuid4()

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {"items": []}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            await client.list_results(job_id=job_id, risk_tier="HIGH")

            call_kwargs = mock_instance.get.call_args
            params = call_kwargs[1]["params"]
            assert params["job_id"] == str(job_id)
            assert params["risk_tier"] == "HIGH"

    @pytest.mark.asyncio
    async def test_get_result(self):
        """Get result by ID."""
        client = OpenLabelsClient("http://test")
        result_id = uuid4()

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {"id": str(result_id)}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            await client.get_result(result_id)

            assert f"/api/v1/results/{result_id}" in str(mock_instance.get.call_args)

    @pytest.mark.asyncio
    async def test_get_result_stats(self):
        """Get result statistics."""
        client = OpenLabelsClient("http://test")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {"total": 100, "by_tier": {}}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            await client.get_result_stats()

            assert "/api/v1/results/stats" in str(mock_instance.get.call_args)

    @pytest.mark.asyncio
    async def test_get_result_stats_with_job_filter(self):
        """Get result statistics filtered by job."""
        client = OpenLabelsClient("http://test")
        job_id = uuid4()

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            await client.get_result_stats(job_id=job_id)

            call_kwargs = mock_instance.get.call_args
            params = call_kwargs[1]["params"]
            assert params["job_id"] == str(job_id)


class TestTargetsEndpoints:
    """Tests for targets endpoints."""

    @pytest.mark.asyncio
    async def test_list_targets(self):
        """List targets."""
        client = OpenLabelsClient("http://test")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = [{"id": "1", "name": "Target 1"}]
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            result = await client.list_targets()

            assert "/api/v1/targets" in str(mock_instance.get.call_args)

    @pytest.mark.asyncio
    async def test_list_targets_with_adapter_filter(self):
        """List targets filtered by adapter type."""
        client = OpenLabelsClient("http://test")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = []
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            await client.list_targets(adapter="sharepoint")

            call_kwargs = mock_instance.get.call_args
            params = call_kwargs[1]["params"]
            assert params["adapter"] == "sharepoint"

    @pytest.mark.asyncio
    async def test_create_target(self):
        """Create target."""
        client = OpenLabelsClient("http://test", token="token")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {"id": "new-id"}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            result = await client.create_target(
                name="My Target",
                adapter="filesystem",
                config={"path": "/data"},
            )

            call_kwargs = mock_instance.post.call_args
            json_body = call_kwargs[1]["json"]
            assert json_body["name"] == "My Target"
            assert json_body["adapter"] == "filesystem"
            assert json_body["config"] == {"path": "/data"}


class TestDashboardEndpoints:
    """Tests for dashboard endpoints."""

    @pytest.mark.asyncio
    async def test_get_dashboard_stats(self):
        """Get dashboard statistics."""
        client = OpenLabelsClient("http://test")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {"total_files": 1000}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            result = await client.get_dashboard_stats()

            assert "/api/v1/dashboard/stats" in str(mock_instance.get.call_args)

    @pytest.mark.asyncio
    async def test_get_heatmap(self):
        """Get heatmap data."""
        client = OpenLabelsClient("http://test")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {"data": []}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            await client.get_heatmap()

            assert "/api/v1/dashboard/heatmap" in str(mock_instance.get.call_args)

    @pytest.mark.asyncio
    async def test_get_heatmap_with_job_filter(self):
        """Get heatmap filtered by job."""
        client = OpenLabelsClient("http://test")
        job_id = uuid4()

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = {}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            await client.get_heatmap(job_id=job_id)

            call_kwargs = mock_instance.get.call_args
            params = call_kwargs[1]["params"]
            assert params["job_id"] == str(job_id)


class TestErrorHandling:
    """Tests for error handling."""

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        """401 error should raise HTTPStatusError."""
        client = OpenLabelsClient("http://test")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Unauthorized",
                request=MagicMock(),
                response=MagicMock(status_code=401),
            )

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await client.list_scans()

            assert exc_info.value.response.status_code == 401

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        """404 error should raise HTTPStatusError."""
        client = OpenLabelsClient("http://test")
        scan_id = uuid4()

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Not Found",
                request=MagicMock(),
                response=MagicMock(status_code=404),
            )

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await client.get_scan(scan_id)

            assert exc_info.value.response.status_code == 404

    @pytest.mark.asyncio
    async def test_500_server_error(self):
        """500 error should raise HTTPStatusError."""
        client = OpenLabelsClient("http://test")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Internal Server Error",
                request=MagicMock(),
                response=MagicMock(status_code=500),
            )

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            with pytest.raises(httpx.HTTPStatusError):
                await client.health()

    @pytest.mark.asyncio
    async def test_connection_error(self):
        """Connection error should propagate."""
        client = OpenLabelsClient("http://nonexistent")

        with patch("openlabels.client.client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get.side_effect = httpx.ConnectError("Connection refused")
            MockClient.return_value.__aenter__.return_value = mock_instance

            with pytest.raises(httpx.ConnectError):
                await client.health()


class TestModuleExports:
    """Tests for module exports."""

    def test_client_exported_from_init(self):
        """OpenLabelsClient should be exported from __init__."""
        from openlabels.client import OpenLabelsClient as ImportedClient
        assert ImportedClient is OpenLabelsClient

    def test_all_exports(self):
        """__all__ should contain OpenLabelsClient."""
        from openlabels.client import __all__
        assert "OpenLabelsClient" in __all__
