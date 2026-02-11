"""
Comprehensive tests for OpenLabels Python SDK client.

Tests cover client initialization, persistent connections, retry logic,
auto-pagination, authentication, request construction, response handling,
error cases, and complete API coverage.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import asyncio
import pytest
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from openlabels.client.client import OpenLabelsClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(json_data=None, status_code=200):
    """Create a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    resp.raise_for_status = MagicMock()
    return resp


def _mock_client(response=None):
    """Create a mock httpx.AsyncClient suitable for the persistent pattern."""
    mock = AsyncMock(spec=httpx.AsyncClient)
    mock.is_closed = False
    if response is not None:
        mock.request.return_value = response
        mock.get.return_value = response
    return mock


# ===========================================================================
# Initialization
# ===========================================================================


class TestClientInitialization:
    """Tests for client initialization."""

    def test_default_base_url(self):
        client = OpenLabelsClient()
        assert client.base_url == "http://localhost:8000"

    def test_custom_base_url(self):
        client = OpenLabelsClient("https://api.example.com")
        assert client.base_url == "https://api.example.com"

    def test_base_url_trailing_slash_stripped(self):
        client = OpenLabelsClient("https://api.example.com/")
        assert client.base_url == "https://api.example.com"

    def test_multiple_trailing_slashes_handled(self):
        client = OpenLabelsClient("https://api.example.com///")
        assert client.base_url == "https://api.example.com"

    def test_token_stored(self):
        client = OpenLabelsClient(token="test-token")
        assert client.token == "test-token"

    def test_no_token_by_default(self):
        client = OpenLabelsClient()
        assert client.token is None

    def test_default_timeout(self):
        client = OpenLabelsClient()
        assert client.timeout == 30.0

    def test_custom_timeout(self):
        client = OpenLabelsClient(timeout=60.0)
        assert client.timeout == 60.0

    def test_default_max_retries(self):
        client = OpenLabelsClient()
        assert client.max_retries == 3

    def test_custom_max_retries(self):
        client = OpenLabelsClient(max_retries=5)
        assert client.max_retries == 5

    def test_api_base_with_version(self):
        client = OpenLabelsClient("http://test", api_version="v1")
        assert client.api_base == "http://test/api/v1"

    def test_api_base_without_version(self):
        client = OpenLabelsClient("http://test", api_version=None)
        assert client.api_base == "http://test/api"


class TestHeaders:
    """Tests for request header generation."""

    def test_headers_without_token(self):
        client = OpenLabelsClient()
        headers = client._headers()
        assert headers["Content-Type"] == "application/json"
        assert "Authorization" not in headers

    def test_headers_with_token(self):
        client = OpenLabelsClient(token="my-token")
        headers = client._headers()
        assert headers["Content-Type"] == "application/json"
        assert headers["Authorization"] == "Bearer my-token"

    def test_empty_token_treated_as_none(self):
        client = OpenLabelsClient(token="")
        headers = client._headers()
        assert "Authorization" not in headers


# ===========================================================================
# Persistent client + context manager
# ===========================================================================


class TestPersistentClient:
    """Tests for persistent client lifecycle."""

    async def test_get_client_creates_once(self):
        """_get_client should reuse the same instance."""
        client = OpenLabelsClient("http://test")
        with patch("openlabels.client.client.httpx.AsyncClient") as MockCls:
            mock_inst = AsyncMock()
            mock_inst.is_closed = False
            MockCls.return_value = mock_inst

            c1 = await client._get_client()
            c2 = await client._get_client()
            assert c1 is c2
            assert MockCls.call_count == 1

    async def test_get_client_recreates_after_close(self):
        """_get_client should create a new instance if previous was closed."""
        client = OpenLabelsClient("http://test")
        with patch("openlabels.client.client.httpx.AsyncClient") as MockCls:
            mock_inst = AsyncMock()
            mock_inst.is_closed = False
            MockCls.return_value = mock_inst

            await client._get_client()
            mock_inst.is_closed = True
            await client._get_client()
            assert MockCls.call_count == 2

    async def test_context_manager(self):
        """async with should call close on exit."""
        client = OpenLabelsClient("http://test")
        with patch("openlabels.client.client.httpx.AsyncClient") as MockCls:
            mock_inst = AsyncMock()
            mock_inst.is_closed = False
            MockCls.return_value = mock_inst

            async with client:
                await client._get_client()
            mock_inst.aclose.assert_awaited_once()

    async def test_close_is_idempotent(self):
        """Calling close twice should not error."""
        client = OpenLabelsClient("http://test")
        await client.close()
        await client.close()


# ===========================================================================
# Retry logic
# ===========================================================================


class TestRetryLogic:
    """Tests for automatic retry on transient failures."""

    async def test_no_retry_on_success(self):
        """Successful request should not retry."""
        client = OpenLabelsClient("http://test", max_retries=3)
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock

        resp = await client._request("GET", "/test")
        assert mock.request.await_count == 1

    async def test_retry_on_transport_error(self):
        """TransportError should trigger retries."""
        client = OpenLabelsClient("http://test", max_retries=2)
        mock = _mock_client()
        mock.request.side_effect = [
            httpx.ConnectError("fail"),
            httpx.ConnectError("fail"),
            _mock_response({"ok": True}),
        ]
        client._client = mock

        with patch("openlabels.client.client.asyncio.sleep", new_callable=AsyncMock):
            resp = await client._request("GET", "/test")
        assert mock.request.await_count == 3

    async def test_retry_on_502(self):
        """502 should trigger retries."""
        client = OpenLabelsClient("http://test", max_retries=1)
        error_resp = MagicMock(spec=httpx.Response)
        error_resp.status_code = 502
        error_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Bad Gateway", request=MagicMock(), response=error_resp,
        )
        ok_resp = _mock_response({"ok": True})
        mock = _mock_client()
        mock.request.side_effect = [error_resp, ok_resp]
        client._client = mock

        with patch("openlabels.client.client.asyncio.sleep", new_callable=AsyncMock):
            resp = await client._request("GET", "/test")
        assert mock.request.await_count == 2

    async def test_no_retry_on_400(self):
        """400 (non-retryable) should raise immediately."""
        client = OpenLabelsClient("http://test", max_retries=3)
        error_resp = MagicMock(spec=httpx.Response)
        error_resp.status_code = 400
        error_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Bad Request", request=MagicMock(), response=error_resp,
        )
        mock = _mock_client()
        mock.request.return_value = error_resp
        client._client = mock

        with pytest.raises(httpx.HTTPStatusError):
            await client._request("GET", "/test")
        assert mock.request.await_count == 1

    async def test_exhausted_retries_raises(self):
        """After exhausting retries, the last error should be raised."""
        client = OpenLabelsClient("http://test", max_retries=1)
        mock = _mock_client()
        mock.request.side_effect = httpx.ConnectError("fail")
        client._client = mock

        with patch("openlabels.client.client.asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(httpx.ConnectError):
                await client._request("GET", "/test")
        assert mock.request.await_count == 2  # 1 + 1 retry


# ===========================================================================
# Auto-pagination
# ===========================================================================


class TestAutoPagination:
    """Tests for cursor-based auto-pagination."""

    async def test_single_page(self):
        """Single page with no has_more."""
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client()
        mock.request.return_value = _mock_response({
            "items": [{"id": 1}, {"id": 2}],
            "has_more": False,
            "next_cursor": None,
        })
        client._client = mock

        items = []
        async for item in client._iter_pages("/test"):
            items.append(item)
        assert len(items) == 2
        assert items[0]["id"] == 1
        assert items[1]["id"] == 2

    async def test_multi_page(self):
        """Multiple pages should be followed until has_more is False."""
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client()
        mock.request.side_effect = [
            _mock_response({
                "items": [{"id": 1}],
                "has_more": True,
                "next_cursor": "cursor_abc",
            }),
            _mock_response({
                "items": [{"id": 2}],
                "has_more": False,
                "next_cursor": None,
            }),
        ]
        client._client = mock

        items = []
        async for item in client._iter_pages("/test"):
            items.append(item)
        assert len(items) == 2
        assert items[0]["id"] == 1
        assert items[1]["id"] == 2

        # Second call should include cursor param
        second_call = mock.request.call_args_list[1]
        assert second_call.kwargs.get("params", {}).get("cursor") == "cursor_abc"


# ===========================================================================
# Health endpoints
# ===========================================================================


class TestHealthEndpoint:
    """Tests for health check endpoints."""

    async def test_health_check_success(self):
        client = OpenLabelsClient("http://test")
        mock = _mock_client()
        mock.get.return_value = _mock_response({"status": "healthy"})
        client._client = mock

        result = await client.health()
        assert result == {"status": "healthy"}

    async def test_health_check_failure(self):
        client = OpenLabelsClient("http://test")
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 500
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=resp,
        )
        mock = _mock_client()
        mock.get.return_value = resp
        client._client = mock

        with pytest.raises(httpx.HTTPStatusError):
            await client.health()

    async def test_get_health_status(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"db": "ok", "redis": "ok"}))
        client._client = mock
        result = await client.get_health_status()
        assert result["db"] == "ok"

    async def test_get_cache_health(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"hit_rate": 0.95}))
        client._client = mock
        result = await client.get_cache_health()
        assert result["hit_rate"] == 0.95


# ===========================================================================
# Scans
# ===========================================================================


class TestScansEndpoints:
    """Tests for scan-related endpoints."""

    async def test_create_scan(self):
        client = OpenLabelsClient("http://test", token="test-token", max_retries=0)
        target_id = uuid4()
        mock = _mock_client(_mock_response({"id": "new", "status": "pending"}))
        client._client = mock

        result = await client.create_scan(target_id, name="Test Scan")

        call_kwargs = mock.request.call_args
        assert call_kwargs.args == ("POST", "/scans")
        json_body = call_kwargs.kwargs["json"]
        assert json_body["target_id"] == str(target_id)
        assert json_body["name"] == "Test Scan"

    async def test_list_scans_default_params(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"items": [], "total": 0}))
        client._client = mock

        await client.list_scans()

        call_kwargs = mock.request.call_args
        params = call_kwargs.kwargs["params"]
        assert params["limit"] == 50
        assert "status" not in params

    async def test_list_scans_with_filters(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"items": [], "total": 0}))
        client._client = mock

        await client.list_scans(status="running", limit=10)

        call_kwargs = mock.request.call_args
        params = call_kwargs.kwargs["params"]
        assert params["status"] == "running"
        assert params["limit"] == 10

    async def test_get_scan(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        scan_id = uuid4()
        mock = _mock_client(_mock_response({"id": str(scan_id)}))
        client._client = mock

        await client.get_scan(scan_id)
        assert mock.request.call_args.args == ("GET", f"/scans/{scan_id}")

    async def test_delete_scan(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        scan_id = uuid4()
        mock = _mock_client(_mock_response(status_code=204))
        client._client = mock

        await client.delete_scan(scan_id)
        assert mock.request.call_args.args == ("DELETE", f"/scans/{scan_id}")

    async def test_cancel_scan(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        scan_id = uuid4()
        mock = _mock_client(_mock_response({"status": "cancelled"}))
        client._client = mock

        await client.cancel_scan(scan_id)
        assert mock.request.call_args.args == ("POST", f"/scans/{scan_id}/cancel")

    async def test_retry_scan(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        scan_id = uuid4()
        mock = _mock_client(_mock_response({"status": "pending"}))
        client._client = mock

        await client.retry_scan(scan_id)
        assert mock.request.call_args.args == ("POST", f"/scans/{scan_id}/retry")


# ===========================================================================
# Results
# ===========================================================================


class TestResultsEndpoints:
    """Tests for results endpoints."""

    async def test_list_results_default(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"items": []}))
        client._client = mock

        await client.list_results()
        assert mock.request.call_args.args[1] == "/results"

    async def test_list_results_with_filters(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        job_id = uuid4()
        mock = _mock_client(_mock_response({"items": []}))
        client._client = mock

        await client.list_results(job_id=job_id, risk_tier="HIGH")
        params = mock.request.call_args.kwargs["params"]
        assert params["job_id"] == str(job_id)
        assert params["risk_tier"] == "HIGH"

    async def test_get_result(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        result_id = uuid4()
        mock = _mock_client(_mock_response({"id": str(result_id)}))
        client._client = mock

        await client.get_result(result_id)
        assert f"/results/{result_id}" in mock.request.call_args.args[1]

    async def test_get_result_stats(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"total": 100}))
        client._client = mock

        await client.get_result_stats()
        assert mock.request.call_args.args[1] == "/results/stats"

    async def test_get_result_stats_with_job_filter(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        job_id = uuid4()
        mock = _mock_client(_mock_response({}))
        client._client = mock

        await client.get_result_stats(job_id=job_id)
        params = mock.request.call_args.kwargs["params"]
        assert params["job_id"] == str(job_id)

    async def test_delete_result(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        result_id = uuid4()
        mock = _mock_client(_mock_response(status_code=204))
        client._client = mock

        await client.delete_result(result_id)
        assert mock.request.call_args.args == ("DELETE", f"/results/{result_id}")

    async def test_clear_all_results(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response(status_code=204))
        client._client = mock

        await client.clear_all_results()
        assert mock.request.call_args.args == ("DELETE", "/results")

    async def test_apply_recommended_label(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        result_id = uuid4()
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock

        await client.apply_recommended_label(result_id)
        assert mock.request.call_args.args == ("POST", f"/results/{result_id}/apply-label")

    async def test_rescan_file(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        result_id = uuid4()
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock

        await client.rescan_file(result_id)
        assert mock.request.call_args.args == ("POST", f"/results/{result_id}/rescan")

    async def test_export_results(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"data": []}))
        client._client = mock

        await client.export_results()
        assert mock.request.call_args.args == ("GET", "/results/export")


# ===========================================================================
# Targets
# ===========================================================================


class TestTargetsEndpoints:
    """Tests for targets endpoints."""

    async def test_list_targets(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response([{"id": "1"}]))
        client._client = mock

        await client.list_targets()
        assert mock.request.call_args.args[1] == "/targets"

    async def test_list_targets_with_adapter_filter(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response([]))
        client._client = mock

        await client.list_targets(adapter="sharepoint")
        params = mock.request.call_args.kwargs["params"]
        assert params["adapter"] == "sharepoint"

    async def test_create_target(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"id": "new-id"}))
        client._client = mock

        await client.create_target("My Target", "filesystem", {"path": "/data"})
        json_body = mock.request.call_args.kwargs["json"]
        assert json_body["name"] == "My Target"
        assert json_body["adapter"] == "filesystem"
        assert json_body["config"] == {"path": "/data"}

    async def test_get_target(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        tid = uuid4()
        mock = _mock_client(_mock_response({"id": str(tid)}))
        client._client = mock

        await client.get_target(tid)
        assert mock.request.call_args.args == ("GET", f"/targets/{tid}")

    async def test_update_target(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        tid = uuid4()
        mock = _mock_client(_mock_response({"id": str(tid)}))
        client._client = mock

        await client.update_target(tid, name="Updated")
        assert mock.request.call_args.args == ("PUT", f"/targets/{tid}")
        assert mock.request.call_args.kwargs["json"]["name"] == "Updated"

    async def test_delete_target(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        tid = uuid4()
        mock = _mock_client(_mock_response(status_code=204))
        client._client = mock

        await client.delete_target(tid)
        assert mock.request.call_args.args == ("DELETE", f"/targets/{tid}")


# ===========================================================================
# Labels
# ===========================================================================


class TestLabelsEndpoints:
    """Tests for labels endpoints."""

    async def test_list_labels(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response([]))
        client._client = mock
        await client.list_labels()
        assert mock.request.call_args.args == ("GET", "/labels")

    async def test_sync_labels(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"synced": 5}))
        client._client = mock
        await client.sync_labels()
        assert mock.request.call_args.args == ("POST", "/labels/sync")

    async def test_get_sync_status(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"status": "complete"}))
        client._client = mock
        await client.get_sync_status()
        assert mock.request.call_args.args == ("GET", "/labels/sync/status")

    async def test_invalidate_label_cache(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.invalidate_label_cache()
        assert mock.request.call_args.args == ("POST", "/labels/cache/invalidate")

    async def test_list_label_rules(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response([]))
        client._client = mock
        await client.list_label_rules()
        assert mock.request.call_args.args == ("GET", "/labels/rules")

    async def test_create_label_rule(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"id": "rule1"}))
        client._client = mock
        await client.create_label_rule("Rule A", "label-1", {"tier": "HIGH"})
        body = mock.request.call_args.kwargs["json"]
        assert body["name"] == "Rule A"
        assert body["label_id"] == "label-1"
        assert body["conditions"] == {"tier": "HIGH"}

    async def test_delete_label_rule(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        rid = uuid4()
        mock = _mock_client(_mock_response(status_code=204))
        client._client = mock
        await client.delete_label_rule(rid)
        assert mock.request.call_args.args == ("DELETE", f"/labels/rules/{rid}")

    async def test_apply_label(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        result_id = uuid4()
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.apply_label(result_id, "label-1")
        body = mock.request.call_args.kwargs["json"]
        assert body["result_id"] == str(result_id)
        assert body["label_id"] == "label-1"

    async def test_get_label_mappings(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({}))
        client._client = mock
        await client.get_label_mappings()
        assert mock.request.call_args.args == ("GET", "/labels/mappings")

    async def test_update_label_mappings(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.update_label_mappings({"SSN": "Confidential"})
        assert mock.request.call_args.kwargs["json"] == {"SSN": "Confidential"}


# ===========================================================================
# Schedules
# ===========================================================================


class TestSchedulesEndpoints:

    async def test_list_schedules(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response([]))
        client._client = mock
        await client.list_schedules()
        assert mock.request.call_args.args == ("GET", "/schedules")

    async def test_create_schedule(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        tid = uuid4()
        mock = _mock_client(_mock_response({"id": "s1"}))
        client._client = mock
        await client.create_schedule("Nightly", "0 0 * * *", tid)
        body = mock.request.call_args.kwargs["json"]
        assert body["name"] == "Nightly"
        assert body["cron"] == "0 0 * * *"
        assert body["target_id"] == str(tid)

    async def test_get_schedule(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        sid = uuid4()
        mock = _mock_client(_mock_response({"id": str(sid)}))
        client._client = mock
        await client.get_schedule(sid)
        assert mock.request.call_args.args == ("GET", f"/schedules/{sid}")

    async def test_update_schedule(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        sid = uuid4()
        mock = _mock_client(_mock_response({"id": str(sid)}))
        client._client = mock
        await client.update_schedule(sid, cron="0 6 * * *")
        assert mock.request.call_args.args == ("PUT", f"/schedules/{sid}")
        assert mock.request.call_args.kwargs["json"]["cron"] == "0 6 * * *"

    async def test_delete_schedule(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        sid = uuid4()
        mock = _mock_client(_mock_response(status_code=204))
        client._client = mock
        await client.delete_schedule(sid)
        assert mock.request.call_args.args == ("DELETE", f"/schedules/{sid}")

    async def test_trigger_schedule(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        sid = uuid4()
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.trigger_schedule(sid)
        assert mock.request.call_args.args == ("POST", f"/schedules/{sid}/run")


# ===========================================================================
# Users
# ===========================================================================


class TestUsersEndpoints:

    async def test_list_users(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response([]))
        client._client = mock
        await client.list_users()
        assert mock.request.call_args.args == ("GET", "/users")

    async def test_create_user(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"id": "u1"}))
        client._client = mock
        await client.create_user("user@test.com", role="admin")
        body = mock.request.call_args.kwargs["json"]
        assert body["email"] == "user@test.com"
        assert body["role"] == "admin"

    async def test_get_user(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        uid = uuid4()
        mock = _mock_client(_mock_response({"id": str(uid)}))
        client._client = mock
        await client.get_user(uid)
        assert mock.request.call_args.args == ("GET", f"/users/{uid}")

    async def test_update_user(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        uid = uuid4()
        mock = _mock_client(_mock_response({"id": str(uid)}))
        client._client = mock
        await client.update_user(uid, role="admin")
        assert mock.request.call_args.args == ("PUT", f"/users/{uid}")

    async def test_delete_user(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        uid = uuid4()
        mock = _mock_client(_mock_response(status_code=204))
        client._client = mock
        await client.delete_user(uid)
        assert mock.request.call_args.args == ("DELETE", f"/users/{uid}")


# ===========================================================================
# Settings
# ===========================================================================


class TestSettingsEndpoints:

    async def test_update_azure_settings(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.update_azure_settings({"tenant_id": "t1"})
        assert mock.request.call_args.args == ("POST", "/settings/azure")

    async def test_update_scan_settings(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.update_scan_settings({"max_files": 1000})
        assert mock.request.call_args.args == ("POST", "/settings/scan")

    async def test_update_entity_settings(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.update_entity_settings({"enabled": ["SSN"]})
        assert mock.request.call_args.args == ("POST", "/settings/entities")

    async def test_reset_settings(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.reset_settings()
        assert mock.request.call_args.args == ("POST", "/settings/reset")


# ===========================================================================
# Monitoring
# ===========================================================================


class TestMonitoringEndpoints:

    async def test_list_monitored_files(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response([]))
        client._client = mock
        await client.list_monitored_files()
        assert mock.request.call_args.args == ("GET", "/monitoring/files")

    async def test_enable_file_monitoring(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"id": "f1"}))
        client._client = mock
        await client.enable_file_monitoring("/data/secret.docx")
        body = mock.request.call_args.kwargs["json"]
        assert body["path"] == "/data/secret.docx"
        assert body["risk_tier"] == "HIGH"

    async def test_disable_file_monitoring(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        fid = uuid4()
        mock = _mock_client(_mock_response(status_code=204))
        client._client = mock
        await client.disable_file_monitoring(fid)
        assert mock.request.call_args.args == ("DELETE", f"/monitoring/files/{fid}")

    async def test_list_access_events(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"items": []}))
        client._client = mock
        await client.list_access_events()
        assert mock.request.call_args.args == ("GET", "/monitoring/events")

    async def test_get_file_access_history(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response([]))
        client._client = mock
        await client.get_file_access_history("/data/file.txt")
        assert "/monitoring/events/file/" in mock.request.call_args.args[1]

    async def test_get_user_access_history(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response([]))
        client._client = mock
        await client.get_user_access_history("jdoe")
        assert mock.request.call_args.args == ("GET", "/monitoring/events/user/jdoe")

    async def test_get_access_stats(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({}))
        client._client = mock
        await client.get_access_stats()
        assert mock.request.call_args.args == ("GET", "/monitoring/stats")

    async def test_detect_access_anomalies(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response([]))
        client._client = mock
        await client.detect_access_anomalies()
        assert mock.request.call_args.args == ("GET", "/monitoring/stats/anomalies")


# ===========================================================================
# Audit
# ===========================================================================


class TestAuditEndpoints:

    async def test_list_audit_logs(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"items": []}))
        client._client = mock
        await client.list_audit_logs()
        assert mock.request.call_args.args == ("GET", "/audit")

    async def test_get_audit_filters(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({}))
        client._client = mock
        await client.get_audit_filters()
        assert mock.request.call_args.args == ("GET", "/audit/filters")

    async def test_get_audit_log(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        lid = uuid4()
        mock = _mock_client(_mock_response({"id": str(lid)}))
        client._client = mock
        await client.get_audit_log(lid)
        assert mock.request.call_args.args == ("GET", f"/audit/{lid}")

    async def test_get_resource_history(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        rid = uuid4()
        mock = _mock_client(_mock_response([]))
        client._client = mock
        await client.get_resource_history("scan", rid)
        assert mock.request.call_args.args == ("GET", f"/audit/resource/scan/{rid}")


# ===========================================================================
# Jobs
# ===========================================================================


class TestJobsEndpoints:

    async def test_list_jobs(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response([]))
        client._client = mock
        await client.list_jobs()
        assert mock.request.call_args.args == ("GET", "/jobs")

    async def test_get_queue_stats(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({}))
        client._client = mock
        await client.get_queue_stats()
        assert mock.request.call_args.args == ("GET", "/jobs/stats")

    async def test_list_failed_jobs(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response([]))
        client._client = mock
        await client.list_failed_jobs()
        assert mock.request.call_args.args == ("GET", "/jobs/failed")

    async def test_get_job(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        jid = uuid4()
        mock = _mock_client(_mock_response({"id": str(jid)}))
        client._client = mock
        await client.get_job(jid)
        assert mock.request.call_args.args == ("GET", f"/jobs/{jid}")

    async def test_requeue_job(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        jid = uuid4()
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.requeue_job(jid)
        assert mock.request.call_args.args == ("POST", f"/jobs/{jid}/requeue")

    async def test_requeue_all_failed(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.requeue_all_failed()
        assert mock.request.call_args.args == ("POST", "/jobs/requeue-all")

    async def test_purge_failed_jobs(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.purge_failed_jobs()
        assert mock.request.call_args.args == ("POST", "/jobs/purge")

    async def test_cancel_job(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        jid = uuid4()
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.cancel_job(jid)
        assert mock.request.call_args.args == ("POST", f"/jobs/{jid}/cancel")

    async def test_get_worker_status(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({}))
        client._client = mock
        await client.get_worker_status()
        assert mock.request.call_args.args == ("GET", "/jobs/workers/status")

    async def test_update_worker_config(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.update_worker_config({"concurrency": 4})
        assert mock.request.call_args.args == ("POST", "/jobs/workers/config")
        assert mock.request.call_args.kwargs["json"] == {"concurrency": 4}


# ===========================================================================
# Auth
# ===========================================================================


class TestAuthEndpoints:

    async def test_login(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"redirect": "/oauth"}))
        client._client = mock
        await client.login()
        assert mock.request.call_args.args == ("GET", "/auth/login")

    async def test_auth_callback(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"token": "abc"}))
        client._client = mock
        await client.auth_callback(code="xyz", state="s1")
        assert mock.request.call_args.args == ("GET", "/auth/callback")

    async def test_logout(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.logout()
        assert mock.request.call_args.args == ("GET", "/auth/logout")

    async def test_get_current_user(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"email": "a@b.com"}))
        client._client = mock
        await client.get_current_user()
        assert mock.request.call_args.args == ("GET", "/auth/me")

    async def test_get_token(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"token": "t1"}))
        client._client = mock
        await client.get_token(username="u", password="p")
        assert mock.request.call_args.args == ("POST", "/auth/token")

    async def test_auth_status(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"authenticated": True}))
        client._client = mock
        await client.auth_status()
        assert mock.request.call_args.args == ("GET", "/auth/status")

    async def test_revoke_token(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.revoke_token()
        assert mock.request.call_args.args == ("POST", "/auth/revoke")

    async def test_logout_all_sessions(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.logout_all_sessions()
        assert mock.request.call_args.args == ("POST", "/auth/logout-all")


# ===========================================================================
# Remediation
# ===========================================================================


class TestRemediationEndpoints:

    async def test_list_remediation_actions(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"items": []}))
        client._client = mock
        await client.list_remediation_actions()
        assert mock.request.call_args.args == ("GET", "/remediation")

    async def test_get_remediation_action(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        aid = uuid4()
        mock = _mock_client(_mock_response({"id": str(aid)}))
        client._client = mock
        await client.get_remediation_action(aid)
        assert mock.request.call_args.args == ("GET", f"/remediation/{aid}")

    async def test_quarantine_file(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        rid = uuid4()
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.quarantine_file(rid)
        body = mock.request.call_args.kwargs["json"]
        assert body["result_id"] == str(rid)

    async def test_lockdown_file(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        rid = uuid4()
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.lockdown_file(rid)
        body = mock.request.call_args.kwargs["json"]
        assert body["result_id"] == str(rid)

    async def test_rollback_action(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        aid = uuid4()
        mock = _mock_client(_mock_response({"ok": True}))
        client._client = mock
        await client.rollback_action(aid)
        body = mock.request.call_args.kwargs["json"]
        assert body["action_id"] == str(aid)

    async def test_get_remediation_stats(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"total": 10}))
        client._client = mock
        await client.get_remediation_stats()
        assert mock.request.call_args.args == ("GET", "/remediation/stats/summary")


# ===========================================================================
# Dashboard
# ===========================================================================


class TestDashboardEndpoints:
    """Tests for dashboard endpoints."""

    async def test_get_dashboard_stats(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"total_files": 1000}))
        client._client = mock
        result = await client.get_dashboard_stats()
        assert mock.request.call_args.args == ("GET", "/dashboard/stats")

    async def test_get_heatmap(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({"data": []}))
        client._client = mock
        await client.get_heatmap()
        assert mock.request.call_args.args == ("GET", "/dashboard/heatmap")

    async def test_get_heatmap_with_job_filter(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        job_id = uuid4()
        mock = _mock_client(_mock_response({}))
        client._client = mock
        await client.get_heatmap(job_id=job_id)
        params = mock.request.call_args.kwargs["params"]
        assert params["job_id"] == str(job_id)

    async def test_get_trends(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({}))
        client._client = mock
        await client.get_trends()
        assert mock.request.call_args.args == ("GET", "/dashboard/trends")

    async def test_get_entity_trends(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({}))
        client._client = mock
        await client.get_entity_trends()
        assert mock.request.call_args.args == ("GET", "/dashboard/entity-trends")

    async def test_get_access_heatmap(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client(_mock_response({}))
        client._client = mock
        await client.get_access_heatmap()
        assert mock.request.call_args.args == ("GET", "/dashboard/access-heatmap")


# ===========================================================================
# Error handling (new architecture)
# ===========================================================================


class TestErrorHandling:
    """Tests for error handling with the persistent client."""

    async def test_401_unauthorized(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        error_resp = MagicMock(spec=httpx.Response)
        error_resp.status_code = 401
        error_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Unauthorized", request=MagicMock(), response=error_resp,
        )
        mock = _mock_client()
        mock.request.return_value = error_resp
        client._client = mock

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.list_scans()
        assert exc_info.value.response.status_code == 401

    async def test_404_not_found(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        scan_id = uuid4()
        error_resp = MagicMock(spec=httpx.Response)
        error_resp.status_code = 404
        error_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found", request=MagicMock(), response=error_resp,
        )
        mock = _mock_client()
        mock.request.return_value = error_resp
        client._client = mock

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.get_scan(scan_id)
        assert exc_info.value.response.status_code == 404

    async def test_500_server_error(self):
        client = OpenLabelsClient("http://test", max_retries=0)
        error_resp = MagicMock(spec=httpx.Response)
        error_resp.status_code = 500
        error_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=error_resp,
        )
        mock = _mock_client()
        mock.get.return_value = error_resp
        client._client = mock

        with pytest.raises(httpx.HTTPStatusError):
            await client.health()

    async def test_connection_error_after_retries(self):
        """ConnectError should propagate after retries are exhausted."""
        client = OpenLabelsClient("http://test", max_retries=0)
        mock = _mock_client()
        mock.request.side_effect = httpx.ConnectError("Connection refused")
        client._client = mock

        with pytest.raises(httpx.ConnectError):
            await client.list_scans()
