"""
Python SDK client for OpenLabels API.

Provides a persistent async HTTP client with:
- Connection pooling via a single ``httpx.AsyncClient``
- Automatic retry with exponential backoff on transient failures
- Cursor-based auto-pagination helpers
- Complete coverage of all API endpoints

Supports API versioning:
- Default API version: v1 (/api/v1/)
- Legacy routes (/api/) are deprecated but still supported

Example::

    async with OpenLabelsClient("http://localhost:8000", token="...") as client:
        scans = await client.list_scans()
        async for result in client.iter_results(job_id=scan_id):
            print(result["file_path"])
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any
from uuid import UUID

import httpx
from httpx import HTTPStatusError, TransportError

logger = logging.getLogger(__name__)

# HTTP status codes that are safe to retry
_RETRYABLE_STATUS_CODES = frozenset({502, 503, 504})


class OpenLabelsClient:
    """Async Python client for the OpenLabels API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        token: str | None = None,
        api_version: str | None = "v1",
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.api_version = api_version
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: httpx.AsyncClient | None = None

    # Connection lifecycle
    @property
    def api_base(self) -> str:
        if self.api_version:
            return f"{self.base_url}/api/{self.api_version}"
        return f"{self.base_url}/api"

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.api_base,
                headers=self._headers(),
                timeout=self.timeout,
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    # Core request with retry
    async def _request(
        self,
        method: str,
        url: str,
        *,
        max_retries: int | None = None,
        **kwargs,
    ) -> httpx.Response:
        """Make a request with automatic retry on transient failures."""
        client = await self._get_client()
        retries = max_retries if max_retries is not None else self.max_retries
        last_error: Exception | None = None

        for attempt in range(retries + 1):
            try:
                response = await client.request(method, url, **kwargs)
                response.raise_for_status()
                return response
            except TransportError as e:
                last_error = e
                if attempt < retries:
                    delay = 2 ** attempt
                    logger.warning(
                        "Transport error on %s %s (attempt %d/%d), retrying in %ds: %s",
                        method, url, attempt + 1, retries + 1, delay, e,
                    )
                    await asyncio.sleep(delay)
            except HTTPStatusError as e:
                if e.response.status_code in _RETRYABLE_STATUS_CODES and attempt < retries:
                    last_error = e
                    delay = 2 ** attempt
                    logger.warning(
                        "HTTP %d on %s %s (attempt %d/%d), retrying in %ds",
                        e.response.status_code, method, url,
                        attempt + 1, retries + 1, delay,
                    )
                    await asyncio.sleep(delay)
                else:
                    raise

        raise last_error  # type: ignore[misc]

    async def _json(self, method: str, url: str, **kwargs) -> Any:
        """Shorthand: make request and return parsed JSON."""
        resp = await self._request(method, url, **kwargs)
        if resp.status_code == 204:
            return None
        return resp.json()

    # Auto-pagination
    async def _iter_pages(
        self,
        url: str,
        *,
        limit: int = 100,
        params: dict | None = None,
    ) -> AsyncIterator[dict]:
        """Auto-paginating cursor-based iterator.

        The server returns ``{"items": [...], "next_cursor": "...", "has_more": bool}``.
        """
        cursor: str | None = None
        base_params = dict(params or {})
        while True:
            page_params = {**base_params, "limit": limit}
            if cursor:
                page_params["cursor"] = cursor
            resp = await self._json("GET", url, params=page_params)
            for item in resp.get("items", []):
                yield item
            if not resp.get("has_more", False):
                break
            cursor = resp.get("next_cursor")
            if not cursor:
                break

    # Health
    async def health(self) -> dict:
        """GET /health -- basic health check (root-level, not versioned)."""
        client = await self._get_client()
        resp = await client.get(f"{self.base_url}/health")
        resp.raise_for_status()
        return resp.json()

    async def get_health_status(self) -> dict:
        """GET /health/status -- detailed health status."""
        return await self._json("GET", "/health/status")

    async def get_cache_health(self) -> dict:
        """GET /health/cache -- cache health info."""
        return await self._json("GET", "/health/cache")

    # Scans
    async def create_scan(
        self, target_id: UUID, name: str | None = None,
    ) -> dict:
        """POST /scans"""
        return await self._json(
            "POST", "/scans",
            json={"target_id": str(target_id), "name": name},
        )

    async def list_scans(
        self,
        status: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict:
        """GET /scans"""
        params: dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status
        if cursor:
            params["cursor"] = cursor
        return await self._json("GET", "/scans", params=params)

    async def iter_scans(self, **filters) -> AsyncIterator[dict]:
        """Auto-paginating scan iterator."""
        params = {k: v for k, v in filters.items() if v is not None}
        async for item in self._iter_pages("/scans", params=params):
            yield item

    async def get_scan(self, scan_id: UUID) -> dict:
        """GET /scans/{scan_id}"""
        return await self._json("GET", f"/scans/{scan_id}")

    async def delete_scan(self, scan_id: UUID) -> None:
        """DELETE /scans/{scan_id}"""
        await self._request("DELETE", f"/scans/{scan_id}")

    async def cancel_scan(self, scan_id: UUID) -> dict:
        """POST /scans/{scan_id}/cancel"""
        return await self._json("POST", f"/scans/{scan_id}/cancel")

    async def retry_scan(self, scan_id: UUID) -> dict:
        """POST /scans/{scan_id}/retry"""
        return await self._json("POST", f"/scans/{scan_id}/retry")

    # Results
    async def list_results(
        self,
        job_id: UUID | None = None,
        risk_tier: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict:
        """GET /results"""
        params: dict[str, Any] = {"limit": limit}
        if job_id:
            params["job_id"] = str(job_id)
        if risk_tier:
            params["risk_tier"] = risk_tier
        if cursor:
            params["cursor"] = cursor
        return await self._json("GET", "/results", params=params)

    async def list_results_cursor(
        self,
        job_id: UUID | None = None,
        risk_tier: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict:
        """GET /results/cursor"""
        params: dict[str, Any] = {"limit": limit}
        if job_id:
            params["job_id"] = str(job_id)
        if risk_tier:
            params["risk_tier"] = risk_tier
        if cursor:
            params["cursor"] = cursor
        return await self._json("GET", "/results/cursor", params=params)

    async def iter_results(self, **filters) -> AsyncIterator[dict]:
        """Auto-paginating result iterator."""
        params = {k: str(v) if isinstance(v, UUID) else v for k, v in filters.items() if v is not None}
        async for item in self._iter_pages("/results/cursor", params=params):
            yield item

    async def get_result_stats(self, job_id: UUID | None = None) -> dict:
        """GET /results/stats"""
        params = {}
        if job_id:
            params["job_id"] = str(job_id)
        return await self._json("GET", "/results/stats", params=params)

    async def export_results(
        self,
        job_id: UUID | None = None,
        risk_tier: str | None = None,
    ) -> Any:
        """GET /results/export"""
        params: dict[str, Any] = {}
        if job_id:
            params["job_id"] = str(job_id)
        if risk_tier:
            params["risk_tier"] = risk_tier
        return await self._json("GET", "/results/export", params=params)

    async def get_result(self, result_id: UUID) -> dict:
        """GET /results/{result_id}"""
        return await self._json("GET", f"/results/{result_id}")

    async def delete_result(self, result_id: UUID) -> None:
        """DELETE /results/{result_id}"""
        await self._request("DELETE", f"/results/{result_id}")

    async def clear_all_results(self) -> None:
        """DELETE /results"""
        await self._request("DELETE", "/results")

    async def apply_recommended_label(self, result_id: UUID) -> dict:
        """POST /results/{result_id}/apply-label"""
        return await self._json("POST", f"/results/{result_id}/apply-label")

    async def rescan_file(self, result_id: UUID) -> dict:
        """POST /results/{result_id}/rescan"""
        return await self._json("POST", f"/results/{result_id}/rescan")

    # Targets
    async def list_targets(self, adapter: str | None = None) -> Any:
        """GET /targets"""
        params = {}
        if adapter:
            params["adapter"] = adapter
        return await self._json("GET", "/targets", params=params)

    async def create_target(
        self, name: str, adapter: str, config: dict,
    ) -> dict:
        """POST /targets"""
        return await self._json(
            "POST", "/targets",
            json={"name": name, "adapter": adapter, "config": config},
        )

    async def get_target(self, target_id: UUID) -> dict:
        """GET /targets/{target_id}"""
        return await self._json("GET", f"/targets/{target_id}")

    async def update_target(
        self, target_id: UUID, **fields,
    ) -> dict:
        """PUT /targets/{target_id}"""
        return await self._json("PUT", f"/targets/{target_id}", json=fields)

    async def delete_target(self, target_id: UUID) -> None:
        """DELETE /targets/{target_id}"""
        await self._request("DELETE", f"/targets/{target_id}")

    # Labels
    async def list_labels(self) -> Any:
        """GET /labels"""
        return await self._json("GET", "/labels")

    async def sync_labels(self) -> dict:
        """POST /labels/sync"""
        return await self._json("POST", "/labels/sync")

    async def get_sync_status(self) -> dict:
        """GET /labels/sync/status"""
        return await self._json("GET", "/labels/sync/status")

    async def invalidate_label_cache(self) -> dict:
        """POST /labels/cache/invalidate"""
        return await self._json("POST", "/labels/cache/invalidate")

    async def list_label_rules(self) -> Any:
        """GET /labels/rules"""
        return await self._json("GET", "/labels/rules")

    async def create_label_rule(
        self,
        name: str,
        label_id: str,
        conditions: dict,
        **kwargs,
    ) -> dict:
        """POST /labels/rules"""
        body = {"name": name, "label_id": label_id, "conditions": conditions, **kwargs}
        return await self._json("POST", "/labels/rules", json=body)

    async def delete_label_rule(self, rule_id: UUID) -> None:
        """DELETE /labels/rules/{rule_id}"""
        await self._request("DELETE", f"/labels/rules/{rule_id}")

    async def apply_label(
        self, result_id: UUID, label_id: str,
    ) -> dict:
        """POST /labels/apply"""
        return await self._json(
            "POST", "/labels/apply",
            json={"result_id": str(result_id), "label_id": label_id},
        )

    async def get_label_mappings(self) -> Any:
        """GET /labels/mappings"""
        return await self._json("GET", "/labels/mappings")

    async def update_label_mappings(self, mappings: dict) -> dict:
        """POST /labels/mappings"""
        return await self._json("POST", "/labels/mappings", json=mappings)

    # Schedules
    async def list_schedules(self) -> Any:
        """GET /schedules"""
        return await self._json("GET", "/schedules")

    async def create_schedule(
        self,
        name: str,
        cron: str,
        target_id: UUID,
        **kwargs,
    ) -> dict:
        """POST /schedules"""
        body = {"name": name, "cron": cron, "target_id": str(target_id), **kwargs}
        return await self._json("POST", "/schedules", json=body)

    async def get_schedule(self, schedule_id: UUID) -> dict:
        """GET /schedules/{schedule_id}"""
        return await self._json("GET", f"/schedules/{schedule_id}")

    async def update_schedule(self, schedule_id: UUID, **fields) -> dict:
        """PUT /schedules/{schedule_id}"""
        return await self._json("PUT", f"/schedules/{schedule_id}", json=fields)

    async def delete_schedule(self, schedule_id: UUID) -> None:
        """DELETE /schedules/{schedule_id}"""
        await self._request("DELETE", f"/schedules/{schedule_id}")

    async def trigger_schedule(self, schedule_id: UUID) -> dict:
        """POST /schedules/{schedule_id}/run"""
        return await self._json("POST", f"/schedules/{schedule_id}/run")

    # Users
    async def list_users(self) -> Any:
        """GET /users"""
        return await self._json("GET", "/users")

    async def create_user(
        self, email: str, role: str = "viewer", **kwargs,
    ) -> dict:
        """POST /users"""
        body = {"email": email, "role": role, **kwargs}
        return await self._json("POST", "/users", json=body)

    async def get_user(self, user_id: UUID) -> dict:
        """GET /users/{user_id}"""
        return await self._json("GET", f"/users/{user_id}")

    async def update_user(self, user_id: UUID, **fields) -> dict:
        """PUT /users/{user_id}"""
        return await self._json("PUT", f"/users/{user_id}", json=fields)

    async def delete_user(self, user_id: UUID) -> None:
        """DELETE /users/{user_id}"""
        await self._request("DELETE", f"/users/{user_id}")

    # Settings
    async def update_azure_settings(self, settings: dict) -> dict:
        """POST /settings/azure"""
        return await self._json("POST", "/settings/azure", json=settings)

    async def update_scan_settings(self, settings: dict) -> dict:
        """POST /settings/scan"""
        return await self._json("POST", "/settings/scan", json=settings)

    async def update_entity_settings(self, settings: dict) -> dict:
        """POST /settings/entities"""
        return await self._json("POST", "/settings/entities", json=settings)

    async def reset_settings(self) -> dict:
        """POST /settings/reset"""
        return await self._json("POST", "/settings/reset")

    # Monitoring
    async def list_monitored_files(self) -> Any:
        """GET /monitoring/files"""
        return await self._json("GET", "/monitoring/files")

    async def enable_file_monitoring(
        self, path: str, risk_tier: str = "HIGH", **kwargs,
    ) -> dict:
        """POST /monitoring/files"""
        body = {"path": path, "risk_tier": risk_tier, **kwargs}
        return await self._json("POST", "/monitoring/files", json=body)

    async def disable_file_monitoring(self, file_id: UUID) -> None:
        """DELETE /monitoring/files/{file_id}"""
        await self._request("DELETE", f"/monitoring/files/{file_id}")

    async def list_access_events(
        self,
        limit: int = 50,
        cursor: str | None = None,
        **filters,
    ) -> dict:
        """GET /monitoring/events"""
        params: dict[str, Any] = {"limit": limit, **filters}
        if cursor:
            params["cursor"] = cursor
        return await self._json("GET", "/monitoring/events", params=params)

    async def iter_access_events(self, **filters) -> AsyncIterator[dict]:
        """Auto-paginating access event iterator."""
        params = {k: v for k, v in filters.items() if v is not None}
        async for item in self._iter_pages("/monitoring/events", params=params):
            yield item

    async def get_file_access_history(self, file_path: str) -> Any:
        """GET /monitoring/events/file/{file_path}"""
        return await self._json("GET", f"/monitoring/events/file/{file_path}")

    async def get_user_access_history(self, user_name: str) -> Any:
        """GET /monitoring/events/user/{user_name}"""
        return await self._json("GET", f"/monitoring/events/user/{user_name}")

    async def get_access_stats(self) -> dict:
        """GET /monitoring/stats"""
        return await self._json("GET", "/monitoring/stats")

    async def detect_access_anomalies(self) -> Any:
        """GET /monitoring/stats/anomalies"""
        return await self._json("GET", "/monitoring/stats/anomalies")

    # Audit
    async def list_audit_logs(
        self,
        limit: int = 50,
        cursor: str | None = None,
        **filters,
    ) -> dict:
        """GET /audit"""
        params: dict[str, Any] = {"limit": limit, **filters}
        if cursor:
            params["cursor"] = cursor
        return await self._json("GET", "/audit", params=params)

    async def iter_audit_logs(self, **filters) -> AsyncIterator[dict]:
        """Auto-paginating audit log iterator."""
        params = {k: v for k, v in filters.items() if v is not None}
        async for item in self._iter_pages("/audit", params=params):
            yield item

    async def get_audit_filters(self) -> dict:
        """GET /audit/filters"""
        return await self._json("GET", "/audit/filters")

    async def get_audit_log(self, log_id: UUID) -> dict:
        """GET /audit/{log_id}"""
        return await self._json("GET", f"/audit/{log_id}")

    async def get_resource_history(
        self, resource_type: str, resource_id: UUID,
    ) -> Any:
        """GET /audit/resource/{resource_type}/{resource_id}"""
        return await self._json(
            "GET", f"/audit/resource/{resource_type}/{resource_id}",
        )

    # Jobs
    async def list_jobs(self) -> Any:
        """GET /jobs"""
        return await self._json("GET", "/jobs")

    async def get_queue_stats(self) -> dict:
        """GET /jobs/stats"""
        return await self._json("GET", "/jobs/stats")

    async def list_failed_jobs(self) -> Any:
        """GET /jobs/failed"""
        return await self._json("GET", "/jobs/failed")

    async def get_job(self, job_id: UUID) -> dict:
        """GET /jobs/{job_id}"""
        return await self._json("GET", f"/jobs/{job_id}")

    async def requeue_job(self, job_id: UUID) -> dict:
        """POST /jobs/{job_id}/requeue"""
        return await self._json("POST", f"/jobs/{job_id}/requeue")

    async def requeue_all_failed(self) -> dict:
        """POST /jobs/requeue-all"""
        return await self._json("POST", "/jobs/requeue-all")

    async def purge_failed_jobs(self) -> dict:
        """POST /jobs/purge"""
        return await self._json("POST", "/jobs/purge")

    async def cancel_job(self, job_id: UUID) -> dict:
        """POST /jobs/{job_id}/cancel"""
        return await self._json("POST", f"/jobs/{job_id}/cancel")

    async def get_worker_status(self) -> dict:
        """GET /jobs/workers/status"""
        return await self._json("GET", "/jobs/workers/status")

    async def update_worker_config(self, config: dict) -> dict:
        """POST /jobs/workers/config"""
        return await self._json("POST", "/jobs/workers/config", json=config)

    # Auth
    async def login(self) -> Any:
        """GET /auth/login -- initiate OAuth login flow."""
        return await self._json("GET", "/auth/login")

    async def auth_callback(self, **params) -> Any:
        """GET /auth/callback -- OAuth callback."""
        return await self._json("GET", "/auth/callback", params=params)

    async def logout(self) -> Any:
        """GET /auth/logout"""
        return await self._json("GET", "/auth/logout")

    async def get_current_user(self) -> dict:
        """GET /auth/me"""
        return await self._json("GET", "/auth/me")

    async def get_token(self, **credentials) -> dict:
        """POST /auth/token"""
        return await self._json("POST", "/auth/token", json=credentials)

    async def auth_status(self) -> dict:
        """GET /auth/status"""
        return await self._json("GET", "/auth/status")

    async def revoke_token(self) -> dict:
        """POST /auth/revoke"""
        return await self._json("POST", "/auth/revoke")

    async def logout_all_sessions(self) -> dict:
        """POST /auth/logout-all"""
        return await self._json("POST", "/auth/logout-all")

    # Remediation
    async def list_remediation_actions(
        self,
        limit: int = 50,
        cursor: str | None = None,
        **filters,
    ) -> dict:
        """GET /remediation"""
        params: dict[str, Any] = {"limit": limit, **filters}
        if cursor:
            params["cursor"] = cursor
        return await self._json("GET", "/remediation", params=params)

    async def iter_remediation_actions(self, **filters) -> AsyncIterator[dict]:
        """Auto-paginating remediation action iterator."""
        params = {k: v for k, v in filters.items() if v is not None}
        async for item in self._iter_pages("/remediation", params=params):
            yield item

    async def get_remediation_action(self, action_id: UUID) -> dict:
        """GET /remediation/{action_id}"""
        return await self._json("GET", f"/remediation/{action_id}")

    async def quarantine_file(self, result_id: UUID, **kwargs) -> dict:
        """POST /remediation/quarantine"""
        body = {"result_id": str(result_id), **kwargs}
        return await self._json("POST", "/remediation/quarantine", json=body)

    async def lockdown_file(self, result_id: UUID, **kwargs) -> dict:
        """POST /remediation/lockdown"""
        body = {"result_id": str(result_id), **kwargs}
        return await self._json("POST", "/remediation/lockdown", json=body)

    async def rollback_action(self, action_id: UUID) -> dict:
        """POST /remediation/rollback"""
        return await self._json(
            "POST", "/remediation/rollback",
            json={"action_id": str(action_id)},
        )

    async def get_remediation_stats(self) -> dict:
        """GET /remediation/stats/summary"""
        return await self._json("GET", "/remediation/stats/summary")

    # Dashboard
    async def get_dashboard_stats(self) -> dict:
        """GET /dashboard/stats"""
        return await self._json("GET", "/dashboard/stats")

    async def get_trends(self, **params) -> dict:
        """GET /dashboard/trends"""
        return await self._json("GET", "/dashboard/trends", params=params or None)

    async def get_entity_trends(self, **params) -> dict:
        """GET /dashboard/entity-trends"""
        return await self._json("GET", "/dashboard/entity-trends", params=params or None)

    async def get_access_heatmap(self, **params) -> dict:
        """GET /dashboard/access-heatmap"""
        return await self._json("GET", "/dashboard/access-heatmap", params=params or None)

    async def get_heatmap(self, job_id: UUID | None = None) -> dict:
        """GET /dashboard/heatmap"""
        params = {}
        if job_id:
            params["job_id"] = str(job_id)
        return await self._json("GET", "/dashboard/heatmap", params=params or None)
