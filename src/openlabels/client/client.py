"""
Python SDK client for OpenLabels API.
"""

from typing import Optional
from uuid import UUID

import httpx


class OpenLabelsClient:
    """
    Python client for OpenLabels API.

    Example:
        client = OpenLabelsClient("http://localhost:8000", token="...")
        scans = await client.list_scans()
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        token: Optional[str] = None,
    ):
        """
        Initialize the client.

        Args:
            base_url: OpenLabels server URL
            token: Optional Bearer token for authentication
        """
        self.base_url = base_url.rstrip("/")
        self.token = token

    def _headers(self) -> dict:
        """Get request headers."""
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def health(self) -> dict:
        """Check server health."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/health",
                headers=self._headers(),
            )
            response.raise_for_status()
            return response.json()

    # Scans
    async def create_scan(self, target_id: UUID, name: Optional[str] = None) -> dict:
        """Create a new scan."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/scans",
                headers=self._headers(),
                json={"target_id": str(target_id), "name": name},
            )
            response.raise_for_status()
            return response.json()

    async def list_scans(
        self,
        status: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> dict:
        """List scan jobs."""
        params = {"page": page, "limit": limit}
        if status:
            params["status"] = status

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/scans",
                headers=self._headers(),
                params=params,
            )
            response.raise_for_status()
            return response.json()

    async def get_scan(self, scan_id: UUID) -> dict:
        """Get scan details."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/scans/{scan_id}",
                headers=self._headers(),
            )
            response.raise_for_status()
            return response.json()

    async def cancel_scan(self, scan_id: UUID) -> None:
        """Cancel a scan."""
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                f"{self.base_url}/api/scans/{scan_id}",
                headers=self._headers(),
            )
            response.raise_for_status()

    # Results
    async def list_results(
        self,
        job_id: Optional[UUID] = None,
        risk_tier: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
    ) -> dict:
        """List scan results."""
        params = {"page": page, "limit": limit}
        if job_id:
            params["job_id"] = str(job_id)
        if risk_tier:
            params["risk_tier"] = risk_tier

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/results",
                headers=self._headers(),
                params=params,
            )
            response.raise_for_status()
            return response.json()

    async def get_result(self, result_id: UUID) -> dict:
        """Get result details."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/results/{result_id}",
                headers=self._headers(),
            )
            response.raise_for_status()
            return response.json()

    async def get_result_stats(self, job_id: Optional[UUID] = None) -> dict:
        """Get result statistics."""
        params = {}
        if job_id:
            params["job_id"] = str(job_id)

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/results/stats",
                headers=self._headers(),
                params=params,
            )
            response.raise_for_status()
            return response.json()

    # Targets
    async def list_targets(self, adapter: Optional[str] = None) -> list[dict]:
        """List scan targets."""
        params = {}
        if adapter:
            params["adapter"] = adapter

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/targets",
                headers=self._headers(),
                params=params,
            )
            response.raise_for_status()
            return response.json()

    async def create_target(
        self,
        name: str,
        adapter: str,
        config: dict,
    ) -> dict:
        """Create a scan target."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/targets",
                headers=self._headers(),
                json={"name": name, "adapter": adapter, "config": config},
            )
            response.raise_for_status()
            return response.json()

    # Dashboard
    async def get_dashboard_stats(self) -> dict:
        """Get dashboard statistics."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/dashboard/stats",
                headers=self._headers(),
            )
            response.raise_for_status()
            return response.json()

    async def get_heatmap(self, job_id: Optional[UUID] = None) -> dict:
        """Get heatmap data."""
        params = {}
        if job_id:
            params["job_id"] = str(job_id)

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/dashboard/heatmap",
                headers=self._headers(),
                params=params,
            )
            response.raise_for_status()
            return response.json()
