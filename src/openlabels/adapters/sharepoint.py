"""
SharePoint Online adapter via Microsoft Graph API.

Features:
- Rate-limited Graph API access with connection pooling
- Delta queries for incremental scanning
- File/account filtering support
- Exposure level detection from sharing info
"""

import logging
from datetime import datetime, timezone
from typing import AsyncIterator, Optional

from openlabels.adapters.base import Adapter, FileInfo, ExposureLevel, FilterConfig, DEFAULT_FILTER
from openlabels.adapters.graph_client import GraphClient, RateLimiterConfig

logger = logging.getLogger(__name__)


class SharePointAdapter:
    """
    Adapter for SharePoint Online scanning via Graph API.

    Uses shared GraphClient for rate limiting and connection pooling.
    Supports delta queries for efficient incremental scans.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        rate_config: Optional[RateLimiterConfig] = None,
    ):
        """
        Initialize the SharePoint adapter.

        Args:
            tenant_id: Azure AD tenant ID
            client_id: Azure AD application (client) ID
            client_secret: Azure AD client secret
            rate_config: Optional rate limiting configuration
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.rate_config = rate_config

        # GraphClient instance (created on first use)
        self._client: Optional[GraphClient] = None
        self._owns_client = False  # Whether we created the client

    @property
    def adapter_type(self) -> str:
        return "sharepoint"

    def supports_delta(self) -> bool:
        """SharePoint supports delta queries via Graph API."""
        return True

    async def _get_client(self) -> GraphClient:
        """Get or create the GraphClient instance."""
        if self._client is None:
            self._client = GraphClient(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
                rate_config=self.rate_config,
            )
            await self._client.__aenter__()
            self._owns_client = True
        return self._client

    async def close(self) -> None:
        """Close the GraphClient if we own it."""
        if self._client and self._owns_client:
            await self._client.__aexit__(None, None, None)
            self._client = None

    async def list_sites(self) -> list[dict]:
        """List all SharePoint sites accessible to the application."""
        client = await self._get_client()
        return await client.get_all_pages("/sites?search=*")

    async def list_files(
        self,
        target: str,
        recursive: bool = True,
        filter_config: Optional[FilterConfig] = None,
        use_delta: bool = True,
    ) -> AsyncIterator[FileInfo]:
        """
        List files in a SharePoint site.

        Args:
            target: Site ID or site URL
            recursive: Whether to scan subdirectories
            filter_config: Optional filter for file/account exclusions
            use_delta: Whether to use delta queries for incremental sync

        Yields:
            FileInfo objects for each file (after filtering)
        """
        filter_config = filter_config or DEFAULT_FILTER
        client = await self._get_client()

        # Resolve target to site ID
        site_id = target
        if target.startswith("https://"):
            site_info = await client.get(f"/sites/{target.replace('https://', '')}")
            site_id = site_info["id"]

        # Get root drive
        drive = await client.get(f"/sites/{site_id}/drive")
        drive_id = drive["id"]

        # Use delta query if available and requested
        resource_path = f"sharepoint:{site_id}:{drive_id}"

        if use_delta:
            initial_path = f"/sites/{site_id}/drives/{drive_id}/root/delta"
            items, is_delta = await client.get_with_delta(initial_path, resource_path)

            if is_delta:
                logger.info(f"Delta scan returned {len(items)} changed items")

            for item in items:
                # Skip deleted items
                if item.get("deleted"):
                    # Yield with change_type for inventory to handle
                    yield FileInfo(
                        path=item.get("name", "unknown"),
                        name=item.get("name", "unknown"),
                        size=0,
                        modified=datetime.now(timezone.utc),
                        adapter=self.adapter_type,
                        item_id=item.get("id"),
                        site_id=site_id,
                        change_type="deleted",
                    )
                    continue

                # Skip folders
                if "folder" in item:
                    continue

                # Only yield files
                if "file" in item:
                    file_info = self._item_to_file_info(item, site_id)

                    # Apply filter
                    if filter_config.should_include(file_info):
                        file_info.change_type = "modified" if is_delta else None
                        yield file_info
        else:
            # Traditional recursive enumeration
            async for file_info in self._list_drive_items(
                client, site_id, drive_id, "/", recursive, filter_config
            ):
                yield file_info

    async def _list_drive_items(
        self,
        client: GraphClient,
        site_id: str,
        drive_id: str,
        path: str,
        recursive: bool,
        filter_config: FilterConfig,
    ) -> AsyncIterator[FileInfo]:
        """Recursively list items in a drive folder."""
        if path == "/":
            endpoint = f"/sites/{site_id}/drives/{drive_id}/root/children"
        else:
            endpoint = f"/sites/{site_id}/drives/{drive_id}/root:{path}:/children"

        items = await client.get_all_pages(endpoint)

        for item in items:
            if "folder" in item:
                if recursive:
                    folder_path = f"{path}/{item['name']}" if path != "/" else f"/{item['name']}"
                    async for file_info in self._list_drive_items(
                        client, site_id, drive_id, folder_path, recursive, filter_config
                    ):
                        yield file_info

            elif "file" in item:
                file_info = self._item_to_file_info(item, site_id)

                # Apply filter
                if filter_config.should_include(file_info):
                    yield file_info

    def _item_to_file_info(self, item: dict, site_id: str) -> FileInfo:
        """Convert Graph API item to FileInfo."""
        parent_path = item.get("parentReference", {}).get("path", "")
        parent_path = parent_path.replace("/drive/root:", "")

        # Parse datetime
        modified_str = item.get("lastModifiedDateTime", "")
        if modified_str:
            modified = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
        else:
            modified = datetime.now(timezone.utc)

        # Get owner info
        owner = None
        if "createdBy" in item:
            created_by = item["createdBy"]
            if "user" in created_by:
                owner = created_by["user"].get("email") or created_by["user"].get("displayName")
            elif "application" in created_by:
                owner = created_by["application"].get("displayName")

        return FileInfo(
            path=f"{parent_path}/{item['name']}",
            name=item["name"],
            size=item.get("size", 0),
            modified=modified,
            owner=owner,
            exposure=self._determine_exposure(item),
            adapter=self.adapter_type,
            item_id=item["id"],
            site_id=site_id,
        )

    def _determine_exposure(self, item: dict) -> ExposureLevel:
        """Determine exposure level from sharing info."""
        # Check for sharing links
        permissions = item.get("permissions", [])

        for perm in permissions:
            link = perm.get("link", {})
            scope = link.get("scope")

            if scope == "anonymous":
                return ExposureLevel.PUBLIC
            elif scope == "organization":
                return ExposureLevel.ORG_WIDE

        # Check inherited permissions
        if item.get("shared"):
            return ExposureLevel.INTERNAL

        return ExposureLevel.PRIVATE

    async def read_file(self, file_info: FileInfo) -> bytes:
        """Download file content."""
        client = await self._get_client()
        return await client.get_bytes(
            f"/sites/{file_info.site_id}/drive/items/{file_info.item_id}/content"
        )

    async def get_metadata(self, file_info: FileInfo) -> FileInfo:
        """Get updated metadata for a file."""
        client = await self._get_client()
        item = await client.get(
            f"/sites/{file_info.site_id}/drive/items/{file_info.item_id}"
        )
        return self._item_to_file_info(item, file_info.site_id or "")

    async def test_connection(self, config: dict) -> bool:
        """Test if we can connect to SharePoint."""
        try:
            client = await self._get_client()
            await client.get("/sites?$top=1")
            return True
        except (ConnectionError, TimeoutError) as e:
            logger.warning(
                f"SharePoint connection test failed due to network issue: {e}",
                exc_info=True
            )
            return False
        except PermissionError as e:
            logger.warning(
                f"SharePoint connection test failed due to permission denied: {e}",
                exc_info=True
            )
            return False
        except Exception as e:
            logger.warning(
                f"SharePoint connection test failed with unexpected error: {type(e).__name__}: {e}",
                exc_info=True
            )
            return False

    def get_stats(self) -> dict:
        """Get adapter statistics including rate limiter stats."""
        if self._client:
            return {
                "adapter": self.adapter_type,
                **self._client.get_stats(),
            }
        return {"adapter": self.adapter_type}
