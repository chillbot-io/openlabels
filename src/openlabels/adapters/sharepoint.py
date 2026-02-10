"""
SharePoint Online adapter via Microsoft Graph API.

Features:
- Rate-limited Graph API access with connection pooling
- Delta queries for incremental scanning
- File/account filtering support
- Exposure level detection from sharing info
"""

import logging
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Optional

from openlabels.adapters.base import DEFAULT_FILTER, FileInfo, FilterConfig
from openlabels.adapters.graph_base import BaseGraphAdapter
from openlabels.adapters.graph_client import GraphClient

logger = logging.getLogger(__name__)


class SharePointAdapter(BaseGraphAdapter):
    """
    Adapter for SharePoint Online scanning via Graph API.

    Uses shared GraphClient for rate limiting and connection pooling.
    Supports delta queries for efficient incremental scans.
    """

    _adapter_type = "sharepoint"

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
            items_iter, is_delta = await client.iter_with_delta(initial_path, resource_path)

            if is_delta:
                logger.info(f"Delta scan for {resource_path}")

            async for item in items_iter:
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

        async for item in client.iter_all_pages(endpoint):
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
        return FileInfo(
            **self._base_file_info(item),
            site_id=site_id,
        )

    async def read_file(
        self,
        file_info: FileInfo,
        max_size_bytes: int = 100 * 1024 * 1024,
    ) -> bytes:
        """Download file content with size limit."""
        if file_info.size > max_size_bytes:
            raise ValueError(
                f"File too large for processing: {file_info.size} bytes "
                f"(max: {max_size_bytes} bytes). File: {file_info.path}"
            )
        client = await self._get_client()
        content = await client.get_bytes(
            f"/sites/{file_info.site_id}/drive/items/{file_info.item_id}/content"
        )
        if len(content) > max_size_bytes:
            raise ValueError(
                f"File content exceeds limit: {len(content)} bytes "
                f"(max: {max_size_bytes} bytes). File: {file_info.path}"
            )
        return content

    async def get_metadata(self, file_info: FileInfo) -> FileInfo:
        """Get updated metadata for a file."""
        client = await self._get_client()
        item = await client.get(
            f"/sites/{file_info.site_id}/drive/items/{file_info.item_id}"
        )
        return self._item_to_file_info(item, file_info.site_id or "")

    async def test_connection(self, config: dict) -> bool:
        """Test if we can connect to SharePoint."""
        return await self._test_connection("/sites?$top=1")
