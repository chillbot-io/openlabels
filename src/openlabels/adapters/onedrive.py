"""
OneDrive for Business adapter via Microsoft Graph API.

Features:
- Rate-limited Graph API access with connection pooling
- Delta queries for incremental scanning
- File/account filtering support
- Exposure level detection from sharing info
"""

import logging
from datetime import datetime, timezone
from typing import AsyncIterator, Optional

import httpx

from openlabels.adapters.base import FileInfo, FilterConfig, DEFAULT_FILTER
from openlabels.adapters.graph_base import BaseGraphAdapter
from openlabels.adapters.graph_client import GraphClient

logger = logging.getLogger(__name__)


class OneDriveAdapter(BaseGraphAdapter):
    """
    Adapter for OneDrive for Business scanning via Graph API.

    Uses shared GraphClient for rate limiting and connection pooling.
    Supports delta queries for efficient incremental scans.
    """

    _adapter_type = "onedrive"

    async def list_users(self) -> list[dict]:
        """List all users with OneDrive licenses."""
        client = await self._get_client()
        return await client.get_all_pages(
            "/users?$filter=assignedLicenses/$count ne 0&$count=true"
        )

    async def list_files(
        self,
        target: str,
        recursive: bool = True,
        filter_config: Optional[FilterConfig] = None,
        use_delta: bool = True,
    ) -> AsyncIterator[FileInfo]:
        """
        List files in a user's OneDrive.

        Args:
            target: User ID or user principal name (email)
            recursive: Whether to scan subdirectories
            filter_config: Optional filter for file/account exclusions
            use_delta: Whether to use delta queries for incremental sync

        Yields:
            FileInfo objects for each file (after filtering)
        """
        filter_config = filter_config or DEFAULT_FILTER
        client = await self._get_client()

        user_id = target

        # Get user's drive
        try:
            drive = await client.get(f"/users/{user_id}/drive")
        except (ConnectionError, TimeoutError) as e:
            logger.warning(
                f"Cannot access OneDrive for {user_id} due to network issue: {e}",
                exc_info=True
            )
            return
        except PermissionError as e:
            logger.warning(
                f"Cannot access OneDrive for {user_id} - permission denied: {e}",
                exc_info=True
            )
            return
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            logger.warning(
                f"Cannot access OneDrive for {user_id} - unexpected error ({type(e).__name__}): {e}",
                exc_info=True
            )
            return

        drive_id = drive["id"]

        # Use delta query if available and requested
        resource_path = f"onedrive:{user_id}:{drive_id}"

        if use_delta:
            initial_path = f"/users/{user_id}/drive/root/delta"
            items, is_delta = await client.get_with_delta(initial_path, resource_path)

            if is_delta:
                logger.info(f"Delta scan for {user_id} returned {len(items)} changed items")

            for item in items:
                # Skip deleted items
                if item.get("deleted"):
                    yield FileInfo(
                        path=item.get("name", "unknown"),
                        name=item.get("name", "unknown"),
                        size=0,
                        modified=datetime.now(timezone.utc),
                        adapter=self.adapter_type,
                        item_id=item.get("id"),
                        user_id=user_id,
                        change_type="deleted",
                    )
                    continue

                # Skip folders
                if "folder" in item:
                    continue

                # Only yield files
                if "file" in item:
                    file_info = self._item_to_file_info(item, user_id)

                    # Apply filter
                    if filter_config.should_include(file_info):
                        file_info.change_type = "modified" if is_delta else None
                        yield file_info
        else:
            # Traditional recursive enumeration
            async for file_info in self._list_drive_items(
                client, user_id, "/", recursive, filter_config
            ):
                yield file_info

    async def _list_drive_items(
        self,
        client: GraphClient,
        user_id: str,
        path: str,
        recursive: bool,
        filter_config: FilterConfig,
    ) -> AsyncIterator[FileInfo]:
        """Recursively list items in a user's drive folder."""
        if path == "/":
            endpoint = f"/users/{user_id}/drive/root/children"
        else:
            endpoint = f"/users/{user_id}/drive/root:{path}:/children"

        try:
            items = await client.get_all_pages(endpoint)
        except PermissionError as e:
            # Handle 403 for inaccessible folders
            logger.debug(
                f"Cannot access {path} for {user_id} - permission denied: {e}",
                exc_info=True
            )
            return
        except (ConnectionError, TimeoutError) as e:
            logger.debug(
                f"Cannot access {path} for {user_id} - network error: {e}",
                exc_info=True
            )
            return
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            # Log unexpected errors with full context for debugging
            logger.debug(
                f"Cannot access {path} for {user_id} - unexpected error ({type(e).__name__}): {e}",
                exc_info=True
            )
            return

        for item in items:
            if "folder" in item:
                if recursive:
                    folder_path = f"{path}/{item['name']}" if path != "/" else f"/{item['name']}"
                    async for file_info in self._list_drive_items(
                        client, user_id, folder_path, recursive, filter_config
                    ):
                        yield file_info

            elif "file" in item:
                file_info = self._item_to_file_info(item, user_id)

                # Apply filter
                if filter_config.should_include(file_info):
                    yield file_info

    def _item_to_file_info(self, item: dict, user_id: str) -> FileInfo:
        """Convert Graph API item to FileInfo."""
        return FileInfo(
            **self._base_file_info(item),
            user_id=user_id,
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
            f"/users/{file_info.user_id}/drive/items/{file_info.item_id}/content"
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
            f"/users/{file_info.user_id}/drive/items/{file_info.item_id}"
        )
        return self._item_to_file_info(item, file_info.user_id or "")

    async def test_connection(self, config: dict) -> bool:
        """Test if we can connect to OneDrive."""
        return await self._test_connection("/users?$top=1")
