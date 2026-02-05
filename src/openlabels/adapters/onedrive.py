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

from openlabels.adapters.base import Adapter, FileInfo, ExposureLevel, FilterConfig, DEFAULT_FILTER
from openlabels.adapters.graph_client import GraphClient, RateLimiterConfig

logger = logging.getLogger(__name__)


class OneDriveAdapter:
    """
    Adapter for OneDrive for Business scanning via Graph API.

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
        Initialize the OneDrive adapter.

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
        self._owns_client = False

    @property
    def adapter_type(self) -> str:
        return "onedrive"

    def supports_delta(self) -> bool:
        """OneDrive supports delta queries via Graph API."""
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

    async def list_users(self) -> list[dict]:
        """List all users with OneDrive licenses."""
        client = await self._get_client()
        # Filter for users with assigned licenses
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
        except Exception as e:
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
        except Exception as e:
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
            user_id=user_id,
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
            f"/users/{file_info.user_id}/drive/items/{file_info.item_id}/content"
        )

    async def get_metadata(self, file_info: FileInfo) -> FileInfo:
        """Get updated metadata for a file."""
        client = await self._get_client()
        item = await client.get(
            f"/users/{file_info.user_id}/drive/items/{file_info.item_id}"
        )
        return self._item_to_file_info(item, file_info.user_id or "")

    async def test_connection(self, config: dict) -> bool:
        """Test if we can connect to OneDrive."""
        try:
            client = await self._get_client()
            await client.get("/users?$top=1")
            return True
        except (ConnectionError, TimeoutError) as e:
            logger.warning(
                f"OneDrive connection test failed due to network issue: {e}",
                exc_info=True
            )
            return False
        except PermissionError as e:
            logger.warning(
                f"OneDrive connection test failed due to permission denied: {e}",
                exc_info=True
            )
            return False
        except Exception as e:
            logger.warning(
                f"OneDrive connection test failed with unexpected error: {type(e).__name__}: {e}",
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
