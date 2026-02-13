"""
Base class for Microsoft Graph API adapters.

Extracts shared logic between SharePointAdapter and OneDriveAdapter:
- Client lifecycle (init, lazy creation, close, async context manager)
- Item-to-FileInfo conversion (datetime parsing, owner extraction)
- Exposure level detection from sharing permissions
- Connection testing with error handling
- Statistics reporting
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from types import TracebackType

import httpx

from openlabels.adapters.base import ExposureLevel, FileInfo, FilterConfig, FolderInfo
from openlabels.adapters.graph_client import GraphClient, RateLimiterConfig

logger = logging.getLogger(__name__)


class BaseGraphAdapter:
    """
    Shared base for Graph API-based adapters (SharePoint, OneDrive).

    Both adapters share the same authentication model, client lifecycle,
    item parsing, and exposure detection logic. This base class captures
    that shared domain reality while letting subclasses define their own
    API paths and resource identifiers.
    """

    _adapter_type: str = ""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        rate_config: RateLimiterConfig | None = None,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.rate_config = rate_config

        self._client: GraphClient | None = None
        self._owns_client = False

    @property
    def adapter_type(self) -> str:
        return self._adapter_type

    def supports_delta(self) -> bool:
        """Graph API adapters support delta queries."""
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

    async def __aenter__(self) -> BaseGraphAdapter:
        """Initialize the GraphClient connection."""
        await self._get_client()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Close the GraphClient if we own it."""
        await self.close()

    async def close(self) -> None:
        """Close the GraphClient if we own it."""
        if self._client and self._owns_client:
            await self._client.__aexit__(None, None, None)
            self._client = None

    def _parse_modified(self, item: dict) -> datetime:
        """Parse lastModifiedDateTime from a Graph API item."""
        modified_str = item.get("lastModifiedDateTime", "")
        if modified_str:
            return datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
        return datetime.now(timezone.utc)

    def _parse_owner(self, item: dict) -> str | None:
        """Extract owner info from a Graph API item."""
        if "createdBy" in item:
            created_by = item["createdBy"]
            if "user" in created_by:
                return created_by["user"].get("email") or created_by["user"].get("displayName")
            elif "application" in created_by:
                return created_by["application"].get("displayName")
        return None

    def _determine_exposure(self, item: dict) -> ExposureLevel:
        """Determine exposure level from sharing info."""
        permissions = item.get("permissions", [])

        for perm in permissions:
            link = perm.get("link", {})
            scope = link.get("scope")

            if scope == "anonymous":
                return ExposureLevel.PUBLIC
            elif scope == "organization":
                return ExposureLevel.ORG_WIDE

        if item.get("shared"):
            return ExposureLevel.INTERNAL

        return ExposureLevel.PRIVATE

    def _base_file_info(self, item: dict) -> dict:
        """Build common FileInfo kwargs from a Graph API item."""
        parent_path = item.get("parentReference", {}).get("path", "")
        parent_path = parent_path.replace("/drive/root:", "")

        return {
            "path": f"{parent_path}/{item['name']}",
            "name": item["name"],
            "size": item.get("size", 0),
            "modified": self._parse_modified(item),
            "owner": self._parse_owner(item),
            "exposure": self._determine_exposure(item),
            "adapter": self.adapter_type,
            "item_id": item["id"],
        }

    def _folder_from_item(self, item: dict, **extra) -> FolderInfo:
        """Build a FolderInfo from a Graph API folder item."""
        parent_path = item.get("parentReference", {}).get("path", "")
        parent_path = parent_path.replace("/drive/root:", "")
        folder_meta = item.get("folder", {})

        return FolderInfo(
            path=f"{parent_path}/{item['name']}",
            name=item["name"],
            modified=self._parse_modified(item),
            adapter=self.adapter_type,
            item_id=item["id"],
            child_dir_count=None,  # Graph doesn't separate dir/file counts
            child_file_count=folder_meta.get("childCount"),
            **extra,
        )

    async def _test_connection(self, test_endpoint: str) -> bool:
        """Test if we can connect via Graph API."""
        try:
            client = await self._get_client()
            await client.get(test_endpoint)
            return True
        except (ConnectionError, TimeoutError) as e:
            logger.warning(
                f"{self.adapter_type} connection test failed due to network issue: {e}",
                exc_info=True,
            )
            return False
        except PermissionError as e:
            logger.warning(
                f"{self.adapter_type} connection test failed due to permission denied: {e}",
                exc_info=True,
            )
            return False
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            logger.warning(
                f"{self.adapter_type} connection test failed with unexpected error: "
                f"{type(e).__name__}: {e}",
                exc_info=True,
            )
            return False

    # --- Shared delta-query and folder-listing helpers ---

    async def _iter_delta_files(
        self,
        client: GraphClient,
        initial_path: str,
        resource_path: str,
        resource_id: str,
        resource_kwarg: str,
        filter_config: FilterConfig,
    ) -> AsyncIterator[FileInfo]:
        """Iterate files via delta query, yielding FileInfo objects.

        This is the shared core of the delta branch in ``list_files()``.
        Subclasses supply the endpoint paths and the resource-specific
        FileInfo keyword (``user_id`` or ``site_id``).

        Args:
            client: Active GraphClient.
            initial_path: Full delta endpoint, e.g.
                ``/users/{uid}/drive/root/delta``.
            resource_path: Logical resource key for delta token caching,
                e.g. ``onedrive:{uid}:{drive_id}``.
            resource_id: The resource identifier value (user ID or site ID).
            resource_kwarg: The FileInfo keyword for the resource ID
                (``"user_id"`` or ``"site_id"``).
            filter_config: Filter to apply before yielding.
        """
        items_iter, is_delta = await client.iter_with_delta(
            initial_path, resource_path
        )

        if is_delta:
            logger.info(f"Delta scan for {resource_path}")

        async for item in items_iter:
            if item.get("deleted"):
                yield FileInfo(
                    path=item.get("name", "unknown"),
                    name=item.get("name", "unknown"),
                    size=0,
                    modified=datetime.now(timezone.utc),
                    adapter=self.adapter_type,
                    item_id=item.get("id"),
                    change_type="deleted",
                    **{resource_kwarg: resource_id},
                )
                continue

            if "folder" in item:
                continue

            if "file" in item:
                file_info = FileInfo(
                    **self._base_file_info(item),
                    **{resource_kwarg: resource_id},
                )

                if filter_config.should_include(file_info):
                    file_info.change_type = "modified" if is_delta else None
                    yield file_info

    async def _list_drive_folders_impl(
        self,
        client: GraphClient,
        endpoint_fn,
        resource_kwarg: str,
        resource_id: str,
        path: str,
        recursive: bool,
    ) -> AsyncIterator[FolderInfo]:
        """Shared recursive folder listing.

        Args:
            client: Active GraphClient.
            endpoint_fn: Callable ``(path) -> endpoint_str`` that builds
                the children endpoint for a given folder path.
            resource_kwarg: Keyword for ``_folder_from_item``
                (``"user_id"`` or ``"site_id"``).
            resource_id: Value for that keyword.
            path: Current folder path (``"/"`` for root).
            recursive: Whether to recurse into subfolders.
        """
        endpoint = endpoint_fn(path)

        try:
            items_iter = client.iter_all_pages(endpoint)
            async for item in items_iter:
                if "folder" not in item:
                    continue

                folder_info = self._folder_from_item(
                    item, **{resource_kwarg: resource_id}
                )
                yield folder_info

                if recursive:
                    folder_path = (
                        f"{path}/{item['name']}" if path != "/" else f"/{item['name']}"
                    )
                    async for sub in self._list_drive_folders_impl(
                        client,
                        endpoint_fn,
                        resource_kwarg,
                        resource_id,
                        folder_path,
                        recursive,
                    ):
                        yield sub
        except (
            PermissionError,
            ConnectionError,
            TimeoutError,
            httpx.HTTPStatusError,
            httpx.RequestError,
        ) as e:
            logger.debug(
                f"Cannot list folders at {path} for {resource_id}: {e}"
            )
            return

    def get_stats(self) -> dict:
        """Get adapter statistics including rate limiter stats."""
        if self._client:
            return {
                "adapter": self.adapter_type,
                **self._client.get_stats(),
            }
        return {"adapter": self.adapter_type}
