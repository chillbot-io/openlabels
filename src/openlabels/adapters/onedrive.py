"""
OneDrive for Business adapter via Microsoft Graph API.
"""

from datetime import datetime
from typing import AsyncIterator, Optional

import httpx

from openlabels.adapters.base import Adapter, FileInfo, ExposureLevel


class OneDriveAdapter:
    """Adapter for OneDrive for Business scanning via Graph API."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ):
        """
        Initialize the OneDrive adapter.

        Args:
            tenant_id: Azure AD tenant ID
            client_id: Azure AD application (client) ID
            client_secret: Azure AD client secret
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._access_token: Optional[str] = None
        self._token_expires: Optional[datetime] = None

    @property
    def adapter_type(self) -> str:
        return "onedrive"

    async def _get_token(self) -> str:
        """Get or refresh access token."""
        if self._access_token and self._token_expires:
            if datetime.utcnow() < self._token_expires:
                return self._access_token

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
            response.raise_for_status()
            data = response.json()

            self._access_token = data["access_token"]
            self._token_expires = datetime.utcnow()

            return self._access_token

    async def _graph_get(self, endpoint: str) -> dict:
        """Make a GET request to Graph API."""
        token = await self._get_token()
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://graph.microsoft.com/v1.0{endpoint}",
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()
            return response.json()

    async def _graph_get_binary(self, endpoint: str) -> bytes:
        """Download binary content from Graph API."""
        token = await self._get_token()
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://graph.microsoft.com/v1.0{endpoint}",
                headers={"Authorization": f"Bearer {token}"},
                follow_redirects=True,
            )
            response.raise_for_status()
            return response.content

    async def list_users(self) -> list[dict]:
        """List users with OneDrive."""
        data = await self._graph_get("/users?$filter=assignedLicenses/$count gt 0")
        return data.get("value", [])

    async def list_files(
        self,
        target: str,
        recursive: bool = True,
    ) -> AsyncIterator[FileInfo]:
        """
        List files in a user's OneDrive.

        Args:
            target: User ID or email
            recursive: Whether to scan subdirectories
        """
        user_id = target

        # Get user's drive
        drive = await self._graph_get(f"/users/{user_id}/drive")
        drive_id = drive["id"]

        # List files recursively
        async for file_info in self._list_drive_items(user_id, drive_id, "/", recursive):
            yield file_info

    async def _list_drive_items(
        self,
        user_id: str,
        drive_id: str,
        path: str,
        recursive: bool,
    ) -> AsyncIterator[FileInfo]:
        """Recursively list items in a drive folder."""
        if path == "/":
            endpoint = f"/users/{user_id}/drive/root/children"
        else:
            endpoint = f"/users/{user_id}/drive/root:{path}:/children"

        try:
            data = await self._graph_get(endpoint)
        except httpx.HTTPStatusError:
            return  # Skip inaccessible folders

        for item in data.get("value", []):
            if "folder" in item:
                if recursive:
                    folder_path = f"{path}/{item['name']}" if path != "/" else f"/{item['name']}"
                    async for file_info in self._list_drive_items(
                        user_id, drive_id, folder_path, recursive
                    ):
                        yield file_info
            elif "file" in item:
                yield self._item_to_file_info(item, user_id)

        # Handle pagination
        next_link = data.get("@odata.nextLink")
        while next_link:
            endpoint = next_link.replace("https://graph.microsoft.com/v1.0", "")
            data = await self._graph_get(endpoint)

            for item in data.get("value", []):
                if "file" in item:
                    yield self._item_to_file_info(item, user_id)
                elif "folder" in item and recursive:
                    folder_path = item.get("parentReference", {}).get("path", "") + "/" + item["name"]
                    folder_path = folder_path.replace("/drive/root:", "")
                    async for file_info in self._list_drive_items(
                        user_id, drive_id, folder_path, recursive
                    ):
                        yield file_info

            next_link = data.get("@odata.nextLink")

    def _item_to_file_info(self, item: dict, user_id: str) -> FileInfo:
        """Convert Graph API item to FileInfo."""
        parent_path = item.get("parentReference", {}).get("path", "")
        parent_path = parent_path.replace("/drive/root:", "")

        return FileInfo(
            path=f"{parent_path}/{item['name']}",
            name=item["name"],
            size=item.get("size", 0),
            modified=datetime.fromisoformat(
                item.get("lastModifiedDateTime", "").replace("Z", "+00:00")
            ),
            owner=item.get("createdBy", {}).get("user", {}).get("email"),
            exposure=self._determine_exposure(item),
            adapter=self.adapter_type,
            item_id=item["id"],
            user_id=user_id,
        )

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

    async def read_file(self, file_info: FileInfo) -> bytes:
        """Download file content."""
        return await self._graph_get_binary(
            f"/users/{file_info.user_id}/drive/items/{file_info.item_id}/content"
        )

    async def get_metadata(self, file_info: FileInfo) -> FileInfo:
        """Get updated metadata for a file."""
        item = await self._graph_get(
            f"/users/{file_info.user_id}/drive/items/{file_info.item_id}"
        )
        return self._item_to_file_info(item, file_info.user_id)

    async def test_connection(self, config: dict) -> bool:
        """Test if we can connect to OneDrive."""
        try:
            await self._get_token()
            return True
        except Exception:
            return False
