"""
Base adapter protocol and common types.
"""

from datetime import datetime
from enum import Enum
from typing import Protocol, AsyncIterator, Optional
from dataclasses import dataclass


class ExposureLevel(str, Enum):
    """File exposure/accessibility level."""

    PRIVATE = "PRIVATE"  # Only owner can access
    INTERNAL = "INTERNAL"  # Specific users/groups
    ORG_WIDE = "ORG_WIDE"  # All organization members
    PUBLIC = "PUBLIC"  # Anyone with link / anonymous


@dataclass
class FileInfo:
    """Normalized file information from any adapter."""

    path: str
    name: str
    size: int
    modified: datetime
    owner: Optional[str] = None
    permissions: Optional[dict] = None
    exposure: ExposureLevel = ExposureLevel.PRIVATE

    # Adapter-specific identifiers
    adapter: str = ""
    item_id: Optional[str] = None  # For Graph API items
    site_id: Optional[str] = None  # For SharePoint
    user_id: Optional[str] = None  # For OneDrive


class Adapter(Protocol):
    """Protocol for storage adapters."""

    @property
    def adapter_type(self) -> str:
        """Return the adapter type identifier."""
        ...

    async def list_files(
        self,
        target: str,
        recursive: bool = True,
    ) -> AsyncIterator[FileInfo]:
        """
        List files in the target location.

        Args:
            target: Path, URL, or identifier of the location to scan
            recursive: Whether to scan subdirectories

        Yields:
            FileInfo objects for each file found
        """
        ...

    async def read_file(self, file_info: FileInfo) -> bytes:
        """
        Read file content.

        Args:
            file_info: FileInfo object from list_files

        Returns:
            File content as bytes
        """
        ...

    async def get_metadata(self, file_info: FileInfo) -> FileInfo:
        """
        Get updated metadata for a file.

        Args:
            file_info: FileInfo object to refresh

        Returns:
            Updated FileInfo with current metadata
        """
        ...

    async def test_connection(self, config: dict) -> bool:
        """
        Test if the adapter can connect with the given configuration.

        Args:
            config: Adapter configuration dictionary

        Returns:
            True if connection successful
        """
        ...
