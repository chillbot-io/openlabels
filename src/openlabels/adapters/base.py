"""
Base adapter protocol and common types.

Provides:
- FileInfo dataclass for normalized file metadata
- ExposureLevel enum for access classification
- FilterConfig for file/account filtering
- ReadAdapter protocol for scanning operations
- RemediationAdapter protocol for write/remediation operations
"""

from __future__ import annotations

import fnmatch
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import TracebackType
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# Rust file filter acceleration
_USE_RUST_FILTER = False
_RustFileFilter = None
try:
    from openlabels_matcher import FileFilter as _RustFileFilter
    _USE_RUST_FILTER = True
    logger.info("File filter: using Rust acceleration")
except ImportError:
    logger.info("File filter: using Python fallback")


class ExposureLevel(str, Enum):
    """File exposure/accessibility level."""

    PRIVATE = "PRIVATE"  # Only owner can access
    INTERNAL = "INTERNAL"  # Specific users/groups
    ORG_WIDE = "ORG_WIDE"  # All organization members
    PUBLIC = "PUBLIC"  # Anyone with link / anonymous


@dataclass
class FilterConfig:
    """
    Configuration for filtering files during enumeration.

    Supports:
    - File extension exclusions (e.g., .tmp, .log)
    - Path pattern exclusions (e.g., node_modules/*, .git/*)
    - Account/owner exclusions (e.g., service accounts)
    - Size limits (min/max bytes)
    """

    # File extensions to exclude (without dot, case-insensitive)
    exclude_extensions: list[str] = field(default_factory=list)

    # Path patterns to exclude (glob-style: *, ?, [seq])
    exclude_patterns: list[str] = field(default_factory=list)

    # Accounts/owners to exclude (exact match or pattern)
    exclude_accounts: list[str] = field(default_factory=list)

    # Size limits (None = no limit)
    min_size_bytes: int | None = None
    max_size_bytes: int | None = None

    # Common presets that can be enabled
    exclude_temp_files: bool = True
    exclude_system_dirs: bool = True

    def __post_init__(self):
        """Apply presets after initialization."""
        # Copy lists to avoid mutating caller's arguments
        extensions = list(self.exclude_extensions)
        patterns = list(self.exclude_patterns)

        if self.exclude_temp_files:
            extensions.extend([
                "tmp", "temp", "bak", "swp", "swo", "pyc", "pyo",
                "class", "o", "obj", "cache",
            ])

        if self.exclude_system_dirs:
            patterns.extend([
                ".git/*", ".svn/*", ".hg/*",
                "node_modules/*", "__pycache__/*",
                ".venv/*", "venv/*", ".env/*",
                "*.egg-info/*", "dist/*", "build/*",
                ".tox/*", ".pytest_cache/*",
            ])

        self.exclude_extensions = extensions
        self.exclude_patterns = patterns

        # Normalize extensions (lowercase, no dot)
        self.exclude_extensions = [
            ext.lower().lstrip(".") for ext in self.exclude_extensions
        ]

        # Compile Rust filter if available
        self._rust_filter = None
        if _USE_RUST_FILTER and _RustFileFilter is not None:
            self._rust_filter = _RustFileFilter(
                self.exclude_extensions,
                self.exclude_patterns,
                self.exclude_accounts,
                self.min_size_bytes,
                self.max_size_bytes,
            )

    def should_include(self, file_info: FileInfo) -> bool:
        """
        Check if a file should be included based on filter rules.

        Uses Rust acceleration when available for O(1) extension lookup
        and pre-compiled glob patterns.

        Args:
            file_info: File to check

        Returns:
            True if file passes all filters, False to exclude
        """
        # Rust fast path
        if self._rust_filter is not None:
            return self._rust_filter.should_include(
                file_info.name,
                file_info.path,
                file_info.owner,
                file_info.size,
            )

        # Python fallback
        # Check extension
        if self.exclude_extensions:
            ext = file_info.name.rsplit(".", 1)[-1].lower() if "." in file_info.name else ""
            if ext in self.exclude_extensions:
                return False

        # Check path patterns
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(file_info.path, pattern):
                return False
            # Also check if any path component matches
            if fnmatch.fnmatch(file_info.path, f"*/{pattern}"):
                return False

        # Check account exclusion
        if self.exclude_accounts and file_info.owner:
            owner_lower = file_info.owner.lower()
            for account in self.exclude_accounts:
                # Support both exact match and pattern
                if account.lower() == owner_lower:
                    return False
                if "*" in account or "?" in account:
                    if fnmatch.fnmatch(owner_lower, account.lower()):
                        return False

        # Check size limits
        if self.min_size_bytes is not None and file_info.size < self.min_size_bytes:
            return False
        if self.max_size_bytes is not None and file_info.size > self.max_size_bytes:
            return False

        return True


# Default filter configuration
DEFAULT_FILTER = FilterConfig()

# Extensions that support label metadata via cloud object store re-upload.
# Shared by S3Adapter and GCSAdapter (Phase L).
LABEL_COMPATIBLE_EXTENSIONS = frozenset({
    ".docx", ".xlsx", ".pptx", ".pdf",
    ".doc", ".xls", ".ppt",
    ".csv", ".tsv", ".json", ".xml",
    ".txt", ".md", ".rst", ".html", ".htm",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
    ".zip", ".tar", ".gz",
})


def is_label_compatible(name: str) -> bool:
    """Check if a file type supports label metadata via cloud object store re-upload."""
    dot = name.rfind(".")
    if dot == -1:
        return False
    return name[dot:].lower() in LABEL_COMPATIBLE_EXTENSIONS


@dataclass
class PartitionSpec:
    """
    Defines a key-range partition for parallel scanning.

    Used by the coordinator to tell each worker which slice of the
    keyspace to enumerate.  Adapter-specific interpretation:
    - S3/GCS/Azure Blob: lexicographic key range within the bucket
    - Filesystem: a specific subdirectory path
    - SharePoint: a specific site ID
    - OneDrive: a specific user ID
    """

    # Lexicographic key boundaries (inclusive start, exclusive end)
    start_after: str | None = None  # List keys > this value
    end_before: str | None = None   # Stop when key >= this value

    # Prefix scope (combined with adapter prefix)
    prefix: str | None = None

    # Direct path for filesystem/SharePoint/OneDrive partitioning
    directory: str | None = None
    site_id: str | None = None
    user_id: str | None = None

    def to_dict(self) -> dict:
        """Serialize for JSONB storage."""
        return {k: v for k, v in {
            "start_after": self.start_after,
            "end_before": self.end_before,
            "prefix": self.prefix,
            "directory": self.directory,
            "site_id": self.site_id,
            "user_id": self.user_id,
        }.items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict) -> PartitionSpec:
        """Deserialize from JSONB."""
        return cls(
            start_after=data.get("start_after"),
            end_before=data.get("end_before"),
            prefix=data.get("prefix"),
            directory=data.get("directory"),
            site_id=data.get("site_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class FileInfo:
    """Normalized file information from any adapter."""

    path: str
    name: str
    size: int
    modified: datetime
    owner: str | None = None
    permissions: dict | None = None
    exposure: ExposureLevel = ExposureLevel.PRIVATE

    # Adapter-specific identifiers
    adapter: str = ""
    item_id: str | None = None  # For Graph API items
    site_id: str | None = None  # For SharePoint
    user_id: str | None = None  # For OneDrive

    # Delta tracking
    change_type: str | None = None  # 'created', 'modified', 'deleted' for delta queries

    @classmethod
    def from_scan_result(
        cls,
        result: object,
        adapter: str = "filesystem",
        *,
        exposure: ExposureLevel | None = None,
        item_id_override: str | None = None,
    ) -> FileInfo:
        """Build a FileInfo from a ScanResult (or any duck-typed equivalent).

        Args:
            result: Object with file_path, file_name, file_size,
                    file_modified, and adapter_item_id attributes.
            adapter: Adapter identifier (e.g. "filesystem", "sharepoint").
            exposure: Optional exposure level override.
            item_id_override: If set, used instead of result.adapter_item_id.
        """
        return cls(
            path=result.file_path,
            name=result.file_name,
            size=result.file_size or 0,
            modified=result.file_modified or datetime.now(timezone.utc),
            adapter=adapter,
            item_id=item_id_override if item_id_override is not None else getattr(result, "adapter_item_id", None),
            exposure=exposure if exposure is not None else ExposureLevel.PRIVATE,
        )


@dataclass
class FolderInfo:
    """Normalized folder information from any adapter.

    Used by the directory tree bootstrap pipeline to populate
    the ``directory_tree`` table.  Deliberately lightweight —
    security descriptors are collected in a separate pass.
    """

    path: str
    name: str  # basename only
    modified: datetime | None = None
    adapter: str = ""

    # Filesystem-native identifiers (MFT ref / inode)
    inode: int | None = None
    parent_inode: int | None = None

    # Child counts (when available from stat / iterdir)
    child_dir_count: int | None = None
    child_file_count: int | None = None

    # Adapter-specific identifiers
    item_id: str | None = None  # For Graph API items
    site_id: str | None = None  # For SharePoint
    user_id: str | None = None  # For OneDrive


class ReadAdapter(Protocol):
    """Protocol for storage adapters (read/scan operations).

    All adapters must satisfy this protocol.  Use as an async context
    manager to manage adapter resources (connections, sessions)::

        async with SharePointAdapter(credentials) as adapter:
            async for file_info in adapter.list_files(site_id):
                content = await adapter.read_file(file_info)
    """

    @property
    def adapter_type(self) -> str:
        """Return the adapter type identifier."""
        ...

    async def list_files(
        self,
        target: str,
        recursive: bool = True,
        filter_config: FilterConfig | None = None,
    ) -> AsyncIterator[FileInfo]:
        """List files in the target location.

        Args:
            target: Path, URL, or identifier of the location to scan
            recursive: Whether to scan subdirectories
            filter_config: Optional filter configuration for exclusions

        Yields:
            FileInfo objects for each file found (after filtering)
        """
        ...

    async def list_folders(
        self,
        target: str,
        recursive: bool = True,
    ) -> AsyncIterator[FolderInfo]:
        """List directories in the target location.

        Used by the directory tree bootstrap pipeline.  Implementations
        should yield one :class:`FolderInfo` per directory found.

        Args:
            target: Path, URL, or identifier of the location to scan
            recursive: Whether to descend into subdirectories

        Yields:
            FolderInfo objects for each directory found
        """
        ...

    async def read_file(
        self,
        file_info: FileInfo,
        max_size_bytes: int = 100 * 1024 * 1024,
    ) -> bytes:
        """Read file content with size limit.

        Args:
            file_info: FileInfo object from list_files
            max_size_bytes: Maximum file size to read (default 100MB)

        Returns:
            File content as bytes

        Raises:
            ValueError: If file exceeds max_size_bytes
        """
        ...

    async def get_metadata(self, file_info: FileInfo) -> FileInfo:
        """Get updated metadata for a file.

        Args:
            file_info: FileInfo object to refresh

        Returns:
            Updated FileInfo with current metadata
        """
        ...

    async def test_connection(self, config: dict) -> bool:
        """Test if the adapter can connect with the given configuration.

        Args:
            config: Adapter configuration dictionary

        Returns:
            True if connection successful
        """
        ...

    def supports_delta(self) -> bool:
        """Check if adapter supports delta/incremental queries.

        Returns:
            True if adapter can track changes incrementally
        """
        ...

    async def __aenter__(self) -> ReadAdapter:
        """Initialize adapter resources (connections, sessions)."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Clean up adapter resources."""
        ...


@runtime_checkable
class RemediationAdapter(Protocol):
    """Protocol for adapters that support write/remediation operations.

    Not all adapters implement this — only those that can move files,
    read/write ACLs, etc.  Use :func:`supports_remediation` to check
    at runtime.
    """

    async def move_file(self, file_info: FileInfo, dest_path: str) -> bool:
        """Move a file to a new location (for quarantine).

        Args:
            file_info: FileInfo object of the file to move
            dest_path: Destination path

        Returns:
            True if move successful
        """
        ...

    async def get_acl(self, file_info: FileInfo) -> dict | None:
        """Get the access control list for a file.

        Args:
            file_info: FileInfo object

        Returns:
            Dict containing ACL information, or None if not supported
        """
        ...

    async def set_acl(self, file_info: FileInfo, acl: dict) -> bool:
        """Set the access control list for a file (for lockdown/rollback).

        Args:
            file_info: FileInfo object
            acl: ACL dict to apply

        Returns:
            True if ACL applied successfully
        """
        ...


def supports_remediation(adapter: ReadAdapter) -> bool:
    """Check whether *adapter* supports remediation operations."""
    return isinstance(adapter, RemediationAdapter)


# --- Shared cloud-adapter helpers ---


def resolve_prefix(prefix: str, target: str) -> str:
    """Join a base prefix and a target sub-path, skipping empty parts."""
    parts = [p for p in (prefix, target) if p]
    return "/".join(parts)


def validate_file_size(file_info: FileInfo, max_size_bytes: int) -> None:
    """Raise :class:`ValueError` if *file_info.size* exceeds *max_size_bytes*."""
    if file_info.size > max_size_bytes:
        raise ValueError(
            f"File too large for processing: {file_info.size} bytes "
            f"(max: {max_size_bytes} bytes). File: {file_info.path}"
        )


def validate_content_size(
    content: bytes, max_size_bytes: int, file_path: str
) -> None:
    """Raise :class:`ValueError` if downloaded *content* exceeds *max_size_bytes*."""
    if len(content) > max_size_bytes:
        raise ValueError(
            f"File content exceeds limit: {len(content)} bytes "
            f"(max: {max_size_bytes} bytes). File: {file_path}"
        )
