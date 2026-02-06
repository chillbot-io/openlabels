"""
Base adapter protocol and common types.

Provides:
- FileInfo dataclass for normalized file metadata
- ExposureLevel enum for access classification
- FilterConfig for file/account filtering
- Adapter protocol defining the contract for all adapters
"""

import fnmatch
import logging
from datetime import datetime
from enum import Enum
from typing import Protocol, AsyncIterator, Optional
from dataclasses import dataclass, field

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
    min_size_bytes: Optional[int] = None
    max_size_bytes: Optional[int] = None

    # Common presets that can be enabled
    exclude_temp_files: bool = True
    exclude_system_dirs: bool = True

    def __post_init__(self):
        """Apply presets after initialization."""
        if self.exclude_temp_files:
            self.exclude_extensions.extend([
                "tmp", "temp", "bak", "swp", "swo", "pyc", "pyo",
                "class", "o", "obj", "cache",
            ])

        if self.exclude_system_dirs:
            self.exclude_patterns.extend([
                ".git/*", ".svn/*", ".hg/*",
                "node_modules/*", "__pycache__/*",
                ".venv/*", "venv/*", ".env/*",
                "*.egg-info/*", "dist/*", "build/*",
                ".tox/*", ".pytest_cache/*",
            ])

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

    def should_include(self, file_info: "FileInfo") -> bool:
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

    # Delta tracking
    change_type: Optional[str] = None  # 'created', 'modified', 'deleted' for delta queries


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
        filter_config: Optional[FilterConfig] = None,
    ) -> AsyncIterator[FileInfo]:
        """
        List files in the target location.

        Args:
            target: Path, URL, or identifier of the location to scan
            recursive: Whether to scan subdirectories
            filter_config: Optional filter configuration for exclusions

        Yields:
            FileInfo objects for each file found (after filtering)
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

    def supports_delta(self) -> bool:
        """
        Check if adapter supports delta/incremental queries.

        Returns:
            True if adapter can track changes incrementally
        """
        ...

    # Remediation methods

    async def move_file(self, file_info: FileInfo, dest_path: str) -> bool:
        """
        Move a file to a new location (for quarantine).

        Args:
            file_info: FileInfo object of the file to move
            dest_path: Destination path

        Returns:
            True if move successful
        """
        ...

    async def get_acl(self, file_info: FileInfo) -> Optional[dict]:
        """
        Get the access control list for a file.

        Args:
            file_info: FileInfo object

        Returns:
            Dict containing ACL information, or None if not supported
        """
        ...

    async def set_acl(self, file_info: FileInfo, acl: dict) -> bool:
        """
        Set the access control list for a file (for lockdown/rollback).

        Args:
            file_info: FileInfo object
            acl: ACL dict to apply

        Returns:
            True if ACL applied successfully
        """
        ...

    def supports_remediation(self) -> bool:
        """
        Check if adapter supports remediation operations.

        Returns:
            True if adapter can perform move_file, get_acl, set_acl
        """
        ...
