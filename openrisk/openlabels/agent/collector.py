"""
File Metadata Collector.

Collects file system metadata and converts to OpenLabels NormalizedContext.

The collector gathers:
- File permissions (POSIX or NTFS)
- Owner/group information
- File timestamps (created, modified, accessed)
- File type and size
- Extended attributes (if available)
- Encryption indicators

Example:
    >>> from openlabels.agent import FileCollector
    >>>
    >>> collector = FileCollector()
    >>> metadata = collector.collect("/path/to/file.pdf")
    >>> print(f"Exposure: {metadata.exposure}")
    >>> print(f"Last modified: {metadata.last_modified}")
"""

import os
import stat
import logging
import hashlib
import platform
import mimetypes
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Iterator

from ..adapters.base import NormalizedContext, ExposureLevel
from ..adapters.scanner.constants import (
    FILE_READ_CHUNK_SIZE,
    PARTIAL_HASH_SIZE,
    SUBPROCESS_TIMEOUT,
    MAX_XATTR_NAME_LENGTH,
    MAX_XATTR_VALUE_SIZE,
    MAX_XATTR_COUNT,
    MAX_FILE_SIZE_BYTES,
)
from ..utils.validation import validate_path_for_subprocess

logger = logging.getLogger(__name__)


@dataclass
class FileMetadata:
    """
    Complete file metadata.
    """
    # Basic info
    path: str
    name: str
    size_bytes: int
    file_type: str  # MIME type
    extension: str

    # Timestamps
    created_at: Optional[str] = None  # ISO format
    modified_at: Optional[str] = None
    accessed_at: Optional[str] = None

    # Ownership
    owner: Optional[str] = None
    group: Optional[str] = None
    owner_uid: Optional[int] = None
    group_gid: Optional[int] = None

    # Permissions
    mode: Optional[int] = None
    mode_string: Optional[str] = None
    exposure: ExposureLevel = ExposureLevel.PRIVATE

    # Protection
    is_encrypted: bool = False
    encryption_type: Optional[str] = None
    is_readonly: bool = False
    is_hidden: bool = False

    # Archive info
    is_archive: bool = False
    archive_type: Optional[str] = None

    # Content hash (optional)
    content_hash: Optional[str] = None
    partial_hash: Optional[str] = None  # First 64KB for quick comparison

    # Extended attributes
    xattrs: Dict[str, str] = field(default_factory=dict)

    # Errors during collection
    errors: List[str] = field(default_factory=list)

    def to_normalized_context(self) -> NormalizedContext:
        """Convert to NormalizedContext for scoring."""
        # Calculate staleness
        staleness_days = 0
        if self.modified_at:
            try:
                modified = datetime.fromisoformat(self.modified_at.replace('Z', '+00:00'))
                staleness_days = (datetime.now(modified.tzinfo) - modified).days
            except (ValueError, TypeError) as e:
                logger.debug(f"Could not parse modified_at '{self.modified_at}': {e}")

        encryption = "none"
        if self.is_encrypted:
            encryption = self.encryption_type or "platform"

        return NormalizedContext(
            exposure=self.exposure.name,
            encryption=encryption,
            last_modified=self.modified_at,
            last_accessed=self.accessed_at,
            staleness_days=staleness_days,
            path=self.path,
            owner=self.owner,
            size_bytes=self.size_bytes,
            file_type=self.file_type,
            is_archive=self.is_archive,
        )


class FileCollector:
    """
    Collects file system metadata.

    Platform-aware collector that handles POSIX and Windows file systems.
    """

    # Extensions that typically indicate encryption
    ENCRYPTED_EXTENSIONS = frozenset({
        '.gpg', '.pgp', '.asc',  # PGP
        '.enc', '.encrypted',    # Generic
        '.aes', '.aes256',       # AES
        '.vault',                # Ansible vault
        '.age',                  # age encryption
        '.crypt',                # Generic
    })

    # Archive extensions
    ARCHIVE_EXTENSIONS = frozenset({
        '.zip', '.tar', '.gz', '.tgz', '.tar.gz',
        '.bz2', '.xz', '.7z', '.rar',
    })

    # Common encrypted archive extensions
    ENCRYPTED_ARCHIVE_EXTENSIONS = frozenset({
        '.zip',  # Can be encrypted
        '.7z',   # Can be encrypted
        '.rar',  # Can be encrypted
    })

    def __init__(
        self,
        compute_hash: bool = False,
        compute_partial_hash: bool = True,
        hash_size_limit: int = MAX_FILE_SIZE_BYTES,  # From central constants
        collect_xattrs: bool = True,
    ):
        """
        Initialize collector.

        Args:
            compute_hash: Compute full content hash (slow for large files)
            compute_partial_hash: Compute hash of first 64KB (fast)
            hash_size_limit: Max file size for full hash computation
            collect_xattrs: Collect extended attributes
        """
        self.compute_hash = compute_hash
        self.compute_partial_hash = compute_partial_hash
        self.hash_size_limit = hash_size_limit
        self.collect_xattrs = collect_xattrs
        self._platform = platform.system()

    def collect(self, path: str) -> FileMetadata:
        """
        Collect metadata for a file.

        Args:
            path: Path to file

        Returns:
            FileMetadata with all collected information

        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If file cannot be accessed
            ValueError: If path is a symlink (security protection)
        """
        original_path = Path(path)
        errors = []

        try:
            st = original_path.lstat()  # TOCTOU-001: check before resolve()
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {path}")
        except OSError as e:
            raise PermissionError(f"Cannot access file: {e}")

        if stat.S_ISLNK(st.st_mode):  # Reject symlinks
            raise ValueError(f"Refusing to collect metadata for symlink (security): {path}")

        if not stat.S_ISREG(st.st_mode):  # Regular files only
            raise ValueError(f"Not a regular file: {path}")

        # Now safe to resolve the path for consistent path representation
        path = original_path.resolve()

        # Basic metadata
        metadata = FileMetadata(
            path=str(path),
            name=path.name,
            size_bytes=st.st_size,
            extension=path.suffix.lower(),
            file_type=self._get_mime_type(path),
        )

        # Timestamps
        metadata.created_at = self._format_timestamp(getattr(st, 'st_birthtime', st.st_ctime))
        metadata.modified_at = self._format_timestamp(st.st_mtime)
        metadata.accessed_at = self._format_timestamp(st.st_atime)

        # Permissions and exposure
        try:
            self._collect_permissions(path, st, metadata)
        except (OSError, KeyError) as e:
            errors.append(f"Permission collection failed: {e}")
            logger.debug(f"Permission collection failed for {path}: {e}")

        # Check for encryption indicators
        metadata.is_encrypted = self._check_encryption(path, metadata)

        # Check for archive
        metadata.is_archive = self._check_archive(path, metadata)

        # Hashes
        if self.compute_partial_hash:
            try:
                metadata.partial_hash = self._compute_partial_hash(path)
            except OSError as e:
                errors.append(f"Partial hash failed: {e}")

        if self.compute_hash and st.st_size <= self.hash_size_limit:
            try:
                metadata.content_hash = self._compute_content_hash(path)
            except OSError as e:
                errors.append(f"Content hash failed: {e}")

        # Extended attributes
        if self.collect_xattrs:
            try:
                metadata.xattrs = self._collect_xattrs(path)
            except OSError as e:
                errors.append(f"Xattr collection failed: {e}")
                logger.debug(f"Xattr collection failed for {path}: {e}")

        metadata.errors = errors
        return metadata

    def _collect_permissions(
        self,
        path: Path,
        st: os.stat_result,
        metadata: FileMetadata,
    ) -> None:
        """Collect permission information."""
        metadata.mode = st.st_mode

        if self._platform == "Windows":
            self._collect_windows_permissions(path, metadata)
        else:
            self._collect_posix_permissions(path, st, metadata)

    def _collect_posix_permissions(
        self,
        path: Path,
        st: os.stat_result,
        metadata: FileMetadata,
    ) -> None:
        """Collect POSIX permissions."""
        from .posix import get_posix_permissions

        try:
            perms = get_posix_permissions(str(path))
            metadata.owner = perms.owner_name
            metadata.group = perms.group_name
            metadata.owner_uid = perms.owner_uid
            metadata.group_gid = perms.group_gid
            metadata.mode_string = perms.mode_string
            metadata.exposure = perms.exposure
        except (OSError, KeyError, ValueError) as e:
            logger.debug(f"POSIX permission collection failed: {e}")
            # Fallback to basic mode parsing
            mode = st.st_mode
            metadata.exposure = self._mode_to_exposure(mode)

    def _collect_windows_permissions(
        self,
        path: Path,
        metadata: FileMetadata,
    ) -> None:
        """Collect Windows NTFS permissions."""
        # Try to import Windows-specific module
        try:
            from .ntfs import get_ntfs_permissions
            ntfs_perms = get_ntfs_permissions(str(path))
            metadata.owner = ntfs_perms.owner
            metadata.exposure = ntfs_perms.exposure
        except ImportError:
            # Windows module not available, use basic check
            metadata.exposure = ExposureLevel.PRIVATE
        except (OSError, ValueError) as e:
            logger.debug(f"NTFS permission collection failed: {e}")
            metadata.exposure = ExposureLevel.PRIVATE

    def _mode_to_exposure(self, mode: int) -> ExposureLevel:
        """Simple mode to exposure conversion."""
        if mode & stat.S_IWOTH:
            return ExposureLevel.PUBLIC
        if mode & stat.S_IROTH:
            return ExposureLevel.ORG_WIDE
        if mode & stat.S_IRGRP:
            return ExposureLevel.INTERNAL
        return ExposureLevel.PRIVATE

    def _get_mime_type(self, path: Path) -> str:
        """Get MIME type for file."""
        mime_type, _ = mimetypes.guess_type(str(path))
        return mime_type or "application/octet-stream"

    def _format_timestamp(self, ts: float) -> str:
        """Format Unix timestamp as ISO string."""
        return datetime.fromtimestamp(ts).isoformat()

    def _check_archive_encryption_headers(self, path: Path) -> Optional[str]:
        """
        Inspect archive headers to detect encryption.

        Returns encryption type if detected, None otherwise.

        Supported formats:
        - ZIP: Check general purpose bit flag (bit 0 = encrypted)
        - 7z: Check for encoded header or encryption markers
        - RAR: Check archive flags for encryption
        """
        try:
            with open(path, 'rb') as f:
                header = f.read(64)

            if len(header) < 4:
                return None

            # ZIP format: PK\x03\x04 signature
            # Encryption flag is bit 0 of general purpose bit flag at offset 6
            if header[:4] == b'PK\x03\x04' and len(header) >= 8:
                general_flag = header[6] | (header[7] << 8)
                if general_flag & 0x0001:  # Bit 0 = encrypted
                    return "zip_encrypted"
                # Also check for strong encryption (bit 6)
                if general_flag & 0x0040:
                    return "zip_strong_encryption"

            # 7z format: 7z\xBC\xAF\x27\x1C signature
            # Encrypted 7z archives typically have encoded headers
            if header[:6] == b'7z\xbc\xaf\x27\x1c':
                # Check for next header offset and encrypted header marker
                # This is a heuristic - 7z encryption detection is complex
                if len(header) >= 32:
                    # Offset 20-23: next header offset
                    # If archive uses encryption, often has specific patterns
                    # For now, flag as potentially encrypted for manual review
                    pass

            # RAR format: Rar!\x1a\x07 signature (RAR 4.x and 5.x)
            if header[:7] == b'Rar!\x1a\x07\x00' or header[:7] == b'Rar!\x1a\x07\x01':
                # RAR5: After main header, check for encryption record
                # RAR4: Archive flags at offset 10, bit 2 = encrypted headers
                if len(header) >= 12:
                    # RAR4 style check
                    archive_flags = header[10] | (header[11] << 8)
                    if archive_flags & 0x0004:  # Bit 2 = encrypted headers
                        return "rar_encrypted"

        except (OSError, IOError) as e:
            logger.debug(f"Failed to read archive headers for encryption check: {e}")

        return None

    def _check_encryption(self, path: Path, metadata: FileMetadata) -> bool:
        """Check if file appears to be encrypted."""
        # Check extension
        if metadata.extension in self.ENCRYPTED_EXTENSIONS:
            metadata.encryption_type = "file_level"
            return True

        # Check for encrypted archives - inspect headers for definitive check
        if metadata.extension in self.ARCHIVE_EXTENSIONS:
            encryption_type = self._check_archive_encryption_headers(path)
            if encryption_type:
                metadata.encryption_type = encryption_type
                logger.debug(f"Encrypted archive detected via header inspection: {path}")
                return True

        # Check xattrs for encryption markers
        if metadata.xattrs:
            for key in metadata.xattrs:
                if "encrypt" in key.lower():
                    metadata.encryption_type = "platform"
                    return True

        return False

    def _check_archive(self, path: Path, metadata: FileMetadata) -> bool:
        """Check if file is an archive."""
        if metadata.extension in self.ARCHIVE_EXTENSIONS:
            metadata.archive_type = metadata.extension.lstrip('.')
            return True

        # Check for compound extensions like .tar.gz
        name_lower = path.name.lower()
        for ext in ['.tar.gz', '.tar.bz2', '.tar.xz']:
            if name_lower.endswith(ext):
                metadata.archive_type = ext.lstrip('.')
                return True

        return False

    def _compute_partial_hash(self, path: Path, size: int = PARTIAL_HASH_SIZE) -> str:
        """Compute hash of first N bytes."""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            h.update(f.read(size))
        return h.hexdigest()[:16]  # Short hash

    def _compute_content_hash(self, path: Path) -> str:
        """Compute full content hash."""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(FILE_READ_CHUNK_SIZE), b''):
                h.update(chunk)
        return h.hexdigest()

    def _validate_xattr_name(self, attr_name: str) -> bool:
        """
        Validate xattr attribute name (LOW-006).

        Args:
            attr_name: The attribute name to validate

        Returns:
            True if valid, False otherwise
        """
        if not attr_name or not isinstance(attr_name, str):
            return False
        # Check length
        if len(attr_name) > MAX_XATTR_NAME_LENGTH:
            return False
        # Check for null bytes and control characters
        if '\x00' in attr_name or any(ord(c) < 32 for c in attr_name):
            return False
        # Must start with valid namespace prefix on Linux/macOS
        # user., security., system., trusted. (Linux)
        # com. (macOS)
        valid_prefixes = ('user.', 'security.', 'system.', 'trusted.', 'com.')
        if not any(attr_name.startswith(p) for p in valid_prefixes):
            # Allow unqualified names for compatibility but log
            if '.' not in attr_name:
                logger.debug(f"Xattr name without namespace prefix: {attr_name}")
        return True

    def _collect_xattrs(self, path: Path) -> Dict[str, str]:
        """Collect extended attributes. See SECURITY.md for LOW-006."""
        xattrs = {}

        if self._platform == "Windows":
            return xattrs  # Windows uses NTFS streams, not xattrs

        try:
            import xattr as xattr_module
            attr_count = 0
            for attr_name in xattr_module.listxattr(str(path)):
                if not self._validate_xattr_name(attr_name):  # LOW-006
                    logger.warning(f"Skipping invalid xattr name on {path}: {attr_name!r}")
                    continue

                if attr_count >= MAX_XATTR_COUNT:  # LOW-006: limit count
                    logger.warning(f"Reached max xattr count ({MAX_XATTR_COUNT}) for {path}")
                    break

                try:
                    value = xattr_module.getxattr(str(path), attr_name)

                    if len(value) > MAX_XATTR_VALUE_SIZE:  # LOW-006: limit size
                        logger.warning(
                            f"Skipping oversized xattr '{attr_name}' on {path}: "
                            f"{len(value)} bytes (max {MAX_XATTR_VALUE_SIZE})"
                        )
                        continue

                    try:
                        xattrs[attr_name] = value.decode('utf-8')
                    except UnicodeDecodeError:
                        xattrs[attr_name] = value.hex()
                    attr_count += 1
                except OSError as e:
                    logger.debug(f"Could not read xattr '{attr_name}' from {path}: {e}")
        except ImportError:
            # xattr module not installed, try getfattr command
            import subprocess
            path_str = str(path)
            if not validate_path_for_subprocess(path_str):
                logger.debug(f"Invalid path for xattr fallback: {path_str!r}")
                return xattrs
            try:
                result = subprocess.run(
                    ["getfattr", "-d", path_str],
                    capture_output=True,
                    text=True,
                    timeout=SUBPROCESS_TIMEOUT,
                )
                if result.returncode == 0:
                    attr_count = 0
                    for line in result.stdout.splitlines():
                        if '=' in line and not line.startswith('#'):
                            key, _, value = line.partition('=')
                            key = key.strip()
                            value = value.strip().strip('"')

                            if not self._validate_xattr_name(key):  # LOW-006
                                logger.warning(f"Skipping invalid xattr name: {key!r}")
                                continue
                            if len(value) > MAX_XATTR_VALUE_SIZE:
                                logger.warning(f"Skipping oversized xattr value for {key}")
                                continue
                            if attr_count >= MAX_XATTR_COUNT:
                                logger.warning(f"Reached max xattr count for {path}")
                                break

                            xattrs[key] = value
                            attr_count += 1
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.debug(f"getfattr fallback failed for {path}: {e}")
        except OSError as e:
            logger.debug(f"Could not list xattrs for {path}: {e}")

        return xattrs



# --- Convenience Functions ---


def collect_metadata(path: str, **kwargs) -> FileMetadata:
    """
    Collect metadata for a single file.

    Convenience function that creates a FileCollector and collects metadata.

    Args:
        path: Path to file
        **kwargs: Arguments passed to FileCollector

    Returns:
        FileMetadata
    """
    collector = FileCollector(**kwargs)
    return collector.collect(path)


def collect_directory(
    path: str,
    recursive: bool = True,
    include_hidden: bool = False,
    max_files: Optional[int] = None,
    **kwargs,
) -> Iterator[FileMetadata]:
    """
    Collect metadata for all files in a directory.

    Args:
        path: Directory path
        recursive: Recurse into subdirectories
        include_hidden: Include hidden files
        max_files: Maximum files to collect
        **kwargs: Arguments passed to FileCollector

    Yields:
        FileMetadata for each file
    """
    collector = FileCollector(**kwargs)
    dir_path = Path(path)

    if not dir_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {path}")

    walker = dir_path.rglob("*") if recursive else dir_path.glob("*")
    count = 0

    for file_path in walker:
        try:
            st = file_path.stat(follow_symlinks=False)  # TOCTOU-001
            if not stat.S_ISREG(st.st_mode):
                continue  # Skip non-regular files
        except OSError:
            # File doesn't exist, permission denied, or other issue - skip
            continue

        if not include_hidden and any(p.startswith('.') for p in file_path.parts):
            continue

        if max_files and count >= max_files:
            break

        try:
            yield collector.collect(str(file_path))
            count += 1
        except OSError as e:
            logger.warning(f"Failed to collect metadata for {file_path}: {e}")
            # Yield a minimal metadata object with error
            yield FileMetadata(
                path=str(file_path),
                name=file_path.name,
                size_bytes=0,
                file_type="unknown",
                extension=file_path.suffix.lower(),
                errors=[str(e)],
            )
            count += 1
