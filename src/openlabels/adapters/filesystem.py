"""
Filesystem adapter for local and network file systems.

Features:
- Async file enumeration with aiofiles
- File/account filtering support
- NTFS permission extraction (Windows)
- POSIX permission extraction (Linux/Mac)
- Exposure level calculation from permissions
"""

from __future__ import annotations

import asyncio
import logging
import platform
import stat
import sys
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path
from types import TracebackType

import aiofiles
import aiofiles.os

from openlabels.adapters.base import DEFAULT_FILTER, ExposureLevel, FileInfo, FilterConfig, FolderInfo
from openlabels.exceptions import FilesystemError

logger = logging.getLogger(__name__)


class FilesystemAdapter:
    """
    Adapter for local and network filesystem scanning.

    Supports filtering by file type, path patterns, and account exclusions.
    """

    def __init__(self, service_account: str | None = None):
        """
        Initialize the filesystem adapter.

        Args:
            service_account: Optional service account for impersonation (Windows)
        """
        self.service_account = service_account
        self.is_windows = platform.system() == "Windows"

    async def __aenter__(self) -> FilesystemAdapter:
        """No-op — filesystem adapter has no resources to initialize."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """No-op — filesystem adapter has no resources to clean up."""

    @property
    def adapter_type(self) -> str:
        return "filesystem"

    def supports_delta(self) -> bool:
        """Filesystem doesn't support delta queries (uses hash-based detection)."""
        return False

    async def list_files(
        self,
        target: str,
        recursive: bool = True,
        filter_config: FilterConfig | None = None,
    ) -> AsyncIterator[FileInfo]:
        """
        List files in a directory.

        Args:
            target: Directory path to scan
            recursive: Whether to scan subdirectories
            filter_config: Optional filter for file/account exclusions

        Yields:
            FileInfo objects for each file (after filtering)
        """
        filter_config = filter_config or DEFAULT_FILTER
        target_path = Path(target)

        exists, is_dir = await asyncio.to_thread(
            lambda: (target_path.exists(), target_path.is_dir()),
        )

        if not exists:
            raise FilesystemError(
                "Target path does not exist",
                path=target,
                operation="list_files",
                context="ensure the path exists and is accessible",
            )

        if not is_dir:
            raise FilesystemError(
                "Target path is not a directory",
                path=target,
                operation="list_files",
                context="provide a directory path, not a file path",
            )

        async for file_info in self._walk_directory(target_path, recursive, filter_config):
            yield file_info

    async def list_folders(
        self,
        target: str,
        recursive: bool = True,
    ) -> AsyncIterator[FolderInfo]:
        """List directories under *target*.

        Yields one :class:`FolderInfo` per directory, including the
        target directory itself.
        """
        target_path = Path(target)

        exists, is_dir = await asyncio.to_thread(
            lambda: (target_path.exists(), target_path.is_dir()),
        )

        if not exists:
            raise FilesystemError(
                "Target path does not exist",
                path=target,
                operation="list_folders",
                context="ensure the path exists and is accessible",
            )

        if not is_dir:
            raise FilesystemError(
                "Target path is not a directory",
                path=target,
                operation="list_folders",
                context="provide a directory path, not a file path",
            )

        async for folder_info in self._walk_folders(target_path, recursive):
            yield folder_info

    def _collect_folder_info(
        self,
        directory: Path,
    ) -> tuple[FolderInfo, list[Path]]:
        """Collect FolderInfo for *directory* and its direct child directories.

        All blocking I/O in a single synchronous call so it can be
        dispatched once via ``asyncio.to_thread``.

        Returns:
            A ``(folder_info, child_dirs)`` tuple.
        """
        child_dirs: list[Path] = []
        file_count = 0
        dir_count = 0

        try:
            st = directory.stat()
        except (PermissionError, OSError) as e:
            logger.debug(f"Cannot stat {directory}: {e}")
            st = None

        try:
            for entry in directory.iterdir():
                try:
                    if entry.is_dir():
                        child_dirs.append(entry)
                        dir_count += 1
                    elif entry.is_file():
                        file_count += 1
                except (PermissionError, OSError):
                    pass
        except PermissionError:
            logger.debug(f"Permission denied: {directory}")

        info = FolderInfo(
            path=str(directory.absolute()),
            name=directory.name or str(directory),  # root dirs have empty name
            modified=datetime.fromtimestamp(st.st_mtime) if st else None,
            adapter="filesystem",
            inode=st.st_ino if st else None,
            child_dir_count=dir_count,
            child_file_count=file_count,
        )

        return info, child_dirs

    async def _walk_folders(
        self,
        directory: Path,
        recursive: bool,
    ) -> AsyncIterator[FolderInfo]:
        """Recursively yield FolderInfo for *directory* and its descendants."""
        folder_info, child_dirs = await asyncio.to_thread(
            self._collect_folder_info, directory,
        )
        yield folder_info

        if recursive:
            for child in child_dirs:
                async for sub_info in self._walk_folders(child, recursive):
                    yield sub_info

    def _collect_entries(
        self,
        directory: Path,
    ) -> tuple[list[FileInfo], list[Path]]:
        """Collect file infos and subdirectory paths from *directory*.

        Performs **all** blocking I/O — ``iterdir()``, ``is_file()``,
        ``is_dir()``, ``stat()``, owner / permission / exposure lookups —
        in a single synchronous call so it can be dispatched once via
        ``asyncio.to_thread`` instead of hopping to a thread per entry.

        Returns:
            A ``(files, subdirs)`` tuple where *files* is a list of
            :class:`FileInfo` objects and *subdirs* is a list of
            :class:`Path` objects for child directories.
        """
        files: list[FileInfo] = []
        subdirs: list[Path] = []

        try:
            entries = list(directory.iterdir())
        except PermissionError:
            logger.debug(f"Permission denied: {directory}")
            return files, subdirs

        for entry in entries:
            try:
                if entry.is_file():
                    stat_info = entry.stat()
                    files.append(FileInfo(
                        path=str(entry.absolute()),
                        name=entry.name,
                        size=stat_info.st_size,
                        modified=datetime.fromtimestamp(stat_info.st_mtime),
                        owner=self._get_owner(entry),
                        permissions=self._get_permissions(entry),
                        exposure=self._calculate_exposure(entry),
                        adapter=self.adapter_type,
                    ))
                elif entry.is_dir():
                    subdirs.append(entry)
            except (PermissionError, OSError) as e:
                logger.debug(f"Cannot access {entry}: {e}")

        return files, subdirs

    async def _walk_directory(
        self,
        directory: Path,
        recursive: bool,
        filter_config: FilterConfig,
    ) -> AsyncIterator[FileInfo]:
        """Recursively walk a directory with filtering.

        All blocking I/O for each directory level is batched into a
        single ``asyncio.to_thread(_collect_entries, ...)`` call to
        minimise thread-pool overhead.
        """
        files, subdirs = await asyncio.to_thread(
            self._collect_entries, directory,
        )

        for file_info in files:
            if filter_config.should_include(file_info):
                yield file_info

        if recursive:
            for subdir in subdirs:
                # Check if directory should be skipped by pattern
                skip_dir = False
                for pattern in filter_config.exclude_patterns:
                    # Check if directory name matches exclusion pattern
                    if subdir.name in pattern.replace("/*", "").replace("*", ""):
                        skip_dir = True
                        break

                if not skip_dir:
                    async for file_info in self._walk_directory(subdir, recursive, filter_config):
                        yield file_info

    async def read_file(
        self,
        file_info: FileInfo,
        max_size_bytes: int = 100 * 1024 * 1024,  # Default 100MB
    ) -> bytes:
        """
        Read file content with size limit.

        Security: Enforces maximum file size to prevent DoS attacks via
        memory exhaustion from processing extremely large files.

        Args:
            file_info: FileInfo of file to read
            max_size_bytes: Maximum file size to read (default 100MB)

        Returns:
            File content as bytes

        Raises:
            ValueError: If file exceeds max_size_bytes
        """
        # Security: Check file size before reading to prevent memory exhaustion
        if file_info.size > max_size_bytes:
            raise ValueError(
                f"File too large for processing: {file_info.size} bytes "
                f"(max: {max_size_bytes} bytes). File: {file_info.path}"
            )

        async with aiofiles.open(file_info.path, "rb") as f:
            content = await f.read(max_size_bytes + 1)  # Read one extra byte to detect overflow

            # Double-check actual content size (file may have grown since stat)
            if len(content) > max_size_bytes:
                raise ValueError(
                    f"File content exceeds limit: {len(content)} bytes "
                    f"(max: {max_size_bytes} bytes). File: {file_info.path}"
                )

            return content

    def _get_metadata_sync(self, file_path: str) -> FileInfo:
        """Synchronous metadata collection -- all blocking I/O in one call."""
        path = Path(file_path)
        stat_info = path.stat()

        return FileInfo(
            path=str(path.absolute()),
            name=path.name,
            size=stat_info.st_size,
            modified=datetime.fromtimestamp(stat_info.st_mtime),
            owner=self._get_owner(path),
            permissions=self._get_permissions(path),
            exposure=self._calculate_exposure(path),
            adapter=self.adapter_type,
        )

    async def get_metadata(self, file_info: FileInfo) -> FileInfo:
        """Get updated metadata for a file."""
        return await asyncio.to_thread(self._get_metadata_sync, file_info.path)

    async def test_connection(self, config: dict) -> bool:
        """Test if we can access the configured path."""
        path = config.get("path")
        if not path:
            return False

        target = Path(path)
        return await asyncio.to_thread(lambda: target.exists() and target.is_dir())

    def _get_owner(self, path: Path) -> str | None:
        """Get file owner."""
        if self.is_windows:
            return self._get_windows_owner(path)
        else:
            return self._get_posix_owner(path)

    def _get_windows_owner(self, path: Path) -> str | None:
        """Get file owner on Windows."""
        try:
            import win32security

            sd = win32security.GetFileSecurity(
                str(path),
                win32security.OWNER_SECURITY_INFORMATION,
            )
            owner_sid = sd.GetSecurityDescriptorOwner()
            name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
            return f"{domain}\\{name}"
        except ImportError:
            logger.debug("win32security not installed, cannot get Windows owner")
            return None
        except PermissionError as e:
            logger.debug(f"Permission denied getting Windows owner for {path}: {e}")
            return None
        except OSError as e:
            logger.debug(f"OS error getting Windows owner for {path}: {e}")
            return None

    def _get_posix_owner(self, path: Path) -> str | None:
        """Get file owner on POSIX systems."""
        try:
            import pwd

            stat_info = path.stat()
            return pwd.getpwuid(stat_info.st_uid).pw_name
        except ImportError:
            logger.debug("pwd module not available (non-POSIX system)")
            return None
        except KeyError as e:
            logger.debug(f"UID not found in passwd database for {path}: {e}")
            return None
        except PermissionError as e:
            logger.debug(f"Permission denied getting POSIX owner for {path}: {e}")
            return None
        except OSError as e:
            logger.debug(f"OS error getting POSIX owner for {path}: {e}")
            return None

    def _get_permissions(self, path: Path) -> dict:
        """Get file permissions."""
        if self.is_windows:
            return self._get_windows_permissions(path)
        else:
            return self._get_posix_permissions(path)

    def _get_windows_permissions(self, path: Path) -> dict:
        """Get NTFS permissions on Windows."""
        try:
            import win32security

            sd = win32security.GetFileSecurity(
                str(path),
                win32security.DACL_SECURITY_INFORMATION,
            )
            dacl = sd.GetSecurityDescriptorDacl()

            permissions = {"aces": []}
            if dacl:
                for i in range(dacl.GetAceCount()):
                    ace = dacl.GetAce(i)
                    sid = ace[2]
                    try:
                        name, domain, _ = win32security.LookupAccountSid(None, sid)
                        trustee = f"{domain}\\{name}"
                    except LookupError as e:
                        # SID not found in local or domain account databases
                        logger.debug(
                            f"Failed to lookup SID {sid} - account not found: {e}",
                            exc_info=True
                        )
                        trustee = str(sid)
                    except OSError as e:
                        # Network or system error during SID lookup
                        logger.debug(
                            f"Failed to lookup SID {sid} - OS error: {e}",
                            exc_info=True
                        )
                        trustee = str(sid)
                    except (RuntimeError, ValueError) as e:
                        # win32security may raise RuntimeError or ValueError for invalid SIDs
                        logger.debug(
                            f"Failed to lookup SID {sid} - unexpected error ({type(e).__name__}): {e}",
                            exc_info=True
                        )
                        trustee = str(sid)

                    permissions["aces"].append({
                        "trustee": trustee,
                        "access_mask": ace[1],
                    })

            return permissions
        except ImportError:
            logger.debug("win32security not installed, cannot get Windows permissions")
            return {}
        except PermissionError as e:
            logger.debug(f"Permission denied getting Windows permissions for {path}: {e}")
            return {}
        except OSError as e:
            logger.debug(f"OS error getting Windows permissions for {path}: {e}")
            return {}

    def _get_posix_permissions(self, path: Path) -> dict:
        """Get POSIX permissions."""
        try:
            stat_info = path.stat()
            mode = stat_info.st_mode

            return {
                "mode": oct(mode)[-3:],
                "owner_read": bool(mode & stat.S_IRUSR),
                "owner_write": bool(mode & stat.S_IWUSR),
                "owner_exec": bool(mode & stat.S_IXUSR),
                "group_read": bool(mode & stat.S_IRGRP),
                "group_write": bool(mode & stat.S_IWGRP),
                "group_exec": bool(mode & stat.S_IXGRP),
                "other_read": bool(mode & stat.S_IROTH),
                "other_write": bool(mode & stat.S_IWOTH),
                "other_exec": bool(mode & stat.S_IXOTH),
            }
        except PermissionError as e:
            logger.debug(f"Permission denied getting POSIX permissions for {path}: {e}")
            return {}
        except OSError as e:
            logger.debug(f"OS error getting POSIX permissions for {path}: {e}")
            return {}

    def _calculate_exposure(self, path: Path) -> ExposureLevel:
        """Determine exposure level from permissions."""
        if self.is_windows:
            return self._get_ntfs_exposure(path)
        else:
            return self._get_posix_exposure(path)

    def _get_ntfs_exposure(self, path: Path) -> ExposureLevel:
        """Determine exposure level from NTFS permissions."""
        try:
            import win32security

            sd = win32security.GetFileSecurity(
                str(path),
                win32security.DACL_SECURITY_INFORMATION,
            )
            dacl = sd.GetSecurityDescriptorDacl()

            if not dacl:
                return ExposureLevel.ORG_WIDE  # No DACL = Everyone access

            # Check for well-known SIDs
            everyone_sid = win32security.ConvertStringSidToSid("S-1-1-0")
            authenticated_users_sid = win32security.ConvertStringSidToSid("S-1-5-11")
            domain_users_sid = None  # Would need to look up

            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                sid = ace[2]

                if sid == everyone_sid:
                    return ExposureLevel.PUBLIC
                elif sid == authenticated_users_sid:
                    return ExposureLevel.ORG_WIDE

            # If we got here, it's probably internal or private
            ace_count = dacl.GetAceCount()
            if ace_count <= 2:  # Owner + maybe one group
                return ExposureLevel.PRIVATE
            else:
                return ExposureLevel.INTERNAL

        except ImportError:
            logger.debug("win32security not installed, cannot determine NTFS exposure")
            return ExposureLevel.PRIVATE
        except PermissionError as e:
            logger.debug(f"Permission denied getting NTFS exposure for {path}: {e}")
            return ExposureLevel.PRIVATE
        except OSError as e:
            logger.debug(f"OS error getting NTFS exposure for {path}: {e}")
            return ExposureLevel.PRIVATE

    def _get_posix_exposure(self, path: Path) -> ExposureLevel:
        """Determine exposure level from POSIX permissions."""
        try:
            stat_info = path.stat()
            mode = stat_info.st_mode

            # Check 'other' permissions
            if mode & stat.S_IROTH:
                return ExposureLevel.PUBLIC

            # Check 'group' permissions
            if mode & stat.S_IRGRP:
                return ExposureLevel.ORG_WIDE

            return ExposureLevel.PRIVATE

        except PermissionError as e:
            logger.debug(f"Permission denied getting POSIX exposure for {path}: {e}")
            return ExposureLevel.PRIVATE
        except OSError as e:
            logger.debug(f"OS error getting POSIX exposure for {path}: {e}")
            return ExposureLevel.PRIVATE

    def _move_file_sync(self, source_path: str, dest_path: str) -> bool:
        """Synchronous file move -- all blocking I/O in one call."""
        import shutil

        source = Path(source_path)
        dest = Path(dest_path)

        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(dest))
            return True
        except PermissionError as e:
            logger.error(f"Permission denied moving {source} to {dest}: {e}")
            return False
        except FileNotFoundError as e:
            logger.error(f"File not found moving {source} to {dest}: {e}")
            return False
        except OSError as e:
            logger.error(f"OS error moving {source} to {dest}: {e}")
            return False

    async def move_file(self, file_info: FileInfo, dest_path: str) -> bool:
        """
        Move a file to a new location (quarantine).

        Args:
            file_info: FileInfo of file to move
            dest_path: Destination path

        Returns:
            True if successful
        """
        return await asyncio.to_thread(self._move_file_sync, file_info.path, dest_path)

    async def get_acl(self, file_info: FileInfo) -> dict | None:
        """
        Get ACL for a file.

        Returns dict with platform-specific ACL info.
        """
        path = Path(file_info.path)

        if sys.platform == "win32":
            return await asyncio.to_thread(self._get_windows_acl, path)
        else:
            return await asyncio.to_thread(self._get_posix_acl, path)

    def _get_windows_acl(self, path: Path) -> dict | None:
        """Get Windows ACL (DACL)."""
        try:
            import win32security

            sd = win32security.GetFileSecurity(
                str(path),
                win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION
            )
            dacl = sd.GetSecurityDescriptorDacl()
            owner_sid = sd.GetSecurityDescriptorOwner()

            # Convert owner SID to string
            owner_str = win32security.ConvertSidToStringSid(owner_sid)

            # Get ACEs
            aces = []
            if dacl:
                for i in range(dacl.GetAceCount()):
                    ace = dacl.GetAce(i)
                    ace_type, ace_flags = ace[0]
                    mask = ace[1]
                    sid = ace[2]
                    sid_str = win32security.ConvertSidToStringSid(sid)
                    aces.append({
                        "type": ace_type,
                        "flags": ace_flags,
                        "mask": mask,
                        "sid": sid_str,
                    })

            return {
                "platform": "windows",
                "owner": owner_str,
                "aces": aces,
            }
        except ImportError:
            logger.error("win32security not installed, cannot get Windows ACL")
            return None
        except PermissionError as e:
            logger.error(f"Permission denied getting Windows ACL for {path}: {e}")
            return None
        except OSError as e:
            logger.error(f"OS error getting Windows ACL for {path}: {e}")
            return None

    def _get_posix_acl(self, path: Path) -> dict | None:
        """Get POSIX permissions."""
        try:
            stat_info = path.stat()
            return {
                "platform": "posix",
                "mode": stat_info.st_mode,
                "uid": stat_info.st_uid,
                "gid": stat_info.st_gid,
            }
        except PermissionError as e:
            logger.error(f"Permission denied getting POSIX ACL for {path}: {e}")
            return None
        except OSError as e:
            logger.error(f"OS error getting POSIX ACL for {path}: {e}")
            return None

    async def set_acl(self, file_info: FileInfo, acl: dict) -> bool:
        """
        Set ACL for a file.

        Args:
            file_info: FileInfo of file
            acl: ACL dict from get_acl or custom

        Returns:
            True if successful
        """
        path = Path(file_info.path)
        platform = acl.get("platform", "")

        if platform == "windows" and sys.platform == "win32":
            return await asyncio.to_thread(self._set_windows_acl, path, acl)
        elif platform == "posix":
            return await asyncio.to_thread(self._set_posix_acl, path, acl)
        else:
            logger.error(f"ACL platform mismatch: {platform} vs {sys.platform}")
            return False

    def _set_windows_acl(self, path: Path, acl: dict) -> bool:
        """Set Windows ACL."""
        try:
            import win32security

            # Create new DACL
            dacl = win32security.ACL()

            for ace_info in acl.get("aces", []):
                sid = win32security.ConvertStringSidToSid(ace_info["sid"])
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    ace_info["mask"],
                    sid
                )

            # Create security descriptor and set DACL
            sd = win32security.SECURITY_DESCRIPTOR()
            sd.SetSecurityDescriptorDacl(True, dacl, False)

            # Apply to file
            win32security.SetFileSecurity(
                str(path),
                win32security.DACL_SECURITY_INFORMATION,
                sd
            )
            return True
        except ImportError:
            logger.error("win32security not installed, cannot set Windows ACL")
            return False
        except PermissionError as e:
            logger.error(f"Permission denied setting Windows ACL for {path}: {e}")
            return False
        except OSError as e:
            logger.error(f"OS error setting Windows ACL for {path}: {e}")
            return False

    def _set_posix_acl(self, path: Path, acl: dict) -> bool:
        """Set POSIX permissions."""
        try:
            import os

            mode = acl.get("mode")
            if mode is not None:
                os.chmod(str(path), mode)

            uid = acl.get("uid")
            gid = acl.get("gid")
            if uid is not None or gid is not None:
                os.chown(str(path), uid or -1, gid or -1)

            return True
        except PermissionError as e:
            logger.error(f"Permission denied setting POSIX ACL for {path}: {e}")
            return False
        except OSError as e:
            logger.error(f"OS error setting POSIX ACL for {path}: {e}")
            return False

    async def lockdown_file(
        self,
        file_info: FileInfo,
        allowed_sids: list[str] | None = None,
    ) -> tuple[bool, dict | None]:
        """
        Lockdown a file by restricting permissions.

        Args:
            file_info: File to lockdown
            allowed_sids: List of SIDs (Windows) or UIDs (POSIX) to allow access

        Returns:
            Tuple of (success, original_acl for rollback)
        """
        # Get original ACL first
        original_acl = await self.get_acl(file_info)
        if original_acl is None:
            return False, None

        path = Path(file_info.path)

        if sys.platform == "win32":
            success = await asyncio.to_thread(self._lockdown_windows, path, allowed_sids or [])
        else:
            success = await asyncio.to_thread(self._lockdown_posix, path)

        return success, original_acl if success else None

    def _lockdown_windows(self, path: Path, allowed_sids: list[str]) -> bool:
        """Lockdown on Windows - restrict to specific SIDs."""
        try:
            import ntsecuritycon
            import win32security

            # Create new DACL with only allowed SIDs
            dacl = win32security.ACL()

            for sid_str in allowed_sids:
                sid = win32security.ConvertStringSidToSid(sid_str)
                # Grant full control to allowed principals
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    ntsecuritycon.FILE_ALL_ACCESS,
                    sid
                )

            # Apply
            sd = win32security.SECURITY_DESCRIPTOR()
            sd.SetSecurityDescriptorDacl(True, dacl, False)

            win32security.SetFileSecurity(
                str(path),
                win32security.DACL_SECURITY_INFORMATION,
                sd
            )
            return True
        except ImportError:
            logger.error("win32security not installed, cannot lockdown Windows file")
            return False
        except PermissionError as e:
            logger.error(f"Permission denied locking down {path}: {e}")
            return False
        except OSError as e:
            logger.error(f"OS error locking down {path}: {e}")
            return False

    def _lockdown_posix(self, path: Path) -> bool:
        """Lockdown on POSIX - restrict to owner only (mode 600)."""
        try:
            import os
            os.chmod(str(path), 0o600)  # Owner read/write only
            return True
        except PermissionError as e:
            logger.error(f"Permission denied locking down {path}: {e}")
            return False
        except OSError as e:
            logger.error(f"OS error locking down {path}: {e}")
            return False
