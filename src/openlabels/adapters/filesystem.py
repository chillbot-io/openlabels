"""
Filesystem adapter for local and network file systems.
"""

import os
import platform
import stat
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator, Optional

import aiofiles
import aiofiles.os

from openlabels.adapters.base import Adapter, FileInfo, ExposureLevel


class FilesystemAdapter:
    """Adapter for local and network filesystem scanning."""

    def __init__(self, service_account: Optional[str] = None):
        """
        Initialize the filesystem adapter.

        Args:
            service_account: Optional service account for impersonation (Windows)
        """
        self.service_account = service_account
        self.is_windows = platform.system() == "Windows"

    @property
    def adapter_type(self) -> str:
        return "filesystem"

    async def list_files(
        self,
        target: str,
        recursive: bool = True,
    ) -> AsyncIterator[FileInfo]:
        """List files in a directory."""
        target_path = Path(target)

        if not target_path.exists():
            raise ValueError(f"Target path does not exist: {target}")

        if not target_path.is_dir():
            raise ValueError(f"Target path is not a directory: {target}")

        async for file_info in self._walk_directory(target_path, recursive):
            yield file_info

    async def _walk_directory(
        self,
        directory: Path,
        recursive: bool,
    ) -> AsyncIterator[FileInfo]:
        """Recursively walk a directory."""
        try:
            entries = list(directory.iterdir())
        except PermissionError:
            # Log and skip directories we can't access
            return

        for entry in entries:
            try:
                if entry.is_file():
                    stat_info = entry.stat()
                    yield FileInfo(
                        path=str(entry.absolute()),
                        name=entry.name,
                        size=stat_info.st_size,
                        modified=datetime.fromtimestamp(stat_info.st_mtime),
                        owner=self._get_owner(entry),
                        permissions=self._get_permissions(entry),
                        exposure=self._calculate_exposure(entry),
                        adapter=self.adapter_type,
                    )
                elif entry.is_dir() and recursive:
                    async for file_info in self._walk_directory(entry, recursive):
                        yield file_info
            except (PermissionError, OSError):
                # Skip files we can't access
                continue

    async def read_file(self, file_info: FileInfo) -> bytes:
        """Read file content."""
        async with aiofiles.open(file_info.path, "rb") as f:
            return await f.read()

    async def get_metadata(self, file_info: FileInfo) -> FileInfo:
        """Get updated metadata for a file."""
        path = Path(file_info.path)
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

    async def test_connection(self, config: dict) -> bool:
        """Test if we can access the configured path."""
        path = config.get("path")
        if not path:
            return False

        target = Path(path)
        return target.exists() and target.is_dir()

    def _get_owner(self, path: Path) -> Optional[str]:
        """Get file owner."""
        if self.is_windows:
            return self._get_windows_owner(path)
        else:
            return self._get_posix_owner(path)

    def _get_windows_owner(self, path: Path) -> Optional[str]:
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
        except Exception:
            return None

    def _get_posix_owner(self, path: Path) -> Optional[str]:
        """Get file owner on POSIX systems."""
        try:
            import pwd

            stat_info = path.stat()
            return pwd.getpwuid(stat_info.st_uid).pw_name
        except Exception:
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
            import ntsecuritycon as con

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
                    except Exception:
                        trustee = str(sid)

                    permissions["aces"].append({
                        "trustee": trustee,
                        "access_mask": ace[1],
                    })

            return permissions
        except Exception:
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
        except Exception:
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

        except Exception:
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

        except Exception:
            return ExposureLevel.PRIVATE
