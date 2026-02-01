"""
Data inventory service for delta scanning.

This module provides inventory management to enable efficient delta scans:
- Folder-level tracking for non-sensitive content
- File-level tracking for sensitive files
- Content hash comparison for change detection
"""

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import UUID

from sqlalchemy import select, and_, delete
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import (
    FolderInventory,
    FileInventory,
    ScanTarget,
    ScanResult,
)
from openlabels.adapters.base import FileInfo

logger = logging.getLogger(__name__)


class InventoryService:
    """
    Service for managing the data inventory.

    The inventory enables delta scanning by tracking:
    - All folders (at folder level)
    - Sensitive files only (at file level with content hashes)
    """

    def __init__(self, session: AsyncSession, tenant_id: UUID, target_id: UUID):
        """
        Initialize the inventory service.

        Args:
            session: Database session
            tenant_id: Tenant ID
            target_id: Scan target ID
        """
        self.session = session
        self.tenant_id = tenant_id
        self.target_id = target_id
        self._folder_cache: dict[str, FolderInventory] = {}
        self._file_cache: dict[str, FileInventory] = {}

    async def load_folder_inventory(self) -> dict[str, FolderInventory]:
        """Load existing folder inventory into cache."""
        query = select(FolderInventory).where(
            and_(
                FolderInventory.tenant_id == self.tenant_id,
                FolderInventory.target_id == self.target_id,
            )
        )
        result = await self.session.execute(query)
        folders = result.scalars().all()

        self._folder_cache = {f.folder_path: f for f in folders}
        return self._folder_cache

    async def load_file_inventory(self) -> dict[str, FileInventory]:
        """Load existing file inventory into cache."""
        query = select(FileInventory).where(
            and_(
                FileInventory.tenant_id == self.tenant_id,
                FileInventory.target_id == self.target_id,
            )
        )
        result = await self.session.execute(query)
        files = result.scalars().all()

        self._file_cache = {f.file_path: f for f in files}
        return self._file_cache

    async def should_scan_folder(
        self,
        folder_path: str,
        folder_modified: Optional[datetime] = None,
        force_full_scan: bool = False,
    ) -> bool:
        """
        Check if a folder needs scanning.

        Args:
            folder_path: Path to the folder
            folder_modified: Folder modification time
            force_full_scan: Force scan regardless of inventory

        Returns:
            True if folder should be scanned
        """
        if force_full_scan:
            return True

        if folder_path not in self._folder_cache:
            return True  # New folder

        folder_inv = self._folder_cache[folder_path]

        # If no last scan, needs scanning
        if not folder_inv.last_scanned_at:
            return True

        # If folder modified since last scan, needs scanning
        if folder_modified and folder_inv.folder_modified:
            if folder_modified > folder_inv.folder_modified:
                return True

        # If has sensitive files, always scan
        if folder_inv.has_sensitive_files:
            return True

        return False

    async def should_scan_file(
        self,
        file_info: FileInfo,
        content_hash: Optional[str] = None,
        force_full_scan: bool = False,
    ) -> tuple[bool, str]:
        """
        Check if a file needs scanning.

        Args:
            file_info: File information
            content_hash: Pre-computed content hash (if available)
            force_full_scan: Force scan regardless of inventory

        Returns:
            Tuple of (should_scan, reason)
        """
        if force_full_scan:
            return True, "full_scan"

        file_path = file_info.path

        if file_path not in self._file_cache:
            return True, "new_file"

        file_inv = self._file_cache[file_path]

        # Check if flagged for rescan
        if file_inv.needs_rescan:
            return True, "flagged_rescan"

        # Check content hash if available
        if content_hash and file_inv.content_hash:
            if content_hash != file_inv.content_hash:
                return True, "content_changed"

        # Check file modification time
        if file_info.modified and file_inv.file_modified:
            if file_info.modified > file_inv.file_modified:
                return True, "modified_time"

        # Check file size changed
        if file_info.size != file_inv.file_size:
            return True, "size_changed"

        return False, "unchanged"

    def compute_content_hash(self, content: bytes) -> str:
        """Compute SHA-256 hash of file content."""
        return hashlib.sha256(content).hexdigest()

    async def update_folder_inventory(
        self,
        folder_path: str,
        adapter: str,
        job_id: UUID,
        file_count: int = 0,
        total_size: int = 0,
        folder_modified: Optional[datetime] = None,
        has_sensitive: bool = False,
        highest_risk: Optional[str] = None,
        total_entities: int = 0,
    ) -> FolderInventory:
        """
        Update or create folder inventory entry.

        Args:
            folder_path: Path to the folder
            adapter: Adapter type
            job_id: Current scan job ID
            file_count: Number of files in folder
            total_size: Total size of files in folder
            folder_modified: Folder modification time
            has_sensitive: Whether folder contains sensitive files
            highest_risk: Highest risk tier in folder
            total_entities: Total entities found in folder

        Returns:
            Updated or created FolderInventory
        """
        if folder_path in self._folder_cache:
            folder_inv = self._folder_cache[folder_path]
            folder_inv.file_count = file_count
            folder_inv.total_size_bytes = total_size
            folder_inv.folder_modified = folder_modified
            folder_inv.last_scanned_at = datetime.now(timezone.utc)
            folder_inv.last_scan_job_id = job_id
            folder_inv.has_sensitive_files = has_sensitive
            folder_inv.highest_risk_tier = highest_risk
            folder_inv.total_entities_found = total_entities
        else:
            folder_inv = FolderInventory(
                tenant_id=self.tenant_id,
                target_id=self.target_id,
                folder_path=folder_path,
                adapter=adapter,
                file_count=file_count,
                total_size_bytes=total_size,
                folder_modified=folder_modified,
                last_scanned_at=datetime.now(timezone.utc),
                last_scan_job_id=job_id,
                has_sensitive_files=has_sensitive,
                highest_risk_tier=highest_risk,
                total_entities_found=total_entities,
            )
            self.session.add(folder_inv)
            self._folder_cache[folder_path] = folder_inv

        return folder_inv

    async def update_file_inventory(
        self,
        file_info: FileInfo,
        scan_result: ScanResult,
        content_hash: str,
        job_id: UUID,
        folder_id: Optional[UUID] = None,
    ) -> FileInventory:
        """
        Update or create file inventory entry for a sensitive file.

        Args:
            file_info: File information
            scan_result: Scan result for the file
            content_hash: SHA-256 hash of file content
            job_id: Current scan job ID
            folder_id: Parent folder inventory ID

        Returns:
            Updated or created FileInventory
        """
        file_path = file_info.path

        if file_path in self._file_cache:
            file_inv = self._file_cache[file_path]

            # Track content changes
            if file_inv.content_hash != content_hash:
                file_inv.content_changed_count += 1

            file_inv.content_hash = content_hash
            file_inv.file_size = file_info.size
            file_inv.file_modified = file_info.modified
            file_inv.risk_score = scan_result.risk_score
            file_inv.risk_tier = scan_result.risk_tier
            file_inv.entity_counts = scan_result.entity_counts
            file_inv.total_entities = scan_result.total_entities
            file_inv.exposure_level = scan_result.exposure_level
            file_inv.owner = scan_result.owner
            file_inv.last_scanned_at = datetime.now(timezone.utc)
            file_inv.last_scan_job_id = job_id
            file_inv.scan_count += 1
            file_inv.needs_rescan = False

            # Update label info if present
            if scan_result.label_applied:
                file_inv.current_label_id = scan_result.current_label_id
                file_inv.current_label_name = scan_result.current_label_name
                file_inv.label_applied_at = scan_result.label_applied_at
        else:
            file_inv = FileInventory(
                tenant_id=self.tenant_id,
                target_id=self.target_id,
                folder_id=folder_id,
                file_path=file_path,
                file_name=file_info.name,
                adapter=file_info.adapter,
                content_hash=content_hash,
                file_size=file_info.size,
                file_modified=file_info.modified,
                risk_score=scan_result.risk_score,
                risk_tier=scan_result.risk_tier,
                entity_counts=scan_result.entity_counts,
                total_entities=scan_result.total_entities,
                exposure_level=scan_result.exposure_level,
                owner=scan_result.owner,
                last_scanned_at=datetime.now(timezone.utc),
                last_scan_job_id=job_id,
                current_label_id=scan_result.current_label_id if scan_result.label_applied else None,
                current_label_name=scan_result.current_label_name if scan_result.label_applied else None,
                label_applied_at=scan_result.label_applied_at if scan_result.label_applied else None,
            )
            self.session.add(file_inv)
            self._file_cache[file_path] = file_inv

        return file_inv

    async def mark_missing_files(self, seen_paths: set[str], job_id: UUID) -> int:
        """
        Mark files that were not seen in current scan.

        Files that exist in inventory but weren't seen may have been:
        - Deleted
        - Moved
        - Access revoked

        Args:
            seen_paths: Set of file paths seen in current scan
            job_id: Current scan job ID

        Returns:
            Count of files marked for rescan
        """
        marked_count = 0

        for file_path, file_inv in self._file_cache.items():
            if file_path not in seen_paths:
                # File not seen - mark for rescan
                file_inv.needs_rescan = True
                marked_count += 1

        return marked_count

    async def get_inventory_stats(self) -> dict:
        """Get statistics about the current inventory."""
        folder_count = len(self._folder_cache)
        file_count = len(self._file_cache)

        risk_tiers = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
        total_entities = 0
        labeled_count = 0

        for file_inv in self._file_cache.values():
            if file_inv.risk_tier in risk_tiers:
                risk_tiers[file_inv.risk_tier] += 1
            total_entities += file_inv.total_entities
            if file_inv.current_label_id:
                labeled_count += 1

        return {
            "total_folders": folder_count,
            "total_sensitive_files": file_count,
            "risk_tier_breakdown": risk_tiers,
            "total_entities": total_entities,
            "labeled_files": labeled_count,
            "pending_rescan": sum(1 for f in self._file_cache.values() if f.needs_rescan),
        }


def get_folder_path(file_path: str) -> str:
    """Extract folder path from file path."""
    return str(Path(file_path).parent)
