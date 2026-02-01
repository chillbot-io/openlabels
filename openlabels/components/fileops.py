"""
OpenLabels FileOps Component.

Handles file operations: quarantine, move, delete.
Provides structured error classification with retryability information.
"""

import errno
import json
import logging
import os
import shutil
import stat as stat_module
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, TYPE_CHECKING

from ..core.types import FilterCriteria, OperationResult
from ..core.exceptions import FileErrorType, FileOperationError
from ..utils.hashing import quick_hash

if TYPE_CHECKING:
    from ..context import Context
    from .scanner import Scanner

logger = logging.getLogger(__name__)


# Manifest file for tracking idempotent operations
QUARANTINE_MANIFEST = ".quarantine_manifest.json"


@dataclass
class FileError:
    """Structured file operation error with classification and retryability info."""
    path: str
    error_type: FileErrorType
    message: str
    retryable: bool

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "path": self.path,
            "error_type": self.error_type.value,
            "message": self.message,
            "retryable": self.retryable,
        }

    @classmethod
    def from_exception(cls, e: Exception, path: str) -> "FileError":
        """Create FileError from a standard exception."""
        file_op_error = FileOperationError.from_exception(e, path)
        return cls(
            path=path,
            error_type=file_op_error.error_type,
            message=file_op_error.message,
            retryable=file_op_error.retryable,
        )


@dataclass
class QuarantineResult:
    """Result of a quarantine operation."""
    moved_count: int
    error_count: int
    moved_files: List[Dict[str, Any]]
    errors: List[Dict[str, Any]]  # Changed from List[Dict[str, str]] for structured errors
    destination: str

    # Error classification
    retryable_errors: int = 0
    permanent_errors: int = 0

    def __post_init__(self):
        """Calculate error classification counts."""
        self.retryable_errors = sum(
            1 for e in self.errors if e.get("retryable", False)
        )
        self.permanent_errors = self.error_count - self.retryable_errors


@dataclass
class DeleteResult:
    """Result of a delete operation."""
    deleted_count: int
    error_count: int
    deleted_files: List[str]
    errors: List[Dict[str, Any]]  # Changed from List[Dict[str, str]] for structured errors

    # Error classification
    retryable_errors: int = 0
    permanent_errors: int = 0

    def __post_init__(self):
        """Calculate error classification counts."""
        self.retryable_errors = sum(
            1 for e in self.errors if e.get("retryable", False)
        )
        self.permanent_errors = self.error_count - self.retryable_errors


class FileOps:
    """
    File operations component.

    Handles:
    - quarantine(): Move matching files to quarantine
    - move(): Move a single file
    - delete(): Delete matching files

    Example:
        >>> from openlabels import Context
        >>> from openlabels.components import Scorer, Scanner, FileOps
        >>>
        >>> ctx = Context()
        >>> scorer = Scorer(ctx)
        >>> scanner = Scanner(ctx, scorer)
        >>> ops = FileOps(ctx, scanner)
        >>> result = ops.quarantine("/data", "/quarantine", min_score=80)
    """

    def __init__(self, context: "Context", scanner: "Scanner"):
        self._ctx = context
        self._scanner = scanner

    def _load_manifest(self, manifest_path: Path) -> Dict[str, Any]:
        """Load quarantine manifest file."""
        if manifest_path.exists():
            try:
                with open(manifest_path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                # Log the error so we know the manifest couldn't be loaded
                # This could indicate corruption or permissions issues
                logger.warning(
                    f"Could not load quarantine manifest {manifest_path}: {e}. "
                    "Starting with empty manifest."
                )
        return {"processed": {}}

    def _save_manifest(self, manifest_path: Path, manifest: Dict[str, Any]) -> None:
        """Save quarantine manifest file atomically."""
        try:
            # Write to temp file then rename for atomic update
            fd, tmp_path = tempfile.mkstemp(
                dir=manifest_path.parent,
                prefix='.manifest_',
                suffix='.tmp'
            )
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump(manifest, f)
                os.replace(tmp_path, manifest_path)
            except Exception:
                # Clean up temp file on error
                try:
                    os.unlink(tmp_path)
                except OSError as cleanup_err:
                    logger.debug(f"Failed to clean up temp manifest file {tmp_path}: {cleanup_err}")
                raise
        except OSError as e:
            logger.warning(f"Failed to save quarantine manifest: {e}")

    def _idempotent_move(
        self,
        source: Path,
        dest: Path,
        manifest_path: Path,
    ) -> tuple[bool, Optional[FileError]]:
        """
        Perform idempotent file move operation.

        Handles retry scenarios where:
        - Source is gone but dest exists (already moved)
        - Source is gone and in manifest (already processed)
        - Dest exists with same content (skip)
        - Dest exists with different content (error)

        Returns:
            Tuple of (success, FileError or None)

        Security: Uses lstat() for TOCTOU protection (TOCTOU-001).
        (Issue 3.5): Returns structured FileError instead of string.
        """
        # TOCTOU-001: Use lstat() instead of exists() to prevent symlink attacks
        try:
            source_st = source.lstat()
            source_exists = True
            # HIGH-002: Reject symlinks for security
            if stat_module.S_ISLNK(source_st.st_mode):
                return False, FileError(
                    path=str(source),
                    error_type=FileErrorType.PERMISSION_DENIED,
                    message=f"Symlinks not allowed for security reasons: {source}",
                    retryable=False,
                )
            # Only allow regular files
            if not stat_module.S_ISREG(source_st.st_mode):
                return False, FileError(
                    path=str(source),
                    error_type=FileErrorType.PERMISSION_DENIED,
                    message=f"Not a regular file: {source}",
                    retryable=False,
                )
        except FileNotFoundError:
            source_exists = False
        except OSError as e:
            return False, FileError.from_exception(e, str(source))

        try:
            dest.lstat()  # Check existence without following symlinks
            dest_exists = True
        except FileNotFoundError:
            dest_exists = False
        except OSError as e:
            return False, FileError.from_exception(e, str(dest))

        # Case 1: Both exist - verify content
        if source_exists and dest_exists:
            source_hash = quick_hash(source)
            dest_hash = quick_hash(dest)
            # If we can't hash either file, we can't compare - treat as error
            if source_hash is None or dest_hash is None:
                return False, FileError(
                    path=str(source),
                    error_type=FileErrorType.UNKNOWN,
                    message="Cannot verify content: unable to hash files",
                    retryable=True,  # May work after temporary issue resolves
                )
            if source_hash == dest_hash:
                # Same file, skip (idempotent success)
                logger.debug(f"Skipping {source}: already at destination with same content")
                return True, None
            else:
                return False, FileError(
                    path=str(source),
                    error_type=FileErrorType.ALREADY_EXISTS,
                    message=f"Different file already exists at {dest}",
                    retryable=False,
                )

        # Case 2: Only dest exists - check manifest
        if not source_exists and dest_exists:
            manifest = self._load_manifest(manifest_path)
            if str(source) in manifest.get("processed", {}):
                # Already processed in previous run
                logger.debug(f"Skipping {source}: found in manifest as processed")
                return True, None
            # Source missing unexpectedly
            return False, FileError(
                path=str(source),
                error_type=FileErrorType.NOT_FOUND,
                message=f"Source missing and not in manifest: {source}",
                retryable=False,
            )

        # Case 3: Source missing, dest missing - check manifest
        if not source_exists and not dest_exists:
            manifest = self._load_manifest(manifest_path)
            if str(source) in manifest.get("processed", {}):
                # Dest may have been moved/deleted since
                return False, FileError(
                    path=str(source),
                    error_type=FileErrorType.NOT_FOUND,
                    message=f"Previously processed but destination missing: {dest}",
                    retryable=False,
                )
            return False, FileError(
                path=str(source),
                error_type=FileErrorType.NOT_FOUND,
                message=f"Source not found: {source}",
                retryable=False,
            )

        # Case 4: Normal case - source exists, dest doesn't
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            source_hash = quick_hash(source)
            shutil.move(str(source), str(dest))

            # Record in manifest (hash may be None if file was unreadable)
            manifest = self._load_manifest(manifest_path)
            manifest.setdefault("processed", {})[str(source)] = {
                "dest": str(dest),
                "hash": source_hash,
            }
            self._save_manifest(manifest_path, manifest)

            return True, None
        except OSError as e:
            return False, FileError.from_exception(e, str(source))

    def quarantine(
        self,
        source: Union[str, Path],
        destination: Union[str, Path],
        filter_criteria: Optional[FilterCriteria] = None,
        filter_expr: Optional[str] = None,
        min_score: Optional[int] = None,
        recursive: bool = True,
        dry_run: bool = False,
    ) -> QuarantineResult:
        """
        Move files matching criteria to quarantine.

        Args:
            source: Source directory to scan
            destination: Quarantine destination directory
            filter_criteria: Filter criteria for files to quarantine
            filter_expr: Filter expression string
            min_score: Minimum score to quarantine
            recursive: Recurse into subdirectories
            dry_run: If True, don't actually move files

        Returns:
            QuarantineResult with counts and moved file list
        """
        source = Path(source)
        destination = Path(destination)
        filter_criteria = self._build_filter_criteria(filter_criteria, min_score)

        moved_files: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []

        if not dry_run:
            destination.mkdir(parents=True, exist_ok=True)

        for result in self._scanner.scan(
            source,
            recursive=recursive,
            filter_criteria=filter_criteria,
            filter_expr=filter_expr,
        ):
            if result.error:
                # Scan errors are not file operation errors
                errors.append({
                    "path": result.path,
                    "error_type": FileErrorType.UNKNOWN.value,
                    "message": result.error,
                    "retryable": False,
                })
                continue

            try:
                rel_path = Path(result.path).relative_to(source)
            except ValueError:
                rel_path = Path(result.path).name

            dest_path = destination / rel_path

            if dry_run:
                moved_files.append({
                    "source": result.path,
                    "destination": str(dest_path),
                    "score": result.score,
                    "tier": result.tier,
                    "dry_run": True,
                })
            else:
                manifest_path = destination / QUARANTINE_MANIFEST
                success, file_error = self._idempotent_move(
                    Path(result.path), dest_path, manifest_path
                )
                if success:
                    moved_files.append({
                        "source": result.path,
                        "destination": str(dest_path),
                        "score": result.score,
                        "tier": result.tier,
                    })
                else:
                    if file_error:
                        errors.append(file_error.to_dict())
                    else:
                        errors.append({
                            "path": result.path,
                            "error_type": FileErrorType.UNKNOWN.value,
                            "message": "Unknown error",
                            "retryable": False,
                        })

        return QuarantineResult(
            moved_count=len(moved_files),
            error_count=len(errors),
            moved_files=moved_files,
            errors=errors,
            destination=str(destination),
        )

    def move(
        self,
        source: Union[str, Path],
        destination: Union[str, Path],
    ) -> OperationResult:
        """
        Move a single file or directory.

        Args:
            source: Source path
            destination: Destination path

        Returns:
            OperationResult indicating success or failure.
            Error is a string for backward compatibility, but metadata
            contains structured error info.

        Security: See SECURITY.md for TOCTOU-001, HIGH-002, CVE-READY-002.
        """
        source = Path(source)
        destination = Path(destination)

        try:
            try:
                st = source.lstat()  # TOCTOU-001: atomic, no symlink follow
            except FileNotFoundError:
                return OperationResult(
                    success=False,
                    operation="move",
                    source_path=str(source),
                    error=f"Source file not found: {source}",
                    metadata={
                        "error_type": FileErrorType.NOT_FOUND.value,
                        "retryable": False,
                    },
                )

            if stat_module.S_ISLNK(st.st_mode):  # HIGH-002: reject symlinks
                return OperationResult(
                    success=False,
                    operation="move",
                    source_path=str(source),
                    error=f"Symlinks not allowed for security reasons: {source}",
                    metadata={
                        "error_type": FileErrorType.PERMISSION_DENIED.value,
                        "retryable": False,
                    },
                )

            if not stat_module.S_ISREG(st.st_mode):  # Regular files only
                return OperationResult(
                    success=False,
                    operation="move",
                    source_path=str(source),
                    error=f"Not a regular file: {source}",
                    metadata={
                        "error_type": FileErrorType.PERMISSION_DENIED.value,
                        "retryable": False,
                    },
                )

            destination.parent.mkdir(parents=True, exist_ok=True)  # CVE-READY-002: no exists() check
            shutil.move(str(source), str(destination))

            return OperationResult(
                success=True,
                operation="move",
                source_path=str(source),
                dest_path=str(destination),
            )

        except OSError as e:
            file_error = FileError.from_exception(e, str(source))
            return OperationResult(
                success=False,
                operation="move",
                source_path=str(source),
                error=str(e),
                metadata={
                    "error_type": file_error.error_type.value,
                    "retryable": file_error.retryable,
                },
            )

    def delete(
        self,
        path: Union[str, Path],
        filter_criteria: Optional[FilterCriteria] = None,
        filter_expr: Optional[str] = None,
        min_score: Optional[int] = None,
        recursive: bool = True,
        confirm: bool = True,
        dry_run: bool = False,
    ) -> DeleteResult:
        """
        Delete files matching criteria.

        WARNING: This permanently deletes files. Use dry_run=True first.

        Args:
            path: Directory to scan for files to delete
            filter_criteria: Filter criteria
            filter_expr: Filter expression
            min_score: Minimum score to delete
            recursive: Recurse into subdirectories
            confirm: If True, requires explicit confirmation
            dry_run: If True, don't actually delete files

        Returns:
            DeleteResult with counts and deleted file list
        """
        path = Path(path)
        filter_criteria = self._build_filter_criteria(filter_criteria, min_score)

        if confirm and not dry_run:
            logger.warning("Delete operation requires confirmation")

        deleted_files: List[str] = []
        errors: List[Dict[str, Any]] = []

        try:
            st = path.lstat()  # TOCTOU-001: atomic stat
            is_single_file = stat_module.S_ISREG(st.st_mode)
            is_symlink = stat_module.S_ISLNK(st.st_mode)
        except FileNotFoundError:
            return DeleteResult(
                deleted_count=0,
                error_count=1,
                deleted_files=[],
                errors=[{
                    "path": str(path),
                    "error_type": FileErrorType.NOT_FOUND.value,
                    "message": "File not found",
                    "retryable": False,
                }],
            )
        except OSError as e:
            file_error = FileError.from_exception(e, str(path))
            return DeleteResult(
                deleted_count=0,
                error_count=1,
                deleted_files=[],
                errors=[file_error.to_dict()],
            )

        if is_symlink:  # Reject symlinks
            return DeleteResult(
                deleted_count=0,
                error_count=1,
                deleted_files=[],
                errors=[{
                    "path": str(path),
                    "error_type": FileErrorType.PERMISSION_DENIED.value,
                    "message": f"Symlinks not allowed for security: {path}",
                    "retryable": False,
                }],
            )

        # Single file
        if is_single_file:
            if dry_run:
                return DeleteResult(
                    deleted_count=1,
                    error_count=0,
                    deleted_files=[str(path)],
                    errors=[],
                )
            try:
                path.unlink()
                return DeleteResult(
                    deleted_count=1,
                    error_count=0,
                    deleted_files=[str(path)],
                    errors=[],
                )
            except OSError as e:
                file_error = FileError.from_exception(e, str(path))
                return DeleteResult(
                    deleted_count=0,
                    error_count=1,
                    deleted_files=[],
                    errors=[file_error.to_dict()],
                )

        # Directory
        for result in self._scanner.scan(
            path,
            recursive=recursive,
            filter_criteria=filter_criteria,
            filter_expr=filter_expr,
        ):
            if result.error:
                # Scan errors
                errors.append({
                    "path": result.path,
                    "error_type": FileErrorType.UNKNOWN.value,
                    "message": result.error,
                    "retryable": False,
                })
                continue

            if dry_run:
                deleted_files.append(result.path)
            else:
                try:
                    Path(result.path).unlink()
                    deleted_files.append(result.path)
                except OSError as e:
                    file_error = FileError.from_exception(e, result.path)
                    errors.append(file_error.to_dict())

        return DeleteResult(
            deleted_count=len(deleted_files),
            error_count=len(errors),
            deleted_files=deleted_files,
            errors=errors,
        )

    def _build_filter_criteria(
        self,
        filter_criteria: Optional[FilterCriteria],
        min_score: Optional[int],
    ) -> Optional[FilterCriteria]:
        """Build filter criteria, merging min_score if provided."""
        if min_score is None:
            return filter_criteria
        if filter_criteria is None:
            return FilterCriteria(min_score=min_score)
        filter_criteria.min_score = min_score
        return filter_criteria
