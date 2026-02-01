"""
Encrypted image file storage for redacted images.

Stores face-blurred and PHI-redacted images encrypted on disk,
separate from SQLite to avoid BLOB performance issues.

File structure:
    ~/.scrubiq/
    ├── vault.db
    └── images/
        ├── {job_id}_face_blurred.enc
        ├── {job_id}_redacted.enc
        └── {job_id}_redacted.pdf.enc
"""

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple, List

from .database import Database
from ..crypto import KeyManager

logger = logging.getLogger(__name__)


class ImageFileType(str, Enum):
    """Type of stored image file."""
    FACE_BLURRED = "face_blurred"  # Intermediate: face blur only
    REDACTED = "redacted"          # Final: face blur + PHI redaction
    REDACTED_PDF = "redacted_pdf"  # Multi-page output as PDF


@dataclass
class ImageFileInfo:
    """Metadata about a stored image file."""
    job_id: str
    file_type: ImageFileType
    encrypted_path: str  # Relative path in images dir
    original_filename: str
    content_type: str  # image/png, application/pdf
    sha256_hash: str   # Hash of plaintext for integrity
    size_bytes: int
    created_at: datetime


class ImageStore:
    """
    Encrypted image storage backed by filesystem + SQLite metadata.
    
    Images are encrypted with AES-256-GCM using the session DEK.
    Metadata (paths, hashes) stored in SQLite for lookup.
    
    On vault lock, DEK is wiped making files unreadable.
    """
    
    def __init__(
        self, 
        db: Database, 
        keys: KeyManager, 
        images_dir: Path,
        session_id: str,
    ):
        """
        Initialize image store.
        
        Args:
            db: Database connection
            keys: Key manager for encryption
            images_dir: Directory for encrypted image files
            session_id: Current session ID
        """
        self._db = db
        self._keys = keys
        self._images_dir = images_dir
        self._session_id = session_id
        
        # Ensure images directory exists
        self._images_dir.mkdir(parents=True, exist_ok=True)
    
    def store(
        self,
        job_id: str,
        file_type: ImageFileType,
        image_bytes: bytes,
        original_filename: str,
        content_type: str,
    ) -> ImageFileInfo:
        """
        Store an encrypted image file.
        
        Args:
            job_id: Associated job ID
            file_type: Type of image (face_blurred, redacted, etc.)
            image_bytes: Plaintext image data
            original_filename: Original uploaded filename
            content_type: MIME type (image/png, application/pdf)
            
        Returns:
            ImageFileInfo with storage metadata
        """
        # Generate filename based on type
        ext = ".pdf.enc" if file_type == ImageFileType.REDACTED_PDF else ".enc"
        filename = f"{job_id}_{file_type.value}{ext}"
        file_path = self._images_dir / filename
        relative_path = f"images/{filename}"
        
        # Hash plaintext for integrity verification
        sha256_hash = hashlib.sha256(image_bytes).hexdigest()
        
        # Encrypt and write to disk
        encrypted_bytes = self._keys.encrypt(image_bytes)
        file_path.write_bytes(encrypted_bytes)
        
        logger.debug(
            f"Stored encrypted image: {relative_path} "
            f"({len(image_bytes)} bytes plaintext, {len(encrypted_bytes)} bytes encrypted)"
        )
        
        # Store metadata in database
        created_at = datetime.now(timezone.utc)
        self._db.execute("""
            INSERT INTO image_files 
            (job_id, file_type, encrypted_path, original_filename, 
             content_type, sha256_hash, size_bytes, session_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id, file_type) DO UPDATE SET
                encrypted_path = excluded.encrypted_path,
                sha256_hash = excluded.sha256_hash,
                size_bytes = excluded.size_bytes,
                created_at = excluded.created_at
        """, (
            job_id, file_type.value, relative_path, original_filename,
            content_type, sha256_hash, len(image_bytes), self._session_id,
            created_at.isoformat(),
        ))
        
        return ImageFileInfo(
            job_id=job_id,
            file_type=file_type,
            encrypted_path=relative_path,
            original_filename=original_filename,
            content_type=content_type,
            sha256_hash=sha256_hash,
            size_bytes=len(image_bytes),
            created_at=created_at,
        )
    
    def retrieve(
        self,
        job_id: str,
        file_type: ImageFileType = ImageFileType.REDACTED,
    ) -> Optional[Tuple[bytes, ImageFileInfo]]:
        """
        Retrieve and decrypt an image file.
        
        Args:
            job_id: Job ID to retrieve
            file_type: Which image type (defaults to REDACTED)
            
        Returns:
            Tuple of (decrypted_bytes, info) or None if not found
        """
        # Look up metadata
        # SECURITY: Filter by session_id to prevent cross-tenant data access
        # Without this, an attacker who guesses another tenant's job_id
        # could access their files
        row = self._db.fetchone("""
            SELECT job_id, file_type, encrypted_path, original_filename,
                   content_type, sha256_hash, size_bytes, created_at
            FROM image_files
            WHERE job_id = ? AND file_type = ? AND session_id = ?
        """, (job_id, file_type.value, self._session_id))
        
        if not row:
            return None
        
        info = ImageFileInfo(
            job_id=row["job_id"],
            file_type=ImageFileType(row["file_type"]),
            encrypted_path=row["encrypted_path"],
            original_filename=row["original_filename"],
            content_type=row["content_type"],
            sha256_hash=row["sha256_hash"],
            size_bytes=row["size_bytes"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )
        
        # Construct full path and read encrypted file
        file_path = (self._images_dir.parent / info.encrypted_path).resolve()

        # Security: Validate path is within images directory (prevent path traversal)
        images_dir_resolved = self._images_dir.resolve()
        if not str(file_path).startswith(str(images_dir_resolved)):
            logger.error(f"Path traversal attempt detected: {file_path}")
            return None

        if not file_path.exists():
            logger.error(f"Image file not found: {file_path}")
            return None
        
        encrypted_bytes = file_path.read_bytes()
        
        # Decrypt
        try:
            decrypted_bytes = self._keys.decrypt(encrypted_bytes)
        except Exception as e:
            logger.error(f"Failed to decrypt image {job_id}: {e}")
            return None
        
        # Verify integrity
        actual_hash = hashlib.sha256(decrypted_bytes).hexdigest()
        if actual_hash != info.sha256_hash:
            logger.error(
                f"Image integrity check failed for {job_id}: "
                f"expected {info.sha256_hash}, got {actual_hash}"
            )
            return None
        
        return decrypted_bytes, info
    
    def get_info(
        self,
        job_id: str,
        file_type: ImageFileType = ImageFileType.REDACTED,
    ) -> Optional[ImageFileInfo]:
        """Get metadata without decrypting the file."""
        row = self._db.fetchone("""
            SELECT job_id, file_type, encrypted_path, original_filename,
                   content_type, sha256_hash, size_bytes, created_at
            FROM image_files
            WHERE job_id = ? AND file_type = ?
        """, (job_id, file_type.value))
        
        if not row:
            return None
        
        return ImageFileInfo(
            job_id=row["job_id"],
            file_type=ImageFileType(row["file_type"]),
            encrypted_path=row["encrypted_path"],
            original_filename=row["original_filename"],
            content_type=row["content_type"],
            sha256_hash=row["sha256_hash"],
            size_bytes=row["size_bytes"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )
    
    def has_redacted_image(self, job_id: str) -> bool:
        """Check if a redacted image exists for a job."""
        # Check for either single image or PDF
        row = self._db.fetchone("""
            SELECT 1 FROM image_files
            WHERE job_id = ? AND file_type IN (?, ?)
        """, (job_id, ImageFileType.REDACTED.value, ImageFileType.REDACTED_PDF.value))
        return row is not None
    
    def list_for_job(self, job_id: str) -> List[ImageFileInfo]:
        """List all image files for a job."""
        rows = self._db.fetchall("""
            SELECT job_id, file_type, encrypted_path, original_filename,
                   content_type, sha256_hash, size_bytes, created_at
            FROM image_files
            WHERE job_id = ?
            ORDER BY created_at
        """, (job_id,))
        
        return [
            ImageFileInfo(
                job_id=row["job_id"],
                file_type=ImageFileType(row["file_type"]),
                encrypted_path=row["encrypted_path"],
                original_filename=row["original_filename"],
                content_type=row["content_type"],
                sha256_hash=row["sha256_hash"],
                size_bytes=row["size_bytes"],
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]
    
    def delete(self, job_id: str, file_type: Optional[ImageFileType] = None) -> int:
        """
        Delete image file(s) for a job.
        
        Args:
            job_id: Job ID
            file_type: Specific type to delete, or None for all
            
        Returns:
            Number of files deleted
        """
        if file_type:
            rows = self._db.fetchall("""
                SELECT encrypted_path FROM image_files
                WHERE job_id = ? AND file_type = ?
            """, (job_id, file_type.value))
            
            self._db.execute("""
                DELETE FROM image_files
                WHERE job_id = ? AND file_type = ?
            """, (job_id, file_type.value))
        else:
            rows = self._db.fetchall("""
                SELECT encrypted_path FROM image_files WHERE job_id = ?
            """, (job_id,))
            
            self._db.execute("""
                DELETE FROM image_files WHERE job_id = ?
            """, (job_id,))
        
        # Delete files from disk
        deleted = 0
        for row in rows:
            file_path = self._images_dir.parent / row["encrypted_path"]
            if file_path.exists():
                file_path.unlink()
                deleted += 1
        
        return deleted
    
    def cleanup_orphaned_files(self) -> int:
        """
        Remove encrypted files not tracked in database.
        
        Useful for cleanup after crashes or incomplete operations.
        
        Returns:
            Number of orphaned files removed
        """
        # Get all tracked paths
        rows = self._db.fetchall("SELECT encrypted_path FROM image_files")
        tracked_paths = {row["encrypted_path"] for row in rows}
        
        # Find and remove orphaned files
        removed = 0
        for file_path in self._images_dir.glob("*.enc"):
            relative_path = f"images/{file_path.name}"
            if relative_path not in tracked_paths:
                logger.warning(f"Removing orphaned image file: {file_path}")
                file_path.unlink()
                removed += 1
        
        return removed
    
    def get_storage_stats(self) -> dict:
        """Get storage statistics."""
        row = self._db.fetchone("""
            SELECT 
                COUNT(*) as file_count,
                SUM(size_bytes) as total_plaintext_bytes,
                COUNT(DISTINCT job_id) as job_count
            FROM image_files
        """)
        
        # Calculate actual encrypted size on disk
        encrypted_size = sum(
            f.stat().st_size 
            for f in self._images_dir.glob("*.enc")
            if f.is_file()
        )
        
        return {
            "file_count": row["file_count"] or 0,
            "job_count": row["job_count"] or 0,
            "total_plaintext_bytes": row["total_plaintext_bytes"] or 0,
            "total_encrypted_bytes": encrypted_size,
            "images_dir": str(self._images_dir),
        }
