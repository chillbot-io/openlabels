"""
Secure temporary storage for multi-page file processing.

Provides temp directories with restricted permissions for storing
intermediate page images during processing. Ensures cleanup on
completion or crash.

Security considerations:
- Temp files contain face-blurred but not PHI-redacted images
- Restricted permissions (700) on directory
- atexit handler for cleanup on unexpected exit
- Context manager for reliable cleanup
"""

import atexit
import logging
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Iterator, List, Optional
import uuid

logger = logging.getLogger(__name__)

_active_temp_dirs: List[Path] = []  # HIGH-012: thread-safe tracking
_active_temp_dirs_lock = threading.Lock()


def _cleanup_on_exit() -> None:
    """Clean up any remaining temp directories on process exit."""
    with _active_temp_dirs_lock:
        dirs_to_clean = _active_temp_dirs.copy()
        _active_temp_dirs.clear()

    for temp_dir in dirs_to_clean:
        try:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
                logger.debug(f"Cleaned up orphaned temp dir: {temp_dir}")
        except OSError as e:
            logger.warning(f"Failed to clean up temp dir {temp_dir}: {e}")


# Register cleanup with shutdown coordinator (falls back to atexit if unavailable)
def _register_temp_cleanup():
    """Register temp cleanup with shutdown coordinator."""
    try:
        from ...shutdown import get_shutdown_coordinator
        coordinator = get_shutdown_coordinator()
        coordinator.register(
            callback=_cleanup_on_exit,
            name="temp_storage_cleanup",
            priority=5,  # Run after executors (priority 10) finish their work
        )
        logger.debug("Registered temp storage cleanup with shutdown coordinator")
    except Exception as e:
        logger.debug(f"Could not register with shutdown coordinator: {e}")
        # Fall back to atexit
        atexit.register(_cleanup_on_exit)


_register_temp_cleanup()


class SecureTempDir:
    """
    Secure temporary directory for page processing.
    
    Creates a temp directory with restricted permissions (700) and
    ensures cleanup when done.
    
    Usage:
        with SecureTempDir("job_123") as temp_dir:
            # temp_dir is a Path object
            page_path = temp_dir / "page_0.png"
            page_path.write_bytes(image_data)
            # ...process pages...
        # Directory automatically cleaned up
        
    Also supports manual lifecycle:
        temp = SecureTempDir("job_123")
        temp_dir = temp.create()
        try:
            # ...use temp_dir...
        finally:
            temp.cleanup()
    """
    
    def __init__(self, job_id: str, base_dir: Optional[Path] = None):
        """
        Initialize secure temp directory.
        
        Args:
            job_id: Job ID for identification in logs
            base_dir: Optional base directory (uses system temp if None)
        """
        self.job_id = job_id
        self.base_dir = base_dir or Path(tempfile.gettempdir())
        self._path: Optional[Path] = None
    
    @property
    def path(self) -> Optional[Path]:
        """Get temp directory path, or None if not created."""
        return self._path
    
    def create(self) -> Path:
        """
        Create the secure temp directory.
        
        Returns:
            Path to the temp directory
        """
        if self._path and self._path.exists():
            return self._path
        
        # Create unique directory name
        dir_name = f"openlabels_scan_{self.job_id}_{uuid.uuid4().hex[:8]}"
        self._path = self.base_dir / dir_name
        
        # Create with restricted permissions
        self._path.mkdir(mode=0o700, parents=True, exist_ok=True)

        # Track for cleanup on exit (thread-safe)
        with _active_temp_dirs_lock:
            _active_temp_dirs.append(self._path)

        logger.debug(f"Created secure temp dir: {self._path}")
        return self._path
    
    def cleanup(self) -> None:
        """
        Clean up the temp directory.

        Safe to call multiple times.
        """
        if self._path and self._path.exists():
            try:
                shutil.rmtree(self._path)
                logger.debug(f"Cleaned up temp dir: {self._path}")
            except OSError as e:
                logger.warning(f"Failed to clean up temp dir {self._path}: {e}")

            # Remove from tracking list (thread-safe)
            with _active_temp_dirs_lock:
                if self._path in _active_temp_dirs:
                    _active_temp_dirs.remove(self._path)

            self._path = None
    
    def __enter__(self) -> Path:
        """Context manager entry."""
        return self.create()
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - always cleanup."""
        self.cleanup()
    
    # File operations for convenience
    
    def write_page(self, page_num: int, data: bytes, ext: str = ".png") -> Path:
        """
        Write a page to temp storage.
        
        Args:
            page_num: Page number (0-indexed)
            data: Image bytes
            ext: File extension
            
        Returns:
            Path to the written file
        """
        if not self._path:
            raise RuntimeError("Temp directory not created")
        
        page_path = self._path / f"page_{page_num:04d}{ext}"
        page_path.write_bytes(data)
        return page_path
    
    def read_page(self, page_num: int, ext: str = ".png") -> bytes:
        """
        Read a page from temp storage.
        
        Args:
            page_num: Page number (0-indexed)
            ext: File extension
            
        Returns:
            Image bytes
        """
        if not self._path:
            raise RuntimeError("Temp directory not created")
        
        page_path = self._path / f"page_{page_num:04d}{ext}"
        return page_path.read_bytes()
    
    def page_path(self, page_num: int, ext: str = ".png") -> Path:
        """Get path for a page (may not exist yet)."""
        if not self._path:
            raise RuntimeError("Temp directory not created")
        return self._path / f"page_{page_num:04d}{ext}"
    
    def list_pages(self, ext: str = ".png") -> List[Path]:
        """
        List all page files in order.
        
        Returns:
            List of page paths, sorted by page number
        """
        if not self._path or not self._path.exists():
            return []
        
        pages = list(self._path.glob(f"page_*{ext}"))
        pages.sort(key=lambda p: int(p.stem.split("_")[1]))
        return pages
    
    def iter_pages(self, ext: str = ".png") -> Iterator[bytes]:
        """
        Iterate over pages, yielding bytes for each.
        
        Memory efficient - only one page in memory at a time.
        """
        for page_path in self.list_pages(ext):
            yield page_path.read_bytes()
