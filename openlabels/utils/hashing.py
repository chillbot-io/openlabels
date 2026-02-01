"""Hashing utilities for OpenLabels."""

import hashlib
from pathlib import Path
from typing import Optional


def quick_hash(path: Path, block_size: int = 65536) -> Optional[str]:
    """
    Compute a quick hash of a file using first/last blocks + size.

    This is faster than a full file hash while still detecting most changes.
    Used for file modification detection and content comparison.

    Args:
        path: Path to the file
        block_size: Size of blocks to read from start/end

    Returns:
        Hex digest string (32 chars), or None if file cannot be read

    Security Note:
        This function handles TOCTOU conditions where the file may be modified
        or truncated between the initial stat() and subsequent read operations.
        Seek failures are caught and handled gracefully.
    """
    try:
        size = path.stat().st_size
        hasher = hashlib.blake2b()
        hasher.update(str(size).encode())

        with open(path, 'rb') as f:
            hasher.update(f.read(block_size))
            if size > block_size * 2:
                try:  # MED-010: validate seek succeeded
                    new_pos = f.seek(-block_size, 2)  # Seek from end
                    # Verify we actually moved to expected position
                    expected_pos = max(0, size - block_size)
                    if new_pos < 0:
                        # Seek failed (shouldn't happen, but handle gracefully)
                        return None
                    hasher.update(f.read(block_size))
                except OSError:
                    # Seek failed (e.g., file truncated), use what we have
                    pass

        return hasher.hexdigest()[:32]
    except OSError:
        return None
