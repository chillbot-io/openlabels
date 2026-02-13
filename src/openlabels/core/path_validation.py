"""
Path validation for preventing path traversal attacks.

Security features:
- Path normalization to prevent traversal (../, ./, etc.)
- Null byte injection prevention
- System directory access blocking
- Sensitive file pattern blocking
"""

import logging
import os

logger = logging.getLogger(__name__)


# Security: Paths that are never allowed to be accessed
BLOCKED_PATH_PREFIXES = (
    "/etc/",
    "/var/",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/root/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/boot/",
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
    "C:\\ProgramData\\",
)

# Security: File patterns that should never be accessed
BLOCKED_FILE_PATTERNS = (
    ".env",
    ".git/",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    ".htpasswd",
    "shadow",
    "passwd",
    "credentials",
)


class PathValidationError(ValueError):
    """Raised when path validation fails."""
    pass


def validate_path(
    file_path: str,
    *,
    require_exists: bool = False,
    require_parent_exists: bool = False,
    allow_relative: bool = True,
) -> str:
    """
    Validate a file path to prevent path traversal attacks.

    Security checks:
    1. Strip null bytes to prevent null byte injection
    2. Normalize path to prevent traversal (../, ./, etc.)
    3. Block access to system directories
    4. Block access to sensitive files

    Args:
        file_path: The file path to validate
        require_exists: If True, raise error if path doesn't exist
        require_parent_exists: If True, raise error if parent dir doesn't exist
        allow_relative: If True, allow relative paths (converts to absolute)

    Returns:
        Canonicalized safe path

    Raises:
        PathValidationError: If path is invalid, blocked, or doesn't meet requirements
    """
    if not file_path:
        raise PathValidationError("File path is required")

    if not isinstance(file_path, str):
        raise PathValidationError("File path must be a string")

    # Security: Strip null bytes to prevent null byte injection attacks
    # Null bytes can be used to truncate paths: "/data/file.pdf\x00.txt" -> "/data/file.pdf"
    if "\x00" in file_path:
        logger.warning(f"Null byte injection attempt detected: {repr(file_path)}")
        file_path = file_path.replace("\x00", "")

    # Store original for traversal detection
    original_path = file_path

    # Check blocked paths on original path first (before abspath mangles Windows paths on Linux)
    # This ensures Windows paths like C:\Windows\ are blocked even on Linux systems
    _check_blocked_paths(original_path)

    # Normalize the path to resolve .. and . components
    # This converts paths like /data/../etc/passwd to /etc/passwd
    try:
        if allow_relative:
            canonical_path = os.path.normpath(os.path.abspath(file_path))
        else:
            if not os.path.isabs(file_path):
                raise PathValidationError("Path must be absolute")
            canonical_path = os.path.normpath(file_path)
    except (ValueError, TypeError) as e:
        logger.warning(f"Invalid file path format: {file_path} - {e}")
        raise PathValidationError(f"Invalid file path format: {e}") from e

    # Check if path traversal was attempted
    # If original path contains "..", log a warning (the path was normalized)
    if ".." in original_path:
        logger.warning(f"Path traversal attempt detected: {original_path}")
        raise PathValidationError("Path traversal is not allowed")

    # Block access to system directories (also check canonical path for Unix paths)
    _check_blocked_paths(canonical_path)

    # Block access to sensitive files
    _check_blocked_patterns(canonical_path)

    # Check existence requirements
    if require_exists and not os.path.exists(canonical_path):
        raise PathValidationError(f"Path does not exist: {canonical_path}")

    if require_parent_exists:
        parent = os.path.dirname(canonical_path)
        if not os.path.exists(parent):
            raise PathValidationError(f"Parent directory does not exist: {parent}")

    return canonical_path


def validate_output_path(output_path: str, *, create_parent: bool = False) -> str:
    """
    Validate an output file path for safe writing.

    This is specifically for CLI commands that write output files.
    Additional checks beyond validate_path:
    - Warns if file already exists
    - Can optionally create parent directory

    Args:
        output_path: The output file path to validate
        create_parent: If True, create parent directory if it doesn't exist

    Returns:
        Canonicalized safe path

    Raises:
        PathValidationError: If path is invalid or blocked
    """
    canonical_path = validate_path(output_path, allow_relative=True)

    parent = os.path.dirname(canonical_path)
    if parent and not os.path.exists(parent):
        if create_parent:
            try:
                os.makedirs(parent, exist_ok=True)
                logger.debug(f"Created output directory: {parent}")
            except OSError as e:
                raise PathValidationError(f"Cannot create output directory: {e}") from e
        else:
            raise PathValidationError(f"Output directory does not exist: {parent}")

    # Check if we can write to the destination
    if os.path.exists(canonical_path):
        if os.path.isdir(canonical_path):
            raise PathValidationError(f"Output path is a directory: {canonical_path}")
        # File exists - we'll overwrite it, which is usually expected behavior
        logger.debug(f"Output file exists, will be overwritten: {canonical_path}")

    return canonical_path


def _check_blocked_paths(path: str) -> None:
    """Check if path is in a blocked system directory."""
    path_lower = path.lower()
    for blocked in BLOCKED_PATH_PREFIXES:
        blocked_lower = blocked.lower()
        if path_lower.startswith(blocked_lower):
            logger.warning(f"Blocked access to system path: {path}")
            raise PathValidationError("Access to system directories is not allowed")


def _check_blocked_patterns(path: str) -> None:
    """Check if path matches a blocked file pattern."""
    path_parts = path.lower().replace("\\", "/")
    for pattern in BLOCKED_FILE_PATTERNS:
        if pattern in path_parts:
            logger.warning(f"Blocked access to sensitive file: {path}")
            raise PathValidationError("Access to this file type is not allowed")


