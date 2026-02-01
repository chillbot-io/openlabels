"""
Input validation utilities for OpenLabels.

Provides consistent validation across all modules that perform
subprocess calls or handle untrusted input.
"""

from ..adapters.scanner.constants import MAX_PATH_LENGTH, MAX_XATTR_VALUE_SIZE

# Characters that could enable shell injection or cause subprocess issues
SHELL_METACHARACTERS = frozenset(['`', '$', '|', ';', '&', '>', '<', '\n', '\r', '\x00'])


def validate_path_for_subprocess(path: str) -> bool:
    """
    Validate path is safe for subprocess calls.

    Checks for:
    - Empty paths
    - Shell metacharacters that could enable injection
    - Excessively long paths

    Args:
        path: File path to validate

    Returns:
        True if path is safe, False otherwise
    """
    if not path:
        return False
    if any(c in path for c in SHELL_METACHARACTERS):
        return False
    if len(path) > MAX_PATH_LENGTH:
        return False
    return True


def validate_xattr_value(value: str) -> bool:
    """
    Validate xattr value is safe for storage.

    Args:
        value: Extended attribute value to validate

    Returns:
        True if value is safe, False otherwise
    """
    if not value:
        return False
    if any(c in value for c in SHELL_METACHARACTERS):
        return False
    if len(value) > MAX_XATTR_VALUE_SIZE:
        return False
    return True
