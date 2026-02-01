"""
OpenLabels Unified Label Reader.

Reads labels from files using the appropriate transport mechanism:
1. Embedded labels (native metadata) for supported file types
2. Virtual labels (xattr + index) for other files

Per the spec, transport priority is:
1. Check native metadata first (for supported file types)
2. Check extended attributes (for all file types)
"""

import logging
import stat as stat_module
from pathlib import Path
from typing import Optional, Union, Tuple
from dataclasses import dataclass

from ..core.labels import LabelSet, VirtualLabelPointer, compute_content_hash_file
from .embed import supports_embedded_labels, read_embedded_label, write_embedded_label
from .virtual import (
    read_virtual_label,
    write_virtual_label,
    read_cloud_label,
)
from .index import get_default_index, LabelIndex

logger = logging.getLogger(__name__)


@dataclass
class LabelReadResult:
    """Result of reading a label from a file."""
    label_set: Optional[LabelSet]
    transport: str  # "embedded", "virtual", "cloud", or "none"
    verified: bool  # True if content hash matches current file
    pointer: Optional[VirtualLabelPointer] = None


def read_label(
    path: Union[str, Path],
    index: Optional[LabelIndex] = None,
    verify_hash: bool = True,
) -> LabelReadResult:
    """
    Read a label from a file using the appropriate transport.

    This is the primary function for reading labels. It automatically
    selects the correct transport mechanism based on file type.

    Args:
        path: Path to the file
        index: Optional LabelIndex for virtual label resolution.
               If None, uses default index.
        verify_hash: If True, verify content hash matches current file.

    Returns:
        LabelReadResult with the label set and metadata

    Example:
        >>> result = read_label("document.pdf")
        >>> if result.label_set:
        ...     print(f"Found {len(result.label_set.labels)} labels")
        ...     print(f"Transport: {result.transport}")
        ...     print(f"Verified: {result.verified}")
    """
    path = Path(path)
    idx = index or get_default_index()

    # 1. Try embedded label first (for supported file types)
    if supports_embedded_labels(path):
        label_set = read_embedded_label(path)
        if label_set:
            verified = True
            if verify_hash:
                current_hash = compute_content_hash_file(str(path))
                verified = (current_hash == label_set.content_hash)

            return LabelReadResult(
                label_set=label_set,
                transport="embedded",
                verified=verified,
            )

    # 2. Try virtual label (xattr + index)
    pointer = read_virtual_label(path)
    if pointer:
        label_set = idx.resolve(pointer)
        if label_set:
            verified = True
            if verify_hash:
                current_hash = compute_content_hash_file(str(path))
                verified = (current_hash == pointer.content_hash)

            return LabelReadResult(
                label_set=label_set,
                transport="virtual",
                verified=verified,
                pointer=pointer,
            )

    # 3. No label found
    return LabelReadResult(
        label_set=None,
        transport="none",
        verified=False,
    )


def read_cloud_label_full(
    uri: str,
    index: Optional[LabelIndex] = None,
    **kwargs,
) -> LabelReadResult:
    """
    Read a label from a cloud storage object.

    Args:
        uri: Cloud storage URI (s3://, gs://, azure://)
        index: Optional LabelIndex for resolution
        **kwargs: Additional arguments for cloud client

    Returns:
        LabelReadResult with the label set and metadata
    """
    idx = index or get_default_index()

    pointer = read_cloud_label(uri, **kwargs)
    if pointer:
        label_set = idx.resolve(pointer)
        if label_set:
            return LabelReadResult(
                label_set=label_set,
                transport="cloud",
                verified=False,  # Can't verify without downloading
                pointer=pointer,
            )

    return LabelReadResult(
        label_set=None,
        transport="none",
        verified=False,
    )


def write_label(
    path: Union[str, Path],
    label_set: LabelSet,
    index: Optional[LabelIndex] = None,
    risk_score: Optional[int] = None,
    risk_tier: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Write a label to a file using the appropriate transport.

    For files that support native metadata, writes an embedded label.
    For other files, writes a virtual label (xattr) and stores in index.

    Args:
        path: Path to the file
        label_set: The LabelSet to write
        index: Optional LabelIndex. If None, uses default.
        risk_score: Optional risk score to store in index
        risk_tier: Optional risk tier to store in index

    Returns:
        Tuple of (success: bool, transport: str)

    Example:
        >>> from openlabels.core.labels import LabelSet, Label
        >>> labels = [Label(type="SSN", confidence=0.99, detector="checksum", value_hash="15e2b0")]
        >>> with open("data.csv", "rb") as f:
        ...     label_set = LabelSet.create(labels, f.read())
        >>> success, transport = write_label("data.csv", label_set)
        >>> print(f"Wrote {transport} label: {success}")
    """
    path = Path(path)
    idx = index or get_default_index()

    # Try embedded label first
    if supports_embedded_labels(path):
        success = write_embedded_label(path, label_set)
        if success:
            # Also store in index for searchability
            idx.store(label_set, str(path), risk_score, risk_tier)
            return True, "embedded"

    # Fall back to virtual label
    success = write_virtual_label(path, label_set)
    if success:
        # Must store in index for virtual labels
        idx.store(label_set, str(path), risk_score, risk_tier)
        return True, "virtual"

    return False, "none"


def has_label(path: Union[str, Path]) -> bool:
    """
    Check if a file has any label (embedded or virtual).

    Args:
        path: Path to the file

    Returns:
        True if the file has a label
    """
    path = Path(path)

    # Check embedded
    if supports_embedded_labels(path):
        if read_embedded_label(path) is not None:
            return True

    # Check virtual
    if read_virtual_label(path) is not None:
        return True

    return False


def get_label_transport(path: Union[str, Path]) -> str:
    """
    Determine which transport mechanism a file uses for labels.

    Args:
        path: Path to the file

    Returns:
        Transport type: "embedded", "virtual", or "none"
    """
    path = Path(path)

    # Check embedded first
    if supports_embedded_labels(path):
        if read_embedded_label(path) is not None:
            return "embedded"

    # Check virtual
    if read_virtual_label(path) is not None:
        return "virtual"

    return "none"


def verify_label(path: Union[str, Path]) -> Tuple[bool, str]:
    """
    Verify that a file's label matches its current content.

    Computes the current content hash and compares to the stored hash.

    Args:
        path: Path to the file

    Returns:
        Tuple of (is_valid: bool, reason: str)

    Example:
        >>> is_valid, reason = verify_label("document.pdf")
        >>> if not is_valid:
        ...     print(f"Label invalid: {reason}")
    """
    result = read_label(path, verify_hash=True)

    if result.label_set is None:
        return False, "no_label"

    if result.verified:
        return True, "valid"
    else:
        return False, "hash_mismatch"


def rescan_if_stale(
    path: Union[str, Path],
    scanner_func=None,
) -> Optional[LabelSet]:
    """
    Check if a file needs rescanning and optionally rescan.

    A label is considered stale if the content hash doesn't match
    the current file content.

    Args:
        path: Path to the file
        scanner_func: Optional function to call for rescanning.
                     Signature: scanner_func(path) -> LabelSet

    Returns:
        New LabelSet if rescanned, existing LabelSet if valid,
        None if no scanner provided and rescan needed.
    """
    result = read_label(path, verify_hash=True)

    if result.label_set is None or not result.verified:
        # Need to rescan
        if scanner_func:
            return scanner_func(path)
        return None

    # Label is still valid
    return result.label_set



# --- Batch Operations ---


def read_labels_batch(
    paths: list,
    index: Optional[LabelIndex] = None,
    verify_hash: bool = False,
) -> dict:
    """
    Read labels from multiple files.

    Args:
        paths: List of file paths
        index: Optional LabelIndex
        verify_hash: Whether to verify content hashes

    Returns:
        Dict mapping path -> LabelReadResult
    """
    results = {}
    for path in paths:
        results[str(path)] = read_label(path, index, verify_hash)
    return results


def find_unlabeled(directory: Union[str, Path], recursive: bool = True) -> list:
    """
    Find files without labels in a directory.

    Args:
        directory: Directory to search
        recursive: Whether to search recursively

    Returns:
        List of paths to unlabeled files
    """
    directory = Path(directory)
    unlabeled = []

    if recursive:
        files = directory.rglob("*")
    else:
        files = directory.glob("*")

    for path in files:
        try:
            st = path.lstat()  # TOCTOU-001
            if stat_module.S_ISREG(st.st_mode) and not has_label(path):
                unlabeled.append(path)
        except OSError as e:
            # Log inaccessible files at DEBUG level
            logger.debug(f"Could not access file during unlabeled scan: {path}: {e}")
            continue

    return unlabeled


def find_stale_labels(
    directory: Union[str, Path],
    recursive: bool = True,
) -> list:
    """
    Find files with stale labels (hash mismatch).

    Args:
        directory: Directory to search
        recursive: Whether to search recursively

    Returns:
        List of paths with stale labels
    """
    directory = Path(directory)
    stale = []

    if recursive:
        files = directory.rglob("*")
    else:
        files = directory.glob("*")

    for path in files:
        try:
            st = path.lstat()  # TOCTOU-001
            if stat_module.S_ISREG(st.st_mode):
                is_valid, reason = verify_label(path)
                if reason == "hash_mismatch":
                    stale.append(path)
        except OSError as e:
            # Log inaccessible files at DEBUG level
            logger.debug(f"Could not access file during stale label scan: {path}: {e}")
            continue

    return stale
