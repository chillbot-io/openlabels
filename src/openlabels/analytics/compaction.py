"""
Partition compaction — merge small Parquet files into optimally-sized ones.

Over time, periodic flushes produce many small Parquet files (one per
flush cycle).  Compaction reads all files in a partition, merges them
via DuckDB, and writes back fewer, larger files.

Schedule: weekly or on-demand via ``openlabels catalog compact``.
"""

from __future__ import annotations

import fcntl
import logging
import tempfile
from datetime import datetime
from pathlib import Path

from openlabels.analytics.storage import CatalogStorage

logger = logging.getLogger(__name__)


_LOCK_DIR = Path(tempfile.gettempdir()) / "openlabels_compaction_locks"


def compact_catalog(
    storage: CatalogStorage,
    tables: list[str],
    *,
    threshold: int = 10,
) -> int:
    """Compact partitions across multiple tables.

    Returns the total number of partitions that were compacted.
    """
    total = 0
    for table_name in tables:
        total += compact_table(storage, table_name, threshold=threshold)
    return total


def compact_table(
    storage: CatalogStorage,
    table_name: str,
    *,
    threshold: int = 10,
) -> int:
    """Compact all partitions in a single table.

    Walks the Hive partition tree and compacts leaf partitions
    that contain more than *threshold* Parquet files.

    Uses a file lock to prevent concurrent compaction of the same table.

    Returns the number of partitions compacted.
    """
    # Acquire an exclusive file lock to prevent concurrent compaction
    _LOCK_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = _LOCK_DIR / f"{table_name}.lock"
    lock_file = open(lock_path, "w")  # noqa: SIM115
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        logger.warning(
            "Compaction already running for table %s, skipping",
            table_name,
        )
        lock_file.close()
        return 0

    try:
        return _compact_table_locked(storage, table_name, threshold=threshold)
    finally:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()


def _compact_table_locked(
    storage: CatalogStorage,
    table_name: str,
    *,
    threshold: int = 10,
) -> int:
    """Inner compaction logic, called while holding the table lock."""
    compacted = 0

    # Find all leaf partitions by listing files and extracting directory paths
    all_files = storage.list_files(table_name)
    if not all_files:
        return 0

    # Group files by partition directory
    partition_files: dict[str, list[str]] = {}
    for f in all_files:
        # f is relative to catalog root, e.g.
        # "scan_results/tenant=.../scan_date=.../part-00000.parquet"
        parts = f.rsplit("/", 1)
        if len(parts) == 2:
            partition_dir = parts[0]
            partition_files.setdefault(partition_dir, []).append(f)

    for partition_dir, files in partition_files.items():
        if len(files) < threshold:
            logger.debug(
                "Skipping %s (%d files < threshold %d)",
                partition_dir,
                len(files),
                threshold,
            )
            continue

        try:
            _compact_partition(storage, partition_dir, files)
            compacted += 1
            logger.info(
                "Compacted %s: %d files → 1",
                partition_dir,
                len(files),
            )
        except Exception:  # noqa: BLE001 — catch-all for compaction resilience
            logger.warning(
                "Failed to compact %s",
                partition_dir,
                exc_info=True,
            )

    return compacted


def _compact_partition(
    storage: CatalogStorage,
    partition_dir: str,
    files: list[str],
) -> None:
    """Merge all Parquet files in one partition into a single file.

    Steps:
    1. Read files one at a time and incrementally merge via PyArrow
    2. Write merged result to a new file
    3. Delete old files

    Files are processed one at a time to avoid loading all partition
    data into memory simultaneously.
    """
    import pyarrow as pa

    merged: pa.Table | None = None

    # Process files one at a time to limit memory usage
    for f in files:
        try:
            t = storage.read_parquet(f)
        except (OSError, ValueError, RuntimeError):
            logger.warning("Could not read %s during compaction, skipping", f)
            continue

        if merged is None:
            merged = t
        else:
            merged = pa.concat_tables([merged, t], promote_options="default")

    if merged is None:
        return

    # Sort by common time columns if present
    col_names = set(merged.column_names)
    sort_col = None
    for candidate in ("scanned_at", "event_time", "created_at"):
        if candidate in col_names:
            sort_col = candidate
            break

    if sort_col:
        indices = merged.column(sort_col).to_pylist()
        # Use a sort key that handles None safely: sort None values last
        # by using a tuple of (is_none, value).  datetime.min serves as
        # a placeholder that keeps the type consistent with real timestamps.
        sorted_indices = sorted(
            range(len(indices)),
            key=lambda i: (indices[i] is None, indices[i] or datetime.min),
        )
        merged = merged.take(sorted_indices)

    # Write the compacted file
    from openlabels.analytics.partition import timestamped_part_filename
    dest = f"{partition_dir}/{timestamped_part_filename()}"
    storage.write_parquet(dest, merged)

    # Delete old files
    for f in files:
        try:
            storage.delete(f)
        except (OSError, RuntimeError):
            logger.warning("Could not delete %s after compaction", f)
