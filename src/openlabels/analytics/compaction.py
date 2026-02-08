"""
Partition compaction — merge small Parquet files into optimally-sized ones.

Over time, periodic flushes produce many small Parquet files (one per
flush cycle).  Compaction reads all files in a partition, merges them
via DuckDB, and writes back fewer, larger files.

Schedule: weekly or on-demand via ``openlabels catalog compact``.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pyarrow.parquet as pq

from openlabels.analytics.storage import CatalogStorage

logger = logging.getLogger(__name__)


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

    Returns the number of partitions compacted.
    """
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
        except Exception:
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
    1. Read all existing files into a DuckDB in-memory table
    2. Write merged result to a new file
    3. Delete old files
    """
    # Read all files and merge via PyArrow
    tables = []
    for f in files:
        try:
            t = storage.read_parquet(f)
            tables.append(t)
        except Exception:
            logger.warning("Could not read %s during compaction, skipping", f)

    if not tables:
        return

    import pyarrow as pa
    merged = pa.concat_tables(tables, promote_options="default")

    # Sort by common time columns if present
    col_names = set(merged.column_names)
    sort_col = None
    for candidate in ("scanned_at", "event_time", "created_at"):
        if candidate in col_names:
            sort_col = candidate
            break

    if sort_col:
        indices = merged.column(sort_col).to_pylist()
        sorted_indices = sorted(range(len(indices)), key=lambda i: indices[i] or "")
        merged = merged.take(sorted_indices)

    # Write the compacted file
    from openlabels.analytics.partition import timestamped_part_filename
    dest = f"{partition_dir}/{timestamped_part_filename()}"
    storage.write_parquet(dest, merged)

    # Delete old files
    for f in files:
        try:
            storage.delete(f)
        except Exception:
            logger.warning("Could not delete %s after compaction", f)
