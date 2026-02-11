# Horizontal Scaling: Coordinator + Fan-Out for Data Scan

## Problem

Today a ScanJob is monolithic: one worker claims the entire job and processes
all files sequentially. For a 10M+ object S3 bucket, scan throughput is
bottlenecked by single-worker I/O and CPU.

## Solution

Coordinator pattern: split a ScanJob into N partitions, fan-out to parallel
workers, aggregate results when all complete.

```
ScanJob (status: coordinating)
  → ScanCoordinator samples bucket, creates N partitions
  → N ScanPartition rows (each with a prefix range)
  → N job_queue entries (task_type = "scan_partition")
  → Workers claim partitions via existing SELECT FOR UPDATE SKIP LOCKED
  → Each partition scans its file range independently
  → Last partition to complete aggregates stats → marks parent job completed
```

## Steps

### Step 1: ScanPartition model + migration

**File: `src/openlabels/server/models.py`**
- Add `ScanPartition` model after `ScanJob`:
  - `id` (UUIDv7 PK)
  - `tenant_id` (FK tenants)
  - `job_id` (FK scan_jobs) — parent job
  - `partition_index` (Integer) — 0-based index
  - `total_partitions` (Integer) — total count for completion check
  - `partition_spec` (JSONB) — `{"start_after": "m", "end_before": "t", "prefix": "data/"}`
  - `status` (JobStatusEnum) — pending/running/completed/failed
  - `worker_id` (String)
  - `started_at`, `completed_at` (DateTime)
  - `files_scanned`, `files_with_pii`, `files_skipped` (Integer)
  - `total_entities` (Integer)
  - `stats` (JSONB) — full stats blob from scan
  - `error` (Text)
- Indexes: `(job_id, status)`, `(job_id, partition_index)` unique

**File: `alembic/versions/<new>_add_scan_partitions.py`**
- Create `scan_partitions` table + indexes

### Step 2: Adapter prefix-range listing

**File: `src/openlabels/adapters/base.py`**
- Add `PartitionSpec` dataclass: `start_after: str | None`, `end_before: str | None`
- Add optional `partition` parameter to `ReadAdapter.list_files()` protocol

**File: `src/openlabels/adapters/s3.py`**
- Add `start_after` and `end_before` support to `list_files()`:
  - Use S3 `StartAfter` param for efficient skip-ahead
  - Filter `key >= end_before` to stop at boundary
  - Break pagination when past boundary (don't enumerate rest of bucket)

### Step 3: ScanCoordinator

**File: `src/openlabels/jobs/coordinator.py`** (new)

```python
class ScanCoordinator:
    """
    Splits a ScanJob into partitions for parallel execution.

    Strategy:
    1. Sample the keyspace to find boundary keys
    2. Create N partitions (N = min(target_workers, estimated_files / min_partition_size))
    3. Each partition gets a key range [start_after, end_before)
    """

    MIN_PARTITION_SIZE = 1000      # Don't create tiny partitions
    MAX_PARTITIONS = 32            # Cap for sanity
    DEFAULT_PARTITIONS = 4         # When we can't estimate size
    SAMPLING_LIMIT = 10000         # Sample first N keys to estimate distribution

    async def coordinate(self, session, job, target, adapter) -> list[ScanPartition]:
        """Partition the scan job and create sub-tasks."""

    async def _estimate_and_partition(self, adapter, target_path, num_partitions) -> list[dict]:
        """Sample the keyspace and compute partition boundaries."""

    async def _create_partition_tasks(self, session, job, partitions) -> None:
        """Create ScanPartition rows + enqueue job_queue entries."""
```

Partitioning strategy for S3:
- List first SAMPLING_LIMIT keys to get distribution
- Use quantile boundaries to split into roughly equal ranges
- Each partition spec: `{"start_after": key_N, "end_before": key_M}`

Fallback for small targets (< MIN_PARTITION_SIZE files):
- Skip partitioning, run as single partition (existing behavior)

### Step 4: Partitioned scan task

**File: `src/openlabels/jobs/tasks/scan_partition.py`** (new)

Core execution:
- Load ScanPartition from DB
- Mark partition running
- Get adapter with partition spec
- Reuse `_detect_and_score()` and inventory logic from scan.py
- Track per-partition stats
- Mark partition completed
- Check if all sibling partitions are done → if so, aggregate + complete parent job

Refactor from scan.py:
- Extract file processing loop into `_process_files()` that both the monolithic
  scan task and the partition task can call
- Share: `_detect_and_score()`, inventory updates, WebSocket streaming, policy evaluation

### Step 5: Worker dispatch

**File: `src/openlabels/jobs/worker.py`**
- Add `scan_coordinate` and `scan_partition` to `_execute_job()` dispatch
- `scan_coordinate` → calls coordinator to split and enqueue
- `scan_partition` → calls partitioned scan task

### Step 6: Scan launch integration

**File: `src/openlabels/jobs/tasks/scan.py`**
- Add logic: when a scan is launched against a target that supports partitioning
  (S3, GCS, Azure Blob) AND the estimated file count exceeds a threshold,
  set job status to "coordinating" and enqueue a `scan_coordinate` task
  instead of running the monolithic scan
- Keep monolithic path as default for filesystem/SharePoint/OneDrive and
  small targets

### Step 7: Aggregation logic

In `scan_partition.py`, after each partition completes:
```python
async def _check_and_aggregate(session, job_id):
    """If all partitions complete, aggregate stats to parent ScanJob."""
    # SELECT COUNT(*) FROM scan_partitions WHERE job_id = ? AND status != 'completed'
    # If 0 remaining: aggregate files_scanned, files_with_pii, etc.
    # Mark parent job completed
    # Run post-scan hooks (auto-labeling, catalog flush, SIEM export)
```

### Step 8: Tests

- `tests/jobs/test_coordinator.py` — unit tests for partition boundary calculation
- `tests/jobs/test_scan_partition.py` — partition execution with mock adapter
- `tests/jobs/test_aggregation.py` — multi-partition completion + aggregation
- `tests/adapters/test_s3_partition.py` — S3 prefix-range listing

## What stays the same

- FileInventory: still only tracks sensitive files (no MFT)
- DistributedScanInventory: Redis dedup prevents double-processing at partition boundaries
- Delta scanning: `should_scan_file()` works per-partition identically
- FolderInventory: updated per-partition, no conflicts (folder paths are unique)
- WebSocket streaming: each partition streams independently
- Auto-labeling + post-scan hooks: run once during aggregation
