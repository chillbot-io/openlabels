# OLAP and Data Lake Architecture Plan

**Version:** 1.0
**Status:** Proposed
**Last Updated:** February 2026

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Three-Workload Separation](#2-three-workload-separation)
3. [Storage Backend](#3-storage-backend)
4. [Parquet Catalog Design](#4-parquet-catalog-design)
5. [Delta Write Strategy](#5-delta-write-strategy)
6. [DuckDB Query Engine](#6-duckdb-query-engine)
7. [Module Structure](#7-module-structure)
8. [Configuration](#8-configuration)
9. [Endpoint Migration Map](#9-endpoint-migration-map)
10. [Integration Points](#10-integration-points)
11. [Data Lifecycle and Retention](#11-data-lifecycle-and-retention)
12. [Implementation Phases](#12-implementation-phases)

---

## 1. Motivation

### The Problem

The current OpenLabels architecture uses PostgreSQL for everything — OLTP writes during
scans and OLAP analytical reads for the dashboard. This works at small scale but creates
measurable problems as data grows:

**Symptoms already visible in the codebase:**

| Symptom | Location | What It Reveals |
|---------|----------|-----------------|
| 5,000-row sampling cap | `dashboard.py:299` (`get_entity_trends`) | Can't aggregate full dataset |
| 1,000-row batch streaming | `dashboard.py:366-388` (`_aggregate_entity_counts_streaming`) | In-memory aggregation to avoid Postgres load |
| 10,000-file heatmap cap | `dashboard.py:482` (`HEATMAP_MAX_FILES`) | Full treemap impossible at scale |
| 60-second Redis cache on stats | `dashboard.py:34` (`DASHBOARD_STATS_TTL`) | Hides slow queries behind cache |
| LIMIT 10 on top users | `monitoring.py:442` (`get_access_stats`) | Prevents full user aggregation |
| HAVING > 100 threshold | `monitoring.py:484-496` (`detect_access_anomalies`) | Pre-filters to reduce result set |

**Root cause:** PostgreSQL is optimized for row-at-a-time OLTP access. Analytical queries
(GROUP BY date, COUNT across millions of rows, full-table aggregations) fight against
its row-oriented storage. Adding indexes helps individual queries but hurts write throughput
during scans.

**The constraint:** OpenLabels is a single-server deployment. We cannot add a separate
ClickHouse or Spark cluster. The solution must be embedded and zero-ops.

### The Solution

A **lakehouse pattern** using:

- **Parquet files** on configurable storage (S3, Azure Blob, local/NAS) as the durable
  analytical data store
- **DuckDB** as an embedded columnar query engine that reads Parquet directly
- **PostgreSQL** continues handling OLTP (job queue, config, sessions, active state)

This gives us columnar analytics at zero operational cost — DuckDB is an in-process
library with no server to manage.

---

## 2. Three-Workload Separation

```
┌──────────────────────────────────────────────────────────────────────┐
│                        WRITE PATH (OLTP)                             │
│                                                                      │
│   execute_scan_task() ──► PostgreSQL (ScanResult, FileInventory)     │
│                       ──► Parquet delta flush (post-commit hook)     │
│                                                                      │
│   collect_access_events() ──► PostgreSQL (FileAccessEvent)           │
│                            ──► Parquet append flush (periodic)       │
│                                                                      │
│   audit_log() ──► PostgreSQL (AuditLog)                              │
│                ──► Parquet append flush (periodic)                   │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                      READ PATH — OLTP (PostgreSQL)                   │
│                                                                      │
│   Single-row lookups:  GET /scans/{id}, GET /results/{id}           │
│   Active state:        Job queue, sessions, pending auth             │
│   Config/CRUD:         Targets, labels, schedules, users, settings   │
│   Transactional:       Remediation actions (status updates)          │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                      READ PATH — OLAP (DuckDB + Parquet)             │
│                                                                      │
│   Dashboard:    Trends, entity trends, heatmaps, overall stats       │
│   Monitoring:   Access stats, anomaly detection, heatmap patterns    │
│   Export:       Full CSV/JSON export (streaming from Parquet)         │
│   Remediation:  Stats/summary aggregations                           │
│   Catalog:      File inventory browsing, folder roll-ups             │
└──────────────────────────────────────────────────────────────────────┘
```

**Principle:** PostgreSQL remains the source of truth. Parquet is a derived, append-optimized
analytical copy. DuckDB never writes back to PostgreSQL. If the Parquet catalog is lost,
it can be rebuilt from PostgreSQL.

---

## 3. Storage Backend

### User-Configurable Storage

Users choose where Parquet files are stored. Three backends supported:

| Backend | Use Case | URI Format |
|---------|----------|------------|
| **Local / NAS** | Single server, mapped drives, NAS shares | `/data/openlabels/catalog` or `\\NAS\openlabels\catalog` |
| **S3** | AWS deployments, S3-compatible (MinIO) | `s3://bucket-name/openlabels/catalog` |
| **Azure Blob** | Azure / M365-centric deployments | `az://container-name/openlabels/catalog` |

### Storage Abstraction

```python
# src/openlabels/analytics/storage.py

class CatalogStorage(Protocol):
    """Protocol for catalog storage backends."""

    async def write_parquet(self, path: str, table: pa.Table) -> None: ...
    async def read_parquet(self, path: str) -> pa.Table: ...
    async def list_partitions(self, prefix: str) -> list[str]: ...
    async def exists(self, path: str) -> bool: ...
    async def delete(self, path: str) -> None: ...


class LocalStorage:
    """Local filesystem / UNC path storage."""

    def __init__(self, base_path: str):
        self.base = Path(base_path)


class S3Storage:
    """S3-compatible object storage."""

    def __init__(self, bucket: str, prefix: str, region: str,
                 access_key: str, secret_key: str, endpoint_url: str | None = None):
        ...


class AzureBlobStorage:
    """Azure Blob Storage backend."""

    def __init__(self, container: str, prefix: str,
                 connection_string: str | None = None,
                 account_name: str | None = None, account_key: str | None = None):
        ...
```

DuckDB can read from all three backends natively:
- **Local:** Direct file path
- **S3:** Via `httpfs` extension (`SET s3_region=...; SET s3_access_key_id=...;`)
- **Azure:** Via `azure` extension (`SET azure_storage_connection_string=...;`)

### Filesystem Layout

```
{catalog_root}/
├── scan_results/
│   └── tenant={uuid}/
│       └── target={uuid}/
│           └── scan_date=2026-02-08/
│               ├── part-00000.parquet    (first 100K rows)
│               └── part-00001.parquet    (next 100K rows)
├── file_inventory/
│   └── tenant={uuid}/
│       └── target={uuid}/
│           └── snapshot.parquet          (latest full snapshot)
├── folder_inventory/
│   └── tenant={uuid}/
│       └── target={uuid}/
│           └── snapshot.parquet
├── access_events/
│   └── tenant={uuid}/
│       └── event_date=2026-02-08/
│           └── part-00000.parquet
├── audit_log/
│   └── tenant={uuid}/
│       └── log_date=2026-02-08/
│           └── part-00000.parquet
└── _metadata/
    ├── flush_state.json                  (last flush timestamps/cursors)
    └── schema_version.json               (catalog schema version)
```

**Partitioning rationale:**

- **Hive-style partitions** (`key=value/`) — DuckDB reads these natively with automatic
  partition pruning. A query filtered to one tenant skips all other tenant directories.
- **scan_date / event_date** — Most analytical queries have a time window (last 7 days,
  last 30 days). Date partitioning enables predicate pushdown; DuckDB only reads the
  relevant date folders.
- **tenant + target** — Natural access pattern. Every API call is scoped to a tenant.
  Multi-tenant isolation at the storage level.
- **File inventory uses snapshots** — Not date-partitioned because inventory represents
  current state, not time-series. A single `snapshot.parquet` per target is overwritten
  on each flush.

---

## 4. Parquet Catalog Design

### Table Schemas

#### scan_results.parquet

Maps directly from `ScanResult` model (`models.py:297-357`).

| Column | Parquet Type | Source Column |
|--------|-------------|---------------|
| `id` | `BINARY(16)` (UUID) | `ScanResult.id` |
| `job_id` | `BINARY(16)` | `ScanResult.job_id` |
| `file_path` | `UTF8` | `ScanResult.file_path` |
| `file_name` | `UTF8` | `ScanResult.file_name` |
| `file_size` | `INT64` | `ScanResult.file_size` |
| `file_modified` | `TIMESTAMP_MILLIS` | `ScanResult.file_modified` |
| `content_hash` | `UTF8` | `ScanResult.content_hash` |
| `risk_score` | `INT32` | `ScanResult.risk_score` |
| `risk_tier` | `UTF8` (dictionary-encoded) | `ScanResult.risk_tier` |
| `content_score` | `FLOAT` | `ScanResult.content_score` |
| `exposure_multiplier` | `FLOAT` | `ScanResult.exposure_multiplier` |
| `exposure_level` | `UTF8` (dictionary-encoded) | `ScanResult.exposure_level` |
| `owner` | `UTF8` | `ScanResult.owner` |
| `entity_counts` | `MAP<UTF8, INT32>` | `ScanResult.entity_counts` (JSONB) |
| `total_entities` | `INT32` | `ScanResult.total_entities` |
| `label_applied` | `BOOLEAN` | `ScanResult.label_applied` |
| `current_label_name` | `UTF8` | `ScanResult.current_label_name` |
| `scanned_at` | `TIMESTAMP_MILLIS` | `ScanResult.scanned_at` |

**Key design decisions:**
- `entity_counts` stored as Parquet `MAP` instead of JSON string — DuckDB can query
  individual keys efficiently (`entity_counts['SSN']`)
- `risk_tier` and `exposure_level` use dictionary encoding — low cardinality enums compress
  to a few bytes per value
- `findings` JSONB column is **excluded** — it's large (up to 50 detailed entries per row),
  only needed for single-result detail views (OLTP), and would bloat the Parquet files

#### file_inventory.parquet

Maps from `FileInventory` model (`models.py:503-569`).

| Column | Parquet Type | Source Column |
|--------|-------------|---------------|
| `id` | `BINARY(16)` | `FileInventory.id` |
| `folder_id` | `BINARY(16)` | `FileInventory.folder_id` |
| `file_path` | `UTF8` | `FileInventory.file_path` |
| `file_name` | `UTF8` | `FileInventory.file_name` |
| `adapter` | `UTF8` (dict-encoded) | `FileInventory.adapter` |
| `content_hash` | `UTF8` | `FileInventory.content_hash` |
| `file_size` | `INT64` | `FileInventory.file_size` |
| `file_modified` | `TIMESTAMP_MILLIS` | `FileInventory.file_modified` |
| `risk_score` | `INT32` | `FileInventory.risk_score` |
| `risk_tier` | `UTF8` (dict-encoded) | `FileInventory.risk_tier` |
| `entity_counts` | `MAP<UTF8, INT32>` | `FileInventory.entity_counts` |
| `total_entities` | `INT32` | `FileInventory.total_entities` |
| `exposure_level` | `UTF8` (dict-encoded) | `FileInventory.exposure_level` |
| `owner` | `UTF8` | `FileInventory.owner` |
| `current_label_name` | `UTF8` | `FileInventory.current_label_name` |
| `last_scanned_at` | `TIMESTAMP_MILLIS` | `FileInventory.last_scanned_at` |
| `scan_count` | `INT32` | `FileInventory.scan_count` |
| `content_changed_count` | `INT32` | `FileInventory.content_changed_count` |

#### access_events.parquet

Maps from `FileAccessEvent` model (`models.py:670-722`). This is the highest-volume
table — append-only events that can reach millions of rows.

| Column | Parquet Type | Source Column |
|--------|-------------|---------------|
| `id` | `BINARY(16)` | `FileAccessEvent.id` |
| `monitored_file_id` | `BINARY(16)` | `FileAccessEvent.monitored_file_id` |
| `file_path` | `UTF8` | `FileAccessEvent.file_path` |
| `action` | `UTF8` (dict-encoded) | `FileAccessEvent.action` |
| `success` | `BOOLEAN` | `FileAccessEvent.success` |
| `user_name` | `UTF8` | `FileAccessEvent.user_name` |
| `user_domain` | `UTF8` | `FileAccessEvent.user_domain` |
| `process_name` | `UTF8` | `FileAccessEvent.process_name` |
| `event_time` | `TIMESTAMP_MILLIS` | `FileAccessEvent.event_time` |
| `collected_at` | `TIMESTAMP_MILLIS` | `FileAccessEvent.collected_at` |

**Excluded:** `raw_event` (JSONB) — too large, only needed for forensic single-event views.

#### audit_log.parquet

Maps from `AuditLog` model (`models.py:404-422`).

| Column | Parquet Type | Source Column |
|--------|-------------|---------------|
| `id` | `BINARY(16)` | `AuditLog.id` |
| `user_id` | `BINARY(16)` | `AuditLog.user_id` |
| `action` | `UTF8` (dict-encoded) | `AuditLog.action` |
| `resource_type` | `UTF8` | `AuditLog.resource_type` |
| `resource_id` | `BINARY(16)` | `AuditLog.resource_id` |
| `details` | `UTF8` (JSON string) | `AuditLog.details` |
| `created_at` | `TIMESTAMP_MILLIS` | `AuditLog.created_at` |

### Row Group Sizing

- **Target row group size:** 100,000 rows or 128 MB (whichever comes first)
- **Target file size:** 256 MB max (split into `part-NNNNN.parquet` files)
- **Compression:** Zstd (best ratio for analytical workloads, DuckDB reads it natively)

---

## 5. Delta Write Strategy

### Principle

Only write **changed data** to the data lake. Never re-export the entire PostgreSQL
table. This keeps flush operations fast and predictable regardless of total data size.

### Flush Triggers

There are three types of flush operations:

#### 5.1 Scan Completion Flush (Event-Driven)

**When:** After `execute_scan_task()` commits the final batch (`scan.py:430-432`)
**What:** New `ScanResult` rows from this job + updated `FileInventory` snapshots
**How:**

```python
# Called from execute_scan_task() post-commit hook
async def flush_scan_results(session: AsyncSession, job: ScanJob):
    """Export new scan results and updated inventory to Parquet."""

    # 1. Query only results from THIS job (delta)
    results = await session.execute(
        select(ScanResult)
        .where(ScanResult.job_id == job.id)
        .order_by(ScanResult.scanned_at)
    )

    # 2. Convert to Arrow table
    table = scan_results_to_arrow(results.scalars())

    # 3. Write to partitioned path
    #    scan_results/tenant={tid}/target={tgt}/scan_date=YYYY-MM-DD/part-NNNNN.parquet
    partition_path = (
        f"scan_results/tenant={job.tenant_id}/target={job.target_id}"
        f"/scan_date={job.completed_at.date()}"
    )
    await storage.write_parquet(partition_path, table)

    # 4. Overwrite file inventory snapshot for this target
    inventory = await session.execute(
        select(FileInventory)
        .where(FileInventory.tenant_id == job.tenant_id)
        .where(FileInventory.target_id == job.target_id)
    )
    inv_table = file_inventory_to_arrow(inventory.scalars())
    await storage.write_parquet(
        f"file_inventory/tenant={job.tenant_id}/target={job.target_id}/snapshot.parquet",
        inv_table,
    )
```

**Why this is efficient:**
- `ScanResult.job_id == job.id` uses existing index `ix_scan_results_job_time`
- Typically hundreds to low-thousands of rows per job — fast to read and serialize
- File inventory snapshot for a single target is bounded by number of files in that target

#### 5.2 Event Flush (Periodic)

**When:** Every N minutes (configurable, default 5 minutes) via background task
**What:** New `FileAccessEvent` and `AuditLog` rows since last flush
**How:**

```python
# Runs on a periodic schedule (e.g., every 5 minutes)
async def flush_events(session: AsyncSession):
    """Export new access events and audit logs to Parquet."""

    state = await load_flush_state()  # from _metadata/flush_state.json

    # 1. Access events since last flush
    new_events = await session.execute(
        select(FileAccessEvent)
        .where(FileAccessEvent.collected_at > state.last_access_event_flush)
        .order_by(FileAccessEvent.collected_at)
    )
    if events := list(new_events.scalars()):
        table = access_events_to_arrow(events)
        # Partition by tenant + event_date
        for (tenant_id, event_date), group in group_by_partition(table):
            await storage.write_parquet(
                f"access_events/tenant={tenant_id}/event_date={event_date}/part-{timestamp}.parquet",
                group,
            )
        state.last_access_event_flush = events[-1].collected_at

    # 2. Audit logs since last flush
    new_logs = await session.execute(
        select(AuditLog)
        .where(AuditLog.created_at > state.last_audit_log_flush)
        .order_by(AuditLog.created_at)
    )
    if logs := list(new_logs.scalars()):
        table = audit_log_to_arrow(logs)
        for (tenant_id, log_date), group in group_by_partition(table):
            await storage.write_parquet(
                f"audit_log/tenant={tenant_id}/log_date={log_date}/part-{timestamp}.parquet",
                group,
            )
        state.last_audit_log_flush = logs[-1].created_at

    await save_flush_state(state)
```

**Cursor tracking:** `_metadata/flush_state.json` stores the last-flushed timestamp
for each table. On restart, the flush resumes from where it left off. If the flush state
is lost, a full re-export is triggered (safe because Parquet writes are idempotent within
a partition).

```json
{
  "last_access_event_flush": "2026-02-08T14:30:00Z",
  "last_audit_log_flush": "2026-02-08T14:30:00Z",
  "schema_version": 1
}
```

#### 5.3 Inventory Snapshot Refresh (On-Demand)

**When:** After a scan completes (bundled with 5.1), or on manual trigger
**What:** Full `FileInventory` and `FolderInventory` for a specific target
**Why snapshot, not delta:** Inventory represents *current state*, not a time series.
A file's risk score, label, and scan count change in place. The Parquet snapshot is
the current view — overwritten atomically each time.

### Flush State Diagram

```
Scan Job Completes
        │
        ▼
┌──────────────────┐     ┌───────────────────────────────┐
│ flush_scan_results│────►│ scan_results/tenant=.../      │
│                  │     │   scan_date=.../part-N.parquet │
└──────────────────┘     └───────────────────────────────┘
        │
        ▼
┌──────────────────┐     ┌───────────────────────────────┐
│ flush_inventory  │────►│ file_inventory/tenant=.../     │
│                  │     │   target=.../snapshot.parquet  │
└──────────────────┘     └───────────────────────────────┘

Every 5 Minutes (Background)
        │
        ▼
┌──────────────────┐     ┌───────────────────────────────┐
│ flush_events     │────►│ access_events/tenant=.../      │
│                  │     │   event_date=.../part-N.parquet│
└──────────────────┘     └───────────────────────────────┘
        │
        ▼
┌──────────────────┐     ┌───────────────────────────────┐
│ flush_audit_logs │────►│ audit_log/tenant=.../          │
│                  │     │   log_date=.../part-N.parquet  │
└──────────────────┘     └───────────────────────────────┘
```

---

## 6. DuckDB Query Engine

### Architecture

DuckDB runs **in-process** — no separate server. A single `duckdb.Connection` is created
at startup and shared across async request handlers via a connection pool.

```python
# src/openlabels/analytics/engine.py

class DuckDBEngine:
    """Embedded DuckDB query engine for analytical workloads."""

    def __init__(self, catalog_root: str, storage_config: CatalogSettings):
        self._catalog_root = catalog_root
        self._config = storage_config
        self._db = duckdb.connect(":memory:")
        self._configure_extensions()
        self._register_views()

    def _configure_extensions(self):
        """Load DuckDB extensions for remote storage."""
        self._db.execute("INSTALL httpfs; LOAD httpfs;")
        self._db.execute("INSTALL azure; LOAD azure;")

        if self._config.backend == "s3":
            self._db.execute(f"SET s3_region='{self._config.s3.region}';")
            self._db.execute(f"SET s3_access_key_id='{self._config.s3.access_key}';")
            self._db.execute(f"SET s3_secret_access_key='{self._config.s3.secret_key}';")
            if self._config.s3.endpoint_url:
                self._db.execute(f"SET s3_endpoint='{self._config.s3.endpoint_url}';")
        elif self._config.backend == "azure":
            self._db.execute(
                f"SET azure_storage_connection_string='{self._config.azure.connection_string}';"
            )

    def _register_views(self):
        """Register Parquet glob paths as DuckDB views for clean query syntax."""
        root = self._catalog_root

        self._db.execute(f"""
            CREATE OR REPLACE VIEW scan_results AS
            SELECT * FROM read_parquet('{root}/scan_results/*/*/*.parquet',
                                        hive_partitioning=true);
        """)

        self._db.execute(f"""
            CREATE OR REPLACE VIEW file_inventory AS
            SELECT * FROM read_parquet('{root}/file_inventory/**/snapshot.parquet',
                                        hive_partitioning=true);
        """)

        self._db.execute(f"""
            CREATE OR REPLACE VIEW access_events AS
            SELECT * FROM read_parquet('{root}/access_events/*/*/*.parquet',
                                        hive_partitioning=true);
        """)

        self._db.execute(f"""
            CREATE OR REPLACE VIEW audit_log AS
            SELECT * FROM read_parquet('{root}/audit_log/*/*/*.parquet',
                                        hive_partitioning=true);
        """)

    def query(self, sql: str, params: dict | None = None) -> duckdb.DuckDBPyRelation:
        """Execute an analytical query and return a DuckDB relation."""
        return self._db.execute(sql, params or {})

    def query_df(self, sql: str, params: dict | None = None):
        """Execute a query and return a PyArrow Table (zero-copy)."""
        return self.query(sql, params).fetch_arrow_table()
```

### View Registration

DuckDB views over Parquet globs let us write clean SQL without embedded file paths.
The `hive_partitioning=true` flag means `WHERE tenant = '...'` automatically prunes
directories — DuckDB only reads Parquet files in the matching `tenant={uuid}/` folder.

### Async Integration

DuckDB is not async-native. For FastAPI integration, queries run in a thread pool:

```python
# src/openlabels/analytics/service.py

class AnalyticsService:
    """Async wrapper around DuckDB for use in FastAPI route handlers."""

    def __init__(self, engine: DuckDBEngine):
        self._engine = engine
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="duckdb")

    async def query(self, sql: str, params: dict | None = None) -> list[dict]:
        """Run an analytical query in a background thread."""
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self._executor,
            lambda: self._engine.query(sql, params).fetchall()
        )
        columns = self._engine.query(sql, params).description
        return [dict(zip([c[0] for c in columns], row)) for row in result]

    async def query_arrow(self, sql: str, params: dict | None = None):
        """Run a query and return a PyArrow Table (zero-copy from DuckDB)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: self._engine.query_df(sql, params)
        )
```

### Example Queries — Before vs After

#### Dashboard Overall Stats (`dashboard.py:84` → `get_overall_stats`)

**Before (PostgreSQL):** Two separate queries, Redis cached for 60 seconds.

```sql
-- Query 1: Active scan count
SELECT count(*) FROM scan_jobs WHERE tenant_id = ? AND status IN ('pending', 'running');

-- Query 2: File stats (5 CASE aggregations)
SELECT count(*), sum(CASE WHEN total_entities > 0 THEN 1 END), ...
FROM scan_results WHERE tenant_id = ?;
```

**After (DuckDB):** Single query, no cache needed — columnar scan is fast enough.

```sql
SELECT
    count(*) AS total_files,
    count(*) FILTER (WHERE total_entities > 0) AS files_with_pii,
    count(*) FILTER (WHERE label_applied) AS labels_applied,
    count(*) FILTER (WHERE risk_tier = 'CRITICAL') AS critical_files,
    count(*) FILTER (WHERE risk_tier = 'HIGH') AS high_files
FROM scan_results
WHERE tenant = ?;
```

Active scan count still comes from PostgreSQL (it's OLTP state).

#### Entity Trends (`dashboard.py:231` → `get_entity_trends`)

**Before (PostgreSQL):** Three-step process with 1,000-row sampling and 5,000-row detail cap.

**After (DuckDB):** Single query, no caps needed.

```sql
SELECT
    scan_date,
    map_keys(entity_counts) AS entity_type,
    sum(map_values(entity_counts)) AS count
FROM scan_results
WHERE tenant = ? AND scan_date >= ?
GROUP BY scan_date, entity_type
ORDER BY scan_date;
```

DuckDB handles `MAP` columns natively — `unnest(entity_counts)` expands the map into
rows for aggregation. Full dataset, no sampling.

#### Access Heatmap (`dashboard.py:415` → `get_access_heatmap`)

**Before (PostgreSQL):** `EXTRACT(isodow ...)` and `EXTRACT(hour ...)` with GROUP BY.

**After (DuckDB):** Same logic but faster on columnar data.

```sql
SELECT
    dayofweek(event_time) + 1 AS day_of_week,
    hour(event_time) AS hour,
    count(*) AS access_count
FROM access_events
WHERE tenant = ? AND event_time >= current_date - INTERVAL 28 DAY
GROUP BY day_of_week, hour
ORDER BY day_of_week, hour;
```

#### File Heatmap (`dashboard.py:488` → `get_heatmap`)

**Before (PostgreSQL):** 10,000-file cap with streaming partitions of 1,000.

**After (DuckDB):** Full treemap, no cap needed.

```sql
SELECT
    file_path,
    risk_score,
    file_size,
    entity_counts
FROM scan_results
WHERE tenant = ? AND job_id = ?
ORDER BY risk_score DESC;
```

DuckDB streams results efficiently — the 10K cap becomes unnecessary. The tree construction
still happens in Python but operates on the full dataset.

#### Anomaly Detection (`monitoring.py:464` → `detect_access_anomalies`)

**Before (PostgreSQL):** Two separate queries with HAVING thresholds.

**After (DuckDB):** Combined query with window functions.

```sql
WITH user_activity AS (
    SELECT
        user_name,
        file_path,
        count(*) AS total_events,
        count(*) FILTER (WHERE NOT success) AS failed_events
    FROM access_events
    WHERE tenant = ? AND event_time >= current_timestamp - INTERVAL ? HOUR
    GROUP BY user_name, file_path
)
SELECT * FROM user_activity
WHERE total_events > 100 OR failed_events > 5
ORDER BY total_events DESC;
```

#### Export (`results.py:201` → `export_results`)

**Before (PostgreSQL):** Async generator streaming from SQLAlchemy with Python-side filtering.

**After (DuckDB → Arrow → CSV/JSON):** Zero-copy export.

```python
async def export_results_parquet(self, tenant_id, filters):
    """Stream export directly from Parquet via DuckDB."""
    sql = "SELECT * FROM scan_results WHERE tenant = ?"
    arrow_table = await self.query_arrow(sql, {"tenant": tenant_id})

    # Arrow → CSV is a single call, streamed in batches
    for batch in arrow_table.to_batches(max_chunksize=10_000):
        yield batch_to_csv(batch)
```

---

## 7. Module Structure

```
src/openlabels/analytics/
├── __init__.py              # Public API: AnalyticsService, DuckDBEngine
├── engine.py                # DuckDB connection, view registration, query execution
├── service.py               # Async wrapper for FastAPI integration
├── storage.py               # CatalogStorage protocol + LocalStorage, S3Storage, AzureBlobStorage
├── flush.py                 # Delta flush logic (scan results, events, inventory snapshots)
├── arrow_convert.py         # SQLAlchemy model → PyArrow Table converters
├── partition.py             # Hive-style partition path generation, partition pruning helpers
└── schemas.py               # PyArrow schema definitions for each table
```

### Dependency Map

```
server/routes/dashboard.py ──► analytics/service.py ──► analytics/engine.py ──► DuckDB
server/routes/monitoring.py ─┘                                                    │
server/routes/results.py ────┘                                                    ▼
                                                                             Parquet files
jobs/tasks/scan.py ──► analytics/flush.py ──► analytics/storage.py ──► S3/Azure/Local
                                            ▲
jobs/tasks/flush.py ─────────────────────────┘  (periodic event flush)
```

### New Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `duckdb` | `>=1.0` | Embedded columnar query engine |
| `pyarrow` | `>=15.0` | Arrow tables, Parquet read/write |

Both are pure-Python wheels with native extensions — no external services to deploy.

**Optional (for remote storage):**

| Package | Version | Purpose |
|---------|---------|---------|
| `boto3` | `>=1.34` | S3 write path (DuckDB reads S3 natively via httpfs) |
| `azure-storage-blob` | `>=12.19` | Azure Blob write path |

---

## 8. Configuration

### New Settings Section

Following the existing pattern in `config.py` (Pydantic BaseSettings with
`OPENLABELS_` prefix and `__` nested delimiter):

```python
class S3CatalogSettings(BaseSettings):
    """S3 storage configuration for the data catalog."""

    bucket: str = ""
    prefix: str = "openlabels/catalog"
    region: str = "us-east-1"
    access_key: str = ""
    secret_key: str = ""
    endpoint_url: str | None = None  # For S3-compatible (MinIO)


class AzureCatalogSettings(BaseSettings):
    """Azure Blob storage configuration for the data catalog."""

    container: str = ""
    prefix: str = "openlabels/catalog"
    connection_string: str | None = None
    account_name: str | None = None
    account_key: str | None = None


class CatalogSettings(BaseSettings):
    """Data lake / catalog configuration."""

    enabled: bool = False
    backend: Literal["local", "s3", "azure"] = "local"
    local_path: str = ""  # Local filesystem or UNC path (e.g., \\NAS\openlabels\catalog)
    s3: S3CatalogSettings = Field(default_factory=S3CatalogSettings)
    azure: AzureCatalogSettings = Field(default_factory=AzureCatalogSettings)

    # Flush settings
    event_flush_interval_seconds: int = 300  # 5 minutes
    max_parquet_row_group_size: int = 100_000
    max_parquet_file_size_mb: int = 256
    compression: Literal["zstd", "snappy", "gzip", "none"] = "zstd"

    # DuckDB settings
    duckdb_memory_limit: str = "2GB"
    duckdb_threads: int = 4


# Added to main Settings class:
class Settings(BaseSettings):
    ...
    catalog: CatalogSettings = Field(default_factory=CatalogSettings)
```

### Environment Variable Examples

```bash
# Enable the data lake with local storage
OPENLABELS_CATALOG__ENABLED=true
OPENLABELS_CATALOG__BACKEND=local
OPENLABELS_CATALOG__LOCAL_PATH=/data/openlabels/catalog
# or UNC path:
OPENLABELS_CATALOG__LOCAL_PATH=\\NAS\share\openlabels\catalog

# Enable with S3
OPENLABELS_CATALOG__ENABLED=true
OPENLABELS_CATALOG__BACKEND=s3
OPENLABELS_CATALOG__S3__BUCKET=my-openlabels-bucket
OPENLABELS_CATALOG__S3__REGION=us-west-2
OPENLABELS_CATALOG__S3__ACCESS_KEY=AKIA...
OPENLABELS_CATALOG__S3__SECRET_KEY=...

# Enable with Azure Blob
OPENLABELS_CATALOG__ENABLED=true
OPENLABELS_CATALOG__BACKEND=azure
OPENLABELS_CATALOG__AZURE__CONTAINER=openlabels
OPENLABELS_CATALOG__AZURE__CONNECTION_STRING=DefaultEndpointsProtocol=https;...

# Tune DuckDB
OPENLABELS_CATALOG__DUCKDB_MEMORY_LIMIT=4GB
OPENLABELS_CATALOG__DUCKDB_THREADS=8
```

### YAML Example

```yaml
catalog:
  enabled: true
  backend: s3
  s3:
    bucket: my-openlabels-bucket
    region: us-west-2
    access_key: AKIA...
    secret_key: ...
  event_flush_interval_seconds: 300
  duckdb_memory_limit: 4GB
  duckdb_threads: 8
```

---

## 9. Endpoint Migration Map

### Moves to DuckDB (OLAP)

| Endpoint | Route File | Function | Line | Current Tables | Why It Moves |
|----------|-----------|----------|------|----------------|-------------|
| `GET /dashboard/stats` | `dashboard.py` | `get_overall_stats` | 84 | ScanJob, ScanResult | Full-table COUNT + 5 CASE aggregations |
| `GET /dashboard/trends` | `dashboard.py` | `get_trends` | 154 | ScanResult | GROUP BY date over unbounded range |
| `GET /dashboard/entity-trends` | `dashboard.py` | `get_entity_trends` | 231 | ScanResult | JSONB aggregation with sampling workaround |
| `GET /dashboard/access-heatmap` | `dashboard.py` | `get_access_heatmap` | 415 | FileAccessEvent | 7x24 GROUP BY EXTRACT over 28 days |
| `GET /dashboard/heatmap` | `dashboard.py` | `get_heatmap` | 488 | ScanResult | Full treemap with 10K cap |
| `GET /monitoring/stats` | `monitoring.py` | `get_access_stats` | 386 | FileAccessEvent, MonitoredFile | Multi-aggregation with LIMIT workaround |
| `GET /monitoring/stats/anomalies` | `monitoring.py` | `detect_access_anomalies` | 464 | FileAccessEvent | GROUP BY + HAVING over time window |
| `GET /remediation/stats/summary` | `remediation.py` | `get_remediation_stats` | 601 | RemediationAction | 7 CASE aggregations |
| `GET /results/export` | `results.py` | `export_results` | 201 | ScanResult | Full-table streaming export |

### Stays on PostgreSQL (OLTP)

| Category | Endpoints | Reason |
|----------|-----------|--------|
| **Single-row CRUD** | GET/PUT/DELETE `/scans/{id}`, `/results/{id}`, `/targets/{id}`, etc. | Point lookups by primary key |
| **Job management** | POST `/scans`, GET `/jobs/{id}`, PUT `/jobs/{id}/cancel` | Transactional state machine |
| **Auth & sessions** | POST `/auth/login`, GET `/auth/session`, DELETE `/auth/logout` | Session state, tokens |
| **User management** | GET/POST/PUT/DELETE `/users/*` | Low-volume CRUD |
| **Settings** | GET/PUT `/settings/*` | Configuration reads/writes |
| **Label management** | GET/POST/PUT/DELETE `/labels/*` | CRUD + M365 sync |
| **Schedules** | GET/POST/PUT/DELETE `/schedules/*` | CRUD + cron state |
| **Audit log CRUD** | GET `/audit/{id}`, GET `/audit` (paginated list) | Paginated list with cursor — OLTP pattern |
| **Remediation CRUD** | POST/PUT/DELETE `/remediation/*` | Transactional status updates |
| **Monitoring CRUD** | POST/PUT/DELETE `/monitoring/*` | Transactional CRUD |
| **Active scan count** | Part of `get_overall_stats` | Queries `scan_jobs` active state |

### Hybrid Endpoints

Some endpoints use **both** PostgreSQL and DuckDB:

- **`GET /dashboard/stats`**: Active scan count from PostgreSQL (`scan_jobs` table) +
  file aggregations from DuckDB (`scan_results` Parquet).
- **`GET /monitoring/stats`**: Monitored file count from PostgreSQL (`monitored_files` table) +
  event aggregations from DuckDB (`access_events` Parquet).

### Graceful Fallback

When `catalog.enabled = false` (default), all endpoints continue using PostgreSQL
exactly as they do today. The DuckDB path is opt-in. This means:

```python
# In each migrated endpoint
async def get_trends(tenant_id: UUID, days: int, ...):
    settings = get_settings()
    if settings.catalog.enabled:
        return await analytics_service.get_trends(tenant_id, days)
    else:
        # Existing PostgreSQL implementation (unchanged)
        ...
```

No breaking changes. Users who don't configure the catalog get identical behavior.

---

## 10. Integration Points

### 10.1 Scan Task Post-Commit Hook

**File:** `src/openlabels/jobs/tasks/scan.py`
**Location:** After the final commit (`scan.py:430-432`)

```python
# After: job.status = "completed" / await session.commit()

# NEW: Flush scan results and inventory to data lake
settings = get_settings()
if settings.catalog.enabled:
    from openlabels.analytics.flush import flush_scan_to_catalog
    try:
        await flush_scan_to_catalog(session, job)
    except Exception:
        logger.warning(
            "Catalog flush failed for job %s; data lake will catch up on next flush",
            job.id,
            exc_info=True,
        )
        # Non-fatal — PostgreSQL has the data, Parquet is eventually consistent
```

**Key:** Catalog flush failure is **non-fatal**. PostgreSQL remains the source of truth.
The periodic event flush will eventually write any missing data.

### 10.2 Periodic Event Flush Task

**File:** `src/openlabels/jobs/tasks/flush.py` (new)

Registered as a periodic background task alongside existing tasks like `cleanup_completed_jobs`:

```python
async def periodic_event_flush():
    """Flush new access events and audit logs to the data lake."""
    settings = get_settings()
    if not settings.catalog.enabled:
        return

    async with get_session() as session:
        await flush_events_to_catalog(session)
```

**Scheduling:** Uses the existing `SchedulerSettings.poll_interval` pattern. Runs every
`catalog.event_flush_interval_seconds` (default 300 = 5 minutes).

### 10.3 Application Startup

**File:** `src/openlabels/server/app.py`

On startup, initialize the DuckDB engine and register views:

```python
@app.on_event("startup")
async def startup():
    ...
    settings = get_settings()
    if settings.catalog.enabled:
        from openlabels.analytics.engine import DuckDBEngine
        from openlabels.analytics.service import AnalyticsService
        engine = DuckDBEngine(
            catalog_root=resolve_catalog_root(settings.catalog),
            storage_config=settings.catalog,
        )
        app.state.analytics = AnalyticsService(engine)
```

Route handlers access via `request.app.state.analytics`.

### 10.4 Full Re-Export (Bootstrap / Recovery)

For initial migration or if `flush_state.json` is lost:

```python
# CLI command: openlabels catalog rebuild
async def rebuild_catalog():
    """Full export of PostgreSQL tables to Parquet. Used for initial setup or recovery."""
    settings = get_settings()
    storage = create_storage(settings.catalog)

    async with get_session() as session:
        # Stream all scan results in batches of 10,000
        for batch in stream_batches(session, ScanResult, batch_size=10_000):
            table = scan_results_to_arrow(batch)
            # Write to appropriate partition based on tenant/target/date
            write_partitioned(storage, "scan_results", table)

        # Similar for FileInventory, FolderInventory, FileAccessEvent, AuditLog
        ...
```

This is a one-time operation. Expected runtime: ~1 minute per million rows
(bottlenecked by PostgreSQL sequential scan, not Parquet write speed).

---

## 11. Data Lifecycle and Retention

### Parquet Compaction

Over time, many small Parquet files accumulate (one per flush). Periodic compaction
merges them into optimally-sized files:

```python
async def compact_partitions(storage: CatalogStorage, table: str, tenant_id: UUID):
    """Merge small Parquet files in a partition into larger ones."""
    partitions = await storage.list_partitions(f"{table}/tenant={tenant_id}/")
    for partition in partitions:
        files = await storage.list_files(partition)
        if len(files) > 10:  # Only compact if many small files
            # Read all files, merge, write back as fewer large files
            merged = duckdb.query(f"""
                SELECT * FROM read_parquet('{partition}/*.parquet')
                ORDER BY scanned_at
            """).fetch_arrow_table()
            # Write back as optimally-sized files
            await storage.delete(partition)
            await write_partitioned_files(storage, partition, merged)
```

**Schedule:** Weekly, during low-usage hours. Non-blocking — reads continue from
existing files during compaction.

### Retention Policy

Aligns with existing `JobSettings` TTLs:

| Data | PostgreSQL Retention | Parquet Retention |
|------|---------------------|-------------------|
| `ScanResult` | `completed_job_ttl_days` (7 days default) | Indefinite (analytical history) |
| `FileInventory` | Permanent (current state) | Latest snapshot only |
| `FileAccessEvent` | Configurable (default 90 days) | Same as PostgreSQL |
| `AuditLog` | Permanent (compliance) | Permanent |

**Key insight:** PostgreSQL can aggressively prune old `ScanResult` rows because the
Parquet catalog preserves the full history. This reduces PostgreSQL storage and improves
OLTP performance — the data lake becomes the long-term archive.

---

## 12. Implementation Phases

### Phase A: Foundation (Storage + Arrow Converters)

1. Add `duckdb` and `pyarrow` to dependencies
2. Create `src/openlabels/analytics/` package
3. Implement `CatalogStorage` protocol + `LocalStorage` backend
4. Implement `arrow_convert.py` — SQLAlchemy model → Arrow converters
5. Implement `schemas.py` — PyArrow schema definitions
6. Add `CatalogSettings` to `config.py`
7. Tests: Storage read/write round-trips, Arrow conversion accuracy

### Phase B: Write Path (Delta Flush)

1. Implement `flush.py` — scan completion flush + periodic event flush
2. Implement `partition.py` — Hive-style path generation
3. Add post-commit hook to `execute_scan_task()`
4. Add periodic flush task registration
5. Implement `_metadata/flush_state.json` tracking
6. Tests: Delta flush correctness, idempotency, cursor tracking

### Phase C: Read Path (DuckDB Engine)

1. Implement `engine.py` — DuckDB connection, view registration
2. Implement `service.py` — async wrapper with thread pool
3. Wire up `app.py` startup initialization
4. Tests: Query execution, partition pruning, concurrent access

### Phase D: Endpoint Migration

1. Migrate `get_overall_stats` (simplest — good proof of concept)
2. Migrate `get_trends` and `get_entity_trends` (remove sampling workarounds)
3. Migrate `get_heatmap` and `get_access_heatmap` (remove caps)
4. Migrate `get_access_stats` and `detect_access_anomalies`
5. Migrate `get_remediation_stats`
6. Migrate `export_results` to stream from Parquet
7. Add graceful fallback for `catalog.enabled = false`
8. Tests: Endpoint parity — same responses from both paths

### Phase E: Remote Storage + Polish

1. Implement `S3Storage` and `AzureBlobStorage` backends
2. DuckDB httpfs/azure extension configuration
3. Implement `catalog rebuild` CLI command
4. Implement partition compaction
5. Add catalog health metrics (flush lag, partition count, storage size)
6. Tests: S3/Azure integration tests (mocked), compaction correctness

---

## Appendix: Why Not Alternatives?

| Alternative | Why Not |
|-------------|---------|
| **ClickHouse** | Separate server process, operational overhead, overkill for single-server |
| **postgres_scanner** (DuckDB extension) | Queries PostgreSQL directly — doesn't solve the write contention problem. OLAP queries still compete with OLTP writes on the same database |
| **TimescaleDB** | Still row-oriented for non-time-series queries. Helps time-series but not general OLAP aggregations |
| **Materialized views** | Must be refreshed (blocking), grow PostgreSQL storage, don't solve export performance |
| **Redis caching** | Already in use (`DASHBOARD_STATS_TTL`). Masks the problem but doesn't solve it — stale data, cache invalidation complexity, memory bound |
| **Read replicas** | Operational overhead, replication lag, still row-oriented PostgreSQL |

The DuckDB + Parquet approach is uniquely suited because:
1. **Zero ops** — embedded library, no server to manage
2. **Columnar** — purpose-built for the exact queries that are slow today
3. **Decoupled** — Parquet on object storage survives PostgreSQL restarts/migrations
4. **Scalable** — same architecture works from 10K files to 100M files
5. **Portable** — Parquet is an open standard; data isn't locked to any engine
