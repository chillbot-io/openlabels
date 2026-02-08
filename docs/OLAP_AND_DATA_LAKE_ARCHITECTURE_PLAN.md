# OLAP and Data Lake Architecture Plan

**Version:** 1.2
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
12. [Unified Event Collection](#12-unified-event-collection)
13. [Unified Scan Pipeline](#13-unified-scan-pipeline)
14. [Policy Engine Integration](#14-policy-engine-integration)
15. [Alerting and Notification System](#15-alerting-and-notification-system)
16. [Reporting and Distribution](#16-reporting-and-distribution)
17. [Operational Readiness](#17-operational-readiness)
18. [Implementation Phases](#18-implementation-phases)

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

src/openlabels/monitoring/
├── __init__.py              # Existing — exports MonitoringRegistry, EventCollector
├── collector.py             # Existing — platform event parsing (refactored into providers)
├── registry.py              # Existing — SACL/auditd configuration + cache management
├── history.py               # Existing — on-demand access history queries
├── harvester.py             # NEW — EventHarvester background service
├── stream.py                # NEW — EventStreamManager for real-time providers
└── providers/
    ├── __init__.py
    ├── base.py              # EventProvider protocol + RawAccessEvent dataclass
    ├── windows_sacl.py      # Windows Security Event Log harvester
    ├── windows_usn.py       # NTFS USN Journal real-time stream
    ├── linux_auditd.py      # Linux auditd log harvester
    ├── linux_fanotify.py    # Linux fanotify real-time stream
    ├── m365_audit.py        # M365 Management Activity API harvester
    └── graph_webhook.py     # Graph API webhook change notifications
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

monitoring/harvester.py ──► monitoring/providers/* ──► FileAccessEvent (PostgreSQL)
monitoring/stream.py ───────┘                                  │
                                                               ▼
                                              analytics/flush.py (periodic → Parquet)
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


class MonitoringSettings(BaseSettings):
    """Event collection and monitoring configuration."""

    # Harvester settings
    harvest_enabled: bool = False
    harvest_interval_seconds: int = 30          # On-prem: 30s, M365: 300s
    m365_harvest_interval_seconds: int = 300    # M365 audit API batches events

    # Real-time stream settings
    stream_enabled: bool = False
    stream_batch_size: int = 100
    stream_flush_interval_seconds: float = 5.0

    # Provider selection (auto-detected if empty)
    providers: list[str] = []   # e.g., ["windows_sacl", "usn_journal", "m365_audit"]

    # M365 audit API (reuses existing Graph OAuth2 credentials)
    m365_content_type: str = "Audit.SharePoint"

    # Graph webhooks
    webhook_enabled: bool = False
    webhook_url: str = ""       # Public HTTPS URL for M365 push notifications

    # USN Journal (Windows)
    usn_volumes: list[str] = [] # e.g., ["C:", "D:"] — empty = auto-detect

    # fanotify (Linux)
    fanotify_mount_points: list[str] = []  # e.g., ["/data", "/home"] — empty = skip


# Added to main Settings class:
class Settings(BaseSettings):
    ...
    catalog: CatalogSettings = Field(default_factory=CatalogSettings)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)
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

# Enable event collection (Windows example)
OPENLABELS_MONITORING__HARVEST_ENABLED=true
OPENLABELS_MONITORING__PROVIDERS=["windows_sacl","usn_journal"]
OPENLABELS_MONITORING__STREAM_ENABLED=true
OPENLABELS_MONITORING__USN_VOLUMES=["C:","D:"]

# Enable event collection (Linux example)
OPENLABELS_MONITORING__HARVEST_ENABLED=true
OPENLABELS_MONITORING__PROVIDERS=["linux_auditd","fanotify"]
OPENLABELS_MONITORING__STREAM_ENABLED=true
OPENLABELS_MONITORING__FANOTIFY_MOUNT_POINTS=["/data","/home"]

# Enable M365 audit collection
OPENLABELS_MONITORING__HARVEST_ENABLED=true
OPENLABELS_MONITORING__PROVIDERS=["m365_audit"]
OPENLABELS_MONITORING__WEBHOOK_ENABLED=true
OPENLABELS_MONITORING__WEBHOOK_URL=https://openlabels.example.com/api/v1/webhooks/m365
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

monitoring:
  harvest_enabled: true
  harvest_interval_seconds: 30
  stream_enabled: true
  providers:
    - windows_sacl
    - usn_journal
  usn_volumes:
    - "C:"
    - "D:"
  # For M365:
  # providers:
  #   - m365_audit
  # webhook_enabled: true
  # webhook_url: https://openlabels.example.com/api/v1/webhooks/m365
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

### 10.4 Event Collection Startup

**File:** `src/openlabels/server/app.py`

On startup, initialize the event harvester and stream manager based on configured providers:

```python
@app.on_event("startup")
async def startup():
    ...
    settings = get_settings()

    # Start event collection
    if settings.monitoring.harvest_enabled:
        from openlabels.monitoring.harvester import EventHarvester
        from openlabels.monitoring.providers import auto_detect_providers

        providers = auto_detect_providers(settings.monitoring)
        harvester = EventHarvester(providers, get_session)
        app.state.harvester_task = asyncio.create_task(
            harvester.run_forever(settings.monitoring.harvest_interval_seconds)
        )

    if settings.monitoring.stream_enabled:
        from openlabels.monitoring.stream import EventStreamManager

        stream_providers = [p for p in providers if hasattr(p, 'start_stream')]
        if stream_providers:
            stream_mgr = EventStreamManager(
                stream_providers, get_session,
                batch_size=settings.monitoring.stream_batch_size,
                flush_interval=settings.monitoring.stream_flush_interval_seconds,
            )
            await stream_mgr.start()
            app.state.stream_manager = stream_mgr
```

### 10.5 Full Re-Export (Bootstrap / Recovery)

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

## 12. Unified Event Collection

### Current State

The monitoring subsystem has **models, API endpoints, and OS-level audit configuration**
fully implemented — but the critical middle layer that actually *collects* events into the
database is missing. The plumbing exists at both ends with nothing connecting them.

**What works today:**

| Component | File | Status |
|-----------|------|--------|
| `FileAccessEvent` model | `models.py:670-722` | Schema + indexes ready |
| `MonitoredFile` registration | `routes/monitoring.py:139-211` | API + CLI working |
| Windows SACL configuration | `registry.py:476-569` | PowerShell adds audit rules |
| Linux auditd configuration | `registry.py:628-721` | `auditctl -w` adds watch rules |
| Windows event log parser | `collector.py:46-131` | Parses Event 4663/4656 via `wevtutil` |
| Linux auditd parser | `collector.py:137-226` | Parses `ausearch` output |
| On-demand history query | `history.py:29-68` | CLI: `openlabels monitor history` |
| Monitoring API (8 endpoints) | `routes/monitoring.py:252-538` | Stats, anomalies, filtering |

**What's missing:**

| Gap | Impact |
|-----|--------|
| No background event harvester | `EventCollector` class exists but is never instantiated |
| No continuous collection loop | Zero `FileAccessEvent` rows created in production |
| No SharePoint/OneDrive audit collection | M365 audit logs never queried |
| No real-time filesystem events | Only poll-based OS audit log parsing |
| Cache-to-DB sync never called | `registry.py:173-241` — dead code |

### Event Provider Architecture

A unified `EventProvider` protocol abstracts all four platforms behind one interface.
Each provider converts platform-specific events into `FileAccessEvent` records.

```python
# src/openlabels/monitoring/providers/base.py

@dataclass
class RawAccessEvent:
    """Platform-normalized access event before DB persistence."""

    file_path: str
    action: str                    # read, write, delete, rename, permission_change, execute
    success: bool
    user_name: str
    user_domain: str | None = None
    user_sid: str | None = None    # Windows SID or Linux UID
    process_name: str | None = None
    process_id: int | None = None
    event_time: datetime = None
    event_id: str | None = None    # Platform-specific event ID
    event_source: str = ""         # "ntfs_sacl", "auditd", "graph_audit", "usn", "fanotify"
    raw_event: dict | None = None  # Original event for forensics


class EventProvider(Protocol):
    """Protocol for platform-specific event collection."""

    async def collect_since(self, checkpoint: str | None) -> tuple[list[RawAccessEvent], str]:
        """
        Collect events since the last checkpoint.

        Args:
            checkpoint: Opaque checkpoint string from previous call (None for first run).

        Returns:
            Tuple of (events, new_checkpoint).
            The checkpoint is provider-specific:
              - Windows SACL: last event record ID
              - Linux auditd: last ausearch timestamp
              - M365 audit: continuation URI
              - USN journal: last USN number
              - fanotify: not applicable (real-time only)
        """
        ...

    async def start_stream(self) -> AsyncIterator[RawAccessEvent]:
        """
        Start a real-time event stream (for providers that support it).

        Not all providers support streaming — SACL and auditd are poll-only.
        USN journal, fanotify, and Graph webhooks support streaming.

        Raises NotImplementedError for poll-only providers.
        """
        ...

    def platform(self) -> str:
        """Return platform identifier: 'windows', 'linux', 'sharepoint', 'onedrive'."""
        ...
```

### Platform Implementations

#### 12.1 Windows — SACL Event Harvester

**What it does:** Periodically reads Windows Security Event Log for file access audit events
on monitored files.

**Existing code to wire up:** `collector.py:46-131` (`_collect_windows`)

```python
# src/openlabels/monitoring/providers/windows_sacl.py

class WindowsSACLProvider:
    """
    Harvests file access events from Windows Security Event Log.

    Prerequisites:
    - SACL audit rules configured on monitored files (registry.py handles this)
    - "Audit Object Access" policy enabled in Windows Security Policy
    - Service running with SeSecurityPrivilege

    Collects:
    - Event 4663: An attempt was made to access an object
    - Event 4656: A handle to an object was requested
    - Event 4660: An object was deleted
    - Event 4670: Permissions on an object were changed
    """

    def __init__(self, monitored_paths: list[str]):
        self._paths = set(monitored_paths)

    async def collect_since(self, checkpoint: str | None) -> tuple[list[RawAccessEvent], str]:
        # Use wevtutil or win32evtlog to read Security log
        # Filter by event IDs and monitored paths
        # checkpoint = last EventRecordID processed
        ...

    def platform(self) -> str:
        return "windows"
```

**Key events captured:**

| Event ID | Meaning | Maps To |
|----------|---------|---------|
| 4663 | Object access attempted | `read`, `write`, `execute` (from AccessMask) |
| 4656 | Handle requested | `read` (used for access tracking) |
| 4660 | Object deleted | `delete` |
| 4670 | Permissions changed | `permission_change` |
| 4659 | Delete intent | `delete` (handle requested with DELETE) |

#### 12.2 Windows — USN Journal Provider (Real-Time)

**What it does:** Reads the NTFS Update Sequence Number journal for real-time file change
notifications. This is how Windows Search, backup software, and "Everything" work.

**This is new code** — not in the current codebase.

```python
# src/openlabels/monitoring/providers/windows_usn.py

class USNJournalProvider:
    """
    Real-time file change detection via NTFS USN Journal.

    The USN journal records every file system change on a volume:
    - File create, modify, delete, rename
    - Attribute and security changes
    - No user/process attribution (use SACL for that)

    Two operations:
    1. FSCTL_ENUM_USN_DATA: Enumerate entire MFT (~30 seconds for 10M files)
    2. FSCTL_READ_USN_JOURNAL: Read changes since a USN number (milliseconds)

    Use cases:
    - Fast initial file inventory (replaces slow recursive walk)
    - Real-time change detection for delta scans
    - Complements SACL by providing change events (SACL provides access events)
    """

    def __init__(self, volume: str = "C:"):
        self._volume = volume
        self._handle = None

    async def enumerate_all_files(self) -> AsyncIterator[FileInfo]:
        """
        Enumerate every file on the volume via MFT.

        ~30 seconds for 10M files vs hours for recursive walk.
        Returns file_path, size, timestamps, attributes.
        Does NOT return content or security info (that requires separate calls).
        """
        # FSCTL_ENUM_USN_DATA via ctypes/DeviceIoControl
        ...

    async def collect_since(self, checkpoint: str | None) -> tuple[list[RawAccessEvent], str]:
        # checkpoint = last USN number (int serialized as string)
        # FSCTL_READ_USN_JOURNAL returns changes since that USN
        # USN_REASON flags map to actions:
        #   USN_REASON_DATA_OVERWRITE → write
        #   USN_REASON_DATA_EXTEND → write
        #   USN_REASON_FILE_CREATE → create
        #   USN_REASON_FILE_DELETE → delete
        #   USN_REASON_RENAME_NEW_NAME → rename
        #   USN_REASON_SECURITY_CHANGE → permission_change
        ...

    async def start_stream(self) -> AsyncIterator[RawAccessEvent]:
        """
        Continuous journal monitoring — poll every 1 second for new entries.
        Near real-time with minimal CPU overhead.
        """
        ...

    def platform(self) -> str:
        return "windows"
```

**USN journal vs SACL — complementary, not competing:**

| Aspect | USN Journal | SACL Event Log |
|--------|-------------|----------------|
| **What** | File changes (create/modify/delete/rename) | File access (read/write/execute) |
| **Who** | No user attribution | Full user SID, process name, PID |
| **Speed** | Microseconds for delta | Seconds to parse event log |
| **Volume** | Very low (journal entries are tiny) | Can be high (verbose security log) |
| **Use for** | Change detection → trigger scans | Access auditing → anomaly detection |

**Best together:** USN journal detects *what changed* (feed to scan pipeline).
SACL tracks *who accessed what* (feed to `FileAccessEvent` for analytics).

#### 12.3 Linux — auditd Harvester

**What it does:** Periodically reads auditd logs for file access events on monitored files.

**Existing code to wire up:** `collector.py:137-226` (`_collect_linux`)

```python
# src/openlabels/monitoring/providers/linux_auditd.py

class AuditdProvider:
    """
    Harvests file access events from Linux auditd.

    Prerequisites:
    - auditd service running
    - Watch rules added via auditctl (registry.py handles this)
    - Rules tagged with -k openlabels for efficient querying

    Collects via ausearch:
    - open/openat syscalls → read/write (based on flags)
    - unlink/unlinkat → delete
    - rename/renameat → rename
    - chmod/fchmod → permission_change
    """

    async def collect_since(self, checkpoint: str | None) -> tuple[list[RawAccessEvent], str]:
        # checkpoint = last audit event timestamp
        # ausearch -k openlabels -ts <checkpoint> --format csv
        # Parse CSV rows into RawAccessEvent
        ...

    def platform(self) -> str:
        return "linux"
```

**Syscall to action mapping (from existing `collector.py:175-226`):**

| Syscall | Action | Notes |
|---------|--------|-------|
| `open`, `openat` | `read` or `write` | Based on O_RDONLY/O_WRONLY/O_RDWR flags |
| `read`, `pread64` | `read` | Direct read syscalls |
| `write`, `pwrite64` | `write` | Direct write syscalls |
| `unlink`, `unlinkat` | `delete` | File removal |
| `rename`, `renameat`, `renameat2` | `rename` | File move/rename |
| `chmod`, `fchmod`, `fchmodat` | `permission_change` | Mode bits changed |
| `chown`, `fchown`, `fchownat` | `permission_change` | Ownership changed |
| `execve` | `execute` | Binary execution |

#### 12.4 Linux — fanotify Provider (Real-Time)

**What it does:** Kernel-level filesystem monitoring that watches entire mount points.
Unlike inotify (per-directory watches, 8192 limit), fanotify scales to any filesystem size.

**This is new code.**

```python
# src/openlabels/monitoring/providers/linux_fanotify.py

class FanotifyProvider:
    """
    Real-time file access monitoring via Linux fanotify.

    Advantages over inotify:
    - FAN_MARK_FILESYSTEM: Watch entire filesystem, not per-directory
    - No watch limit (inotify limited to fs.inotify.max_user_watches, default 8192)
    - Can monitor access (reads), not just modifications
    - Provides PID of accessing process
    - Used by ClamAV, AIDE, and enterprise EDR tools

    Requirements:
    - Linux kernel ≥ 5.1 (for FAN_REPORT_FID)
    - CAP_SYS_ADMIN capability
    - Python fanotify bindings (cffi or ctypes)

    Events monitored:
    - FAN_ACCESS: File was read
    - FAN_MODIFY: File was written
    - FAN_CLOSE_WRITE: File closed after writing (best for "file changed" detection)
    - FAN_CLOSE_NOWRITE: File closed after reading only
    - FAN_OPEN: File was opened
    - FAN_MOVED_FROM / FAN_MOVED_TO: File renamed/moved
    - FAN_DELETE: File deleted (kernel ≥ 5.1)
    - FAN_CREATE: File created (kernel ≥ 5.1)
    """

    def __init__(self, mount_point: str = "/", monitored_paths: set[str] | None = None):
        self._mount = mount_point
        self._paths = monitored_paths  # None = monitor all, set = filter to these
        self._fd = None

    async def start_stream(self) -> AsyncIterator[RawAccessEvent]:
        """
        Start continuous monitoring.

        Uses fanotify_init() + fanotify_mark() to register.
        Reads events from the fanotify fd in a loop.
        """
        # fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_FID, O_RDONLY)
        # fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
        #               FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE | ...,
        #               AT_FDCWD, mount_point)
        # Loop: read(fd) → parse fanotify_event_metadata → yield RawAccessEvent
        ...

    async def collect_since(self, checkpoint: str | None) -> tuple[list[RawAccessEvent], str]:
        raise NotImplementedError("fanotify is real-time only; use start_stream()")

    def platform(self) -> str:
        return "linux"
```

**fanotify vs auditd — complementary:**

| Aspect | fanotify | auditd |
|--------|----------|--------|
| **Latency** | Real-time (in-kernel callback) | Seconds (log file parsing) |
| **Scope** | Entire mount point | Per-file watch rules |
| **User info** | PID only (resolve via /proc) | Full UID, username, syscall |
| **Persistence** | In-memory only (events lost on restart) | Persisted to audit.log |
| **Use for** | Real-time alerts, trigger immediate scans | Historical auditing, compliance |

#### 12.5 SharePoint — M365 Management Activity API

**What it does:** Collects file access audit events from Microsoft 365 unified audit log.
This is the only way to get "who accessed what file in SharePoint/OneDrive" data.

**This is new code** — the current adapters only do file scanning, not audit collection.

```python
# src/openlabels/monitoring/providers/m365_audit.py

class M365AuditProvider:
    """
    Collects file access events from Microsoft 365 Management Activity API.

    API: https://manage.office.com/api/v1.0/{tenant}/activity/feed
    Content type: Audit.SharePoint (covers both SharePoint and OneDrive)

    Events collected:
    - FileAccessed: User opened/viewed a file
    - FileModified: User edited a file
    - FileDeleted: User deleted a file
    - FileMoved: User moved a file
    - FileRenamed: User renamed a file
    - FileCopied: User copied a file
    - SharingSet: Sharing permissions changed
    - SharingRevoked: Sharing removed
    - FileDownloaded: User downloaded a file
    - FileUploaded: User uploaded a file
    - FilePreviewed: User previewed (no download)

    Each event includes:
    - UserId (UPN), ClientIP, UserAgent
    - ObjectId (full file URL), SourceFileName
    - SiteUrl, SourceRelativeUrl
    - ItemType (File, Folder, Web)
    - EventSource (SharePoint, OneDrive)

    Authentication:
    - Uses existing Graph API OAuth2 credentials
    - Requires additional permission: ActivityFeed.Read (Office 365 Management API)

    Subscription model:
    1. Start subscription: POST /subscriptions/start?contentType=Audit.SharePoint
    2. List available content: GET /subscriptions/content?contentType=Audit.SharePoint
    3. Retrieve content blobs: GET {contentUri}
    4. Content available for 7 days after event
    """

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = f"https://manage.office.com/api/v1.0/{tenant_id}/activity/feed"

    async def collect_since(self, checkpoint: str | None) -> tuple[list[RawAccessEvent], str]:
        """
        Collect events from M365 audit log.

        checkpoint = last content URI processed, or ISO timestamp for first run.
        """
        # 1. List available content blobs since checkpoint
        # GET /subscriptions/content?contentType=Audit.SharePoint
        #     &startTime={checkpoint}&endTime={now}
        # Returns list of content URIs

        # 2. Fetch each content blob (batch of events as JSON array)
        # GET {contentUri}
        # Returns [{ Operation, UserId, ObjectId, ClientIP, ... }, ...]

        # 3. Filter to monitored sites/paths if configured
        # 4. Map M365 operations to RawAccessEvent actions
        # 5. Return (events, last_content_uri)
        ...

    async def start_stream(self) -> AsyncIterator[RawAccessEvent]:
        """
        Near-real-time via webhook subscription.

        POST /subscriptions/start with webhook URL.
        M365 sends POST to webhook when new content is available.
        Webhook handler calls collect_since() to fetch new events.
        Latency: typically 5-15 minutes (M365 batches audit events).
        """
        ...

    def platform(self) -> str:
        return "sharepoint"  # Covers both SharePoint and OneDrive


# M365 operation → action mapping
M365_OPERATION_MAP = {
    "FileAccessed": "read",
    "FileModified": "write",
    "FileDeleted": "delete",
    "FileMoved": "rename",
    "FileRenamed": "rename",
    "FileCopied": "read",       # Copy is a read from source perspective
    "FileDownloaded": "read",
    "FileUploaded": "write",
    "FilePreviewed": "read",
    "SharingSet": "permission_change",
    "SharingRevoked": "permission_change",
    "FileCheckedOut": "write",   # Exclusive lock for editing
    "FileCheckedIn": "write",
    "FileRecycled": "delete",    # Moved to recycle bin
    "FileRestored": "write",     # Restored from recycle bin
}
```

#### 12.6 Graph API Webhooks (SharePoint/OneDrive Real-Time)

**What it does:** Receives push notifications from Microsoft Graph when files change
in monitored SharePoint sites or OneDrive locations. Complements the M365 audit API
with lower-latency change detection.

```python
# src/openlabels/monitoring/providers/graph_webhook.py

class GraphWebhookProvider:
    """
    Real-time change notifications via Microsoft Graph webhooks.

    Subscribes to /drives/{drive-id}/root changes.
    Graph sends POST to our webhook endpoint when files change.

    Differences from M365 Audit:
    - Audit API: Who accessed what (user, IP, operation) — 5-15 min latency
    - Webhooks: What changed (delta) — seconds latency, no user attribution

    Use webhooks to trigger delta scans immediately.
    Use audit API for access tracking and anomaly detection.
    """

    async def subscribe(self, drive_id: str, webhook_url: str) -> str:
        """Create a change notification subscription (max 30 days, must renew)."""
        # POST /subscriptions
        # { changeType: "updated", resource: f"/drives/{drive_id}/root",
        #   notificationUrl: webhook_url, expirationDateTime: now + 29 days }
        ...

    async def handle_notification(self, notification: dict) -> list[RawAccessEvent]:
        """
        Process incoming webhook notification.

        Called by FastAPI webhook endpoint.
        Fetches delta to get actual changed files.
        """
        # 1. Validate notification (clientState matches)
        # 2. Use delta query to get changed items: GET /drives/{id}/root/delta
        # 3. Map each changed item to RawAccessEvent
        ...
```

### Event Harvester Service

The `EventHarvester` is the background service that ties providers to the database.
It runs as a periodic task alongside the Parquet flush.

```python
# src/openlabels/monitoring/harvester.py

class EventHarvester:
    """
    Background service that collects events from all configured providers
    and persists them as FileAccessEvent records.

    Runs on a configurable interval (default: 30 seconds for on-prem,
    5 minutes for M365 audit).
    """

    def __init__(self, providers: list[EventProvider], session_factory):
        self._providers = providers
        self._session_factory = session_factory
        self._checkpoints: dict[str, str] = {}  # provider_key → checkpoint

    async def harvest_cycle(self) -> int:
        """
        Run one collection cycle across all providers.

        Returns total number of events collected.
        """
        total = 0

        for provider in self._providers:
            key = f"{provider.platform()}:{id(provider)}"
            checkpoint = self._checkpoints.get(key)

            try:
                events, new_checkpoint = await provider.collect_since(checkpoint)

                if events:
                    async with self._session_factory() as session:
                        for raw in events:
                            # Look up monitored_file_id if this path is monitored
                            monitored_file = await self._resolve_monitored_file(
                                session, raw.file_path
                            )

                            db_event = FileAccessEvent(
                                file_path=raw.file_path,
                                action=raw.action,
                                success=raw.success,
                                user_name=raw.user_name,
                                user_domain=raw.user_domain,
                                user_sid=raw.user_sid,
                                process_name=raw.process_name,
                                process_id=raw.process_id,
                                event_time=raw.event_time,
                                event_id=raw.event_id,
                                event_source=raw.event_source,
                                collected_at=datetime.utcnow(),
                                raw_event=raw.raw_event,
                                monitored_file_id=(
                                    monitored_file.id if monitored_file else None
                                ),
                                tenant_id=monitored_file.tenant_id if monitored_file else None,
                            )
                            session.add(db_event)

                        await session.commit()
                        total += len(events)

                    # Update monitored file stats
                    if monitored_file:
                        monitored_file.access_count += len(events)
                        monitored_file.last_event_at = events[-1].event_time

                self._checkpoints[key] = new_checkpoint

            except Exception:
                logger.warning(
                    "Event collection failed for %s; will retry next cycle",
                    provider.platform(),
                    exc_info=True,
                )
                # Non-fatal — retry on next cycle with same checkpoint

        return total

    async def run_forever(self, interval_seconds: float = 30.0):
        """Run harvest cycles in a loop."""
        while True:
            count = await self.harvest_cycle()
            if count > 0:
                logger.info("Collected %d access events", count)
            await asyncio.sleep(interval_seconds)
```

### Real-Time Event Stream Manager

For providers that support streaming (USN journal, fanotify, Graph webhooks),
a separate manager runs continuous listeners:

```python
# src/openlabels/monitoring/stream.py

class EventStreamManager:
    """
    Manages real-time event streams from providers that support them.

    Runs as long-lived async tasks alongside the main application.
    Writes events to an in-memory buffer, flushed to DB in batches
    every N seconds or N events (whichever comes first).
    """

    def __init__(
        self,
        providers: list[EventProvider],
        session_factory,
        batch_size: int = 100,
        flush_interval: float = 5.0,
    ):
        self._providers = providers
        self._session_factory = session_factory
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._buffer: list[RawAccessEvent] = []
        self._tasks: list[asyncio.Task] = []

    async def start(self):
        """Start stream listeners for all capable providers."""
        for provider in self._providers:
            try:
                stream = provider.start_stream()
                task = asyncio.create_task(self._consume_stream(provider, stream))
                self._tasks.append(task)
                logger.info("Started real-time stream for %s", provider.platform())
            except NotImplementedError:
                # Provider is poll-only (SACL, auditd) — skip
                pass

        # Start buffer flush task
        self._tasks.append(asyncio.create_task(self._periodic_flush()))

    async def _consume_stream(self, provider, stream: AsyncIterator[RawAccessEvent]):
        """Read events from a real-time stream into the buffer."""
        async for event in stream:
            self._buffer.append(event)
            if len(self._buffer) >= self._batch_size:
                await self._flush_buffer()

    async def _periodic_flush(self):
        """Flush buffer on timer even if batch_size not reached."""
        while True:
            await asyncio.sleep(self._flush_interval)
            if self._buffer:
                await self._flush_buffer()

    async def _flush_buffer(self):
        """Persist buffered events to database."""
        events = self._buffer
        self._buffer = []

        async with self._session_factory() as session:
            for raw in events:
                session.add(FileAccessEvent(
                    file_path=raw.file_path,
                    action=raw.action,
                    success=raw.success,
                    user_name=raw.user_name,
                    user_domain=raw.user_domain,
                    event_time=raw.event_time,
                    event_source=raw.event_source,
                    collected_at=datetime.utcnow(),
                ))
            await session.commit()
```

### Data Flow — Events to OLAP

Event collection feeds directly into the OLAP data lake pipeline defined in
[Section 5.2](#52-event-flush-periodic):

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     EVENT COLLECTION LAYER                              │
│                                                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌─────────────┐ │
│  │ Windows  │ │ Windows  │ │  Linux   │ │  Linux    │ │    M365     │ │
│  │  SACL    │ │   USN    │ │ auditd   │ │ fanotify  │ │ Audit API   │ │
│  │(harvest) │ │(stream)  │ │(harvest) │ │ (stream)  │ │ (harvest)   │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬─────┘ └──────┬──────┘ │
│       │             │            │              │              │        │
│       ▼             ▼            ▼              ▼              ▼        │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │              EventHarvester / EventStreamManager                 │   │
│  │                  ┌─────────────────────┐                        │   │
│  │                  │  RawAccessEvent buf  │                       │   │
│  │                  └──────────┬──────────┘                        │   │
│  └─────────────────────────────┼───────────────────────────────────┘   │
└────────────────────────────────┼───────────────────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │  PostgreSQL             │
                    │  file_access_events     │
                    │  (OLTP — recent events) │
                    └────────────┬────────────┘
                                 │
                    Every 5 min (periodic flush from Section 5.2)
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │  Parquet (Data Lake)    │
                    │  access_events/         │
                    │  tenant=.../            │
                    │  event_date=.../        │
                    │  part-N.parquet         │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │  DuckDB (OLAP)         │
                    │  Access heatmaps       │
                    │  Anomaly detection     │
                    │  User activity reports  │
                    └────────────────────────┘
```

### Platform Availability Matrix

| Provider | Collection Mode | Latency | User Attribution | Requirements |
|----------|----------------|---------|-----------------|--------------|
| Windows SACL | Periodic harvest | 30-60s | Full (SID, process) | SeSecurityPrivilege, audit policy |
| Windows USN | Continuous stream | <1s | None (change only) | Admin for `CreateFile` on volume |
| Linux auditd | Periodic harvest | 30-60s | Full (UID, syscall) | auditd running, CAP_AUDIT_CONTROL |
| Linux fanotify | Continuous stream | <1s | PID only | CAP_SYS_ADMIN, kernel ≥ 5.1 |
| M365 Audit API | Periodic harvest | 5-15 min | Full (UPN, IP, client) | ActivityFeed.Read permission |
| Graph Webhooks | Push notification | 1-30s | None (change only) | Graph subscription, HTTPS endpoint |

**Recommended combinations:**

- **Windows on-prem:** SACL harvester (who accessed) + USN stream (what changed)
- **Linux on-prem:** auditd harvester (who accessed) + fanotify stream (what changed)
- **SharePoint/OneDrive:** M365 audit harvester (who accessed) + Graph webhooks (what changed)

---

## 13. Unified Scan Pipeline

### Current State

Two completely separate scan code paths exist:

- **`execute_scan_task`** (`scan.py:148-521`): Sequential, adapter-integrated, full
  delta detection, scoring, labeling, inventory — but single-threaded
- **`execute_parallel_scan_task`** (`scan.py:861-1115`): Multi-process agents via
  `AgentPool` — but bypasses adapters, no delta detection, hardcoded scoring,
  no labeling, local filesystem only

### Target Architecture

One unified pipeline that separates concerns into concurrent stages:

```
┌────────────────────────┐
│   Change Provider      │   USN / fanotify / Graph delta / full walk
│   (Section 12)         │   Yields only files that need scanning
└──────────┬─────────────┘
           ▼
┌────────────────────────┐
│   Adapter + Delta      │   adapter.read_file() → content_hash →
│   Filter               │   inventory.should_scan_file() → skip unchanged
└──────────┬─────────────┘
           ▼
┌────────────────────────┐
│   Text Extraction      │   extract_text() + TextChunker
│   + Chunking           │   Produces WorkItems with metadata attached
└──────────┬─────────────┘
           ▼
    ┌──────┴──────┐
    │  Work Queue  │   Bounded, backpressure (existing AgentPool)
    └──────┬──────┘
     ┌─────┼─────┬─────┐
     ▼     ▼     ▼     ▼
   ┌───┐ ┌───┐ ┌───┐ ┌───┐
   │ A │ │ A │ │ A │ │ A │   N ClassificationAgents (separate processes)
   │ 0 │ │ 1 │ │ 2 │ │ 3 │   Each with own NER model (existing worker.py)
   └─┬─┘ └─┬─┘ └─┬─┘ └─┬─┘
     └─────┼─────┴─────┘
           ▼
    ┌──────┴──────┐
    │ Result Queue │
    └──────┬──────┘
           ▼
┌────────────────────────┐
│   Result Pipeline      │   Risk scoring engine (full, not hardcoded)
│                        │   → Exposure calculation (from adapter metadata)
│                        │   → Inventory update (content_hash, scan_count)
│                        │   → Label application (MIP client)
│                        │   → DB persist (ScanResult + FileInventory)
│                        │   → Parquet flush (Section 5.1)
│                        │   → WebSocket progress events
└────────────────────────┘
```

The existing `AgentPool` and `ClassificationAgent` classes don't change.
What changes is `ScanOrchestrator`:

1. **`_walk_files()`** uses the adapter + change provider instead of `Path.rglob`
2. **`_extract_and_submit()`** runs delta checks before reading file content
3. **`_collect_and_store()`** runs the full result pipeline instead of the
   simplified persist logic in `execute_parallel_scan_task`

This eliminates the two-code-path problem and makes parallel classification
work across all platforms (filesystem, SharePoint, OneDrive) with full
delta detection and scoring.

---

## 14. Policy Engine Integration

### Current State

A complete policy engine exists at `src/openlabels/core/policies/` (~500 lines) with:

- `PolicyEngine` class — add/remove/evaluate policies (`engine.py`)
- `PolicyPack` schema — defines policy rules, conditions, and actions (`schema.py`)
- Compliance framework categories: HIPAA, GDPR, PCI-DSS, SOC2, CCPA
- Risk level ordering and policy matching logic
- Policy loader utilities (`loader.py`)

**The problem:** Nothing in the application ever imports or calls it. It's complete
dead code. Scan results don't include policy violations, no API endpoint exposes
policy evaluation, and there's no way to define or manage policies through the UI.

### What Policy Integration Looks Like

Policies answer: "Given what we found in this file, what rules does it violate?"

```
File scanned → 3 SSNs found, exposure=PUBLIC, risk_tier=CRITICAL
                        │
                        ▼
              ┌─────────────────────┐
              │   Policy Engine     │
              │                     │
              │  HIPAA Rule:        │
              │    has(SSN) AND     │──► VIOLATION: HIPAA §164.502
              │    exposure=PUBLIC  │    Action: quarantine + notify
              │                     │
              │  PCI-DSS Rule:      │
              │    has(CREDIT_CARD) │──► No match (no credit cards)
              │    AND count > 5    │
              │                     │
              │  Internal Policy:   │
              │    tier=CRITICAL    │──► VIOLATION: Corporate Policy
              │    AND !labeled     │    Action: auto-label + alert
              └─────────────────────┘
```

### Integration Points

1. **Scan pipeline** (`scan.py` post-classification): Evaluate policies against each
   `ScanResult` after scoring. Add `policy_violations` field to result.

2. **API endpoints**: New `/api/v1/policies/` resource group:
   - `GET /policies` — List configured policies
   - `POST /policies` — Create policy from pack template or custom
   - `PUT /policies/{id}` — Update policy rules/actions
   - `DELETE /policies/{id}` — Remove policy
   - `POST /policies/evaluate` — Dry-run evaluation against existing results

3. **Automated actions**: Policy violations can trigger:
   - Quarantine (connect to `remediation/quarantine.py`)
   - Label application (connect to `labeling/engine.py`)
   - Alert notification (connect to Section 15 alerting)
   - Monitoring enrollment (add to `MonitoredFile`)

4. **Dashboard integration**: Policy compliance stats as a DuckDB OLAP query —
   violations by policy, trend over time, compliance percentage per target.

### Data Model Addition

```python
# Addition to ScanResult model
class ScanResult(Base):
    ...
    policy_violations: list[dict] = Column(JSONB, default=[])
    # [{"policy_id": "...", "policy_name": "HIPAA PHI Exposure",
    #   "framework": "HIPAA", "severity": "critical",
    #   "rule": "has(SSN) AND exposure=PUBLIC",
    #   "action_taken": "quarantine"}]
```

---

## 15. Alerting and Notification System

### Current State

The only notification mechanism is Windows system tray balloon messages (`tray.py`).
The web UI settings page has a notifications section that renders forms but **discards
all input** — the POST handlers don't persist anything.

For an enterprise data classification tool that detects CRITICAL risk files, this is
a fundamental gap. Finding sensitive data is useless if nobody is told about it.

### Alert Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      ALERT TRIGGERS                               │
│                                                                    │
│  Scan completion ──┐                                              │
│  CRITICAL finding ─┤                                              │
│  Policy violation ─┤──► AlertEngine.evaluate() ──► Alert Rules    │
│  Anomaly detected ─┤                                              │
│  Remediation event ┘                                              │
└──────────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────────────┐
│                      ALERT RULES                                  │
│                                                                    │
│  Rule: "CRITICAL files found"                                     │
│    Condition: scan.critical_files > 0                             │
│    Severity: HIGH                                                 │
│    Channels: [email, slack]                                       │
│    Throttle: max 1 per hour per target                            │
│                                                                    │
│  Rule: "Anomalous access detected"                                │
│    Condition: anomaly.type = "high_volume"                        │
│    Severity: CRITICAL                                             │
│    Channels: [email, slack, webhook]                              │
│    Throttle: immediate                                            │
└──────────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────────────┐
│                   DELIVERY CHANNELS                               │
│                                                                    │
│  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌──────────┐ │
│  │  Email  │ │  Slack  │ │  Teams   │ │ Webhook │ │  Syslog  │ │
│  │  (SMTP) │ │  (API)  │ │ (Connec.)│ │ (HTTP)  │ │ (RFC5424)│ │
│  └─────────┘ └─────────┘ └──────────┘ └─────────┘ └──────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### Delivery Channels

| Channel | Protocol | Use Case |
|---------|----------|----------|
| **Email** | SMTP/STARTTLS | Default — compliance reports, scan summaries, critical alerts |
| **Slack** | Slack Web API (`chat.postMessage`) | Real-time team notifications |
| **Microsoft Teams** | Incoming Webhook Connector | M365-centric organizations |
| **Generic Webhook** | HTTP POST (JSON payload) | SIEM integration, custom automation |
| **Syslog** | RFC 5424 (UDP/TCP/TLS) | Enterprise logging infrastructure |

### Channel Protocol

```python
# src/openlabels/alerting/channels/base.py

@dataclass
class AlertMessage:
    """Normalized alert message for all channels."""

    title: str
    body: str                     # Markdown formatted
    severity: str                 # info, warning, high, critical
    source: str                   # scan, monitoring, remediation, policy
    tenant_id: UUID
    metadata: dict                # Channel-specific data (scan_id, file_path, etc.)
    timestamp: datetime


class AlertChannel(Protocol):
    """Protocol for alert delivery channels."""

    async def send(self, message: AlertMessage) -> bool:
        """Send an alert. Returns True if delivery succeeded."""
        ...

    async def test(self) -> bool:
        """Test channel connectivity. Used by UI 'Send Test' button."""
        ...
```

### Configuration

```python
class AlertSettings(BaseSettings):
    """Alerting configuration."""

    enabled: bool = False

    # Email (SMTP)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_from_address: str = "openlabels@example.com"
    smtp_to_addresses: list[str] = []

    # Slack
    slack_webhook_url: str = ""
    slack_channel: str = ""

    # Microsoft Teams
    teams_webhook_url: str = ""

    # Generic webhook
    webhook_url: str = ""
    webhook_headers: dict[str, str] = {}

    # Syslog
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_protocol: str = "udp"   # udp, tcp, tls

    # Throttling
    throttle_window_seconds: int = 3600  # 1 hour default
    max_alerts_per_window: int = 10
```

```bash
# Environment variables
OPENLABELS_ALERTING__ENABLED=true
OPENLABELS_ALERTING__SMTP_HOST=smtp.company.com
OPENLABELS_ALERTING__SMTP_TO_ADDRESSES=["security@company.com","compliance@company.com"]
OPENLABELS_ALERTING__SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
OPENLABELS_ALERTING__TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
```

### Alert Trigger Integration

Alerts fire from existing code paths with minimal changes:

| Trigger Point | File | What Fires |
|--------------|------|------------|
| Scan completed | `scan.py:420-430` | Summary: X files scanned, Y critical, Z labeled |
| CRITICAL file found | `scan.py:302-323` (per-file) | Immediate: "CRITICAL risk file detected at {path}" |
| Policy violation | Policy engine (Section 14) | Per-policy: "HIPAA violation: SSN in public file" |
| Anomaly detected | `monitoring.py:464-538` | "Unusual access: {user} accessed {N} files in {T}h" |
| Remediation action | `remediation/quarantine.py` | "File quarantined: {path} (risk: {tier})" |
| Label applied | `labeling/engine.py` | "Sensitivity label applied: {label} to {N} files" |

---

## 16. Reporting and Distribution

### Current State

- CLI `report.py` generates text/JSON/CSV/HTML reports (one-off, stdout or file)
- CLI `export.py` exports scan results as CSV/JSON
- API `export_results` endpoint streams results
- No PDF generation, no scheduled reports, no email delivery

### Target Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    REPORT GENERATION                              │
│                                                                    │
│  Templates:                                                       │
│  ├── Executive Summary (1-page PDF, risk posture overview)       │
│  ├── Compliance Report (policy violations by framework)           │
│  ├── Scan Detail (per-target file listing with findings)          │
│  ├── Access Audit (who accessed what, when — from events)         │
│  └── Trend Report (risk score trends over time)                   │
│                                                                    │
│  Formats: PDF, HTML, CSV, JSON                                   │
│  Data source: DuckDB (OLAP) for aggregations, Postgres for CRUD  │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                    DISTRIBUTION                                   │
│                                                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────────┐   │
│  │  Scheduled   │  │  On-demand  │  │  Event-triggered       │   │
│  │  (cron)      │  │  (API/CLI)  │  │  (post-scan, weekly)   │   │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬────────────┘   │
│         └────────────────┼─────────────────────┘                 │
│                          ▼                                        │
│  Delivery: Email (SMTP), S3/Azure upload, local file, API download│
└──────────────────────────────────────────────────────────────────┘
```

### PDF Generation

Uses `weasyprint` (HTML→PDF via CSS) rather than a heavy reporting framework.
Report templates are Jinja2 HTML with print-optimized CSS — same templates used
for HTML export and PDF rendering.

```python
# src/openlabels/reporting/renderer.py

class ReportRenderer:
    """Render reports in multiple formats from Jinja2 templates."""

    async def render_pdf(self, template: str, data: dict) -> bytes:
        html = self._render_html(template, data)
        return weasyprint.HTML(string=html).write_pdf()

    async def render_html(self, template: str, data: dict) -> str:
        return self._render_html(template, data)

    async def render_csv(self, template: str, data: dict) -> str:
        # Flat tabular export
        ...
```

### Report Scheduling

```python
# Addition to existing ScheduleSettings or new ReportSettings
class ReportSchedule(BaseSettings):
    """Scheduled report configuration."""

    enabled: bool = False
    reports: list[dict] = []
    # [{"template": "executive_summary", "schedule": "0 8 * * MON",
    #   "recipients": ["ciso@company.com"], "format": "pdf"}]
```

Reports use the existing cron/schedule infrastructure (`croniter`-based scheduling
in the job system) and the alerting email channel (Section 15) for delivery.

---

## 17. Operational Readiness

### Current Gaps

| Gap | Risk | Fix |
|-----|------|-----|
| **Web UI settings don't persist** | Users configure settings that silently vanish | Fix POST handlers in `web/routes.py` to write to config/DB |
| **`scan_all_sites`/`scan_all_users` unused** | Config keys defined but adapters ignore them | Wire into SharePoint/OneDrive adapter `list_files()` |
| **Permission restore missing** | Can lock down files but can't undo programmatically | Add `restore_permissions()` using backed-up ACLs from `lock_down()` |
| **Health endpoint requires auth** | `/api/v1/health/status` needs authentication; load balancers can't probe | Make health endpoints unauthenticated |
| **`system backup` command stubbed** | `cli/commands/system.py` has placeholder | Implement `pg_dump` wrapper + config export |
| **WebSocket no rate limiting** | Unbounded message rate/size on WS connections | Add message rate and payload size limits |
| **Dev hardcodes in production** | `ws.py:167` has `"dev-tenant"`, `ws.py:179` has `"dev@localhost"` | Gate behind `DEBUG` flag or remove |
| **64x `except Exception`** | Broad exception handlers mask real errors | Narrow to specific exception types in critical paths |
| **OCR models not bundled** | Code exists but models require separate download | Auto-download on first use, or bundle in Docker image |
| **ML detectors non-functional** | PHI-BERT/PII-BERT scaffolded but models not included | Bundle models or add download CLI command |

### Database Backup and Restore

```python
# src/openlabels/cli/commands/system.py

# openlabels system backup --output /backups/openlabels-2026-02-08.sql.gz
async def backup(output: str):
    """Full database backup via pg_dump + config export."""
    settings = get_settings()
    # 1. pg_dump --format=custom to compressed file
    # 2. Export current settings as YAML
    # 3. Export Parquet catalog metadata (flush_state.json, schema_version.json)
    ...

# openlabels system restore --input /backups/openlabels-2026-02-08.sql.gz
async def restore(input: str):
    """Restore from backup."""
    # 1. pg_restore from backup file
    # 2. Rebuild Parquet catalog from restored DB (openlabels catalog rebuild)
    ...
```

### CI/CD Pipeline

Current GitHub Actions: lint + mypy + tests only.

Add:

| Stage | Tool | Purpose |
|-------|------|---------|
| **Dependency audit** | `pip-audit` / `safety` | CVE scanning on Python dependencies |
| **SAST** | `bandit` | Static security analysis (catches the `except Exception` pattern) |
| **Docker build** | `docker build` | Build production image with bundled models |
| **Python matrix** | `matrix: [3.11, 3.12, 3.13]` | Verify compatibility |
| **Integration tests** | `docker compose` | Full stack: Postgres + Redis + app |
| **Coverage gate** | `pytest-cov` | Minimum coverage threshold |

### Model Bundling Strategy

```
Models needed:
├── NER model (~350MB) — Required for all scans
│   └── Auto-download from HuggingFace on first use
│       OR bundled in Docker image (openlabels:full)
├── OCR model (~50MB) — Optional, for image/scanned PDF
│   └── Auto-download when enable_ocr=true
│       OR pip install openlabels[ocr]
└── ML detectors (~200MB each) — Optional PHI/PII-BERT
    └── openlabels models download phi-bert
        OR pip install openlabels[ml]

# Docker images:
# openlabels:slim  — No models bundled (~200MB), downloads on first use
# openlabels:full  — NER + OCR bundled (~800MB), air-gap ready
```

---

## 18. Implementation Phases

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

### Phase F: On-Prem Event Collection (Windows + Linux)

Wire up the existing but disconnected event collection code, and add the background
harvester that persists events to `FileAccessEvent`.

1. Create `EventProvider` protocol and `RawAccessEvent` dataclass (`monitoring/providers/base.py`)
2. Implement `WindowsSACLProvider` — wrap existing `collector.py:46-131` behind the protocol
3. Implement `AuditdProvider` — wrap existing `collector.py:137-226` behind the protocol
4. Implement `EventHarvester` — periodic background task that calls providers and persists
5. Add `MonitoringSettings` to config (harvest interval, enabled providers, checkpoint storage)
6. Register harvester as background task in `app.py` startup (alongside periodic flush)
7. Wire up `registry.py:173-241` cache-to-DB sync on startup (currently dead code)
8. Fix security issue: command injection in `_disable_monitoring_windows` (`registry.py:573-577`)
9. Fix security issue: unused `escaped_path` in `_get_history_windows` (`history.py:121-131`)
10. Tests: Harvester cycle with mock providers, checkpoint persistence, DB insertion

### Phase G: Cloud Event Collection (M365 Audit)

Add SharePoint and OneDrive audit log collection via the Office 365 Management Activity API.

1. Implement `M365AuditProvider` — subscribe to `Audit.SharePoint` content type
2. Add M365 operation → action mapping (FileAccessed→read, FileModified→write, etc.)
3. Add `ActivityFeed.Read` permission to Graph OAuth2 scope configuration
4. Implement content blob pagination (7-day sliding window, continuation URIs)
5. Add webhook endpoint for near-real-time M365 audit notifications (`POST /api/v1/webhooks/m365`)
6. Implement `GraphWebhookProvider` — subscription management + delta query on notification
7. Add webhook validation (clientState matching, validation token handling)
8. Add M365 provider to `EventHarvester` with separate harvest interval (5 min default)
9. Tests: M365 audit response parsing, webhook validation, subscription lifecycle

### Phase H: Real-Time Event Streams (USN + fanotify)

Add real-time, low-latency event sources that complement the periodic harvesters.

1. Implement `USNJournalProvider` — NTFS USN journal via `ctypes`/`DeviceIoControl`
   - `FSCTL_READ_USN_JOURNAL` for change stream
   - `FSCTL_ENUM_USN_DATA` for fast MFT enumeration (initial inventory bootstrap)
2. Implement `FanotifyProvider` — Linux kernel filesystem monitoring via `ctypes`
   - `fanotify_init()` with `FAN_CLASS_NOTIF | FAN_REPORT_FID`
   - `fanotify_mark()` with `FAN_MARK_FILESYSTEM` for whole-mount monitoring
   - PID → username resolution via `/proc/{pid}/status`
3. Implement `EventStreamManager` — long-lived async tasks, batched DB writes
4. Add real-time alert hooks — trigger immediate scan on high-risk file modification
5. Integrate USN journal with scan pipeline as change provider (Section 13)
6. Integrate fanotify with scan pipeline as change provider (Section 13)
7. Tests: USN journal parsing (mock DeviceIoControl), fanotify event parsing, buffer flush

### Phase I: Unified Scan Pipeline

Merge the two scan code paths into one pipeline with parallel classification agents.

1. Refactor `ScanOrchestrator._walk_files()` to accept adapter + change provider
2. Refactor `ScanOrchestrator._extract_and_submit()` to run `inventory.should_scan_file()` delta check
3. Refactor `ScanOrchestrator._collect_and_store()` to run full result pipeline (scoring, exposure, labeling)
4. Remove `execute_parallel_scan_task()` — replaced by unified pipeline
5. Add adapter metadata (exposure level, permissions) to `WorkItem.metadata` for post-classification scoring
6. Add MIP label application to result pipeline
7. Add Parquet flush hook to result pipeline (Section 5.1)
8. Tests: End-to-end pipeline with mock adapter, agent pool, and DB verification

### Phase J: Policy Engine Integration

Wire the dead `core/policies/` package into the live scan pipeline and expose via API.

1. Add `policy_violations` JSONB column to `ScanResult` model
2. Create database migration for the new column
3. Call `PolicyEngine.evaluate()` in scan pipeline after scoring (post-classification)
4. Store violations in `ScanResult.policy_violations`
5. Add `/api/v1/policies/` CRUD endpoints (list, create, update, delete)
6. Add `POST /api/v1/policies/evaluate` dry-run endpoint against existing results
7. Connect policy violation actions to remediation (quarantine, label, monitor)
8. Connect policy violations to alerting system (Section 15)
9. Add compliance dashboard stats to DuckDB OLAP queries
10. Add default policy packs: HIPAA, GDPR, PCI-DSS, SOC2 (loadable templates)
11. Tests: Policy evaluation against scan results, action triggering, API CRUD

### Phase K: Alerting and Notification System

Build the alert delivery infrastructure that all other subsystems use.

1. Create `src/openlabels/alerting/` package
2. Implement `AlertChannel` protocol and `AlertMessage` dataclass
3. Implement `EmailChannel` — SMTP/STARTTLS with Jinja2 email templates
4. Implement `SlackChannel` — Slack Web API `chat.postMessage`
5. Implement `TeamsChannel` — Microsoft Teams Incoming Webhook Connector
6. Implement `WebhookChannel` — generic HTTP POST with configurable headers
7. Implement `SyslogChannel` — RFC 5424 over UDP/TCP/TLS
8. Implement `AlertEngine` — rule evaluation, throttling, channel routing
9. Add `AlertSettings` to config (SMTP, Slack, Teams, webhook, syslog credentials)
10. Add alert trigger hooks to: scan completion, CRITICAL findings, anomaly detection, remediation
11. Add `/api/v1/alerts/` endpoints: list rules, create rule, test channel
12. Fix web UI settings persistence — POST handlers must write to config/DB
13. Tests: Channel delivery (mocked), throttling, rule evaluation, template rendering

### Phase L: Reporting and Distribution

Scheduled and on-demand report generation with email delivery.

1. Create `src/openlabels/reporting/` package
2. Implement `ReportRenderer` — Jinja2 HTML templates → PDF (via `weasyprint`), HTML, CSV
3. Create report templates: executive summary, compliance report, scan detail, access audit
4. Add `weasyprint` as optional dependency (`pip install openlabels[reports]`)
5. Implement report scheduling via existing cron/job infrastructure
6. Add email delivery using alerting `EmailChannel` (Phase K)
7. Add `/api/v1/reports/` endpoints: generate, schedule, list, download
8. Add `openlabels report generate --template executive_summary --format pdf` CLI command
9. Tests: Template rendering, PDF generation, scheduled report execution

### Phase M: Operational Hardening

Fix the known wiring issues, security gaps, and deployment infrastructure.

1. Fix web UI settings persistence — `web/routes.py` POST handlers write to config
2. Wire `scan_all_sites` / `scan_all_users` config into SharePoint/OneDrive adapters
3. Implement `restore_permissions()` — inverse of `lock_down()` using backed-up ACLs
4. Make `/api/v1/health/status` unauthenticated (load balancer probe)
5. Add WebSocket rate limiting (message rate + payload size)
6. Remove dev hardcodes from `ws.py` (gate behind `DEBUG` or remove entirely)
7. Narrow 64x `except Exception` to specific exception types in critical paths
8. Implement `openlabels system backup` — `pg_dump` wrapper + config export
9. Implement `openlabels system restore` — `pg_restore` + catalog rebuild
10. Tests: Settings persistence round-trip, permission restore, backup/restore cycle

### Phase N: Model Bundling and CI/CD

Production deployment pipeline and model distribution strategy.

1. Add `pip-audit` / `safety` to CI for dependency CVE scanning
2. Add `bandit` to CI for static security analysis
3. Add Python version matrix (3.11, 3.12, 3.13) to GitHub Actions
4. Build `Dockerfile` with multi-stage build (slim + full variants)
5. Add `docker compose` integration test suite (Postgres + Redis + app)
6. Add `pytest-cov` coverage gate to CI
7. Implement model auto-download on first use (NER model from HuggingFace)
8. Implement `openlabels models download` CLI command for air-gapped environments
9. Add OCR model download/bundling (`pip install openlabels[ocr]`)
10. Wire ML detectors (PHI-BERT, PII-BERT) into detection pipeline when models present
11. Tests: Model download mocking, Docker build verification, CI pipeline

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
