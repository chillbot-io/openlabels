# OLAP and Data Lake Architecture Plan

**Version:** 2.0
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
15. [SIEM Export Integration](#15-siem-export-integration)
16. [Cloud Object Store Adapters (S3 + GCS)](#16-cloud-object-store-adapters-s3--gcs)
17. [Reporting and Distribution](#17-reporting-and-distribution)
18. [Operational Readiness](#18-operational-readiness)
19. [Implementation Phases](#19-implementation-phases)

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
| HAVING > 100 threshold | `monitoring.py:484-496` | Pre-filters to reduce result set |

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
│   Monitoring:   Access stats, access heatmap patterns                │
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
├── harvester.py             # EventHarvester background service + periodic_m365_harvest
├── notification_queue.py    # In-memory webhook notification queues (dependency-free)
├── stream.py                # PLANNED — EventStreamManager for real-time providers
└── providers/
    ├── __init__.py
    ├── base.py              # EventProvider protocol + RawAccessEvent dataclass
    ├── windows.py           # Windows Security Event Log harvester (SACL)
    ├── windows_usn.py       # PLANNED — NTFS USN Journal real-time stream
    ├── linux.py             # Linux auditd log harvester
    ├── linux_fanotify.py    # PLANNED — Linux fanotify real-time stream
    ├── m365_audit.py        # M365 Management Activity API harvester
    └── graph_webhook.py     # Graph API webhook change notifications

src/openlabels/adapters/                 # Existing adapter package
├── filesystem.py            # Existing — local/UNC filesystem adapter
├── sharepoint.py            # Existing — SharePoint Online adapter
├── onedrive.py              # Existing — OneDrive for Business adapter
├── s3.py                    # NEW — S3/S3-compatible adapter with label sync-back
└── gcs.py                   # NEW — Google Cloud Storage adapter with label sync-back

src/openlabels/export/
├── __init__.py              # Public API: ExportEngine, SIEMAdapter
├── engine.py                # Export orchestration, cursor tracking, scheduling
├── records.py               # ExportRecord dataclass, record builders
└── adapters/
    ├── __init__.py           # Adapter auto-discovery from config
    ├── base.py              # SIEMAdapter protocol
    ├── splunk.py            # Splunk HEC adapter
    ├── sentinel.py          # Microsoft Sentinel Log Analytics adapter
    ├── qradar.py            # IBM QRadar syslog/LEEF adapter
    ├── elastic.py           # Elasticsearch Bulk API adapter
    └── syslog_cef.py        # Generic syslog CEF adapter
```

### Dependency Map

```
server/routes/dashboard.py ──► analytics/service.py ──► analytics/engine.py ──► DuckDB
server/routes/monitoring.py ─┘                                                    │
server/routes/results.py ────┘                                                    ▼
                                                                             Parquet files
jobs/tasks/scan.py ──► analytics/flush.py ──► analytics/storage.py ──► S3/Azure/Local
                   │                        ▲
                   │   jobs/tasks/flush.py ──┘  (periodic event flush)
                   │
                   └──► export/engine.py ──► export/adapters/* ──► Splunk/Sentinel/QRadar/Elastic

adapters/s3.py ──► scan pipeline ──► labeling/engine.py ──► s3.apply_label_and_sync()
adapters/gcs.py ─┘                                      └──► gcs.apply_label_and_sync()

monitoring/harvester.py ──► monitoring/providers/* ──► FileAccessEvent (PostgreSQL)
                                    ▲                          │
server/routes/webhooks.py ──► notification_queue.py            ▼
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
| `boto3` | `>=1.34` | S3 write path + S3 scan adapter (DuckDB reads S3 natively via httpfs) |
| `azure-storage-blob` | `>=12.19` | Azure Blob write path |
| `google-cloud-storage` | `>=2.14` | GCS scan adapter (optional — `pip install openlabels[gcs]`) |

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

    enabled: bool = False
    tenant_id: str | None = None  # DB tenant UUID for registry cache sync
    harvest_interval_seconds: int = 60    # OS providers: 60s
    providers: list[str] = ["windows_sacl", "auditd"]
    store_raw_events: bool = False
    max_events_per_cycle: int = 10_000
    sync_cache_on_startup: bool = True
    sync_cache_on_shutdown: bool = True

    # --- M365 audit (Management Activity API) ---
    m365_harvest_interval_seconds: int = 300    # Cloud providers: 5 min
    m365_site_urls: list[str] = []              # Filter to specific sites (empty = all)

    # --- Graph webhooks ---
    webhook_enabled: bool = False
    webhook_url: str = ""             # Public HTTPS URL for Graph push notifications
    webhook_client_state: str = ""    # Shared secret for validating inbound notifications

    # --- PLANNED: Real-time stream settings (Phase I) ---
    # stream_enabled: bool = False
    # stream_batch_size: int = 100
    # usn_volumes: list[str] = []
    # fanotify_mount_points: list[str] = []


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
OPENLABELS_MONITORING__ENABLED=true
OPENLABELS_MONITORING__PROVIDERS=["windows_sacl"]

# Enable event collection (Linux example)
OPENLABELS_MONITORING__ENABLED=true
OPENLABELS_MONITORING__PROVIDERS=["auditd"]

# Enable M365 audit collection
OPENLABELS_MONITORING__ENABLED=true
OPENLABELS_MONITORING__PROVIDERS=["m365_audit","graph_webhook"]
OPENLABELS_MONITORING__M365_HARVEST_INTERVAL_SECONDS=300
OPENLABELS_MONITORING__M365_SITE_URLS=["https://contoso.sharepoint.com/sites/finance"]
OPENLABELS_MONITORING__WEBHOOK_ENABLED=true
OPENLABELS_MONITORING__WEBHOOK_URL=https://openlabels.example.com/api/v1/webhooks/graph
OPENLABELS_MONITORING__WEBHOOK_CLIENT_STATE=<random-secret>
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
  enabled: true
  harvest_interval_seconds: 60
  providers:
    - windows_sacl
  # For M365 audit collection:
  # providers:
  #   - m365_audit
  #   - graph_webhook
  # m365_harvest_interval_seconds: 300
  # m365_site_urls:
  #   - https://contoso.sharepoint.com/sites/finance
  # webhook_enabled: true
  # webhook_url: https://openlabels.example.com/api/v1/webhooks/graph
  # webhook_client_state: <random-secret>
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

@dataclass(frozen=True)
class RawAccessEvent:
    """Platform-normalized access event before DB persistence."""

    file_path: str
    event_time: datetime
    action: str                    # read, write, delete, rename, permission_change, execute
    event_source: str              # "windows_sacl", "auditd", "m365_audit", "graph_webhook"

    user_sid: str | None = None    # Windows SID or Linux UID
    user_name: str | None = None
    user_domain: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    event_id: int | None = None
    success: bool = True
    raw: dict | None = None        # Original event for forensics


@runtime_checkable
class EventProvider(Protocol):
    """Async protocol for platform-specific event collection.

    All providers — whether they use synchronous subprocesses (SACL,
    auditd) or async HTTP APIs (M365 audit, Graph webhooks) — present
    the same async interface.  Sync providers wrap their blocking I/O
    in ``asyncio.get_running_loop().run_in_executor()`` internally.

    Checkpoints are managed by the EventHarvester, not the providers.
    The harvester tracks a per-provider ``datetime`` checkpoint
    (the latest ``event_time`` from the previous cycle) and passes
    it as the ``since`` parameter.  Checkpoints are only advanced
    after the DB transaction commits successfully.
    """

    @property
    def name(self) -> str:
        """Short identifier (e.g. 'windows_sacl', 'm365_audit')."""
        ...

    async def collect(self, since: datetime | None = None) -> list[RawAccessEvent]:
        """
        Return events that occurred after *since*.

        Args:
            since: Exclusive lower-bound timestamp.  ``None`` = first run.

        Returns:
            List of RawAccessEvent instances.  The harvester handles
            filtering, back-pressure, persistence, and checkpoint
            advancement.
        """
        ...
```

### Platform Implementations

#### 12.1 Windows — SACL Event Harvester

**What it does:** Periodically reads Windows Security Event Log for file access audit events
on monitored files.

**Existing code to wire up:** `collector.py:46-131` (`_collect_windows`)

```python
# src/openlabels/monitoring/providers/windows.py

class WindowsSACLProvider:
    """
    Harvests file access events from Windows Security Event Log.

    Implements the async EventProvider protocol.  The synchronous
    ``wevtutil`` subprocess is dispatched to a thread executor.
    """

    def __init__(self, watched_paths: list[str] | None = None):
        self._collector = EventCollector()
        self._watched_paths = watched_paths

    @property
    def name(self) -> str:
        return "windows_sacl"

    async def collect(self, since: datetime | None = None) -> list[RawAccessEvent]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self._collect_sync(since))

    def _collect_sync(self, since: datetime | None = None) -> list[RawAccessEvent]:
        # Delegates to EventCollector._collect_windows()
        # Converts AccessEvent → RawAccessEvent
        ...
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
# src/openlabels/monitoring/providers/linux.py

class AuditdProvider:
    """
    Harvests file access events from Linux auditd.

    Implements the async EventProvider protocol.  The synchronous
    ``ausearch`` subprocess is dispatched to a thread executor.
    """

    def __init__(self, watched_paths: list[str] | None = None):
        self._collector = EventCollector()
        self._watched_paths = watched_paths

    @property
    def name(self) -> str:
        return "auditd"

    async def collect(self, since: datetime | None = None) -> list[RawAccessEvent]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self._collect_sync(since))

    def _collect_sync(self, since: datetime | None = None) -> list[RawAccessEvent]:
        # Delegates to EventCollector._collect_linux()
        # Converts AccessEvent → RawAccessEvent
        ...
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
| **Use for** | Real-time change detection, trigger immediate scans | Historical auditing, compliance |

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

    Authentication:
    - Same Azure AD app credentials (client_id / client_secret) as Graph API
    - Token scoped to https://manage.office.com/.default (not Graph)
    - Requires ``ActivityFeed.Read`` application permission (Office 365 Management APIs)

    Subscription model:
    1. Start subscription: POST /subscriptions/start?contentType=Audit.SharePoint
    2. List available content: GET /subscriptions/content?contentType=Audit.SharePoint
    3. Retrieve content blobs: GET {contentUri}
    4. Content available for 7 days after event
    """

    def __init__(self, tenant_id, client_id, client_secret, *,
                 monitored_site_urls: list[str] | None = None):
        ...

    @property
    def name(self) -> str:
        return "m365_audit"

    async def collect(self, since: datetime | None = None) -> list[RawAccessEvent]:
        """
        Collect events from M365 audit log.

        1. Ensure subscription is active (re-verified every 6 hours)
        2. List content blobs (paginated, max 500 pages, max 200 blobs per cycle)
        3. Fetch each blob → parse audit records → filter by site URL + item type
        4. Map M365 operations to RawAccessEvent actions
        """
        ...

    async def close(self) -> None:
        """Close the httpx client and clear credentials."""
        ...


# M365 operation → action mapping (30+ operations)
M365_OPERATION_MAP = {
    # File access
    "FileAccessed": "read",
    "FileAccessedExtended": "read",
    "FilePreviewed": "read",
    "FileDownloaded": "read",
    "FileSyncDownloadedFull": "read",
    "FileSyncDownloadedPartial": "read",
    "FileCopied": "read",
    # File modification
    "FileModified": "write",
    "FileModifiedExtended": "write",
    "FileUploaded": "write",
    "FileSyncUploadedFull": "write",
    "FileSyncUploadedPartial": "write",
    "FileCheckedOut": "write",
    "FileCheckedIn": "write",
    "FileRestored": "write",
    # File deletion
    "FileDeleted": "delete",
    "FileDeletedFirstStageRecycleBin": "delete",
    "FileDeletedSecondStageRecycleBin": "delete",
    "FileRecycled": "delete",
    "FileVersionsAllDeleted": "delete",
    # Rename / move
    "FileMoved": "rename",
    "FileRenamed": "rename",
    # Permission changes
    "SharingSet": "permission_change",
    "SharingRevoked": "permission_change",
    "SharingInheritanceBroken": "permission_change",
    "SharingInheritanceReset": "permission_change",
    "AnonymousLinkCreated": "permission_change",
    "AnonymousLinkUpdated": "permission_change",
    "AnonymousLinkRemoved": "permission_change",
    "CompanyLinkCreated": "permission_change",
    "CompanyLinkRemoved": "permission_change",
    "AddedToSecureLink": "permission_change",
    "RemovedFromSecureLink": "permission_change",
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
    The webhook route (``routes/webhooks.py``) validates the notification
    and queues it in ``notification_queue.py``.  On each harvest cycle,
    ``collect()`` drains the queue and runs delta queries.

    Differences from M365 Audit:
    - Audit API: Who accessed what (user, IP, operation) — 5-15 min latency
    - Webhooks: What changed (delta) — seconds latency, no user attribution

    Use webhooks to trigger delta scans immediately.
    Use audit API for access tracking and anomaly detection.
    """

    def __init__(self, graph_client: GraphClient, *, webhook_url: str = "",
                 client_state: str = "", drive_ids: list[str] | None = None):
        ...

    @property
    def name(self) -> str:
        return "graph_webhook"

    async def collect(self, since: datetime | None = None) -> list[RawAccessEvent]:
        """Drain notification queue, deduplicate by drive, run delta queries."""
        ...

    async def subscribe(self, drive_id: str) -> str:
        """Create a Graph change notification subscription (29-day expiry)."""
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

    Runs on a configurable interval (default: 60 seconds for on-prem,
    5 minutes for M365 audit via a separate ``periodic_m365_harvest`` task).

    Checkpoints are per-provider ``datetime`` values tracking the latest
    ``event_time`` seen.  They are staged as pending during each cycle
    and only advanced after the DB transaction commits successfully.
    """

    def __init__(self, providers: list[EventProvider], *,
                 interval_seconds: float = 60.0,
                 max_events_per_cycle: int = 10_000,
                 store_raw_events: bool = False):
        self._providers = providers
        self._interval = interval_seconds
        self._max_events = max_events_per_cycle
        self._store_raw = store_raw_events
        self._checkpoints: dict[str, datetime] = {}  # provider.name → datetime

    async def harvest_once(self, session) -> int:
        """
        Run one collection cycle across all providers.

        For each provider:
        1. ``await provider.collect(since=checkpoint)``
        2. Filter out ``UNKNOWN`` actions (not in DB enum)
        3. Back-pressure: if total > ``max_events_per_cycle``, keep earliest
        4. Resolve monitored file IDs
        5. Persist as ``FileAccessEvent`` rows
        6. Advance checkpoints only after successful flush
        """
        ...

    async def run(self, shutdown_event: asyncio.Event | None = None):
        """Run harvest_once() in a loop until shutdown_event is set."""
        ...


async def periodic_m365_harvest(
    *, tenant_id, client_id, client_secret,
    interval_seconds=300, ..., shutdown_event=None,
) -> None:
    """
    Top-level coroutine for M365 cloud providers.

    Creates an M365AuditProvider (and optionally a GraphWebhookProvider),
    runs a separate EventHarvester loop, and ensures the M365 provider's
    httpx client is closed on shutdown via try/finally.
    """
    ...
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
   - SIEM export (findings pushed to configured SIEMs via Section 15)
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

## 15. SIEM Export Integration

### Purpose

OpenLabels detects and classifies sensitive data. The customer's SIEM (Splunk, Sentinel,
QRadar, Elastic) handles correlation, alerting, dashboarding, and incident response.
OpenLabels needs to be a **first-class data source** for these platforms — not just a
CSV dump, but native adapters that speak each SIEM's ingestion protocol.

### Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    EXPORT SOURCES                                  │
│                                                                    │
│  scan_results (Parquet) ──┐                                       │
│  file_inventory (Parquet) ┤                                       │
│  access_events (Parquet) ─┤──► ExportEngine ──► SIEM Adapters     │
│  audit_log (Parquet) ─────┤                                       │
│  policy_violations ───────┘                                       │
└──────────────────────────────────────────────────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│  Splunk          │ │ Microsoft        │ │  IBM QRadar      │
│  (HEC API)       │ │ Sentinel         │ │  (Syslog/LEEF)   │
│                  │ │ (Log Analytics)  │ │                  │
└──────────────────┘ └──────────────────┘ └──────────────────┘
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│  Elastic         │ │  Generic         │ │  File Export     │
│  (Bulk API)      │ │  Syslog (CEF)    │ │  (CSV/JSON/CEF)  │
└──────────────────┘ └──────────────────┘ └──────────────────┘
```

### SIEM Adapter Protocol

```python
# src/openlabels/export/adapters/base.py

@dataclass
class ExportRecord:
    """Normalized record for SIEM export."""

    record_type: str              # scan_result, access_event, policy_violation
    timestamp: datetime
    tenant_id: UUID
    file_path: str
    risk_score: int | None
    risk_tier: str | None
    entity_types: list[str]       # ["SSN", "CREDIT_CARD", ...]
    entity_counts: dict[str, int]
    policy_violations: list[str]  # ["HIPAA §164.502", ...]
    action_taken: str | None      # labeled, quarantined, etc.
    user: str | None              # For access events
    source_adapter: str           # filesystem, sharepoint, onedrive
    metadata: dict                # Adapter-specific fields


class SIEMAdapter(Protocol):
    """Protocol for SIEM-specific export adapters."""

    async def export_batch(self, records: list[ExportRecord]) -> int:
        """
        Export a batch of records to the SIEM.
        Returns number of records successfully ingested.
        """
        ...

    async def test_connection(self) -> bool:
        """Verify connectivity to the SIEM endpoint."""
        ...

    def format_name(self) -> str:
        """Return adapter name: 'splunk', 'sentinel', 'qradar', etc."""
        ...
```

### Platform Adapters

#### 15.1 Splunk — HTTP Event Collector (HEC)

```python
# src/openlabels/export/adapters/splunk.py

class SplunkAdapter:
    """
    Export to Splunk via HTTP Event Collector (HEC).

    HEC endpoint: https://{host}:8088/services/collector/event
    Authentication: Bearer token (HEC token)
    Format: JSON events with sourcetype=openlabels

    Splunk indexes events by sourcetype and source. OpenLabels findings
    appear as structured events that Splunk dashboards, alerts, and
    correlation searches can consume natively.
    """

    def __init__(self, hec_url: str, hec_token: str,
                 index: str = "main", sourcetype: str = "openlabels",
                 verify_ssl: bool = True):
        self._url = hec_url
        self._token = hec_token
        self._index = index
        self._sourcetype = sourcetype
        self._verify_ssl = verify_ssl

    async def export_batch(self, records: list[ExportRecord]) -> int:
        # POST /services/collector/event
        # Each record becomes a Splunk event:
        # {"event": {...}, "sourcetype": "openlabels", "index": "main",
        #  "time": epoch, "source": "openlabels:scan_result"}
        # Batch POST with newline-delimited JSON
        ...

    def format_name(self) -> str:
        return "splunk"
```

#### 15.2 Microsoft Sentinel — Log Analytics Data Collector API

```python
# src/openlabels/export/adapters/sentinel.py

class SentinelAdapter:
    """
    Export to Microsoft Sentinel via Log Analytics Data Collector API.

    Endpoint: https://{workspace_id}.ods.opinsights.azure.com/api/logs
    Authentication: Shared key (workspace ID + primary key)
    Format: JSON array with custom log type

    Records appear in Sentinel as custom log table: OpenLabels_CL
    Fields auto-mapped with _s (string), _d (double), _t (datetime) suffixes.
    Can be queried via KQL in Sentinel workbooks and analytics rules.
    """

    def __init__(self, workspace_id: str, shared_key: str,
                 log_type: str = "OpenLabels"):
        self._workspace_id = workspace_id
        self._shared_key = shared_key
        self._log_type = log_type

    async def export_batch(self, records: list[ExportRecord]) -> int:
        # POST /api/logs?api-version=2016-04-01
        # Header: Authorization: SharedKey {workspace_id}:{signature}
        # Header: Log-Type: OpenLabels
        # Body: JSON array of records
        # HMAC-SHA256 signature over content-length + date + resource
        ...

    def format_name(self) -> str:
        return "sentinel"
```

#### 15.3 IBM QRadar — Syslog / LEEF

```python
# src/openlabels/export/adapters/qradar.py

class QRadarAdapter:
    """
    Export to IBM QRadar via syslog using LEEF format.

    LEEF (Log Event Extended Format) is QRadar's preferred structured format.
    Alternative: CEF (Common Event Format) also supported.

    Transport: Syslog over UDP/TCP/TLS (RFC 5424)
    Format: LEEF:2.0|OpenLabels|OpenLabels|1.0|ScanResult|...

    QRadar auto-parses LEEF fields into event properties for correlation rules,
    offenses, and dashboard widgets.
    """

    def __init__(self, syslog_host: str, syslog_port: int = 514,
                 protocol: str = "tcp", use_tls: bool = False,
                 format: str = "leef"):
        self._host = syslog_host
        self._port = syslog_port
        self._protocol = protocol
        self._use_tls = use_tls
        self._format = format  # "leef" or "cef"

    async def export_batch(self, records: list[ExportRecord]) -> int:
        # Each record → LEEF syslog message:
        # LEEF:2.0|OpenLabels|Scanner|2.0|ScanResult|
        #   filePath={path}\triskScore={score}\triskTier={tier}\t
        #   entityTypes={types}\tpolicyViolations={violations}
        ...

    def _to_leef(self, record: ExportRecord) -> str:
        """Convert ExportRecord to LEEF 2.0 format string."""
        ...

    def _to_cef(self, record: ExportRecord) -> str:
        """Convert ExportRecord to CEF format string."""
        # CEF:0|OpenLabels|Scanner|2.0|ScanResult|Sensitive Data Found|{sev}|
        #   filePath={path} riskScore={score} ...
        ...

    def format_name(self) -> str:
        return "qradar"
```

#### 15.4 Elastic — Bulk API

```python
# src/openlabels/export/adapters/elastic.py

class ElasticAdapter:
    """
    Export to Elasticsearch / Elastic SIEM via Bulk API.

    Endpoint: https://{host}:9200/_bulk
    Authentication: API key or basic auth
    Format: NDJSON (action + document pairs)
    Index pattern: openlabels-{record_type}-YYYY.MM.DD

    Records are indexed as ECS-compatible documents. Elastic SIEM rules,
    Kibana dashboards, and Lens visualizations can query them directly.
    """

    def __init__(self, hosts: list[str], api_key: str | None = None,
                 username: str | None = None, password: str | None = None,
                 index_prefix: str = "openlabels",
                 verify_ssl: bool = True):
        self._hosts = hosts
        self._api_key = api_key
        self._username = username
        self._password = password
        self._index_prefix = index_prefix
        self._verify_ssl = verify_ssl

    async def export_batch(self, records: list[ExportRecord]) -> int:
        # POST /_bulk
        # Each record → two NDJSON lines:
        # {"index": {"_index": "openlabels-scan_result-2026.02.08"}}
        # {"@timestamp": "...", "file.path": "...", "risk.score": ..., ...}
        # Map to ECS fields where possible (file.*, user.*, event.*)
        ...

    def format_name(self) -> str:
        return "elastic"
```

#### 15.5 Generic Syslog — CEF Format

```python
# src/openlabels/export/adapters/syslog_cef.py

class SyslogCEFAdapter:
    """
    Generic syslog export using CEF (Common Event Format).

    CEF is supported by most SIEMs and log management platforms.
    Useful as a fallback when no native adapter exists for the target SIEM.

    Transport: UDP, TCP, or TLS syslog (RFC 5424)
    Format: CEF:0|OpenLabels|Scanner|2.0|{event_id}|{name}|{severity}|{ext}
    """

    def __init__(self, host: str, port: int = 514,
                 protocol: str = "tcp", use_tls: bool = False):
        ...

    async def export_batch(self, records: list[ExportRecord]) -> int:
        ...

    def format_name(self) -> str:
        return "syslog_cef"
```

### Export Engine

The `ExportEngine` manages adapter lifecycle, scheduling, and delivery tracking.

```python
# src/openlabels/export/engine.py

class ExportEngine:
    """
    Manages SIEM export across configured adapters.

    Supports:
    - Scheduled export (post-scan, periodic)
    - On-demand export (API trigger, CLI)
    - Continuous streaming (near-real-time to SIEM)
    - Delivery tracking (last exported timestamp per adapter)
    """

    def __init__(self, adapters: list[SIEMAdapter], analytics: AnalyticsService):
        self._adapters = adapters
        self._analytics = analytics
        self._cursors: dict[str, datetime] = {}  # adapter_name → last_exported_at

    async def export_since_last(self, record_type: str = "all") -> dict[str, int]:
        """
        Export new records to all adapters since their last cursor.
        Returns {adapter_name: records_exported}.
        """
        results = {}
        for adapter in self._adapters:
            cursor = self._cursors.get(adapter.format_name())
            records = await self._fetch_new_records(record_type, since=cursor)
            if records:
                count = await adapter.export_batch(records)
                self._cursors[adapter.format_name()] = records[-1].timestamp
                results[adapter.format_name()] = count
        return results

    async def export_scan(self, job_id: UUID) -> dict[str, int]:
        """Export all results from a specific scan job to all adapters."""
        ...

    async def export_full(self, tenant_id: UUID, since: datetime | None = None,
                          record_types: list[str] | None = None) -> dict[str, int]:
        """Full or filtered export to all adapters."""
        ...
```

### Configuration

```python
class SIEMExportSettings(BaseSettings):
    """SIEM export configuration."""

    enabled: bool = False
    mode: Literal["post_scan", "periodic", "continuous"] = "post_scan"
    periodic_interval_seconds: int = 300  # 5 minutes (for periodic mode)

    # Splunk HEC
    splunk_hec_url: str = ""
    splunk_hec_token: str = ""
    splunk_index: str = "main"
    splunk_sourcetype: str = "openlabels"
    splunk_verify_ssl: bool = True

    # Microsoft Sentinel
    sentinel_workspace_id: str = ""
    sentinel_shared_key: str = ""
    sentinel_log_type: str = "OpenLabels"

    # IBM QRadar
    qradar_syslog_host: str = ""
    qradar_syslog_port: int = 514
    qradar_protocol: str = "tcp"
    qradar_use_tls: bool = False
    qradar_format: str = "leef"  # "leef" or "cef"

    # Elastic
    elastic_hosts: list[str] = []
    elastic_api_key: str = ""
    elastic_username: str = ""
    elastic_password: str = ""
    elastic_index_prefix: str = "openlabels"
    elastic_verify_ssl: bool = True

    # Generic syslog (CEF)
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_protocol: str = "tcp"
    syslog_use_tls: bool = False

    # Record types to export
    export_record_types: list[str] = ["scan_result", "policy_violation"]
    # Options: scan_result, access_event, policy_violation, audit_log


# Added to main Settings class:
class Settings(BaseSettings):
    ...
    siem_export: SIEMExportSettings = Field(default_factory=SIEMExportSettings)
```

```bash
# Environment variables — Splunk example
OPENLABELS_SIEM_EXPORT__ENABLED=true
OPENLABELS_SIEM_EXPORT__MODE=post_scan
OPENLABELS_SIEM_EXPORT__SPLUNK_HEC_URL=https://splunk.company.com:8088/services/collector/event
OPENLABELS_SIEM_EXPORT__SPLUNK_HEC_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
OPENLABELS_SIEM_EXPORT__SPLUNK_INDEX=security

# Sentinel example
OPENLABELS_SIEM_EXPORT__ENABLED=true
OPENLABELS_SIEM_EXPORT__SENTINEL_WORKSPACE_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
OPENLABELS_SIEM_EXPORT__SENTINEL_SHARED_KEY=...base64...

# QRadar example
OPENLABELS_SIEM_EXPORT__ENABLED=true
OPENLABELS_SIEM_EXPORT__QRADAR_SYSLOG_HOST=qradar.company.com
OPENLABELS_SIEM_EXPORT__QRADAR_USE_TLS=true
OPENLABELS_SIEM_EXPORT__QRADAR_FORMAT=leef

# Elastic example
OPENLABELS_SIEM_EXPORT__ENABLED=true
OPENLABELS_SIEM_EXPORT__ELASTIC_HOSTS=["https://elastic.company.com:9200"]
OPENLABELS_SIEM_EXPORT__ELASTIC_API_KEY=...
```

### Export Trigger Integration

| Trigger | Mode | Behavior |
|---------|------|----------|
| Scan completed | `post_scan` | Export all results from completed scan job to configured SIEMs |
| Background timer | `periodic` | Export new records since last cursor every N seconds |
| Continuous stream | `continuous` | Near-real-time: export as records are written (via flush hook) |
| API call | On-demand | `POST /api/v1/export/siem` triggers immediate export |
| CLI command | On-demand | `openlabels export siem --since 2026-02-01` |

### Data Mapping

Each adapter maps `ExportRecord` fields to the SIEM's native schema:

| ExportRecord Field | Splunk | Sentinel (KQL) | QRadar (LEEF) | Elastic (ECS) |
|-------------------|--------|----------------|---------------|---------------|
| `file_path` | `file_path` | `FilePath_s` | `filePath` | `file.path` |
| `risk_score` | `risk_score` | `RiskScore_d` | `riskScore` | `event.risk_score` |
| `risk_tier` | `risk_tier` | `RiskTier_s` | `riskTier` | `event.severity_name` |
| `entity_types` | `entity_types` | `EntityTypes_s` | `entityTypes` | `labels.entity_types` |
| `policy_violations` | `policy_violations` | `PolicyViolations_s` | `policyViolations` | `rule.name` |
| `user` | `user` | `User_s` | `userName` | `user.name` |
| `action_taken` | `action` | `ActionTaken_s` | `actionTaken` | `event.action` |
| `timestamp` | `_time` | `TimeGenerated` | `devTime` | `@timestamp` |

---

## 16. Cloud Object Store Adapters (S3 + GCS)

### Purpose

Extend OpenLabels to scan files stored in cloud object stores — Amazon S3 (and
S3-compatible like MinIO, Wasabi) and Google Cloud Storage. The workflow:

1. **Download** object from cloud storage
2. **Scan + classify** through the standard pipeline (NER, regex, scoring)
3. **Apply MIP label** to the file content (Office docs, PDFs)
4. **Conditionally re-upload** with the label embedded, preserving all original metadata

This makes OpenLabels a **multi-cloud data classification tool** — not just on-prem
and M365, but S3 and GCS as first-class scan targets with label-back capability.

### Download → Label → Re-Upload Workflow

```
┌─────────────────────┐
│  S3 Bucket / GCS    │
│  Bucket             │
│                     │
│  quarterly-report.  │
│  docx               │◄────── 5. PUT (conditional: If-Match original ETag)
│                     │           File content: labeled version
└─────────┬───────────┘           Metadata: preserved exactly
          │
          │ 1. GET Object + HEAD (capture all metadata)
          ▼
┌─────────────────────┐
│  Temp Local Copy    │
│                     │
│  quarterly-report.  │
│  docx (original)    │
└─────────┬───────────┘
          │
          │ 2. Extract text, classify (standard pipeline)
          ▼
┌─────────────────────┐
│  Classification     │
│                     │
│  3 SSNs found       │
│  risk_tier=CRITICAL │
│  policy: HIPAA §164 │
└─────────┬───────────┘
          │
          │ 3. Apply MIP label to file bytes
          ▼
┌─────────────────────┐
│  Labeled Copy       │
│                     │
│  quarterly-report.  │
│  docx (labeled)     │──────► 4. Verify: only label changed, content intact
└─────────────────────┘
```

### Metadata Preservation

When re-uploading a labeled file, **all cloud metadata must be round-tripped exactly**.
Only the file content (with embedded MIP label) changes.

#### S3 Metadata Round-Trip

```python
# src/openlabels/adapters/s3.py

class S3Adapter:
    """S3-compatible object store adapter with label-back capability."""

    async def _capture_metadata(self, bucket: str, key: str) -> dict:
        """Capture all object metadata for round-trip preservation."""
        head = await self._client.head_object(Bucket=bucket, Key=key)
        return {
            "ContentType": head.get("ContentType", "application/octet-stream"),
            "ContentEncoding": head.get("ContentEncoding"),
            "ContentDisposition": head.get("ContentDisposition"),
            "ContentLanguage": head.get("ContentLanguage"),
            "CacheControl": head.get("CacheControl"),
            "Metadata": head.get("Metadata", {}),      # x-amz-meta-* user metadata
            "StorageClass": head.get("StorageClass", "STANDARD"),
            "ServerSideEncryption": head.get("ServerSideEncryption"),
            "SSEKMSKeyId": head.get("SSEKMSKeyId"),     # KMS key for re-encryption
            "ETag": head["ETag"],                        # For conditional re-upload
        }

    async def _get_tags(self, bucket: str, key: str) -> dict:
        """Capture object tags for preservation."""
        resp = await self._client.get_object_tagging(Bucket=bucket, Key=key)
        return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}

    async def apply_label_and_sync(
        self, bucket: str, key: str, labeled_content: bytes, original_meta: dict
    ) -> bool:
        """
        Re-upload labeled file with preserved metadata.

        Uses conditional PUT (If-Match) to prevent overwriting concurrent changes.
        If the object was modified between download and re-upload, the PUT fails
        and we return False (caller should re-scan the new version).
        """
        put_args = {
            "Bucket": bucket,
            "Key": key,
            "Body": labeled_content,
            "ContentType": original_meta["ContentType"],
            "Metadata": original_meta["Metadata"],
            "StorageClass": original_meta["StorageClass"],
        }

        # Conditional write — fail if object changed since we downloaded it
        # S3: If-Match is not natively supported on PutObject, so we use
        # a two-step approach: check ETag, then put. For versioned buckets,
        # the old version is preserved automatically.
        current = await self._client.head_object(Bucket=bucket, Key=key)
        if current["ETag"] != original_meta["ETag"]:
            return False  # Object changed — re-scan needed

        # Preserve encryption settings
        if original_meta.get("ServerSideEncryption"):
            put_args["ServerSideEncryption"] = original_meta["ServerSideEncryption"]
        if original_meta.get("SSEKMSKeyId"):
            put_args["SSEKMSKeyId"] = original_meta["SSEKMSKeyId"]

        # Preserve optional headers
        for header in ("ContentEncoding", "ContentDisposition",
                       "ContentLanguage", "CacheControl"):
            if original_meta.get(header):
                put_args[header] = original_meta[header]

        await self._client.put_object(**put_args)

        # Restore tags (PutObject doesn't carry tags forward)
        tags = await self._get_tags(bucket, key)
        if tags:
            await self._client.put_object_tagging(
                Bucket=bucket, Key=key,
                Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]}
            )

        return True
```

#### GCS Metadata Round-Trip

```python
# src/openlabels/adapters/gcs.py

class GCSAdapter:
    """Google Cloud Storage adapter with label-back capability."""

    async def _capture_metadata(self, bucket: str, blob_name: str) -> dict:
        """Capture all blob metadata for round-trip preservation."""
        blob = self._bucket.blob(blob_name)
        blob.reload()
        return {
            "content_type": blob.content_type,
            "content_encoding": blob.content_encoding,
            "content_disposition": blob.content_disposition,
            "content_language": blob.content_language,
            "cache_control": blob.cache_control,
            "metadata": blob.metadata or {},              # Custom metadata
            "storage_class": blob.storage_class,
            "kms_key_name": blob.kms_key_name,
            "generation": blob.generation,                # For conditional re-upload
        }

    async def apply_label_and_sync(
        self, bucket: str, blob_name: str, labeled_content: bytes, original_meta: dict
    ) -> bool:
        """
        Re-upload labeled file with preserved metadata.

        Uses generation-based precondition (if_generation_match) to prevent
        overwriting concurrent changes. If the blob was modified, upload fails
        and we return False.
        """
        blob = self._bucket.blob(blob_name)

        # Set preserved metadata
        blob.content_type = original_meta["content_type"]
        blob.metadata = original_meta["metadata"]
        if original_meta.get("content_encoding"):
            blob.content_encoding = original_meta["content_encoding"]
        if original_meta.get("content_disposition"):
            blob.content_disposition = original_meta["content_disposition"]
        if original_meta.get("cache_control"):
            blob.cache_control = original_meta["cache_control"]

        try:
            # Conditional write — fail if blob generation changed
            blob.upload_from_string(
                labeled_content,
                content_type=original_meta["content_type"],
                if_generation_match=original_meta["generation"],
            )
            return True
        except google.api_core.exceptions.PreconditionFailed:
            return False  # Blob changed — re-scan needed
```

### Change Detection for Cloud Objects

Delta detection is critical — scanning every object in a bucket on every run is
wasteful. Each cloud platform has native change detection mechanisms:

| Mechanism | Platform | Latency | Use Case |
|-----------|----------|---------|----------|
| **S3 Event Notifications → SQS** | AWS | Seconds | Near-real-time: queue `s]ObjectCreated`, `s3:ObjectModified` events |
| **S3 Inventory** | AWS | 24h | Batch: daily CSV/Parquet manifest of all objects with ETags |
| **S3 ListObjectsV2 + ETag diff** | AWS/S3-compat | On-demand | Fallback for S3-compatible stores without event support |
| **GCS Pub/Sub Notifications** | GCP | Seconds | Near-real-time: `OBJECT_FINALIZE`, `OBJECT_DELETE` events |
| **GCS List + generation numbers** | GCP | On-demand | Fallback: compare generation numbers to detect changes |

**Recommended setup:**
- **AWS**: S3 Event Notifications → SQS queue → OpenLabels polls SQS for changed objects
- **S3-compatible (MinIO)**: ListObjectsV2 with ETag comparison against inventory
- **GCS**: Pub/Sub subscription → OpenLabels pulls notifications for changed objects

```python
# src/openlabels/adapters/s3.py (change detection)

class S3ChangeProvider:
    """
    Detect changed objects in S3 via SQS event notifications or ETag diff.

    For SQS mode:
    - Pre-requisite: S3 bucket configured to send events to SQS queue
    - Polls SQS for s3:ObjectCreated:* and s3:ObjectRemoved:* events
    - Returns only changed object keys for scanning

    For inventory mode:
    - Compares current ETag/LastModified against stored inventory
    - Used for S3-compatible stores without event notification support
    """

    async def get_changed_keys(self, since: datetime | None = None) -> list[str]:
        """Return object keys that changed since last check."""
        if self._sqs_queue_url:
            return await self._poll_sqs()
        else:
            return await self._diff_inventory()
```

### Label-Compatible File Types

MIP labels are embedded in file content. Not all file types support this:

| File Type | MIP Label Support | Mechanism |
|-----------|------------------|-----------|
| **Office docs** (docx, xlsx, pptx) | Full | Custom XML properties in OPC package |
| **PDF** | Full | Document properties / XMP metadata |
| **Office 97-2003** (doc, xls, ppt) | Partial | Custom document properties |
| **Email** (msg, eml) | Full | MIME headers / message properties |
| **Images** (jpg, png, tiff) | No | N/A — classify but don't label |
| **Plain text** (txt, csv, json, xml) | No | N/A — classify but don't label |
| **Archives** (zip, tar, gz) | No | N/A — extract and classify contents |

**Strategy:** Scan and classify ALL file types. Only re-upload files where a MIP label
was actually embedded. Files that can't hold labels are still classified, scored, and
reported — the scan results and SIEM export capture the findings regardless of whether
a label was applied.

### Configuration

```python
class S3AdapterSettings(BaseSettings):
    """S3 scan target configuration."""

    enabled: bool = False
    bucket: str = ""
    prefix: str = ""                       # Scan only objects under this prefix
    region: str = "us-east-1"
    access_key: str = ""
    secret_key: str = ""
    endpoint_url: str | None = None        # For S3-compatible (MinIO, Wasabi)
    role_arn: str | None = None            # For IAM role assumption

    # Label-back settings
    apply_labels: bool = True              # Re-upload with MIP label
    label_file_types: list[str] = [        # Only re-upload these types
        ".docx", ".xlsx", ".pptx", ".pdf",
        ".doc", ".xls", ".ppt", ".msg",
    ]

    # Change detection
    change_detection: Literal["sqs", "inventory", "list"] = "list"
    sqs_queue_url: str = ""                # For SQS-based change detection
    inventory_bucket: str = ""             # For S3 Inventory manifests


class GCSAdapterSettings(BaseSettings):
    """Google Cloud Storage scan target configuration."""

    enabled: bool = False
    bucket: str = ""
    prefix: str = ""
    project_id: str = ""
    credentials_json: str = ""             # Path to service account key JSON
    # or use Application Default Credentials (ADC) in GCP environments

    # Label-back settings
    apply_labels: bool = True
    label_file_types: list[str] = [
        ".docx", ".xlsx", ".pptx", ".pdf",
        ".doc", ".xls", ".ppt", ".msg",
    ]

    # Change detection
    change_detection: Literal["pubsub", "list"] = "list"
    pubsub_subscription: str = ""          # For Pub/Sub-based change detection


# Added to main Settings class:
class Settings(BaseSettings):
    ...
    s3_targets: list[S3AdapterSettings] = []     # Multiple buckets supported
    gcs_targets: list[GCSAdapterSettings] = []
```

```bash
# Environment variables — S3 target
OPENLABELS_S3_TARGETS__0__ENABLED=true
OPENLABELS_S3_TARGETS__0__BUCKET=company-documents
OPENLABELS_S3_TARGETS__0__REGION=us-west-2
OPENLABELS_S3_TARGETS__0__ACCESS_KEY=AKIA...
OPENLABELS_S3_TARGETS__0__SECRET_KEY=...
OPENLABELS_S3_TARGETS__0__APPLY_LABELS=true
OPENLABELS_S3_TARGETS__0__CHANGE_DETECTION=sqs
OPENLABELS_S3_TARGETS__0__SQS_QUEUE_URL=https://sqs.us-west-2.amazonaws.com/123456789/openlabels-events

# GCS target
OPENLABELS_GCS_TARGETS__0__ENABLED=true
OPENLABELS_GCS_TARGETS__0__BUCKET=company-docs-gcs
OPENLABELS_GCS_TARGETS__0__PROJECT_ID=my-project-123
OPENLABELS_GCS_TARGETS__0__CREDENTIALS_JSON=/etc/openlabels/gcs-sa-key.json
OPENLABELS_GCS_TARGETS__0__CHANGE_DETECTION=pubsub
OPENLABELS_GCS_TARGETS__0__PUBSUB_SUBSCRIPTION=projects/my-project/subscriptions/openlabels-changes
```

### Integration with Scan Pipeline

Cloud object store adapters implement the same adapter protocol as filesystem,
SharePoint, and OneDrive. They plug directly into the unified scan pipeline
(Section 13) with no changes to the classification or post-processing stages:

```
┌────────────────────────┐
│   Adapter Selection    │   filesystem / sharepoint / onedrive / s3 / gcs
│   (target.adapter)     │
└──────────┬─────────────┘
           ▼
┌────────────────────────┐
│   Change Provider      │   USN / fanotify / Graph delta / SQS / Pub/Sub / full walk
│   (Section 12)         │
└──────────┬─────────────┘
           ▼
┌────────────────────────┐
│   Download + Delta     │   adapter.read_file() → temp copy → content_hash →
│   Filter               │   inventory.should_scan_file() → skip unchanged
└──────────┬─────────────┘
           ▼
   ... (standard pipeline: extract → classify → score → label → persist) ...
           │
           ▼
┌────────────────────────┐
│   Label Sync-Back      │   For S3/GCS: apply_label_and_sync()
│   (cloud targets only) │   Conditional re-upload with preserved metadata
└────────────────────────┘
```

The key addition is the **label sync-back step** at the end of the pipeline,
which only runs for cloud object store targets and only for label-compatible
file types where a label was actually applied.

---

## 17. Reporting and Distribution

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
in the job system). Delivery via email (SMTP), local file, or S3/Azure upload.

---

## 18. Operational Readiness

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

## 19. Implementation Phases

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
4. Migrate `get_access_stats`
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

### Phase F: Unified Scan Pipeline

Merge the two scan code paths into one pipeline with parallel classification agents.
**This must land before new features are added to the scan pipeline** — otherwise
every integration (event collection, policy engine, SIEM export, cloud adapters)
would need to be wired into two separate code paths.

1. Define `ChangeProvider` protocol with default `FullWalkProvider` implementation
2. Refactor `ScanOrchestrator._walk_files()` to accept adapter + change provider
3. Refactor `ScanOrchestrator._extract_and_submit()` to run `inventory.should_scan_file()` delta check
4. Refactor `ScanOrchestrator._collect_and_store()` to run full result pipeline (scoring, exposure, labeling)
5. Remove `execute_parallel_scan_task()` — replaced by unified pipeline
6. Add adapter metadata (exposure level, permissions) to `WorkItem.metadata` for post-classification scoring
7. Add MIP label application to result pipeline
8. Add Parquet flush hook to result pipeline (Section 5.1)
9. Tests: End-to-end pipeline with mock adapter, agent pool, and DB verification

### Phase G: On-Prem Event Collection (Windows + Linux)

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

### Phase H: Cloud Event Collection (M365 Audit)

Add SharePoint and OneDrive audit log collection via the Office 365 Management Activity API.

0. Refactor `EventProvider` protocol to async — all providers now implement `async def collect()`.
   Sync OS providers (SACL, auditd) wrap their blocking subprocess calls in `run_in_executor()` internally.
   This keeps the harvester simple: `await provider.collect(since=...)` for all providers.
1. Implement `M365AuditProvider` — subscribe to `Audit.SharePoint` content type
2. Add M365 operation → action mapping (FileAccessed→read, FileModified→write, etc.)
3. Add M365 monitoring config to `MonitoringSettings` (harvest interval, scope note)
4. Implement content blob pagination (7-day sliding window, continuation URIs)
5. Add webhook endpoint for near-real-time M365 audit notifications (`POST /api/v1/webhooks/m365`)
6. Implement `GraphWebhookProvider` — subscription management + delta query on notification
7. Add webhook validation (clientState matching, validation token handling)
8. Wire M365 providers into lifespan with separate harvester instance (5 min default interval)
9. Tests: M365 audit response parsing, webhook validation, subscription lifecycle

### Phase I: Real-Time Event Streams (USN + fanotify)

Add real-time, low-latency event sources that complement the periodic harvesters.
These also serve as change providers for the unified scan pipeline (Phase F).

1. Implement `USNJournalProvider` — NTFS USN journal via `ctypes`/`DeviceIoControl`
   - `FSCTL_READ_USN_JOURNAL` for change stream
   - `FSCTL_ENUM_USN_DATA` for fast MFT enumeration (initial inventory bootstrap)
2. Implement `FanotifyProvider` — Linux kernel filesystem monitoring via `ctypes`
   - `fanotify_init()` with `FAN_CLASS_NOTIF | FAN_REPORT_FID`
   - `fanotify_mark()` with `FAN_MARK_FILESYSTEM` for whole-mount monitoring
   - PID → username resolution via `/proc/{pid}/status`
3. Implement `EventStreamManager` — long-lived async tasks, batched DB writes
4. Add real-time scan triggers — detect high-risk file modification and queue immediate scan
5. Implement `USNChangeProvider` — adapts USN journal as a `ChangeProvider` for Phase F pipeline
6. Implement `FanotifyChangeProvider` — adapts fanotify as a `ChangeProvider` for Phase F pipeline
7. Tests: USN journal parsing (mock DeviceIoControl), fanotify event parsing, buffer flush

### Phase J: Policy Engine Integration

Wire the dead `core/policies/` package into the live scan pipeline and expose via API.

1. Add `policy_violations` JSONB column to `ScanResult` model
2. Create database migration for the new column
3. Call `PolicyEngine.evaluate()` in scan pipeline after scoring (post-classification)
4. Store violations in `ScanResult.policy_violations`
5. Add `/api/v1/policies/` CRUD endpoints (list, create, update, delete)
6. Add `POST /api/v1/policies/evaluate` dry-run endpoint against existing results
7. Connect policy violation actions to remediation (quarantine, label, monitor)
8. Connect policy violations to SIEM export (Section 15)
9. Add compliance dashboard stats to DuckDB OLAP queries
10. Add default policy packs: HIPAA, GDPR, PCI-DSS, SOC2 (loadable templates)
11. Tests: Policy evaluation against scan results, action triggering, API CRUD

### Phase K: SIEM Export Integration

Build adapters for major SIEM platforms so OpenLabels findings flow natively into
the customer's security operations tooling.

1. Create `src/openlabels/export/` package with `SIEMAdapter` protocol and `ExportRecord` dataclass
2. Implement `SplunkAdapter` — HTTP Event Collector (HEC) with batched JSON events
3. Implement `SentinelAdapter` — Log Analytics Data Collector API with HMAC-SHA256 auth
4. Implement `QRadarAdapter` — syslog transport with LEEF/CEF format encoding
5. Implement `ElasticAdapter` — Elasticsearch Bulk API with ECS field mapping
6. Implement `SyslogCEFAdapter` — generic CEF over syslog (fallback for other SIEMs)
7. Implement `ExportEngine` — adapter lifecycle, cursor tracking, batch scheduling
8. Add `SIEMExportSettings` to config (per-adapter credentials and options)
9. Add post-scan export hook to unified scan pipeline — push findings after each scan
10. Add periodic export mode — background task exports new records on interval
11. Add `/api/v1/export/siem` endpoint: trigger export, test connection, view status
12. Add `openlabels export siem --adapter splunk --since 2026-02-01` CLI command
13. Tests: Adapter serialization (CEF/LEEF/JSON), connection testing (mocked), cursor tracking

### Phase L: Cloud Object Store Adapters (S3 + GCS)

Extend scanning to cloud object stores with download → classify → label → re-upload.
Requires unified scan pipeline (Phase F) for single integration point.

1. Implement `S3Adapter` — `list_files()`, `read_file()`, `get_metadata()` using `boto3`
2. Implement `S3Adapter.apply_label_and_sync()` — conditional re-upload with metadata preservation
3. Implement S3 change detection: SQS event polling mode + ListObjectsV2 ETag diff fallback
4. Implement `SQSChangeProvider` — adapts S3 event notifications as a `ChangeProvider`
5. Implement `GCSAdapter` — same protocol using `google-cloud-storage`
6. Implement `GCSAdapter.apply_label_and_sync()` — generation-based conditional re-upload
7. Implement GCS change detection: Pub/Sub notification polling + list diff fallback
8. Implement `PubSubChangeProvider` — adapts GCS notifications as a `ChangeProvider`
9. Add `S3AdapterSettings` and `GCSAdapterSettings` to config (multi-target support)
10. Add `google-cloud-storage` as optional dependency (`pip install openlabels[gcs]`)
11. Register S3/GCS as adapter types in scan target configuration
12. Add label sync-back step to unified scan pipeline result handler
13. Handle label-incompatible file types: classify but skip re-upload
14. Handle re-upload conflicts: ETag/generation mismatch → log warning, re-scan on next cycle
15. Tests: Metadata round-trip (mocked S3/GCS), conditional write conflict handling, change detection

### Phase M: Reporting and Distribution

Scheduled and on-demand report generation with distribution.

1. Create `src/openlabels/reporting/` package
2. Implement `ReportRenderer` — Jinja2 HTML templates → PDF (via `weasyprint`), HTML, CSV
3. Create report templates: executive summary, compliance report, scan detail, access audit
4. Add `weasyprint` as optional dependency (`pip install openlabels[reports]`)
5. Implement report scheduling via existing cron/job infrastructure
6. Add email delivery via SMTP (reuse `SIEMExportSettings` SMTP config or standalone)
7. Add `/api/v1/reports/` endpoints: generate, schedule, list, download
8. Add `openlabels report generate --template executive_summary --format pdf` CLI command
9. Tests: Template rendering, PDF generation, scheduled report execution

### Phase N: Operational Hardening

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

### Phase O: Model Bundling and CI/CD

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
