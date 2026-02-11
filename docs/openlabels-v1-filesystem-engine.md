# OpenLabels V1: Filesystem Intelligence Engine
## See Everything. Classify Everything. Lock It Down in Minutes.

**Version:** 2.0
**Author:** chillbot.io LLC
**Date:** February 2026
**Status:** Extension of existing codebase (Phases A–O complete)

---

## Table of Contents

1. [The V1 Vision](#1-the-v1-vision)
2. [What Already Exists](#2-what-already-exists)
3. [What This Document Adds](#3-what-this-document-adds)
4. [Architecture: How It Fits](#4-architecture-how-it-fits)
5. [The Filesystem Index](#5-the-filesystem-index)
6. [Schema Extensions](#6-schema-extensions)
7. [Bootstrap: First Walk](#7-bootstrap-first-walk)
8. [Delta Sync: Staying Current](#8-delta-sync-staying-current)
9. [Query Routing: PostgreSQL vs DuckDB](#9-query-routing-postgresql-vs-duckdb)
10. [Consumer 1: Share & File Tree Browser](#10-consumer-1-share--file-tree-browser)
11. [Consumer 2: Classification Pipeline Integration](#11-consumer-2-classification-pipeline-integration)
12. [Consumer 3: Remediation Engine](#12-consumer-3-remediation-engine)
13. [Policy Engine Wiring](#13-policy-engine-wiring)
14. [Module Structure](#14-module-structure)
15. [Configuration](#15-configuration)
16. [Implementation Phases](#16-implementation-phases)
17. [Performance Summary](#17-performance-summary)
18. [Key Technical Decisions](#18-key-technical-decisions)
19. [Cross-Platform Summary](#19-cross-platform-summary)
20. [V2 Roadmap](#20-v2-roadmap)

---

## 1. The V1 Vision

V1 is three capabilities built on one foundation:

1. **See** — enumerate every share, every file, every permission across the entire estate. Users navigate a live file tree with full permission visibility.
2. **Classify** — OpenLabels detection pipeline scans content and assigns sensitivity labels.
3. **Lock down** — quarantine and remediate permissions on classified files in minutes, not days.

All three are powered by the same core: a **filesystem index** that knows the location,
metadata, permissions, and classification state of every object at all times.

---

## 2. What Already Exists

This document is **not** a greenfield design. Phases A through O of the OLAP and Data Lake
Architecture Plan are complete. The following infrastructure is built and running:

### Storage & Analytics Layer (Phases A–E)

| Component | Module | Status |
|-----------|--------|--------|
| `CatalogStorage` protocol + LocalStorage, S3Storage, AzureBlobStorage | `analytics/storage.py` | ✅ |
| PyArrow schema definitions + SQLAlchemy → Arrow converters | `analytics/schemas.py`, `analytics/arrow_convert.py` | ✅ |
| Delta flush (scan completion + periodic event flush) | `analytics/flush.py` | ✅ |
| DuckDB engine (in-process, views over Parquet globs) | `analytics/engine.py` | ✅ |
| Async service wrapper with thread pool | `analytics/service.py` | ✅ |
| Hive-style partitioning with automatic pruning | `analytics/partition.py` | ✅ |
| Partition compaction and `catalog rebuild` CLI | `analytics/` | ✅ |
| `CatalogSettings` in config with env vars | `config.py` | ✅ |

### Data Models (Existing Schema)

| Table | Model Location | Purpose |
|-------|---------------|---------|
| `ScanResult` | `models.py:297-357` | Per-file classification results |
| `FileInventory` | `models.py:503-569` | Current file state per scan target |
| `FolderInventory` | `models.py` | Directory-level aggregated state |
| `FileAccessEvent` | `models.py:670-722` | Access audit events |
| `ScanJob` | `models.py` | Job queue and status tracking |
| `RemediationAction` | `models.py` | Remediation task tracking |
| `AuditLog` | `models.py:404-422` | System audit trail |

### Unified Scan Pipeline (Phase F)

| Component | Status |
|-----------|--------|
| `ChangeProvider` protocol + `FullWalkProvider` | ✅ |
| `ScanOrchestrator` with adapter + change provider | ✅ |
| `inventory.should_scan_file()` delta check | ✅ |
| Agent pool with parallel classification | ✅ |
| Parquet flush hook in result pipeline | ✅ |

### Event Collection (Phases G–I)

| Component | Module | Status |
|-----------|--------|--------|
| `EventProvider` protocol + `RawAccessEvent` | `monitoring/providers/base.py` | ✅ |
| `WindowsSACLProvider` | `monitoring/providers/windows.py` | ✅ |
| `AuditdProvider` | `monitoring/providers/linux.py` | ✅ |
| `M365AuditProvider` | `monitoring/providers/m365_audit.py` | ✅ |
| `GraphWebhookProvider` | `monitoring/providers/graph_webhook.py` | ✅ |
| `EventHarvester` (periodic background task) | `monitoring/harvester.py` | ✅ |
| `USNJournalProvider` (real-time) | `monitoring/providers/windows_usn.py` | ✅ |
| `FanotifyProvider` (real-time) | `monitoring/providers/linux_fanotify.py` | ✅ |
| `EventStreamManager` (long-lived async tasks) | `monitoring/stream.py` | ✅ |
| `USNChangeProvider` (adapts USN as `ChangeProvider`) | `monitoring/providers/windows_usn.py` | ✅ |
| `FanotifyChangeProvider` (adapts fanotify as `ChangeProvider`) | `monitoring/providers/linux_fanotify.py` | ✅ |

### Policy Engine (Phase J)

| Component | Status |
|-----------|--------|
| `PolicyEngine.evaluate()` in scan pipeline | ✅ |
| `policy_violations` JSONB column on `ScanResult` | ✅ |
| `PolicyActionExecutor` (quarantine, labeling, monitoring, audit) | ✅ |
| `/api/v1/policies/` CRUD + dry-run + compliance stats | ✅ |
| Default policy packs (HIPAA, GDPR, PCI-DSS, SOC2, CCPA, GLBA, FERPA, PII, Credentials) | ✅ |

### SIEM Export (Phase K), Cloud Adapters (Phase L), Reporting (Phase M), Ops (Phase N), CI/CD (Phase O)

All complete. See `OLAP_AND_DATA_LAKE_ARCHITECTURE_PLAN.md` for details.

---

## 3. What This Document Adds

The filesystem index is the missing layer between the raw filesystem and the existing
infrastructure. Everything above operates on files *after* they've been discovered.
The index provides the *discovery* — and the permission/share visibility that makes
the entire product work at enterprise scale.

### New capabilities this document introduces:

| Capability | What It Enables |
|-----------|-----------------|
| **Share enumeration** | Discover every SMB/NFS share, map to filesystem paths, expose share-level permissions |
| **Filesystem-level bootstrap** | MFT scan / inode table scan for billion-file enumeration in minutes, not hours |
| **Security descriptor index** | Deduplicated SD store (3K–50K entries) for differential remediation planning |
| **Permission-aware file tree** | UI for navigating shares, directories, permissions, classifications — all from the index |
| **Remediation engine** | Planner (differential SD transformation) + Applicator (parallel `OpenFileById`/`open_by_handle_at`) + Reconciler |
| **File-by-ID operations** | `OpenFileById()` / `open_by_handle_at()` for classification reads and ACL writes — no path traversal |

### What this does NOT add:

- No new database engine — uses existing PostgreSQL + DuckDB + Parquet
- No new flush pipeline — extends existing `analytics/flush.py`
- No new event providers — wires existing `USNChangeProvider` / `FanotifyChangeProvider`
- No new policy engine — wires existing `PolicyEngine.evaluate()` into remediation

---

## 4. Architecture: How It Fits

```
┌───────────────────────────────────────────────────────────────────────────┐
│                         OPENLABELS V1 ENGINE                              │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                  FILESYSTEM INDEX (This Document)                    │  │
│  │                                                                     │  │
│  │  Bootstrap: MFT scan / inode table scan ──► PostgreSQL bulk load   │  │
│  │  Live sync: USNChangeProvider / FanotifyChangeProvider (existing)   │  │
│  │  Share enum: NetShareEnum / smb.conf ──► shares table              │  │
│  │  SD store: security_descriptors table (3K–50K unique SDs)          │  │
│  │                                                                     │  │
│  │  PostgreSQL holds: file records, folder records, SDs, shares,      │  │
│  │                    classification state, remediation state          │  │
│  │  Parquet holds:    snapshots for analytical queries                 │  │
│  │  DuckDB reads:     Parquet for dashboard/audit/export              │  │
│  └──────┬──────────────┬────────────────────┬─────────────────────────┘  │
│         │              │                    │                             │
│   ┌─────▼──────┐ ┌────▼───────┐  ┌────────▼───────────┐                │
│   │  SHARE &   │ │ CLASSIFI-  │  │  REMEDIATION        │                │
│   │  FILE TREE │ │ CATION     │  │  ENGINE (New)       │                │
│   │  BROWSER   │ │ PIPELINE   │  │                     │                │
│   │  (New)     │ │ (Existing) │  │  Planner             │                │
│   │            │ │            │  │  Applicator           │                │
│   │ Navigate   │ │ Scan       │  │  Reconciler           │                │
│   │ Audit      │ │ Label      │  │                      │                │
│   │ Query      │ │ Track      │  │  ► PolicyEngine ✅    │                │
│   └────────────┘ └────────────┘  └──────────────────────┘                │
│                                                                           │
│  EXISTING INFRASTRUCTURE:                                                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  │
│  │ SIEM ✅  │ │ S3/GCS ✅│ │Report ✅ │ │Policy ✅ │ │ Monitoring ✅ │  │
│  │ Export   │ │ Adapters │ │ Engine   │ │ Engine   │ │ Harvesters    │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └───────────────┘  │
└───────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
                          WRITE PATH
                          ─────────
Raw Filesystem ──► Bootstrap/Delta Sync ──► PostgreSQL (source of truth)
                                                │
                                    ┌───────────┴───────────┐
                                    │                       │
                              Post-commit hook         Periodic flush
                              (existing pattern)       (existing pattern)
                                    │                       │
                                    ▼                       ▼
                              Parquet files            Parquet files
                              (scan_results,           (access_events,
                               file_inventory)          audit_log)

                          READ PATH — OLTP
                          ────────────────
Single-row lookups ──► PostgreSQL
Tree navigation    ──► PostgreSQL (list_children, get_path)
Active state       ──► PostgreSQL (jobs, sessions, remediation status)
SD planning        ──► PostgreSQL (security_descriptors table — tiny)

                          READ PATH — OLAP
                          ────────────────
Dashboard stats    ──► DuckDB → Parquet (existing endpoints)
Heatmaps/trends    ──► DuckDB → Parquet (existing endpoints)
Audit aggregations ──► DuckDB → Parquet (files_with_world_access, etc.)
Export             ──► DuckDB → Arrow → CSV/JSON (existing)
Share risk scores  ──► DuckDB → Parquet (new queries)
Permission reports ──► DuckDB → Parquet (new queries)
```

---

## 5. The Filesystem Index

The index is an extension of the existing `FileInventory` and `FolderInventory` models,
plus two new tables: `security_descriptors` and `shares`. It is **not** a separate data
store — it lives in PostgreSQL and flushes to Parquet via the existing delta flush pipeline.

### What's New vs What's Extended

| Component | Status | Change |
|-----------|--------|--------|
| `FileInventory` model | Existing | Add `file_ref`, `security_id`, `share_id`, `depth`, `flags` columns |
| `FolderInventory` model | Existing | Add `file_ref`, `security_id`, `share_id`, `depth` columns |
| `security_descriptors` table | **New** | Deduplicated SD store, 3K–50K rows per volume |
| `shares` table | **New** | Enumerated shares with UNC paths and share-level permissions |
| `file_inventory` Parquet schema | Existing | Add `security_id`, `share_id` columns |
| `folder_inventory` Parquet schema | Existing | Add `security_id`, `share_id` columns |
| DuckDB views | Existing | Add `security_descriptors` view (local only — too small for Parquet) |

---

## 6. Schema Extensions

### 6.1 FileInventory Model Extensions

Add to the existing `FileInventory` model (`models.py:503-569`):

```python
class FileInventory(Base):
    # ... existing columns ...

    # NEW: Filesystem-native identifiers
    file_ref: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True, index=True,
        comment="NTFS MFT file reference number or Linux inode number"
    )
    parent_ref: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True, index=True,
        comment="Parent directory file_ref/inode for tree navigation"
    )

    # NEW: Security descriptor reference
    security_id: Mapped[int | None] = mapped_column(
        Integer, nullable=True, index=True,
        comment="NTFS SecurityId or hash of POSIX ACL — FK to security_descriptors"
    )

    # NEW: Share membership
    share_id: Mapped[int | None] = mapped_column(
        SmallInteger, nullable=True, index=True,
        comment="FK to shares table — which share exposes this file"
    )

    # NEW: Tree metadata
    depth: Mapped[int | None] = mapped_column(
        SmallInteger, nullable=True,
        comment="Tree depth from volume root (for subtree queries)"
    )
    flags: Mapped[int | None] = mapped_column(
        SmallInteger, nullable=True,
        comment="Bitmask: file/dir/symlink/reparse/hidden/system/compressed"
    )
```

**Index additions** (for the query patterns the three consumers need):

```python
# Tree navigation: list_children(parent_ref)
Index("ix_file_inventory_parent_ref", "tenant_id", "target_id", "parent_ref")

# Remediation planning: files_by_security_id(sid)
Index("ix_file_inventory_security_id", "tenant_id", "security_id")

# Share analysis: files in a specific share
Index("ix_file_inventory_share_id", "tenant_id", "share_id")

# Classification targeting: unscanned + modified
Index("ix_file_inventory_scan_state", "tenant_id", "last_scanned_at", "file_modified")
```

### 6.2 SecurityDescriptors Table (New)

```python
class SecurityDescriptor(Base):
    """Deduplicated security descriptor store.

    NTFS deduplicates SDs natively — a volume with 1 billion files typically
    has only 3,000–50,000 unique SDs. This table mirrors that deduplication
    for Linux (where ACLs are per-inode) by hashing the ACL bytes.

    This table is small enough to fit entirely in memory. It never goes to
    Parquet — DuckDB queries join against it via the security_id on
    file_inventory Parquet snapshots.
    """
    __tablename__ = "security_descriptors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)

    # SD identification
    sd_hash: Mapped[str] = mapped_column(
        String(64), unique=True,
        comment="SHA-256 of raw SD bytes (Windows) or POSIX ACL bytes (Linux)"
    )
    security_id_native: Mapped[int | None] = mapped_column(
        Integer, nullable=True,
        comment="NTFS SecurityId from $Secure — only populated on Windows"
    )

    # SD content
    sd_bytes: Mapped[bytes] = mapped_column(
        LargeBinary,
        comment="Raw security descriptor (Windows SDDL-serialized) or POSIX ACL bytes"
    )
    sd_sddl: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Human-readable SDDL string (Windows only)"
    )

    # Parsed ACE summary for fast query (avoids parsing SD bytes at query time)
    owner_sid: Mapped[str | None] = mapped_column(String(256), nullable=True)
    group_sid: Mapped[str | None] = mapped_column(String(256), nullable=True)
    ace_summary: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True,
        comment="Parsed ACEs: [{principal, access_mask, type, flags}]"
    )
    grants_world_access: Mapped[bool] = mapped_column(
        Boolean, default=False, index=True,
        comment="True if any ACE grants Everyone/Authenticated Users/Domain Users"
    )

    # Metadata
    file_count: Mapped[int] = mapped_column(
        Integer, default=0,
        comment="Number of files referencing this SD (maintained by triggers/app logic)"
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())
```

**Why this is tiny:** Even on a volume with 1 billion files, this table has 3,000–50,000
rows. It fits in PostgreSQL's shared_buffers cache permanently. No Parquet needed.

### 6.3 Shares Table (New)

```python
class Share(Base):
    """Enumerated network shares — SMB, NFS, DFS.

    Discovered via NetShareEnum (Windows), /etc/exports + smb.conf (Linux),
    or DFS namespace queries. Updated by periodic polling (every 60 seconds)
    or inotify/WMI event subscription.
    """
    __tablename__ = "shares"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    target_id: Mapped[UUID] = mapped_column(ForeignKey("scan_targets.id"), index=True)

    # Share identification
    share_name: Mapped[str] = mapped_column(String(255), comment="SMB share name or NFS export path")
    unc_path: Mapped[str] = mapped_column(String(1024), comment="\\\\SERVER\\Share or server:/export")
    local_path: Mapped[str] = mapped_column(String(1024), comment="Local filesystem path the share maps to")
    share_type: Mapped[str] = mapped_column(
        String(32), default="smb",
        comment="smb | nfs | dfs"
    )

    # Share-level permissions (separate from NTFS/POSIX file ACLs)
    share_permissions: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True,
        comment="Share-level ACEs — applied BEFORE file-level ACLs"
    )
    remark: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Aggregated stats (updated by flush or background task)
    file_count: Mapped[int] = mapped_column(BigInteger, default=0)
    total_size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    classified_count: Mapped[int] = mapped_column(Integer, default=0)
    world_accessible_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)

    # Directory reference for mapping files to shares
    root_file_ref: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True,
        comment="file_ref/inode of the directory this share points to"
    )

    # Lifecycle
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    last_verified_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
```

### 6.4 Parquet Schema Extensions

Add to the existing `file_inventory.parquet` schema in `analytics/schemas.py`:

```python
# Add to file_inventory Arrow schema
("file_ref", pa.int64()),
("parent_ref", pa.int64()),
("security_id", pa.int32()),
("share_id", pa.int16()),
("depth", pa.int16()),
("flags", pa.int16()),
```

Add to existing `arrow_convert.py` for the new columns in `file_inventory_to_arrow()`.

### 6.5 DuckDB View Extensions

Add to `analytics/engine.py` `_register_views()`:

```python
# Security descriptors stay in Postgres (tiny table, no Parquet needed)
# but we register a view for cross-engine joins via postgres_scanner
# OR we load it as an in-memory table on startup (preferred — 3K–50K rows):

def _load_security_descriptors(self, session: AsyncSession):
    """Load the SD table into DuckDB memory for cross-engine joins."""
    sds = await session.execute(select(SecurityDescriptor))
    table = security_descriptors_to_arrow(sds.scalars())
    self._db.execute("CREATE OR REPLACE TABLE security_descriptors AS SELECT * FROM table")
```

### 6.6 Database Migration

Single Alembic migration:

```python
def upgrade():
    # 1. Add columns to file_inventory
    op.add_column("file_inventory", sa.Column("file_ref", sa.BigInteger, nullable=True))
    op.add_column("file_inventory", sa.Column("parent_ref", sa.BigInteger, nullable=True))
    op.add_column("file_inventory", sa.Column("security_id", sa.Integer, nullable=True))
    op.add_column("file_inventory", sa.Column("share_id", sa.SmallInteger, nullable=True))
    op.add_column("file_inventory", sa.Column("depth", sa.SmallInteger, nullable=True))
    op.add_column("file_inventory", sa.Column("flags", sa.SmallInteger, nullable=True))

    # 2. Create indexes
    op.create_index("ix_file_inventory_parent_ref", "file_inventory",
                    ["tenant_id", "target_id", "parent_ref"])
    op.create_index("ix_file_inventory_security_id", "file_inventory",
                    ["tenant_id", "security_id"])
    op.create_index("ix_file_inventory_share_id", "file_inventory",
                    ["tenant_id", "share_id"])

    # 3. Create security_descriptors table
    op.create_table("security_descriptors", ...)

    # 4. Create shares table
    op.create_table("shares", ...)
```

---

## 7. Bootstrap: First Walk

Runs once per volume on first deployment. Uses the same scan target configuration
as the existing classification pipeline — no new target setup needed.

### Windows (NTFS)

1. **Enumerate shares** via `NetShareEnum` API — discovers every SMB share on the
   server, its path, share-level permissions, and remark. Also queries DFS namespace
   if present. Populates the `shares` table.

2. **Open raw volume handle:** `CreateFile("\\\\.\\C:", GENERIC_READ, ...)`

3. **Enumerate every MFT record** via `FSCTL_ENUM_USN_DATA`. Returns file reference
   numbers, parent references, filenames, and attributes at wire speed — sequential
   MFT scan, no directory traversal.
   - Throughput: ~50–100 million records/minute on NVMe
   - 1 billion files: **10–20 minutes** for full bootstrap

4. **Read SecurityId** from each MFT record's `$STANDARD_INFORMATION` attribute
   (4-byte field).

5. **Read `$Secure:$SDS` stream** to build the complete map of `SecurityId → security
   descriptor bytes`. NTFS deduplicates SDs — typically only **3,000–50,000 unique SDs**
   even on volumes with billions of files. Populates `security_descriptors` table.

6. **Map share paths to MFT directory references** — resolves each share's local path
   to an MFT file reference, enabling annotation of every file with which share(s)
   expose it.

7. **Bulk load into PostgreSQL** via `COPY` — stage records to a temp file, then bulk
   insert into `file_inventory`. At 500K–1M rows/sec via `COPY`, 1 billion files loads
   in ~15–30 minutes.

8. **Flush to Parquet** — triggers the existing `flush_scan_to_catalog()` pattern to
   write the `file_inventory` snapshot for DuckDB.

### Linux (ext4/XFS/Btrfs/ZFS)

1. **Enumerate exports** via `/etc/exports` (NFS), `/etc/samba/smb.conf` (SMB), and
   systemd mount units. Parse share-level access controls. Populates `shares` table.

2. **Filesystem-specific fast enumeration:**
   - **ext4:** Parse the inode table directly from the block device using `libext2fs`.
     Sequential inode table scan is far faster than tree walk.
   - **XFS:** Parse the AG (Allocation Group) inode B-trees directly. XFS stores
     inodes in predictable AG locations.
   - **Btrfs:** Walk the extent tree using `btrfs_util`. Btrfs stores all metadata
     in B-trees that can be scanned sequentially.

3. **Read POSIX ACLs** from `system.posix_acl_access` xattr, SELinux context from
   `security.selinux` xattr, and standard permission bits. Hash ACL bytes to produce
   a `security_id` for deduplication into `security_descriptors`.

4. **Map export/share paths to inode numbers** for share annotation.

5. **Bulk load + Parquet flush** — same as Windows path.

### Bootstrap Integration Point

The bootstrap runs as a CLI command and/or a first-run task in the scan target setup:

```bash
# CLI: bootstrap a volume
openlabels index --volume D: --target <target-uuid>

# Or: bootstrap all configured targets
openlabels index --all
```

The bootstrap populates the same `file_inventory` and `folder_inventory` tables the
existing scan pipeline uses. After bootstrap, the existing scan pipeline can target
files by querying the inventory instead of walking the filesystem.

---

## 8. Delta Sync: Staying Current

After bootstrap, the index is kept current in real-time using the **existing**
`USNChangeProvider` and `FanotifyChangeProvider` from Phase I.

### Wiring Into Existing Providers

The USN and fanotify providers already exist as `ChangeProvider` implementations for
the unified scan pipeline. The filesystem index extends their role:

```python
# Current: USNChangeProvider feeds changed files to the scan pipeline
# New: USNChangeProvider ALSO updates file_inventory directly

class FilesystemIndexUpdater:
    """Consumes USN/fanotify change events to keep file_inventory current.

    Runs alongside the existing EventStreamManager. Receives the same
    RawAccessEvent stream but updates the inventory table instead of
    (or in addition to) creating FileAccessEvent records.
    """

    async def handle_change(self, event: RawAccessEvent):
        match event.action:
            case "create":
                await self._insert_file_record(event)
            case "delete":
                await self._delete_file_record(event)
            case "rename":
                await self._update_file_path(event)
            case "security_change":
                await self._update_security_id(event)
            case "write" | "truncate":
                await self._update_file_metadata(event)
```

### Event Types and Index Updates

**Windows (USN Journal):**

| USN Reason | Index Action |
|-----------|--------------|
| `FILE_CREATE` | Insert new `file_inventory` row |
| `FILE_DELETE` | Delete `file_inventory` row |
| `RENAME_NEW_NAME` | Update `file_path`, `file_name`, `parent_ref` |
| `SECURITY_CHANGE` | Re-read SecurityId, update `security_id` |
| `DATA_EXTEND` / `DATA_TRUNCATION` | Update `file_size` |
| `CLOSE` (with changes) | Update `file_modified` timestamp |

**Linux (fanotify):**

| fanotify Event | Index Action |
|---------------|--------------|
| `FAN_CREATE` | Insert new `file_inventory` row |
| `FAN_DELETE` | Delete `file_inventory` row |
| `FAN_MOVED_FROM` / `FAN_MOVED_TO` | Update path, parent |
| `FAN_ATTRIB` | Re-read ACL, update `security_id` |
| `FAN_MODIFY` | Update `file_size`, `file_modified` |

**Share changes:**

- Windows: periodic `NetShareEnum` poll (every 60 seconds) or WMI event subscription
- Linux: `inotify` on `/etc/exports` and `/etc/samba/smb.conf`
- Updates `shares` table, re-annotates affected files with new `share_id`

### Inventory Snapshot Refresh

After accumulating delta changes, the `file_inventory` Parquet snapshot is refreshed
using the existing flush pattern from Section 5.3 of the OLAP plan:

```python
# Existing pattern in analytics/flush.py — snapshot overwrite per target
await storage.write_parquet(
    f"file_inventory/tenant={tid}/target={tgt}/snapshot.parquet",
    inv_table,
)
```

The snapshot is overwritten atomically. DuckDB picks up the new snapshot on next query.

---

## 9. Query Routing: PostgreSQL vs DuckDB

The filesystem index serves three consumer layers with different access patterns.
Each query routes to the appropriate engine:

### PostgreSQL (OLTP) — Point Lookups and Tree Navigation

| Query | Consumer | Why PostgreSQL |
|-------|----------|---------------|
| `list_children(parent_ref)` | File Tree Browser | B-tree index on `parent_ref`, returns ~100 rows per directory |
| `get_path(file_ref)` | File Tree Browser | Recursive parent_ref walk, ~8 hops avg |
| `get_file(file_ref)` | All consumers | Single-row PK lookup |
| `security_id_map()` | Remediation Planner | Full scan of `security_descriptors` — 3K–50K rows, fits in cache |
| `update_security_id(file_ref, new_sid)` | Remediation Applicator | Single-row update |
| `insert_file_record(...)` | Delta Sync | Transactional insert |
| `get_shares()` | Share Browser | Full scan of `shares` — ~100 rows |

### DuckDB + Parquet (OLAP) — Aggregations and Analytical Queries

| Query | Consumer | Why DuckDB |
|-------|----------|------------|
| `files_with_world_access()` | Permission Audit | Full-table scan with filter on `security_id` ∈ {world-accessible SDs} |
| `files_accessible_by(principal)` | Permission Audit | Join `file_inventory` × `security_descriptors` with ACE filter |
| `get_subtree_stats(dir_ref)` | File Tree Browser | Recursive aggregation over millions of rows |
| `files_by_security_id(sid)` | Remediation Planner | Filter on `security_id` across full inventory |
| `permission_diff(subtree, policy)` | Remediation Planner | Cross-join inventory × policy × SD table |
| `shares_exposing(classification)` | Share Browser | Join `file_inventory` × `shares` with classification filter |
| `unscanned_files(subtree)` | Classification Pipeline | Filter `last_scanned_at IS NULL` across full inventory |
| `stale_classifications(age)` | Classification Pipeline | Filter `last_scanned_at < threshold` across full inventory |
| Share risk score computation | Share Browser | Aggregation per share across all files |
| Classification coverage stats | Dashboard | COUNT + GROUP BY across full inventory |

### DuckDB Query Examples

```sql
-- Files with world access (joins in-memory SD table with Parquet inventory)
SELECT fi.file_path, fi.file_size, fi.current_label_name, fi.risk_score
FROM file_inventory fi
JOIN security_descriptors sd ON fi.security_id = sd.id
WHERE fi.tenant = ? AND sd.grants_world_access = true;

-- Share risk scores
SELECT
    s.share_name,
    s.unc_path,
    count(*) AS total_files,
    count(*) FILTER (WHERE fi.total_entities > 0) AS files_with_pii,
    count(*) FILTER (WHERE sd.grants_world_access) AS world_accessible,
    count(*) FILTER (WHERE fi.risk_tier = 'CRITICAL') AS critical_files
FROM file_inventory fi
JOIN shares s ON fi.share_id = s.id
JOIN security_descriptors sd ON fi.security_id = sd.id
WHERE fi.tenant = ?
GROUP BY s.share_name, s.unc_path;

-- Subtree classification stats (fast on columnar data)
SELECT
    fi.current_label_name,
    count(*) AS file_count,
    sum(fi.file_size) AS total_bytes,
    count(*) FILTER (WHERE sd.grants_world_access) AS exposed_count
FROM file_inventory fi
JOIN security_descriptors sd ON fi.security_id = sd.id
WHERE fi.tenant = ? AND fi.file_path LIKE '/data/research/%'
GROUP BY fi.current_label_name;

-- Remediation: files needing lockdown for a given policy
SELECT fi.file_ref, fi.file_path, fi.security_id
FROM file_inventory fi
JOIN security_descriptors sd ON fi.security_id = sd.id
WHERE fi.tenant = ?
  AND fi.current_label_name IN ('PHI', 'PII')
  AND fi.risk_tier IN ('CRITICAL', 'HIGH')
  AND sd.grants_world_access = true;
```

### Graceful Fallback

Same pattern as existing endpoints — when `catalog.enabled = false`, all queries
fall back to PostgreSQL:

```python
async def files_with_world_access(tenant_id: UUID):
    settings = get_settings()
    if settings.catalog.enabled:
        return await analytics_service.query(WORLD_ACCESS_SQL, {"tenant": tenant_id})
    else:
        # PostgreSQL fallback — works but slower on large datasets
        return await session.execute(
            select(FileInventory)
            .join(SecurityDescriptor, ...)
            .where(SecurityDescriptor.grants_world_access == True)
            .where(FileInventory.tenant_id == tenant_id)
        )
```

---

## 10. Consumer 1: Share & File Tree Browser

**Purpose:** Give users complete visibility into their file estate — what's shared,
what's exposed, who has access, what's been classified, and where the risk is.

### Share Discovery View

First thing the user sees. An inventory of every share on the server:

```
┌─────────────────────────────────────────────────────────────────┐
│ SHARES                                                          │
│                                                                 │
│ Share Name    Path                  Files      Size    Risk     │
│ ──────────    ────                  ─────      ────    ────     │
│ \\SRV\Data    D:\Data               48.2M    120 TB   ⚠ HIGH   │
│ \\SRV\Home    D:\Users\Home         12.1M     32 TB   ● MED    │
│ \\SRV\Public  D:\Public              2.3M      8 TB   🔴 CRIT  │
│ \\SRV\Backup  E:\Backups            89.4M    180 TB   ○ LOW    │
│                                                                 │
│ Risk = f(world-accessible files, unscanned files,               │
│          classified files with non-compliant ACLs)              │
└─────────────────────────────────────────────────────────────────┘
```

Risk score is computed entirely from the index — no additional scanning needed.
Available seconds after bootstrap completes. Computed via DuckDB aggregation over
the `file_inventory` Parquet snapshot joined with `security_descriptors`.

### File Tree Navigation

Users drill into any share and navigate the tree. Every level shows aggregated
metadata pulled from PostgreSQL (list_children for the current directory) with
subtree stats from DuckDB (aggregated counts and classification breakdowns):

```
┌─────────────────────────────────────────────────────────────────┐
│ \\SRV\Data > Research > Clinical-Trials                         │
│                                                                 │
│ Name              Type   Size    Perms         Classification   │
│ ──────            ────   ────    ─────         ──────────────   │
│ 📁 Study-2024/    dir    42 GB   Domain Users  ⚠ 847 PHI files │
│ 📁 Templates/     dir     1 GB   Everyone      ○ Clean          │
│ 📁 Archive/       dir   180 GB   HIPAA-Auth    ● Compliant      │
│ 📄 enrollment.xlsx file  24 MB   Everyone      🔴 PHI+PII       │
│ 📄 protocol.pdf    file  12 MB   Domain Users  ○ Public         │
│                                                                 │
│ Subtree summary: 2.4M files | 223 GB | 12,847 classified PHI   │
│                  3,201 files with non-compliant permissions      │
│                                                                 │
│ [🔒 Quarantine Selected]  [📊 Permission Report]  [🔍 Scan]    │
└─────────────────────────────────────────────────────────────────┘
```

**Query routing for this view:**

- Directory listing (current level): PostgreSQL `list_children(parent_ref)` —
  B-tree index, returns ~100 rows, sub-millisecond
- Subtree stats (aggregated counts below each directory): DuckDB aggregation
  on `file_inventory` Parquet with `file_path LIKE '/path/%'` predicate
- Permission display (per-file SD resolution): PostgreSQL join against
  `security_descriptors` — 3K–50K row table, always cached

### Permission Audit Views

**"What can this user access?"**
→ Resolve the user's group memberships, query `security_descriptors` for SDs with
matching ACEs, then DuckDB query `files_by_security_id(matching_sids)` across the
Parquet inventory. Returns in seconds because the SD table is tiny — the join key
space is 3K–50K, not a billion.

**"What's exposed to Everyone?"**
→ `SELECT id FROM security_descriptors WHERE grants_world_access = true` (milliseconds
in PostgreSQL), then DuckDB: `SELECT * FROM file_inventory WHERE security_id IN (...)`
on Parquet. The boolean flag avoids parsing SD bytes at query time.

**"Which shares contain PHI?"**
→ DuckDB: join `shares` × `file_inventory` with `current_label_name` filter. Instant.

**"Show me permission changes in the last 24 hours."**
→ Query existing `FileAccessEvent` records (already populated by the USN/fanotify
providers in Phase I) filtered by `SECURITY_CHANGE` action, joined with `file_inventory`
for context.

### New API Endpoints

```
GET /api/v1/shares                          → List all shares with risk scores
GET /api/v1/shares/{id}                     → Share detail with top-level stats
GET /api/v1/browse/{target_id}?parent_ref=  → Directory listing with metadata
GET /api/v1/browse/{target_id}/stats?path=  → Subtree aggregation stats
GET /api/v1/audit/world-access              → All world-accessible files
GET /api/v1/audit/accessible-by?principal=  → Files accessible by a given user/group
GET /api/v1/audit/permission-diff           → Files not matching a target policy
```

---

## 11. Consumer 2: Classification Pipeline Integration

**Purpose:** The existing classification pipeline uses the index to know what to scan,
what to prioritize, and what's changed — instead of walking the filesystem.

### Scan Targeting via Index

Instead of the existing `FullWalkProvider` walking the filesystem to discover files,
the pipeline can query the inventory:

```python
# New ChangeProvider implementation that queries the index
class InventoryChangeProvider:
    """Provides scan targets from the file_inventory table.

    Replaces FullWalkProvider for targets where the index has been bootstrapped.
    Falls back to FullWalkProvider if no index exists for the target.
    """

    async def get_changed_files(self, since: datetime | None) -> list[str]:
        if since is None:
            # First scan: everything unscanned
            return await self._query_unscanned()
        else:
            # Incremental: only files modified since last scan
            return await self._query_modified_since(since)

    async def _query_unscanned(self) -> list[str]:
        """Files with last_scanned_at IS NULL."""
        # Uses ix_file_inventory_scan_state index
        ...

    async def _query_modified_since(self, since: datetime) -> list[str]:
        """Files where file_modified > last_scanned_at."""
        ...
```

### Priority Scanning

The index enables smart scan prioritization that wasn't possible with filesystem walks:

```python
# Priority scan: unscanned files in world-accessible shares FIRST
high_priority = await analytics_service.query("""
    SELECT fi.file_path
    FROM file_inventory fi
    JOIN security_descriptors sd ON fi.security_id = sd.id
    WHERE fi.tenant = ? AND fi.last_scanned_at IS NULL
      AND sd.grants_world_access = true
    ORDER BY fi.file_size DESC
""")
```

### Classification Writeback

When the existing pipeline classifies a file, it already writes to `ScanResult`
and updates `FileInventory`. The index extends this to also update `security_id`
context — no new write path needed.

The existing Parquet flush (post-commit hook on scan completion) automatically
includes the new columns in the `file_inventory` snapshot.

### File-by-ID Operations

The classification pipeline can open files by filesystem ID instead of path:

```python
# Windows: OpenFileById() — bypasses directory traversal
import ctypes
handle = ctypes.windll.kernel32.OpenFileById(
    volume_handle, file_ref, GENERIC_READ, FILE_SHARE_READ, None, 0
)

# Linux: open_by_handle_at() — bypasses path resolution
import os
handle = os.open_by_handle_at(mount_fd, file_handle, os.O_RDONLY)
```

This eliminates path resolution overhead for deep directory structures. For a file
at depth 8, that's 8 directory opens, 8 security checks, and 8 potential cache misses
avoided per file.

---

## 12. Consumer 3: Remediation Engine

**Purpose:** When classified files have non-compliant permissions, fix them fast.

The remediation engine is the most novel component. It uses the SD deduplication
insight to turn a billion-file permission change into a 50K-entry planning problem.

### Planner

Given a lockdown request (from the existing `PolicyEngine` or manual trigger),
computes the minimal set of changes without touching any files.

**Input** from existing `PolicyActionExecutor`:

```json
{
  "action": "quarantine",
  "scope": {
    "path": "/data/research/clinical-trials",
    "classification": ["PHI", "PII"],
    "min_sensitivity": "CONFIDENTIAL"
  },
  "policy": {
    "remove_principals": ["Everyone", "Domain Users", "Authenticated Users"],
    "add_principals": [
      {"identity": "HIPAA-Authorized", "access": "READ"},
      {"identity": "Data-Owners", "access": "FULL_CONTROL"}
    ],
    "preserve_principals": ["SYSTEM", "Administrators"]
  }
}
```

**Planning algorithm:**

1. **SD Inventory** (milliseconds) — read all unique security descriptors from
   `security_descriptors` table. On a volume with 1 billion files: 3,000–50,000 entries.
   Fits entirely in memory.

2. **SD Transformation** (milliseconds) — for each unique SD, apply the requested
   modification in memory:
   - Parse the DACL ACEs
   - Remove ACEs matching `remove_principals`
   - Add ACEs for `add_principals`
   - Preserve ACEs matching `preserve_principals`
   - Compute the new SD bytes

   Three outcomes per SD:
   - **No change needed** — SD already satisfies the policy. Skip.
   - **Transforms to existing SD** — the modified SD matches another SD already
     in `security_descriptors`. Just remap the security_id.
   - **Transforms to new SD** — need to register a new SD.

3. **SecurityId Registration** (seconds) — for new SDs:
   - Windows: Call `SetNamedSecurityInfo` on a dummy file to force NTFS to create
     the `$Secure` entry. Read back the assigned SecurityId. Delete the dummy file.
     Repeat for each new SD (typically < 100).
   - Linux: No equivalent needed — POSIX ACLs are stored per-inode, not deduplicated.

4. **Scope Filtering** (seconds) — DuckDB query:
   ```sql
   SELECT fi.file_ref, fi.file_path, fi.security_id
   FROM file_inventory fi
   WHERE fi.tenant = ?
     AND fi.security_id IN (?)  -- SDs that need changes
     AND fi.current_label_name IN ('PHI', 'PII')
     AND fi.file_path LIKE '/data/research/clinical-trials/%'
   ```
   All analytical — no filesystem I/O.

5. **Work Plan Output:**

   ```
   Work Plan Summary:
     Total files in scope:     142,000,000
     Already compliant (skip):  98,000,000  (69%)
     Need ACL update:           44,000,000  (31%)
     Unique SD transformations:         23
     New SDs to register:                4
     Estimated time:               7 min 20 sec
   ```

The differential insight: 60–80% of files already comply. The planner eliminates
them before a single file is touched. This alone cuts the work by 2–5×.

### Applicator

Parallel API blitz on a live filesystem. No raw filesystem writes, no maintenance
window, full rollback via snapshot.

**Windows:**

1. **Pre-flight:** Take a VSS snapshot (instant rollback safety net).
2. **Open files by ID, not path.** `OpenFileById()` goes directly from MFT file
   reference to file handle — bypasses directory traversal, path resolution,
   and parent security checks.
3. **Request minimum access.** Open with `WRITE_DAC` only.
4. **256 parallel workers** pulling from the work plan queue.
5. **Disable inheritance propagation** via `PROTECTED_DACL_SECURITY_INFORMATION`.
6. **Batch by MFT locality.** Sort work plan by file reference number — turns
   random I/O into sequential metadata writes.
7. **Call `SetSecurityInfo`** with the pre-computed SD.

**Linux:**

1. **Pre-flight:** Btrfs/LVM/ZFS snapshot.
2. **Open files by inode** via `open_by_handle_at()`.
3. **Set ACLs via `fsetxattr()`** on `system.posix_acl_access` — single syscall,
   no path resolution.
4. **256 parallel workers** using io_uring for batched syscall submission (kernel 5.6+).
5. **Batch by inode number** for sequential metadata I/O.

**Expected throughput:**

| Storage | Platform | Files/sec | 44M files |
|---------|----------|-----------|-----------|
| NVMe SSD | Windows | 100,000–200,000 | 3.5–7 min |
| NVMe SSD | Linux (io_uring) | 200,000–500,000 | 1.5–3.5 min |
| SAS SSD array | Windows | 50,000–100,000 | 7–15 min |
| SAS SSD array | Linux | 100,000–200,000 | 3.5–7 min |
| Spinning disk | Windows | 10,000–30,000 | 25–75 min |
| Spinning disk | Linux | 20,000–50,000 | 15–35 min |

### Reconciler

Runs continuously after any lockdown, using the **existing** event providers:

1. **New file enforcement** — any file created in a quarantined subtree is caught
   by the existing `USNChangeProvider` / `FanotifyChangeProvider`, evaluated against
   active policies via the existing `PolicyEngine.evaluate()`, and has the correct
   ACL applied within seconds.

2. **Drift detection** — periodic spot-checks via DuckDB query: compare current
   `security_id` against expected SD for the file's classification level. Drift
   from admin changes, backup restores, or application resets triggers automatic
   remediation.

3. **Unlock workflow** — when files are reclassified (e.g., de-identified), the
   reconciler restores original permissions from historical `security_id` tracked
   in `ScanResult` history (available indefinitely in Parquet even after PostgreSQL
   prunes old `ScanResult` rows per the retention policy).

### Remediation API Endpoints

Extend existing `/api/v1/remediation/` endpoints:

```
POST /api/v1/remediation/plan           → Compute work plan (dry run)
POST /api/v1/remediation/execute         → Execute work plan
GET  /api/v1/remediation/active          → Active remediation jobs
POST /api/v1/remediation/rollback/{id}   → Rollback via VSS/LVM snapshot
GET  /api/v1/remediation/drift           → Current drift report
```

---

## 13. Policy Engine Wiring

The existing `PolicyEngine` (Phase J) already evaluates classification results against
policy rules and triggers actions via `PolicyActionExecutor`. The filesystem engine
extends this with a new action type: `remediate_permissions`.

```python
# Extension to existing PolicyActionExecutor
class PermissionRemediationAction:
    """New action type triggered by PolicyEngine.evaluate().

    When a file is classified as PHI and the policy requires restricted
    permissions, this action:
    1. Checks the file's current security_id against the policy
    2. If non-compliant, queues a remediation work item
    3. The Applicator processes the queue in batches
    """

    async def execute(self, result: ScanResult, policy: Policy):
        sd = await get_security_descriptor(result.security_id)
        if not sd.satisfies_policy(policy.enforcement):
            await queue_remediation_work_item(
                file_ref=result.file_ref,
                current_sd=sd,
                target_policy=policy.enforcement,
            )
```

The existing policy packs (HIPAA, GDPR, PCI-DSS, etc.) can be extended with
`enforcement.permissions` blocks:

```yaml
# Extension to existing policy pack format
policies:
  - name: "HIPAA PHI Lockdown"
    trigger:
      sensitivity: ["CONFIDENTIAL", "RESTRICTED"]
      categories: ["PHI"]
    actions:
      - type: "quarantine"        # Existing action
      - type: "label"             # Existing action
      - type: "remediate_permissions"  # NEW
        enforcement:
          windows:
            remove: ["Everyone", "Domain Users", "Authenticated Users"]
            add:
              - principal: "HIPAA-Authorized-RO"
                access: "READ_EXECUTE"
              - principal: "HIPAA-Data-Owners"
                access: "FULL_CONTROL"
            preserve: ["SYSTEM", "BUILTIN\\Administrators"]
          linux:
            remove_world_access: true
            remove_group_access: true
            set_owner_group: "hipaa-authorized"
            acl:
              - "group:hipaa-readers:r-x"
              - "group:hipaa-owners:rwx"
              - "mask::rwx"
```

---

## 14. Module Structure

New modules added to the existing codebase:

```
src/openlabels/
├── analytics/                    # EXISTING — Phases A–E
│   ├── engine.py                 # EXTEND: add security_descriptors in-memory table
│   ├── schemas.py                # EXTEND: add security_id, share_id to file_inventory schema
│   ├── arrow_convert.py          # EXTEND: add new columns to converters
│   ├── flush.py                  # EXTEND: include new columns in inventory snapshot
│   └── ...
│
├── monitoring/                   # EXISTING — Phases G–I
│   ├── providers/
│   │   ├── windows_usn.py        # EXISTING: USNChangeProvider (also feeds index updater)
│   │   ├── linux_fanotify.py     # EXISTING: FanotifyChangeProvider (also feeds index updater)
│   │   └── ...
│   └── ...
│
├── core/policies/                # EXISTING — Phase J
│   └── ...                       # EXTEND: add remediate_permissions action type
│
├── index/                        # NEW — Filesystem Index
│   ├── __init__.py               # Public API: IndexService, IndexBootstrapper
│   ├── bootstrap.py              # MFT/inode enumeration, bulk load, SD parsing
│   ├── updater.py                # FilesystemIndexUpdater — consumes USN/fanotify events
│   ├── shares.py                 # Share enumeration: NetShareEnum, smb.conf, /etc/exports
│   ├── security.py               # SD parsing, ACE extraction, SDDL conversion
│   ├── queries.py                # Index query functions (routes to Postgres or DuckDB)
│   └── platform/
│       ├── __init__.py
│       ├── windows.py            # FSCTL_ENUM_USN_DATA, $Secure:$SDS, OpenFileById
│       └── linux.py              # libext2fs, xfs_db, btrfs_util, open_by_handle_at
│
├── remediation/                  # NEW — Remediation Engine
│   ├── __init__.py               # Public API: RemediationService
│   ├── planner.py                # SD transformation, differential planning, work plan
│   ├── applicator.py             # Parallel API blitz: OpenFileById + SetSecurityInfo
│   ├── reconciler.py             # Drift detection, new file enforcement, unlock
│   ├── snapshot.py               # VSS/LVM/Btrfs/ZFS snapshot management
│   └── platform/
│       ├── __init__.py
│       ├── windows.py            # Win32 ACL APIs, VSS
│       └── linux.py              # POSIX ACL, io_uring, LVM/Btrfs snapshots
│
├── server/routes/
│   ├── browse.py                 # NEW: File tree browser endpoints
│   ├── shares.py                 # NEW: Share discovery endpoints
│   └── ...                       # EXISTING routes unchanged
│
└── models.py                     # EXTEND: add SecurityDescriptor, Share models
                                  # EXTEND: add columns to FileInventory
```

### New Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `liburing` | `>=2.0` | io_uring bindings for Linux ACL batching (optional) |

All other dependencies (`pyarrow`, `duckdb`, `boto3`, etc.) are already present
from Phases A–O.

Platform-specific libraries (`ctypes` for Windows APIs, `libext2fs` for ext4) are
accessed via `ctypes` FFI — no compiled extensions needed.

---

## 15. Configuration

Extensions to existing `Settings` in `config.py`:

```python
class IndexSettings(BaseSettings):
    """Filesystem index configuration."""

    enabled: bool = False
    bootstrap_batch_size: int = 100_000      # Rows per COPY batch during bootstrap
    delta_sync_batch_size: int = 1_000       # Events batched before DB write
    share_poll_interval_seconds: int = 60    # NetShareEnum / smb.conf re-read interval
    snapshot_refresh_after_delta: int = 10_000  # Re-flush Parquet after N delta changes


class RemediationSettings(BaseSettings):
    """Remediation engine configuration."""

    enabled: bool = False
    parallel_workers: int = 256
    batch_sort_by_locality: bool = True      # Sort work plan by file_ref for sequential I/O
    pre_snapshot: bool = True                # Take VSS/LVM snapshot before applying
    reconciler_interval_seconds: int = 300   # Drift check interval
    reconciler_enabled: bool = True


# Added to main Settings class:
class Settings(BaseSettings):
    ...
    index: IndexSettings = Field(default_factory=IndexSettings)
    remediation: RemediationSettings = Field(default_factory=RemediationSettings)
```

```bash
# Enable filesystem index
OPENLABELS_INDEX__ENABLED=true

# Enable remediation engine
OPENLABELS_REMEDIATION__ENABLED=true
OPENLABELS_REMEDIATION__PARALLEL_WORKERS=256
OPENLABELS_REMEDIATION__PRE_SNAPSHOT=true
```

---

## 16. Implementation Phases

These phases build on the completed Phases A–O. Each phase is independently
deployable and provides value on its own.

### Phase P: Schema Extensions + Bootstrap

The foundation — get file-level data into the existing database.

1. Create Alembic migration: add columns to `file_inventory`, create
   `security_descriptors` and `shares` tables
2. Extend `arrow_convert.py` and `schemas.py` for new Parquet columns
3. Implement `index/platform/windows.py`: `FSCTL_ENUM_USN_DATA` wrapper,
   `$Secure:$SDS` reader, `OpenFileById` wrapper
4. Implement `index/platform/linux.py`: `libext2fs` wrapper, `open_by_handle_at`
   wrapper (ext4 first, XFS/Btrfs follow)
5. Implement `index/bootstrap.py`: orchestrate MFT/inode scan → bulk COPY into
   PostgreSQL → Parquet flush
6. Implement `index/shares.py`: `NetShareEnum` wrapper (Windows), `/etc/exports`
   + `smb.conf` parser (Linux)
7. Implement `index/security.py`: SD parsing, ACE extraction, SDDL conversion,
   `grants_world_access` computation
8. Add `IndexSettings` to config
9. Add `openlabels index --volume` CLI command
10. Tests: Bootstrap accuracy (synthetic MFT data), SD parsing, share enumeration

### Phase Q: Delta Sync Integration

Wire the existing USN/fanotify providers into the index.

1. Implement `index/updater.py`: `FilesystemIndexUpdater` consuming
   `RawAccessEvent` from existing providers
2. Register updater alongside existing `EventStreamManager` in `app.py` startup
3. Implement share change detection (periodic poll + inotify/WMI)
4. Add Parquet snapshot refresh trigger after N delta changes
5. Extend DuckDB engine to load `security_descriptors` as in-memory table
6. Tests: Delta sync correctness (create/delete/rename/security_change),
   Parquet snapshot refresh

### Phase R: File Tree Browser + Share Discovery

The user-facing navigation layer.

1. Implement `server/routes/browse.py`: directory listing, path resolution,
   subtree stats
2. Implement `server/routes/shares.py`: share listing, share detail, risk scores
3. Implement DuckDB queries for share risk computation and subtree aggregation
4. Add permission audit endpoints (world-access, accessible-by, permission-diff)
5. Wire into existing web UI framework
6. Tests: Browse API responses, share risk score computation, permission audit accuracy

### Phase S: Remediation Engine

The lockdown capability.

1. Implement `remediation/planner.py`: SD transformation, differential planning,
   work plan generation
2. Implement `remediation/applicator.py`: parallel worker pool with
   `OpenFileById`/`open_by_handle_at` and `SetSecurityInfo`/`fsetxattr`
3. Implement `remediation/snapshot.py`: VSS and LVM/Btrfs/ZFS snapshot wrapper
4. Implement `remediation/reconciler.py`: drift detection, new file enforcement
5. Extend existing `PolicyActionExecutor` with `remediate_permissions` action type
6. Add remediation API endpoints
7. Add `openlabels lockdown --policy <name> --path <path>` CLI command
8. Add `RemediationSettings` to config
9. Tests: Planner differential accuracy, applicator throughput (mock filesystem),
   reconciler drift detection

### Phase T: io_uring + Performance Optimization

Linux-specific acceleration for the applicator.

1. Implement io_uring batched syscall submission for `fsetxattr` calls
2. Implement MFT locality sorting for Windows work plans
3. Add throughput metrics and progress reporting
4. Benchmark on real volumes (target: 100K+ files/sec on NVMe)
5. Tests: io_uring correctness, locality sort effectiveness

---

## 17. Performance Summary

### Scenario: 200 TB File Server, 1 Billion Objects

| Phase | Time | What Happens |
|-------|------|--------------|
| **Bootstrap** (once) | 10–20 min | Share enumeration + MFT/inode scan → PostgreSQL bulk load → Parquet flush |
| **Delta sync** (ongoing) | Real-time | Existing USN/fanotify providers → index updater → periodic Parquet refresh |
| **File tree query** | < 1 sec | PostgreSQL `list_children` (B-tree) + DuckDB subtree stats (Parquet) |
| **Permission audit** | < 5 sec | PostgreSQL SD lookup + DuckDB inventory scan |
| **Share risk scores** | < 3 sec | DuckDB aggregation over Parquet |
| **Classification scan** | Continuous | Existing pipeline, now targets from index instead of filesystem walk |
| **Remediation plan** | 5–30 sec | PostgreSQL SD inventory + DuckDB scope filter |
| **Remediation apply** | 3–15 min | Parallel `OpenFileById` / `open_by_handle_at` with locality batching |
| **Reconcile** | Real-time | Existing event providers → policy evaluation → auto-remediate |
| **Dashboard/trends** | < 1 sec | Existing DuckDB queries (Phases A–D), now with permission data |

**Bootstrap to full visibility: 10–20 minutes.** After that, everything is live.

**Lockdown command to all permissions updated: 3–15 minutes** on a live filesystem
with no downtime. Snapshot rollback available if needed.

---

## 18. Key Technical Decisions

### Why Extend the Existing Schema Instead of a Separate Index?

The previous version of this document described a standalone mmap-based index. That
made sense in isolation but ignored the infrastructure that now exists. PostgreSQL
is already the source of truth for `file_inventory`. DuckDB + Parquet already handle
the analytical queries. The delta flush pipeline already syncs Postgres → Parquet.
Adding columns to the existing tables and two small new tables is simpler, more
maintainable, and reuses every piece of infrastructure built in Phases A–O.

### Why PostgreSQL for Tree Navigation?

`list_children(parent_ref)` returns ~100 rows for a typical directory. This is a
B-tree point lookup — PostgreSQL's sweet spot. DuckDB would need to scan the full
`file_inventory` Parquet file just to find children of one directory. For navigation
(the hot path in the file tree browser), PostgreSQL wins.

For aggregations *across* the tree (subtree stats, share risk scores, "all
world-accessible files"), DuckDB wins. The routing follows the existing
three-workload separation.

### Why a Separate security_descriptors Table?

NTFS deduplicates security descriptors. A volume with 1 billion files typically
has 3,000–50,000 unique SDs. Storing the full SD on each `file_inventory` row would
bloat the table by ~500 bytes per row (50 GB for 100M files). The normalized table
stores each SD once and uses a 4-byte integer foreign key. This also enables the
differential planning algorithm — you compute ACL transformations on 50K entries
instead of per-file.

### Why OpenFileById / open_by_handle_at?

Opening a file by path requires the OS to walk every directory in the path, check
permissions at each level, resolve symlinks, and handle reparse points. For a file
at depth 8, that's 8 directory opens, 8 security checks, 8 potential cache misses.
`OpenFileById` / `open_by_handle_at` goes directly from the filesystem's internal
ID to the file. Single operation, single security check, no path resolution. This
is used everywhere: the classification pipeline reading file content, the remediation
engine writing ACLs, and the browser resolving file details on demand.

### Why Not a Kernel Driver / Minifilter?

V1 ships without any kernel code. This eliminates WHQL certification (Windows),
kernel module signing (Linux secure boot), kernel version compatibility matrices,
crash risk from kernel bugs, and customer IT team resistance to kernel modifications.
The userspace approach using `OpenFileById`, `FSCTL_ENUM_USN_DATA`, and io_uring
achieves the speed needed without deployment friction. Kernel components (virtual
ACL overlay, SELinux MLS integration) are V2 features.

---

## 19. Cross-Platform Summary

| Capability | Windows | Linux |
|-----------|---------|-------|
| Share enumeration | `NetShareEnum` + DFS namespace | `/etc/exports` + `smb.conf` parsing |
| Fast enumeration | `FSCTL_ENUM_USN_DATA` (MFT scan) | `libext2fs` / `xfs_db` (inode table scan) |
| Change journal | USN Journal — existing `USNChangeProvider` | `fanotify` — existing `FanotifyChangeProvider` |
| Open by ID | `OpenFileById()` | `open_by_handle_at()` |
| Set ACL API | `SetNamedSecurityInfo()` | `fsetxattr()` on `system.posix_acl_access` |
| Batched I/O | Win32 thread pool | `io_uring` (kernel 5.6+) |
| Snapshot/rollback | VSS | LVM / Btrfs / ZFS snapshot |
| SD deduplication | Native (NTFS `$Secure`) | Hash-based (ACL bytes → security_id) |

---

## 20. V2 Roadmap (Not in V1)

- Windows DAC resource property integration (instant policy enforcement)
- MIP sensitivity label writing (Microsoft cloud enforcement)
- SELinux MLS/MCS context setting (kernel-level Linux enforcement)
- Central policy management across multi-server environments
- Enterprise storage adapters (NetApp ONTAP, Dell EMC, Pure Storage)
- S3/GCS bucket policy generation from classification output
- Database row-level security integration (PostgreSQL, Snowflake)
- Multi-server index aggregation (local SQLite per server → central PostgreSQL)
- Direct MFT rewrite for maintenance-window lockdown (bypasses Win32 API for 10–100× speed)
