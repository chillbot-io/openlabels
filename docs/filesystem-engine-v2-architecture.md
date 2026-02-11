# Filesystem Engine v2: Folder-Only Index Architecture

> **Status:** Draft — February 2026
> **Supersedes:** Phases P–T of `openlabels-v1-filesystem-engine.md`

## 1. Core Insight: Index Folders, Not Files

The v1 filesystem engine design proposed indexing every file on a volume — up
to 1 billion MFT/inode records loaded into PostgreSQL. That works on paper but
creates real problems: multi-billion-row tables with expensive indexes, schema
complexity for tree navigation (`file_ref`, `parent_ref`, `depth`), and a bulk
load pipeline that dominates bootstrap time.

**v2 flips the model: index only the directory tree.**

Directories are 1–5% of filesystem entries. A volume with 1 billion files
typically has 10–50 million directories. This changes everything:

| Metric                | v1 (all files)       | v2 (folders only)     |
|-----------------------|----------------------|-----------------------|
| Rows indexed          | ~1 B                 | 10–50 M               |
| PostgreSQL table size | 200–500 GB           | 2–10 GB               |
| Bootstrap time        | 10–20 min            | 1–3 min               |
| In-memory tree        | Not feasible         | Fits comfortably      |
| Bulk load throughput  | Bottleneck            | Trivial               |

The directory tree gives us everything we actually need for security posture:
- **Tree navigation** — browse any path, list children, walk ancestors
- **Permission inheritance** — ACLs are set on directories; files inherit
- **Share mapping** — shares point at directories, not individual files
- **Scan targeting** — the scan pipeline already discovers files lazily via
  `adapter.list_files()`; the directory index tells it *where to look*

Files that matter (sensitive content) are already tracked individually in
`FileInventory`. The rest don't need a database row — they just need a
directory to live in.


## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      Bootstrap                              │
│                                                             │
│   Windows: FSCTL_ENUM_USN_DATA  →  filter to directories   │
│   Linux:   libext2fs / XFS AG   →  filter to directories   │
│   Cloud:   adapter.list_folders()                           │
│                                                             │
│              ↓  bulk load (COPY)                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│                   directory_tree  (PostgreSQL)              │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │  volume_id  │  dir_ref  │  parent_ref  │  path      │   │
│   │  sd_hash    │  share_id │  flags       │  mtime     │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                      Delta Sync                             │
│                                                             │
│   USN journal / fanotify  →  filter to directory events     │
│   S3/GCS notifications    →  prefix change detection        │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                      Consumers                              │
│                                                             │
│   Browse API   │  Scan Targeting  │  Remediation Planner    │
│   Share Risk   │  Permission Audit │  Parquet Snapshots     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Relationship to Existing Tables

```
directory_tree (NEW)              folder_inventory (EXISTING)
├── volume/share topology         ├── scan-time folder metadata
├── parent_ref tree links         ├── risk aggregation
├── security descriptor hash      ├── delta scan state
├── share assignment              └── sensitive file flags
└── filesystem-native IDs
                                  file_inventory (EXISTING, unchanged)
security_descriptors (NEW)        ├── sensitive files only
├── sd_hash → SDDL               ├── content hash delta detection
├── owner / group                 ├── label tracking
└── effective permissions cache   └── risk scoring

shares (NEW)
├── share name / UNC path
├── share-level permissions
└── protocol (SMB / NFS)
```

`directory_tree` is **not** a replacement for `folder_inventory`. They serve
different purposes:

- **`directory_tree`** — the raw filesystem topology. Populated by bootstrap
  and maintained by delta sync. Knows nothing about scan results.
- **`folder_inventory`** — aggregated scan state. Populated by the scan
  pipeline. Knows risk tiers, entity counts, sensitive file flags.

A directory appears in both tables once it has been scanned. The join key is
`(tenant_id, target_id, folder_path)`.


## 3. Schema

### 3.1 `directory_tree`

The core index table. One row per directory per volume.

```sql
CREATE TABLE directory_tree (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),
    target_id       UUID        NOT NULL REFERENCES scan_targets(id),

    -- Filesystem-native identifiers
    dir_ref         BIGINT,             -- MFT ref (Windows) or inode (Linux)
    parent_ref      BIGINT,             -- parent MFT ref / inode
    parent_id       UUID,               -- self-FK for SQL tree queries

    -- Path (denormalized for fast lookups)
    dir_path        TEXT        NOT NULL,
    dir_name        TEXT        NOT NULL,   -- basename only

    -- Security
    sd_hash         BYTEA,              -- SHA-256 of security descriptor
    share_id        UUID        REFERENCES shares(id),

    -- Metadata
    dir_modified    TIMESTAMPTZ,
    child_dir_count INT,                -- direct subdirectory count
    child_file_count INT,               -- direct file count (from MFT/inode scan)
    flags           INT         DEFAULT 0,  -- bitfield: hidden, system, reparse, etc.

    -- Housekeeping
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, target_id, dir_path)
);

-- Tree navigation: list children of a directory
CREATE INDEX ix_dirtree_parent
    ON directory_tree (tenant_id, parent_id);

-- Filesystem-native lookups (delta sync resolves parent_ref to rows)
CREATE INDEX ix_dirtree_ref
    ON directory_tree (tenant_id, target_id, dir_ref);

-- Security analysis: find all directories sharing a permission set
CREATE INDEX ix_dirtree_sd
    ON directory_tree (tenant_id, sd_hash)
    WHERE sd_hash IS NOT NULL;

-- Share scoping: all directories under a share
CREATE INDEX ix_dirtree_share
    ON directory_tree (share_id)
    WHERE share_id IS NOT NULL;
```

**Why `parent_ref` AND `parent_id`?**
- `parent_ref` is the raw MFT/inode value from bootstrap. It's what the
  filesystem gives us. Delta sync events from USN/fanotify also reference
  parent by native ID.
- `parent_id` is a UUID FK for SQL tree queries (`WITH RECURSIVE`, joins).
  Populated in a second pass after bulk load: a single `UPDATE ... FROM`
  that resolves `parent_ref` → `parent_id` across the table.

**Why `child_dir_count` / `child_file_count`?**
MFT and inode enumeration give us these for free (they're in the directory
entry metadata). Storing them avoids a `COUNT(*)` query every time the UI
renders a folder listing. Updated lazily by delta sync.

### 3.2 `security_descriptors`

Deduplicated security descriptor storage. A typical NTFS volume has
3,000–50,000 unique security descriptors shared across millions of
directories. On Linux, the equivalent is unique `(uid, gid, mode)` tuples
plus ACL entries.

```sql
CREATE TABLE security_descriptors (
    sd_hash         BYTEA       PRIMARY KEY,    -- SHA-256 of canonical form
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),

    -- Parsed fields (platform-dependent)
    owner_sid       TEXT,               -- Windows SID or Linux uid
    group_sid       TEXT,               -- Windows SID or Linux gid
    dacl_sddl       TEXT,               -- SDDL string (Windows) or POSIX ACL text
    permissions_json JSONB,             -- normalized { principal: [permissions] }

    -- Derived flags for fast filtering
    world_accessible    BOOLEAN DEFAULT FALSE,  -- Everyone/world has access
    authenticated_users BOOLEAN DEFAULT FALSE,  -- Authenticated Users / users group
    custom_acl          BOOLEAN DEFAULT FALSE,  -- non-inherited explicit ACE

    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**Why deduplicate?**
50 million directories but only ~30K unique permission sets. Storing the full
ACL on every directory row would bloat the table by 100x. With deduplication:
- `directory_tree` stores a 32-byte hash per row (compact)
- Permission queries join to `security_descriptors` (fast, small table)
- Remediation can diff two SDs without touching the main table

### 3.3 `shares`

Network share definitions. Populated by `NetShareEnum` (Windows) or
`/etc/exports` + `smb.conf` parsing (Linux).

```sql
CREATE TABLE shares (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),
    target_id       UUID        NOT NULL REFERENCES scan_targets(id),

    share_name      TEXT        NOT NULL,   -- e.g. "Finance$"
    share_path      TEXT        NOT NULL,   -- local path the share exposes
    unc_path        TEXT,                   -- \\server\share
    protocol        TEXT        NOT NULL DEFAULT 'smb',  -- smb, nfs, dfs
    share_type      TEXT,                   -- DISK, PRINT, IPC, etc.

    -- Share-level permissions (separate from NTFS/POSIX ACLs)
    share_permissions_json  JSONB,

    -- Metadata
    is_hidden       BOOLEAN     DEFAULT FALSE,  -- trailing $ in name
    is_admin_share  BOOLEAN     DEFAULT FALSE,  -- C$, ADMIN$, IPC$
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, target_id, share_name)
);
```


## 4. Bootstrap Pipeline

### 4.1 Windows: MFT Directory Scan

```
FSCTL_ENUM_USN_DATA
    ↓
    for each MFT record:
        if record.FileAttributes & FILE_ATTRIBUTE_DIRECTORY:
            emit (FileReferenceNumber, ParentFileReferenceNumber,
                  FileName, SecurityId, timestamps)
    ↓
    CSV buffer (batch 100K rows)
    ↓
    COPY directory_tree FROM STDIN
    ↓
    UPDATE directory_tree SET parent_id = p.id
      FROM directory_tree p
     WHERE directory_tree.parent_ref = p.dir_ref
       AND directory_tree.tenant_id = p.tenant_id
       AND directory_tree.target_id = p.target_id
    ↓
    Parse $Secure:$SDS stream → INSERT security_descriptors
    ↓
    NetShareEnum → INSERT shares
    ↓
    UPDATE directory_tree SET share_id = s.id
      FROM shares s
     WHERE directory_tree.dir_path LIKE s.share_path || '%'
```

**Performance expectations:**
- MFT scan: 50–100M records/min. Filtering to directories (~2–5%) means
  we process 1–5M directory records/min of output.
- Bulk load via COPY: 500K–1M rows/sec into PostgreSQL.
- A 1-billion-file volume with 30M directories: **~60 seconds** for MFT scan
  + COPY. The `parent_id` resolution UPDATE adds ~30 seconds.
- Total bootstrap: **~2 minutes** per volume.

### 4.2 Linux: Inode Table Scan

```
libext2fs (ext4) / XFS AG B-trees / btrfs extent tree
    ↓
    for each inode:
        if S_ISDIR(inode.mode):
            emit (inode_number, parent from '..' entry,
                  name, uid, gid, mode, timestamps)
    ↓
    (same bulk load pipeline as Windows)
```

On Linux, security descriptors are simpler: `(uid, gid, mode)` plus optional
POSIX ACLs. The `sd_hash` is computed from the canonical representation of
these fields.

### 4.3 Cloud Adapters

Cloud storage doesn't have real directories. The adapter synthesizes a folder
listing from object key prefixes:

```python
async def list_folders(self, prefix: str) -> AsyncIterator[FolderInfo]:
    """Yield unique directory prefixes from object listing."""
    paginator = client.get_paginator("list_objects_v2")
    async for page in paginator.paginate(Bucket=bucket, Prefix=prefix, Delimiter="/"):
        for cp in page.get("CommonPrefixes", []):
            yield FolderInfo(path=cp["Prefix"], ...)
```

No MFT or inode magic needed — just the standard delimiter-based listing that
S3/GCS/Azure Blob already support. Directories are inserted via normal
`INSERT ... ON CONFLICT UPDATE` rather than COPY bulk load.


## 5. Delta Sync

Once the directory tree is bootstrapped, it must stay current.

### 5.1 Filesystem Events

The existing `ChangeProvider` protocol already handles USN journal (Windows)
and fanotify (Linux). v2 adds a directory-focused filter:

```python
class DirectoryChangeFilter:
    """Filter change events to directory-only operations."""

    DIRECTORY_EVENTS = {
        # USN journal reason codes
        USN_REASON_FILE_CREATE,          # new directory created
        USN_REASON_FILE_DELETE,          # directory deleted
        USN_REASON_RENAME_NEW_NAME,     # directory renamed/moved
        USN_REASON_SECURITY_CHANGE,     # ACL changed on directory
        # fanotify equivalents
        FAN_CREATE | FAN_ONDIR,
        FAN_DELETE | FAN_ONDIR,
        FAN_MOVED_TO | FAN_ONDIR,
    }

    async def filter(self, event: ChangeEvent) -> ChangeEvent | None:
        if event.is_directory and event.reason in self.DIRECTORY_EVENTS:
            return event
        return None
```

**What about file-level changes?**
They don't touch `directory_tree`. The scan pipeline's existing delta logic
(content hash comparison in `FileInventory`) handles file-level changes
independently.

**ACL changes on directories** are critical — they affect the `sd_hash` column
and may cascade to child directories (inheritance). On a security change event:
1. Re-read the directory's security descriptor
2. Compute new `sd_hash`
3. If the hash changed, update `directory_tree` and upsert into
   `security_descriptors`
4. If the SD has inheritable ACEs, queue child directories for re-evaluation

### 5.2 Cloud Adapter Sync

S3 event notifications and GCS Pub/Sub already feed into `SQSChangeProvider`
and `PubSubChangeProvider`. For directory sync:
- Object creation with a new prefix → insert directory
- All objects under a prefix deleted → mark directory stale or remove
- Prefix rename (copy + delete pattern) → update `dir_path`


## 6. Consumers

### 6.1 Browse API

The directory tree enables a proper tree-browsing UI:

```
GET /api/browse/{target_id}?parent_id={dir_uuid}
```

```sql
SELECT d.id, d.dir_name, d.child_dir_count, d.child_file_count,
       d.sd_hash, sd.world_accessible,
       fi.has_sensitive_files, fi.highest_risk_tier
  FROM directory_tree d
  LEFT JOIN security_descriptors sd ON d.sd_hash = sd.sd_hash
  LEFT JOIN folder_inventory fi ON fi.tenant_id = d.tenant_id
       AND fi.target_id = d.target_id AND fi.folder_path = d.dir_path
 WHERE d.parent_id = :parent_id
 ORDER BY d.dir_name;
```

One query, no filesystem round-trips. The UI gets the tree structure, file
counts, permission flags, and risk state all at once.

### 6.2 Scan Targeting

The directory tree tells the scan pipeline where to focus:

```sql
-- Directories with world-accessible permissions that haven't been scanned
SELECT d.dir_path
  FROM directory_tree d
  JOIN security_descriptors sd ON d.sd_hash = sd.sd_hash
  LEFT JOIN folder_inventory fi ON fi.folder_path = d.dir_path
       AND fi.tenant_id = d.tenant_id AND fi.target_id = d.target_id
 WHERE sd.world_accessible = TRUE
   AND (fi.last_scanned_at IS NULL
        OR fi.last_scanned_at < d.dir_modified)
 ORDER BY d.child_file_count DESC
 LIMIT 1000;
```

This enables **risk-prioritized scanning**: scan world-accessible directories
with the most files first, then work inward. Much better than the current
linear walk through every file.

### 6.3 Remediation Planner

The remediation engine needs to know which directories share a permission set
and how changing one SD would affect the tree:

```sql
-- How many directories use this permission set?
SELECT count(*) AS affected_dirs,
       sum(child_file_count) AS affected_files
  FROM directory_tree
 WHERE sd_hash = :target_sd_hash
   AND tenant_id = :tenant_id;

-- Directories where Everyone has access under a specific share
SELECT d.dir_path, d.child_file_count, sd.dacl_sddl
  FROM directory_tree d
  JOIN security_descriptors sd ON d.sd_hash = sd.sd_hash
 WHERE d.share_id = :share_id
   AND sd.world_accessible = TRUE;
```

The planner can compute the blast radius of a remediation action before
applying it — how many directories, how many files affected, which shares
impacted.

### 6.4 Parquet Snapshots

The directory tree exports to Parquet for DuckDB analytics:

```
directory_tree/
  tenant={tenant_uuid}/
    target={target_uuid}/
      snapshot.parquet        -- full tree, overwritten atomically
```

DuckDB queries can then correlate tree structure with scan results:

```sql
-- Risk heatmap: directories with most sensitive files, grouped by share
SELECT s.share_name,
       d.dir_path,
       fi.highest_risk_tier,
       fi.total_entities_found,
       sd.world_accessible
  FROM read_parquet('directory_tree/tenant=*/target=*/*.parquet',
       hive_partitioning=true) d
  JOIN read_parquet('shares/*.parquet') s ON d.share_id = s.id
  JOIN read_parquet('folder_inventory/tenant=*/target=*/*.parquet') fi
       ON d.dir_path = fi.folder_path
  JOIN security_descriptors sd ON d.sd_hash = sd.sd_hash
 WHERE fi.has_sensitive_files = TRUE
 ORDER BY fi.total_entities_found DESC;
```


## 7. CLI Commands

```bash
# Bootstrap: enumerate directory tree from MFT/inodes
openlabels index <target_name>
openlabels index <target_name> --volume D:
openlabels index <target_name> --volume /dev/sda1

# Show index stats
openlabels index status <target_name>
# Output:
#   Volume: D:\  (NTFS)
#   Directories indexed: 12,847,293
#   Security descriptors: 4,217
#   Shares: 14
#   Bootstrap time: 87s
#   Last delta sync: 2026-02-11T14:23:00Z

# Force re-bootstrap (drops and rebuilds)
openlabels index rebuild <target_name>

# Enumerate shares
openlabels shares discover <target_name>
openlabels shares list <target_name>

# Risk-prioritized scan using the directory index
openlabels scan start <target_name> --strategy risk-priority
```


## 8. Why Not Index Files?

The natural question: if we're already scanning MFT records, why throw away
the file entries? Here's the reasoning:

1. **PostgreSQL isn't the right home for 1B rows of ephemeral data.**
   File entries change constantly (creates, deletes, renames). Keeping a
   billion-row table in sync with the filesystem is a maintenance burden
   that doesn't pay for itself.

2. **We already track the files that matter.**
   `FileInventory` stores sensitive files — the ones with detected PII,
   applied labels, and remediation actions. That's typically <1% of all
   files. The other 99% don't need a database row.

3. **Directories are the unit of permission management.**
   You set ACLs on directories. Files inherit. When a security team asks
   "what's exposed?", they're asking about directory-level permissions,
   not individual files. The directory tree answers that question directly.

4. **The scan pipeline discovers files lazily.**
   `adapter.list_files(target_path)` already enumerates files within a
   directory on demand. The directory index tells the pipeline *which*
   directories to prioritize — it doesn't need to pre-enumerate every file.

5. **If you need file-level analytics, use Parquet.**
   Scan results are already exported to Parquet with Hive partitioning.
   DuckDB handles billion-row analytical queries over Parquet without
   needing PostgreSQL as an intermediary.


## 9. Implementation Phases

### Phase 1: Schema & Bootstrap (foundations)
- [ ] `directory_tree` table + migration
- [ ] `security_descriptors` table + migration
- [ ] `shares` table + migration
- [ ] Windows MFT directory scanner (Rust/C extension or ctypes)
- [ ] Linux inode directory scanner (libext2fs bindings)
- [ ] Bulk load pipeline (CSV → COPY)
- [ ] `parent_ref` → `parent_id` resolution pass
- [ ] `openlabels index` CLI command

### Phase 2: Delta Sync
- [ ] `DirectoryChangeFilter` for USN/fanotify providers
- [ ] ACL change detection and `sd_hash` update
- [ ] Share change detection (`NetShareEnum` polling)
- [ ] Cloud prefix change → directory upsert

### Phase 3: Consumers
- [ ] Browse API endpoint
- [ ] Risk-prioritized scan strategy
- [ ] Parquet snapshot for `directory_tree`
- [ ] DuckDB view registration for directory analytics

### Phase 4: Remediation Integration
- [ ] Remediation planner: blast-radius queries
- [ ] SD diff algorithm (current vs. target)
- [ ] Batch SD application via directory tree traversal


## 10. Performance Targets

| Operation                         | Target          | Notes                          |
|-----------------------------------|-----------------|--------------------------------|
| MFT/inode bootstrap (1B files)    | < 3 min         | Directory filter reduces to ~30M rows |
| Bulk COPY into PostgreSQL         | < 60 sec        | 30M rows at 500K/sec           |
| `parent_id` resolution UPDATE     | < 30 sec        | Single self-join on indexed column |
| Browse API (list children)        | < 50 ms         | Index scan on `parent_id`      |
| Full tree Parquet snapshot        | < 45 sec        | 30M rows, ~6 GB Parquet        |
| Delta sync event processing       | < 5 ms/event    | Single row upsert              |
| SD dedup lookup                   | < 1 ms          | Primary key lookup, ~30K rows  |
| Risk-priority scan query          | < 200 ms        | Index scan + join              |
