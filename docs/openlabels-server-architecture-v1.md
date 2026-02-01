# OpenLabels Server Architecture v1.0

**Open Source Data Classification & Auto-Labeling Platform**

This document is the ground truth for OpenLabels Server architecture. It captures the complete design for the server-based deployment model, including the detection engine, MIP labeling integration, adapters, GUI, and deployment options.

---

## Table of Contents

1. [Vision & Identity](#vision--identity)
2. [Core Value Proposition](#core-value-proposition)
3. [System Architecture](#system-architecture)
4. [Server Components](#server-components)
5. [Detection Engine](#detection-engine)
6. [MIP Labeling Integration](#mip-labeling-integration)
7. [Adapters](#adapters)
8. [Database Schema](#database-schema)
9. [Authentication & Authorization](#authentication--authorization)
10. [GUI Application](#gui-application)
11. [Deployment Models](#deployment-models)
12. [Windows Installer](#windows-installer)
13. [Azure Cloud Deployment](#azure-cloud-deployment)
14. [Configuration](#configuration)
15. [CLI Reference](#cli-reference)
16. [API Reference](#api-reference)
17. [Repository Structure](#repository-structure)
18. [Implementation Roadmap](#implementation-roadmap)

---

## Vision & Identity

### What OpenLabels Server Is

OpenLabels Server is an **open-source data classification and auto-labeling platform** that fills the gap between detection and action. It combines:

- **Content Classification**: Detect sensitive data (PII, PHI, PCI) across file systems and cloud storage
- **Risk Scoring**: Quantify risk by combining content sensitivity with exposure context
- **Auto-Labeling**: Apply Microsoft Information Protection (MIP) sensitivity labels automatically

### The Problem We Solve

```
Microsoft 365 E3 customers don't get auto-labeling.
That's an E5 feature ($57/user/mo vs E3 at $36/user/mo).

OpenLabels fills that gap.
```

Organizations can now:
- Scan on-prem file servers, SharePoint, and OneDrive
- Automatically classify and label sensitive data
- Achieve compliance without upgrading to E5

### What OpenLabels Server Is NOT

- **Not a replacement for DLP** — it complements existing DLP tools
- **Not just a scanner** — the auto-labeling is the key differentiator
- **Not cloud-only** — designed for on-prem Windows Server deployment first

---

## Core Value Proposition

| Need | Solution |
|------|----------|
| E3 customers need auto-labeling | MIP SDK integration applies labels automatically |
| On-prem file servers need classification | Windows-native scanner with NTFS support |
| SharePoint/OneDrive need labeling | Graph API integration for cloud content |
| Cross-platform visibility | Unified dashboard across all sources |
| Compliance reporting | Full audit trail and label status reports |

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OPENLABELS SERVER                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                         API LAYER (FastAPI)                             │ │
│  │                                                                         │ │
│  │  /scans    /results    /targets    /schedules    /labels    /dashboard │ │
│  │                                                                         │ │
│  └──────────────────────────────────┬─────────────────────────────────────┘ │
│                                     │                                        │
│  ┌──────────────────────────────────┼─────────────────────────────────────┐ │
│  │                           JOB QUEUE                                     │ │
│  │                    (PostgreSQL-backed)                                  │ │
│  └──────────────────────────────────┬─────────────────────────────────────┘ │
│                                     │                                        │
│  ┌──────────────────────────────────┴─────────────────────────────────────┐ │
│  │                         WORKER POOL                                     │ │
│  │                                                                         │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐   │ │
│  │  │                    DETECTION ENGINE                              │   │ │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │   │ │
│  │  │  │ Patterns │  │ Checksum │  │  Secrets │  │    ML    │        │   │ │
│  │  │  │ Detector │  │ Detector │  │ Detector │  │ Detector │        │   │ │
│  │  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │   │ │
│  │  │                                                                  │   │ │
│  │  │  ┌──────────────────────────────────────────────────────────┐   │   │ │
│  │  │  │              RUST CORE (PatternMatcher)                   │   │   │ │
│  │  │  │  • RegexSet + Aho-Corasick prefilter                     │   │   │ │
│  │  │  │  • Rayon parallel batch processing                        │   │   │ │
│  │  │  │  • Validators (Luhn, SSN, Phone, IPv4)                   │   │   │ │
│  │  │  └──────────────────────────────────────────────────────────┘   │   │ │
│  │  └─────────────────────────────────────────────────────────────────┘   │ │
│  │                                                                         │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐   │ │
│  │  │                    LABELING ENGINE                               │   │ │
│  │  │  ┌──────────────────────┐  ┌──────────────────────┐            │   │ │
│  │  │  │   MIP SDK (.NET)     │  │    Graph API         │            │   │ │
│  │  │  │   Local files        │  │    SharePoint/OD     │            │   │ │
│  │  │  │   Network shares     │  │                      │            │   │ │
│  │  │  └──────────────────────┘  └──────────────────────┘            │   │ │
│  │  └─────────────────────────────────────────────────────────────────┘   │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                           ADAPTERS                                      │ │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐       │ │
│  │  │ Filesystem │  │ SharePoint │  │  OneDrive  │  │    SMB     │       │ │
│  │  │  (Local)   │  │  (Graph)   │  │  (Graph)   │  │  (Network) │       │ │
│  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘       │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                         POSTGRESQL                                      │ │
│  │  • Scan jobs & results    • Label rules    • Audit logs                │ │
│  │  • Schedules              • Config         • Tenant data               │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTP/WebSocket
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OPENLABELS GUI (PyQt)                             │
│                                                                              │
│  • Scan configuration       • Results heatmap (tree view)                   │
│  • Label rule management    • File detail context cards                     │
│  • Schedule management      • Dashboard & reporting                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Configure   │────►│    Scan      │────►│   Classify   │────►│    Label     │
│   Target     │     │   Content    │     │   & Score    │     │   (MIP)      │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
       │                    │                    │                    │
       ▼                    ▼                    ▼                    ▼
  ┌─────────┐         ┌─────────┐         ┌─────────┐         ┌─────────┐
  │ DB:     │         │ Detect  │         │ Risk    │         │ Apply   │
  │ targets │         │ 50+ SIT │         │ 0-100   │         │ Label   │
  │ schedule│         │ types   │         │ + tier  │         │ to file │
  └─────────┘         └─────────┘         └─────────┘         └─────────┘
```

---

## Server Components

### API Server (FastAPI)

The API server handles all client requests and WebSocket connections for real-time updates.

| Endpoint Group | Purpose |
|----------------|---------|
| `/api/scans` | Create, list, cancel scan jobs |
| `/api/results` | Query scan results, filter, export |
| `/api/targets` | Configure scan targets (paths, sites) |
| `/api/schedules` | Manage scheduled scans |
| `/api/labels` | Label configuration, sync from M365 |
| `/api/dashboard` | Statistics, aggregations |
| `/api/config` | Server configuration |
| `/ws/scans/{id}` | WebSocket for live scan progress |

### Job Queue

PostgreSQL-backed job queue for reliable task processing.

```python
class JobQueue:
    """PostgreSQL-backed job queue with priority support."""

    async def enqueue(
        self,
        task_type: str,      # 'scan', 'label', 'export'
        payload: dict,
        priority: int = 50,  # 0-100, higher = more urgent
        scheduled_for: datetime = None,
    ) -> UUID:
        """Add job to queue."""

    async def dequeue(self, worker_id: str) -> Job | None:
        """Get next job for processing."""

    async def complete(self, job_id: UUID, result: dict):
        """Mark job as completed."""

    async def fail(self, job_id: UUID, error: str, retry: bool = True):
        """Mark job as failed, optionally retry."""
```

### Worker Pool

Workers process scan and labeling jobs. Each worker is a separate process with its own Rust core instance.

```python
class WorkerPool:
    """Manages worker processes for parallel job execution."""

    def __init__(self, num_workers: int = None):
        # Default to CPU count
        self.num_workers = num_workers or os.cpu_count()

    def start(self):
        """Start worker processes."""
        for i in range(self.num_workers):
            process = multiprocessing.Process(
                target=worker_main,
                args=(i, self.config)
            )
            process.start()
            self.workers.append(process)
```

---

## Detection Engine

### Detector Orchestrator

Coordinates multiple detectors running in parallel.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DETECTOR ORCHESTRATOR                                │
│                                                                              │
│  Input: Text content                                                         │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                    PARALLEL DETECTION (ThreadPoolExecutor)              │ │
│  │                                                                         │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │ │
│  │  │   Checksum   │  │   Pattern    │  │   Secrets    │                  │ │
│  │  │   Detector   │  │   Detector   │  │   Detector   │                  │ │
│  │  │              │  │              │  │              │                  │ │
│  │  │ • SSN        │  │ • Names      │  │ • API Keys   │                  │ │
│  │  │ • Credit Card│  │ • Dates      │  │ • Tokens     │                  │ │
│  │  │ • NPI        │  │ • Addresses  │  │ • Passwords  │                  │ │
│  │  │ • IBAN       │  │ • Phones     │  │ • Private    │                  │ │
│  │  │ • CUSIP      │  │ • Emails     │  │   Keys       │                  │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘                  │ │
│  │                                                                         │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │ │
│  │  │  Financial   │  │  Government  │  │  Dictionary  │                  │ │
│  │  │  Detector    │  │  Detector    │  │  Detector    │                  │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘                  │ │
│  │                                                                         │ │
│  │  ┌──────────────┐  ┌──────────────┐                                    │ │
│  │  │     ML       │  │  Structured  │    (Optional)                      │ │
│  │  │   Detector   │  │  Detector    │                                    │ │
│  │  └──────────────┘  └──────────────┘                                    │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                     │                                        │
│                                     ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                         POST-PROCESSING                                 │ │
│  │  • Merge overlapping spans       • Deduplicate                         │ │
│  │  • Apply confidence thresholds   • Context enhancement                 │ │
│  │  • Normalize entity types        • Filter false positives              │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  Output: List[DetectedEntity]                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Rust Core

High-performance pattern matching using Rust, exposed to Python via PyO3.

```rust
// src/lib.rs
use pyo3::prelude::*;
use regex::RegexSet;
use rayon::prelude::*;

#[pyclass]
pub struct PatternMatcher {
    regex_set: RegexSet,
    patterns: Vec<PatternInfo>,
}

#[pymethods]
impl PatternMatcher {
    /// Find all matches in batch (parallel via Rayon)
    fn find_matches_batch(&self, py: Python, texts: Vec<&str>) -> Vec<Vec<RawMatch>> {
        py.allow_threads(|| {
            texts.par_iter()
                .map(|text| self.find_matches_single(text))
                .collect()
        })
    }
}
```

### Confidence Tiers

| Tier | Confidence | Source |
|------|------------|--------|
| **Tier 1** | 0.95 - 1.00 | Checksum-validated (Luhn, mod-97) |
| **Tier 2** | 0.80 - 0.95 | Pattern + context validation |
| **Tier 3** | 0.60 - 0.80 | ML detection |
| **Tier 4** | 0.40 - 0.60 | Pattern-only (no validation) |

---

## MIP Labeling Integration

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LABELING ENGINE                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                    UNIFIED LABELING INTERFACE                           │ │
│  │                                                                         │ │
│  │    label_engine.apply(target_type, path, label_id)                     │ │
│  │                                                                         │ │
│  └──────────────────────────────┬─────────────────────────────────────────┘ │
│                                 │                                            │
│           ┌─────────────────────┴─────────────────────┐                     │
│           ▼                                           ▼                     │
│  ┌─────────────────────────┐              ┌─────────────────────────┐      │
│  │      MIP SDK            │              │      Graph API          │      │
│  │    (.NET via pythonnet) │              │                         │      │
│  │                         │              │                         │      │
│  │  • Local files          │              │  • SharePoint Online    │      │
│  │  • Network shares       │              │  • OneDrive for Business│      │
│  │  • Office documents     │              │                         │      │
│  │  • PDFs, images         │              │                         │      │
│  └─────────────────────────┘              └─────────────────────────┘      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### MIP SDK Integration

```python
# labeling/mip_sdk.py
import clr
clr.AddReference("Microsoft.InformationProtection")
clr.AddReference("Microsoft.InformationProtection.File")

class MIPLabeler:
    """Apply sensitivity labels to local files using MIP SDK."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._initialize_mip()

    def get_labels(self) -> list[SensitivityLabel]:
        """Get available sensitivity labels for this tenant."""
        return self._file_engine.SensitivityLabels

    def apply_label(self, file_path: str, label_id: str) -> bool:
        """Apply a sensitivity label to a file."""
        handler = self._file_engine.CreateFileHandler(file_path)
        handler.SetLabel(label_id, LabelingOptions())
        return handler.CommitAsync(file_path).GetAwaiter().GetResult()

    def get_current_label(self, file_path: str) -> SensitivityLabel | None:
        """Get the current label on a file."""
        handler = self._file_engine.CreateFileHandler(file_path)
        return handler.GetLabel()
```

### Graph API Labeling

```python
# labeling/graph_labeler.py
class GraphLabeler:
    """Apply sensitivity labels via Microsoft Graph API."""

    async def apply_label(
        self,
        site_id: str,
        item_id: str,
        label_id: str
    ) -> bool:
        """Apply MIP sensitivity label to a SharePoint/OneDrive file."""
        await self.graph.patch(
            f"/sites/{site_id}/drive/items/{item_id}",
            json={
                "sensitivityLabel": {
                    "labelId": label_id,
                    "assignmentMethod": "auto"
                }
            }
        )
        return True
```

### Label Mapping Rules

```yaml
# config.yaml
labeling:
  enabled: true
  mode: auto  # 'auto' | 'recommend'

  # Map risk tiers to MIP labels
  risk_tier_mapping:
    CRITICAL: "Highly Confidential"
    HIGH: "Confidential"
    MEDIUM: "Internal"
    LOW: null  # No label
    MINIMAL: null

  # Override by entity type
  entity_type_mapping:
    SSN: "Highly Confidential"
    CREDIT_CARD: "Highly Confidential"
    PHI: "Confidential"
```

---

## Adapters

### Adapter Interface

All adapters implement a common interface for listing and reading files.

```python
from typing import Protocol, AsyncIterator
from dataclasses import dataclass

@dataclass
class FileInfo:
    """Normalized file information."""
    path: str
    name: str
    size: int
    modified: datetime
    owner: str | None
    permissions: dict
    exposure: ExposureLevel

class Adapter(Protocol):
    """Protocol for storage adapters."""

    async def list_files(
        self,
        target: str,
        recursive: bool = True
    ) -> AsyncIterator[FileInfo]:
        """List files in target location."""
        ...

    async def read_file(self, path: str) -> bytes:
        """Read file content."""
        ...

    async def get_metadata(self, path: str) -> FileInfo:
        """Get file metadata."""
        ...
```

### Filesystem Adapter

```python
class FilesystemAdapter:
    """Local and network filesystem adapter."""

    def __init__(self, service_account: str = None):
        self.service_account = service_account
        self.is_windows = platform.system() == "Windows"

    async def list_files(self, target: str, recursive: bool = True):
        """List files with NTFS/POSIX permission detection."""
        for path in self._walk(target, recursive):
            yield FileInfo(
                path=path,
                name=os.path.basename(path),
                size=os.path.getsize(path),
                modified=datetime.fromtimestamp(os.path.getmtime(path)),
                owner=self._get_owner(path),
                permissions=self._get_permissions(path),
                exposure=self._calculate_exposure(path),
            )

    def _calculate_exposure(self, path: str) -> ExposureLevel:
        """Determine exposure level from permissions."""
        if self.is_windows:
            return self._get_ntfs_exposure(path)
        else:
            return self._get_posix_exposure(path)
```

### SharePoint Adapter

```python
class SharePointAdapter:
    """SharePoint Online adapter via Microsoft Graph API."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.graph = GraphClient(tenant_id, client_id, client_secret)

    async def list_sites(self) -> list[Site]:
        """List all SharePoint sites."""
        response = await self.graph.get("/sites?search=*")
        return [Site(**s) for s in response["value"]]

    async def list_files(
        self,
        site_id: str,
        path: str = "/",
        recursive: bool = True
    ) -> AsyncIterator[FileInfo]:
        """List files in a SharePoint site."""
        items = await self.graph.get(
            f"/sites/{site_id}/drive/root:/{path}:/children"
        )
        for item in items["value"]:
            if item.get("folder") and recursive:
                async for child in self.list_files(site_id, item["path"]):
                    yield child
            else:
                yield self._to_file_info(item)

    async def read_file(self, site_id: str, item_id: str) -> bytes:
        """Download file content."""
        return await self.graph.get_binary(
            f"/sites/{site_id}/drive/items/{item_id}/content"
        )
```

### OneDrive Adapter

```python
class OneDriveAdapter:
    """OneDrive for Business adapter via Microsoft Graph API."""

    async def list_users(self) -> list[User]:
        """List users with OneDrive."""
        response = await self.graph.get("/users?$filter=assignedLicenses/$count gt 0")
        return [User(**u) for u in response["value"]]

    async def list_files(
        self,
        user_id: str,
        path: str = "/",
        recursive: bool = True
    ) -> AsyncIterator[FileInfo]:
        """List files in a user's OneDrive."""
        items = await self.graph.get(
            f"/users/{user_id}/drive/root:/{path}:/children"
        )
        # Similar to SharePoint...
```

---

## Database Schema

### Core Tables

```sql
-- Tenants (for multi-tenancy support)
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    azure_tenant_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    email TEXT NOT NULL,
    name TEXT,
    role TEXT NOT NULL DEFAULT 'viewer',  -- 'admin' | 'viewer'
    azure_oid TEXT,  -- Azure AD object ID
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

-- Scan targets (configured locations to scan)
CREATE TABLE scan_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    name TEXT NOT NULL,
    adapter TEXT NOT NULL,  -- 'filesystem', 'sharepoint', 'onedrive'
    config JSONB NOT NULL,  -- Adapter-specific configuration
    enabled BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Scan schedules
CREATE TABLE scan_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    name TEXT NOT NULL,
    target_id UUID REFERENCES scan_targets(id),
    cron TEXT,  -- Cron expression, NULL = on-demand only
    enabled BOOLEAN DEFAULT true,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Scan jobs (each execution)
CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    schedule_id UUID REFERENCES scan_schedules(id),
    status TEXT NOT NULL DEFAULT 'pending',  -- 'pending', 'running', 'completed', 'failed', 'cancelled'
    progress JSONB,  -- {files_scanned, files_total, current_file}
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    files_scanned INT DEFAULT 0,
    files_with_pii INT DEFAULT 0,
    error TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Scan results (per file)
CREATE TABLE scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    job_id UUID REFERENCES scan_jobs(id),

    -- File identification
    file_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size BIGINT,
    file_modified TIMESTAMPTZ,
    content_hash TEXT,  -- For change detection

    -- Risk scoring
    risk_score INT NOT NULL,  -- 0-100
    risk_tier TEXT NOT NULL,  -- 'MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'

    -- Score breakdown
    content_score FLOAT,
    exposure_multiplier FLOAT,
    co_occurrence_rules TEXT[],

    -- Exposure
    exposure_level TEXT,  -- 'PRIVATE', 'INTERNAL', 'ORG_WIDE', 'PUBLIC'
    owner TEXT,

    -- Entity summary
    entity_counts JSONB NOT NULL,  -- {"SSN": 5, "CREDIT_CARD": 2, ...}
    total_entities INT NOT NULL,

    -- Detailed findings (optional, for drill-down)
    findings JSONB,  -- [{type, value_preview, confidence, positions}, ...]

    -- Labeling status
    current_label_id TEXT,
    current_label_name TEXT,
    recommended_label_id TEXT,
    recommended_label_name TEXT,
    label_applied BOOLEAN DEFAULT false,
    label_applied_at TIMESTAMPTZ,
    label_error TEXT,

    -- Timestamps
    scanned_at TIMESTAMPTZ DEFAULT NOW(),

    -- Indexes
    CONSTRAINT scan_results_unique UNIQUE (job_id, file_path)
);

-- Sensitivity labels (synced from M365)
CREATE TABLE sensitivity_labels (
    id TEXT PRIMARY KEY,  -- MIP label GUID
    tenant_id UUID REFERENCES tenants(id),
    name TEXT NOT NULL,
    description TEXT,
    priority INT,
    color TEXT,
    parent_id TEXT,
    synced_at TIMESTAMPTZ DEFAULT NOW()
);

-- Label mapping rules
CREATE TABLE label_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    rule_type TEXT NOT NULL,  -- 'risk_tier' | 'entity_type'
    match_value TEXT NOT NULL,  -- 'CRITICAL' | 'SSN'
    label_id TEXT REFERENCES sensitivity_labels(id),
    priority INT DEFAULT 0,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit log
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    user_id UUID REFERENCES users(id),
    action TEXT NOT NULL,  -- 'scan_started', 'label_applied', 'config_changed', etc.
    resource_type TEXT,
    resource_id UUID,
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_scan_results_job ON scan_results(job_id);
CREATE INDEX idx_scan_results_risk ON scan_results(risk_tier, risk_score DESC);
CREATE INDEX idx_scan_results_path ON scan_results(file_path);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX idx_scan_jobs_tenant ON scan_jobs(tenant_id);
CREATE INDEX idx_audit_log_tenant ON audit_log(tenant_id, created_at DESC);
```

---

## Authentication & Authorization

### OAuth 2.0 / OIDC with Azure AD

```python
# auth.py
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer
import msal

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize",
    tokenUrl=f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Validate token and return user."""
    claims = validate_token(token)

    user = await get_or_create_user(
        email=claims["preferred_username"],
        azure_oid=claims["oid"],
        name=claims.get("name"),
    )

    return user

def require_admin(user: User = Depends(get_current_user)) -> User:
    """Require admin role."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return user
```

### Azure AD App Registration

Required permissions:

```
Microsoft Graph API (Application):
├── Sites.Read.All           # Read SharePoint sites
├── Files.ReadWrite.All      # Read/write files for labeling
├── InformationProtection.Read.All    # Read available labels
├── User.Read.All            # User enumeration for OneDrive

Azure Rights Management Services:
└── Content.SuperUser        # Apply labels to any file
```

### Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full access: configure targets, schedules, label rules, view all results |
| **Viewer** | View-only: see scan results, dashboards, reports |

---

## GUI Application

### Technology Stack

- **Framework**: PySide6 (Qt for Python)
- **Communication**: REST API + WebSocket for live updates
- **Packaging**: PyInstaller for Windows executable

### Main Screens

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ OpenLabels                                              [🔔 Update] [≡]    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  [Dashboard] [Scans] [Results] [Schedules] [Labels] [Settings]              │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                         (Screen content)                                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Results Heatmap (Tree View)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Risk Heatmap                                          [Expand All] [−]      │
├───────────────────────────────┬─────┬───────┬───────┬─────────────┬────────┤
│ Name                          │ SSN │ EMAIL │ PHONE │ CREDIT_CARD │ Score  │
├───────────────────────────────┼─────┼───────┼───────┼─────────────┼────────┤
│ ▼ 📁 Local                    │ 142 │  234  │  189  │     45      │  12450 │
│   ▼ 📁 finance                │  89 │   45  │   67  │     38      │   8200 │
│     ▼ 📁 payroll              │  45 │   12  │   23  │      8      │   4500 │
│         📄 salaries.xlsx      │  23 │    5  │   12  │      4      │   2800 │
│         📄 bonuses.xlsx       │  22 │    7  │   11  │      4      │   1700 │
│     ▶ 📁 invoices             │  44 │   33  │   44  │     30      │   3700 │
│   ▶ 📁 hr                     │  53 │  189  │  122  │      7      │   4250 │
│ ▶ 📁 SharePoint               │  67 │  456  │  234  │     12      │   8900 │
│ ▶ 📁 OneDrive                 │  23 │  123  │   78  │      5      │   3200 │
└───────────────────────────────┴─────┴───────┴───────┴─────────────┴────────┘
```

### File Detail Context Card

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 📄 payroll_2024.xlsx                                                   [×]  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  RISK SCORE                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  ████████████████████████████████░░░░░░░░░░  78 / 100  HIGH        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  SCORE BREAKDOWN                                                             │
│  ├─ Entity severity (SSN × 23, CREDIT_CARD × 8)      +45                   │
│  ├─ Entity density (31 entities in 2.4MB)            +12                   │
│  ├─ Co-occurrence multiplier (SSN + NAME)            ×1.5                  │
│  └─ Exposure level: ORG_WIDE                         +15                   │
│                                                       ─────                 │
│                                                       = 78                  │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  SENSITIVE INFORMATION TYPES (SITs)                                         │
│  ┌──────────────┬───────┬────────────┬─────────────────────────────┐       │
│  │ Type         │ Count │ Confidence │ Sample                      │       │
│  ├──────────────┼───────┼────────────┼─────────────────────────────┤       │
│  │ SSN          │   23  │ HIGH       │ ***-**-6789                 │       │
│  │ CREDIT_CARD  │    8  │ HIGH       │ ****-****-****-4532         │       │
│  │ NAME         │   45  │ MEDIUM     │ John S***                   │       │
│  │ EMAIL        │   12  │ HIGH       │ j***@company.com            │       │
│  └──────────────┴───────┴────────────┴─────────────────────────────┘       │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  EXPOSURE & ACCESS                                                           │
│  ├─ Exposure Level:     ORG_WIDE ⚠️                                         │
│  ├─ Current Permissions: "All Employees" (1,247 users)                      │
│  ├─ Owner:              jsmith@company.com                                  │
│  └─ Location:           \\fileserver\finance\payroll\                       │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  LABELING                                                                    │
│  ├─ Current Label:      None                                                │
│  ├─ Recommended Label:  🔴 Highly Confidential                              │
│  └─ Reason:             Contains SSN + financial data                       │
│                                                                              │
│  [ Apply Recommended Label ]  [ Choose Different Label ▾ ]                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Scan Progress

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Scan: Nightly Finance Scan                                     [Cancel]     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Progress: ████████████████░░░░░░░░░░░░░░░░  1,247 / 3,456 files (36%)     │
│                                                                              │
│  Current: \\fileserver\finance\payroll\q4_2024\december\bonuses.xlsx       │
│                                                                              │
│  Stats:                                                                      │
│  ├─ Files with PII:   342                                                   │
│  ├─ Critical:         12                                                    │
│  ├─ High:             45                                                    │
│  ├─ Medium:           128                                                   │
│  └─ Elapsed:          00:04:32                                              │
│                                                                              │
│  Log:                                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 10:32:15  Scanning december/bonuses.xlsx                            │   │
│  │ 10:32:14  Found 23 SSN in november/salaries.xlsx (Score: 82)       │   │
│  │ 10:32:12  Scanning november/salaries.xlsx                           │   │
│  │ 10:32:10  Scanning november/invoices.csv                            │   │
│  │ ...                                                                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Deployment Models

### Mode 1: Laptop / Small Team

```
Single Windows Machine
├── OpenLabels Server (Windows Service)
├── PostgreSQL (embedded)
├── Workers (same machine)
└── GUI (connects to localhost)
```

**Use case**: Individual consultant, small team, demo/POC

### Mode 2: On-Prem Windows Server

```
Windows Server
├── OpenLabels Server (Windows Service)
├── PostgreSQL (same or separate server)
└── Workers (same machine, multiple processes)

User Workstations
└── OpenLabels GUI (connects to server)
```

**Use case**: Enterprise on-prem deployment, E3 customer

### Mode 3: Azure Cloud

```
Azure Subscription
├── Container Apps Environment
│   ├── openlabels-api (scales 0-N)
│   └── openlabels-worker (Container App Job)
├── Azure Database for PostgreSQL
└── (Optional) Azure Blob for exports
```

**Use case**: Cloud-forward customers, SaaS offering

---

## Windows Installer

### Package Contents

```
OpenLabels-Setup.exe
├── Python 3.11 runtime (embedded)
├── OpenLabels package (wheels)
├── PostgreSQL 16 (optional embed)
├── .NET 8 Runtime (for MIP SDK)
├── MIP SDK NuGet packages
├── pythonnet wheel
├── Rust extension (.pyd)
├── Windows Service wrapper (NSSM or pywin32)
└── GUI shortcut
```

### Installer Wizard

1. **Welcome** - License agreement
2. **Install Type** - Server only / Server + GUI / GUI only
3. **Database** - Embedded PostgreSQL / Connect to existing
4. **Service Account** - Domain account for file access
5. **Azure AD** - Tenant ID, Client ID, Secret (or skip for local-only)
6. **Port** - Server port (default 8000)
7. **Install** - Progress bar
8. **Finish** - Start service, open GUI

### Service Configuration

```
Service Name: OpenLabels
Display Name: OpenLabels Server
Description: Data classification and auto-labeling service
Startup Type: Automatic
Log On As: .\OpenLabelsService (or domain account)
```

---

## Azure Cloud Deployment

### Bicep Template

```bicep
// infra/main.bicep
param location string = resourceGroup().location
param adminEmail string

resource containerAppEnv 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: 'openlabels-env'
  location: location
  properties: {}
}

resource api 'Microsoft.App/containerApps@2023-05-01' = {
  name: 'openlabels-api'
  location: location
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8000
      }
      secrets: [
        { name: 'db-connection', value: postgres.properties.connectionString }
      ]
    }
    template: {
      containers: [{
        name: 'api'
        image: 'ghcr.io/chillbot-io/openlabels:latest'
        env: [
          { name: 'DATABASE_URL', secretRef: 'db-connection' }
        ]
      }]
      scale: {
        minReplicas: 0
        maxReplicas: 5
      }
    }
  }
}

resource worker 'Microsoft.App/jobs@2023-05-01' = {
  name: 'openlabels-worker'
  location: location
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      triggerType: 'Schedule'
      scheduleTriggerConfig: {
        cronExpression: '*/5 * * * *'  // Check queue every 5 min
      }
      replicaTimeout: 1800
    }
    template: {
      containers: [{
        name: 'worker'
        image: 'ghcr.io/chillbot-io/openlabels:latest'
        command: ['openlabels', 'worker']
      }]
    }
  }
}

resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-03-01-preview' = {
  name: 'openlabels-db'
  location: location
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    version: '16'
    administratorLogin: 'openlabels'
    storage: { storageSizeGB: 32 }
  }
}
```

### Deployment

```bash
az deployment group create \
  --resource-group openlabels-rg \
  --template-file main.bicep \
  --parameters adminEmail=admin@customer.com
```

---

## Configuration

### Configuration File

```yaml
# config.yaml (or environment variables)

server:
  host: 0.0.0.0
  port: 8000
  workers: 4  # API workers (uvicorn)

database:
  url: postgresql://localhost/openlabels
  # Or: sqlite:///openlabels.db (for single-user)

auth:
  provider: azure_ad  # or 'none' for local-only
  tenant_id: "..."
  client_id: "..."
  client_secret: "..."  # Or use AZURE_CLIENT_SECRET env var

adapters:
  filesystem:
    enabled: true
    service_account: "DOMAIN\\OpenLabelsService"

  sharepoint:
    enabled: true
    scan_all_sites: false
    sites:
      - "https://customer.sharepoint.com/sites/Finance"
      - "https://customer.sharepoint.com/sites/HR"

  onedrive:
    enabled: true
    scan_all_users: false
    users:
      - "ceo@customer.com"
      - "cfo@customer.com"

labeling:
  enabled: true
  mode: auto  # 'auto' | 'recommend'

  risk_tier_mapping:
    CRITICAL: "Highly Confidential"
    HIGH: "Confidential"
    MEDIUM: "Internal"

detection:
  confidence_threshold: 0.70
  enable_ml: true
  enable_ocr: true
  max_file_size_mb: 100

logging:
  level: INFO
  file: /var/log/openlabels/server.log
```

---

## CLI Reference

### Server Commands

```bash
# Start server
openlabels serve [--host HOST] [--port PORT] [--workers N]

# Start worker process
openlabels worker [--concurrency N]

# Database migrations
openlabels db upgrade
openlabels db downgrade

# Configuration
openlabels config show
openlabels config set KEY VALUE
```

### Admin Commands

```bash
# User management
openlabels user list
openlabels user create EMAIL --role admin
openlabels user delete EMAIL

# Target management
openlabels target list
openlabels target add NAME --adapter filesystem --path /data
openlabels target remove NAME

# Scan management
openlabels scan start TARGET_NAME
openlabels scan status JOB_ID
openlabels scan cancel JOB_ID

# Label sync
openlabels labels sync  # Sync from M365

# Backup/restore
openlabels backup --output ./backup/
openlabels restore --from ./backup/2024-01-20/

# Export
openlabels export results --job JOB_ID --format csv --output report.csv
```

### GUI Command

```bash
# Launch GUI
openlabels gui [--server URL]
```

---

## API Reference

### Authentication

All API requests require a Bearer token:

```
Authorization: Bearer <access_token>
```

### Endpoints

#### Scans

```
POST   /api/scans                 Create new scan job
GET    /api/scans                 List scan jobs
GET    /api/scans/{id}            Get scan job details
DELETE /api/scans/{id}            Cancel scan job
GET    /api/scans/{id}/progress   Get scan progress (SSE)
WS     /ws/scans/{id}             WebSocket for live updates
```

#### Results

```
GET    /api/results               List results (paginated, filterable)
GET    /api/results/{id}          Get single result
GET    /api/results/export        Export results (CSV, JSON)
GET    /api/results/stats         Aggregated statistics
```

#### Targets

```
GET    /api/targets               List configured targets
POST   /api/targets               Create target
GET    /api/targets/{id}          Get target details
PUT    /api/targets/{id}          Update target
DELETE /api/targets/{id}          Delete target
```

#### Schedules

```
GET    /api/schedules             List schedules
POST   /api/schedules             Create schedule
GET    /api/schedules/{id}        Get schedule details
PUT    /api/schedules/{id}        Update schedule
DELETE /api/schedules/{id}        Delete schedule
POST   /api/schedules/{id}/run    Trigger immediate run
```

#### Labels

```
GET    /api/labels                List sensitivity labels
POST   /api/labels/sync           Sync labels from M365
GET    /api/labels/rules          List label rules
POST   /api/labels/rules          Create label rule
DELETE /api/labels/rules/{id}     Delete label rule
POST   /api/labels/apply          Apply label to file
```

#### Dashboard

```
GET    /api/dashboard/stats       Overall statistics
GET    /api/dashboard/trends      Trends over time
GET    /api/dashboard/heatmap     Heatmap data
```

### Request/Response Examples

#### Create Scan

```http
POST /api/scans
Content-Type: application/json

{
  "target_id": "uuid",
  "name": "Ad-hoc Finance Scan"
}
```

```json
{
  "id": "uuid",
  "status": "pending",
  "created_at": "2024-01-20T10:00:00Z"
}
```

#### Get Results

```http
GET /api/results?job_id=uuid&risk_tier=CRITICAL&limit=100
```

```json
{
  "items": [
    {
      "id": "uuid",
      "file_path": "\\\\server\\share\\file.xlsx",
      "risk_score": 85,
      "risk_tier": "CRITICAL",
      "entity_counts": {"SSN": 23, "CREDIT_CARD": 8},
      "exposure_level": "ORG_WIDE",
      "current_label": null,
      "recommended_label": "Highly Confidential"
    }
  ],
  "total": 1234,
  "page": 1,
  "pages": 13
}
```

---

## Repository Structure

```
openlabels/
├── openrisk/                    # Source package (detection engine)
├── scrubiq/                     # Source package (redaction)
│
├── src/openlabels/              # THE SERVER PRODUCT
│   ├── __init__.py
│   ├── __main__.py              # CLI entry point
│   │
│   ├── server/
│   │   ├── __init__.py
│   │   ├── app.py               # FastAPI application
│   │   ├── config.py            # Configuration management
│   │   ├── db.py                # Database connection
│   │   └── routes/
│   │       ├── __init__.py
│   │       ├── scans.py
│   │       ├── results.py
│   │       ├── targets.py
│   │       ├── schedules.py
│   │       ├── labels.py
│   │       ├── dashboard.py
│   │       └── ws.py            # WebSocket handlers
│   │
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── oauth.py             # Azure AD OAuth
│   │   └── middleware.py
│   │
│   ├── jobs/
│   │   ├── __init__.py
│   │   ├── queue.py             # PostgreSQL job queue
│   │   ├── worker.py            # Worker process
│   │   └── tasks/
│   │       ├── scan.py
│   │       └── label.py
│   │
│   ├── core/                    # Detection engine (from openrisk)
│   │   ├── __init__.py
│   │   ├── detectors/
│   │   ├── pipeline/
│   │   ├── scoring/
│   │   └── _rust/               # Rust extension
│   │
│   ├── labeling/
│   │   ├── __init__.py
│   │   ├── engine.py            # Unified labeling interface
│   │   ├── mip_sdk.py           # MIP SDK integration
│   │   ├── graph_labeler.py     # Graph API labeling
│   │   ├── rules.py             # Label rule engine
│   │   └── sync.py              # Sync labels from M365
│   │
│   ├── adapters/
│   │   ├── __init__.py
│   │   ├── base.py              # Adapter protocol
│   │   ├── filesystem.py        # Local + SMB
│   │   ├── sharepoint.py        # Graph API
│   │   └── onedrive.py          # Graph API
│   │
│   ├── client/
│   │   └── client.py            # Python SDK client
│   │
│   └── gui/                     # PyQt GUI
│       ├── __init__.py
│       ├── main.py
│       ├── main_window.py
│       ├── style.py
│       ├── widgets/
│       │   ├── dashboard.py     # Heatmap tree view
│       │   ├── file_detail.py   # Context card
│       │   ├── scan_progress.py
│       │   ├── targets.py
│       │   ├── schedules.py
│       │   └── labels.py
│       └── workers/
│           ├── api_client.py
│           └── scan_worker.py
│
├── docs/
│   ├── openlabels-server-architecture-v1.md   # This document
│   └── openlabels-server-spec-v1.md           # Specification
│
├── infra/
│   ├── main.bicep               # Azure deployment
│   └── docker-compose.yml       # Local development
│
├── packaging/
│   ├── installer.iss            # Inno Setup script
│   ├── build-windows.ps1
│   └── icon.ico
│
├── tests/
│   └── ...
│
├── pyproject.toml
└── README.md
```

---

## Implementation Roadmap

### Phase 1: Core Server (MVP)

- [ ] FastAPI server skeleton
- [ ] PostgreSQL database schema
- [ ] Basic auth (Azure AD)
- [ ] Filesystem adapter
- [ ] Detection engine integration (from openrisk)
- [ ] Basic GUI (scan + results)

### Phase 2: Cloud Adapters

- [ ] SharePoint adapter
- [ ] OneDrive adapter
- [ ] Graph API client

### Phase 3: MIP Labeling

- [ ] MIP SDK integration (.NET)
- [ ] Graph API labeling
- [ ] Label rule engine
- [ ] Label sync from M365

### Phase 4: GUI Enhancements

- [ ] Heatmap tree view
- [ ] File detail context card
- [ ] Scan progress with log stream
- [ ] Label configuration screens

### Phase 5: Scheduling & Jobs

- [ ] PostgreSQL job queue
- [ ] Worker pool
- [ ] Cron scheduling
- [ ] Job management API

### Phase 6: Deployment

- [ ] Windows installer (Inno Setup)
- [ ] Windows Service integration
- [ ] Azure Bicep templates
- [ ] Documentation

### Phase 7: Polish

- [ ] Update checker
- [ ] Backup/restore
- [ ] Reporting/export
- [ ] Performance optimization

---

*This document is the authoritative architecture reference for OpenLabels Server v1. All implementation should align with this specification.*
