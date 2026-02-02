# OpenLabels Architecture v3.0

**The Universal Data Risk Scoring Standard**

This document is the ground truth for OpenLabels architecture. It captures the complete design including detection, scoring, remediation, and monitoring capabilities.

**Version:** 3.0
**Last Updated:** February 2026
**Status:** Active Development

---

## Table of Contents

1. [Vision & Identity](#vision--identity)
2. [Core Value Proposition](#core-value-proposition)
3. [System Architecture](#system-architecture)
4. [Detection Engine](#detection-engine)
5. [ML Models & OCR](#ml-models--ocr)
6. [Scoring Engine](#scoring-engine)
7. [Remediation Actions](#remediation-actions)
8. [Targeted Monitoring](#targeted-monitoring)
9. [Adapters](#adapters)
10. [CLI & Query Language](#cli--query-language)
11. [Repository Structure](#repository-structure)
12. [Implementation Status](#implementation-status)

---

## Vision & Identity

### What OpenLabels Is

OpenLabels is a **universal risk scoring standard** that combines:
- **Content sensitivity** (what data is present)
- **Exposure context** (how it's stored and who can access it)

Into a single **portable 0-100 risk score** that works across any platform.

### What OpenLabels Is NOT

- **Not just a scanner** — it's a scoring framework with remediation capabilities
- **Not just another label** — it quantifies risk by combining content sensitivity with exposure context

### The Core Insight

```
Traditional DLP tells you WHAT's in your data.
OpenLabels tells you HOW RISKY that data actually is, given WHERE it lives.
```

An SSN in a private, encrypted bucket ≠ an SSN in a public, unencrypted bucket.

Same content, different risk. Only OpenLabels captures this.

---

## Core Value Proposition

| Need | Solution |
|------|----------|
| Cross-platform comparison | Same score formula everywhere |
| Content + Context risk | Only OpenLabels combines both |
| Want portability | Works anywhere (on-prem, SharePoint, OneDrive) |
| **Sensitive file found** | **Quarantine, lock down permissions, or monitor access** |
| **MIP label integration** | **Apply Microsoft sensitivity labels based on risk** |

---

## System Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              INPUT LAYER                                    │
└─────────────────────────────────────────────────────────────────────────────┘
        │                                                    │
        ▼                                                    ▼
┌─────────────────┐                               ┌─────────────────────┐
│  Cloud Storage  │                               │   Local / On-Prem   │
│  + Vendor DLP   │                               │   File Systems      │
└────────┬────────┘                               └──────────┬──────────┘
         │                                                   │
         ▼                                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ADAPTERS                                       │
│                     (all produce normalized entities + context)             │
│                                                                             │
│  ┌─────────────────────────────────────────────┐  ┌─────────────────────┐  │
│  │              STORAGE ADAPTERS               │  │      SCANNER        │  │
│  │   (enumerate files + read metadata)         │  │  (analyze content)  │  │
│  │                                             │  │                     │  │
│  │  ┌─────────────┐ ┌─────────────────────┐   │  │ • Patterns          │  │
│  │  │ Filesystem  │ │  SharePoint/OneDrive │   │  │ • Checksums         │  │
│  │  │  (NTFS/NFS) │ │   (Graph API)        │   │  │ • ML detection      │  │
│  │  └─────────────┘ └─────────────────────┘   │  │ • OCR (RapidOCR)    │  │
│  │                                             │  │ • Archives          │  │
│  │  • File enumeration                         │  │                     │  │
│  │  • Content reading                          │  │                     │  │
│  │  • ACL/permission extraction                │  │                     │  │
│  └─────────────────────┬───────────────────────┘  └──────────┬──────────┘  │
│                        │                                      │             │
│                        └──────────────────┬───────────────────┘             │
│                                    │                                        │
│                                    ▼                                        │
│                        ┌─────────────────────┐                             │
│                        │  Normalized Format  │                             │
│                        │  • Entities[]       │                             │
│                        │  • Context{}        │                             │
│                        └──────────┬──────────┘                             │
└───────────────────────────────────┼─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              OPENLABELS CORE                                │
│                                                                             │
│    ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐        │
│    │   Merger     │───►│    Scorer    │───►│   Output Generator   │        │
│    │              │    │              │    │                      │        │
│    │ • Union      │    │ • Content    │    │ • Score 0-100        │        │
│    │ • Dedupe     │    │ • Exposure   │    │ • Risk level         │        │
│    │ • Max conf   │    │ • Combined   │    │ • Entity summary     │        │
│    └──────────────┘    └──────────────┘    └──────────────────────┘        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         REMEDIATION & MONITORING                            │
│                                                                             │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐        │
│   │  Quarantine  │    │  Permission  │    │  Targeted Monitoring │        │
│   │              │    │  Lockdown    │    │                      │        │
│   │ • robocopy   │    │              │    │ • SACL registration  │        │
│   │ • Preserve   │    │ • icacls     │    │ • Audit log query    │        │
│   │   ACLs       │    │ • Local      │    │ • "Who accessed?"    │        │
│   │ • Audit      │    │   Admin only │    │                      │        │
│   └──────────────┘    └──────────────┘    └──────────────────────┘        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Detection Engine

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SCANNER (Content Classification)                         │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Content Input                                     │   │
│  │    (bytes, file path, or pre-extracted text)                        │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│                                 ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    File Type Detection                               │   │
│  │                                                                      │   │
│  │    Archive? → Expand                                                 │   │
│  │    Image (.png, .jpg, .tiff)? → OCR                                 │   │
│  │    Scanned PDF? → OCR fallback                                      │   │
│  │    Text/Office? → Direct extraction                                 │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│                                 ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Detector Orchestrator                             │   │
│  │    (parallel execution via ThreadPoolExecutor)                       │   │
│  │                                                                      │   │
│  │    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │   │
│  │    │   Checksum   │  │   Patterns   │  │   Secrets    │             │   │
│  │    │  Detector    │  │  Detector    │  │  Detector    │             │   │
│  │    │              │  │              │  │              │             │   │
│  │    │ • SSN        │  │ • Names      │  │ • API Keys   │             │   │
│  │    │ • Credit Card│  │ • Dates      │  │ • Tokens     │             │   │
│  │    │ • NPI        │  │ • Addresses  │  │ • Passwords  │             │   │
│  │    │ • IBAN       │  │ • Phones     │  │ • Private    │             │   │
│  │    │ • VIN        │  │ • Emails     │  │   Keys       │             │   │
│  │    │ • DEA        │  │ • MRN        │  │              │             │   │
│  │    └──────────────┘  └──────────────┘  └──────────────┘             │   │
│  │                                                                      │   │
│  │    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │   │
│  │    │  Financial   │  │  Government  │  │  ML (ONNX)   │             │   │
│  │    │  Detector    │  │  Detector    │  │  Detectors   │             │   │
│  │    │              │  │              │  │              │             │   │
│  │    │ • CUSIP      │  │ • Classif.   │  │ • PHI-BERT   │             │   │
│  │    │ • ISIN       │  │ • CAGE codes │  │ • PII-BERT   │             │   │
│  │    │ • SWIFT      │  │ • Contracts  │  │ • FastCoref  │             │   │
│  │    │ • Crypto     │  │              │  │              │             │   │
│  │    └──────────────┘  └──────────────┘  └──────────────┘             │   │
│  │                                                                      │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│                                 ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Tiered Pipeline                                   │   │
│  │    (intelligent escalation based on content and confidence)         │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│                                 ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Context Enhancer                                  │   │
│  │    (deny lists, hotwords, pattern exclusions)                       │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│                                 ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Entity Resolver                                   │   │
│  │    (merge identical values, resolve coreferences)                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Supported File Types

| Category | Extensions | Extraction Method |
|----------|------------|-------------------|
| Plain Text | .txt, .log, .md, .csv, .json, .xml, .yaml | Direct decode |
| Office | .docx, .xlsx, .pptx | python-docx, openpyxl |
| PDF | .pdf | pdfplumber/PyMuPDF + OCR fallback |
| Images | .png, .jpg, .jpeg, .tiff, .bmp, .gif, .webp | RapidOCR |
| Archives | .zip, .tar, .gz | Recursive expansion |

### Tiered Detection Pipeline

The tiered pipeline optimizes detection by avoiding unnecessary ML processing:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TIERED DETECTION PIPELINE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  STAGE 1: FAST TRIAGE (always runs)                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  • Checksum detectors (SSN, CC, NPI, IBAN, VIN)                     │   │
│  │  • Secrets detector (API keys, tokens, passwords)                    │   │
│  │  • Financial detector (CUSIP, ISIN, crypto)                         │   │
│  │  • Government detector (classifications, CAGE codes)                │   │
│  │  • Pattern detector (names, dates, phones, emails)                  │   │
│  │  • Hyperscan acceleration (optional, 10-100x faster)                │   │
│  └────────────────────────────────┬────────────────────────────────────┘   │
│                                   │                                         │
│                                   ▼                                         │
│                    ┌──────────────────────────┐                             │
│                    │    ESCALATION CHECK      │                             │
│                    │  • confidence < 0.7?     │                             │
│                    │  • medical context?      │                             │
│                    │  • ML-beneficial type?   │                             │
│                    └─────────┬────────────────┘                             │
│                              │                                              │
│              ┌───────────────┴───────────────┐                              │
│              │ No                         Yes │                              │
│              ▼                               ▼                              │
│      ┌───────────┐            ┌─────────────────────────────────────┐      │
│      │   DONE    │            │  STAGE 2: ML ESCALATION             │      │
│      │ (Stage 1  │            │  • Medical? → PHI-BERT + PII-BERT   │      │
│      │  results) │            │  • Non-medical? → PII-BERT only     │      │
│      └───────────┘            │  • Coreference (disabled by default)│      │
│                               └─────────────────────────────────────┘      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Features:**
- **Escalation threshold**: 0.7 confidence (configurable)
- **Medical context detection**: Uses dictionaries to identify clinical content
- **Dual BERT for medical**: PHI-BERT alone misses standard PII in clinical docs
- **OCR optimization**: Quick text check before full OCR pipeline

**Usage:**

```python
from openlabels.core.pipeline import TieredPipeline, create_pipeline

# Create pipeline with medical context auto-detection
pipeline = create_pipeline(auto_detect_medical=True)

# Detect PII/PHI
result = pipeline.detect(text)
print(f"Stages executed: {result.stages_executed}")
print(f"Medical context: {result.medical_context_detected}")
print(f"Entities: {result.result.entity_counts}")

# For images with OCR optimization
result = pipeline.detect_image("document.png")
```

### Medical Dictionaries

The `dictionaries/` module provides 380,000+ medical and clinical terms for context detection:

| Dictionary | Terms | Source |
|------------|-------|--------|
| diagnoses.txt | 97,444 | ICD-10-CM |
| drugs.txt | 53,607 | FDA NDC |
| facilities.txt | 65,642 | CMS Providers |
| lab_tests.txt | 157,595 | LOINC |
| professions.txt | 253 | Healthcare roles |
| clinical_workflow.txt | 258 | High-signal terms |
| us_cities.txt | 2,820 | US Census |
| us_counties.txt | 1,786 | US Census |
| us_states.txt | 58 | US states/territories |
| payers.txt | 78 | Insurance companies |
| clinical_stopwords.txt | 62 | False positive filters |

**Dictionary Loader:**

```python
from openlabels.dictionaries import get_dictionary_loader

loader = get_dictionary_loader()

# Check if term exists
if loader.contains("drugs", "metformin"):
    print("Found drug")

# Detect medical context (used by tiered pipeline)
if loader.has_medical_context("Patient diagnosed with diabetes"):
    print("Medical context detected - escalate to PHI+PII analysis")

# Get detailed medical indicators
indicators = loader.get_medical_indicators(text)
# {'workflow': {'discharge summary', 'diagnosis'}, 'professions': set(), ...}
```

---

## ML Models & OCR

### Model Directory Structure

All ML models are stored in `~/.openlabels/models/`:

```
~/.openlabels/models/
├── fastcoref/
│   ├── fastcoref.onnx           (~50 MB) - Coreference resolution
│   ├── fastcoref.tokenizer.json
│   ├── fastcoref_tokenizer/
│   └── fastcoref.config.json
│
├── phi-bert/                    (~100 MB) - PHI detection (int8 quantized)
│   ├── model.onnx
│   ├── tokenizer.json
│   └── config.json
│
├── pii-bert/                    (~100 MB) - PII detection (int8 quantized)
│   ├── model.onnx
│   ├── tokenizer.json
│   └── config.json
│
└── rapidocr/                    (~17 MB total) - Text extraction from images
    ├── det.onnx                 (~4.5 MB) - Text region detection
    ├── rec.onnx                 (~11 MB)  - Text recognition
    └── cls.onnx                 (~1.5 MB) - Orientation classification
```

### RapidOCR Integration

RapidOCR is PaddleOCR's models pre-converted to ONNX, running on onnxruntime. This aligns with OpenLabels' all-ONNX inference stack.

**Features:**
- Lazy loading (models load on first use)
- Background pre-warming (reduces first-call latency)
- Custom model path support (defaults to `~/.openlabels/models/rapidocr/`)
- Fallback to bundled models if custom ones aren't present
- Text-to-coordinate mapping for visual redaction

**OCR Module API:**

```python
from openlabels.core.ocr import OCREngine, OCRResult

# Initialize (uses default models dir)
engine = OCREngine()

# Simple text extraction
text = engine.extract_text(image_path)

# Text with confidence
text, confidence = engine.extract_text_with_confidence(image_array)

# Full result with bounding boxes (for redaction)
result: OCRResult = engine.extract_with_coordinates(image_path)
for span in phi_spans:
    blocks = result.get_blocks_for_span(span.start, span.end)
    # blocks contain bounding box coordinates for visual redaction
```

**Scanned PDF Handling:**

When native PDF text extraction yields minimal text (< 20 chars), the processor automatically:
1. Renders each page to an image at 150 DPI
2. Runs OCR on each rendered page
3. Concatenates results with page breaks

---

## Scoring Engine

### The Formula

```python
WEIGHT_SCALE = 4.0
content_score = Σ(weight × WEIGHT_SCALE × (1 + ln(count)) × confidence)
content_score *= co_occurrence_multiplier
exposure_multiplier = f(context)
final_score = min(100, content_score × exposure_multiplier)
```

### Risk Tiers

| Score Range | Tier | Description |
|-------------|------|-------------|
| 80-100 | CRITICAL | Immediate action required |
| 55-79 | HIGH | High priority remediation |
| 31-54 | MEDIUM | Review and assess |
| 11-30 | LOW | Monitor |
| 0-10 | MINIMAL | No action needed |

### Exposure Multipliers

| Exposure Level | Multiplier |
|----------------|------------|
| PRIVATE | 1.0× |
| INTERNAL | 1.2× |
| ORG_WIDE | 1.8× |
| PUBLIC | 2.5× |

### Co-occurrence Rules

| Rule | Condition | Multiplier |
|------|-----------|------------|
| HIPAA PHI | Direct ID + Health Data | 2.0× |
| Identity Theft | Direct ID + Financial | 1.8× |
| Credential Exposure | Any credential type | 1.5× |
| Classified Data | Classification marking | 2.5× |

---

## Remediation Actions

OpenLabels provides three remediation actions for sensitive files:

### 1. Quarantine (Data Migration)

Move sensitive files to a secure quarantine location while preserving metadata.

**Implementation:** Uses adapter-based file operations:
- `shutil.move` with directory creation
- ACL preservation via `win32security` (Windows) or stat/chown (Linux)
- Full audit trail in database
- Rollback support

```python
from openlabels.remediation import quarantine

result = quarantine(
    source="/data/sensitive/ssn_list.xlsx",
    destination="/quarantine/2026-02/",
    preserve_acls=True,
)
# File moved, original location logged, ACLs preserved
```

**CLI (single file):**
```bash
openlabels quarantine ./sensitive.xlsx ./quarantine/
```

**CLI (batch with filter):**
```bash
openlabels quarantine --where "score > 75" --scan-path /data -r /quarantine/ --dry-run
```

### 2. Permission Lockdown (ACL Reduction)

Restrict file access to a minimal set of principals (default: Local Administrators only).

**Implementation:**
- Windows: `win32security` API for DACL manipulation
- Linux: `os.chmod` / `os.chown` for POSIX permissions
- Original ACL saved for rollback

```python
from openlabels.remediation import lock_down

result = lock_down(
    path="/data/sensitive/ssn_list.xlsx",
    allowed_principals=["BUILTIN\\Administrators"],
    remove_inheritance=True,
    backup_acl=True,  # Save original for rollback
)
# All existing ACEs removed, only Administrators can access
```

**CLI (single file):**
```bash
openlabels lock-down ./sensitive.xlsx --principals "Administrators"
```

**CLI (batch with filter):**
```bash
openlabels lock-down --where "has(SSN) AND tier = CRITICAL" --scan-path /hr -r --dry-run
```

### 3. Targeted Monitoring

Track who accesses flagged sensitive files without full-scope monitoring.

**Implementation (Windows):**
1. Add SACL (System ACL) to flagged files for auditing
2. Windows logs all access to Security Event Log (Event IDs 4663, 4656)
3. Query audit log on-demand: "Who accessed this file in the last 30 days?"

```python
from openlabels.monitoring import enable_monitoring, get_access_history

# When scan flags HIGH/CRITICAL file
enable_monitoring(
    path="/data/sensitive/ssn_list.xlsx",
    audit_read=True,
    audit_write=True,
)

# Later: check who accessed
history = get_access_history(
    path="/data/sensitive/ssn_list.xlsx",
    days=30,
)
for event in history:
    print(f"{event.user} - {event.action} - {event.timestamp}")
```

**Dashboard View:**
```
┌─────────────────────────────────────────────────────────────┐
│  📄 HR/employees_ssn.xlsx                                   │
│  ├── Risk: CRITICAL (SSN, DOB detected)                     │
│  ├── Last Scanned: 2 hours ago                              │
│  ├── Access History: ⚠️ 3 users in last 7 days              │
│  │   └── jsmith (Jan 31, 2:14 PM) - Read                    │
│  │   └── mjohnson (Jan 30, 9:02 AM) - Read                  │
│  │   └── SYSTEM (Jan 29, 3:00 AM) - Backup                  │
│  │                                                          │
│  └── Actions: [🔒 Lock Down] [📦 Quarantine] [👁️ Details]   │
└─────────────────────────────────────────────────────────────┘
```

---

## Targeted Monitoring

### Architecture (Option B: SACL + Audit Log Query)

Unlike Varonis which monitors everything, OpenLabels monitors only what you've flagged:

```
┌─────────────────────────────────────────────────────────────┐
│              OPENLABELS TARGETED MONITORING                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Phase 1: SCAN                                              │
│    • Detect sensitive data                                  │
│    • Score risk                                             │
│    • Flag HIGH/CRITICAL files                               │
│                                                             │
│  Phase 2: REGISTER FOR MONITORING                           │
│    • Add SACL to flagged files (Windows audit rules)        │
│    • Store in watch_list table                              │
│    • Windows automatically logs all access                  │
│                                                             │
│  Phase 3: ON-DEMAND QUERY                                   │
│    • User asks "Who accessed this file?"                    │
│    • Query Security Event Log (4663, 4656)                  │
│    • Display access timeline                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Why This Approach?

| Approach | Pros | Cons |
|----------|------|------|
| Full monitoring (Varonis) | Complete visibility | Massive event volume, complex infrastructure |
| **Targeted monitoring** | Low volume, simple, answers the question | Only monitors flagged files |

**Key insight:** You don't need to monitor everything. Monitor only the files you've already identified as sensitive. This is 1% of the volume with 80% of the value.

### Database Schema

```sql
-- Files registered for monitoring
CREATE TABLE watch_list (
    path          TEXT PRIMARY KEY,
    risk_tier     TEXT NOT NULL,        -- 'CRITICAL', 'HIGH', etc.
    added_at      TIMESTAMP NOT NULL,
    last_event_at TIMESTAMP,
    sacl_enabled  BOOLEAN DEFAULT FALSE
);

-- Access events (populated on-demand from Windows audit log)
CREATE TABLE access_events (
    id            SERIAL PRIMARY KEY,
    path          TEXT NOT NULL,
    timestamp     TIMESTAMP NOT NULL,
    user_sid      TEXT NOT NULL,
    user_name     TEXT,
    action        TEXT NOT NULL,        -- 'read', 'write', 'delete'
    process_name  TEXT
);
```

### Windows Event IDs

| Event ID | Description |
|----------|-------------|
| 4663 | An attempt was made to access an object |
| 4656 | A handle to an object was requested |
| 4660 | An object was deleted |
| 4658 | The handle to an object was closed |

---

## Adapters

### Implemented Adapters

| Adapter | Source | Capabilities |
|---------|--------|--------------|
| FilesystemAdapter | Local filesystem | File enumeration, content reading, ACL get/set, file move, remediation support |
| SharePointAdapter | SharePoint Online | Site enumeration, file listing, content download via Graph API |
| OneDriveAdapter | OneDrive | User drive enumeration, file operations via Graph API |

### Adapter Protocol

All adapters implement the base protocol with remediation support:

```python
from openlabels.adapters.base import Adapter, FileInfo

class Adapter(Protocol):
    # Core operations
    async def list_files(self, path: str, recursive: bool = False) -> AsyncIterator[FileInfo]
    async def read_file(self, file_info: FileInfo) -> bytes
    async def get_metadata(self, file_info: FileInfo) -> dict

    # Remediation operations (optional)
    async def move_file(self, file_info: FileInfo, dest_path: str) -> bool
    async def get_acl(self, file_info: FileInfo) -> Optional[dict]
    async def set_acl(self, file_info: FileInfo, acl: dict) -> bool
    def supports_remediation(self) -> bool
```

### FilesystemAdapter Remediation

The FilesystemAdapter provides full remediation support:

```python
from openlabels.adapters.filesystem import FilesystemAdapter

adapter = FilesystemAdapter()

# Move file (quarantine)
success = await adapter.move_file(file_info, "/quarantine/")

# Get current ACL
acl = await adapter.get_acl(file_info)
# Windows: Returns serialized DACL via win32security
# Linux: Returns {"mode": 0o644, "uid": 1000, "gid": 1000}

# Set restrictive ACL (lockdown)
await adapter.set_acl(file_info, restricted_acl)

# Lockdown with original ACL backup
success, original_acl = await adapter.lockdown_file(file_info, allowed_sids=["S-1-5-32-544"])
```

---

## CLI & Query Language

### Commands

```bash
# Server and GUI
openlabels serve [--host HOST] [--port PORT] [--workers N]
openlabels gui [--server URL]
openlabels worker [--concurrency N]

# Local classification (no server required)
openlabels classify <path> [-r] [--enable-ml] [--output results.json]

# Find with filters
openlabels find <path> --where "<filter>" [-r] [--format table|json|csv|paths]

# Remediation actions (single file or batch with --where)
openlabels quarantine <source> <dest>
openlabels quarantine --where "<filter>" --scan-path <path> -r <dest>
openlabels lock-down <file>
openlabels lock-down --where "<filter>" --scan-path <path> -r [--principals admin]

# Monitoring commands
openlabels monitor enable <file> [--risk-tier HIGH]
openlabels monitor disable <file>
openlabels monitor list [--json]
openlabels monitor history <file> [--days 30]
openlabels monitor status <file>

# Reporting
openlabels report <path> [-r] [--where "<filter>"] [--format text|json|csv|html] [-o report.html]
openlabels heatmap <path> [-r] [--depth 2] [--format text|json]

# System status
openlabels status

# Label management
openlabels labels list
openlabels labels sync
openlabels labels apply <file> --label "Confidential"
openlabels labels remove <file>
openlabels labels info <file>

# Target and scan management
openlabels target list
openlabels target add <name> --adapter filesystem --path /data
openlabels scan start <target_name>
openlabels scan status <job_id>
openlabels scan cancel <job_id>

# Configuration
openlabels config show
openlabels config set <key> <value>
openlabels db upgrade
```

### Filter Grammar

The filter grammar supports logical expressions for querying scan results:

```
filter      = or_expr
or_expr     = and_expr (OR and_expr)*
and_expr    = condition (AND condition)*
condition   = comparison | function_call | "(" filter ")" | NOT condition
comparison  = field operator value
field       = identifier (score, tier, path, exposure, owner, etc.)
operator    = "=" | "!=" | ">" | "<" | ">=" | "<=" | "~" (regex) | "contains"
value       = string | number | identifier
function_call = "has(" entity_type ")" | "missing(" field ")" | "count(" entity_type ")" operator value
```

**Supported Fields:**
- `score` / `risk_score` - Risk score (0-100)
- `tier` / `risk_tier` - Risk tier (CRITICAL, HIGH, MEDIUM, LOW, MINIMAL)
- `path` / `file_path` - File path
- `name` / `file_name` - File name
- `exposure` / `exposure_level` - Exposure level (PRIVATE, INTERNAL, ORG_WIDE, PUBLIC)
- `owner` - File owner
- `entities` / `total_entities` - Total entity count

**Functions:**
- `has(SSN)` - True if entity type exists with count > 0
- `missing(owner)` - True if field is null or empty
- `count(SSN) >= 10` - Compare entity type count

### Examples

```bash
# Find high-risk files
openlabels find ./data -r --where "score > 75"

# Find files with SSNs at critical tier
openlabels find . -r --where "has(SSN) AND tier = CRITICAL"

# Find Excel files with credit cards
openlabels find ./docs -r --where "path ~ '.*\\.xlsx$' AND has(CREDIT_CARD)"

# Find files with 10+ SSNs
openlabels find ./hr -r --where "count(SSN) >= 10"

# Quarantine high-risk public data
openlabels quarantine --where "score > 75 AND exposure = PUBLIC" \
  --scan-path /data -r /quarantine/

# Lock down all files with SSNs
openlabels lock-down --where "has(SSN)" --scan-path /hr -r --principals "HR_Admins"

# Generate HTML report for critical files
openlabels report ./data -r --where "tier = CRITICAL" --format html -o report.html

# Generate risk heatmap
openlabels heatmap ./data -r --depth 3

# Check access history
openlabels monitor history ./sensitive.xlsx --days 30
```

---

## Repository Structure

```
openlabels/
├── pyproject.toml
├── README.md
├── LICENSE                          # Apache 2.0
│
├── docs/
│   ├── openlabels-architecture-v3.md    # This document
│   ├── openlabels-spec-v2.md
│   └── openlabels-entity-registry.md
│
├── src/openlabels/
│   ├── __init__.py
│   ├── __main__.py                  # CLI entry point ✓
│   │
│   ├── cli/                         # CLI utilities ✓
│   │   ├── __init__.py
│   │   ├── filter_parser.py         # Filter grammar parser ✓
│   │   └── filter_executor.py       # Filter evaluation ✓
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── types.py                 # Span, Entity, RiskTier
│   │   ├── constants.py             # Weights, timeouts, model paths
│   │   ├── processor.py             # FileProcessor (entry point)
│   │   ├── ocr.py                   # RapidOCR integration ✓
│   │   │
│   │   ├── detectors/
│   │   │   ├── orchestrator.py      # Parallel detector execution
│   │   │   ├── checksum.py          # SSN, CC, NPI, IBAN, VIN ✓
│   │   │   ├── financial.py         # CUSIP, ISIN, crypto ✓
│   │   │   ├── government.py        # Classifications ✓
│   │   │   ├── secrets.py           # API keys, tokens ✓
│   │   │   └── ml_onnx.py           # BERT detectors
│   │   │
│   │   ├── pipeline/
│   │   │   ├── __init__.py          # Pipeline exports
│   │   │   ├── tiered.py            # Tiered detection pipeline ✓
│   │   │   ├── context_enhancer.py  # False positive filtering ✓
│   │   │   ├── entity_resolver.py   # Merge identical values ✓
│   │   │   ├── span_validation.py   # Span boundary validation ✓
│   │   │   └── coref.py             # Coreference resolution
│   │   │
│   │   └── scoring/
│   │       └── scorer.py            # Risk scoring engine ✓
│   │
│   ├── dictionaries/                # Medical/clinical term dictionaries ✓
│   │   ├── __init__.py              # DictionaryLoader class
│   │   ├── diagnoses.txt            # 97K ICD-10-CM diagnoses
│   │   ├── drugs.txt                # 54K FDA NDC drugs
│   │   ├── facilities.txt           # 66K CMS providers
│   │   ├── lab_tests.txt            # 158K LOINC lab tests
│   │   ├── professions.txt          # Healthcare roles
│   │   ├── clinical_workflow.txt    # High-signal medical terms
│   │   └── ...                      # Additional location dictionaries
│   │
│   ├── remediation/                 # Remediation actions ✓
│   │   ├── __init__.py              # quarantine, lock_down exports
│   │   ├── quarantine.py            # File migration
│   │   └── permissions.py           # ACL lockdown
│   │
│   ├── monitoring/                  # Access monitoring ✓
│   │   ├── __init__.py              # enable_monitoring, get_access_history exports
│   │   ├── base.py                  # Types and models
│   │   ├── registry.py              # Watch list management
│   │   └── history.py               # Audit log queries (Windows/Linux)
│   │
│   ├── labeling/                    # MIP SDK integration ✓
│   │   ├── __init__.py
│   │   ├── engine.py                # LabelingEngine
│   │   └── mip.py                   # MIP SDK wrapper (Windows)
│   │
│   ├── adapters/                    # Storage adapters ✓
│   │   ├── base.py                  # Protocol + FileInfo
│   │   ├── filesystem.py            # Local filesystem with remediation ✓
│   │   ├── onedrive.py              # OneDrive via Graph API
│   │   └── sharepoint.py            # SharePoint via Graph API
│   │
│   ├── server/                      # FastAPI server ✓
│   │   ├── app.py                   # Application factory
│   │   ├── config.py                # Settings
│   │   ├── db.py                    # Database session
│   │   ├── models.py                # SQLAlchemy models (full schema)
│   │   └── routes/
│   │       ├── __init__.py
│   │       ├── auth.py              # Authentication
│   │       ├── scans.py             # Scan management
│   │       ├── results.py           # Scan results
│   │       ├── dashboard.py         # Dashboard endpoints ✓
│   │       ├── remediation.py       # Remediation endpoints ✓
│   │       └── health.py            # Health/status endpoint ✓
│   │
│   ├── gui/                         # PyQt6 GUI ✓
│   │   ├── main.py                  # Application entry
│   │   ├── main_window.py           # Main window with tabs
│   │   └── widgets/
│   │       ├── dashboard_widget.py  # Dashboard tab ✓
│   │       ├── settings_widget.py   # Settings tab ✓
│   │       ├── monitoring_widget.py # Monitoring tab ✓
│   │       ├── health_widget.py     # Health tab ✓
│   │       └── charts/
│   │           ├── heat_map_chart.py      # Access heatmap ✓
│   │           └── sensitive_data_chart.py # Entity trends ✓
│   │
│   └── jobs/                        # Background jobs
│       └── worker.py                # Job worker
│
├── tests/
│   ├── core/
│   │   ├── test_checksum.py         # 42 tests ✓
│   │   ├── test_financial.py        # ✓
│   │   ├── test_government.py       # ✓
│   │   ├── test_secrets.py          # ✓
│   │   ├── test_scorer.py           # 51 tests ✓
│   │   ├── test_types.py            # 28 tests ✓
│   │   └── test_ocr.py              # 39 tests ✓
│   │
│   └── pipeline/
│       ├── test_context_enhancer.py # 60+ tests ✓
│       ├── test_entity_resolver.py  # 25 tests ✓
│       └── test_span_validation.py  # 25 tests ✓
│
└── ~/.openlabels/models/            # ML models directory (user home)
    ├── phi-bert/
    ├── pii-bert/
    ├── fastcoref/
    └── rapidocr/
```

---

## Implementation Status

### Completed ✓

| Component | Status | Tests |
|-----------|--------|-------|
| Core types (Span, RiskTier, Entity) | ✓ | 28 |
| Checksum detectors (SSN, CC, NPI, IBAN) | ✓ | 42 |
| Financial detectors (CUSIP, ISIN) | ✓ | Yes |
| Government detectors | ✓ | Yes |
| Secrets detectors | ✓ | Yes |
| Context enhancer | ✓ | 60+ |
| Entity resolver | ✓ | 25 |
| Span validation | ✓ | 25 |
| Risk scorer | ✓ | 51 |
| OCR (RapidOCR) | ✓ | 39 |
| Tiered Pipeline | ✓ | - |
| Medical Dictionaries | ✓ | - |
| **CLI with filter grammar** | ✓ | - |
| **GUI (Dashboard, Settings, Monitoring, Health, Charts)** | ✓ | - |
| **Server routes (health, dashboard, remediation)** | ✓ | - |
| **Remediation (quarantine, lock-down)** | ✓ | - |
| **Monitoring (enable, disable, history)** | ✓ | - |
| **Adapters (filesystem with remediation)** | ✓ | - |
| **Total** | | **754+ tests** |

### In Progress

| Component | Status | Priority |
|-----------|--------|----------|
| ML detectors (PHI-BERT, PII-BERT) | Scaffolded | Medium |
| Coreference resolution (FastCoref) | Scaffolded | Low |

### Test Coverage

| Module | Coverage |
|--------|----------|
| scorer.py | 97% |
| entity_resolver.py | 95% |
| government.py | 96% |
| secrets.py | 92% |
| span_validation.py | 91% |
| context_enhancer.py | 52% |
| **Overall** | **~32%** |

---

## Appendix: Constants

### Model Paths

```python
from pathlib import Path

DEFAULT_MODELS_DIR = Path.home() / ".openlabels" / "models"

# Expected model files:
# - {DEFAULT_MODELS_DIR}/fastcoref/fastcoref.onnx
# - {DEFAULT_MODELS_DIR}/phi-bert/model.onnx
# - {DEFAULT_MODELS_DIR}/pii-bert/model.onnx
# - {DEFAULT_MODELS_DIR}/rapidocr/det.onnx
# - {DEFAULT_MODELS_DIR}/rapidocr/rec.onnx
# - {DEFAULT_MODELS_DIR}/rapidocr/cls.onnx
```

### Timeouts

```python
MODEL_LOAD_TIMEOUT = 60.0   # seconds - loading ML models
OCR_READY_TIMEOUT = 30.0    # seconds - OCR engine readiness
DETECTOR_TIMEOUT = 120.0    # seconds - detector execution
```

---

*This document is the authoritative architecture reference for OpenLabels v3. All implementation should align with this specification.*
