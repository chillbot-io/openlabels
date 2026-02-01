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
- **Not a replacement for Macie/DLP/Purview** — it consumes their output and normalizes to a universal score
- **Not just another label** — it quantifies risk by combining content sensitivity with exposure context

### The Core Insight

```
Macie tells you WHAT's in your data.
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
| Already have Macie/DLP | Use **Labeler** → normalize existing findings |
| No DLP capabilities | Use **Scanner** → analyze content directly |
| Want portability | Scanner works anywhere (on-prem, any cloud) |
| **Sensitive file found** | **Quarantine, lock down permissions, or monitor access** |

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
│  │              LABELER ADAPTERS               │  │      SCANNER        │  │
│  │   (read metadata + existing labels)         │  │  (analyze content)  │  │
│  │                                             │  │                     │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐       │  │ • Patterns          │  │
│  │  │  Macie  │ │ GCP DLP │ │ Purview │       │  │ • Checksums         │  │
│  │  │ +S3 meta│ │+GCS meta│ │+Blob    │       │  │ • ML detection      │  │
│  │  └─────────┘ └─────────┘ └─────────┘       │  │ • OCR (RapidOCR)    │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐       │  │ • Archives          │  │
│  │  │  NTFS   │ │   NFS   │ │  M365   │       │  │                     │  │
│  │  │  ACLs   │ │ exports │ │ perms   │       │  │                     │  │
│  │  └─────────┘ └─────────┘ └─────────┘       │  │                     │  │
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

**Implementation:** Uses `robocopy` on Windows for:
- ACL preservation
- Resumable transfers
- Retry logic on network errors
- Full audit trail

```python
from openlabels.remediation import quarantine

result = quarantine(
    source="/data/sensitive/ssn_list.xlsx",
    destination="/quarantine/2026-02/",
    preserve_acls=True,
    create_audit_log=True,
)
# File moved, original location logged, ACLs preserved
```

**CLI:**
```bash
openlabels quarantine /data/sensitive --where "score > 75" --to /quarantine/
```

### 2. Permission Lockdown (ACL Reduction)

Restrict file access to a minimal set of principals (default: Local Administrators only).

**Implementation:**
- Windows: `icacls` / `Set-Acl` PowerShell
- Linux: `setfacl` / `chmod`

```python
from openlabels.remediation import lock_down

result = lock_down(
    path="/data/sensitive/ssn_list.xlsx",
    allowed_principals=["BUILTIN\\Administrators"],
    remove_inheritance=True,
)
# All existing ACEs removed, only Administrators can access
```

**CLI:**
```bash
openlabels lock-down /data/sensitive --where "score > 80" --allow "Administrators"
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

### Labeler Adapters

Read metadata and existing classifications from external sources:

| Adapter | Source | What It Reads |
|---------|--------|---------------|
| MacieAdapter | AWS | Macie findings + S3 bucket/object metadata |
| DLPAdapter | GCP | DLP findings + GCS metadata |
| PurviewAdapter | Azure | Purview classifications + Blob metadata |
| NTFSAdapter | Windows | ACLs, permissions, EFS encryption status |
| NFSAdapter | Linux | POSIX permissions, exports |
| M365Adapter | Microsoft | SharePoint/OneDrive permissions |

### Scanner Adapter

Analyzes content directly using patterns, checksums, ML, and OCR:

```python
class ScannerAdapter:
    def __init__(
        self,
        enable_ocr: bool = True,
        enable_ml: bool = False,
        ml_model_dir: Path = None,
    ):
        self.orchestrator = DetectorOrchestrator(enable_ml=enable_ml)
        self.ocr_engine = OCREngine(models_dir=ml_model_dir) if enable_ocr else None
```

---

## CLI & Query Language

### Commands

```bash
# Scan and score
openlabels scan <path>
openlabels scan s3://bucket/prefix
openlabels scan /mnt/fileshare --recursive

# Find with filters
openlabels find <path> --where "<filter>"

# Remediation actions
openlabels quarantine <path> --where "<filter>" --to <dest>
openlabels lock-down <path> --where "<filter>" --allow "Administrators"
openlabels monitor <path> --where "<filter>"

# Monitoring queries
openlabels access-history <path> --days 30
openlabels who-accessed <path>

# Reporting
openlabels report <path> --format json|csv|html
openlabels heatmap <path>
```

### Filter Grammar

```
<filter>     := <condition> (AND|OR <condition>)*
<condition>  := <field> <operator> <value>
             | has(<entity_type>)
             | missing(<field>)

<field>      := score | exposure | encryption | last_accessed
             | last_modified | size | entity_count | source

<operator>   := = | != | > | < | >= | <= | contains | matches

<value>      := <number> | <duration> | <enum> | <string>
<duration>   := <number>(d|w|m|y)  # days, weeks, months, years
```

### Examples

```bash
# Quarantine high-risk public data
openlabels quarantine /data \
  --where "score > 75 AND exposure = public" \
  --to /quarantine/

# Lock down all files with SSNs
openlabels lock-down /hr \
  --where "has(SSN)" \
  --allow "HR_Admins"

# See who accessed sensitive files in last week
openlabels access-history /data/sensitive --days 7

# Complex query
openlabels find . --where "
  score > 75
  AND exposure >= org_wide
  AND last_accessed > 1y
  AND (has(SSN) OR has(CREDIT_CARD))
  AND encryption = none
"
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
│   │   │   ├── context_enhancer.py  # False positive filtering ✓
│   │   │   ├── entity_resolver.py   # Merge identical values ✓
│   │   │   ├── span_validation.py   # Span boundary validation ✓
│   │   │   └── coref.py             # Coreference resolution
│   │   │
│   │   └── scoring/
│   │       └── scorer.py            # Risk scoring engine ✓
│   │
│   ├── remediation/                 # NEW
│   │   ├── __init__.py
│   │   ├── quarantine.py            # robocopy-based file migration
│   │   ├── permissions.py           # ACL lockdown (icacls/setfacl)
│   │   └── monitoring.py            # SACL management + audit queries
│   │
│   ├── adapters/
│   │   ├── base.py
│   │   ├── filesystem.py
│   │   ├── onedrive.py
│   │   └── sharepoint.py
│   │
│   ├── server/
│   │   ├── app.py                   # FastAPI application
│   │   ├── models.py                # SQLAlchemy models
│   │   └── routes/
│   │
│   └── gui/
│       ├── main_window.py           # PyQt6 main window
│       └── widgets/
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
└── data/
    └── models/                      # Downloaded models go here
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
| **OCR (RapidOCR)** | ✓ | 39 |
| **Total** | | **384 tests passing** |

### In Progress

| Component | Status | Priority |
|-----------|--------|----------|
| Remediation: Quarantine | Planned | High |
| Remediation: Permission Lockdown | Planned | High |
| Remediation: Targeted Monitoring | Planned | High |
| ML detectors (PHI-BERT, PII-BERT) | Scaffolded | Medium |
| Coreference resolution (FastCoref) | Scaffolded | Medium |

### Test Coverage

| Module | Coverage |
|--------|----------|
| scorer.py | 97% |
| entity_resolver.py | 95% |
| government.py | 96% |
| secrets.py | 92% |
| span_validation.py | 91% |
| context_enhancer.py | 52% |
| **Overall** | **18%** (GUI/server untested) |

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
