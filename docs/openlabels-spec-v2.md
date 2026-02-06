# OpenLabels Specification v2.0

**Version:** 2.0.0-draft
**Status:** Draft
**Document ID:** OL-SPEC-002
**Last Updated:** February 2026

---

## Abstract

This document defines OpenLabels, a data sensitivity detection and risk scoring system with integrated remediation and monitoring capabilities. OpenLabels enables detection and classification of sensitive data across platforms, with the ability to apply Microsoft Information Protection (MIP) labels and take action on high-risk findings.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Data Model](#3-data-model)
4. [Serialization](#4-serialization)
5. [Storage](#5-storage)
6. [Index](#6-index)
7. [Algorithms](#7-algorithms)
8. [Remediation](#8-remediation)
9. [Monitoring](#9-monitoring)
10. [OCR Specification](#10-ocr-specification)
11. [Conformance](#11-conformance)
12. [Security Considerations](#12-security-considerations)
13. [Appendix A: JSON Schema](#appendix-a-json-schema)
14. [Appendix B: Entity Type Registry](#appendix-b-entity-type-registry)
15. [Appendix C: Examples](#appendix-c-examples)

---

## 1. Introduction

### 1.1 Purpose

OpenLabels defines a system for detecting sensitive data within files and data streams, scoring risk, and taking remediation actions. The system is designed to be:

- **Comprehensive**: Detects 50+ PII/PHI entity types with multi-stage detection
- **Actionable**: Remediation and monitoring capabilities built-in
- **Integrated**: Applies Microsoft Information Protection (MIP) labels based on risk
- **Extensible**: New entity types can be registered

### 1.2 Design Principles

```
DETECTION IS THE FOUNDATION. RISK IS DERIVED. ACTION IS OPTIONAL.
```

OpenLabels separates three concerns:

1. **Detection**: Identify what sensitive data is present in files
2. **Risk**: Computed from detected entities plus exposure context
3. **Action**: Remediation, monitoring, and MIP labeling based on risk

### 1.3 What's New in v2.0

| Feature | Description |
|---------|-------------|
| **Remediation Actions** | Quarantine, permission lockdown specifications |
| **Targeted Monitoring** | SACL-based access monitoring for flagged files |
| **OCR Specification** | RapidOCR integration for images and scanned PDFs |
| **ML Model Paths** | Standardized model directory structure |
| **Tiered Detection** | Multi-stage pipeline with intelligent ML escalation |
| **Medical Dictionaries** | 380K+ terms for clinical context detection |

---

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

| Term | Definition |
|------|------------|
| **Label** | A single detected entity with type, confidence, detector, and hash |
| **Label Set** | A collection of labels for a single file or data unit |
| **labelID** | Immutable identifier assigned to a file when first labeled |
| **Content Hash** | SHA-256 hash of file content, changes when file is modified |
| **Quarantine** | Moving a file to a secure location while preserving metadata |
| **Permission Lockdown** | Restricting file access to a minimal set of principals |
| **Targeted Monitoring** | Tracking access to specific flagged files |
| **SACL** | System Access Control List (Windows audit rules) |
| **OCR** | Optical Character Recognition for image/scanned text extraction |

---

## 3. Data Model

### 3.1 labelID

The labelID is the immutable anchor for all label data associated with a file.

#### 3.1.1 Format

```
labelID = "ol_" + random_hex(12)
```

Example: `ol_7f3a9b2c4d5e`

#### 3.1.2 Properties

- MUST be assigned when a file is first labeled
- MUST NOT change for the lifetime of the labeled file
- MUST be unique within a tenant
- SHOULD be globally unique (collision probability negligible with 48 bits)

### 3.2 Content Hash

The content hash tracks file versions.

```
content_hash = sha256(file_content)[:12]
```

Example: `e3b0c44298fc`

### 3.3 Label Set

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `v` | integer | REQUIRED | Specification version. MUST be `2` for this version. |
| `id` | string | REQUIRED | The labelID. Format: `ol_` + 12 hex chars. |
| `hash` | string | REQUIRED | Content hash. 12 lowercase hex characters. |
| `labels` | array | REQUIRED | Array of Label objects. MAY be empty. |
| `src` | string | REQUIRED | Source identifier. Format: `generator:version`. |
| `ts` | integer | REQUIRED | Unix timestamp when labels were generated. |
| `risk` | object | OPTIONAL | Risk assessment (score, tier, exposure). |
| `remediation` | object | OPTIONAL | Remediation status. |
| `monitoring` | object | OPTIONAL | Monitoring status. |
| `x` | object | OPTIONAL | Extension data. |

### 3.4 Label

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `t` | string | REQUIRED | Entity type (registered or `x-` prefixed). |
| `c` | number | REQUIRED | Confidence score [0.0, 1.0]. |
| `d` | string | REQUIRED | Detector type: `checksum`, `pattern`, `ml`, `structured`, `ocr`. |
| `h` | string | REQUIRED | Value hash (6 hex characters). |
| `n` | integer | OPTIONAL | Occurrence count (default: 1). |
| `x` | object | OPTIONAL | Extension data. |

### 3.5 Risk Assessment

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `score` | integer | REQUIRED | Risk score [0, 100]. |
| `tier` | string | REQUIRED | Risk tier: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `MINIMAL`. |
| `exposure` | string | OPTIONAL | Exposure level: `PRIVATE`, `INTERNAL`, `ORG_WIDE`, `PUBLIC`. |
| `multiplier` | number | OPTIONAL | Applied exposure multiplier. |

### 3.6 Remediation Status

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | REQUIRED | Action taken: `quarantine`, `lockdown`, `none`. |
| `at` | integer | OPTIONAL | Unix timestamp when action was taken. |
| `by` | string | OPTIONAL | User or system that took action. |
| `dest` | string | OPTIONAL | Destination path (for quarantine). |
| `principals` | array | OPTIONAL | Allowed principals (for lockdown). |

### 3.7 Monitoring Status

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | boolean | REQUIRED | Whether monitoring is enabled. |
| `since` | integer | OPTIONAL | Unix timestamp when monitoring started. |
| `last_access` | object | OPTIONAL | Most recent access event. |
| `access_count` | integer | OPTIONAL | Total access count since monitoring started. |

---

## 4. Serialization

### 4.1 JSON Format

Label Sets MUST be serialized as JSON conforming to [RFC 8259](https://tools.ietf.org/html/rfc8259).

- JSON text MUST be encoded as UTF-8
- Writers MUST NOT include a byte order mark (BOM)
- Writers SHOULD use compact serialization (no unnecessary whitespace)

### 4.2 Field Order

Field order is not significant. Readers MUST accept fields in any order.

### 4.3 Unknown Fields

Readers MUST ignore unrecognized fields without error. This enables forward compatibility.

---

## 5. Storage

### 5.1 Database Storage

All scan results and label data are stored in the PostgreSQL database. The `scan_results` table contains detection findings, risk scores, and entity counts for each scanned file.

### 5.2 MIP Label Integration

For Microsoft 365 environments, OpenLabels integrates with Microsoft Information Protection (MIP) to apply sensitivity labels based on detection results and risk scores.

| Platform | Label Method |
|----------|--------------|
| SharePoint/OneDrive | Microsoft Graph API |
| Local files (Windows) | MIP SDK via pythonnet |

---

## 6. Index

### 6.1 Schema

```sql
-- Core label records
CREATE TABLE label_objects (
    label_id      TEXT PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    created_at    TIMESTAMP NOT NULL
);

-- Version history
CREATE TABLE label_versions (
    label_id      TEXT NOT NULL REFERENCES label_objects(label_id),
    content_hash  TEXT NOT NULL,
    scanned_at    TIMESTAMP NOT NULL,
    labels        JSONB NOT NULL,
    risk_score    INTEGER,
    risk_tier     TEXT,
    exposure      TEXT,
    source        TEXT NOT NULL,

    PRIMARY KEY (label_id, content_hash)
);

-- Watch list for monitoring
CREATE TABLE watch_list (
    path          TEXT PRIMARY KEY,
    label_id      TEXT REFERENCES label_objects(label_id),
    risk_tier     TEXT NOT NULL,
    added_at      TIMESTAMP NOT NULL,
    last_event_at TIMESTAMP,
    sacl_enabled  BOOLEAN DEFAULT FALSE
);

-- Access events (populated on-demand)
CREATE TABLE access_events (
    id            SERIAL PRIMARY KEY,
    path          TEXT NOT NULL,
    timestamp     TIMESTAMP NOT NULL,
    user_sid      TEXT NOT NULL,
    user_name     TEXT,
    action        TEXT NOT NULL,
    process_name  TEXT
);

-- Remediation audit log
CREATE TABLE remediation_log (
    id            SERIAL PRIMARY KEY,
    label_id      TEXT NOT NULL,
    action        TEXT NOT NULL,
    source_path   TEXT NOT NULL,
    dest_path     TEXT,
    principals    TEXT[],
    performed_at  TIMESTAMP NOT NULL,
    performed_by  TEXT NOT NULL,
    success       BOOLEAN NOT NULL,
    error_message TEXT
);
```

---

## 7. Algorithms

### 7.1 Risk Scoring

```
WEIGHT_SCALE = 4.0
content_score = Σ(weight × WEIGHT_SCALE × (1 + ln(count)) × confidence)
content_score *= co_occurrence_multiplier
exposure_multiplier = f(exposure_level)
final_score = min(100, content_score × exposure_multiplier)
```

### 7.2 Score to Tier Mapping

| Score Range | Tier |
|-------------|------|
| 80-100 | CRITICAL |
| 55-79 | HIGH |
| 31-54 | MEDIUM |
| 11-30 | LOW |
| 0-10 | MINIMAL |

### 7.3 Exposure Multipliers

| Exposure | Multiplier |
|----------|------------|
| PRIVATE | 1.0 |
| INTERNAL | 1.2 |
| ORG_WIDE | 1.8 |
| PUBLIC | 2.5 |

### 7.4 Tiered Detection Pipeline

To optimize performance, implementations SHOULD use a tiered detection approach:

#### 7.4.1 Stage 1: Fast Triage (Required)

All content MUST pass through Stage 1 detectors:
- Checksum-validated patterns (SSN, credit cards, NPI, IBAN)
- Secret/credential patterns (API keys, tokens)
- Financial patterns (CUSIP, ISIN, crypto addresses)
- Government markings (classifications, CAGE codes)
- General regex patterns (names, dates, phones, emails)

#### 7.4.2 Stage 2: ML Escalation (Conditional)

ML detectors SHOULD only run when:
- Any Stage 1 span has confidence < 0.7 (escalation threshold)
- Medical context is detected in content
- Entity types that benefit from ML refinement are present

#### 7.4.3 Stage 3: Deep Analysis (Medical Context)

When medical context is detected:
- MUST run both PHI-BERT and PII-BERT
- PHI-BERT alone misses standard PII in clinical documents
- Dual analysis catches both clinical entities and general PII

#### 7.4.4 Medical Context Detection

Medical context SHOULD be detected using dictionary-based keyword matching:

| Dictionary | Purpose | Example Terms |
|------------|---------|---------------|
| diagnoses | ICD-10-CM codes | diabetes, hypertension, carcinoma |
| drugs | FDA NDC medications | metformin, lisinopril, atorvastatin |
| clinical_workflow | High-signal terms | discharge summary, prognosis, intubation |
| professions | Healthcare roles | physician, nurse practitioner |

Implementations SHOULD provide at least 50,000 medical terms for reliable context detection.

#### 7.4.5 OCR Optimization

For image files, implementations SHOULD:
1. Perform quick text detection check before full OCR
2. Skip OCR pipeline if no text regions detected
3. Use lazy model loading to reduce startup time

---

## 8. Remediation

### 8.1 Quarantine

Quarantine moves sensitive files to a secure location while preserving metadata.

#### 8.1.1 Requirements

- MUST preserve file ACLs (Windows) or permissions (Linux)
- MUST support resumable transfers for large files
- MUST create audit log entry
- MUST update Label Set with remediation status
- MAY use platform-native tools or standard libraries

#### 8.1.2 Reference Implementation

The OpenLabels reference implementation uses adapter-based file operations:

```python
from openlabels.remediation import quarantine

result = quarantine(
    source=Path("/data/sensitive/ssn_list.xlsx"),
    destination=Path("/quarantine/"),
    preserve_acls=True,
)
```

**Windows:** Uses `shutil.move` with `win32security` for ACL preservation
**Linux:** Uses `shutil.move` with `os.chmod`/`os.chown` for permission preservation

#### 8.1.3 Alternative: Platform-Native Tools

For production deployments requiring advanced features (resumable transfers, retry logic):

**Windows:**
```bash
robocopy <source_dir> <dest_dir> <filename> /COPY:DATSOU /MOVE /R:3 /W:5 /LOG+:quarantine.log
```

**Linux:**
```bash
rsync -avX --remove-source-files <source> <dest>
```

#### 8.1.4 Quarantine Record

```json
{
  "remediation": {
    "action": "quarantine",
    "at": 1706745600,
    "by": "admin@example.com",
    "dest": "/quarantine/2026-02/ssn_list.xlsx",
    "source": "/data/hr/ssn_list.xlsx"
  }
}
```

### 8.2 Permission Lockdown

Permission lockdown restricts file access to a minimal set of principals.

#### 8.2.1 Requirements

- MUST remove all existing discretionary ACEs
- MUST add only specified principals with specified permissions
- MUST optionally remove inheritance
- MUST create audit log entry
- MUST update Label Set with remediation status
- SHOULD save original ACL for rollback support

#### 8.2.2 Reference Implementation

The OpenLabels reference implementation uses direct API calls:

```python
from openlabels.remediation import lock_down

result = lock_down(
    path=Path("/data/sensitive/ssn_list.xlsx"),
    allowed_principals=["BUILTIN\\Administrators"],
    remove_inheritance=True,
    backup_acl=True,  # Save original for rollback
)
```

**Windows:** Uses `win32security` API for DACL manipulation
**Linux:** Uses `os.chmod(path, 0o600)` and `os.chown` for ownership

#### 8.2.3 Alternative: Windows Command Line

```powershell
# Remove all existing permissions
icacls <path> /reset

# Remove inheritance, copy inherited to explicit
icacls <path> /inheritance:d

# Grant only to Administrators
icacls <path> /grant:r "BUILTIN\Administrators:(OI)(CI)F"

# Remove all others
icacls <path> /remove "Everyone" /remove "Users" /remove "Authenticated Users"
```

Or via PowerShell:
```powershell
$acl = Get-Acl <path>
$acl.SetAccessRuleProtection($true, $false)  # Disable inheritance
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators", "FullControl", "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl <path> $acl
```

#### 8.2.4 Alternative: Linux Command Line

```bash
# Remove all ACLs
setfacl -b <path>

# Set owner-only permissions
chmod 600 <path>

# Optionally add specific group
setfacl -m g:admins:rw <path>
```

#### 8.2.4 Lockdown Record

```json
{
  "remediation": {
    "action": "lockdown",
    "at": 1706745600,
    "by": "admin@example.com",
    "principals": ["BUILTIN\\Administrators"],
    "previous_acl": "base64-encoded-previous-acl"
  }
}
```

---

## 9. Monitoring

### 9.1 Targeted Monitoring Model

OpenLabels implements targeted monitoring: only files flagged as sensitive are monitored.

```
Scan → Flag HIGH/CRITICAL → Register for Monitoring → Query Access History
```

This approach:
- Reduces event volume by ~99% compared to full monitoring
- Leverages platform-native auditing (Windows Security Event Log)
- Provides on-demand access history without continuous event processing

### 9.2 SACL Management (Windows)

#### 9.2.1 Enabling Monitoring

When a file is flagged for monitoring:

1. Add SACL entry for "Everyone" auditing reads and writes
2. Record in watch_list table
3. Windows automatically logs access to Security Event Log

```powershell
# Add audit rule for reads and writes
$acl = Get-Acl <path>
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "Read,Write",
    "Success,Failure"
)
$acl.AddAuditRule($rule)
Set-Acl <path> $acl
```

#### 9.2.2 Prerequisites

Windows Object Access Auditing must be enabled:

```powershell
# Enable via local policy
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

Or via Group Policy:
```
Computer Configuration → Windows Settings → Security Settings →
Advanced Audit Policy Configuration → Object Access → Audit File System → Success, Failure
```

### 9.3 Access History Query

#### 9.3.1 Windows Event IDs

| Event ID | Description |
|----------|-------------|
| 4663 | An attempt was made to access an object |
| 4656 | A handle to an object was requested |
| 4660 | An object was deleted |

#### 9.3.2 Query Example

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4663, 4656
    StartTime = (Get-Date).AddDays(-30)
} | Where-Object {
    $_.Properties[6].Value -like "*ssn_list.xlsx*"
} | Select-Object TimeCreated,
    @{N='User';E={$_.Properties[1].Value}},
    @{N='Object';E={$_.Properties[6].Value}},
    @{N='Access';E={$_.Properties[8].Value}}
```

#### 9.3.3 Monitoring Record

```json
{
  "monitoring": {
    "enabled": true,
    "since": 1706745600,
    "last_access": {
      "at": 1706832000,
      "user": "jsmith@example.com",
      "action": "read"
    },
    "access_count": 5
  }
}
```

### 9.4 Linux Auditing (auditd)

For Linux systems, use auditd rules:

```bash
# Add audit rule for specific file
auditctl -w /data/sensitive/ssn_list.csv -p rwa -k openlabels

# Query audit log
ausearch -k openlabels -ts recent
```

---

## 10. OCR Specification

### 10.1 Overview

OpenLabels uses RapidOCR (PaddleOCR models converted to ONNX) for text extraction from:
- Image files (.png, .jpg, .jpeg, .tiff, .bmp, .gif, .webp)
- Scanned PDFs (when native text extraction yields < 20 characters)

### 10.2 Model Requirements

Models MUST be stored in `{MODELS_DIR}/rapidocr/`:

| File | Size | Purpose |
|------|------|---------|
| `det.onnx` | ~4.5 MB | Text region detection |
| `rec.onnx` | ~11 MB | Text recognition |
| `cls.onnx` | ~1.5 MB | Orientation classification |

Default MODELS_DIR: `~/.openlabels/models/`

### 10.3 OCR Result Format

```python
@dataclass
class OCRBlock:
    text: str                    # Extracted text
    bbox: List[List[float]]      # [[x1,y1], [x2,y2], [x3,y3], [x4,y4]]
    confidence: float            # Detection confidence

@dataclass
class OCRResult:
    full_text: str               # All text joined with proper spacing
    blocks: List[OCRBlock]       # Individual text blocks with coordinates
    offset_map: List[Tuple[int, int, int]]  # (start, end, block_idx)
    confidence: float            # Average confidence
```

### 10.4 Text Cleaning

OCR output SHOULD be cleaned to fix common artifacts:

```python
def clean_ocr_text(text: str) -> str:
    # Fix stuck field codes: "15SEX" → "15 SEX"
    text = re.sub(r'(\d[a-z]?)([A-Z]{2,})', r'\1 \2', text)

    # Add space after colon: "DOB:01/01" → "DOB: 01/01"
    text = re.sub(r':([A-Za-z0-9])', r': \1', text)

    return text
```

### 10.5 Scanned PDF Handling

For PDFs where native text extraction yields minimal text:

1. Render each page to image at 150 DPI
2. Run OCR on rendered image
3. Concatenate page results with double newlines
4. Apply text cleaning

---

## 11. Conformance

### 11.1 Conformance Levels

| Level | Requirements |
|-------|--------------|
| **Reader** | Read label data from PostgreSQL database and query MIP label status |
| **Writer** | Store label data in PostgreSQL database, apply MIP labels, maintain index |
| **Remediator** | Writer + quarantine and lockdown capabilities |
| **Monitor** | Remediator + access monitoring capabilities |
| **Full** | All of the above |

### 11.2 Reader Requirements

A conforming Reader MUST:
1. Parse any valid Label Set JSON (v1 or v2)
2. Query scan results from the database index
3. Ignore unknown fields without error

### 11.3 Writer Requirements

A conforming Writer MUST:
1. Produce JSON conforming to this specification
2. Set `v` field to `2`
3. Generate labelID per Section 3.1
4. Compute content_hash per Section 7
5. Store scan results in the database index

### 11.4 Remediator Requirements

A conforming Remediator MUST:
1. Meet all Writer requirements
2. Implement quarantine with ACL preservation
3. Implement permission lockdown
4. Create audit log entries for all remediation actions
5. Update Label Set with remediation status

### 11.5 Monitor Requirements

A conforming Monitor MUST:
1. Meet all Remediator requirements
2. Manage SACLs (Windows) or audit rules (Linux) for flagged files
3. Query access history from platform audit logs
4. Update monitoring status in Label Set

---

## 12. Security Considerations

### 12.1 Value Hash Privacy

The value hash provides correlation, not secrecy. High-value targets can be brute-forced.

### 12.2 Remediation Security

- Quarantine destinations MUST have appropriate access controls
- Permission lockdown MUST be logged for audit purposes
- Remediation actions SHOULD require appropriate authorization

### 12.3 Monitoring Security

- SACL management requires administrator privileges
- Access history queries may expose user behavior patterns
- Audit logs SHOULD be protected from tampering

### 12.4 OCR Security

- OCR models run locally (no cloud API calls)
- Temporary image files SHOULD be securely deleted
- Memory SHOULD be cleared after processing sensitive images

---

## Appendix A: JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://openlabels.dev/schema/v2/labelset.json",
  "title": "OpenLabels Label Set v2",
  "type": "object",
  "required": ["v", "id", "hash", "labels", "src", "ts"],
  "properties": {
    "v": {
      "type": "integer",
      "const": 2
    },
    "id": {
      "type": "string",
      "pattern": "^ol_[a-f0-9]{12}$"
    },
    "hash": {
      "type": "string",
      "pattern": "^[a-f0-9]{12}$"
    },
    "labels": {
      "type": "array",
      "items": { "$ref": "#/$defs/label" }
    },
    "src": {
      "type": "string",
      "pattern": "^[a-z0-9_-]+:[0-9a-z.-]+$"
    },
    "ts": {
      "type": "integer",
      "minimum": 0
    },
    "risk": { "$ref": "#/$defs/risk" },
    "remediation": { "$ref": "#/$defs/remediation" },
    "monitoring": { "$ref": "#/$defs/monitoring" },
    "x": { "type": "object" }
  },
  "$defs": {
    "label": {
      "type": "object",
      "required": ["t", "c", "d", "h"],
      "properties": {
        "t": { "type": "string", "minLength": 1 },
        "c": { "type": "number", "minimum": 0, "maximum": 1 },
        "d": { "type": "string", "enum": ["checksum", "pattern", "ml", "structured", "ocr"] },
        "h": { "type": "string", "pattern": "^[a-f0-9]{6}$" },
        "n": { "type": "integer", "minimum": 1 },
        "x": { "type": "object" }
      }
    },
    "risk": {
      "type": "object",
      "required": ["score", "tier"],
      "properties": {
        "score": { "type": "integer", "minimum": 0, "maximum": 100 },
        "tier": { "type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"] },
        "exposure": { "type": "string", "enum": ["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"] },
        "multiplier": { "type": "number", "minimum": 1 }
      }
    },
    "remediation": {
      "type": "object",
      "required": ["action"],
      "properties": {
        "action": { "type": "string", "enum": ["quarantine", "lockdown", "none"] },
        "at": { "type": "integer" },
        "by": { "type": "string" },
        "dest": { "type": "string" },
        "principals": { "type": "array", "items": { "type": "string" } }
      }
    },
    "monitoring": {
      "type": "object",
      "required": ["enabled"],
      "properties": {
        "enabled": { "type": "boolean" },
        "since": { "type": "integer" },
        "last_access": {
          "type": "object",
          "properties": {
            "at": { "type": "integer" },
            "user": { "type": "string" },
            "action": { "type": "string" }
          }
        },
        "access_count": { "type": "integer" }
      }
    }
  }
}
```

---

## Appendix B: Entity Type Registry

See [openlabels-entity-registry.md](./openlabels-entity-registry.md) for the full registry of 300+ entity types.

Core categories:

| Category | Examples |
|----------|----------|
| direct_id | SSN, PASSPORT, DRIVER_LICENSE |
| financial | CREDIT_CARD, BANK_ACCOUNT, IBAN |
| contact | EMAIL, PHONE, ADDRESS |
| health | MRN, NPI, DIAGNOSIS |
| credential | API_KEY, PASSWORD, PRIVATE_KEY |

---

## Appendix C: Examples

### C.1 Complete Label Set with Risk and Remediation

```json
{
  "v": 2,
  "id": "ol_7f3a9b2c4d5e",
  "hash": "e3b0c44298fc",
  "labels": [
    {"t": "SSN", "c": 0.99, "d": "checksum", "h": "15e2b0", "n": 12},
    {"t": "NAME", "c": 0.92, "d": "pattern", "h": "ef61a5", "n": 12},
    {"t": "DATE_DOB", "c": 0.88, "d": "pattern", "h": "7c4a8d", "n": 12}
  ],
  "src": "openlabels:3.0.0",
  "ts": 1706745600,
  "risk": {
    "score": 87,
    "tier": "CRITICAL",
    "exposure": "ORG_WIDE",
    "multiplier": 1.8
  },
  "remediation": {
    "action": "lockdown",
    "at": 1706746000,
    "by": "security@example.com",
    "principals": ["BUILTIN\\Administrators", "HR_Admins"]
  },
  "monitoring": {
    "enabled": true,
    "since": 1706746000,
    "last_access": {
      "at": 1706832000,
      "user": "jsmith@example.com",
      "action": "read"
    },
    "access_count": 3
  }
}
```

### C.2 OCR-Extracted Label

```json
{
  "v": 2,
  "id": "ol_abc123def456",
  "hash": "f1e2d3c4b5a6",
  "labels": [
    {"t": "SSN", "c": 0.95, "d": "ocr", "h": "ab12cd", "n": 1},
    {"t": "NAME", "c": 0.85, "d": "ocr", "h": "de34fg", "n": 1}
  ],
  "src": "openlabels:3.0.0",
  "ts": 1706745600,
  "risk": {
    "score": 72,
    "tier": "HIGH"
  },
  "x": {
    "ocr_confidence": 0.91,
    "ocr_model": "rapidocr:1.3.0"
  }
}
```

### C.3 Quarantine Record

```json
{
  "v": 2,
  "id": "ol_7f3a9b2c4d5e",
  "hash": "e3b0c44298fc",
  "labels": [
    {"t": "SSN", "c": 0.99, "d": "checksum", "h": "15e2b0", "n": 50}
  ],
  "src": "openlabels:3.0.0",
  "ts": 1706745600,
  "risk": {
    "score": 92,
    "tier": "CRITICAL",
    "exposure": "PUBLIC"
  },
  "remediation": {
    "action": "quarantine",
    "at": 1706746000,
    "by": "incident-response@example.com",
    "dest": "/quarantine/incident-2026-02-01/customer_ssns.xlsx",
    "source": "/public_share/reports/customer_ssns.xlsx"
  }
}
```

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0-draft | 2026-01 | Initial draft |
| 2.0.0-draft | 2026-02 | Added remediation, monitoring, OCR specifications |

---

## Appendix D: Implementation Notes

This section documents the current state of the OpenLabels reference implementation relative to this specification.

### D.1 Label Storage (Sections 4-5)

Labels live in exactly two places:

1. **MIP labels** applied to files via Microsoft Graph API (SharePoint/OneDrive) or MIP SDK (local Windows files). These are the sensitivity labels that travel with the file.
2. **PostgreSQL database** (`scan_results` table) for detection results, risk scores, entity counts, and audit history.

OpenLabels does not write labels into file metadata (XMP, OOXML custom properties, extended attributes, etc.). Sensitivity classification is expressed through MIP labels; all scan and tracking data is stored in the database.

### D.2 Database Schema (Section 6)

**Spec:** Defines `label_objects`, `label_versions`, `watch_list`, `access_events`, `remediation_log` tables.

**Current Implementation:** Uses a more comprehensive schema with:
- `scan_results` - Per-file scan results with risk scoring
- `file_inventory` - Sensitive file tracking for delta scans
- `folder_inventory` - Folder-level inventory
- `remediation_actions` - Remediation audit trail
- `monitored_files` - Watch list for access monitoring
- `file_access_events` - Access event storage

See `src/openlabels/server/models.py` for the full schema.

### D.3 CLI Filter Grammar

**Spec:** Not specified in this document.

**Current Implementation:** Full filter grammar support:
```
filter      = or_expr
or_expr     = and_expr (OR and_expr)*
and_expr    = condition (AND condition)*
condition   = comparison | function_call | "(" filter ")" | NOT condition
comparison  = field operator value
function_call = has(entity) | missing(field) | count(entity) operator value
```

Example: `openlabels find ./data -r --where "score > 75 AND has(SSN)"`

### D.4 Adapters

**Spec:** Not specified in this document.

**Current Implementation:** Three adapters available:
- `FilesystemAdapter` - Local filesystem with full remediation support
- `SharePointAdapter` - SharePoint Online via Microsoft Graph
- `OneDriveAdapter` - OneDrive via Microsoft Graph

---

**Labels are the primitive. Risk is derived. Action is optional.**
