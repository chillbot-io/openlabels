# OpenLabels Specification

**Version:** 1.0.0-draft
**Status:** Draft
**Document ID:** OL-SPEC-001
**Last Updated:** January 2026

---

## Abstract

This document defines OpenLabels, a portable format for data sensitivity labels. OpenLabels enables interoperable labeling of sensitive data across platforms, tools, and organizational boundaries. Labels describe WHAT sensitive data is present; risk is computed separately based on exposure context.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Data Model](#3-data-model)
4. [Serialization](#4-serialization)
5. [Transport](#5-transport)
6. [Index](#6-index)
7. [Algorithms](#7-algorithms)
8. [Conformance](#8-conformance)
9. [Security Considerations](#9-security-considerations)
10. [IANA Considerations](#10-iana-considerations)
11. [References](#11-references)
12. [Appendix A: JSON Schema](#appendix-a-json-schema)
13. [Appendix B: Entity Type Registry](#appendix-b-entity-type-registry)
14. [Appendix C: Examples](#appendix-c-examples)

---

## 1. Introduction

### 1.1 Purpose

OpenLabels defines a standard format for describing sensitive data detected within files or data streams. The format is designed to be:

- **Portable**: Labels travel with data across systems
- **Interoperable**: Multiple implementations can read/write labels
- **Minimal**: Compact representation suitable for embedding
- **Extensible**: New entity types can be registered

### 1.2 Design Principles

```
LABELS ARE THE PRIMITIVE. RISK IS DERIVED.
```

OpenLabels separates two concerns:

1. **Labels**: Describe what sensitive data is present (portable, travels with data)
2. **Risk**: Computed locally from labels plus exposure context (not portable)

This separation enables cross-system correlation while respecting that risk depends on context.

### 1.3 Label Types

OpenLabels supports two types of labels:

| Type | Storage | Source of Truth |
|------|---------|-----------------|
| **Embedded Label** | Full label data in file's native metadata | The file itself |
| **Virtual Label** | Pointer (labelID + hash) in extended attributes | The index |

### 1.4 Scope

This specification defines:

- The Label data model
- JSON serialization format
- Transport mechanisms (embedded and virtual)
- The labelID and content hash model
- Index requirements
- Conformance requirements

This specification does NOT define:

- Detection algorithms (how labels are produced)
- Risk scoring formulas (how risk is computed from labels)
- Index storage implementation (database-specific)

---

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

| Term | Definition |
|------|------------|
| **Label** | A single detected entity with type, confidence, detector, and hash |
| **Label Set** | A collection of labels for a single file or data unit |
| **labelID** | Immutable identifier assigned to a file when first labeled |
| **Content Hash** | SHA-256 hash of file content, changes when file is modified |
| **Embedded Label** | Full Label Set stored in file's native metadata |
| **Virtual Label** | Pointer stored in extended attributes, resolved via index |
| **Entity Type** | The category of sensitive data (e.g., "SSN", "CREDIT_CARD") |
| **Confidence** | A score from 0.0 to 1.0 indicating detection certainty |
| **Detector** | The method used to detect the entity (checksum, pattern, ml, structured) |
| **Index** | Database storing label data for virtual labels |
| **Reader** | An implementation that reads labels (embedded or virtual) |
| **Writer** | An implementation that writes labels (embedded or virtual) |

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

#### 3.1.3 Generation

```python
import secrets

def generate_label_id() -> str:
    return "ol_" + secrets.token_hex(6)
```

### 3.2 Content Hash

The content hash tracks file versions.

#### 3.2.1 Format

```
content_hash = sha256(file_content)[:12]
```

Example: `e3b0c44298fc`

#### 3.2.2 Properties

- MUST be recomputed when file content changes
- MUST use SHA-256 algorithm
- MUST be truncated to first 12 hexadecimal characters (48 bits)
- Used to detect file modifications and track versions

### 3.3 Label Set

A Label Set contains all labels for a data unit.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `v` | integer | REQUIRED | Specification version. MUST be `1` for this version. |
| `id` | string | REQUIRED | The labelID. Format: `ol_` + 12 hex chars. |
| `hash` | string | REQUIRED | Content hash. 12 lowercase hex characters. |
| `labels` | array | REQUIRED | Array of Label objects. MAY be empty. |
| `src` | string | REQUIRED | Source identifier. Format: `generator:version`. |
| `ts` | integer | REQUIRED | Unix timestamp (seconds since epoch) when labels were generated. |
| `x` | object | OPTIONAL | Extension data. See Section 3.5. |

### 3.4 Label

A Label describes a single detected sensitive entity.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `t` | string | REQUIRED | Entity type. MUST be a registered type (Appendix B) or prefixed with `x-`. |
| `c` | number | REQUIRED | Confidence score. MUST be in range [0.0, 1.0]. |
| `d` | string | REQUIRED | Detector type. MUST be one of: `checksum`, `pattern`, `ml`, `structured`. |
| `h` | string | REQUIRED | Value hash. MUST be exactly 6 lowercase hexadecimal characters. |
| `n` | integer | OPTIONAL | Occurrence count. MUST be >= 1. Default is 1. |
| `x` | object | OPTIONAL | Extension data. See Section 3.5. |

### 3.5 Extensions

Implementations MAY include additional data in the `x` field at the Label Set or Label level.

- Extension field names SHOULD use reverse domain notation (e.g., `com.example.custom`)
- Readers MUST ignore unrecognized extension fields
- Writers MUST NOT require extensions for basic interoperability

### 3.6 Detector Types

| Value | Description | Typical Confidence |
|-------|-------------|-------------------|
| `checksum` | Validated via checksum algorithm (Luhn, SSN, etc.) | 0.95 - 1.00 |
| `pattern` | Matched via regular expression | 0.70 - 0.95 |
| `ml` | Detected by machine learning model | 0.60 - 0.95 |
| `structured` | Extracted from structured data (JSON keys, headers) | 0.80 - 1.00 |

---

## 4. Serialization

### 4.1 JSON Format

Label Sets MUST be serialized as JSON conforming to [RFC 8259](https://tools.ietf.org/html/rfc8259).

### 4.2 Encoding

- JSON text MUST be encoded as UTF-8
- Writers MUST NOT include a byte order mark (BOM)
- Writers SHOULD use compact serialization (no unnecessary whitespace)

### 4.3 Numeric Precision

- Confidence values (`c`) SHOULD be serialized with at most 2 decimal places
- Implementations MUST accept confidence values with any decimal precision

### 4.4 Field Order

Field order is not significant. Readers MUST accept fields in any order.

### 4.5 Unknown Fields

Readers MUST ignore unrecognized fields without error. This enables forward compatibility.

---

## 5. Transport

Labels are transported via two mechanisms based on file type capabilities.

### 5.1 Decision Tree

```
┌─────────────────────────────────────────┐
│   Does file format support native       │
│   metadata? (PDF, DOCX, images, etc.)   │
│                                         │
│        YES                    NO        │
│         │                      │        │
│         ▼                      ▼        │
│   ┌───────────┐         ┌───────────┐  │
│   │ Embedded  │         │ Virtual   │  │
│   │ Label     │         │ Label     │  │
│   │           │         │           │  │
│   │ Full JSON │         │ xattr:    │  │
│   │ in native │         │ id:hash   │  │
│   │ metadata  │         │           │  │
│   └───────────┘         └─────┬─────┘  │
│                               │        │
│                               ▼        │
│                        ┌───────────┐   │
│                        │  Index    │   │
│                        │  (query)  │   │
│                        └───────────┘   │
└─────────────────────────────────────────┘
```

### 5.2 Embedded Labels

For files with native metadata support, the full Label Set is embedded.

#### 5.2.1 PDF Files

- Store in XMP metadata
- Namespace: `http://openlabels.dev/ns/1.0/`
- Property: `openlabels`
- Value: Compact JSON Label Set

#### 5.2.2 Office Documents (DOCX, XLSX, PPTX)

- Store in Custom Document Properties
- Property name: `openlabels`
- Value: Compact JSON Label Set

#### 5.2.3 Images (JPEG, PNG, TIFF, WebP)

- Store in XMP metadata (preferred)
- Fallback: EXIF UserComment field
- Namespace: `http://openlabels.dev/ns/1.0/`
- Property: `openlabels`

#### 5.2.4 Requirements

- Embedded labels MUST NOT alter the visual/functional content of the file
- Writers MUST use compact JSON (no unnecessary whitespace)
- If metadata size limit is exceeded, implementation SHOULD fall back to virtual labels

#### 5.2.5 Applicable File Types

| Format | Metadata Location | Size Limit |
|--------|-------------------|------------|
| PDF | XMP | ~100KB typical |
| DOCX/XLSX/PPTX | Custom Properties | ~32KB |
| JPEG | XMP or EXIF | ~64KB |
| PNG | XMP (iTXt chunk) | ~2GB theoretical |
| TIFF | XMP | ~100KB typical |
| WebP | XMP | ~100KB typical |
| MP4/MOV | XMP | Varies |

### 5.3 Virtual Labels

For files without native metadata support, a pointer is stored in extended attributes.

#### 5.3.1 Extended Attribute Format

| Platform | Attribute Name | Value Format |
|----------|----------------|--------------|
| Linux | `user.openlabels` | `labelID:content_hash` |
| macOS | `com.openlabels.label` | `labelID:content_hash` |
| Windows | NTFS ADS `openlabels` | `labelID:content_hash` |

#### 5.3.2 Value Format

```
xattr_value = labelID ":" content_hash
```

Example:
```
ol_7f3a9b2c4d5e:e3b0c44298fc
```

#### 5.3.3 Operations

**Writing:**
```bash
# Linux
setfattr -n user.openlabels -v "ol_7f3a9b2c4d5e:e3b0c44298fc" file.csv

# macOS
xattr -w com.openlabels.label "ol_7f3a9b2c4d5e:e3b0c44298fc" file.csv

# Windows (PowerShell)
Set-Content -Path file.csv:openlabels -Value "ol_7f3a9b2c4d5e:e3b0c44298fc"
```

**Reading:**
```bash
# Linux
getfattr -n user.openlabels file.csv

# macOS
xattr -p com.openlabels.label file.csv

# Windows (PowerShell)
Get-Content -Path file.csv:openlabels
```

#### 5.3.4 Cloud Storage

| Platform | Mechanism | Key |
|----------|-----------|-----|
| AWS S3 | Object metadata | `x-amz-meta-openlabels` |
| Google Cloud Storage | Custom metadata | `openlabels` |
| Azure Blob Storage | Metadata | `openlabels` |

#### 5.3.5 Applicable File Types

Virtual labels are used for files without native metadata:

- Plain text: `.txt`, `.log`, `.md`
- Data files: `.csv`, `.tsv`, `.json`, `.jsonl`
- Config files: `.yaml`, `.yml`, `.xml`, `.ini`
- Source code: `.py`, `.js`, `.java`, `.go`, etc.
- Query files: `.sql`
- Archives: `.zip`, `.tar`, `.gz`, `.7z`
- Email: `.eml`, `.msg`

#### 5.3.6 Resolution

To read a virtual label:

1. Read extended attribute from file
2. Parse `labelID:content_hash`
3. Query index for Label Set by labelID
4. Optionally verify content_hash matches current file

### 5.4 Transport Priority

When reading labels, implementations SHOULD check in order:

1. Native metadata (for supported file types)
2. Extended attributes (for all file types)

---

## 6. Index

The index stores Label Sets for virtual labels and provides query capabilities.

### 6.1 Requirements

- Index MUST NOT leave the user's tenant
- Index MUST support lookup by labelID
- Index MUST support lookup by content_hash
- Index SHOULD support querying by entity type
- Index SHOULD support querying by risk score

### 6.2 Schema (Informative)

Implementations MAY use any storage backend. A reference schema:

```sql
-- Core label records
CREATE TABLE label_objects (
    label_id      TEXT PRIMARY KEY,    -- immutable
    tenant_id     UUID NOT NULL,
    created_at    TIMESTAMP NOT NULL,

    INDEX idx_tenant (tenant_id)
);

-- Version history
CREATE TABLE label_versions (
    label_id      TEXT NOT NULL REFERENCES label_objects(label_id),
    content_hash  TEXT NOT NULL,
    scanned_at    TIMESTAMP NOT NULL,
    labels        JSONB NOT NULL,      -- array of label objects
    risk_score    INTEGER,             -- computed, mutable
    exposure      TEXT,                -- computed, mutable
    source        TEXT NOT NULL,       -- generator:version

    PRIMARY KEY (label_id, content_hash),
    INDEX idx_hash (content_hash),
    INDEX idx_risk (risk_score)
);
```

### 6.3 Immutability

- `label_id` is immutable once created
- `content_hash` creates a new version record
- `labels`, `risk_score`, `exposure` may be updated within a version

### 6.4 Deployment Modes

| Mode | Storage | Use Case |
|------|---------|----------|
| Local | SQLite | Single machine, CLI |
| Server | PostgreSQL | Multi-node, API |
| Cloud | Object metadata | Serverless |

---

## 7. Algorithms

### 7.1 Value Hash Computation

The value hash enables cross-system correlation without exposing sensitive values.

#### 7.1.1 Algorithm

```
INPUT: value (string) - the detected sensitive value
OUTPUT: hash (string) - 6 character lowercase hexadecimal string

PROCEDURE:
  1. Normalize value (see 7.1.3)
  2. Encode as UTF-8 bytes
  3. Compute SHA-256 digest
  4. Return first 6 characters of hex encoding
```

#### 7.1.2 Pseudocode

```python
def compute_value_hash(value: str) -> str:
    normalized = normalize(value)
    value_bytes = normalized.encode('utf-8')
    digest = sha256(value_bytes)
    hex_digest = digest.hexdigest().lower()
    return hex_digest[:6]
```

#### 7.1.3 Normalization

Before hashing, values SHOULD be normalized:

- Remove leading/trailing whitespace
- For SSNs: Remove hyphens (e.g., "123-45-6789" → "123456789")
- For credit cards: Remove spaces and hyphens
- For phone numbers: Digits only

Implementations MUST document their normalization rules.

#### 7.1.4 Properties

- **Deterministic**: Same input always produces same hash
- **Collision space**: 16,777,216 possible values (24 bits)
- **Non-reversible**: Cannot recover value from hash

### 7.2 Content Hash Computation

#### 7.2.1 Algorithm

```
INPUT: file_content (bytes)
OUTPUT: hash (string) - 12 character lowercase hexadecimal string

PROCEDURE:
  1. Compute SHA-256 digest of file_content
  2. Return first 12 characters of hex encoding
```

#### 7.2.2 Pseudocode

```python
def compute_content_hash(content: bytes) -> str:
    digest = sha256(content)
    return digest.hexdigest().lower()[:12]
```

### 7.3 Label Merging (Informative)

When combining labels from multiple sources, implementations SHOULD use conservative union:

- For same entity type, take maximum count
- For same entity type, take maximum confidence
- Include entity if ANY source detected it

This is informative guidance, not a normative requirement.

---

## 8. Conformance

### 8.1 Conformance Levels

| Level | Requirements |
|-------|--------------|
| **Reader** | Read embedded and virtual labels |
| **Writer** | Write embedded and virtual labels, maintain index |
| **Full** | Reader + Writer |

### 8.2 Reader Conformance

A conforming OpenLabels Reader:

1. MUST parse any valid Label Set JSON (Section 3, 4)
2. MUST read embedded labels from PDF, DOCX, and images (Section 5.2)
3. MUST read virtual labels from extended attributes (Section 5.3)
4. MUST resolve virtual labels via index lookup
5. MUST ignore unknown fields without error (Section 4.5)
6. MUST accept `v` value of `1`
7. MUST validate `id` field matches format `ol_[a-f0-9]{12}`
8. MUST validate `h` field is 6 hexadecimal characters
9. MUST validate `c` field is in range [0.0, 1.0]
10. SHOULD verify content_hash matches current file

### 8.3 Writer Conformance

A conforming OpenLabels Writer:

1. MUST produce JSON conforming to Section 3 and 4
2. MUST set `v` field to `1`
3. MUST generate labelID per Section 3.1
4. MUST compute content_hash per Section 7.2
5. MUST compute value hashes per Section 7.1
6. MUST write embedded labels for supported file types
7. MUST write virtual labels for unsupported file types
8. MUST store Label Sets in index for virtual labels
9. MUST use registered entity types OR prefix custom types with `x-`
10. SHOULD set confidence based on detection certainty

### 8.4 Conformance Testing

Implementations SHOULD pass the OpenLabels Conformance Test Suite (published separately).

---

## 9. Security Considerations

### 9.1 Value Hash Privacy

The value hash is NOT encryption. It provides:

- **Correlation**: Match same values across systems
- **Pseudonymity**: Cannot directly read the value

It does NOT provide:

- **Secrecy**: High-value targets can be brute-forced
- **Encryption**: Hash is deterministic, not random

Implementations SHOULD NOT rely on hash secrecy for security.

### 9.2 Information Disclosure

Label Sets reveal metadata about file contents:

- Entity types present
- Approximate counts
- Detection confidence

This metadata may itself be sensitive. Implementations SHOULD apply appropriate access controls to Label Sets.

### 9.3 Index Security

Label indexes aggregate sensitive metadata. Per the OpenLabels Constitution:

- Indexes MUST NOT leave the user's tenant
- Indexes SHOULD be encrypted at rest
- Indexes SHOULD have appropriate access controls
- Cross-tenant queries MUST be explicitly authorized

### 9.4 Extended Attribute Persistence

Extended attributes may not survive all file operations:

| Operation | xattr Preserved? |
|-----------|------------------|
| Local copy (cp -p) | Yes |
| rsync -X | Yes |
| Email attachment | No |
| Upload to web app | Usually no |
| ZIP archive | No |
| Cross-filesystem copy | Maybe |

Implementations SHOULD re-scan and re-label files when xattr loss is detected.

### 9.5 labelID Confidentiality

The labelID is a stable identifier that could be used to track files. Implementations SHOULD:

- Treat labelID as sensitive metadata
- Not expose labelID in logs or public interfaces
- Regenerate labelID when file confidentiality requires it

---

## 10. IANA Considerations

### 10.1 Media Type Registration

This specification registers the following media type:

```
Type name: application
Subtype name: openlabels+json
Required parameters: none
Optional parameters: none
Encoding considerations: UTF-8
Security considerations: See Section 9
Interoperability considerations: See Section 8
Published specification: This document
Applications that use this media type: Data classification tools
```

### 10.2 Entity Type Registry

The OpenLabels Entity Type Registry is maintained at:

```
https://openlabels.dev/registry/entity-types
```

New entity types may be registered via the process defined in the registry documentation.

---

## 11. References

### 11.1 Normative References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC 8259] Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017.
- [FIPS 180-4] "Secure Hash Standard (SHS)", FIPS PUB 180-4, August 2015.

### 11.2 Informative References

- OpenLabels Constitution v3
- OpenLabels Entity Registry v1
- OpenLabels Architecture v2

---

## Appendix A: JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://openlabels.dev/schema/v1/labelset.json",
  "title": "OpenLabels Label Set",
  "type": "object",
  "required": ["v", "id", "hash", "labels", "src", "ts"],
  "properties": {
    "v": {
      "type": "integer",
      "const": 1,
      "description": "Specification version"
    },
    "id": {
      "type": "string",
      "pattern": "^ol_[a-f0-9]{12}$",
      "description": "Immutable label ID"
    },
    "hash": {
      "type": "string",
      "pattern": "^[a-f0-9]{12}$",
      "description": "Content hash"
    },
    "labels": {
      "type": "array",
      "items": { "$ref": "#/$defs/label" },
      "description": "Array of labels"
    },
    "src": {
      "type": "string",
      "pattern": "^[a-z0-9_-]+:[0-9a-z.-]+$",
      "description": "Source generator:version"
    },
    "ts": {
      "type": "integer",
      "minimum": 0,
      "description": "Unix timestamp"
    },
    "x": {
      "type": "object",
      "description": "Extension data"
    }
  },
  "$defs": {
    "label": {
      "type": "object",
      "required": ["t", "c", "d", "h"],
      "properties": {
        "t": {
          "type": "string",
          "minLength": 1,
          "description": "Entity type"
        },
        "c": {
          "type": "number",
          "minimum": 0,
          "maximum": 1,
          "description": "Confidence score"
        },
        "d": {
          "type": "string",
          "enum": ["checksum", "pattern", "ml", "structured"],
          "description": "Detector type"
        },
        "h": {
          "type": "string",
          "pattern": "^[a-f0-9]{6}$",
          "description": "Value hash"
        },
        "n": {
          "type": "integer",
          "minimum": 1,
          "description": "Occurrence count"
        },
        "x": {
          "type": "object",
          "description": "Extension data"
        }
      }
    }
  }
}
```

---

## Appendix B: Entity Type Registry

The following entity types are registered in v1.0:

### B.1 Direct Identifiers

| Type | Description | Category |
|------|-------------|----------|
| `SSN` | US Social Security Number | direct_id |
| `PASSPORT` | Passport number | direct_id |
| `DRIVER_LICENSE` | Driver's license number | direct_id |
| `NATIONAL_ID` | National identification number | direct_id |

### B.2 Financial

| Type | Description | Category |
|------|-------------|----------|
| `CREDIT_CARD` | Credit/debit card number | financial |
| `BANK_ACCOUNT` | Bank account number | financial |
| `IBAN` | International Bank Account Number | financial |
| `SWIFT` | SWIFT/BIC code | financial |
| `ROUTING_NUMBER` | Bank routing number | financial |

### B.3 Contact Information

| Type | Description | Category |
|------|-------------|----------|
| `EMAIL` | Email address | contact |
| `PHONE` | Phone number | contact |
| `ADDRESS` | Physical address | contact |

### B.4 Personal Information

| Type | Description | Category |
|------|-------------|----------|
| `NAME` | Person name | pii |
| `DATE_DOB` | Date of birth | pii |
| `AGE` | Age | pii |
| `GENDER` | Gender | pii |

### B.5 Healthcare

| Type | Description | Category |
|------|-------------|----------|
| `MRN` | Medical Record Number | health |
| `NPI` | National Provider Identifier | health |
| `DEA` | DEA Number | health |
| `DIAGNOSIS` | Medical diagnosis | health |
| `MEDICATION` | Medication name | health |

### B.6 Credentials

| Type | Description | Category |
|------|-------------|----------|
| `AWS_ACCESS_KEY` | AWS access key ID | credential |
| `AWS_SECRET_KEY` | AWS secret access key | credential |
| `API_KEY` | Generic API key | credential |
| `PASSWORD` | Password | credential |
| `PRIVATE_KEY` | Cryptographic private key | credential |

### B.7 Network

| Type | Description | Category |
|------|-------------|----------|
| `IP_ADDRESS` | IP address (v4 or v6) | network |
| `MAC_ADDRESS` | MAC address | network |
| `URL` | URL with potential PII | network |

See the full registry at https://openlabels.dev/registry for 300+ types.

---

## Appendix C: Examples

### C.1 Embedded Label (PDF)

Full Label Set stored in PDF XMP metadata:

```json
{
  "v": 1,
  "id": "ol_7f3a9b2c4d5e",
  "hash": "e3b0c44298fc",
  "labels": [
    {"t": "SSN", "c": 0.99, "d": "checksum", "h": "15e2b0"},
    {"t": "NAME", "c": 0.92, "d": "pattern", "h": "ef61a5"},
    {"t": "DATE_DOB", "c": 0.88, "d": "pattern", "h": "7c4a8d"}
  ],
  "src": "orscan:1.0.0",
  "ts": 1706140800
}
```

### C.2 Virtual Label (CSV)

Extended attribute on file:

```
user.openlabels = "ol_7f3a9b2c4d5e:e3b0c44298fc"
```

Label Set stored in index (same JSON as C.1).

### C.3 Version History

Same labelID, different content hashes (file was edited):

**Version 1:**
```json
{
  "v": 1,
  "id": "ol_7f3a9b2c4d5e",
  "hash": "e3b0c44298fc",
  "labels": [
    {"t": "SSN", "c": 0.99, "d": "checksum", "h": "15e2b0", "n": 3}
  ],
  "src": "orscan:1.0.0",
  "ts": 1706140800
}
```

**Version 2 (more SSNs added):**
```json
{
  "v": 1,
  "id": "ol_7f3a9b2c4d5e",
  "hash": "a1b2c3d4e5f6",
  "labels": [
    {"t": "SSN", "c": 0.99, "d": "checksum", "h": "15e2b0", "n": 5},
    {"t": "SSN", "c": 0.99, "d": "checksum", "h": "8d969e", "n": 2}
  ],
  "src": "orscan:1.0.0",
  "ts": 1706227200
}
```

### C.4 Cloud Storage (S3)

Object metadata:

```
x-amz-meta-openlabels: ol_7f3a9b2c4d5e:e3b0c44298fc
```

### C.5 With Extensions

```json
{
  "v": 1,
  "id": "ol_7f3a9b2c4d5e",
  "hash": "e3b0c44298fc",
  "labels": [
    {
      "t": "SSN",
      "c": 0.99,
      "d": "checksum",
      "h": "15e2b0",
      "x": {
        "com.example.page": 3,
        "com.example.redacted": true
      }
    }
  ],
  "src": "orscan:1.0.0",
  "ts": 1706140800,
  "x": {
    "com.example.scan_duration_ms": 1250,
    "com.example.ocr_used": true
  }
}
```

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0-draft | 2026-01 | Initial draft |
| 1.0.0-draft | 2026-01 | Revised: removed sidecars and trailers, added virtual labels and index |

---

## Authors

OpenLabels Community

---

## License

This specification is released under CC BY 4.0.

---

**Labels are the primitive. Risk is derived.**
