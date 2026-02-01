# OpenLabels Constitution

**Authoritative Design Principles for OpenLabels**

---

**Version:** 3.0
**Status:** Active
**Last Updated:** January 2026

---

## Purpose

This document defines the core principles, boundaries, and design decisions for OpenLabels. It serves as the authoritative reference for contributors, maintainers, and AI assistants working on the project.

**Read this document before making any changes to OpenLabels.**

---

## The Core Insight

```
LABELS ARE THE PRIMITIVE. RISK IS DERIVED.
```

OpenLabels is a universal, portable standard for data sensitivity **labels** that travel with data. Risk scores are computed from labels plus exposure context.

- A label describes WHAT is in the data (SSN, credit card, diagnosis, etc.)
- Risk describes HOW DANGEROUS that data is, given WHERE it lives
- Same label, different context = different risk

**Labels are portable. Risk is computed locally based on context.**

---

## Core Principles

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         OPENLABELS CONSTITUTION v3                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. LABELS ARE THE PRIMITIVE, RISK IS DERIVED                               │
│     Labels describe content. Risk = Labels × Exposure.                      │
│     Labels travel with data. Risk is computed in context.                   │
│                                                                             │
│  2. THE SCANNER (orscan) IS AN ADAPTER, NOT A SEPARATE PRODUCT              │
│     orscan produces labels just like Macie/DLP/Purview adapters.            │
│     It lives in the same repo, uses the same interfaces.                    │
│     "orscan" = open source risk scanner, the backup when no DLP exists.     │
│                                                                             │
│  3. EXPOSURE ALWAYS CONTRIBUTES TO RISK                                     │
│     Exposure is not conditional. It's not a "bonus" or "optional factor."   │
│     Every risk score includes exposure multiplier. This is the core insight.│
│     content_score × exposure_multiplier = risk_score. Always.               │
│                                                                             │
│  4. ADAPTERS NORMALIZE, THEY DON'T REPLACE                                  │
│     Macie adapter normalizes Macie output to OpenLabels format.             │
│     GCP adapter normalizes GCP output to OpenLabels format.                 │
│     Scanner adapter normalizes scanner output to OpenLabels format.         │
│     All adapters produce identical Label structures.                        │
│                                                                             │
│  5. CONSERVATIVE UNION FOR DEFENSE IN DEPTH                                 │
│     When multiple adapters run, take max confidence per entity type.        │
│     If Macie says 3 SSNs and Scanner says 5, use 5.                         │
│     Safety first. False negatives are worse than false positives.           │
│                                                                             │
│  6. LABEL INDEX STAYS IN USER'S TENANT                                      │
│     The label index contains sensitive meta-metadata.                       │
│     It NEVER leaves the user's self-hosted or cloud tenant.                 │
│     When files change tenants, labels travel; index updates locally.        │
│                                                                             │
│  7. PERMISSION NORMALIZATION IS UNIVERSAL                                   │
│     S3 "authenticated-read" = NTFS "Authenticated Users" = ORG_WIDE     │
│     GCS "allUsers" = Azure "Blob" public = POSIX "o+r" = PUBLIC             │
│     Same exposure levels across all platforms. This enables comparison.     │
│                                                                             │
│  8. OCR IS ALWAYS-ON, LAZY-LOADED                                           │
│     RapidOCR is not optional. Many file types need it.                      │
│     Load on first use, stay loaded for session.                             │
│     Priority queue based on metadata exposure.                              │
│                                                                             │
│  9. CLI ENABLES RISK-AWARE DATA MANAGEMENT                                  │
│     quarantine, find, move, delete based on risk + filters.                 │
│     "orscan find s3://bucket --where 'risk > 75 AND stale > 5y'"            │
│     This is the operational value. Not just labeling, but action.           │
│                                                                             │
│  10. TWO DEPLOYMENT MODES: LOCAL AND SERVER                                 │
│      Local: SQLite-based, single machine, CLI-driven (orscan)               │
│      Server: Self-hosted Postgres, multi-node, API daemon                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## What OpenLabels IS

| Attribute | Description |
|-----------|-------------|
| **A labeling standard** | Portable labels that travel with data |
| **Content + Context** | Labels detected AND exposure/metadata combined for risk |
| **Adapter-based** | All inputs (Macie, DLP, Purview, Scanner) use same interface |
| **Cross-platform** | Same labels for S3, GCS, Azure, NTFS, POSIX |
| **Actionable** | CLI for quarantine, find, move based on risk filters |
| **Open source** | Apache 2.0 license |

---

## What OpenLabels Is NOT

| Attribute | Why Not |
|-----------|---------|
| **Just a risk format** | Labels are the primitive; risk is derived from context |
| **A replacement for Macie/DLP** | We consume their output via adapters |
| **A platform or SaaS** | It's a standard with reference implementation |
| **Enterprise software** | No RBAC, no multi-tenant, no audit dashboard |
| **A real-time monitor** | Batch scanning, not streaming |
| **Varonis competitor** | Different scope, different budget class |

---

## Key Design Decisions

### 1. Labels Travel, Risk is Computed

**Decision:** Labels are portable metadata. Risk is calculated locally.

**Rationale:**
- Labels describe what's IN the data (entities detected)
- Risk depends on WHERE the data lives (exposure, encryption, access)
- Same file, same labels, different bucket = different risk
- This separation enables cross-system correlation via label hash

**Implementation:**
```json
{
  "v": 1,
  "labels": [
    {"t": "SSN", "c": 0.99, "d": "checksum", "h": "a1b2c3"},
    {"t": "NAME", "c": 0.87, "d": "pattern", "h": "d4e5f6"}
  ],
  "src": "orscan:0.1.0",
  "ts": 1706000000
}
```

### 2. Exposure Multipliers

**Decision:** Exposure always multiplies content score to compute risk.

**Rationale:**
- An SSN in a private bucket is different risk than SSN in public bucket
- This is the unique value proposition of OpenLabels
- Without this, we're just another classification format

**Implementation:**
```python
EXPOSURE_MULTIPLIERS = {
    ExposureLevel.PRIVATE: 1.0,
    ExposureLevel.INTERNAL: 1.2,
    ExposureLevel.ORG_WIDE: 1.8,
    ExposureLevel.PUBLIC: 2.5,
}

risk_score = min(100, content_score * exposure_multiplier)
```

### 3. Scanner (orscan) as Adapter

**Decision:** Scanner is an adapter, not a separate repo.

**Rationale:**
- Scanner produces same labels as other adapters
- Shares entity registry, output formats
- Cannot be "un-intertwined" - the coupling is architectural, not accidental

**Implementation:**
```
openlabels/
├── adapters/
│   ├── macie.py
│   ├── dlp.py
│   ├── purview.py
│   └── scanner/     ← orscan IS an adapter
│       ├── adapter.py
│       ├── detectors/
│       └── ocr/
```

### 4. Index Architecture

**Decision:** Label index stays in user's tenant. Two deployment modes.

**Rationale:**
- Index contains sensitive meta-metadata that could identify crown jewels
- Must never leave user's self-hosted or cloud tenant
- When files move tenants, labels travel with them; new tenant's index updates

**Deployment Modes:**
- **Local**: SQLite file co-located with data
- **Server**: Self-hosted Postgres in user's VPC/datacenter

### 5. Label Portability

**Decision:** Labels travel with files via embedded labels or virtual labels.

**Two transport mechanisms:**
- **Embedded labels**: For files with native metadata (PDF, DOCX, images)
  - Full Label Set JSON stored in XMP/EXIF/custom properties
  - Source of truth: the file itself
- **Virtual labels**: For files without native metadata (CSV, TXT, JSON, archives)
  - Extended attribute stores `labelID:content_hash` pointer
  - Source of truth: the index

**Immutable labelID enables correlation:**
- Each file gets a unique labelID on first scan
- labelID never changes, even when file content changes
- When file moves to new tenant, labelID + hash travel via xattr
- New tenant's index registers the file under same labelID

---

## Scope Boundaries

### In Scope for v1

- SDK core (LabelReader, LabelWriter, RiskScorer)
- All adapters (Macie, DLP, Purview, Scanner/orscan)
- Normalizers (entity types, metadata/permissions)
- Risk scoring engine with exposure multipliers
- CLI (orscan scan, find, quarantine, move, report)
- Agent for on-prem (NTFS, POSIX)
- Entity registry (300+ types)
- Local SQLite index
- Virtual label transport (extended attributes)

### Deferred (v2+)

- Server mode (Postgres-based)
- Web dashboard
- Real-time streaming
- Multi-user / RBAC
- Incremental scanning (USN journal)

### Never Scope

- SaaS platform
- Enterprise feature parity with Varonis
- GPU cloud hosting
- Mobile apps
- Centralized index service (violates tenant isolation)

---

## Forbidden Suggestions

Do not suggest:

| Suggestion | Why Forbidden |
|------------|---------------|
| "Make exposure optional" | Exposure is the core differentiator |
| "Separate scanner repo" | Scanner is architecturally coupled as adapter |
| "Skip OCR for speed" | Many file types require it |
| "Add web dashboard" | Out of scope for v1 |
| "Build SaaS platform" | OpenLabels is a standard, not a product |
| "Use GPU for inference" | No GPU budget; speed via filtering |
| "Centralized index service" | Violates tenant isolation principle |
| "Per-entity confidence thresholds" | Complexity without value |

---

## Questions to Ask Before Changes

1. Does this preserve Labels as the primitive, Risk as derived?
2. Does this keep the scanner as an adapter?
3. Is this in v1 scope?
4. Does this preserve cross-platform normalization?
5. Does this enable, not hinder, the CLI actions (quarantine, find, etc.)?
6. Does this keep the index in the user's tenant?

---

## Architecture Summary

```
┌────────────────────────────────────────────────────────────────────────┐
│                           OPENLABELS                                   │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   ADAPTERS (all produce Labels)                                        │
│   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐                     │
│   │  Macie  │ │   DLP   │ │ Purview │ │ orscan  │                     │
│   └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘                     │
│        │           │           │           │                           │
│        └───────────┴───────────┴───────────┘                           │
│                          │                                             │
│                          ▼                                             │
│   ┌─────────────────────────────────────────┐                          │
│   │         NORMALIZERS                      │                          │
│   │   • Entity types → canonical             │                          │
│   │   • Permissions → exposure levels        │                          │
│   └─────────────────────┬───────────────────┘                          │
│                         │                                              │
│                         ▼                                              │
│   ┌─────────────────────────────────────────┐                          │
│   │         MERGER                           │                          │
│   │   • Conservative union                   │                          │
│   │   • Max confidence per type              │                          │
│   └─────────────────────┬───────────────────┘                          │
│                         │                                              │
│                         ▼                                              │
│   ┌─────────────────────────────────────────┐                          │
│   │         LABEL WRITER                     │                          │
│   │   • Embedded labels (native metadata)    │                          │
│   │   • Virtual labels (xattr + index)       │                          │
│   │   • Immutable labelID for correlation    │                          │
│   └─────────────────────┬───────────────────┘                          │
│                         │                                              │
│                         ▼                                              │
│   ┌─────────────────────────────────────────┐                          │
│   │         LOCAL INDEX                      │                          │
│   │   • SQLite (local mode)                  │                          │
│   │   • Postgres (server mode)               │                          │
│   │   • NEVER leaves user's tenant           │                          │
│   └─────────────────────┬───────────────────┘                          │
│                         │                                              │
│                         ▼                                              │
│   ┌─────────────────────────────────────────┐                          │
│   │         RISK SCORER                      │                          │
│   │   • Labels + Exposure → Risk score       │                          │
│   │   • content_score × exposure_multiplier  │                          │
│   │   • = final_score (0-100)                │                          │
│   └─────────────────────────────────────────┘                          │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01 | Initial constitution (scanner separate) |
| 2.0 | 2026-01 | Major rewrite: scanner as adapter, exposure multipliers |
| 3.0 | 2026-01 | Rebrand to OpenLabels. Labels are primitive, risk is derived. |
| 3.1 | 2026-01 | Revised transport: embedded labels + virtual labels. Removed trailers/sidecars. |

---

**This document is the authoritative design reference for OpenLabels.**

*All contributors and AI assistants must internalize these principles before making changes.*
