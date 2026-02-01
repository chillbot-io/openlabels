# OpenLabels Architecture v2.0

**The Universal Data Risk Scoring Standard**

This document is the ground truth for OpenLabels architecture. It captures the complete design, including the SDK, adapters, scanner, CLI, and scoring methodology.

---

## Table of Contents

1. [Terminology: Labeler vs Scanner](#terminology-labeler-vs-scanner)
2. [Vision & Identity](#vision--identity)
3. [Core Value Proposition](#core-value-proposition)
4. [System Architecture](#system-architecture)
5. [Labeler Adapters](#labeler-adapters)
6. [Normalizers](#normalizers)
7. [Scanner (Content Classification)](#scanner-content-classification)
8. [Scoring Engine](#scoring-engine)
9. [Scan Triggers](#scan-triggers)
10. [OCR Priority Queue](#ocr-priority-queue)
11. [Agent (On-Prem)](#agent-on-prem)
12. [CLI & Query Language](#cli--query-language)
13. [Repository Structure](#repository-structure)
14. [API Reference](#api-reference)
15. [Implementation Roadmap](#implementation-roadmap)

---

## Terminology: Labeler vs Scanner

OpenLabels provides two distinct modes of operation. This distinction is critical for understanding the architecture:

| Term | Definition |
|------|------------|
| **Labeler** | Reads metadata and existing labels/classifications from external sources (Macie findings, DLP results, Purview classifications, NTFS ACLs, NFS exports, etc.). Does NOT analyze file content—trusts external classification. |
| **Scanner** | Built-in classification engine that analyzes file content to detect sensitive entities using patterns, checksums, and ML. For users without DLP capabilities, or as defense-in-depth verification. |

### When to Use Which

| Scenario | Use |
|----------|-----|
| Already have Macie/DLP/Purview classifying data | **Labeler** — normalize existing findings to portable scores |
| No DLP capabilities | **Scanner** — analyze content directly |
| Want defense-in-depth | **Both** — Labeler pulls existing labels, Scanner verifies with content analysis |
| Scanning local Windows/Linux files | **Scanner** — plus Labeler for permission metadata (NTFS ACLs, POSIX modes) |

### Architectural Mapping

In the codebase:

| Concept | Implementation |
|---------|----------------|
| Labeler | `MacieAdapter`, `DLPAdapter`, `PurviewAdapter`, `NTFSAdapter`, `NFSAdapter`, `M365Adapter` |
| Scanner | `ScannerAdapter` (wraps detector orchestrator) |
| Combined | `Orchestrator` merges outputs from both |

Both Labeler and Scanner produce the same `NormalizedInput` format, enabling seamless combination.

---

## Vision & Identity

### What OpenLabels Is

OpenLabels is a **universal risk scoring standard** that combines:
- **Content sensitivity** (what data is present)
- **Exposure context** (how it's stored and who can access it)

Into a single **portable 0-100 risk score** that works across any platform.

### What OpenLabels Is NOT

- **Not just a scanner** — it's a scoring framework. The Scanner is one component; the Labeler consumes external DLP findings.
- **Not a replacement for Macie/DLP/Purview** — it consumes their output via the Labeler and normalizes to a universal score
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
| Already have Macie/DLP | Use **Labeler** → normalize existing findings to portable score |
| No DLP capabilities | Use **Scanner** → analyze content directly |
| Want portability | Scanner works anywhere (on-prem, any cloud) |
| Want defense in depth | Run **Labeler + Scanner** together → conservative union |
| Actionable remediation | CLI with quarantine, move, delete based on risk |

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
│  │  └─────────┘ └─────────┘ └─────────┘       │  │ • OCR Worker        │  │
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
│                              OPENLABELS CORE                                  │
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
│                              OUTPUT                                         │
│                                                                             │
│    Score: 73                                                                │
│    Level: HIGH                                                              │
│    Entities: [SSN (3), EMAIL (12), CREDIT_CARD (1)]                        │
│    Exposure: PUBLIC                                                         │
│    Triggers: [public_access, no_encryption]                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Processing Flow

```
┌──────────────────┐
│   Object/File    │
└────────┬─────────┘
         │
         ▼
┌────────────────────────────────┐
│  1. Normalize metadata         │
│  (exposure, encryption, age)   │
└────────────────┬───────────────┘
                 │
                 ▼
┌────────────────────────────────┐
│  2. Has labels/classification? │
└────────────────┬───────────────┘
                 │
   ┌─────────────┴─────────────┐
   ▼                           ▼
  YES                          NO
   │                           │
   ▼                           ▼
┌─────────────┐       ┌─────────────────┐
│ Check scan  │       │ MUST scan       │
│ triggers    │       │ (no other data) │
└──────┬──────┘       └────────┬────────┘
       │                       │
 ┌─────┴─────┐                 │
 ▼           ▼                 │
SCAN       TRUST               │
ANYWAY     LABELS              │
 │           │                 │
 └───────────┴─────────────────┘
                 │
                 ▼
┌────────────────────────────────┐
│  3. Is PDF/Image detected?     │
└────────────────┬───────────────┘
                 │
   ┌─────────────┴─────────────┐
   ▼                           ▼
  YES                          NO
   │                           │
   ▼                           ▼
┌──────────────────┐    ┌──────────────┐
│ Queue OCR Worker │    │   Continue   │
│ (priority based  │    │              │
│  on metadata)    │    │              │
└────────┬─────────┘    └──────┬───────┘
         │                     │
         └─────────────────────┘
                 │
                 ▼
┌────────────────────────────────┐
│  4. Merge entities, calculate  │
│  score with exposure multiplier│
└────────────────────────────────┘
```

---

## Labeler Adapters

**Labeler adapters** read metadata and existing classifications from external sources. They do NOT analyze file content—they normalize what external tools have already classified.

All adapters implement the same interface and produce normalized output:

```python
from typing import Protocol, List, Any
from dataclasses import dataclass
from enum import Enum
from datetime import datetime


class ExposureLevel(Enum):
    """Normalized exposure levels across all platforms."""
    PRIVATE = 0          # Only owner/specific principals
    INTERNAL = 1         # Same org/tenant
    ORG_WIDE = 2         # Too broad (authenticated users, large groups)
    PUBLIC = 3           # Anyone, anonymous


@dataclass
class Entity:
    """A detected sensitive entity."""
    type: str              # Canonical OpenLabels type (e.g., "SSN")
    count: int             # Number of occurrences
    confidence: float      # 0.0 - 1.0
    weight: int            # From entity registry (1-10)
    source: str            # "macie", "dlp", "purview", "scanner"
    positions: List[tuple] # Optional: [(start, end), ...]


@dataclass
class NormalizedContext:
    """Normalized metadata context."""
    # Exposure factors
    exposure: ExposureLevel
    cross_account_access: bool
    anonymous_access: bool

    # Protection factors
    encryption: str              # "none" | "platform" | "customer_managed"
    versioning: bool
    access_logging: bool
    retention_policy: bool

    # Staleness
    last_modified: datetime
    last_accessed: datetime      # If available
    staleness_days: int

    # Source info
    has_classification: bool
    classification_source: str   # "macie" | "dlp" | "purview" | "scanner" | "none"

    # File info
    file_size: int
    file_type: str
    is_archive: bool


@dataclass
class NormalizedInput:
    """Standard input to the OpenLabels scorer."""
    entities: List[Entity]
    context: NormalizedContext


class Adapter(Protocol):
    """All adapters implement this interface."""

    def extract(self, source: Any, metadata: Any) -> NormalizedInput:
        """Extract entities and context from a source."""
        ...
```

### Macie Adapter

```python
class MacieAdapter:
    """AWS Macie + S3 metadata adapter."""

    # Entity type mapping: Macie → OpenLabels
    ENTITY_MAP = {
        "AWS_CREDENTIALS": "AWS_ACCESS_KEY",
        "CREDIT_CARD_NUMBER": "CREDIT_CARD",
        "USA_SOCIAL_SECURITY_NUMBER": "SSN",
        "USA_PASSPORT_NUMBER": "PASSPORT",
        "USA_DRIVER_LICENSE": "DRIVER_LICENSE",
        "BANK_ACCOUNT_NUMBER": "BANK_ACCOUNT",
        "DATE_OF_BIRTH": "DATE_DOB",
        "EMAIL_ADDRESS": "EMAIL",
        "IP_ADDRESS": "IP_ADDRESS",
        "PHONE_NUMBER": "PHONE",
        "NAME": "NAME",
        "ADDRESS": "ADDRESS",
        # ... complete mapping
    }

    def extract(
        self,
        findings: dict,  # Macie findings
        s3_metadata: dict,  # S3 object/bucket metadata
    ) -> NormalizedInput:
        """Convert Macie findings + S3 metadata to normalized format."""

        entities = []
        for finding in findings.get("findings", []):
            entity_type = self.ENTITY_MAP.get(
                finding["type"],
                finding["type"]  # Pass through if unknown
            )
            entities.append(Entity(
                type=entity_type,
                count=finding.get("count", 1),
                confidence=self._severity_to_confidence(finding["severity"]),
                weight=ENTITY_REGISTRY[entity_type]["weight"],
                source="macie",
            ))

        context = self._normalize_s3_context(s3_metadata)

        return NormalizedInput(entities=entities, context=context)

    def _severity_to_confidence(self, severity: str) -> float:
        """Map Macie severity to confidence score."""
        return {
            "High": 0.95,
            "Medium": 0.80,
            "Low": 0.65,
        }.get(severity, 0.75)

    def _normalize_s3_context(self, meta: dict) -> NormalizedContext:
        """Normalize S3 metadata to standard context."""

        # Determine exposure level
        exposure = ExposureLevel.PRIVATE
        if meta.get("public_access_block") is False:
            if "public-read" in meta.get("acl", ""):
                exposure = ExposureLevel.PUBLIC
            elif "authenticated-read" in meta.get("acl", ""):
                exposure = ExposureLevel.ORG_WIDE

        return NormalizedContext(
            exposure=exposure,
            cross_account_access=meta.get("cross_account", False),
            anonymous_access=exposure == ExposureLevel.PUBLIC,
            encryption=self._normalize_encryption(meta.get("encryption")),
            versioning=meta.get("versioning") == "Enabled",
            access_logging=meta.get("logging_enabled", False),
            retention_policy=meta.get("object_lock", False),
            last_modified=meta.get("last_modified"),
            last_accessed=meta.get("last_accessed"),
            staleness_days=self._calc_staleness(meta.get("last_modified")),
            has_classification=True,
            classification_source="macie",
            file_size=meta.get("size", 0),
            file_type=meta.get("content_type", ""),
            is_archive=self._is_archive(meta.get("key", "")),
        )

    def _normalize_encryption(self, enc: str) -> str:
        if not enc:
            return "none"
        if "aws:kms" in enc:
            return "customer_managed"
        return "platform"
```

### GCP DLP Adapter

```python
class DLPAdapter:
    """GCP DLP + GCS metadata adapter."""

    ENTITY_MAP = {
        "CREDIT_CARD_NUMBER": "CREDIT_CARD",
        "US_SOCIAL_SECURITY_NUMBER": "SSN",
        "EMAIL_ADDRESS": "EMAIL",
        "PHONE_NUMBER": "PHONE",
        "PERSON_NAME": "NAME",
        "STREET_ADDRESS": "ADDRESS",
        "DATE_OF_BIRTH": "DATE_DOB",
        "US_PASSPORT": "PASSPORT",
        "US_DRIVERS_LICENSE_NUMBER": "DRIVER_LICENSE",
        # ... complete mapping
    }

    def extract(
        self,
        findings: dict,  # DLP inspection results
        gcs_metadata: dict,  # GCS object/bucket metadata
    ) -> NormalizedInput:

        entities = []
        for finding in findings.get("findings", []):
            entity_type = self.ENTITY_MAP.get(
                finding["infoType"]["name"],
                finding["infoType"]["name"]
            )
            entities.append(Entity(
                type=entity_type,
                count=1,  # DLP reports each occurrence
                confidence=self._likelihood_to_confidence(finding["likelihood"]),
                weight=ENTITY_REGISTRY.get(entity_type, {}).get("weight", 5),
                source="dlp",
            ))

        context = self._normalize_gcs_context(gcs_metadata)
        return NormalizedInput(entities=entities, context=context)

    def _likelihood_to_confidence(self, likelihood: str) -> float:
        return {
            "VERY_LIKELY": 0.95,
            "LIKELY": 0.85,
            "POSSIBLE": 0.70,
            "UNLIKELY": 0.50,
            "VERY_UNLIKELY": 0.30,
        }.get(likelihood, 0.70)

    def _normalize_gcs_context(self, meta: dict) -> NormalizedContext:
        """Normalize GCS metadata to standard context."""

        iam_policy = meta.get("iam_policy", {})
        exposure = ExposureLevel.PRIVATE

        for binding in iam_policy.get("bindings", []):
            members = binding.get("members", [])
            if "allUsers" in members:
                exposure = ExposureLevel.PUBLIC
                break
            if "allAuthenticatedUsers" in members:
                exposure = ExposureLevel.ORG_WIDE

        return NormalizedContext(
            exposure=exposure,
            cross_account_access=self._has_cross_project_access(iam_policy),
            anonymous_access=exposure == ExposureLevel.PUBLIC,
            encryption=self._normalize_encryption(meta.get("encryption")),
            versioning=meta.get("versioning", {}).get("enabled", False),
            access_logging=meta.get("logging", {}).get("logBucket") is not None,
            retention_policy=meta.get("retentionPolicy") is not None,
            last_modified=meta.get("updated"),
            last_accessed=None,  # GCS doesn't track this
            staleness_days=self._calc_staleness(meta.get("updated")),
            has_classification=True,
            classification_source="dlp",
            file_size=int(meta.get("size", 0)),
            file_type=meta.get("contentType", ""),
            is_archive=self._is_archive(meta.get("name", "")),
        )
```

### Purview Adapter

```python
class PurviewAdapter:
    """Azure Purview + Blob metadata adapter."""

    ENTITY_MAP = {
        "Credit Card Number": "CREDIT_CARD",
        "U.S. Social Security Number (SSN)": "SSN",
        "Email": "EMAIL",
        "Phone Number": "PHONE",
        "Person's Name": "NAME",
        "Address": "ADDRESS",
        "Date of Birth": "DATE_DOB",
        "U.S. Passport Number": "PASSPORT",
        "U.S. Driver's License Number": "DRIVER_LICENSE",
        # ... complete mapping
    }

    def extract(
        self,
        classifications: dict,  # Purview classifications
        blob_metadata: dict,  # Blob/container metadata
    ) -> NormalizedInput:

        entities = []
        for classification in classifications.get("classifications", []):
            entity_type = self.ENTITY_MAP.get(
                classification["typeName"],
                classification["typeName"]
            )
            entities.append(Entity(
                type=entity_type,
                count=classification.get("count", 1),
                confidence=0.85,  # Purview doesn't provide confidence
                weight=ENTITY_REGISTRY.get(entity_type, {}).get("weight", 5),
                source="purview",
            ))

        context = self._normalize_blob_context(blob_metadata)
        return NormalizedInput(entities=entities, context=context)

    def _normalize_blob_context(self, meta: dict) -> NormalizedContext:
        """Normalize Azure Blob metadata to standard context."""

        public_access = meta.get("public_access", "None")
        exposure = {
            "None": ExposureLevel.PRIVATE,
            "Blob": ExposureLevel.PUBLIC,
            "Container": ExposureLevel.PUBLIC,
        }.get(public_access, ExposureLevel.PRIVATE)

        return NormalizedContext(
            exposure=exposure,
            cross_account_access=meta.get("cross_tenant", False),
            anonymous_access=exposure == ExposureLevel.PUBLIC,
            encryption=self._normalize_encryption(meta.get("encryption_scope")),
            versioning=meta.get("versioning_enabled", False),
            access_logging=meta.get("diagnostic_logs", False),
            retention_policy=meta.get("immutability_policy") is not None,
            last_modified=meta.get("last_modified"),
            last_accessed=meta.get("last_access_time"),
            staleness_days=self._calc_staleness(meta.get("last_modified")),
            has_classification=True,
            classification_source="purview",
            file_size=meta.get("content_length", 0),
            file_type=meta.get("content_type", ""),
            is_archive=self._is_archive(meta.get("name", "")),
        )
```

---

## Normalizers

### Entity Type Normalizer

Maps vendor entity types to canonical OpenLabels types.

```python
class EntityNormalizer:
    """Maps vendor entity types to OpenLabels canonical types."""

    # Master mapping table
    MAPPINGS = {
        # Macie
        "AWS_CREDENTIALS": "AWS_ACCESS_KEY",
        "CREDIT_CARD_NUMBER": "CREDIT_CARD",
        "USA_SOCIAL_SECURITY_NUMBER": "SSN",

        # GCP DLP
        "US_SOCIAL_SECURITY_NUMBER": "SSN",
        "PERSON_NAME": "NAME",

        # Purview
        "U.S. Social Security Number (SSN)": "SSN",
        "Person's Name": "NAME",

        # Presidio
        "CREDIT_CARD": "CREDIT_CARD",  # Same
        "US_SSN": "SSN",

        # ... hundreds more mappings
    }

    def normalize(self, vendor_type: str, source: str) -> str:
        """Normalize a vendor entity type to OpenLabels canonical type."""

        # Try exact match first
        if vendor_type in self.MAPPINGS:
            return self.MAPPINGS[vendor_type]

        # Try case-insensitive
        for key, value in self.MAPPINGS.items():
            if key.lower() == vendor_type.lower():
                return value

        # Pass through unknown types (logged for future mapping)
        logger.warning(f"Unknown entity type: {vendor_type} from {source}")
        return vendor_type
```

### Metadata Normalizer

Maps platform-specific metadata to normalized context.

```python
class MetadataNormalizer:
    """Normalizes metadata across all platforms."""

    # Permission mapping to exposure levels
    PERMISSION_MAP = {
        # AWS S3
        "private": ExposureLevel.PRIVATE,
        "authenticated-read": ExposureLevel.ORG_WIDE,
        "public-read": ExposureLevel.PUBLIC,
        "public-read-write": ExposureLevel.PUBLIC,
        "bucket-owner-full-control": ExposureLevel.PRIVATE,

        # GCP GCS
        "allUsers": ExposureLevel.PUBLIC,
        "allAuthenticatedUsers": ExposureLevel.ORG_WIDE,
        "projectViewer": ExposureLevel.INTERNAL,
        "projectEditor": ExposureLevel.INTERNAL,

        # Azure Blob
        "None": ExposureLevel.PRIVATE,
        "Blob": ExposureLevel.PUBLIC,
        "Container": ExposureLevel.PUBLIC,

        # NTFS / Windows
        "Authenticated Users": ExposureLevel.ORG_WIDE,
        "Everyone": ExposureLevel.PUBLIC,
        "Domain Users": ExposureLevel.INTERNAL,
        "BUILTIN\\Users": ExposureLevel.ORG_WIDE,
        "BUILTIN\\Administrators": ExposureLevel.PRIVATE,

        # POSIX / Linux (octal)
        "o+r": ExposureLevel.PUBLIC,   # world readable
        "o+rw": ExposureLevel.PUBLIC,  # world read-write
        "g+r": ExposureLevel.INTERNAL, # group readable

        # SharePoint / OneDrive
        "Anyone with link": ExposureLevel.PUBLIC,
        "Anyone with link (edit)": ExposureLevel.PUBLIC,
        "People in org with link": ExposureLevel.INTERNAL,
        "People in org with link (edit)": ExposureLevel.INTERNAL,
        "Specific people": ExposureLevel.PRIVATE,
    }

    def get_exposure_level(self, permissions: List[str]) -> ExposureLevel:
        """Determine highest exposure level from permissions list."""

        max_exposure = ExposureLevel.PRIVATE

        for perm in permissions:
            if perm in self.PERMISSION_MAP:
                level = self.PERMISSION_MAP[perm]
                if level.value > max_exposure.value:
                    max_exposure = level

        return max_exposure
```

---

## Scanner (Content Classification)

The **Scanner** is the built-in classification engine for users without existing DLP capabilities (Macie, DLP, Purview). It analyzes file content directly using patterns, checksums, and ML.

The Scanner is implemented as an adapter, producing the same `NormalizedInput` as Labeler adapters. This enables seamless combination: run the Labeler to pull existing classifications, then run the Scanner to verify with content analysis.

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
│  │    Archive? → Expand    Image/PDF? → Queue OCR    Text? → Direct    │   │
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
│  │    │  Financial   │  │  Government  │  │  Dictionary  │             │   │
│  │    │  Detector    │  │  Detector    │  │  Detector    │             │   │
│  │    │              │  │              │  │              │             │   │
│  │    │ • CUSIP      │  │ • Classif.   │  │ • Drug names │             │   │
│  │    │ • ISIN       │  │ • CAGE codes │  │ • Diagnoses  │             │   │
│  │    │ • SWIFT      │  │ • Contracts  │  │ • Facilities │             │   │
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
│  │                    Normalized Output                                 │   │
│  │    NormalizedInput(entities=[...], context={...})                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Scanner Implementation

```python
class ScannerAdapter:
    """
    Scanner adapter - detects entities in content.

    Like other adapters, produces NormalizedInput.
    Unlike other adapters, it analyzes raw content rather than
    consuming external findings.
    """

    def __init__(
        self,
        enable_ocr: bool = True,
        parallel: bool = True,
    ):
        self.orchestrator = DetectorOrchestrator(
            parallel=parallel,
        )
        self.ocr_worker = OCRWorker() if enable_ocr else None
        self.archive_expander = ArchiveExpander()

    def extract(
        self,
        content: bytes,
        metadata: dict,  # File metadata (size, name, permissions, etc.)
    ) -> NormalizedInput:
        """Extract entities from content and normalize context."""

        file_type = self._detect_file_type(content, metadata.get("name", ""))

        # Handle archives
        if file_type in ("zip", "tar", "gz", "7z"):
            return self._extract_archive(content, metadata)

        # Extract text
        if file_type in ("pdf", "png", "jpg", "jpeg", "tiff", "bmp"):
            text = self._extract_with_ocr(content, file_type)
        else:
            text = self._extract_text(content, file_type)

        # Run detection
        spans = self.orchestrator.detect(text)

        # Convert spans to entities
        entities = self._spans_to_entities(spans)

        # Normalize context
        context = self._normalize_context(metadata)

        return NormalizedInput(entities=entities, context=context)

    def _extract_with_ocr(self, content: bytes, file_type: str) -> str:
        """Extract text using RapidOCR (lazy-loaded)."""
        if self.ocr_worker is None:
            raise RuntimeError("OCR not enabled")
        return self.ocr_worker.extract(content, file_type)

    def _spans_to_entities(self, spans: List[Span]) -> List[Entity]:
        """Convert detector spans to normalized entities."""

        # Aggregate by entity type
        entity_counts = {}
        for span in spans:
            key = span.entity_type
            if key not in entity_counts:
                entity_counts[key] = {
                    "count": 0,
                    "max_confidence": 0.0,
                    "positions": [],
                }
            entity_counts[key]["count"] += 1
            entity_counts[key]["max_confidence"] = max(
                entity_counts[key]["max_confidence"],
                span.confidence
            )
            entity_counts[key]["positions"].append((span.start, span.end))

        entities = []
        for entity_type, data in entity_counts.items():
            entities.append(Entity(
                type=entity_type,
                count=data["count"],
                confidence=data["max_confidence"],
                weight=ENTITY_REGISTRY.get(entity_type, {}).get("weight", 5),
                source="scanner",
                positions=data["positions"],
            ))

        return entities
```

### OCR Worker

```python
class OCRWorker:
    """
    RapidOCR-based text extraction.

    Always-on, lazy-loaded. When first image/PDF is encountered,
    the model loads and stays loaded for the session.
    """

    def __init__(self):
        self._ocr = None  # Lazy-loaded

    @property
    def ocr(self):
        """Lazy-load RapidOCR on first use."""
        if self._ocr is None:
            from rapidocr_onnxruntime import RapidOCR
            self._ocr = RapidOCR()
        return self._ocr

    def extract(self, content: bytes, file_type: str) -> str:
        """Extract text from image or PDF."""

        if file_type == "pdf":
            return self._extract_pdf(content)
        else:
            return self._extract_image(content)

    def _extract_image(self, content: bytes) -> str:
        """Extract text from image bytes."""
        import numpy as np
        from PIL import Image
        import io

        image = Image.open(io.BytesIO(content))
        image_array = np.array(image)

        result, _ = self.ocr(image_array)

        if result is None:
            return ""

        # result is list of (bbox, text, confidence)
        texts = [item[1] for item in result]
        return "\n".join(texts)

    def _extract_pdf(self, content: bytes) -> str:
        """Extract text from PDF, using OCR for scanned pages."""
        import pdfplumber
        import io

        texts = []

        with pdfplumber.open(io.BytesIO(content)) as pdf:
            for page in pdf.pages:
                # Try text extraction first
                text = page.extract_text()

                if text and len(text.strip()) > 50:
                    # Has embedded text
                    texts.append(text)
                else:
                    # Scanned page - use OCR
                    image = page.to_image(resolution=150).original
                    image_array = np.array(image)
                    result, _ = self.ocr(image_array)
                    if result:
                        texts.extend([item[1] for item in result])

        return "\n".join(texts)
```

---

## Scoring Engine

### The Formula

```python
from math import log
from typing import List
from dataclasses import dataclass


@dataclass
class ScoringResult:
    """Complete scoring result."""
    score: int                    # 0-100
    content_score: float          # Before exposure multiplier
    exposure_multiplier: float    # From context
    level: str                    # "CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"
    entities: List[Entity]        # All detected entities
    co_occurrence_rules: List[str]  # Triggered rules
    scan_triggers: List[str]      # Why scan was triggered (if applicable)


class RiskScorer:
    """
    OpenLabels scoring engine.

    Formula (calibrated January 2026):
        WEIGHT_SCALE = 4.0
        content_score = Σ(weight × WEIGHT_SCALE × (1 + ln(count)) × confidence)
        content_score *= co_occurrence_multiplier
        exposure_multiplier = f(context)
        final_score = min(100, content_score × exposure_multiplier)
    """

    # Exposure multipliers
    EXPOSURE_MULTIPLIERS = {
        ExposureLevel.PRIVATE: 1.0,
        ExposureLevel.INTERNAL: 1.2,
        ExposureLevel.ORG_WIDE: 1.8,
        ExposureLevel.PUBLIC: 2.5,
    }

    # Co-occurrence multipliers
    # Categories from registry: direct_identifier, health_info, financial, credential, etc.
    CO_OCCURRENCE_RULES = {
        "hipaa_phi": {
            "condition": lambda e: has_category(e, "direct_identifier") and has_category(e, "health_info"),
            "multiplier": 2.0,
            "description": "HIPAA PHI (direct ID + health data)",
        },
        "identity_theft": {
            "condition": lambda e: has_category(e, "direct_identifier") and has_category(e, "financial"),
            "multiplier": 1.8,
            "description": "Identity theft risk (direct ID + financial)",
        },
        "credential_exposure": {
            "condition": lambda e: has_category(e, "credential"),
            "multiplier": 1.5,
            "description": "Credential exposure",
        },
        "phi_without_id": {
            "condition": lambda e: has_category(e, "quasi_identifier") and has_category(e, "health_info"),
            "multiplier": 1.5,
            "description": "PHI without direct identifier",
        },
        "phi_with_contact": {
            "condition": lambda e: has_category(e, "contact") and has_category(e, "health_info"),
            "multiplier": 1.4,
            "description": "Health info with contact details",
        },
        "full_identity": {
            "condition": lambda e: has_category(e, "direct_identifier") and has_category(e, "quasi_identifier") and has_category(e, "financial"),
            "multiplier": 2.2,
            "description": "Full identity package (direct ID + quasi ID + financial)",
        },
        "classified_data": {
            "condition": lambda e: has_category(e, "classification_marking"),
            "multiplier": 2.5,
            "description": "Classified information",
        },
    }

    def score(self, input: NormalizedInput) -> ScoringResult:
        """Calculate risk score from normalized input."""

        entities = input.entities
        context = input.context

        if not entities:
            # No entities - score based on exposure only
            return self._score_exposure_only(context)

        # Step 1: Calculate content score (with WEIGHT_SCALE calibration)
        WEIGHT_SCALE = 4.0
        content_score = sum(
            entity.weight * WEIGHT_SCALE * (1 + log(max(entity.count, 1))) * entity.confidence
            for entity in entities
        )

        # Step 2: Apply co-occurrence multipliers
        co_occurrence_mult = 1.0
        triggered_rules = []

        for rule_name, rule in self.CO_OCCURRENCE_RULES.items():
            if rule["condition"](entities):
                co_occurrence_mult = max(co_occurrence_mult, rule["multiplier"])
                triggered_rules.append(rule_name)

        content_score *= co_occurrence_mult

        # Step 3: Calculate exposure multiplier
        exposure_mult = self.EXPOSURE_MULTIPLIERS[context.exposure]

        # Additional context adjustments
        if context.encryption == "none":
            exposure_mult *= 1.3
        if not context.access_logging:
            exposure_mult *= 1.1
        if context.staleness_days > 365:
            exposure_mult *= 1.2
        if context.cross_account_access:
            exposure_mult *= 1.3

        # Step 4: Calculate final score
        final_score = min(100, int(content_score * exposure_mult))

        # Step 5: Determine level
        level = self._score_to_level(final_score)

        return ScoringResult(
            score=final_score,
            content_score=content_score,
            exposure_multiplier=exposure_mult,
            level=level,
            entities=entities,
            co_occurrence_rules=triggered_rules,
            scan_triggers=[],
        )

    def _score_exposure_only(self, context: NormalizedContext) -> ScoringResult:
        """Score when no entities found (exposure risk only)."""

        base = 0

        if context.exposure == ExposureLevel.PUBLIC:
            base = 15  # Public but unknown content
        elif context.exposure == ExposureLevel.ORG_WIDE:
            base = 10

        if context.encryption == "none":
            base += 5

        return ScoringResult(
            score=base,
            content_score=0,
            exposure_multiplier=1.0,
            level=self._score_to_level(base),
            entities=[],
            co_occurrence_rules=[],
            scan_triggers=[],
        )

    def _score_to_level(self, score: int) -> str:
        """Convert numeric score to risk level (calibrated thresholds)."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 55:
            return "HIGH"
        elif score >= 31:
            return "MEDIUM"
        elif score >= 11:
            return "LOW"
        else:
            return "MINIMAL"
```

### Merger

```python
class EntityMerger:
    """
    Merges entities from multiple adapters.

    Strategy: Conservative union
    - If same entity type from multiple sources, take max confidence
    - If sources disagree on presence, include it (safety first)
    """

    def merge(self, inputs: List[NormalizedInput]) -> NormalizedInput:
        """Merge multiple adapter outputs into one."""

        if len(inputs) == 1:
            return inputs[0]

        # Merge entities
        merged_entities = {}

        for input in inputs:
            for entity in input.entities:
                key = entity.type

                if key not in merged_entities:
                    merged_entities[key] = entity
                else:
                    existing = merged_entities[key]
                    # Take maximum count and confidence (conservative)
                    merged_entities[key] = Entity(
                        type=entity.type,
                        count=max(existing.count, entity.count),
                        confidence=max(existing.confidence, entity.confidence),
                        weight=entity.weight,
                        source=f"{existing.source}+{entity.source}",
                        positions=existing.positions + entity.positions,
                    )

        # Merge context (take most restrictive view)
        merged_context = self._merge_contexts([i.context for i in inputs])

        return NormalizedInput(
            entities=list(merged_entities.values()),
            context=merged_context,
        )

    def _merge_contexts(self, contexts: List[NormalizedContext]) -> NormalizedContext:
        """Merge contexts, taking most conservative values."""

        # Take highest exposure (most pessimistic)
        max_exposure = max(c.exposure for c in contexts)

        # Take worst encryption status
        encryptions = [c.encryption for c in contexts]
        if "none" in encryptions:
            encryption = "none"
        elif "platform" in encryptions:
            encryption = "platform"
        else:
            encryption = "customer_managed"

        return NormalizedContext(
            exposure=max_exposure,
            cross_account_access=any(c.cross_account_access for c in contexts),
            anonymous_access=any(c.anonymous_access for c in contexts),
            encryption=encryption,
            versioning=all(c.versioning for c in contexts),
            access_logging=all(c.access_logging for c in contexts),
            retention_policy=all(c.retention_policy for c in contexts),
            last_modified=min(c.last_modified for c in contexts if c.last_modified),
            last_accessed=max(
                (c.last_accessed for c in contexts if c.last_accessed),
                default=None
            ),
            staleness_days=max(c.staleness_days for c in contexts),
            has_classification=any(c.has_classification for c in contexts),
            classification_source="+".join(
                c.classification_source for c in contexts if c.classification_source
            ),
            file_size=max(c.file_size for c in contexts),
            file_type=contexts[0].file_type,
            is_archive=any(c.is_archive for c in contexts),
        )
```

---

## Scan Triggers

When to activate the scanner even if labels exist:

```python
from enum import Enum
from typing import Tuple, List


class ScanTrigger(Enum):
    """Reasons to trigger a scan."""
    NO_LABELS = "no_labels"                      # No external classification
    PUBLIC_ACCESS = "public_access"              # Public = always verify
    ORG_WIDE = "org_wide"                        # Broadly shared = verify
    NO_ENCRYPTION = "no_encryption"              # Unprotected = verify
    STALE_DATA = "stale_data"                    # Old data = verify
    LOW_CONFIDENCE_HIGH_RISK = "low_conf_high_risk"  # Uncertain critical finding


CONFIDENCE_THRESHOLD = 0.80  # Single threshold, no per-type variation
HIGH_RISK_WEIGHT_THRESHOLD = 8  # Weight >= 8 is high risk


def should_scan(
    entities: List[Entity],
    context: NormalizedContext
) -> Tuple[bool, List[ScanTrigger]]:
    """
    Determine if scanning is needed and why.

    Returns:
        (should_scan, list_of_triggers)
    """

    triggers = []

    # No labels = must scan
    if not entities or not context.has_classification:
        triggers.append(ScanTrigger.NO_LABELS)

    # Exposure-based triggers
    if context.exposure == ExposureLevel.PUBLIC:
        triggers.append(ScanTrigger.PUBLIC_ACCESS)
    elif context.exposure == ExposureLevel.ORG_WIDE:
        triggers.append(ScanTrigger.ORG_WIDE)

    # Protection gaps
    if context.encryption == "none":
        triggers.append(ScanTrigger.NO_ENCRYPTION)

    # Staleness
    if context.staleness_days > 365:
        triggers.append(ScanTrigger.STALE_DATA)

    # High-risk entity with low/medium confidence = verify
    for entity in entities:
        is_high_risk = entity.weight >= HIGH_RISK_WEIGHT_THRESHOLD
        is_uncertain = entity.confidence < CONFIDENCE_THRESHOLD

        if is_high_risk and is_uncertain:
            triggers.append(ScanTrigger.LOW_CONFIDENCE_HIGH_RISK)
            break  # One is enough

    return len(triggers) > 0, triggers
```

### Decision Matrix

| Scenario | Scan? | Reason |
|----------|-------|--------|
| No labels | ✓ | Nothing to go on |
| Labels exist, private, high confidence | ✗ | Trust external tool |
| Labels exist, **public** | ✓ | Exposure too high to trust |
| Labels exist, **no encryption** | ✓ | Protection gap |
| Labels exist, **stale >1yr** | ✓ | Verify still accurate |
| Labels: **SSN @ 0.65 confidence** | ✓ | High risk + uncertain |
| Labels: **EMAIL @ 0.35 confidence** | ✗ | Lower risk, trust it |
| Labels: **CREDIT_CARD @ 0.90 confidence** | ✗ | High confidence, trust it |

---

## OCR Priority Queue

OCR jobs are prioritized by metadata risk score:

```python
from dataclasses import dataclass
from heapq import heappush, heappop
from typing import Optional
import threading


@dataclass(order=True)
class OCRJob:
    """A prioritized OCR job."""
    priority: int  # Higher = more urgent (negated for min-heap)
    path: str
    content: bytes
    context: NormalizedContext
    callback: callable


class OCRPriorityQueue:
    """
    Priority queue for OCR jobs.

    Higher exposure = higher priority.
    """

    def __init__(self):
        self._queue = []
        self._lock = threading.Lock()

    def add(
        self,
        path: str,
        content: bytes,
        context: NormalizedContext,
        triggers: List[ScanTrigger],
        callback: callable,
    ):
        """Add a job to the queue with calculated priority."""

        priority = self._calculate_priority(context, triggers)

        job = OCRJob(
            priority=-priority,  # Negate for max-heap behavior
            path=path,
            content=content,
            context=context,
            callback=callback,
        )

        with self._lock:
            heappush(self._queue, job)

    def get(self) -> Optional[OCRJob]:
        """Get highest priority job."""
        with self._lock:
            if self._queue:
                return heappop(self._queue)
        return None

    def _calculate_priority(
        self,
        context: NormalizedContext,
        triggers: List[ScanTrigger],
    ) -> int:
        """Calculate job priority based on context and triggers."""

        priority = 0

        # Exposure-based priority
        priority += {
            ExposureLevel.PRIVATE: 0,
            ExposureLevel.INTERNAL: 10,
            ExposureLevel.ORG_WIDE: 30,
            ExposureLevel.PUBLIC: 50,
        }[context.exposure]

        # Trigger-based boosts
        if ScanTrigger.NO_ENCRYPTION in triggers:
            priority += 20
        if ScanTrigger.LOW_CONFIDENCE_HIGH_RISK in triggers:
            priority += 25
        if ScanTrigger.STALE_DATA in triggers:
            priority += 5

        return priority


# Priority examples:
# 75: Public + no encryption + uncertain SSN → IMMEDIATE
# 50: Public bucket, unknown content → HIGH
# 30: Over-exposed internal share → MEDIUM
# 0:  Private, encrypted, no triggers → LOW
```

---

## Agent (On-Prem)

For local/on-prem file systems, an agent collects metadata and runs scans:

```python
import os
import stat
import platform
from typing import Optional
from datetime import datetime


class OpenLabelsAgent:
    """
    Agent for on-prem / local file systems.

    Responsibilities:
    - Collect file system metadata
    - Normalize permissions to exposure levels
    - Trigger scans based on policy
    """

    def __init__(self, scanner: ScannerAdapter):
        self.scanner = scanner
        self.is_windows = platform.system() == "Windows"

    def scan_path(self, path: str) -> ScoringResult:
        """Scan a file and return risk score."""

        # Collect metadata
        context = self.collect_metadata(path)

        # Read content
        with open(path, "rb") as f:
            content = f.read()

        # Run scanner
        input = self.scanner.extract(content, {
            "name": os.path.basename(path),
            "path": path,
            "size": len(content),
        })

        # Override context with local metadata
        input.context = context

        # Score
        scorer = RiskScorer()
        return scorer.score(input)

    def collect_metadata(self, path: str) -> NormalizedContext:
        """Collect and normalize file system metadata."""

        stat_info = os.stat(path)

        if self.is_windows:
            exposure = self._get_ntfs_exposure(path)
            encryption = self._check_efs_encryption(path)
        else:
            exposure = self._get_posix_exposure(stat_info.st_mode)
            encryption = "none"  # POSIX doesn't have native encryption

        return NormalizedContext(
            exposure=exposure,
            cross_account_access=False,  # N/A for local
            anonymous_access=exposure == ExposureLevel.PUBLIC,
            encryption=encryption,
            versioning=False,
            access_logging=False,
            retention_policy=False,
            last_modified=datetime.fromtimestamp(stat_info.st_mtime),
            last_accessed=datetime.fromtimestamp(stat_info.st_atime),
            staleness_days=self._calc_staleness(stat_info.st_mtime),
            has_classification=False,
            classification_source="none",
            file_size=stat_info.st_size,
            file_type=self._guess_type(path),
            is_archive=self._is_archive(path),
        )

    def _get_posix_exposure(self, mode: int) -> ExposureLevel:
        """Map POSIX permissions to exposure level."""

        # World readable
        if mode & stat.S_IROTH:
            return ExposureLevel.PUBLIC

        # Group readable
        if mode & stat.S_IRGRP:
            return ExposureLevel.INTERNAL

        return ExposureLevel.PRIVATE

    def _get_ntfs_exposure(self, path: str) -> ExposureLevel:
        """Map NTFS ACL to exposure level."""

        try:
            import win32security

            sd = win32security.GetFileSecurity(
                path,
                win32security.DACL_SECURITY_INFORMATION
            )
            dacl = sd.GetSecurityDescriptorDacl()

            if dacl is None:
                return ExposureLevel.PRIVATE

            # Check for well-known SIDs
            EVERYONE_SID = win32security.ConvertStringSidToSid("S-1-1-0")
            AUTH_USERS_SID = win32security.ConvertStringSidToSid("S-1-5-11")
            USERS_SID = win32security.ConvertStringSidToSid("S-1-5-32-545")

            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                sid = ace[2]

                if sid == EVERYONE_SID:
                    return ExposureLevel.PUBLIC
                if sid == AUTH_USERS_SID or sid == USERS_SID:
                    return ExposureLevel.ORG_WIDE

            return ExposureLevel.PRIVATE

        except ImportError:
            # pywin32 not installed
            return ExposureLevel.PRIVATE
```

---

## CLI & Query Language

### Commands

```bash
# Scan and score
openlabels scan <path>
openlabels scan s3://bucket/prefix
openlabels scan gs://bucket/prefix
openlabels scan azure://container/path

# Find with filters
openlabels find <path> --where "<filter>"

# Actions
openlabels quarantine <path> --where "<filter>" --to <dest>
openlabels move <path> --where "<filter>" --to <dest>
openlabels delete <path> --where "<filter>" --confirm
openlabels tag <path> --where "<filter>"
openlabels encrypt <path> --where "<filter>" --key <kms-key>
openlabels restrict <path> --where "<filter>" --acl private

# Reporting
openlabels report <path> --format json|csv|html
openlabels heatmap <path>

# Interactive
openlabels shell <path>
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
<enum>       := public | org_wide | internal | private
             | none | platform | customer_managed
```

### Examples

```bash
# Quarantine high-risk stale data
openlabels quarantine s3://prod-bucket \
  --where "score > 75 AND last_accessed > 5y" \
  --to s3://quarantine-bucket

# Find public SSNs
openlabels find s3://data-lake \
  --where "exposure = public AND has(SSN)"

# Delete old low-value data (with preview)
openlabels delete /mnt/fileshare \
  --where "score < 20 AND last_accessed > 7y" \
  --dry-run

# Complex query
openlabels find . --where "
  score > 75
  AND exposure >= org_wide
  AND last_accessed > 1y
  AND (has(SSN) OR has(CREDIT_CARD))
  AND encryption = none
"
```

### CLI Implementation

```python
import click
from typing import Optional


@click.group()
def cli():
    """OpenLabels - Universal Data Risk Scoring"""
    pass


@cli.command()
@click.argument("path")
@click.option("--where", help="Filter expression")
@click.option("--recursive", "-r", is_flag=True, help="Scan recursively")
def find(path: str, where: Optional[str], recursive: bool):
    """Find objects matching filter criteria."""

    client = OpenLabelsClient()
    filter = Filter.parse(where) if where else None

    for result in client.find(path, filter=filter, recursive=recursive):
        click.echo(f"{result.path}\tScore: {result.score}\t{result.entities_summary}")


@cli.command()
@click.argument("source")
@click.option("--where", required=True, help="Filter expression")
@click.option("--to", "dest", required=True, help="Destination path")
@click.option("--dry-run", is_flag=True, help="Preview without moving")
def quarantine(source: str, where: str, dest: str, dry_run: bool):
    """Move matching objects to quarantine location."""

    client = OpenLabelsClient()
    filter = Filter.parse(where)

    matches = list(client.find(source, filter=filter))

    if dry_run:
        click.echo(f"Would quarantine {len(matches)} objects:")
        for m in matches[:10]:
            click.echo(f"  {m.path} (score: {m.score})")
        if len(matches) > 10:
            click.echo(f"  ... and {len(matches) - 10} more")
        return

    with click.progressbar(matches, label="Quarantining") as bar:
        for match in bar:
            client.move(match.path, f"{dest}/{match.basename}")

    click.echo(f"Quarantined {len(matches)} objects to {dest}")


@cli.command()
@click.argument("path")
@click.option("--format", "fmt", type=click.Choice(["json", "csv", "html"]), default="json")
@click.option("--output", "-o", help="Output file (default: stdout)")
def report(path: str, fmt: str, output: Optional[str]):
    """Generate risk report."""

    client = OpenLabelsClient()
    results = client.scan(path, recursive=True)

    if fmt == "json":
        data = [r.to_dict() for r in results]
        content = json.dumps(data, indent=2)
    elif fmt == "csv":
        content = results_to_csv(results)
    else:
        content = results_to_html(results)

    if output:
        with open(output, "w") as f:
            f.write(content)
        click.echo(f"Report written to {output}")
    else:
        click.echo(content)


@cli.command()
@click.argument("path")
def heatmap(path: str):
    """Display risk heatmap of directory structure."""

    client = OpenLabelsClient()
    tree = client.scan_tree(path)

    click.echo(render_heatmap(tree))


def render_heatmap(tree: dict, indent: int = 0) -> str:
    """Render a directory tree with risk scores."""

    lines = []
    prefix = "  " * indent

    for name, data in sorted(tree.items()):
        score = data.get("avg_score", 0)
        bar = score_to_bar(score)
        indicator = "🔴" if score >= 75 else "🟡" if score >= 50 else "🟢" if score >= 25 else "⚪"

        if data.get("children"):
            lines.append(f"{prefix}📁 {name:<40} {bar} {score:>3} avg {indicator}")
            lines.append(render_heatmap(data["children"], indent + 1))
        else:
            lines.append(f"{prefix}📄 {name:<40} {bar} {score:>3} {indicator}")

    return "\n".join(lines)


def score_to_bar(score: int, width: int = 20) -> str:
    """Convert score to visual bar."""
    filled = int(score / 100 * width)
    return "█" * filled + "░" * (width - filled)
```

### SDK Usage

```python
from openlabels import Client, Filter
from openlabels.adapters import macie, scanner

# Initialize client
client = Client()

# Pattern 1: Score with Macie findings
result = client.score(
    adapters=[
        macie.extract(findings, s3_metadata)
    ]
)
print(f"Score: {result.score}")

# Pattern 2: Score with scanner
result = client.score(
    adapters=[
        scanner.extract(file_content, file_metadata)
    ]
)

# Pattern 3: Defense in depth (conservative union)
result = client.score(
    adapters=[
        macie.extract(findings, s3_metadata),
        scanner.extract(file_content, file_metadata)
    ]
)

# Pattern 4: Programmatic filtering
high_risk_stale = Filter(
    score__gt=75,
    last_accessed__gt="5y",
    exposure__gte="org_wide"
)

for obj in client.find("s3://bucket", where=high_risk_stale):
    print(f"{obj.path}: {obj.score}")

# Pattern 5: Quarantine
client.quarantine(
    source="s3://prod",
    dest="s3://quarantine",
    where=Filter(score__gt=80, exposure="public"),
    dry_run=False
)
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
│   ├── openlabels-specification-v0.2.md
│   ├── openlabels-architecture-v2.md      # This document
│   ├── openlabels-scoring-methodology.md
│   ├── openlabels-entity-registry-v1.md
│   ├── openlabels-international-entities.md
│   └── calibration-plan.md
│
├── openlabels/
│   ├── __init__.py
│   ├── client.py                    # High-level client API
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── types.py                 # Entity, NormalizedContext, etc.
│   │   ├── registry.py              # Entity types + weights
│   │   ├── normalizer.py            # Entity type normalization
│   │   ├── metadata.py              # Metadata normalization
│   │   ├── merger.py                # Combine adapter outputs
│   │   ├── scorer.py                # The scoring engine
│   │   └── triggers.py              # Scan trigger logic
│   │
│   ├── adapters/
│   │   ├── __init__.py
│   │   ├── base.py                  # Adapter protocol
│   │   ├── macie.py                 # AWS Macie + S3
│   │   ├── dlp.py                   # GCP DLP + GCS
│   │   ├── purview.py               # Azure Purview + Blob
│   │   ├── presidio.py              # Microsoft Presidio
│   │   │
│   │   └── scanner/                 # Scanner IS an adapter
│   │       ├── __init__.py
│   │       ├── adapter.py           # ScannerAdapter
│   │       ├── orchestrator.py      # Detector orchestration
│   │       ├── detectors/
│   │       │   ├── __init__.py
│   │       │   ├── base.py
│   │       │   ├── checksum.py      # SSN, CC, NPI, IBAN, VIN
│   │       │   ├── patterns.py      # Names, dates, addresses
│   │       │   ├── secrets.py       # API keys, tokens
│   │       │   ├── financial.py     # CUSIP, ISIN, crypto
│   │       │   ├── government.py    # Classifications
│   │       │   └── dictionaries.py  # Drug names, diagnoses
│   │       ├── ocr/
│   │       │   ├── __init__.py
│   │       │   ├── worker.py        # RapidOCR integration
│   │       │   └── queue.py         # Priority queue
│   │       ├── archive/
│   │       │   ├── __init__.py
│   │       │   └── expander.py      # Zip, tar, etc.
│   │       └── context_enhancer.py  # False positive filtering
│   │
│   ├── agent/
│   │   ├── __init__.py
│   │   ├── collector.py             # Metadata collection
│   │   ├── ntfs.py                  # Windows ACL handling
│   │   ├── posix.py                 # Linux/Mac permissions
│   │   └── watcher.py               # File system monitoring
│   │
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── main.py                  # CLI entry point
│   │   ├── commands/
│   │   │   ├── scan.py
│   │   │   ├── find.py
│   │   │   ├── quarantine.py
│   │   │   ├── report.py
│   │   │   └── heatmap.py
│   │   └── filter.py                # Query language parser
│   │
│   └── output/
│       ├── __init__.py
│       ├── embed.py                 # Embedded label writer (native metadata)
│       ├── virtual.py               # Virtual label writer (xattr + index)
│       └── report.py                # Report generators
│
├── tests/
│   ├── __init__.py
│   ├── test_scorer.py
│   ├── test_adapters/
│   ├── test_scanner/
│   └── fixtures/
│
└── data/
    ├── ai4privacy.jsonl             # Calibration data
    ├── claude.jsonl
    ├── corpus.jsonl
    ├── negative.jsonl
    └── template.jsonl
```

---

## API Reference

### Client API

```python
class Client:
    """High-level OpenLabels client."""

    def score(
        self,
        adapters: List[Adapter],
        path: Optional[str] = None,
    ) -> ScoringResult:
        """Score using one or more adapters."""

    def scan(
        self,
        path: str,
        recursive: bool = False,
    ) -> Iterator[ScoringResult]:
        """Scan path(s) and return results."""

    def find(
        self,
        path: str,
        filter: Optional[Filter] = None,
        recursive: bool = True,
    ) -> Iterator[ScoringResult]:
        """Find objects matching filter."""

    def quarantine(
        self,
        source: str,
        dest: str,
        where: Filter,
        dry_run: bool = False,
    ) -> QuarantineResult:
        """Move matching objects to quarantine."""

    def move(
        self,
        source: str,
        dest: str,
    ) -> None:
        """Move a single object."""

    def delete(
        self,
        path: str,
        where: Filter,
        confirm: bool = False,
    ) -> DeleteResult:
        """Delete matching objects."""

    def report(
        self,
        path: str,
        format: str = "json",
    ) -> str:
        """Generate risk report."""
```

### Scoring Result

```python
@dataclass
class ScoringResult:
    """Complete scoring result."""

    # Score
    score: int                      # 0-100
    level: str                      # CRITICAL, HIGH, MEDIUM, LOW, MINIMAL

    # Breakdown
    content_score: float            # Before exposure multiplier
    exposure_multiplier: float      # From context

    # Details
    entities: List[Entity]          # All detected entities
    context: NormalizedContext      # Normalized metadata
    co_occurrence_rules: List[str]  # Triggered rules
    scan_triggers: List[str]        # Why scan was triggered

    # Metadata
    path: str
    source: str                     # Adapter(s) used
    timestamp: datetime

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""

    def to_json(self) -> str:
        """Convert to JSON string."""

    @property
    def entities_summary(self) -> str:
        """Human-readable entity summary."""
        return ", ".join(f"{e.type} ({e.count})" for e in self.entities)
```

---

## Implementation Roadmap

### Phase 1: Core (MVP)

- [ ] Core types and interfaces
- [ ] Entity registry (303 types)
- [ ] Scoring engine with formula
- [ ] Merger with conservative union
- [ ] Basic CLI (scan, find)

### Phase 2: Adapters

- [ ] Macie adapter
- [ ] GCP DLP adapter
- [ ] Purview adapter
- [ ] Scanner adapter (patterns + checksums)

### Phase 3: Scanner

- [ ] Checksum detectors
- [ ] Pattern detectors
- [ ] Secrets detectors
- [ ] OCR worker (RapidOCR)
- [ ] Archive expander

### Phase 4: Agent

- [ ] POSIX permission collection
- [ ] NTFS ACL collection
- [ ] Local file scanning

### Phase 5: CLI & Actions

- [ ] Query language parser
- [ ] quarantine command
- [ ] move/delete commands
- [ ] report command
- [ ] heatmap command

### Phase 6: Polish

- [ ] Calibration with AI4Privacy data
- [ ] Performance optimization
- [ ] Documentation
- [ ] Test coverage

---

## Label Transport

### Overview

OpenLabels uses two transport mechanisms based on file type capabilities:

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   Does file format support native metadata?             │
│   (PDF, DOCX, images, etc.)                            │
│                                                         │
│        YES                         NO                   │
│         │                           │                   │
│         ▼                           ▼                   │
│   ┌───────────┐              ┌─────────────────┐       │
│   │ Embedded  │              │ Virtual Label   │       │
│   │ Label     │              │                 │       │
│   │           │              │ xattr stores:   │       │
│   │ Full JSON │              │ labelID:hash    │       │
│   │ in native │              │                 │       │
│   │ metadata  │              │ Index stores:   │       │
│   └───────────┘              │ full Label Set  │       │
│                              └─────────────────┘       │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Embedded Labels

For files with native metadata support, the full Label Set is embedded directly.

| Format | Metadata Location |
|--------|-------------------|
| PDF | XMP metadata (`http://openlabels.dev/ns/1.0/`) |
| DOCX/XLSX/PPTX | Custom Document Properties |
| JPEG/PNG/TIFF | XMP metadata or EXIF UserComment |
| MP4/MOV | XMP metadata |

### Virtual Labels

For files without native metadata, a pointer is stored in extended attributes:

```
xattr value = labelID:content_hash
Example:     ol_7f3a9b2c4d5e:e3b0c44298fc
```

| Platform | Attribute Name |
|----------|----------------|
| Linux | `user.openlabels` |
| macOS | `com.openlabels.label` |
| Windows | NTFS ADS `openlabels` |
| S3 | `x-amz-meta-openlabels` |
| GCS | `openlabels` metadata |
| Azure Blob | `openlabels` metadata |

### Label Operations

```python
import os
import secrets
import hashlib
from typing import Optional

def generate_label_id() -> str:
    """Generate immutable label ID."""
    return "ol_" + secrets.token_hex(6)

def compute_content_hash(content: bytes) -> str:
    """Compute content hash for version tracking."""
    return hashlib.sha256(content).hexdigest()[:12]

def write_virtual_label(filepath: str, label_id: str, content_hash: str) -> None:
    """Write virtual label to extended attribute."""
    import subprocess
    value = f"{label_id}:{content_hash}"
    # Linux
    subprocess.run(["setfattr", "-n", "user.openlabels", "-v", value, filepath])

def read_virtual_label(filepath: str) -> Optional[tuple[str, str]]:
    """Read virtual label from extended attribute."""
    import subprocess
    result = subprocess.run(
        ["getfattr", "-n", "user.openlabels", "--only-values", filepath],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return None
    parts = result.stdout.strip().split(":")
    if len(parts) != 2:
        return None
    return parts[0], parts[1]  # label_id, content_hash
```

### The Index

Virtual labels require an index to resolve the full Label Set:

```sql
-- Core identity (immutable)
CREATE TABLE label_objects (
    label_id    TEXT PRIMARY KEY,
    tenant_id   UUID NOT NULL,
    created_at  TIMESTAMP NOT NULL
);

-- Version history (append-only)
CREATE TABLE label_versions (
    label_id      TEXT REFERENCES label_objects(label_id),
    content_hash  TEXT NOT NULL,
    scanned_at    TIMESTAMP NOT NULL,
    labels        JSONB NOT NULL,
    risk_score    INTEGER,
    exposure      TEXT,
    source        TEXT NOT NULL,

    PRIMARY KEY (label_id, content_hash)
);
```

### Database Backends

| Backend | Use Case | Connection String |
|---------|----------|-------------------|
| SQLite | Single-node, CLI, development | `~/.openlabels/index.db` (default) |
| PostgreSQL | Server mode, multi-tenant, production | `postgresql://user:pass@host/db` |

```python
from openlabels.output import create_index

# SQLite (default)
index = create_index()

# PostgreSQL (server mode)
index = create_index("postgresql://localhost/openlabels", tenant_id="acme-corp")
```

### File Type Matrix

| File Type | Transport | Source of Truth |
|-----------|-----------|-----------------|
| PDF, DOCX, images | Embedded | The file |
| CSV, JSON, TXT | Virtual (xattr) | The index |
| Archives (ZIP, TAR) | Virtual (xattr) | The index |
| Email (EML, MSG) | Virtual (xattr) | The index |
| Source code | Virtual (xattr) | The index |

---

## Content Integrity & Validation

### Hash Algorithm

OpenLabels uses SHA-256 as the default hash algorithm:

Format: `sha256:<64-character-hex-digest>`

| Algorithm | Format Prefix | Status |
|-----------|---------------|--------|
| SHA-256 | `sha256:` | Default, required |
| SHA-384 | `sha384:` | Optional |
| SHA-512 | `sha512:` | Optional |

MD5 and SHA-1 are explicitly NOT supported.

### Validation Rules

1. `version` MUST match pattern `^\d+\.\d+$`
2. `score` MUST be an integer in range [0, 100]
3. `tier` MUST be one of: "Critical", "High", "Medium", "Low", "Minimal"
4. `content_hash` MUST match pattern `^(sha256|sha384|sha512):[a-f0-9]+$`
5. `content_length` MUST be a non-negative integer
6. `entities` MUST contain at least one entity if `score` > 0
7. `confidence_avg` MUST be in range [0.0, 1.0]
8. `weight` MUST be an integer in range [1, 10]
9. `generated_at` MUST be a valid ISO 8601 timestamp

### Signature Field (Optional)

Tags can include an optional signature for authenticity verification:

```json
{
  "openlabels": {
    ...
    "signature": "ed25519:base64-encoded-signature"
  }
}
```

---

## JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://openlabels.dev/schema/v2.0/tag.json",
  "title": "OpenLabels Tag",
  "type": "object",
  "required": ["openlabels"],
  "properties": {
    "openlabels": {
      "type": "object",
      "required": [
        "version",
        "score",
        "tier",
        "content_hash",
        "content_length",
        "factors",
        "scoring",
        "provenance"
      ],
      "properties": {
        "version": {
          "type": "string",
          "pattern": "^\\d+\\.\\d+$"
        },
        "score": {
          "type": "integer",
          "minimum": 0,
          "maximum": 100
        },
        "tier": {
          "type": "string",
          "enum": ["Critical", "High", "Medium", "Low", "Minimal"]
        },
        "content_hash": {
          "type": "string",
          "pattern": "^(sha256|sha384|sha512):[a-f0-9]+$"
        },
        "content_length": {
          "type": "integer",
          "minimum": 0
        },
        "factors": {
          "type": "object",
          "required": ["entities"],
          "properties": {
            "entities": {
              "type": "array",
              "items": {
                "type": "object",
                "required": ["type", "category", "count", "confidence_avg", "weight"],
                "properties": {
                  "type": {"type": "string"},
                  "category": {"type": "string"},
                  "count": {"type": "integer", "minimum": 1},
                  "confidence_avg": {"type": "number", "minimum": 0, "maximum": 1},
                  "weight": {"type": "integer", "minimum": 1, "maximum": 10}
                }
              }
            },
            "exposure": {
              "type": "string",
              "enum": ["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"]
            },
            "exposure_multiplier": {
              "type": "number",
              "minimum": 1
            },
            "co_occurrence_rules": {
              "type": "array",
              "items": {"type": "string"}
            },
            "co_occurrence_multiplier": {
              "type": "number",
              "minimum": 1
            },
            "raw_score": {"type": "number"},
            "filtered": {
              "type": "array",
              "items": {
                "type": "object",
                "required": ["type", "count", "confidence_avg", "reason"],
                "properties": {
                  "type": {"type": "string"},
                  "count": {"type": "integer"},
                  "confidence_avg": {"type": "number"},
                  "reason": {"type": "string"}
                }
              }
            }
          }
        },
        "context": {
          "type": "object",
          "properties": {
            "encryption": {"type": "string"},
            "versioning": {"type": "boolean"},
            "access_logging": {"type": "boolean"},
            "staleness_days": {"type": "integer"},
            "classification_source": {"type": "string"}
          }
        },
        "scoring": {
          "type": "object",
          "required": ["algorithm", "confidence_threshold", "mode"],
          "properties": {
            "algorithm": {"type": "string"},
            "confidence_threshold": {"type": "number", "minimum": 0, "maximum": 1},
            "mode": {"type": "string", "enum": ["strict", "relaxed"]}
          }
        },
        "provenance": {
          "type": "object",
          "required": ["generator", "generated_at"],
          "properties": {
            "generator": {"type": "string"},
            "generator_org": {"type": "string"},
            "generated_at": {"type": "string", "format": "date-time"},
            "source_tool": {"type": "string"},
            "adapters_used": {
              "type": "array",
              "items": {"type": "string"}
            },
            "scan_duration_ms": {"type": "integer"}
          }
        },
        "signature": {
          "type": ["string", "null"]
        }
      }
    }
  }
}
```

---

## Security Considerations

### Tag Authenticity

When signatures are present, verify using the generator's public key before trusting tag data.

### Information Disclosure

OpenLabels tags reveal metadata about file contents:
- Entity types present
- Approximate counts
- Overall sensitivity level

Consider whether this metadata should be protected in your environment.

### Extended Attribute Security

Extended attributes may not survive all operations:

| Operation | xattr Preserved? |
|-----------|------------------|
| Local copy (cp -p) | Yes |
| rsync -X | Yes |
| Email attachment | No |
| Upload to web app | Usually no |
| ZIP archive | No |

Mitigations:
1. **Re-scan on xattr loss**: Detect missing xattr, re-scan file
2. **Verify content_hash**: If xattr present, verify file hasn't changed
3. **Index as backup**: Virtual labels can be recovered from index

### Denial of Service

Implementations SHOULD limit:
- Maximum label set size: 1 MB
- Maximum entities count: 10,000
- Metadata read timeout: 5 seconds

---

## Conformance

### Conformance Levels

| Level | Requirements |
|-------|--------------|
| **Reader** | Parse valid Label Sets, read embedded labels, resolve virtual labels via index |
| **Writer** | Generate valid Label Sets, write embedded/virtual labels, maintain index |
| **Full** | Reader + Writer + Exposure scoring |

### Reader Requirements

A conforming reader MUST:
1. Parse any valid OpenLabels Label Set JSON
2. Read embedded labels from native metadata (PDF, DOCX, images)
3. Read virtual labels from extended attributes
4. Resolve virtual labels via index lookup
5. Verify content_hash when requested
6. Handle unknown fields gracefully (ignore, don't error)

### Writer Requirements

A conforming writer MUST:
1. Generate valid JSON per schema
2. Use the standard scoring algorithm including exposure multipliers
3. Use only registered entity types in strict mode
4. Compute accurate content_hash and content_length
5. Include all required fields including context/exposure

---

## References

- [OpenLabels Entity Registry v1](./openlabels-entity-registry-v1.md)
- [OpenLabels International Entities](./openlabels-international-entities.md)

---

*This document is the authoritative architecture reference for OpenLabels v2. All implementation should align with this specification.*
