# OpenLabels Server Specification

**Version:** 1.0.0-draft
**Status:** Draft
**Document ID:** OL-SERVER-SPEC-001
**Last Updated:** February 2026

---

## Abstract

This document defines the OpenLabels Server specification, including the REST API contract, data models, authentication requirements, and integration interfaces. OpenLabels Server is a data classification and auto-labeling platform that enables organizations to scan, classify, and label sensitive data across file systems and cloud storage.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Data Models](#3-data-models)
4. [REST API](#4-rest-api)
5. [WebSocket API](#5-websocket-api)
6. [Authentication](#6-authentication)
7. [Adapters](#7-adapters)
8. [Labeling Interface](#8-labeling-interface)
9. [Configuration](#9-configuration)
10. [Error Handling](#10-error-handling)
11. [Security Considerations](#11-security-considerations)
12. [Conformance](#12-conformance)
13. [Appendix A: JSON Schemas](#appendix-a-json-schemas)
14. [Appendix B: Entity Types](#appendix-b-entity-types)

---

## 1. Introduction

### 1.1 Purpose

This specification defines:

- The REST API contract for OpenLabels Server
- Data models for scans, results, labels, and configuration
- Authentication and authorization requirements
- Adapter interfaces for storage backends
- Labeling integration with Microsoft Information Protection (MIP)

### 1.2 Scope

This specification covers:

- Server API endpoints and request/response formats
- WebSocket protocol for real-time updates
- Database schema requirements
- Authentication flows (OAuth 2.0 / OIDC)
- Adapter protocol for storage backends

This specification does NOT cover:

- Detection algorithms (see openlabels-architecture-v2.md)
- Scoring formulas (see openlabels-architecture-v2.md)
- GUI implementation details
- Deployment procedures

### 1.3 Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **Scan Target** | A configured location to scan (file path, SharePoint site, etc.) |
| **Scan Job** | A single execution of scanning a target |
| **Scan Result** | Classification data for a single file |
| **Sensitivity Label** | A Microsoft Information Protection (MIP) label |
| **Label Rule** | A mapping from risk tier or entity type to sensitivity label |
| **Adapter** | A module that provides access to a storage backend |
| **SIT** | Sensitive Information Type (e.g., SSN, CREDIT_CARD) |
| **Risk Tier** | Classification level: CRITICAL, HIGH, MEDIUM, LOW, MINIMAL |
| **Exposure Level** | Access scope: PRIVATE, INTERNAL, ORG_WIDE, PUBLIC |

---

## 3. Data Models

### 3.1 Tenant

Multi-tenancy support for SaaS deployments.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | REQUIRED | Unique tenant identifier |
| `name` | string | REQUIRED | Tenant display name |
| `azure_tenant_id` | string | OPTIONAL | Azure AD tenant ID |
| `created_at` | datetime | REQUIRED | Creation timestamp |

### 3.2 User

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | REQUIRED | Unique user identifier |
| `tenant_id` | UUID | REQUIRED | Associated tenant |
| `email` | string | REQUIRED | User email address |
| `name` | string | OPTIONAL | Display name |
| `role` | enum | REQUIRED | `admin` or `viewer` |
| `azure_oid` | string | OPTIONAL | Azure AD object ID |
| `created_at` | datetime | REQUIRED | Creation timestamp |

### 3.3 Scan Target

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | REQUIRED | Unique target identifier |
| `tenant_id` | UUID | REQUIRED | Associated tenant |
| `name` | string | REQUIRED | Display name |
| `adapter` | enum | REQUIRED | `filesystem`, `sharepoint`, `onedrive` |
| `config` | object | REQUIRED | Adapter-specific configuration |
| `enabled` | boolean | REQUIRED | Whether target is active |
| `created_by` | UUID | REQUIRED | User who created target |
| `created_at` | datetime | REQUIRED | Creation timestamp |

#### 3.3.1 Filesystem Config

```json
{
  "paths": ["\\\\server\\share", "D:\\Data"],
  "exclude_patterns": ["*.tmp", "~$*"],
  "max_depth": 10
}
```

#### 3.3.2 SharePoint Config

```json
{
  "site_urls": ["https://tenant.sharepoint.com/sites/Finance"],
  "include_subsites": true,
  "exclude_libraries": ["Style Library"]
}
```

#### 3.3.3 OneDrive Config

```json
{
  "user_emails": ["ceo@company.com", "cfo@company.com"],
  "scan_all_users": false
}
```

### 3.4 Scan Schedule

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | REQUIRED | Unique schedule identifier |
| `tenant_id` | UUID | REQUIRED | Associated tenant |
| `name` | string | REQUIRED | Display name |
| `target_id` | UUID | REQUIRED | Target to scan |
| `cron` | string | OPTIONAL | Cron expression (null = on-demand only) |
| `enabled` | boolean | REQUIRED | Whether schedule is active |
| `last_run_at` | datetime | OPTIONAL | Last execution time |
| `next_run_at` | datetime | OPTIONAL | Next scheduled execution |
| `created_by` | UUID | REQUIRED | User who created schedule |
| `created_at` | datetime | REQUIRED | Creation timestamp |

### 3.5 Scan Job

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | REQUIRED | Unique job identifier |
| `tenant_id` | UUID | REQUIRED | Associated tenant |
| `schedule_id` | UUID | OPTIONAL | Associated schedule (null if ad-hoc) |
| `status` | enum | REQUIRED | `pending`, `running`, `completed`, `failed`, `cancelled` |
| `progress` | object | OPTIONAL | Progress information |
| `started_at` | datetime | OPTIONAL | Start timestamp |
| `completed_at` | datetime | OPTIONAL | Completion timestamp |
| `files_scanned` | integer | REQUIRED | Number of files scanned |
| `files_with_pii` | integer | REQUIRED | Number of files with PII |
| `error` | string | OPTIONAL | Error message if failed |
| `created_by` | UUID | OPTIONAL | User who started job (null if scheduled) |
| `created_at` | datetime | REQUIRED | Creation timestamp |

#### 3.5.1 Progress Object

```json
{
  "files_scanned": 1247,
  "files_total": 3456,
  "current_file": "\\\\server\\share\\finance\\report.xlsx",
  "percent": 36
}
```

### 3.6 Scan Result

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | REQUIRED | Unique result identifier |
| `tenant_id` | UUID | REQUIRED | Associated tenant |
| `job_id` | UUID | REQUIRED | Associated scan job |
| `file_path` | string | REQUIRED | Full file path |
| `file_name` | string | REQUIRED | File name |
| `file_size` | integer | OPTIONAL | File size in bytes |
| `file_modified` | datetime | OPTIONAL | File modification timestamp |
| `content_hash` | string | OPTIONAL | SHA-256 hash (first 12 chars) |
| `risk_score` | integer | REQUIRED | Risk score 0-100 |
| `risk_tier` | enum | REQUIRED | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `MINIMAL` |
| `content_score` | number | OPTIONAL | Score before exposure multiplier |
| `exposure_multiplier` | number | OPTIONAL | Exposure-based multiplier |
| `co_occurrence_rules` | array | OPTIONAL | Triggered co-occurrence rules |
| `exposure_level` | enum | OPTIONAL | `PRIVATE`, `INTERNAL`, `ORG_WIDE`, `PUBLIC` |
| `owner` | string | OPTIONAL | File owner |
| `entity_counts` | object | REQUIRED | Entity type counts |
| `total_entities` | integer | REQUIRED | Total entity count |
| `findings` | array | OPTIONAL | Detailed findings |
| `current_label_id` | string | OPTIONAL | Current MIP label ID |
| `current_label_name` | string | OPTIONAL | Current MIP label name |
| `recommended_label_id` | string | OPTIONAL | Recommended MIP label ID |
| `recommended_label_name` | string | OPTIONAL | Recommended MIP label name |
| `label_applied` | boolean | REQUIRED | Whether label was applied |
| `label_applied_at` | datetime | OPTIONAL | Label application timestamp |
| `label_error` | string | OPTIONAL | Label application error |
| `scanned_at` | datetime | REQUIRED | Scan timestamp |

#### 3.6.1 Entity Counts Object

```json
{
  "SSN": 23,
  "CREDIT_CARD": 8,
  "NAME": 45,
  "EMAIL": 12
}
```

#### 3.6.2 Finding Object

```json
{
  "type": "SSN",
  "value_preview": "***-**-6789",
  "confidence": 0.95,
  "detector": "checksum",
  "positions": [[120, 131], [456, 467]]
}
```

### 3.7 Sensitivity Label

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | REQUIRED | MIP label GUID |
| `tenant_id` | UUID | REQUIRED | Associated tenant |
| `name` | string | REQUIRED | Label display name |
| `description` | string | OPTIONAL | Label description |
| `priority` | integer | OPTIONAL | Label priority (higher = more sensitive) |
| `color` | string | OPTIONAL | Hex color code |
| `parent_id` | string | OPTIONAL | Parent label ID |
| `synced_at` | datetime | REQUIRED | Last sync timestamp |

### 3.8 Label Rule

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | REQUIRED | Unique rule identifier |
| `tenant_id` | UUID | REQUIRED | Associated tenant |
| `rule_type` | enum | REQUIRED | `risk_tier` or `entity_type` |
| `match_value` | string | REQUIRED | Value to match (e.g., `CRITICAL`, `SSN`) |
| `label_id` | string | REQUIRED | Target sensitivity label ID |
| `priority` | integer | REQUIRED | Rule priority (higher = takes precedence) |
| `created_by` | UUID | REQUIRED | User who created rule |
| `created_at` | datetime | REQUIRED | Creation timestamp |

---

## 4. REST API

### 4.1 Base URL

```
https://{server}:{port}/api
```

### 4.2 Common Headers

All requests MUST include:

```
Authorization: Bearer <access_token>
Content-Type: application/json
Accept: application/json
```

### 4.3 Pagination

List endpoints support pagination:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number (1-indexed) |
| `per_page` | integer | 50 | Items per page (max 100) |

Response includes pagination metadata:

```json
{
  "items": [...],
  "total": 1234,
  "page": 1,
  "per_page": 50,
  "pages": 25
}
```

### 4.4 Filtering

List endpoints support filtering via query parameters:

```
GET /api/results?risk_tier=CRITICAL&job_id=uuid
```

### 4.5 Endpoints

#### 4.5.1 Scans

##### Create Scan

```
POST /api/scans
```

Request:

```json
{
  "target_id": "uuid",
  "name": "Ad-hoc Finance Scan"
}
```

Response: `201 Created`

```json
{
  "id": "uuid",
  "status": "pending",
  "target_id": "uuid",
  "name": "Ad-hoc Finance Scan",
  "created_at": "2026-01-20T10:00:00Z"
}
```

##### List Scans

```
GET /api/scans
```

Query parameters:
- `status`: Filter by status
- `target_id`: Filter by target

Response: `200 OK`

```json
{
  "items": [
    {
      "id": "uuid",
      "status": "completed",
      "target_id": "uuid",
      "name": "Nightly Finance Scan",
      "files_scanned": 3456,
      "files_with_pii": 342,
      "started_at": "2026-01-20T02:00:00Z",
      "completed_at": "2026-01-20T02:45:00Z"
    }
  ],
  "total": 50,
  "page": 1,
  "pages": 1
}
```

##### Get Scan

```
GET /api/scans/{id}
```

Response: `200 OK`

```json
{
  "id": "uuid",
  "status": "running",
  "progress": {
    "files_scanned": 1247,
    "files_total": 3456,
    "current_file": "\\\\server\\share\\file.xlsx",
    "percent": 36
  },
  ...
}
```

##### Cancel Scan

```
DELETE /api/scans/{id}
```

Response: `204 No Content`

#### 4.5.2 Results

##### List Results

```
GET /api/results
```

Query parameters:
- `job_id`: Filter by scan job (required)
- `risk_tier`: Filter by risk tier
- `exposure_level`: Filter by exposure
- `has_entity`: Filter by entity type presence
- `labeled`: Filter by label status (true/false)

Response: `200 OK`

```json
{
  "items": [
    {
      "id": "uuid",
      "file_path": "\\\\server\\share\\file.xlsx",
      "file_name": "file.xlsx",
      "risk_score": 85,
      "risk_tier": "CRITICAL",
      "entity_counts": {"SSN": 23, "CREDIT_CARD": 8},
      "exposure_level": "ORG_WIDE",
      "current_label_name": null,
      "recommended_label_name": "Highly Confidential",
      "scanned_at": "2026-01-20T02:30:00Z"
    }
  ],
  "total": 342,
  "page": 1,
  "pages": 7
}
```

##### Get Result

```
GET /api/results/{id}
```

Response: `200 OK`

Full result object with findings array.

##### Export Results

```
GET /api/results/export
```

Query parameters:
- `job_id`: Scan job ID (required)
- `format`: `csv` or `json` (default: json)

Response: `200 OK` with file download

##### Get Statistics

```
GET /api/results/stats
```

Query parameters:
- `job_id`: Scan job ID (optional, for job-specific stats)

Response: `200 OK`

```json
{
  "total_files": 3456,
  "files_with_pii": 342,
  "by_risk_tier": {
    "CRITICAL": 12,
    "HIGH": 45,
    "MEDIUM": 128,
    "LOW": 89,
    "MINIMAL": 68
  },
  "by_entity_type": {
    "SSN": 234,
    "CREDIT_CARD": 45,
    "EMAIL": 1234
  },
  "by_exposure": {
    "PUBLIC": 3,
    "ORG_WIDE": 89,
    "INTERNAL": 156,
    "PRIVATE": 94
  },
  "labeled": 45,
  "unlabeled": 297
}
```

#### 4.5.3 Targets

##### List Targets

```
GET /api/targets
```

Response: `200 OK`

```json
{
  "items": [
    {
      "id": "uuid",
      "name": "Finance File Server",
      "adapter": "filesystem",
      "config": {"paths": ["\\\\fs01\\finance"]},
      "enabled": true
    }
  ]
}
```

##### Create Target

```
POST /api/targets
```

Request:

```json
{
  "name": "Finance File Server",
  "adapter": "filesystem",
  "config": {
    "paths": ["\\\\fs01\\finance"],
    "exclude_patterns": ["*.tmp"]
  }
}
```

Response: `201 Created`

##### Update Target

```
PUT /api/targets/{id}
```

Request: Same as create

Response: `200 OK`

##### Delete Target

```
DELETE /api/targets/{id}
```

Response: `204 No Content`

#### 4.5.4 Schedules

##### List Schedules

```
GET /api/schedules
```

Response: `200 OK`

```json
{
  "items": [
    {
      "id": "uuid",
      "name": "Nightly Finance Scan",
      "target_id": "uuid",
      "cron": "0 2 * * *",
      "enabled": true,
      "last_run_at": "2026-01-20T02:00:00Z",
      "next_run_at": "2026-01-21T02:00:00Z"
    }
  ]
}
```

##### Create Schedule

```
POST /api/schedules
```

Request:

```json
{
  "name": "Nightly Finance Scan",
  "target_id": "uuid",
  "cron": "0 2 * * *"
}
```

Response: `201 Created`

##### Trigger Schedule

```
POST /api/schedules/{id}/run
```

Response: `201 Created`

Returns the created scan job.

#### 4.5.5 Labels

##### List Labels

```
GET /api/labels
```

Response: `200 OK`

```json
{
  "items": [
    {
      "id": "guid",
      "name": "Highly Confidential",
      "description": "Personal data, financial records",
      "priority": 100,
      "color": "#FF0000"
    }
  ]
}
```

##### Sync Labels

```
POST /api/labels/sync
```

Synchronizes labels from Microsoft 365.

Response: `200 OK`

```json
{
  "synced": 5,
  "added": 1,
  "updated": 0,
  "removed": 0
}
```

##### List Label Rules

```
GET /api/labels/rules
```

Response: `200 OK`

```json
{
  "items": [
    {
      "id": "uuid",
      "rule_type": "risk_tier",
      "match_value": "CRITICAL",
      "label_id": "guid",
      "label_name": "Highly Confidential",
      "priority": 100
    }
  ]
}
```

##### Create Label Rule

```
POST /api/labels/rules
```

Request:

```json
{
  "rule_type": "risk_tier",
  "match_value": "CRITICAL",
  "label_id": "guid",
  "priority": 100
}
```

Response: `201 Created`

##### Apply Label

```
POST /api/labels/apply
```

Request:

```json
{
  "result_id": "uuid",
  "label_id": "guid"
}
```

Response: `200 OK`

```json
{
  "success": true,
  "result_id": "uuid",
  "label_id": "guid",
  "label_name": "Highly Confidential"
}
```

#### 4.5.6 Dashboard

##### Get Dashboard Stats

```
GET /api/dashboard/stats
```

Response: `200 OK`

```json
{
  "total_scans": 150,
  "total_files_scanned": 45678,
  "files_with_pii": 3456,
  "labels_applied": 2100,
  "by_risk_tier": {...},
  "by_adapter": {
    "filesystem": 30000,
    "sharepoint": 10000,
    "onedrive": 5678
  }
}
```

##### Get Trends

```
GET /api/dashboard/trends
```

Query parameters:
- `period`: `7d`, `30d`, `90d` (default: 30d)

Response: `200 OK`

```json
{
  "period": "30d",
  "scans": [
    {"date": "2026-01-01", "count": 5},
    {"date": "2026-01-02", "count": 4}
  ],
  "files_with_pii": [
    {"date": "2026-01-01", "count": 120},
    {"date": "2026-01-02", "count": 145}
  ]
}
```

##### Get Heatmap Data

```
GET /api/dashboard/heatmap
```

Query parameters:
- `job_id`: Scan job ID (optional)

Response: `200 OK`

```json
{
  "name": "All Sources",
  "children": [
    {
      "name": "Local",
      "path": "Local",
      "entity_counts": {"SSN": 142, "EMAIL": 234},
      "total_entities": 500,
      "file_count": 1234,
      "children": [...]
    }
  ]
}
```

---

## 5. WebSocket API

### 5.1 Connection

```
wss://{server}:{port}/ws/scans/{job_id}
```

Authentication via query parameter:

```
wss://server/ws/scans/uuid?token=<access_token>
```

### 5.2 Messages

#### Server → Client: Progress

```json
{
  "type": "progress",
  "data": {
    "files_scanned": 1247,
    "files_total": 3456,
    "current_file": "\\\\server\\share\\file.xlsx",
    "percent": 36
  }
}
```

#### Server → Client: Result

```json
{
  "type": "result",
  "data": {
    "file_path": "\\\\server\\share\\file.xlsx",
    "risk_score": 85,
    "risk_tier": "CRITICAL",
    "entity_counts": {"SSN": 23}
  }
}
```

#### Server → Client: Complete

```json
{
  "type": "complete",
  "data": {
    "files_scanned": 3456,
    "files_with_pii": 342,
    "duration_seconds": 2700
  }
}
```

#### Server → Client: Error

```json
{
  "type": "error",
  "data": {
    "message": "Access denied to \\\\server\\share",
    "fatal": false
  }
}
```

---

## 6. Authentication

### 6.1 OAuth 2.0 / OIDC

OpenLabels Server uses Azure AD for authentication.

#### 6.1.1 Authorization Code Flow (GUI)

1. GUI redirects to Azure AD authorization endpoint
2. User authenticates
3. Azure AD redirects back with authorization code
4. GUI exchanges code for tokens
5. GUI uses access token for API calls

#### 6.1.2 Client Credentials Flow (Service)

For automated/service access:

```http
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

client_id={client_id}
&client_secret={client_secret}
&scope=api://{api_client_id}/.default
&grant_type=client_credentials
```

### 6.2 Token Validation

Servers MUST validate:

1. Token signature (using Azure AD public keys)
2. `iss` claim matches expected issuer
3. `aud` claim matches API client ID
4. `exp` claim is in the future
5. `nbf` claim is in the past

### 6.3 Authorization

| Role | Permissions |
|------|-------------|
| `admin` | Full access to all endpoints |
| `viewer` | Read-only access (GET endpoints only) |

Role is determined by:
1. Azure AD app role claims, OR
2. `users.role` database field

---

## 7. Adapters

### 7.1 Adapter Protocol

```python
from typing import Protocol, AsyncIterator

class StorageAdapter(Protocol):
    """Protocol for storage adapters."""

    async def list_files(
        self,
        config: dict,
        recursive: bool = True
    ) -> AsyncIterator[FileInfo]:
        """List files in configured location."""
        ...

    async def read_file(self, path: str) -> bytes:
        """Read file content."""
        ...

    async def get_metadata(self, path: str) -> FileMetadata:
        """Get file metadata including permissions."""
        ...

    async def apply_label(
        self,
        path: str,
        label_id: str
    ) -> bool:
        """Apply sensitivity label to file."""
        ...
```

### 7.2 FileInfo

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | Full path or URI |
| `name` | string | File name |
| `size` | integer | Size in bytes |
| `modified` | datetime | Last modified time |
| `owner` | string | File owner |
| `permissions` | object | Platform-specific permissions |
| `exposure` | ExposureLevel | Calculated exposure level |

### 7.3 Exposure Calculation

| Level | Filesystem | SharePoint/OneDrive |
|-------|------------|---------------------|
| PUBLIC | Everyone / World readable | Anyone with link |
| ORG_WIDE | Authenticated Users / Domain Users | People in org with link |
| INTERNAL | Specific groups | Specific groups |
| PRIVATE | Owner only | Specific people |

---

## 8. Labeling Interface

### 8.1 Labeler Protocol

```python
class Labeler(Protocol):
    """Protocol for labeling implementations."""

    def get_labels(self) -> list[SensitivityLabel]:
        """Get available labels from tenant."""
        ...

    def get_current_label(self, path: str) -> SensitivityLabel | None:
        """Get current label on file."""
        ...

    def apply_label(self, path: str, label_id: str) -> bool:
        """Apply label to file."""
        ...
```

### 8.2 Label Selection

Labels are selected based on rules in priority order:

1. Entity type rules (e.g., SSN → Highly Confidential)
2. Risk tier rules (e.g., CRITICAL → Highly Confidential)

If multiple rules match, the highest priority rule wins.

### 8.3 MIP SDK Requirements

For local file labeling:

- .NET 8 Runtime
- Microsoft.InformationProtection.File NuGet package
- Azure AD app with RMS permissions

### 8.4 Graph API Requirements

For SharePoint/OneDrive labeling:

- Files.ReadWrite.All permission
- InformationProtection.Read.All permission

---

## 9. Configuration

### 9.1 Configuration Sources

Configuration is loaded in order (later overrides earlier):

1. Default values
2. Configuration file (`config.yaml`)
3. Environment variables

### 9.2 Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENLABELS_DATABASE_URL` | PostgreSQL connection string |
| `OPENLABELS_SERVER_PORT` | Server port (default: 8000) |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | Azure AD client ID |
| `AZURE_CLIENT_SECRET` | Azure AD client secret |

### 9.3 Configuration Schema

See Appendix A for full JSON schema.

---

## 10. Error Handling

### 10.1 Error Response Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid cron expression",
    "details": {
      "field": "cron",
      "value": "invalid"
    }
  }
}
```

### 10.2 Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `UNAUTHORIZED` | 401 | Missing or invalid token |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource conflict |
| `INTERNAL_ERROR` | 500 | Internal server error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

---

## 11. Security Considerations

### 11.1 Data Protection

- All API communication MUST use TLS 1.2+
- Sensitive values in findings MUST be masked/truncated
- Access tokens MUST be short-lived (1 hour max)
- Refresh tokens MUST be stored securely

### 11.2 Service Account

The service account used for file access:

- SHOULD have Backup Operator rights (read-only access to all files)
- SHOULD NOT have administrative privileges
- MUST use a dedicated service account (not a user account)

### 11.3 Audit Logging

All significant actions MUST be logged:

- Scan started/completed
- Label applied
- Configuration changed
- User login

---

## 12. Conformance

### 12.1 Server Requirements

A conforming server MUST:

1. Implement all endpoints in Section 4
2. Return valid JSON per schemas in Appendix A
3. Support OAuth 2.0 authentication
4. Store data per schemas in Section 3
5. Support at least one adapter (filesystem)

### 12.2 Client Requirements

A conforming client MUST:

1. Authenticate via OAuth 2.0
2. Handle pagination for list endpoints
3. Handle all error codes in Section 10

---

## Appendix A: JSON Schemas

### Scan Job Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["id", "status", "files_scanned", "files_with_pii", "created_at"],
  "properties": {
    "id": {"type": "string", "format": "uuid"},
    "status": {"enum": ["pending", "running", "completed", "failed", "cancelled"]},
    "target_id": {"type": "string", "format": "uuid"},
    "schedule_id": {"type": ["string", "null"], "format": "uuid"},
    "name": {"type": "string"},
    "progress": {
      "type": "object",
      "properties": {
        "files_scanned": {"type": "integer"},
        "files_total": {"type": "integer"},
        "current_file": {"type": "string"},
        "percent": {"type": "integer", "minimum": 0, "maximum": 100}
      }
    },
    "files_scanned": {"type": "integer"},
    "files_with_pii": {"type": "integer"},
    "started_at": {"type": ["string", "null"], "format": "date-time"},
    "completed_at": {"type": ["string", "null"], "format": "date-time"},
    "error": {"type": ["string", "null"]},
    "created_at": {"type": "string", "format": "date-time"}
  }
}
```

### Scan Result Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["id", "job_id", "file_path", "risk_score", "risk_tier", "entity_counts", "total_entities", "scanned_at"],
  "properties": {
    "id": {"type": "string", "format": "uuid"},
    "job_id": {"type": "string", "format": "uuid"},
    "file_path": {"type": "string"},
    "file_name": {"type": "string"},
    "file_size": {"type": "integer"},
    "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
    "risk_tier": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]},
    "exposure_level": {"enum": ["PUBLIC", "ORG_WIDE", "INTERNAL", "PRIVATE"]},
    "entity_counts": {
      "type": "object",
      "additionalProperties": {"type": "integer"}
    },
    "total_entities": {"type": "integer"},
    "current_label_name": {"type": ["string", "null"]},
    "recommended_label_name": {"type": ["string", "null"]},
    "label_applied": {"type": "boolean"},
    "scanned_at": {"type": "string", "format": "date-time"}
  }
}
```

---

## Appendix B: Entity Types

See [openlabels-entity-registry-v1.md](./openlabels-entity-registry-v1.md) for the complete entity type registry.

Common entity types:

| Type | Category | Weight |
|------|----------|--------|
| `SSN` | direct_identifier | 10 |
| `CREDIT_CARD` | financial | 9 |
| `PASSPORT` | direct_identifier | 9 |
| `DRIVER_LICENSE` | direct_identifier | 8 |
| `NPI` | healthcare | 8 |
| `MRN` | healthcare | 8 |
| `DATE_DOB` | quasi_identifier | 6 |
| `NAME` | quasi_identifier | 5 |
| `EMAIL` | contact | 5 |
| `PHONE` | contact | 4 |
| `ADDRESS` | contact | 5 |
| `IP_ADDRESS` | network | 3 |
| `AWS_ACCESS_KEY` | credential | 10 |
| `API_KEY` | credential | 9 |

---

*This specification defines the OpenLabels Server API contract. Implementations MUST conform to this specification for interoperability.*
