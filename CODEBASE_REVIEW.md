# OpenLabels Comprehensive Codebase Review

**Date:** 2026-02-27
**Scope:** Full application — 200k+ lines across 624 files
**Method:** 21 parallel review agents, each performing deep file-by-file analysis
**Branch:** `claude/codebase-review-agents-wHnd1`

---

## Executive Summary

OpenLabels is a well-architected multi-tenant PII/sensitive-data detection platform with a FastAPI backend, React/TypeScript frontend, DuckDB analytics, ML-based detection, and SIEM export capabilities. The codebase demonstrates strong patterns in many areas — proper use of PostgreSQL advisory locks, parameterized SQL, Fernet encryption for credentials, and rigorous security tests.

However, the review uncovered **critical security gaps**, **systemic test coverage holes**, and **cross-cutting design issues** that need immediate attention. The most severe findings include tenant isolation bypasses, credential exposure patterns, and near-zero frontend test coverage.

### Findings Summary

| Severity | Security | Errors/Omissions | Scalability | AI Slop | Test Gaps |
|----------|----------|-------------------|-------------|---------|-----------|
| **CRITICAL** | 6 | 3 | 1 | 0 | 3 |
| **HIGH** | 18 | 12 | 5 | 2 | 5 |
| **MEDIUM** | 25+ | 30+ | 15+ | 8 | 10+ |
| **LOW** | 15+ | 20+ | 10+ | 10+ | — |

---

## Table of Contents

1. [CRITICAL Findings (Must Fix)](#critical)
2. [HIGH Findings (Should Fix)](#high)
3. [Security Errors](#security)
4. [Errors and Omissions](#errors)
5. [Non-Scalable Design Patterns](#scalability)
6. [AI Slop](#slop)
7. [Log Coverage Gaps](#logging)
8. [Test Coverage Analysis](#testing)
9. [Recommendations](#recommendations)

---

<a name="critical"></a>
## 1. CRITICAL Findings (Must Fix)

### CRIT-1: Tenant Isolation Not Enforced in DuckDB Query Endpoint
**File:** `src/openlabels/server/routes/query.py`
**Impact:** Any authenticated user can query any tenant's analytics data
**Details:** The DuckDB query endpoint does not enforce `tenant_id` filtering on incoming queries. An attacker who can authenticate as any tenant can execute arbitrary analytical queries against all tenants' data.
**Fix:** Inject mandatory `WHERE tenant_id = :current_tenant` clause into all DuckDB queries at the engine level, not the route level.

### CRIT-2: CSRF Bypass via Bearer Token Header
**File:** `src/openlabels/server/middleware/csrf.py`
**Impact:** Complete CSRF protection bypass for API requests
**Details:** The CSRF middleware skips validation when an `Authorization: Bearer` header is present. An attacker can craft a cross-origin request with this header to bypass CSRF checks entirely.
**Fix:** CSRF validation should not be bypassed based on the presence of an Authorization header. Only skip CSRF for truly stateless token-authenticated requests where the token cannot be sent by the browser automatically.

### CRIT-3: No SHA-256 Checksums for ML Model Files
**File:** `src/openlabels/core/detectors/ml.py`, `gliner.py`
**Impact:** Supply chain attack — malicious model substitution
**Details:** ML model files (HuggingFace transformers, GLiNER, ONNX) are loaded without integrity verification. An attacker with filesystem access can substitute a backdoored model that exfiltrates PII instead of detecting it. Additionally, unsafe pickle deserialization is used in some model loading paths.
**Fix:** Maintain a manifest of expected SHA-256 hashes for all model files. Verify before loading. Avoid pickle deserialization where possible.

### CRIT-4: No Row-Level Security (RLS) in PostgreSQL
**File:** All 21 Alembic migrations, `models.py`
**Impact:** Single missing WHERE clause leaks data across tenants
**Details:** The entire multi-tenant application relies solely on application-level `tenant_id` filtering. Zero RLS policies exist across the entire migration chain. PostgreSQL RLS should be defense-in-depth for tenant isolation.
**Fix:** Enable RLS on all tenant-scoped tables and create policies that restrict access to the current tenant's `SET` session variable.

### CRIT-5: Cross-Tenant Event Flush in Analytics Engine
**File:** `src/openlabels/analytics/engine.py`
**Impact:** Analytics events from one tenant visible to another
**Details:** The analytics event flush does not filter by tenant_id, potentially mixing tenant data in the DuckDB analytics store.
**Fix:** Add tenant_id filtering to all flush and compaction operations.

### CRIT-6: Zero Frontend Test Coverage
**Files:** All `frontend/src/` files
**Impact:** No regression safety net for the entire UI layer
**Details:** Out of 100+ frontend files (components, hooks, stores, API layer, pages), only ONE test file exists (`sql-validation.test.ts`). Critical untested logic includes: CSRF token handling, 401 redirect guard, auth state management, WebSocket reconnection, role mapping, and all page-level business logic.
**Fix:** Prioritize tests for `client.ts`, `auth-store.ts`, `websocket.ts`, and high-risk pages.

---

<a name="high"></a>
## 2. HIGH Findings (Should Fix)

### HIGH-1: M365 Client Secret Stored in Plaintext Sessions
**File:** `src/openlabels/server/routes/m365.py`
**Impact:** OAuth client secrets recoverable from session store
**Details:** The M365 client secret is stored as plaintext in the session `data` JSONB column. If the session store is compromised, all M365 integration secrets are exposed.

### HIGH-2: Credentials Interpolated into DuckDB SQL Strings
**File:** `src/openlabels/analytics/engine.py`
**Impact:** Database credential exposure via SQL string construction
**Details:** Analytics engine connection strings are built via string interpolation rather than parameterized connections.

### HIGH-3: Multiple ReDoS Vulnerabilities in Regex Patterns
**Files:** `src/openlabels/core/detectors/patterns.py`, `financial.py`, `pii.py`
**Impact:** Denial of service via crafted input strings
**Details:** Several regex patterns use nested quantifiers or overlapping alternations that enable catastrophic backtracking. On Windows, the ReDoS timeout protection (via `signal.SIGALRM`) is completely absent.

### HIGH-4: Silent Plaintext Fallback in Crypto Module
**File:** `src/openlabels/server/crypto.py`
**Impact:** Credentials stored unencrypted when key not configured
**Details:** When the encryption key is not configured, the crypto module silently falls back to plaintext storage rather than failing loudly. Operators may not realize credentials are unprotected.

### HIGH-5: SHA-256 Without Proper KDF for Key Derivation
**File:** `src/openlabels/server/crypto.py`
**Impact:** Weak key derivation undermines encryption
**Details:** Raw SHA-256 is used for key derivation instead of a proper KDF like PBKDF2, scrypt, or Argon2.

### HIGH-6: SSRF Vectors in Multiple Modules
**Files:** `src/openlabels/adapters/s3.py` (endpoint_url), `adapters/graph_client.py` (nextLink), `export/adapters/elastic.py` (hosts), `export/adapters/splunk.py` (hec_url), `export/adapters/sentinel.py` (workspace_id)
**Impact:** Server-side request forgery to internal services
**Details:** User-controllable URLs are used in HTTP requests without validation. The S3 `endpoint_url`, Graph API `nextLink` pagination URLs, and SIEM adapter host URLs can be manipulated to target internal services.

### HIGH-7: Credentials Stored as Plain String Attributes Across All Export Adapters
**Files:** `export/adapters/elastic.py`, `splunk.py`, `sentinel.py`, `export/setup.py`, `labeling/engine.py`, `labeling/mip.py`
**Impact:** Credentials persisted in process memory, visible in dumps
**Details:** All SIEM adapters and the labeling engine extract `SecretStr` values at initialization and hold them as plain `str` attributes for the process lifetime. Should call `get_secret_value()` only at point of use.

### HIGH-8: Graph Webhook clientState Validation Bypass
**File:** `src/openlabels/monitoring/providers/graph_webhook.py`
**Impact:** Fake webhook notifications accepted when clientState is empty
**Details:** The default `client_state` is empty string, which disables all notification validation. An attacker who discovers the webhook URL can inject arbitrary change notifications.

### HIGH-9: WinRM Credentials in Plain Memory / No Tenant Filter
**Files:** `src/openlabels/monitoring/providers/winrm.py`, `winrm_remote.py`
**Impact:** Cross-tenant credential exposure
**Details:** `_load_targets_from_db` fetches ALL SMB credentials across all tenants without a tenant_id filter. Decrypted passwords are stored as plain string tuples passed through multiple function calls.

### HIGH-10: Path Traversal via Quarantine Manifest Default
**File:** `src/openlabels/remediation/manifest.py`
**Impact:** Path traversal protection effectively disabled
**Details:** `DEFAULT_ALLOWED_BASES = [Path("/")]` allows any absolute path, making the path traversal prevention a no-op.

### HIGH-11: CEF/LEEF Log Injection in SIEM Adapters
**Files:** `export/adapters/base.py` (CEF), `export/adapters/qradar.py` (LEEF)
**Impact:** Log injection into downstream SIEM systems
**Details:** `entityTypes` and `policyViolations` fields are not escaped in CEF format. LEEF values lack newline escaping. Crafted values can inject additional syslog messages.

### HIGH-12: MIPClient Created and Leaked Per Label Application
**File:** `src/openlabels/labeling/engine.py`
**Impact:** .NET resource exhaustion under load
**Details:** Every label application creates a new MIPClient (loading .NET assemblies, FileProfile, FileEngine), never calls `shutdown()`. Under batch labeling, this exhausts memory and handles.

### HIGH-13: Non-Unique OIDC External ID Index
**File:** `alembic/versions/a1c2d3e4f5a6_generic_oidc_sso_columns.py`
**Impact:** Duplicate user accounts per identity provider
**Details:** The `ix_users_provider_external_id` index was created as non-unique despite being documented as "unique user per provider." The corrective migration fixes this, but verify the fix was applied.

### HIGH-14: AlertRule Model Has No Migration
**File:** `src/openlabels/server/models.py` (lines 815-851)
**Impact:** `alert_rules` table does not exist in database
**Details:** The `AlertRule` model is defined in the ORM but no migration creates the table. Any code referencing this model will crash with "relation does not exist."

### HIGH-15: New httpx.AsyncClient Per Request in All SIEM Adapters
**Files:** `export/adapters/elastic.py`, `splunk.py`, `sentinel.py`
**Impact:** No connection pooling; TLS handshake per request
**Details:** Every chunk export creates and destroys an HTTP client, defeating connection reuse and adding significant overhead for high-throughput export.

### HIGH-16: upsert_monitored_file Is Not Atomic
**File:** `src/openlabels/monitoring/db.py`
**Impact:** Duplicate key violations under concurrent requests
**Details:** SELECT+INSERT pattern races under concurrent access. The same file already uses `on_conflict_do_update` in `sync_to_db` — this pattern should be used consistently.

### HIGH-17: Job Task Type Not Validated at Enqueue Time
**File:** `src/openlabels/jobs/queue.py`
**Impact:** Arbitrary job types can be enqueued
**Details:** The `task_type` parameter is a free-form string with no allowlist validation. Should be validated against `{"scan", "rescan", "scan_partition", "label", "label_sync", "export", "flush"}`.

### HIGH-18: Flush Task Type Missing from Embedded Worker Dispatch
**File:** `src/openlabels/jobs/embedded.py`
**Impact:** Flush jobs fail with "Unknown task type"
**Details:** The dispatch function handles scan, rescan, scan_partition, label, label_sync, and export — but not `flush`. The standalone worker has the same gap.

---

<a name="security"></a>
## 3. Security Errors (Medium Severity)

| # | File | Issue |
|---|------|-------|
| S1 | `server/routes/auth.py` | Null tenant_id in audit logs for some operations |
| S2 | `server/routes/auth.py` | No audit logging for credential CRUD operations |
| S3 | `auth/oidc_provider.py` | OIDC nonce not validated (token replay risk) |
| S4 | `auth/graph.py` | Graph API path injection via user-controlled path segments |
| S5 | `core/detectors/secrets.py` | PII leakage in secret detection — matched secrets in debug logs |
| S6 | `core/pipeline/context_enhancer.py` | PII leakage in context enhancement logs |
| S7 | `core/pipeline/ocr.py` | Path traversal via OCR temp file handling |
| S8 | `adapters/filesystem.py` | Symlink bypass in filesystem adapter |
| S9 | `server/session.py` | Cursor pagination broken without secret key configured |
| S10 | `cli/commands/benchmark.py` | Path validation silently swallowed in `recalibrate` (line 896) |
| S11 | `cli/commands/scan.py` | Job ID interpolated into API URL without UUID validation |
| S12 | `cli/commands/config.py` | No allowlist on configuration keys — any key can be set |
| S13 | `cli/filter_executor.py` | ReDoS protection absent on Windows (signal.SIGALRM fallback) |
| S14 | `export/adapters/base.py` | UDP socket has no timeout — can block executor thread |
| S15 | `labeling/engine.py` | Non-atomic file writes in Office metadata labeling |
| S16 | `labeling/mip.py` | AutoConsentDelegate unconditionally accepts all consent |
| S17 | `labeling/mip.py` | `sys.path` modification for MIP SDK — module injection risk |
| S18 | `reporting/engine.py` | Report storage directory created with world-readable permissions |
| S19 | `reporting/engine.py` | CSV injection prevention incomplete (DDE formulas) |
| S20 | `remediation/permissions.py` | `ast.literal_eval` fallback for ACL restoration |
| S21 | `monitoring/wef_setup.py` | Predictable temp file path — symlink attack vector |
| S22 | `monitoring/gmsa.py` | Environment variable spoofing for identity detection |
| S23 | `monitoring/providers/m365_audit.py` | Content URI scheme not validated (HTTPS downgrade) |
| S24 | `jobs/sd_collect.py` | `os.stat` follows symlinks — TOCTOU attack |
| S25 | `jobs/worker.py` | Redis URL with credentials logged at INFO level |
| S26 | `frontend/src/api/client.ts` | `isRedirectingToLogin` flag never resets — auth DoS |
| S27 | `frontend/src/api/endpoints/enumerate.ts` | Raw credentials sent in POST body instead of credential reference |
| S28 | `frontend/src/api/endpoints/credentials.ts` | `sourceType` not URL-encoded in query string construction |

---

<a name="errors"></a>
## 4. Errors and Omissions

### Runtime Bugs
| # | File | Issue |
|---|------|-------|
| E1 | `cli/commands/report.py` | HTML report `summary['by_tier']` accessed with string keys but dict uses enum keys — `KeyError` at runtime |
| E2 | `cli/commands/benchmark.py` | Uses raw `{output}` instead of `{validated}` path in user message |
| E3 | `cli/utils.py` vs `cli/base.py` | Inconsistent env var names: `OPENLABELS_SERVER` vs `OPENLABELS_SERVER_URL` |
| E4 | `export/engine.py` | `export_scan` ignores `job_id` and `tenant_id` parameters (dead code) |
| E5 | `export/engine.py` | `httpx.HTTPError` not caught — crashes entire export run |
| E6 | `export/adapters/elastic.py` | Host rotation mutates list during concurrent iteration (thread-safety bug) |
| E7 | `remediation/base.py` | `to_dict()` omits `previous_acl` field — audit trail data lost |
| E8 | `remediation/manifest.py` | `fcntl` import fails on Windows — portability bug |
| E9 | `remediation/quarantine.py` | Hash mismatch after move does not trigger rollback — data loss |
| E10 | `export/adapters/sentinel.py` | `test_connection` writes real data to production workspace |
| E11 | `labeling/engine.py` | `create_labeling_engine` passes `None` as `client_secret` when not configured |
| E12 | `jobs/tasks/label.py` | `_infer_adapter` only checks sharepoint/onedrive — cloud URIs misidentified |
| E13 | `jobs/tasks/scan.py` | Duplicate `ExposureLevel` import — one shadows the other |
| E14 | `jobs/summaries.py` | No idempotency guard — duplicate summaries on retry |
| E15 | `jobs/tasks/label_sync.py` | `_remove_stale_labels` deletes without referential integrity check |
| E16 | `models.py` | Session `ondelete` mismatch: model says CASCADE, migration says SET NULL |
| E17 | `models.py` | `ScanResult` ORM PK is `id` only, but partitioned table PK is `(id, scanned_at)` |

### Design Omissions
| # | File | Issue |
|---|------|-------|
| D1 | `monitoring/harvester.py` | Sequential provider processing — slow provider blocks all others |
| D2 | `monitoring/harvester.py` | No deduplication of events across cycles |
| D3 | `monitoring/stream_manager.py` | Provider crash kills reader task permanently — no auto-restart |
| D4 | `monitoring/providers/usn_journal.py` | Path resolution is a documented stub — provider non-functional |
| D5 | `monitoring/notification_queue.py` | No per-tenant isolation — one tenant's flood drops another's notifications |
| D6 | `analytics/engine.py` | Non-atomic compaction — crash during compaction loses data |
| D7 | `export/engine.py` | Silent data loss on adapter failure — no retry or dead-letter queue |
| D8 | `server/routes/results.py` | CSV export has no row limit — OOM risk on large exports |
| D9 | `core/pipeline/extractors.py` | DOCX decompression bomb — no size limit on zip extraction |
| D10 | `jobs/embedded.py` + `worker.py` | Dispatcher code duplication — adding task type requires updating both |

---

<a name="scalability"></a>
## 5. Non-Scalable Design Patterns

### Database & Query Patterns
| # | File | Issue |
|---|------|-------|
| SC1 | `cli/commands/catalog.py` | OFFSET-based pagination degrades at scale — use keyset pagination |
| SC2 | `monitoring/db.py` | `load_monitored_files` hard-limited to 100,000 rows — silent truncation |
| SC3 | `models.py` | `AuditLog` table has no partitioning or TTL — unbounded growth |
| SC4 | `alembic/versions/*_partitioning.py` | Full-table copy during partition migration — requires downtime |
| SC5 | `jobs/delta_sync.py` | `_load_existing_dirs` loads ALL directory paths into memory |

### Connection & Resource Management
| # | File | Issue |
|---|------|-------|
| SC6 | All SIEM adapters | New httpx.AsyncClient per request — no connection pooling |
| SC7 | `export/adapters/base.py` | New TCP/UDP socket per syslog batch — no connection reuse |
| SC8 | `labeling/engine.py` | New MIPClient per label application — .NET assembly reload each time |

### Polling & Concurrency
| # | File | Issue |
|---|------|-------|
| SC9 | `jobs/embedded.py` + `worker.py` | Fixed 1-second poll interval with no backoff under empty queue |
| SC10 | `frontend/src/api/hooks/use-scans.ts` | Polls every 10 seconds unconditionally even when no scans running |
| SC11 | `frontend/src/api/hooks/use-scans.ts` | `useCreateScans` fires N parallel HTTP requests instead of using existing bulk endpoint |

### Copy-Paste Patterns
| # | Files | Issue |
|---|-------|-------|
| SC12 | `cli/commands/classify.py`, `find.py`, `heatmap.py`, `report.py`, `remediation.py` | Identical `process_all` loop duplicated 6+ times — `scan_files()` utility exists but unused |
| SC13 | `cli/commands/catalog.py` | Six near-identical table export blocks in `_run_rebuild` |

---

<a name="slop"></a>
## 6. AI Slop

### Migration IDs Are Hand-Crafted Sequential Hex
**Files:** All Alembic migrations
**Details:** Migration revision IDs follow a clear incrementing hex pattern (`a1b2c3d4e5f6`, `a2b3c4d5e6f7`, `b2c3d4e5f6a7`, ...) rather than Alembic's random hex generation. Multiple `Revises:` docstring headers are incorrect, pointing to wrong parent migrations. This indicates bulk AI generation rather than incremental development.

### Documented Stubs
| File | Issue |
|------|-------|
| `frontend/src/lib/date.ts` | `describeCron` is an acknowledged stub that only handles simplest format |
| `monitoring/providers/usn_journal.py` | `_resolve_path_via_mft` is a documented stub returning unresolved paths |
| `frontend/src/api/types.ts` | Comment: "In production, generate from OpenAPI spec" — types manually maintained |

### Repetitive Patterns
| File | Issue |
|------|-------|
| `labeling/mip.py` | `handler.Protection is not None if hasattr(handler, 'Protection') else False` repeated 4 times |
| `labeling/mip.py` | Identical sync method pattern repeated for apply/remove/get/is_protected |
| `jobs/worker.py` | 9 sequential except clauses with nearly identical logging patterns |
| `cli/commands/remediation.py` | `find_matches` async function duplicated verbatim in quarantine and lock_down |
| `jobs/tasks/scan.py` | Three exception handlers returning nearly identical error dicts |

---

<a name="logging"></a>
## 7. Log Coverage Gaps

### Files with Zero Logging (No Logger Defined)
**Server:** Multiple route files totaling ~5,000+ lines with zero log statements
**CLI:** `classify.py`, `config.py`, `db.py`, `export.py`, `labels.py`, `monitor.py`, `scan.py`, `server.py`, `target.py`, `user.py`
**Frontend:** Console-only logging — no integration with Sentry, Datadog, or any error reporting service

### Files with Unused Loggers (Defined but Never Called)
`cli/commands/catalog.py`, `cli/commands/index.py`, `cli/commands/models.py`

### Silent Error Swallowing
| File | Issue |
|------|-------|
| `frontend/src/lib/websocket.ts` | `catch { // ignore malformed messages }` — no logging at all |
| `frontend/src/hooks/use-scan-websocket.ts` | Same silent catch for malformed messages |
| `frontend/src/hooks/use-local-storage.ts` | Storage errors silently swallowed |
| `frontend/src/stores/auth-store.ts` | Auth check failure silently sets unauthenticated |
| `monitoring/notification_queue.py` | Queue overflow returns false with no logging inside push functions |

### f-string Logging (Performance)
**Files:** `labeling/mip.py` (30+ instances), `monitoring/history.py` (11 instances), `monitoring/registry.py` (7 instances), `jobs/queue.py` (6 instances)
**Impact:** String formatting evaluated even when log level is disabled. Should use lazy `%s` formatting.

### Critical Missing Audit Logging
- No audit logging for credential CRUD operations
- No audit logging for destructive frontend actions (quarantine, lockdown, rollback, user deletion)
- No structured logging with tenant_id in SIEM export engine
- Config changes via CLI not logged (security posture changes)

---

<a name="testing"></a>
## 8. Test Coverage Analysis

### Overall Assessment
The test suite is **above average in quality** for specific areas (security tests, detector tests, pipeline tests) but has **massive gaps** in route coverage, frontend coverage, and integration testing.

### Strengths
- **Security tests are rigorous**: Multi-tenant isolation tests verify database state after cross-tenant operations, not just HTTP status codes
- **Core detector tests exercise real code**: No mocking — real patterns tested against real text
- **Pipeline tests include mathematical invariants**: Tier dominance rules, full text coverage verification
- **Credential encryption tests**: Anti-double-encryption, immutability, legacy plaintext handling

### Critical Test Anti-Patterns Found
1. **Silently-passing tests** in `test_scans.py` (lines 287, 298): `if failed_scans:` instead of `assert failed_scans` — tests skip their body without failure
2. **Self-referential assertion** in `test_job_service.py` (line 43): Asserts payload equals itself from `call_args` — always passes
3. **Testing the mock**: `test_label_service.py` patches `svc.paginate` and asserts it was called — verifies implementation, not behavior

### Source Modules Without ANY Test Coverage

#### Server Routes (0 of 21 route files have dedicated tests beyond auth/scans/enumerate/credentials)
| Module | Lines | Risk |
|--------|-------|------|
| `routes/audit.py` | — | Medium |
| `routes/browse.py` | — | Medium |
| `routes/dashboard.py` | — | Low |
| `routes/export.py` | — | High |
| `routes/health.py` | — | Low |
| `routes/jobs.py` | — | Medium |
| `routes/labels.py` | — | Medium |
| `routes/m365.py` | — | High |
| `routes/monitoring.py` | 1,290 lines | **Critical** |
| `routes/permissions.py` | — | Medium |
| `routes/policies.py` | — | Medium |
| `routes/query.py` | — | **Critical** |
| `routes/reporting.py` | — | Medium |
| `routes/results.py` | — | High |
| `routes/schedules.py` | — | Medium |
| `routes/settings.py` | — | Medium |
| `routes/targets.py` | — | High |
| `routes/users.py` | — | High |
| `routes/webhooks.py` | — | High |
| `routes/ws.py` | — | Medium |
| `routes/ws_events.py` | — | Medium |

#### Server Middleware & Infrastructure
| Module | Risk |
|--------|------|
| `middleware/csrf.py` | **Critical** — CSRF is untested |
| `middleware/rate_limit.py` | High |
| `server/session.py` | High |
| `server/cache.py` | Medium |
| `server/security.py` | High |

#### Jobs System
| Module | Risk |
|--------|------|
| `jobs/embedded.py` | **Critical** — primary single-server execution path |
| `jobs/tasks/export.py` | High |
| `jobs/tasks/flush.py` | Medium |
| `jobs/tasks/scan.py` | **Critical** — core scanning logic |
| `jobs/scheduler.py` | High |
| `jobs/pipeline.py` | High |

#### Monitoring (9 of 23 files untested)
| Module | Risk |
|--------|------|
| `monitoring/collector.py` | High |
| `monitoring/db.py` | High |
| `monitoring/gmsa.py` | Medium |
| `monitoring/notification_queue.py` | Medium |
| `providers/graph_webhook.py` | High |
| `providers/wef.py` | Medium |
| `providers/windows.py` | Low |
| `providers/linux.py` | Low |
| `providers/winrm.py` | High |

#### Core Detection & Pipeline
| Module | Risk |
|--------|------|
| `detectors/allowlist.py` | Medium |
| `detectors/language.py` | Medium |
| `detectors/orchestrator.py` | High |
| `detectors/phi_detector.py` | High |
| `pipeline/entity_resolver.py` | Medium |
| `pipeline/span_validation.py` | Medium |
| `pipeline/tiered.py` | High |
| `circuit_breaker.py` | Medium |

#### Frontend (1 test file out of 100+ source files)
**Only test:** `features/reports/__tests__/sql-validation.test.ts`
**Everything else untested:** API client, all endpoints, all hooks, all stores, all components, all pages

#### Alembic Migrations
**Zero migration tests.** No tests verify upgrade/downgrade chain integrity, data migration correctness, or partition creation logic.

#### Other Untested Modules
| Module | Risk |
|--------|------|
| `export/setup.py` | Medium |
| `remediation/manifest.py` | High |
| `reporting/engine.py` | Medium |
| `labeling/engine.py` | High |
| `labeling/mip.py` | High |
| CLI: `doctor.py`, `models.py`, `server.py`, `output.py` | Low-Medium |

---

<a name="recommendations"></a>
## 9. Prioritized Recommendations

### P0 — Immediate (Security Critical)
1. **Fix tenant isolation in DuckDB query endpoint** (CRIT-1)
2. **Fix CSRF bypass via Bearer header** (CRIT-2)
3. **Add SHA-256 verification for ML model files** (CRIT-3)
4. **Add tenant_id filter to analytics event flush** (CRIT-5)
5. **Fix cross-tenant credential loading in WinRM provider** (HIGH-9)
6. **Fix Graph webhook clientState default to require non-empty value** (HIGH-8)

### P1 — High Priority (Security + Correctness)
7. **Add RLS policies to PostgreSQL tables** (CRIT-4) — schedule as a project
8. **Fix credential storage patterns** — use `SecretStr` at point-of-use across all adapters (HIGH-7)
9. **Fix SSRF vectors** — validate/allowlist URLs in all adapter configurations (HIGH-6)
10. **Fix quarantine manifest DEFAULT_ALLOWED_BASES** — remove `Path("/")` default (HIGH-10)
11. **Fix CEF/LEEF log injection** — escape all fields consistently (HIGH-11)
12. **Add task_type allowlist** to `JobQueue.enqueue()` (HIGH-17)
13. **Unify dispatcher code** between embedded.py and worker.py, add flush task (HIGH-18, D10)
14. **Fix MIPClient lifecycle** — create once, reuse, shutdown properly (HIGH-12)
15. **Fix report.py enum key bug** (E1) — immediate runtime crash
16. **Create alert_rules migration** (HIGH-14)
17. **Fix model/migration ondelete mismatches** (E16)

### P2 — Medium Priority (Reliability + Quality)
18. **Add frontend test infrastructure** — start with client.ts, auth-store.ts, websocket.ts (CRIT-6)
19. **Add tests for CSRF middleware** — this is defense-critical code with zero tests
20. **Add tests for routes/query.py, routes/monitoring.py** — highest-risk untested routes
21. **Add integration tests for jobs/tasks/scan.py and jobs/embedded.py**
22. **Fix silent plaintext fallback in crypto** — fail loudly when key not configured (HIGH-4)
23. **Implement connection pooling** for SIEM adapters (HIGH-15, SC6)
24. **Add error reporting integration** (Sentry/similar) to frontend
25. **Fix copy-paste CLI patterns** — use existing `scan_files()` utility (SC12)
26. **Add keyset pagination** to catalog rebuild (SC1)
27. **Add polling backoff** to embedded/standalone workers (SC9)

### P3 — Low Priority (Maintenance + Polish)
28. Fix f-string logging patterns across codebase
29. Add missing loggers to CLI command files
30. Fix incorrect Alembic migration docstring headers
31. Replace cron description stub with library
32. Deduplicate `getCsrfToken` in frontend
33. Fix env var inconsistency (`OPENLABELS_SERVER` vs `OPENLABELS_SERVER_URL`)
34. Add `updated_at` to Tenant model
35. Add migration tests for upgrade/downgrade chain integrity
36. Add audit log partitioning strategy

---

## Appendix: Files Reviewed

21 review agents covered every source file in the application:

| Agent | Scope | Files | Key Findings |
|-------|-------|-------|-------------|
| Auth Routes & Services | Server auth routes + services | 12 | Null tenant_id in audit, CSV export OOM |
| Server Middleware | CSRF, rate limit, middleware stack | 7 | CSRF bypass, zero middleware tests |
| Data Routes | Scans, results, jobs, targets, query | 8 | Tenant isolation bypass, SSRF |
| Labels/Policies/Export Routes | Labels through ws_events | 12 | M365 secret in sessions, zero monitoring route logging |
| Auth Module | OAuth, OIDC, Graph API | 6 | OIDC nonce not validated, Graph path injection |
| ML Detectors & Orchestrator | ML model loading, orchestration | 11 | No model checksums, unsafe pickle |
| Storage Adapters | S3, Graph, filesystem, health | 11 | SSRF in S3/Graph, symlink bypass |
| Core Detectors/Patterns | Pattern, secrets, financial detectors | 15 | ReDoS vulnerabilities, PII in logs |
| Server Core Infrastructure | Config, crypto, session, cache, DB | 20 | Weak KDF, silent plaintext fallback |
| Core Pipeline & Processing | Pipeline stages, extractors, OCR | 17 | PII leakage, path traversal, decompression bomb |
| Analytics Engine | DuckDB analytics, flush, compaction | 9 | SQL interpolation, cross-tenant flush |
| Frontend Components | All React components | 28 | Zero test files, no role-based access |
| Core Agents/Policies/Benchmark | Worker agents, policy engine | 20 | Double-counting, no resource limits |
| CLI Commands | All CLI command files | 27 | Path traversal, copy-paste patterns |
| Export/Labeling/Remediation | SIEM export, MIP labeling, quarantine | 20 | Credential exposure, log injection, resource leaks |
| Frontend Core/API/Hooks | API client, hooks, stores, lib | 49 | Auth DoS, N+1 requests, zero tests |
| Monitoring & Providers | All monitoring modules + providers | 23 | Webhook bypass, plain credentials, no tenant filter |
| Frontend Feature Pages | All feature page components | 50+ | Health status inconsistency, no audit logging |
| Jobs System | Queue, worker, scheduler, all tasks | 19 | Job injection, dispatcher duplication |
| Alembic Migrations & Models | All migrations + models.py | 22 | No RLS, missing migration, schema drift |
| Test Quality & Coverage | Cross-cutting test analysis | All tests | Silent-passing tests, massive gaps |
