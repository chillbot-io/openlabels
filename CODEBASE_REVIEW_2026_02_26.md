# OpenLabels Codebase Health Review

**Date:** 2026-02-26
**Scope:** Full application review - 200,398 lines across 624 files
**Method:** 20 parallel deep-review agents, each reading every file in their assigned section
**Categories:** Security Errors, Errors & Omissions, Non-scalable Patterns, AI Slop, Log Coverage, Test Coverage

---

## Executive Summary

| Severity | Count | Breakdown |
|----------|-------|-----------|
| **CRITICAL** | 11 | 3 security, 2 bugs, 6 test coverage |
| **HIGH** | 64 | 15 security, 14 bugs, 10 scalability, 5 logging, 20 test coverage |
| **MEDIUM** | ~150 | Distributed across all categories |
| **LOW** | ~160 | Mostly AI slop, minor logging, minor test quality |

The application has solid architecture and good patterns in many areas, but the rapid development pace has left significant gaps in **security boundaries**, **test coverage**, and **credential handling**. The most urgent issues are: a confirmed bug causing double query consumption, credential injection via JSONB configs, path traversal vulnerabilities in multiple modules, and entire security-critical modules with zero test coverage.

---

## CRITICAL Findings (Immediate Action Required)

### CRIT-1: Credential Injection via ScanTarget.config JSONB
- **Location:** `src/openlabels/jobs/tasks/scan.py:857-891`
- **Category:** Security
- **Description:** Credentials can be injected via the `ScanTarget.config` JSONB column, bypassing `SecretStr` protections used elsewhere. Secrets are stored in plaintext in the database.
- **Fix:** Encrypt credentials in the JSONB column using the same Fernet encryption used by `SavedCredential`.

### CRIT-2: Double Cursor Consumption Bug in `assign_targets`
- **Location:** `src/openlabels/server/services/policy_service.py:176-197`
- **Category:** Confirmed Bug
- **Description:** `existing.scalar_one_or_none()` is called twice on the same result cursor. The second call always returns `None` (cursor exhausted), triggering a redundant re-query. The developer noticed something was wrong but patched around it incorrectly.
- **Fix:** Store the result of the first `scalar_one_or_none()` call in a variable and use it.

### CRIT-3: Path Traversal in Policy Quarantine Action
- **Location:** `src/openlabels/core/policies/actions.py:86-96`
- **Category:** Security
- **Description:** The `quarantine()` method constructs filesystem paths using `ctx.file_path` and `ctx.tenant_id` without any sanitization. An attacker controlling `file_path` could inject `../../etc/passwd` to read/move arbitrary files.
- **Fix:** Validate that `ctx.file_path` resolves within an expected base directory using `Path.resolve()`.

### CRIT-4: SQL Execution with Client-Side-Only Protection
- **Location:** `frontend/src/features/reports/page.tsx:53-80, 148-157`
- **Category:** Security
- **Description:** The `DANGEROUS_SQL_PATTERNS` regex is the only guard against destructive SQL. It only warns the user, then allows execution anyway. AI-generated SQL bypasses even this cosmetic check entirely via `handleRunGenerated()`.
- **Fix:** The backend MUST enforce read-only queries (read-only DB role or server-side SQL validation). Client-side checking is cosmetic only.

### CRIT-5: M365 Client Secret Stored Unencrypted in Session
- **Location:** `src/openlabels/server/routes/m365.py:510-514`
- **Category:** Security
- **Description:** After auto-registering an M365 app, the `client_secret` is stored in plaintext in the session store (database), unlike `SavedCredential` which uses Fernet encryption.
- **Fix:** Encrypt `m365_app_credentials` using `_encrypt()` from `credentials.py` before storing in session.

### CRIT-6: Default Password Fallback in docker-compose.yml
- **Location:** `docker-compose.yml:19,35,70`
- **Category:** Security / Infrastructure
- **Description:** The `migrate`, `api`, and `worker` services use `${POSTGRES_PASSWORD:-changeme_dev_only}` as default. If someone sets an empty `POSTGRES_PASSWORD=`, all services silently accept the fallback.
- **Fix:** Use `${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD}` consistently across all services.

### CRIT-7-11: Zero Test Coverage on Security-Critical Modules
- **`auth/oidc_provider.py`** (420 lines) - JWT validation, token exchange, JWKS handling - ZERO tests
- **`server/routes/enumerate.py`** (854 lines) - subprocess calls, credential handling - ZERO tests
- **`server/routes/m365.py`** (602 lines) - OAuth consent, app registration, secret storage - ZERO tests
- **No authorization boundary tests** - ALL tests run as admin, zero verification that viewer role is actually rejected
- **`test_phase_*.py` files** (~67 occurrences) - parse source code as strings instead of testing behavior, providing false confidence

---

## HIGH Findings by Area

### Security (15 findings)

| ID | Location | Issue |
|----|----------|-------|
| H-S1 | `server/routes/health.py:823-932` | System alert rules shared across tenants - no tenant isolation |
| H-S2 | `server/routes/m365.py:425-540` | M365 consent callback lacks user re-authentication |
| H-S3 | `remediation/quarantine.py:342-419` | `restore_from_quarantine` missing path traversal validation |
| H-S4 | `remediation/permissions.py:160-173` | Command injection via unvalidated principal names in subprocess |
| H-S5 | `core/agents/pool.py:679,727` | File read bypasses `path_validation.validate_path()` |
| H-S6 | `analytics/storage.py:203-206` | S3/Azure storage: no path traversal protection (unlike LocalStorage) |
| H-S7 | `server/services/result_service.py:125-216` | User-controlled field names in `getattr()` without allowlist |
| H-S8 | `cli/utils.py:58-77` | `collect_files` follows symlinks without boundary check |
| H-S9 | `server/routes/auth.py:117` | `_refresh_locks` dict grows unbounded (no eviction) |
| H-S10 | `installer/config.sample.yaml:13` | Ships with `0.0.0.0` binding - exposes API on all interfaces |
| H-S11 | `server/routes/monitoring.py:765-781` | Retention settings global in-memory, not tenant-scoped |
| H-S12 | Redis (docker-compose.yml) | No authentication configured - any process on Docker bridge can access |
| H-S13 | `frontend/src/features/setup/wizard-page.tsx:63-65` | SMB credentials held in React state throughout wizard lifetime |
| H-S14 | `frontend/src/features/reports/page.tsx:148-157` | AI-generated SQL bypasses dangerous pattern check entirely |
| H-S15 | Security test permanently skipped (`test_authorization_escalation.py:333`) | Token validation test unconditionally `@pytest.mark.skip` |

### Bugs & Logic Errors (14 findings)

| ID | Location | Issue |
|----|----------|-------|
| H-B1 | `core/benchmark/adapters.py:1166-1169` | Missing f-string prefix - `{cache_path}` printed as literal |
| H-B2 | `core/circuit_breaker.py:247-255` | `__call__` decorator wraps sync functions as async - silent misbehavior |
| H-B3 | `server/routes/auth.py:834` | `UnboundLocalError` if no session cookie - `session_data` never assigned |
| H-B4 | `server/routes/results.py:359-382` | Inconsistent commit pattern (direct `db.delete` vs service layer) |
| H-B5 | `cli/find.py:119` | Sort-by-tier crashes on unexpected `RiskTier` values (`ValueError`) |
| H-B6 | `cli/find.py:133` | `json.dumps` of `RiskTier` enum without `default=str` - `TypeError` |
| H-B7 | `core/pipeline/confidence.py:70-76` | `_next_ceiling()` crashes on unknown Tier (`ValueError`) |
| H-B8 | `server/routes/jobs.py:228-232` | `Query()` used instead of `Field()` in Pydantic body model - validation bypassed |
| H-B9 | `adapters/azure_blob.py:147`, `gcs.py:147` | `list(paged_iter)` materializes ALL pages into memory at once (OOM risk) |
| H-B10 | `graph_client.py:73-96` | Token bucket race condition - lock released before sleep |
| H-B11 | `monitoring/usn_journal.py:288-313` | Stub function produces incorrect paths + floods logs with WARNINGs |
| H-B12 | `monitoring/stream_manager.py:291-294` | Multi-tenant events silently dropped - only first tenant per path stored |
| H-B13 | `adapters/__init__.py:40` | `FolderInfo` in `__all__` but never imported - `AttributeError` at runtime |
| H-B14 | `core/agents/worker.py:152` | Imports `SensitiveDataProcessor` which may not exist - agent pool non-functional |

### Scalability (10 findings)

| ID | Location | Issue |
|----|----------|-------|
| H-P1 | `core/detectors/orchestrator.py:575-663` | O(n^2) ensemble boost - every span compared against every other |
| H-P2 | `server/routes/permissions.py:497-548` | Folder tree loads ALL rows into memory (no LIMIT) |
| H-P3 | `server/middleware/rate_limit.py:95-131` | In-memory tenant rate limiter never evicts stale entries |
| H-P4 | `export/engine.py:51-96` | All export records loaded into memory (no streaming) |
| H-P5 | `cli/` (6+ files) | Entire file read into memory for every file processed |
| H-P6 | `alembic migration d4e5f6a7b8c9:126` | Unbatched full-table copy in single transaction (locks table) |
| H-P7 | `alembic migration d4e5f6a7b8c9:129` | `DROP TABLE CASCADE` silently drops FK constraints |
| H-P8 | No K8s/production orchestration manifests | Only docker-compose for deployment |
| H-P9 | No reverse proxy / TLS configuration | No HTTPS termination anywhere |
| H-P10 | No PostgreSQL backup strategy | Data on Docker volume with no backup config |

### Logging (5 findings)

| ID | Location | Issue |
|----|----------|-------|
| H-L1 | `server/routes/results.py:346-356` | No audit log for mass result deletion (destructive admin operation) |
| H-L2 | `core/detectors/orchestrator.py:657` | PII text (`span.text`) logged at DEBUG - SSNs, credit cards in logs |
| H-L3 | `core/pipeline/context_enhancer.py:582-585` | PII logged without masking despite `_mask_pii()` helper existing |
| H-L4 | `server/services/result_service.py:224-242` | No security logging for cross-tenant access denial |
| H-L5 | `server/security.py:19-50` | `log_security_event` function exists but is NEVER called anywhere |

### Test Coverage (20 findings)

| Module | Lines | Issue |
|--------|-------|-------|
| `adapters/graph_client.py` | 644 | Most complex adapter module - ZERO tests |
| `adapters/graph_base.py` | 317 | Shared Graph logic - ZERO tests |
| `core/agents/pool.py` + `worker.py` | ~1500 | Agent pool lifecycle - ZERO tests |
| `core/path_validation.py` | ~200 | Security-critical path validation - ZERO unit tests |
| `core/extractors.py` | ~1200 | 9 file format extractors - ZERO tests |
| `core/processor.py` | ~500 | File processing pipeline - ZERO tests |
| `core/circuit_breaker.py` | ~290 | Circuit breaker state machine - ZERO tests |
| `core/ocr.py` | ~600 | OCR engine - ZERO tests |
| `core/pipeline/coref.py` | 838 | Coreference resolution - ZERO tests |
| `core/pipeline/span_resolver.py` | 206 | Span overlap resolution - ZERO tests |
| `core/detectors/allowlist.py` | 177 | Allowlist suppression - ZERO tests |
| `server/services/job_service.py` | 402 | Job orchestration (13 methods) - ZERO tests |
| `server/services/label_service.py` | 465 | Label sync + bulk apply - ZERO tests |
| `monitoring/wef_setup.py` | 334 | WEF subscription management - ZERO tests |
| `monitoring/winrm_remote.py` | 348 | WinRM credential + injection prevention - ZERO tests |
| `cli/benchmark.py` | 956 | Largest CLI command - ZERO tests |
| `cli/catalog.py` | 345 | DB pagination logic - ZERO tests |
| `cli/index.py` | 422 | 5 subcommands - ZERO tests |
| `cli/system.py` | 382 | Backup/restore with subprocess - ZERO tests |
| Frontend (all) | ~12K | ZERO test files in any frontend directory |

---

## MEDIUM Findings Summary

### Security (~25 findings)
- ILIKE search parameters not escaped for SQL wildcards (4 locations in routes)
- WebSocket origin validation allows missing Origin header
- Missing rate limiting on bulk import endpoints (unbounded list sizes)
- `ast.literal_eval` fallback for ACL backup data deserialization
- OData injection regex uses blocklist instead of allowlist
- Credentials stored as plain strings on adapter instances (no `SecretStr`)
- `cleanup_old_scans` accepts active status values - could delete running scans
- SSRF: M365 content blob URI validation doesn't check HTTPS scheme
- f-string SQL interpolation pattern in `result_service.py` (fragile precedent)

### Bugs (~30 findings)
- Missing `await db.commit()` in `dev_login` endpoint
- `_enrich_schedule` N+1 query in list endpoint
- Rollback missing `FOR UPDATE` lock (TOCTOU race)
- TOCTOU race in `delete_results` (COUNT then DELETE)
- `get_result` returns `None` instead of raising `NotFoundError` (inconsistent with all other services)
- Bare `except Exception: pass` silently swallows errors (policies, schedules)
- `Retry-After` header parsing assumes integer (crashes on date format)
- Recursive folder listing can cause stack overflow (unbounded recursion in 5 adapter files)
- No timeouts on `asyncio.to_thread` calls in cloud adapters
- No retry logic in S3/Azure/GCS adapters (unlike GraphClient)
- `LabelCache` global singleton with no tenant isolation
- `LabelingEngine._apply_local_label` creates new MIPClient on every call (leaks resources)
- `fcntl` import fails on Windows (compaction.py)

### Scalability (~20 findings)
- Report data loads up to 50K results into memory for processing
- Dashboard heatmap builds nested dict tree for 10K files in-memory
- Error log aggregation sorts/paginates in Python instead of SQL
- Export streaming fallback has no row limit
- `QuarantineManifest` loads entire JSON manifest into memory
- `SIDResolver.resolve_batch` launches unlimited concurrent Graph API calls
- OFFSET-based pagination in catalog rebuild (degrades at scale)
- Sequential file processing with no parallelism across CLI
- Dictionary `find_matches` is O(N*M) for large dictionaries

### AI Slop (~20 findings)
- Copy-paste code: WS receive loop duplicated between ws.py and ws_events.py
- Copy-paste code: PubSub broadcaster classes nearly identical
- Copy-paste code: 30-line file-scan pattern duplicated 7+ times in CLI
- Copy-paste code: Bulk remediation logic duplicated from single endpoints
- Copy-paste code: Credential resolution duplicated between SharePoint/OneDrive enumerate
- Copy-paste code: Target list page duplicated between targets/ and config-resources/
- Copy-paste code: Schedule form duplicated between schedules/ and scan-config/
- Copy-paste code: linux.py and windows.py monitoring providers are 98% identical
- Massive FALSE_POSITIVE_NAMES frozenset (170 lines) with duplicates
- Verbose calibration tuning history comments inline (belong in docs)
- `_INJECTION_CHARS` set duplicated in 3 monitoring files
- S3 adapter `_iter_pages_sync` is dead code (never called)
- Duplicate `_dict_of_lists_to_list_of_dicts` function across benchmark files

### Log Coverage (~15 findings)
- Missing audit logging for alert rule CRUD operations
- Missing audit logging for system alert rules
- Missing logging on bulk remediation failures (silently skipped)
- Missing logging in entire permissions module (logger declared but never used)
- f-string logger usage throughout (defeats lazy evaluation)
- No logging on adapter initialization or connection establishment
- User email logged at INFO on every request (PII in logs at volume)
- Missing logging when notifications are dropped (queue full)
- `wevtutil` failure produces zero events with no log message

### Test Quality (~25 findings)
- Massively duplicated `detector` fixture - same fixture defined 70+ times
- Duplicated `make_span` helper in 13+ files (shared version exists but unused)
- All auth tests bypass real authentication (admin-only fixture)
- Rate limiting tested via source code inspection, not behavior
- `test_phase_*.py` files parse source as strings (~67 occurrences)
- Conditional `if` guards silently skip assertions in test_scans.py
- ~750 lines of rate limiter boilerplate in test_auth.py
- Duplicate test directories: tests/pipeline/ duplicates tests/core/pipeline/
- No shared conftest.py in most test subdirectories
- ~928 occurrences of `# ===...===` separator comments (AI-generated noise)

---

## Recommendations: Priority Action Plan

### Tier 1: Fix Now (Security + Confirmed Bugs)
1. Fix double cursor consumption in `policy_service.py:assign_targets` (CRIT-2)
2. Add path validation to `policies/actions.py:quarantine()` (CRIT-3)
3. Encrypt credentials in `ScanTarget.config` JSONB (CRIT-1)
4. Encrypt M365 client secret in session store (CRIT-5)
5. Enforce read-only SQL on the backend for reports endpoint (CRIT-4)
6. Fix `docker-compose.yml` password defaults (CRIT-6)
7. Add Redis authentication (H-S12)
8. Add tenant isolation to system alert rules (H-S1)
9. Validate principal names before passing to subprocess (H-S4)
10. Add path traversal protection to S3/Azure storage (H-S6)

### Tier 2: This Sprint (High-Impact Bugs + Missing Safety)
1. Fix missing f-string prefix in benchmark error message (H-B1)
2. Fix `CircuitBreaker.__call__` sync/async mismatch (H-B2)
3. Fix cloud adapter `list(paged_iter)` OOM risk (H-B9)
4. Fix token bucket race condition in GraphClient (H-B10)
5. Fix `stream_manager` multi-tenant event loss (H-B12)
6. Fix PII logging in orchestrator and context_enhancer (H-L2, H-L3)
7. Add audit logging for mass result deletion (H-L1)
8. Wire up `log_security_event` or remove dead code (H-L5)
9. Fix `Pydantic Query() vs Field()` in jobs.py (H-B8)
10. Fix `FolderInfo` missing import in adapters/__init__.py (H-B13)

### Tier 3: Next Sprint (Test Coverage + Scalability)
1. Add tests for `oidc_provider.py`, `enumerate.py`, `m365.py`
2. Add authorization boundary tests (viewer vs admin role)
3. Add tests for `graph_client.py`, `path_validation.py`, `extractors.py`
4. Delete/rewrite all `test_phase_*.py` files (false confidence)
5. Fix O(n^2) ensemble boost with interval tree/sweep line
6. Add LIMIT to folder tree query
7. Stream export records instead of materializing in memory
8. Add connection pool eviction to in-memory rate limiter
9. Add frontend test infrastructure (at minimum for security validation functions)
10. Consolidate duplicated test fixtures into shared conftest files

### Tier 4: Ongoing (Code Quality + Infrastructure)
1. Extract duplicated code patterns (CLI scan loop, WS receive loop, monitoring providers)
2. Remove AI slop (verbose docstrings, obvious comments, calibration notes)
3. Add structured JSON logging configuration for containers
4. Add Docker resource limits for worker service
5. Add container image scanning in CI/CD
6. Add TLS/reverse proxy configuration
7. Add PostgreSQL backup strategy
8. Pin Docker image versions
9. Add worker healthcheck
10. Configure graceful shutdown (`stop_grace_period`)

---

*Report generated by 20 parallel review agents examining all 624 source files (200,398 lines) in the OpenLabels codebase.*
