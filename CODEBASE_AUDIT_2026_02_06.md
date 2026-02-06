# OpenLabels Comprehensive Codebase Audit

**Date:** 2026-02-06
**Scope:** Full codebase — 163 source files, 114 test files, 7 Rust files, 32 HTML templates
**Method:** 8 parallel audit agents covering security, correctness, detection engine, error handling, dead code, tests, config/packaging, and spec-vs-implementation gap analysis

---

## Executive Summary

| Severity | Count | Key Themes |
|----------|-------|------------|
| **CRITICAL** | 14 | Auth bypass, command injection, broken Docker build, server crash on startup, CSRF bypass, broken BIP-39 detector, email regex bug |
| **HIGH** | 60+ | Client secret in DB, CSRF weaknesses, hardcoded DB creds, dead code modules, O(n^2) dedup, async/sync mixing, mock-heavy tests, untested service layer |
| **MEDIUM** | 100+ | Broad patterns, magic numbers, DRY violations, missing validation, stale comments, N+1 queries |
| **LOW** | 50+ | Dead imports (87), naming, nesting depth, style nits |

**Bottom line:** The core detection engine and scoring are solid. The server layer has security gaps (auth bypass, CSRF, command injection) and the infrastructure doesn't build (Docker, Sentry crash). Tests exist in quantity (1734 pass) but the 4 service-layer modules (1,962 LOC) have zero coverage, and many tests are AI-generated mock-fests that test nothing real.

---

## PART 1: WHAT'S MISSING (Spec vs. Implementation Gaps)

### Features Promised But Not Implemented

| Feature | Spec Reference | Status | Notes |
|---------|---------------|--------|-------|
| **File-embedded labels** (XMP, custom properties, xattrs) | Spec v2 §4-5 | MISSING | Labels only stored in PostgreSQL. The core portable-label concept from the spec doesn't exist yet. |
| **Azure Cloud Deployment** (Bicep/ARM, Key Vault, Container Apps) | Server Arch §13 | MISSING | Zero IaC templates. The entire cloud deployment story is documentation-only. |
| **Structured Logging** (structlog + request IDs) | Production Plan §6.2 | MISSING | Still using basic `logging` module everywhere. |
| **API Versioning** (`/api/v1/` prefix with `/api/` as alias) | Production Plan §6.3 | PARTIAL | Routes exist at `/api/v1/` but the `/api/` alias is a catch-all redirect, not a proper alias. |
| **Enhanced Health Check** (DB connectivity check) | Production Plan §6.1 | PARTIAL | Health endpoint exists but creates ML detector instances on every call (expensive). |
| **Settings Persistence** (web UI settings forms) | Server routes | STUB | All 4 settings endpoints (`/azure`, `/scan`, `/entities`, `/reset`) accept form data, log it, return "saved" — but **discard all input**. They lie to the user. |
| **ML Detectors** (PHI-BERT, PII-BERT) | Architecture v3 | STUB | Scaffolded classes exist; inference code present but models not bundled. Can't detect PHI/PII via ML. |
| **Coreference Resolution** (FastCoref) | Architecture v3 | STUB | Module exists, imports numpy unconditionally, but disabled by default and untested. |
| **`has_pii` Filter** | Results API | STUB | Parameter accepted by endpoint but never passed to service layer. Silently ignored. |
| **Scan All Sites/Users** (SharePoint/OneDrive) | Config schema | STUB | `scan_all_sites` and `scan_all_users` config keys defined but never read by adapters. |
| **Policy Engine** | `core/policies/` | DEAD | Entire package (3 files, ~500 lines) only imports itself. Nothing outside ever uses it. |
| **Streaming Utilities** | `server/streaming.py` | DEAD | 776 lines, never imported by anything. |

### Features That Diverge From Spec

| Feature | Spec Says | Implementation Does | Impact |
|---------|-----------|-------------------|--------|
| Database schema | `label_objects`, `label_versions`, `watch_list`, `access_events` | `scan_results`, `file_inventory`, `folder_inventory`, `monitored_files`, `file_access_events` | Schema is more comprehensive but different table names/structure. |
| Monitoring watch list | Database-backed | **In-memory dict** (`registry.py:31`) with aspirational comment about database backing | Data lost on restart. |
| `DELETE /scans/{id}` | Delete scan record | Calls `cancel_scan()` | Users expecting deletion get cancellation instead. |

---

## PART 2: SECURITY VULNERABILITIES

### CRITICAL

| # | Finding | File | Line |
|---|---------|------|------|
| S1 | **Auth bypass: `provider="none"` (the default!) grants admin to everyone.** The main `get_current_user` dependency skips token validation entirely and creates an admin user. Any deployment that forgets `AUTH_PROVIDER=azure_ad` is wide open. | `auth/dependencies.py` | 101-109 |
| S2 | **Command injection in `_disable_monitoring_windows`.** Path interpolated into PowerShell f-string with ZERO validation. Compare `_enable_monitoring_windows` which validates. | `monitoring/registry.py` | 249-254 |
| S3 | **Command injection in `_get_history_windows`.** Creates `escaped_path` variable then never uses it — uses raw `path.name` in PowerShell instead. | `monitoring/history.py` | 121-131 |

### HIGH

| # | Finding | File | Line |
|---|---------|------|------|
| S4 | **Client secret stored in plaintext in DB.** `sync_labels` passes `auth.client_secret` into job payload dict, serialized to `JobQueue` table. Any admin API user can read it. | `server/services/label_service.py` | 169 |
| S5 | **CSRF bypass: missing headers = pass.** When both Origin and Referer are absent, `is_same_origin` returns True. Combined with optional token check (S6), CSRF is fully bypassable. | `server/middleware/csrf.py` | 86-89 |
| S6 | **CSRF token only validated when header present.** If `X-CSRF-Token` header is omitted, token check is skipped entirely. Double-submit is effectively optional. | `server/middleware/csrf.py` | 157-168 |
| S7 | **Unauthenticated settings page exposes Azure tenant_id and client_id.** Web UI `/settings` route has no auth dependency. | `web/routes.py` | 201 |
| S8 | **Web form target creation bypasses path validation.** API endpoint calls `validate_target_config()` but web form handler does not. Allows path traversal/SSRF via web UI. | `web/routes.py` | 458-493 |
| S9 | **Hardcoded DB password in docker-compose.** `DATABASE_URL` has literal `openlabels:openlabels` while `POSTGRES_PASSWORD` is configurable — they're disconnected. | `docker-compose.yml` | 19, 47 |

---

## PART 3: BUGS THAT CRASH OR BREAK THINGS

### CRITICAL

| # | Finding | File | Line |
|---|---------|------|------|
| B1 | **Server crashes on startup.** `app.py` calls `init_sentry(settings.sentry, ...)` but `Settings` class has no `sentry` field. `AttributeError` on every startup. | `server/config.py` / `server/app.py` | 460 / 319 |
| B2 | **Docker build fails.** `pyproject.toml` declares `readme = "README.md"` but Dockerfile never copies it. `.dockerignore` excludes `*.md`. Hatchling build fails with `FileNotFoundError`. | `Dockerfile` / `.dockerignore` | 20-23 / 36 |
| B3 | **Timezone mismatch crashes token refresh.** `datetime.min` (naive) compared to `datetime.now(timezone.utc)` (aware) raises `TypeError`. | `server/routes/auth.py` | 557 |
| B4 | **`pending_count`/`failed_count` used outside their scope.** If queue health check fails, these variables are undefined → `NameError`. | `server/routes/health.py` | 305 |

### HIGH

| # | Finding | File | Line |
|---|---------|------|------|
| B5 | **Email regex matches literal pipe `\|`.** `[A-Z\|a-z]{2,}` includes `\|` as matchable char. `user@example.co\|m` would match. | `core/detectors/patterns.py` | 210-211 |
| B6 | **BIP-39 seed phrase detector is broken.** Sample set has 17 of 2048 words. Requires 50% match → real seed phrases fail at ~8%. | `core/detectors/financial.py` | 234-248 |
| B7 | **JSON/CSV exports not actually streaming.** Both accumulate all data in memory, then send as single chunk via `StreamingResponse`. DoS risk on large datasets. | `server/routes/results.py` | 224-278 |
| B8 | **Installer script won't compile.** `ResultCode` variable used in `CheckDockerRequirement` but only declared in `IsDockerInstalled`. Inno Setup rejects it. | `installer/openlabels.iss` | 102 |
| B9 | **Duplicate `api_v1_router` definition.** Defined twice in `app.py`. Second silently overwrites first. | `server/app.py` | 406, 943 |

---

## PART 4: DETECTION ENGINE ISSUES

| # | Finding | Severity | File | Line |
|---|---------|----------|------|------|
| D1 | Context enhancer mutates Span objects in-place, corrupting shared state. Field-by-field mutation has intermediate invalid state. | CRITICAL | `core/pipeline/context_enhancer.py` | 493-496 |
| D2 | Deduplication is O(n^2). For documents with 5000+ spans, this is a bottleneck. | HIGH | `core/detectors/orchestrator.py` | 350-385 |
| D3 | Partial overlaps not handled in dedup. Two spans that partially overlap are both kept, producing confusing redactions. | HIGH | `core/detectors/orchestrator.py` | 368-385 |
| D4 | `detect()` convenience function creates new orchestrator per call. Compiles all regex, initializes all detectors every time. | HIGH | `core/detectors/orchestrator.py` | 408-449 |
| D5 | CUSIP/ISIN validators duplicated in `checksum.py` AND `financial.py` with different interfaces. Same entity detected twice. | HIGH | `checksum.py` / `financial.py` | 375-432 / 32-92 |
| D6 | PatternDetector has no deduplication (unlike all other detectors that use a `seen` set). | HIGH | `core/detectors/patterns.py` | 1462-1540 |
| D7 | OCR line grouping uses hardcoded 20px threshold. Breaks on different DPI/font sizes. | HIGH | `core/ocr.py` | 399-414 |
| D8 | Litecoin/Dogecoin/XRP patterns have no checksum validation. Any Base58 string of right length matches. | MEDIUM | `core/detectors/financial.py` | 302-310 |
| D9 | Bech32 validation skips actual checksum, only checks character set. | MEDIUM | `core/detectors/financial.py` | 192-216 |
| D10 | SEDOL bare pattern matches any 7-char consonant+digit string. Weak checksum. | HIGH | `core/detectors/financial.py` | 278 |

---

## PART 5: ERROR HANDLING & ASYNC ISSUES

### Blocking I/O in Async Functions (CRITICAL)

These `async def` functions perform synchronous file I/O that blocks the event loop:

| File | Methods | Blocking Calls |
|------|---------|---------------|
| `labeling/engine.py` | `_apply_office_metadata`, `_apply_pdf_metadata`, `_apply_sidecar`, `_remove_office_label`, `_remove_pdf_label`, `_get_local_label` | `open()`, `zipfile.ZipFile()`, `io.BytesIO` |
| `adapters/filesystem.py` | `_walk_directory`, `get_metadata` | `iterdir()`, `is_file()`, `stat()` |

### Broad `except Exception` (21 instances)

| File | Line | Impact |
|------|------|--------|
| `adapters/onedrive.py` | 78-83 | Entire OneDrive enumeration silently returns empty on any error |
| `adapters/onedrive.py` | 160-166 | Sub-folder enumeration silently skipped on any error |
| `adapters/graph_base.py` | 145-151 | `_test_connection` swallows all errors, returns False |
| `auth/dependencies.py` | 164-168 | `get_optional_user` catches all exceptions at DEBUG level — config errors degrade to anonymous |
| `server/cache.py` | 6 instances | Redis operations catch `Exception` instead of `redis.RedisError` |
| `core/extractors.py` | 7 instances | All extractors return empty results on any error |

### Return-Sentinel-on-Error

| File | Line | Returns | Should Do |
|------|------|---------|-----------|
| `labeling/mip.py` | 188-217 | `""` on auth failure | Raise AuthenticationError |
| `labeling/mip.py` | 431-449 | `[]` on error AND no-labels | Raise on error, return [] only for no-labels |
| `server/services/result_service.py` | 226-244 | `None` on not-found | Raise NotFoundError (inconsistent with other services) |

---

## PART 6: DEAD CODE & AI SLOP

### Dead Code Summary

| Category | Count | Highlights |
|----------|-------|-----------|
| **Dead imports** | 87 | Spread across all packages. GUI is worst (29 dead imports). |
| **Dead functions/classes** | 17 | 3 in `path_validation.py` (entire public API unused), 3 circuit breaker factories, `handle_http_error` utility, `LabelMappingsUpdate` schema |
| **Dead loggers** | 6 | `logger` created but never called |
| **Dead modules** | 2 | `server/streaming.py` (776 lines), `core/policies/` package (~500 lines) |
| **Commented-out code** | 4 blocks | Stale orchestrator registration, commented ML imports |
| **Unused config keys** | 2 | `scan_all_sites`, `scan_all_users` |

### AI Slop Indicators

| Finding | Location | Evidence |
|---------|----------|---------|
| **Stale project name** | `additional_patterns.py:3`, `patterns.py:771` | References to "scrubiq" (old project name) |
| **Stale wiring instructions** | `additional_patterns.py:249-261` | 13-line commented block explaining how to register detector — already done |
| **Triple-duplicated validators** | `checksum.py`, `financial.py`, `_rust/validators_py.py` | CUSIP, ISIN, Luhn, SSN each implemented 3 times independently |
| **Template exception docstrings** | `core/exceptions.py` | 384 lines of 10 exception classes, each with identical Examples:/Usage: template structure |
| **Verbatim-mirror docstrings** | `web/routes.py` | `def scans_page` → `"""Scans page."""` (5 instances) |
| **Aspirational comments** | `monitoring/registry.py:31` | "In production, this would be backed by a database" — this IS production code |
| **`handle_http_error` utility exists but unused** | `cli/utils.py:38` | Written, never called. Same HTTP error handling copy-pasted 15+ times across CLI commands instead. |

---

## PART 7: TEST SUITE ISSUES

### Test Results

- **1734 passed**, 1 failed, 53 skipped
- Many test modules fail to collect due to missing dependencies in CI
- `pyproject.toml` `addopts` includes `--cov` but `pytest-cov` not in test deps

### Critical Coverage Gaps

**4 service-layer modules (1,962 lines) have ZERO test coverage:**

| Module | Lines | What It Does |
|--------|-------|-------------|
| `server/services/scan_service.py` | 503 | All scan orchestration logic |
| `server/services/job_service.py` | 449 | All job queue management |
| `server/services/label_service.py` | 517 | All label operations |
| `server/services/result_service.py` | 493 | All result queries/exports |

42 source modules total have zero test coverage.

### Test Quality Issues

| Issue | Count | Examples |
|-------|-------|---------|
| **Tests with zero assertions** | 28 | `test_worker_loop_exits_on_concurrency_reduction`: comment says "no assertion needed" |
| **Overly broad status assertions** | 10+ | `assert response.status_code in (200, 201, 400, 422)` — accepts anything |
| **Accepts HTTP 500 as valid** | 1 | `test_input_validation.py:730`: `assert status_code in (200, 400, 422, 500)` |
| **Mock:test ratio > 10x** | 1 file | `test_scan.py`: 561 mocks for 39 tests (14.4x ratio) — tests only verify mocks were called |
| **"Should not raise" as only contract** | 16 tests | No actual behavior verification |
| **Duplicate `_comprehensive` files** | 4 pairs | AI-generated test expansions bolted alongside originals |
| **`sys.path.insert` hacks** | 13 files | Test environment not properly configured |

---

## PART 8: INFRASTRUCTURE & PACKAGING

### CRITICAL

| # | Finding | File |
|---|---------|------|
| I1 | Server crashes on startup — `settings.sentry` undefined | `config.py` / `app.py` |
| I2 | Docker build fails — `README.md` not copied, excluded by `.dockerignore` | `Dockerfile` / `.dockerignore` |
| I3 | `DATABASE_URL` hardcoded password doesn't match configurable `POSTGRES_PASSWORD` | `docker-compose.yml` |

### HIGH

| # | Finding | File |
|---|---------|------|
| I4 | No Redis service in CI — Redis-dependent tests fail silently | `.github/workflows/test.yml` |
| I5 | CI only tests Python 3.11, not 3.10 or 3.12 (both declared supported) | `.github/workflows/test.yml` |
| I6 | Redis service commented out in production compose but application requires it | `docker-compose.yml` |
| I7 | Installer script won't compile — undeclared variable | `installer/openlabels.iss` |
| I8 | No linting or type-checking in CI (`ruff`, `mypy` configured but never run) | `.github/workflows/test.yml` |

### MEDIUM

| # | Finding | File |
|---|---------|------|
| I9 | Version drift: installer says 1.0.0, package says 0.1.0 | `openlabels.iss` / `pyproject.toml` |
| I10 | API deprecation sunset date `2025-06-01` already passed | `server/app.py` |
| I11 | Test compose binds Postgres+Redis to 0.0.0.0 (network exposed) | `docker-compose.test.yml` |
| I12 | Hardcoded fallback DB URL in `alembic.ini` with no credentials | `alembic.ini` |
| I13 | Deprecated `version: "3.8"` in docker-compose | `docker-compose.yml` |
| I14 | Copyright year 2024 in LICENSE (current year is 2026) | `LICENSE` |

---

## PART 9: DRY VIOLATIONS

| Pattern | Copies | Files | Fix |
|---------|--------|-------|-----|
| File-processing loop in CLI commands | 6 | classify, find, report, heatmap, quarantine, lock-down | Extract `scan_files()` helper |
| HTTP error handling in CLI | 15+ | All CLI command files | Use existing `handle_http_error()` from `utils.py` |
| SharePoint/OneDrive adapter logic | ~80% identical | `sharepoint.py`, `onedrive.py` | Extract `BaseGraphAdapter` |
| Tenant-scoped entity lookup | 27+ | 10 server files | Add `get_tenant_entity()` to BaseService |
| HTMX notification response | 13+ | 6 route files | Already have `htmx_notify()` — use it consistently |
| CUSIP/ISIN/Luhn/SSN validation | 3x each | `checksum.py`, `financial.py`, `_rust/validators_py.py` | Single source of truth |

---

## RECOMMENDED FIX ORDER

### Phase 1: Make It Run (Day 1)
1. Add `sentry: SentrySettings = SentrySettings()` to `Settings` class → server can start
2. Add `COPY README.md .` to Dockerfile before `pip install` → Docker can build
3. Template `DATABASE_URL` from `POSTGRES_PASSWORD` in compose → DB connects
4. Guard `provider="none"` auth bypass with `server.debug == True` check

### Phase 2: Security (Day 2-3)
5. Fix command injection in `_disable_monitoring_windows` and `_get_history_windows`
6. Require CSRF token header on all state-changing requests
7. Add auth to web UI settings page
8. Add `validate_target_config()` to web form handlers
9. Stop storing client secret in job payload

### Phase 3: Detection Engine Fixes (Day 3-4)
10. Fix email regex `[A-Z|a-z]` → `[A-Za-z]`
11. Fix BIP-39 sample set (load full 2048-word list)
12. Fix Span mutation (return new Span instead of mutating)
13. Add dedup to PatternDetector

### Phase 4: Dead Code Cleanup (Day 4-5)
14. Delete `server/streaming.py` (776 dead lines)
15. Delete or wire up `core/policies/` package (~500 dead lines)
16. Remove 87 dead imports
17. Remove 17 dead functions
18. Remove stale `scrubiq` references and commented-out code
19. Consolidate triplicated validators

### Phase 5: Test Quality (Week 2)
20. Write real tests for the 4 service-layer modules (1,962 LOC, zero coverage)
21. Fix 28 tests with zero assertions
22. Replace overly broad status assertions
23. Add `pytest-cov` to test dependencies
24. Add Redis service to CI
25. Add Python 3.10/3.12 to CI matrix

### Phase 6: Polish (Week 3)
26. Replace `except Exception` with specific exception types (21 instances)
27. Wrap blocking I/O in `asyncio.to_thread()` (labeling/engine.py, filesystem adapter)
28. Extract CLI file-processing helper (eliminate 6 copies)
29. Wire up `handle_http_error` utility (eliminate 15 copies)
30. Add structured logging (structlog)

---

*Report generated by 8 parallel audit agents scanning 279 Python files, 7 Rust files, and 32 HTML templates.*
