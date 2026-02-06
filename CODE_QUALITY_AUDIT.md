# OpenLabels Code Quality Audit Report

**Date:** 2026-02-06
**Scope:** `src/openlabels/` (232K LOC across 282 Python files + 7 Rust files)
**Goal:** ShowHN readiness — identify and prioritize code smells, security risks, and packaging issues.

---

## Executive Summary

Seven parallel audit agents reviewed the codebase across different quality dimensions. The project has strong fundamentals — good module separation, comprehensive test suite, proper use of async patterns, and solid security basics (parameterized queries, tenant isolation, security headers). However, there are **showstopper issues** that must be fixed before launch, plus a significant backlog of code smells.

| Severity | Count | Description |
|----------|-------|-------------|
| **CRITICAL** | 5 | Build-breaking, security, or legal blockers |
| **HIGH** | 25 | Major code smells, dead modules, missing CI |
| **MEDIUM** | 55+ | DRY violations, broad exception handling, missing types |
| **LOW** | 30+ | Style nits, naming, minor config gaps |

---

## TIER 1: SHOWSTOPPERS (Fix Before Launch)

These will either break your build, expose you legally, or embarrass you on HN.

### 1.1 Dockerfile Is Broken — Won't Build
- **`Dockerfile:21`** — `pip install -e ".[server]"` references a `[server]` extras group that **does not exist** in `pyproject.toml`. Docker build fails immediately.
- **`Dockerfile:20-21`** — Uses editable install (`-e`) but copies `pyproject.toml` *before* `src/`, so there's nothing to install.
- **No `.dockerignore`** — Docker context ships `.git/` (47MB), `tests/`, `__pycache__/`, potentially `.env` files.
- **Fix:** Create `[server]` extras or change to `pip install .`; copy `src/` before install; create `.dockerignore`.

### 1.2 License Is Contradictory and Missing
- `pyproject.toml` says **MIT**. `README.md` says **Apache-2.0**. **No `LICENSE` file exists** in the repo.
- HN commenters *will* notice this. Without a LICENSE file, there is no enforceable license grant.
- **Fix:** Pick one. Add a `LICENSE` file. Update both `pyproject.toml` and `README.md` to match.

### 1.3 Dev Auth Bypass Defaults to Admin for Everyone
- **`auth/oauth.py:68-76`** — When `auth.provider == "none"`, every request gets `roles=["admin"]`. If production accidentally runs with this default, the entire app is wide open.
- **Fix:** Require `server.debug == True` as an additional guard, or refuse to start with `provider="none"` outside development.

### 1.4 Runtime Crash: `/metrics` Endpoint
- **`server/app.py:888-894`** — References `Response`, `generate_latest`, `CONTENT_TYPE_LATEST` which are **never imported**. This endpoint will crash with `NameError` on every request.
- **Fix:** Add the missing imports from `prometheus_client`.

### 1.5 `test_docs/` Contains Internal Audit Reports
- 10 files including `CLAUDE_AUDIT_REPORT.md`, `SECURITY_AUDIT_REPORT.md`, `CODEBASE_AUDIT.md`. These are internal working documents shipped in the repo.
- HN will see your sausage-making process. Not a good look.
- **Fix:** `git rm -r test_docs/` and add to `.gitignore`.

---

## TIER 2: HIGH-PRIORITY CODE SMELLS

### 2.1 Dead Code — Entire Unused Modules (776+ lines to delete)

| File/Module | Lines | Issue |
|-------------|-------|-------|
| `server/streaming.py` | 776 | Never imported by anything. Contains streaming utils, cursor paginator, async helpers — all dead. |
| `server/errors.py` | 320+ | 6 exception classes, 2 data models, 4 helper functions — all dead. Only `ErrorCode` is used (duplicate of classes in `server/exceptions.py`). |
| `core/policies/` (entire package) | ~500 | `engine.py`, `loader.py`, `schema.py` only import each other. Nothing outside ever imports this package. |
| `server/security.py` | 4 funcs | `get_resource_with_tenant_check`, `validate_tenant_id`, `sanitize_for_logging`, `truncate_for_logging` — defined, never called. |

### 2.2 Dead Code — Unused Exceptions & Classes

| File | Item | Line |
|------|------|------|
| `server/exceptions.py` | `AuthenticationError`, `AuthorizationError` | 207, 168 |
| `core/exceptions.py` | `ScoringError`, `ValidationError` | 138, 384 |
| `server/routes/settings.py` | `AzureSettingsForm`, `ScanSettingsForm` | 22, 29 |

### 2.3 Unused Imports (9 findings)
- `server/config.py:14` — `PostgresDsn`, `field_validator`
- `server/metrics.py:11` — `CollectorRegistry`
- `server/dependencies.py:36` — `TYPE_CHECKING`, `Any`
- `server/errors.py:14` — `Request`
- `server/routes/settings.py:11` — `Response`
- `server/app.py:23` — `warnings`

### 2.4 God Modules That Need Splitting

| File | Lines | Problem | Suggested Split |
|------|-------|---------|-----------------|
| `web/routes.py` | 1,393 | 30+ route handlers in one file | `web/routes/dashboard.py`, `targets.py`, `scans.py`, etc. |
| `server/app.py` | 1,079 | App factory + 5 middleware + 5 exception handlers + route mounting + Sentry | `middleware.py`, `exception_handlers.py`, `route_registry.py` |
| `jobs/tasks/scan.py` | `execute_scan_task()` = 374 lines | Single function doing setup, iteration, persistence, labeling, WS streaming | Split into `_process_file()`, `_update_stats()`, `_stream_events()` |

### 2.5 Major DRY Violations

| Pattern | Instances | Files | Fix |
|---------|-----------|-------|-----|
| SharePoint/OneDrive adapters are ~80% identical | 7 methods cloned | `sharepoint.py`, `onedrive.py` | Extract `BaseGraphAdapter` |
| Manual pagination (ignoring existing `paginate_query()`) | 5 copies | `monitoring.py`, `remediation.py` | Use the existing utility |
| Tenant-scoped entity lookup boilerplate | 27+ copies | 10 files | Add `get_tenant_entity()` to `BaseService` |
| HTMX notification response construction | 13+ copies | 6 route files | Extract `htmx_notify()` helper |
| Detector `detect()` iteration/dedup/span-building | 3 copies | `government.py`, `financial.py`, `secrets.py` | Add `_detect_patterns()` to `BaseDetector` |

### 2.6 CI/CD Is Incomplete
- Tests only run on **Python 3.11** — pyproject claims 3.10, 3.11, 3.12 support.
- **No linting or type-checking in CI** — `ruff` and `mypy` are dev deps but never run.
- **No Redis service** in CI — tests requiring Redis will fail silently.
- No publish/release workflow for PyPI.
- No Dependabot configuration.

---

## TIER 3: MEDIUM-PRIORITY ISSUES

### 3.1 Error Handling Anti-Patterns (25 findings)

**Key themes:**

1. **Return-sentinel-on-error (5 critical instances):** Functions return `False`/`None`/`""`/`[]` on error, making it impossible for callers to distinguish expected empty results from failures.
   - `core/detectors/ml_onnx.py:237` — `return False` on model load error
   - `core/detectors/ml_onnx.py:499` — `return []` on inference error (silent false negatives on PII)
   - `labeling/mip.py:822-882` — `get_file_label()` returns `None` for both "no label" and "error reading"

2. **Broad `except Exception` (12 instances):** The codebase has a well-designed exception hierarchy (`DetectionError`, `ExtractionError`, `AdapterError`, etc.) but many modules ignore it and catch `Exception` instead.
   - `core/extractors.py` — 7 extractors catch `Exception` and return empty results
   - `server/cache.py` — 6 Redis operations catch `Exception` instead of `redis.RedisError`

3. **Permanent state changes on transient errors:**
   - `auth/sid_resolver.py:145-147` — A single network blip **permanently** disables Graph API for the singleton instance. Requires process restart to recover.

4. **Silent policy failures:**
   - `core/policies/loader.py:596-608` — Broken policy YAML files are silently skipped. A typo in a GDPR policy means no scans will ever apply GDPR rules, with zero visible indication.

5. **Missing timeout on JWKS fetch:**
   - `auth/oauth.py:57-58` — `httpx.AsyncClient()` with no timeout. If Microsoft's JWKS endpoint hangs, the entire server hangs.

### 3.2 Security Issues

| Finding | File | Risk |
|---------|------|------|
| JWKS cache never expires (key rotation bypass) | `auth/oauth.py:48-61` | HIGH |
| PowerShell command injection via unsanitized path | `monitoring/registry.py:181-197` | HIGH |
| XSS via unescaped HTML f-string construction | `web/routes.py:1334-1344` | MEDIUM |
| CSRF bypass when no Origin/Referer headers present | `server/middleware/csrf.py:86-89` | MEDIUM |
| Docker-compose hardcoded default DB password `openlabels` | `docker-compose.yml:47` | MEDIUM |
| DB credentials hardcoded in compose (not using env var) | `docker-compose.yml:19` | MEDIUM |
| Hardcoded DB URL in alembic.ini | `alembic.ini:92` | MEDIUM |

**Positive security notes:** Parameterized SQL queries throughout, tenant isolation with IDOR logging, comprehensive security headers, Sentry scrubbing, rate limiting, non-root Docker user, path validation module.

### 3.3 Async/Sync Mixing
- `labeling/engine.py` — Multiple `async` methods (`_apply_local_label`, `_apply_office_metadata`, `_apply_pdf_metadata`) do **synchronous** `open()` and `zipfile.ZipFile()` calls, blocking the event loop.
- `core/processor.py` — `_extract_image()` and `_decode_text()` are marked `async` but never `await` anything.
- **Fix:** Wrap blocking I/O in `asyncio.to_thread()` or remove unnecessary `async`.

### 3.4 Duplicate `api_v1_router` Definition
- **`server/app.py:406 + 943`** — `api_v1_router` is defined **twice**. The second assignment silently overwrites the first. Potential bug.

### 3.5 Dead Pydantic Validators
- **`auth/oauth.py:23-34`** — `model_validator_oid` and `model_validator_tenant` are `@classmethod` methods but lack `@field_validator` decorators. They **never execute** as Pydantic validators.

### 3.6 Type Safety Gaps
- `DetectorOrchestrator.__init__` has **13 parameters** — needs a `DetectorConfig` dataclass.
- `update_folder_inventory` has **9 parameters** — needs a `FolderStats` dataclass.
- 12+ uses of `Any` type where more specific types are available.
- Missing type hints on 14 function signatures.

### 3.7 Magic Numbers
- `labeling/engine.py` — `300`, `1000`, `4`, `2.0`, `30.0` all inline without named constants.
- `web/routes.py:45-54` — Time thresholds `60`, `3600`, `86400`, `604800` should be named constants.
- `core/extractors.py:294` — `if compressed_size < 100:` — magic threshold.

---

## TIER 4: LOW-PRIORITY / POLISH

### 4.1 Packaging Polish
- No badges in README (build, coverage, PyPI, license, Python versions)
- No `CONTRIBUTING.md`, `SECURITY.md`, or `CHANGELOG.md`
- Missing `py.typed` PEP 561 marker
- Version hardcoded in both `__init__.py` and `pyproject.toml` (will drift)
- `.gitignore` missing `.mypy_cache/`, `.ruff_cache/`, `coverage.xml`, `config.yaml`
- `docker-compose.yml` uses deprecated `version: "3.8"` key

### 4.2 Naming & Readability
- 9 cryptic variable names (`d`, `n`, `trans`, `mult` in checksum/financial detectors)
- 4 misleading names (`_add()` in 4 detector modules — too generic)
- `US_STATE_ABBREVS` rebuilt on every call inside `_is_false_positive_name()` — hoist to module level
- 3 blocks of stale commented-out code

### 4.3 Deeply Nested Code (>3 levels)
- `auth/__init__.py:14` — 10-deep `if/elif` chain for lazy imports (use dict lookup)
- `gui/workers/scan_worker.py:143` — 8-deep nesting (use dispatch dict)
- `cli/filter_executor.py:216` — 7-deep nesting (use handler dict)

---

## Recommended Fix Order

**Phase 1: Showstoppers (do before ShowHN)**
1. Fix Dockerfile (create `.dockerignore`, fix install command)
2. Resolve license (pick one, add `LICENSE` file)
3. Fix `/metrics` endpoint missing imports
4. Guard dev auth bypass
5. Remove `test_docs/`

**Phase 2: Clean up dead weight**
6. Delete `server/streaming.py`, dead classes in `server/errors.py`
7. Delete or wire up `core/policies/` package
8. Remove unused imports across 9 files
9. Remove unused exception classes and security helpers

**Phase 3: DRY & architecture**
10. Extract `BaseGraphAdapter` from SharePoint/OneDrive
11. Replace manual pagination with existing `paginate_query()`
12. Extract `get_tenant_entity()` utility
13. Extract `htmx_notify()` helper
14. Split god modules (`web/routes.py`, `server/app.py`)

**Phase 4: Error handling & security**
15. Fix broad `except Exception` blocks (use specific exceptions)
16. Fix return-sentinel-on-error pattern
17. Add JWKS cache TTL
18. Fix PowerShell command injection
19. Escape HTML in web routes
20. Add httpx timeout to JWKS fetch

**Phase 5: CI/CD & packaging**
21. Add Python version matrix to CI
22. Add linting/type-checking to CI
23. Add Redis service to CI
24. Add README badges
25. Add `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`
26. Create `.dockerignore`

**Phase 6: Polish**
27. Extract magic numbers to named constants
28. Rename cryptic variables
29. Remove commented-out code
30. Fix async/sync mixing
31. Add missing type hints
