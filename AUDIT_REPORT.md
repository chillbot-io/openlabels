# OpenLabels Code Audit Report

**Date:** 2026-03-03
**Scope:** Full codebase — 512 Python files, 139 TypeScript/TSX files
**Method:** 10 parallel audit agents (6 code quality, 4 security red team)

---

## Executive Summary

The OpenLabels codebase is **generally well-engineered** with strong security fundamentals (RLS, parameterized queries, XXE protection, CSRF middleware, rate limiting, non-root containers). However, this audit identified **4 critical security issues**, **several high-severity vulnerabilities**, and meaningful code quality improvements across god files, DRY violations, and AI slop.

### Finding Counts

| Category           | Critical | High | Medium | Low |
|--------------------|----------|------|--------|-----|
| Security           | 4        | 10   | 10     | 6   |
| Code Quality       | —        | 3    | 6      | 5   |

---

## Part 1: Security Findings

### CRITICAL

#### S1. SQL LIMIT Clause Injection
**Files:** `src/openlabels/server/routes/query.py:535, 621, 745`

LIMIT values are interpolated via f-string instead of parameterized:
```python
limited_sql = f"SELECT * FROM ({execution_sql}) AS __q LIMIT {body.limit + 1}"
```
Although `body.limit` is Pydantic-validated as an integer, this is an unparameterized SQL clause. If validation is ever bypassed or the pattern is copied elsewhere, it enables injection.

**Fix:** Use parameterized LIMIT: `LIMIT ?` with the value passed as a bind parameter.

---

#### S2. Hardcoded Developer Credentials
**File:** `src/openlabels/server/routes/auth.py:768`

The `/auth/dev-login` endpoint accepts hardcoded `admin:admin` credentials:
```python
if body.username != "admin" or body.password != "admin":
```
Guarded by `AUTH_PROVIDER=none` + `DEBUG=true` checks, but if dev mode is accidentally enabled in staging/production, anyone with knowledge of these credentials gets full admin access.

**Fix:** Generate random dev credentials per deployment via environment variables, or remove the endpoint entirely from production builds.

---

#### S3. Open Redirect via `post_logout_redirect_uri`
**File:** `src/openlabels/server/routes/auth.py:871`

Uses `request.base_url` directly in the Azure AD logout redirect:
```python
logout_url = f"...post_logout_redirect_uri={quote(str(request.base_url), safe='')}"
```
An attacker who can manipulate the `Host` or `X-Forwarded-Host` header (misconfigured reverse proxy) can redirect users to attacker-controlled domains after logout.

**Fix:** Validate `request.base_url` against an explicit allowlist of trusted hosts.

---

#### S4. Plaintext Session Token Storage
**File:** `src/openlabels/server/session.py:44-58`

Session encryption via Fernet is optional. When `AUTH_SESSION_ENCRYPTION_KEY` is not set, access tokens, refresh tokens, and ID tokens are stored as plaintext in PostgreSQL. A production `RuntimeError` guard exists but only triggers on first use, not at startup.

**Fix:** Move the encryption-required check to application startup in `lifespan.py` so deployment fails immediately. Require the key for staging environments as well.

---

### HIGH

| ID | Issue | File(s) | Summary |
|----|-------|---------|---------|
| S5 | Missing Azure AD nonce validation | `auth.py:529-608` | Azure AD callback does not validate the nonce claim (OIDC does). Enables token replay attacks. |
| S6 | Symlink validation bypass | `adapters/filesystem.py:287-297` | `Path.resolve(strict=True)` throws on non-existent symlink targets, silently returning instead of blocking. Attacker can create symlinks to future targets. |
| S7 | Unvalidated SMB username | `server/routes/enumerate.py:174-189` | `username` in `smbclient` subprocess call is only `.strip()`-ed, no character validation. |
| S8 | Weak OData injection protection | `auth/graph.py:55-94` | Blocklist-based regex can be bypassed via Unicode normalization. Should use allowlist or normalize to NFC before checking. |
| S9 | Overly permissive CORS defaults | `server/config.py:362-368` | Defaults to `["http://localhost:3000", "http://localhost:8000"]` with `allow_credentials=True`. Dangerous if not overridden in production. |
| S10 | Session fixation incomplete | `auth.py:331-334` | Deletes existing session from DB but doesn't invalidate the cookie in the response. Race condition window between cookie check and new session creation. |
| S11 | Unencrypted WinRM allowed | `monitoring/winrm_remote.py:48-92` | `use_ssl=False` sends admin credentials in cleartext. Default is True but the option exists. |
| S12 | Optional DB SSL | `server/config.py:74-78` | `require_ssl` can be set to `False` without startup validation in production. |
| S13 | Metrics endpoint no auth | `server/app.py:153-162` | `/metrics` protected only by IP check (`127.0.0.1`), which can be spoofed via `X-Forwarded-For` if proxy doesn't strip it. |
| S14 | Hardcoded test credentials | `docker-compose.test.yml:13,28` | `POSTGRES_PASSWORD: test` and `redis-server --requirepass test`. |

### MEDIUM

| ID | Issue | File(s) | Summary |
|----|-------|---------|---------|
| S15 | RLS owner bypass risk | `alembic/.../2fdd60bab56c_*.py:83` | Initial RLS migration lacked `FORCE ROW LEVEL SECURITY`. Partially fixed in follow-up migration but requires correct runtime role configuration. |
| S16 | Missing refresh token rotation | `auth/oidc_provider.py:352-382` | Same refresh token reused indefinitely. Compromised token grants indefinite access. |
| S17 | OIDC discovery not validated | `auth/oidc_provider.py:70-112` | Discovery doc fetched over HTTPS but no signature/pinning validation. MITM could redirect `jwks_uri` to attacker-controlled server. Cached for 1 hour. |
| S18 | CSP uses `unsafe-inline` for styles | `server/middleware/stack.py:179-192` | Documented as required by Tailwind. Migrate to nonce-based CSP. |
| S19 | Content-Disposition header injection | `server/routes/results.py:289,309` | Filename not RFC 5987 encoded. Newlines could break header boundaries. |
| S20 | `auth_provider` defaults to `"none"` | `server/config.py:164` | If admin forgets to set `AUTH_PROVIDER`, system has no authentication. |
| S21 | Unbounded Graph API responses | `server/routes/enumerate.py:499` | No response size validation on SharePoint site search results. |
| S22 | Role sync from external claims | `auth/dependencies.py:188-199` | Admin role auto-synced from OIDC claims. Compromised IdP token can escalate privileges. |
| S23 | Token expiration not enforced in session | `server/session.py:138-148` | Session TTL (7 days) checked but OAuth token expiry (1 hour) not validated before returning. |
| S24 | Insufficient auth failure logging | `server/routes/auth.py:446-494` | No per-username rate limiting, no account lockout, no geographic anomaly detection. |

### LOW

| ID | Issue | File(s) |
|----|-------|---------|
| S25 | Temp ACL file cleanup not guaranteed | `remediation/permissions.py:626-638` |
| S26 | Temp file paths in error logs | `remediation/permissions.py:620-640` |
| S27 | IDN hostnames rejected | `server/routes/enumerate.py:48` |
| S28 | Cookie secure flag trusts `X-Forwarded-Proto` | `server/routes/auth.py:200` |
| S29 | `ast.literal_eval()` on benchmark data | `core/benchmark/adapters.py:42` |
| S30 | Missing HSTS in development | `server/middleware/stack.py:168` |

### Positive Security Controls

The codebase has strong security fundamentals worth acknowledging:
- **XXE protection** — global `defusedxml` monkey-patching in `__init__.py`
- **SQL injection prevention** — comprehensive read-only SQL validation with comment stripping in `query.py`
- **Row-Level Security** — RLS on 23 tenant-scoped tables with restricted `openlabels_app` role
- **Rate limiting** — SlowAPI with Redis backend, per-tenant limits
- **Container hardening** — non-root user, `cap_drop: ALL`, pinned base image digest, multi-stage builds
- **CSRF middleware** — registered and active
- **Session encryption** — Fernet (AES-128-CBC + HMAC) when key is configured
- **Security headers** — HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy all set

---

## Part 2: Code Quality Findings

### 2.1 God Files / Single Responsibility Violations

The top 3 worst offenders:

| File | Lines | Issue | Priority |
|------|-------|-------|----------|
| `core/detectors/patterns.py` | 3,190 | 577 regex patterns + 26 validators + 17 filter sets + detector class. Mixes pattern definitions, validation logic, and false-positive filtering across multiple domains (PII, PHI, identifiers, locations). | **P1 — Split into `patterns/validators/`, `patterns/definitions/`, `patterns/filters.py`, `patterns/detector.py`** |
| `core/detectors/orchestrator.py` | 1,856 | 8 different false-positive suppression strategies, post-processing pipeline, confidence calibration, corroboration, city gazetteer caching all in one class. | **P1 — Extract `suppressors/`, `post_processors/`, `enrichment.py`** |
| `jobs/tasks/scan.py` | 1,662 | 3 execution modes (sequential, pipeline, agent pool), auto-labeling, cloud label sync, adapter factory, configuration building, and job lifecycle all in one file. | **P1 — Extract `processors/`, `labeling/`, `configuration.py`** |

Additional god files (P2):
- `server/routes/monitoring.py` (1,289 lines) — 7 feature domains, 30 endpoints. Split into `monitoring_files.py`, `access_events.py`, `alerts.py`, `retention.py`, `remote_monitoring.py`, `windows_events.py`, `service_identity.py`.
- `server/routes/auth.py` (1,151 lines) — 3 auth providers mixed together. Split into `providers/azure_ad.py`, `providers/oidc.py`, `providers/dev.py`.
- `jobs/inventory.py` (1,285 lines) — Redis + in-memory caching + persistence. Split cache layer from service.
- `core/benchmark/adapters.py` (1,195 lines) — 4 dataset adapters. Split into `gretel.py`, `nemotron.py`, `generic.py`.

Lower priority (P3): `server/models.py` (1,302), `core/extractors.py` (1,186), `labeling/engine.py` (1,134) — these are structured reasonably despite their size.

---

### 2.2 DRY Violations

| Pattern | Files | Est. Savings |
|---------|-------|-------------|
| **Cloud adapter client lifecycle** — identical `__aenter__`/`__aexit__`/`_ensure_client`/`_build_client` in S3, GCS, Azure | `adapters/s3.py`, `gcs.py`, `azure_blob.py` | ~150 lines via `CloudAdapterBase` |
| **Graph API error handling** — identical `ConnectionError`/`TimeoutError`/`PermissionError`/`httpx` catch blocks | `adapters/sharepoint.py`, `onedrive.py`, `graph_base.py` | ~80 lines via error-handling decorator |
| **Route handler boilerplate** — paginated list endpoints repeat build-query + paginate pattern | `server/routes/audit.py`, `labels.py`, `browse.py`, `permissions.py` | ~100 lines via factory |
| **CLI file processing loop** — identical read-file + process + error-handling loop | `cli/commands/find.py`, `heatmap.py`, `classify.py` | ~80 lines via `cli/utils.py` helper |
| **ML detector loading** — similar `__init__`/`load()`/`is_available()` pattern | `core/detectors/ml.py`, `ml_onnx.py` | ~50 lines via `BaseMLDetector` |
| **Frontend CRUD hooks** — identical `useQuery`/`useMutation`/`invalidateQueries` boilerplate | `api/hooks/use-labels.ts`, `use-policies.ts`, `use-schedules.ts`, `use-targets.ts` | ~120 lines via factory functions |
| **Frontend `getCsrfToken()`** — duplicated in two files | `api/client.ts`, `api/endpoints/export.ts` | Extract to shared `lib/csrf.ts` |
| **Frontend remediation hooks** — 3 identical mutation+invalidation patterns | `api/hooks/use-remediation.ts` | ~30 lines via shared invalidation helper |

**Total estimated savings: 300-500 Python lines, ~150 TypeScript lines.**

---

### 2.3 Unused Imports

| File | Import | Line |
|------|--------|------|
| `server/routes/monitoring.py` | `from typing import Literal` (never used) | 17 |
| `server/routes/reporting.py` | `FileAccessEvent` (never used) | 36 |
| `server/routes/dashboard.py` | `from openlabels.core.types import JobStatus` (never used) | 31 |
| `core/detectors/orchestrator.py` | `import re as _re` (duplicate of line 7) | 870 |
| `auth/dependencies.py` | `from sqlalchemy import func as sa_func` (already imported as `func`) | 165 |

---

### 2.4 Dead Code

| Item | File | Lines | Notes |
|------|------|-------|-------|
| `get_categories()` | `core/scoring/scorer.py` | 277-284 | Exported in `__all__` but only called internally by `get_co_occurrence_multiplier()` |
| `AdapterHealthChecker.get_health()` | `adapters/health.py` | 82-84 | Defined but never called; only `check_all()` is used |
| `ScanService.cleanup_old_scans()` | `server/services/scan_service.py` | 276-319 | Async method never invoked anywhere |
| `CircuitBreaker.get_all_status()` | `core/circuit_breaker.py` | 288-291 | Classmethod never called |
| `CircuitBreaker.reset_all()` | `core/circuit_breaker.py` | 293-300 | Testing utility never called (even in tests) |

---

### 2.5 AI Slop / Verbose Comments

The codebase is **relatively clean** (<5% of files affected). Notable patterns:

**Restating-the-obvious comments (~40 instances across codebase):**
```python
# Create file handler
handler = self._file_engine.CreateFileHandler(...)   # labeling/mip.py:595

# Set the label
handler.SetLabel(...)                                 # labeling/mip.py:617

# Initialize state manager (Redis-based with in-memory fallback)
self._state_manager = await get_worker_state_manager()  # jobs/worker.py:408

# Validate inputs
if not source.exists():                               # remediation/quarantine.py:89
```

**Redundant docstrings on self-evident classes:**
```python
class ServerSettings(BaseSettings):
    """Server configuration."""               # server/config.py:22

"""User accounts."""                          # server/models.py:199
"""Scheduled scans."""                        # server/models.py:250
```

**Consolidation opportunities:**
```python
# hyperscan.py:89-96 — two nearly identical log messages differing by one word
if self._using_hyperscan:
    logger.info(f"...{self._matcher.pattern_count} patterns (SIMD-accelerated)")
else:
    logger.info(f"...{self._matcher.pattern_count} patterns (Python regex fallback)")
# → logger.info(f"...{count} patterns ({'SIMD-accelerated' if self._using_hyperscan else 'Python regex fallback'})")
```

**Frontend decorative section comments** in `features/labels/list-page.tsx` and `features/targets/form-page.tsx` — these `/* ── Section Name ── */` comments signal that the nested components should be extracted into separate files rather than visually separated within a single god component (form-page.tsx is 769 lines with 4 nested sub-components).

---

### 2.6 Frontend-Specific Issues

| Issue | File | Details |
|-------|------|---------|
| God component (769 lines) | `features/targets/form-page.tsx` | 4 nested sub-components (PickerTreeItem, PathPicker, SourceTypeSelector, CredentialForm) should be extracted |
| God component (448 lines) | `features/labels/list-page.tsx` | 4 internal components (CreateLabelRuleDialog, LabelRulesTab, LabelMappingsTab, LabelStatsTab) |
| Inconsistent query param style | `api/endpoints/credentials.ts:58` | Manually builds `?source_type=` string instead of using `params` option like other endpoints |

**Frontend strengths:** Clean imports (no unused), no commented-out code, good TypeScript type safety, appropriate React Query usage, legitimate console logging only.

---

## Recommended Priority Actions

### Immediate (P0 — This Week)
1. **S1**: Parameterize LIMIT clauses in `query.py:535,621,745`
2. **S2**: Remove hardcoded `admin:admin` from dev-login or generate random dev creds
3. **S3**: Validate `request.base_url` against trusted host allowlist
4. **S4**: Move session encryption check to startup; require for staging

### Urgent (P1 — Next Sprint)
5. **S5**: Add nonce validation to Azure AD callback
6. **S6**: Fix symlink validation to handle non-existent targets
7. **S8**: Normalize OData input to NFC before blocklist check; consider allowlist
8. **S9**: Require explicit CORS origin configuration in production (no localhost defaults)
9. **S10**: Regenerate session ID and invalidate old cookie on login
10. Begin refactoring `patterns.py` (3,190 lines) and `orchestrator.py` (1,856 lines)

### High (P2 — Next 2 Sprints)
11. **S7, S12, S13**: Validate SMB username, enforce DB SSL in prod, add auth to /metrics
12. **S16, S17**: Implement refresh token rotation, validate OIDC discovery documents
13. Split `monitoring.py` (1,289 lines) into domain-specific route modules
14. Extract cloud adapter base class to eliminate DRY violations across S3/GCS/Azure
15. Clean up unused imports, dead code, and verbose comments

### Medium (P3 — Backlog)
16. Remaining security mediums (S15, S18-S24)
17. Split `scan.py`, `auth.py`, `inventory.py`
18. Frontend: extract god components, create hook factories, deduplicate `getCsrfToken()`
19. Remove dead code (5 functions identified)
