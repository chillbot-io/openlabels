# Red Team Code Audit Report

**Date:** 2026-03-04
**Scope:** Full codebase audit — security vulnerabilities, AI slop, code quality, configuration hygiene

---

## Executive Summary

Three parallel audit agents scanned the entire OpenLabels codebase. Key findings:

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Security | 4 | 7 | 4 | 2 |
| Code Quality (AI Slop) | 0 | 2 | 3 | 5 |
| Config/Infrastructure | 2 | 2 | 3 | 3 |

The codebase has strong security fundamentals (non-root containers, network isolation, RLS, CSRF middleware, CSP headers, Trivy scanning). However, several critical and high-severity issues need immediate attention.

---

## Part 1: Security Vulnerabilities

### CRITICAL

#### S1. SQL LIMIT Clause Injection
**Files:** `src/openlabels/server/routes/query.py:535, 621, 745`

```python
limited_sql = f"SELECT * FROM ({execution_sql}) AS __q LIMIT {body.limit + 1}"
```

Although `body.limit` is Pydantic-validated as an integer, unparameterized LIMIT clauses are a bad pattern. If validation is bypassed or the pattern is copied elsewhere without validation, SQL injection becomes possible.

**Fix:** Use parameterized queries for the LIMIT value.

---

#### S2. Dev Credentials Printed to stderr
**File:** `src/openlabels/server/routes/auth.py:54-66`

```python
_DEV_PASSWORD = secrets.token_urlsafe(16)
print(f"DEV MODE: Generated random dev password: {_DEV_PASSWORD}", file=sys.stderr)
```

Credentials are logged to stderr, which may be captured in log aggregators.

**Fix:** Remove password printing. Enforce `AUTH_PROVIDER != "none"` in production/staging at startup.

---

#### S3. Missing Session Encryption Enforcement at Startup
**File:** `src/openlabels/server/session.py:44-58`

Session encryption is optional. When `AUTH_SESSION_ENCRYPTION_KEY` is unset, OAuth tokens (access_token, refresh_token, id_token) are stored in plaintext in PostgreSQL. The check only raises on first use, not at startup.

**Fix:** Validate encryption key presence in `lifespan.py` at application startup for production/staging.

---

#### S4. OData Injection — Blocklist Bypass
**File:** `src/openlabels/auth/graph.py:56-98`

The OData injection protection uses a blocklist regex that can be bypassed with Unicode variations (e.g., Cyrillic 'e' + Latin 'q' for "eq"). NFC normalization happens after the regex check.

**Fix:** Switch to an allowlist approach. Normalize first, then validate against `^[a-zA-Z0-9\s\-_.@]*$`.

---

### HIGH

#### H1. Azure AD Nonce Validation Missing
**File:** `src/openlabels/server/routes/auth.py:529-608`

The Azure AD callback validates `state` but ignores `nonce`, enabling token replay attacks.

**Fix:** Validate `nonce` claim from the ID token against the stored session nonce.

---

#### H2. Session Fixation Race Condition
**File:** `src/openlabels/server/routes/auth.py:331-376`

Dev-mode login deletes the old session from the DB but the browser still holds the old cookie briefly. Race condition allows the old session to be read.

**Fix:** Ensure DB deletion is committed before setting the new session cookie.

---

#### H3. CORS Defaults Allow localhost in Production
**File:** `src/openlabels/server/config.py:365-368`

```python
allowed_origins: list[str] = Field(
    default_factory=lambda: ["http://localhost:3000", "http://localhost:8000"]
)
allow_credentials: bool = True
```

If admin forgets to override in production, credentials are allowed from localhost origins — exploitable via DNS rebinding.

**Fix:** Add a `model_validator` that rejects localhost-only origins in production/staging.

---

#### H4. /metrics Endpoint IP Check Spoofable
**File:** `src/openlabels/server/app.py:154-169`

The IP-based fallback check uses `request.client.host` which can be spoofed if a reverse proxy doesn't strip `X-Forwarded-For`. Metrics expose system information (memory, CPU, request rates).

**Fix:** Require token auth always (no IP-only fallback). Validate only from trusted proxy IPs.

---

#### H5. `ast.literal_eval()` Fallback in Benchmark Adapters
**File:** `src/openlabels/core/benchmark/adapters.py:339, 511, 796`

```python
except json.JSONDecodeError:
    spans = ast.literal_eval(spans_raw)  # fallback
```

While safer than `eval()`, `literal_eval` can be exploited via deeply nested structures (DoS).

**Fix:** Remove the `literal_eval` fallback. Use JSON-only parsing.

---

#### H6. Unvalidated SMB Username in subprocess
**File:** `src/openlabels/server/routes/enumerate.py:174-189`

Username from form input receives only `.strip()` before being passed to `smbclient` subprocess.

**Fix:** Allowlist validate with `^[\w\.\\\-]+$` before passing to subprocess.

---

#### H7. Database SSL Can Be Disabled in Production
**File:** `src/openlabels/server/config.py:74-78`

`require_ssl: bool = True` can be overridden to `false` without startup validation in production.

**Fix:** Add a startup validator that rejects `require_ssl=false` in production/staging.

---

### MEDIUM

| Issue | File | Description |
|-------|------|-------------|
| RBAC auto-promote from IdP claims | `auth/dependencies.py:188-199` | Admin role auto-granted from IdP token — compromised token = instant admin |
| Open redirect via Host header | `server/routes/auth.py` | `request.base_url` used in `post_logout_redirect_uri` without validation |
| Content-Disposition header injection | `server/routes/results.py:289, 309` | Filename not RFC 5987 encoded — CRLF injection possible |
| No auth failure rate limiting | `server/routes/auth.py` | No per-user rate limiting or lockout after failed attempts |

### LOW

| Issue | File | Description |
|-------|------|-------------|
| Cookie Secure flag trusts X-Forwarded-Proto | `server/routes/auth.py:218` | Attacker can set header to `https` over HTTP if proxy doesn't strip it |
| os.environ direct access bypasses SecretStr | Multiple files | Secrets accessed via `os.environ.get()` instead of Pydantic config |

---

## Part 2: AI Slop & Code Quality

### HIGH — God Files (20+ files over 900 lines)

These files combine unrelated responsibilities and should be split:

| File | Lines | Recommendation |
|------|-------|----------------|
| `core/detectors/patterns/__init__.py` | 2,135 | Split by pattern category |
| `server/models.py` | 1,302 | Split by domain (auth, jobs, monitoring, etc.) |
| `server/routes/monitoring.py` | 1,289 | Split by monitoring feature |
| `jobs/inventory.py` | 1,285 | Separate caching, Redis, and business logic |
| `server/routes/auth.py` | 1,200 | Separate OAuth, OIDC, session, dev-mode flows |
| `core/extractors.py` | 1,196 | Split by extractor type |
| `server/routes/remediation.py` | 1,040 | Split by remediation domain |
| `core/agents/pool.py` | 1,013 | Separate pool management from agent lifecycle |

### HIGH — Overly Broad Exception Handling (10+ instances)

Multiple files catch bare `Exception` instead of specific types, masking real bugs:

- `server/routes/auth.py:914` — catches `Exception` for OIDC endpoint lookup
- `server/crypto.py:187` — `except (InvalidToken, Exception)` is redundant
- `core/detectors/gliner.py:174, 193, 305, 365` — bare `except Exception: pass` hides errors
- `core/detectors/ml_onnx.py:335` — silently returns `4.0` on any exception

### MEDIUM — Excessive Try-Except Density

Files with unusually high try-except counts suggest over-defensive AI-generated code:

| File | Try blocks |
|------|-----------|
| `jobs/tasks/scan.py` | 27 |
| `core/extractors.py` | 24 |
| `server/lifespan.py` | 23 |
| `adapters/filesystem.py` | 21 |
| `labeling/mip.py` | 20 |
| `jobs/inventory.py` | 20 |

### MEDIUM — Obvious/Redundant Comments (20+ instances)

Comments that restate what the code already says:

- `server/schemas/pagination.py:113` — `# Get total count` above `total = ...`
- `server/schemas/pagination.py:123` — `# Get paginated results` above `results = ...`
- `server/middleware/csrf.py:62, 67, 139` — `# Get origin from headers`, `# Check against allowed origins`
- `server/utils.py:75-82` — `# Check X-Forwarded-For (standard proxy header)`

### LOW — Potentially Dead Code (~30 functions)

Functions defined but potentially never called:

- `server/crypto.py` — `encrypt_config_credentials`, `decrypt_config_credentials`, `mask_config_credentials`, `encrypt_dict`, `decrypt_dict`
- `server/config.py` — `reload_settings`
- `server/db.py` — `close_db`, `get_session_context`, `get_tenant_session_context`, `get_pool_stats`, `get_session_factory`, `ensure_partitions`, `run_migrations`
- `server/logging.py` — `set_request_id`, `set_tenant_id`, `set_user_id`

### LOW — Over-Engineered Exception Hierarchy

`exceptions.py` contains 44 exception classes. Many are single-line pass-through markers (e.g., `class TokenExpiredError(AuthError): pass`). Could be consolidated into fewer types with error codes.

### LOW — 330+ isinstance Checks

Extensive runtime type checking in a typed codebase suggests defensive AI-generated code or poor upstream type annotations.

---

## Part 3: Configuration & Infrastructure

### GOOD Practices Already in Place

- **Docker:** Non-root user, multi-stage build, pinned image digests, health checks, `no-new-privileges`, all capabilities dropped
- **Networking:** Database/Redis on isolated internal network, API bound to `127.0.0.1`
- **CI/CD:** GitHub Actions pinned to commit hashes, `pip-audit --strict`, Trivy scanning (fails on CRITICAL/HIGH), ruff + mypy
- **Secrets:** Pydantic `SecretStr` for sensitive config, `.env` excluded from git, `.dockerignore` excludes `*.pem`/`*.key`
- **Pre-commit:** ruff, detect-secrets, bandit

### Issues Found

#### MEDIUM — `os.environ` Direct Access Bypasses Config Validation

Multiple files read secrets via `os.environ.get()` instead of the Pydantic config system:

- `server/schemas/pagination.py` — `os.environ.get("OPENLABELS_SECRET_KEY")`
- `server/routes/query.py` — `os.environ.get("ANTHROPIC_API_KEY")`, `os.environ.get("OPENAI_API_KEY")`
- `server/routes/auth.py` — `os.environ.get("OPENLABELS_DEV_USERNAME")`
- `server/app.py` — `os.environ.get("OPENLABELS_METRICS_TOKEN")`

This bypasses SecretStr protection and Pydantic validation.

#### MEDIUM — Unpinned Frontend Dependencies

All frontend deps in `package.json` use caret ranges (`^X.Y.Z`). While `package-lock.json` provides protection, loose ranges increase update volatility.

#### MEDIUM — Large Data Migration Lacks Downtime Documentation

`alembic/versions/d4e5f6a7b8c9_table_partitioning_scan_results.py` uses `DROP TABLE ... CASCADE` and copies data between tables. On large datasets this could lock the database for extended periods. No downtime guidance is documented.

#### LOW — `results.json` (337K) Committed to Git

Benchmark results file should likely be in `.gitignore` if auto-generated.

#### LOW — Product Docs in Repo

`remaining-user-stories.pdf` and `plan.md` are product management files that belong in a wiki or project management tool.

---

## Resolution Status

### Already Addressed (False Positives from Audit)

The following were flagged by the audit agents but the code **already had mitigations**:

| Issue | Status | Evidence |
|-------|--------|----------|
| S1. SQL LIMIT injection | **Already safe** | Uses `LIMIT ?` parameterized placeholder, not f-string interpolation |
| S3. Session encryption | **Already enforced** | `lifespan.py:29-38` fails fast in production/staging |
| H1. Azure AD nonce | **Already validated** | `auth.py:606-618` uses `hmac.compare_digest` |
| H2. Session fixation | **Already handled** | Old session deleted + new created in same transaction, committed before response |
| H6. SMB username | **Already validated** | `enumerate.py:51,163` uses `_USERNAME_RE` allowlist regex |
| H7. DB SSL enforcement | **Already enforced** | `config.py:888-897` `validate_production_db_ssl` validator |

### Fixed in This Commit

| Issue | Fix |
|-------|-----|
| S2. Dev password on stderr | Password written to `/tmp/.openlabels_dev_password` (mode 0600) instead of stderr |
| S4. OData injection | Switched from blocklist regex to allowlist: `^[a-zA-Z0-9\s\-_.@\\]+$` after NFC normalization |
| H3. CORS localhost in prod | Added `validate_production_cors_origins` validator — rejects localhost-only origins with credentials in production/staging |
| H4. Metrics auth | Token now required in production/staging — returns 403 if `OPENLABELS_METRICS_TOKEN` is not set |
| H5. `ast.literal_eval` | Removed all 3 fallbacks in `adapters.py` — JSON-only parsing now |

### Remaining Backlog (Code Quality)
1. Split god files (start with `models.py`, `auth.py`, `monitoring.py`)
2. Replace broad `except Exception` with specific types
3. Centralize `os.environ` access through Pydantic config
4. Audit and remove dead code functions
5. Remove obvious comments
6. Add auth failure rate limiting
