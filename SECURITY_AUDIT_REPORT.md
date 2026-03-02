# OpenLabels Security Audit Report

**Date:** 2026-03-02
**Scope:** Full codebase red team (~785 files across Python backend, TypeScript frontend, Docker/CI, database migrations)
**Method:** 20 parallel security agents, each specializing in a different attack surface
**Auditors:** Automated deep-analysis agents with full source code access

---

## Executive Summary

The OpenLabels codebase demonstrates **generally strong security awareness** with many well-implemented controls: parameterized SQL queries throughout, centralized path traversal validation, Fernet-based credential encryption with HKDF key derivation and MultiFernet rotation support, CSRF double-submit cookies with constant-time comparison, session fixation prevention, OAuth state replay protection via atomic `SELECT FOR UPDATE` + `DELETE`, and comprehensive CORS/security header configuration.

However, the audit identified **~180 unique findings** across 20 security domains. The findings are categorized as:

| Severity | Count | Description |
|----------|-------|-------------|
| **CRITICAL** | 4 | Must fix immediately -- active exploitation risk |
| **HIGH** | 26 | Fix urgently -- significant security gaps |
| **MEDIUM** | 62 | Fix soon -- defense-in-depth gaps |
| **LOW** | 55 | Improve when practical -- hardening opportunities |
| **Informational** | ~30 | Best-practice notes, no direct risk |

**Top 5 most impactful issues:**

1. **Incomplete Row-Level Security** -- 10 tenant-scoped tables (including `saved_credentials`) have no RLS policies; worker sessions bypass RLS entirely
2. **ML model deserialization** -- `pytorch_model.bin` loaded via pickle without safetensors enforcement; integrity check failures are logged but don't block loading
3. **SQL injection in migration** -- Database role password interpolated into PL/pgSQL via f-string without escaping
4. **CSRF token rejected by CORS** -- `X-CSRF-Token` header missing from CORS `allow_headers`, silently breaking CSRF protection in cross-origin deployments
5. **Missing rate limits on expensive endpoints** -- Report generation, SIEM export, and resource enumeration have no rate limiting

---

## CRITICAL Findings (4)

### C1: SQL Injection via Password Interpolation in Alembic Migration

**File:** `alembic/versions/a1b2c3d4e5f7_enforce_rls_with_restricted_role.py:97-110`
**Agents:** SQL Injection, Database Security

```python
password = os.environ.get('OPENLABELS_APP_ROLE_PASSWORD')
if not password:
    password = 'CHANGE_ME_BEFORE_PRODUCTION'

op.execute(f"""
    DO $$ BEGIN
        CREATE ROLE openlabels_app LOGIN PASSWORD '{password}';
    END $$;
""")
```

**Impact:** Environment variable `OPENLABELS_APP_ROLE_PASSWORD` containing a single quote (e.g., `pa$$w0rd'`) breaks out of the SQL string literal. Migrations run with superuser privileges, enabling arbitrary DDL/DML. The hardcoded fallback `CHANGE_ME_BEFORE_PRODUCTION` is also a risk if left in place.

**Fix:** Escape single quotes (`password.replace("'", "''")`) or fail the migration if the env var is unset.

---

### C2: Incomplete RLS -- 10 Tenant-Scoped Tables Missing Row-Level Security

**File:** `alembic/versions/a1b2c3d4e5f7_enforce_rls_with_restricted_role.py:57-79`
**Agents:** Database Security, Auth/AuthZ, Job Queue

The RLS migration covers 17 of 27 tenant-scoped tables. These 10 tables have `tenant_id` columns but **no RLS policy and no FORCE ROW LEVEL SECURITY**:

| Missing Table | Risk |
|---|---|
| `saved_credentials` | **Encrypted credentials for cloud data sources** |
| `policies` | Tenant policy configurations |
| `policy_target_assignments` | Policy-to-target mappings |
| `scan_summaries` | Pre-aggregated scan data |
| `reports` | Generated report metadata with storage paths |
| `shares` | Network share definitions |
| `security_descriptors` | NTFS/POSIX security descriptors |
| `directory_tree` | Full filesystem directory structure |
| `index_checkpoints` | Delta sync cursors |
| `scan_partitions` | Fan-out scan partition data |

**Impact:** Any SQL injection or application bug touching these tables leaks data across tenants. `saved_credentials` is the most critical.

**Fix:** Create a follow-up migration enabling RLS + FORCE RLS + `tenant_isolation` policies on all 10 tables.

---

### C3: CSRF Protection Silently Broken in Cross-Origin Deployments

**File:** `src/openlabels/server/config.py:361-370`
**Agents:** CSRF, Auth/AuthZ

```python
allow_headers: list[str] = Field(
    default_factory=lambda: [
        "Accept", "Accept-Language", "Authorization", "Content-Type",
        "Origin", "X-Request-ID", "X-Requested-With",
    ]  # Missing: "X-CSRF-Token"
)
```

**Impact:** The frontend sends `X-CSRF-Token` on all state-changing requests (`client.ts:72`). In cross-origin deployments (frontend ≠ backend origin), CORS preflight rejects this header, causing **all POST/PUT/DELETE/PATCH requests to fail**. Developers may disable CSRF entirely to work around this.

**Fix:** Add `"X-CSRF-Token"` to the default `allow_headers` list.

---

### C4: .env.example Ships with Copyable Weak Passwords

**File:** `.env.example:34, 383-388`
**Agents:** Docker/Infra, Secrets/Config

```bash
DATABASE_URL=postgresql+asyncpg://openlabels:your_secure_password@localhost:5432/openlabels
POSTGRES_PASSWORD=your_secure_postgres_password
REDIS_PASSWORD=your_secure_redis_password
```

**Impact:** `cp .env.example .env` satisfies docker-compose's `${POSTGRES_PASSWORD:?}` check while using publicly-known passwords. This is a common real-world breach vector.

**Fix:** Use clearly invalid placeholders: `POSTGRES_PASSWORD=CHANGE_ME_GENERATE_WITH_openssl_rand_base64_32` or leave blank so the required-variable check catches them.

---

## HIGH Findings (26)

### Authentication & Authorization

| # | File | Issue |
|---|------|-------|
| H1 | `middleware/csrf.py:165-176` | **Bearer auth header bypasses CSRF token check** -- any request with `Authorization: Bearer <anything>` skips double-submit validation. Token validity not verified at middleware layer. |
| H2 | `routes/ws.py:73-77` | **WebSocket accepts missing Origin header** -- CSWSH protection bypassed when `Origin` header absent. Inconsistent with CSRF middleware which rejects missing Origin. |
| H3 | `routes/ws.py:93-106` | **WebSocket origin check trusts client-controlled `Host` header** -- attacker sets both `Host: evil.com` and `Origin: https://evil.com` to pass validation. |

### Database & Tenant Isolation

| # | File | Issue |
|---|------|-------|
| H4 | `monitoring/stream_manager.py:282-290` | **Cross-tenant query** -- `MonitoredFile` queried by `file_path` only, no `tenant_id` filter. `get_session_context()` used without RLS. |
| H5 | `jobs/worker.py:505-688` | **Worker sessions bypass RLS** -- all background workers use `get_session_context()` without `set_rls_tenant_id()`. No database-level tenant isolation for job processing. |
| H6 | `jobs/queue.py:171-274` | **Job complete/cancel/fail lack tenant filter** -- `complete()`, `fail()`, `cancel()` update by `job_id` only, no `tenant_id` WHERE clause. |
| H7 | `jobs/tasks/export.py:140-148` | **Export task trusts payload `tenant_id`** -- reads `tenant_id` from untrusted job payload, not from the job's own database record. Cross-tenant data export possible. |
| H8 | `server/config.py:69` | **Database SSL/TLS disabled by default** (`require_ssl: bool = False`). No production validator enforces SSL, unlike `secret_key`. PII, credentials, and session tokens travel in plaintext. |

### Cryptography & Secrets

| # | File | Issue |
|---|------|-------|
| H9 | `server/config.py:35` | **Empty default `secret_key`** (`SecretStr("")`). No minimum entropy check. Developers may set weak keys that propagate to production. |
| H10 | `routes/monitoring.py:952,972` | **WinRM API defaults to HTTP** (`use_ssl: bool = Field(False)`). Overrides the secure default in `winrm_remote.py`. Domain credentials with `SeSecurityPrivilege` sent in cleartext. |

### ML Model Security

| # | File | Issue |
|---|------|-------|
| H11 | `detectors/ml.py:156-183` | **Pickle deserialization via `pytorch_model.bin`** -- `from_pretrained()` called without `use_safetensors=True`. Malicious pickle payload executes arbitrary code. |
| H12 | `agents/worker.py:189-212` | **Worker agent model loading** -- same `from_pretrained()` issue without safetensors enforcement or path validation. |
| H13 | `detectors/model_integrity.py:169-185` | **TOFU integrity vulnerable to first-load attacks** -- attacker places poisoned model before first legitimate load; poisoned hashes become trusted baseline. |
| H14 | `detectors/ml.py:173-179` | **Integrity failures don't block loading** -- logs `CRITICAL` but proceeds: `"Loading anyway, but this should be investigated."` |

### SSRF & Network

| # | File | Issue |
|---|------|-------|
| H15 | `routes/enumerate.py:619-633` | **S3 endpoint_url SSRF** -- user-supplied `endpoint_url` passed directly to `boto3.client()`. Attacker targets `http://169.254.169.254/` for cloud metadata or any internal service. |

### Rate Limiting & DoS

| # | File | Issue |
|---|------|-------|
| H16 | `routes/reporting.py:589` | **No rate limit on report generation** -- loads up to 50K rows into memory, triggers CPU-bound rendering. |
| H17 | `routes/export.py:45` | **No rate limit on SIEM export** -- loads up to 10K rows and sends to all configured SIEM adapters. |
| H18 | `routes/enumerate.py:811` | **No rate limit on resource enumeration** -- spawns subprocesses (`smbclient`, `showmount`) and makes external API calls. |

### Infrastructure

| # | File | Issue |
|---|------|-------|
| H19 | `docker-compose.yml:28-84` | **No container resource limits** -- no CPU/memory limits on any service. Runaway ML inference can OOM the host. |
| H20 | `docker-compose.yml` (all services) | **Missing security hardening** -- no `security_opt: [no-new-privileges:true]`, no `cap_drop: [ALL]`, no `read_only: true`. |
| H21 | `.pre-commit-config.yaml:1-7` | **No security scanning in pre-commit** -- only ruff linter/formatter. No secret scanning (`detect-secrets`), no SAST (`bandit`). |
| H22 | `.github/workflows/docker.yml` | **No Docker image vulnerability scanning** -- images built and pushed to GHCR without Trivy/Grype/Snyk scan. |

### Dependencies

| # | File | Issue |
|---|------|-------|
| H23 | `uv.lock:4916` | **PyTorch (~2GB) as transitive dependency** via `gliner`. Includes CUDA bindings, JIT compilation, and pickle-based `torch.load()`. Massive attack surface for a server-side tool. |

### Cloud Adapters

| # | File | Issue |
|---|------|-------|
| H24 | `adapters/graph_base.py:48` | **Client secret stored as public attribute** (`self.client_secret`). Never cleared from memory, unlike `GraphClient` which uses `self._client_secret` + `clear_credentials()`. |

---

## MEDIUM Findings (62)

### Authentication & Session Management (8)

| # | File | Summary |
|---|------|---------|
| M1 | `middleware/csrf.py:36-45,145` | CSRF exempt paths use exact match -- no path normalization (double slashes, trailing slashes) |
| M2 | `middleware/csrf.py:128-134` | Dev mode (`auth.provider=none`) disables all CSRF. Default is `"none"`. No prod guard prevents this. |
| M3 | `auth/oidc_provider.py:278-285` | JWT algorithm derived from unverified header (allowlist mitigates, but anti-pattern) |
| M4 | `server/session.py:44-57` | Session token encryption optional in non-production. Staging may mirror production data. |
| M5 | `routes/auth.py:924-1021` | `/auth/token` returns raw OAuth access_token in JSON response body |
| M6 | `routes/m365.py:426` | M365 consent callback lacks explicit `require_admin` dependency |
| M7 | `routes/ws_events.py:65-75` | Global WebSocket endpoint (`/ws/events`) has no connection limits (unlike `/ws/scans` which has 500 global / 50 per-tenant) |
| M8 | `middleware/rate_limit.py:74-91` | In-memory rate limiter fallback -- limits multiplied by worker count (4x) when Redis unavailable |

### SQL & Data Injection (5)

| # | File | Summary |
|---|------|---------|
| M9 | `routes/results.py:140-142` | **ILIKE wildcard injection** -- `search` parameter not escaped for `%`/`_`. Other routes do this correctly. |
| M10 | `routes/enumerate.py:579-585` | **OData filter injection** -- only single-quote escaped. Parentheses/operators allow filter manipulation via Graph API. |
| M11 | `routes/monitoring.py:393-394` | **Incomplete ILIKE escape** -- backslash not escaped before `%`/`_` replacement (4 locations) |
| M12 | `server/db.py:277-311` | `ensure_partitions()` uses string replacement in PL/pgSQL (safe via `int()` coercion but fragile pattern) |
| M13 | `analytics/engine.py:78-81` | S3 credentials interpolated into DuckDB SET statements via f-strings |

### SSRF & Network (5)

| # | File | Summary |
|---|------|---------|
| M14 | `routes/enumerate.py:706-718` | Azure `storage_account` not validated against naming rules -- crafted value redirects SDK to attacker server |
| M15 | `routes/enumerate.py:152-236` | SMB/NFS host allows internal IP addresses -- internal network reconnaissance via `smbclient`/`showmount` |
| M16 | `routes/auth.py:726-746` | OIDC `userinfo_endpoint` from discovery doc fetched without URL validation |
| M17 | `monitoring/winrm_remote.py:33-92` | WinRM host validation allows internal IPs -- no private range blocking |
| M18 | `adapters/s3.py:57-108` | S3 SSRF DNS rebinding window -- hostname resolved at validation time but reconnected later by boto3 |

### Cryptography (5)

| # | File | Summary |
|---|------|---------|
| M19 | `server/crypto.py:69-75` | Static HKDF salt (`b"openlabels-credential-encryption-v1"`) -- deterministic across deployments with same secret |
| M20 | `monitoring/winrm_remote.py:49,89` | WinRM `server_cert_validation` accepts `"ignore"` -- disables TLS verification |
| M21 | `export/adapters/splunk.py:37,58` | Splunk and Elastic export adapters allow `verify_ssl=False` |
| M22 | `server/crypto.py:79-94` | Fernet key cached indefinitely via `@lru_cache` -- no runtime rotation without restart |
| M23 | `server/config.py:35` | No minimum entropy/length check on `secret_key` |

### Cloud Adapters (4)

| # | File | Summary |
|---|------|---------|
| M24 | `adapters/s3.py,azure_blob.py,gcs.py` | No credential cleanup in `__aexit__` for S3/Azure/GCS adapters (Graph adapter does this correctly) |
| M25 | `adapters/graph_client.py:286` | Graph API uses `.default` scope -- grants all consented permissions, not least privilege |
| M26 | `adapters/s3.py:80-83` | S3 endpoint validation allows `http://` scheme -- credentials travel in plaintext |
| M27 | `adapters/s3.py,azure_blob.py,gcs.py` | No object key/blob name validation -- crafted keys could contain path traversal or null bytes |

### File Operations (5)

| # | File | Summary |
|---|------|---------|
| M28 | `labeling/engine.py:402-410` | Sidecar file write has no path validation -- `file_path` from user appended with `.openlabels` |
| M29 | `remediation/quarantine.py:325-333` | TOCTOU race in quarantine symlink check -- check and `shutil.move()` not atomic |
| M30 | `adapters/filesystem.py:324-383` | `read_file()` base directory validation is optional (`base_directory` defaults to `None`) |
| M31 | `remediation/permissions.py:624-638` | `setfacl --restore` with user-controlled temp file content -- crafted ACL data could grant access to arbitrary files |
| M32 | `monitoring/wef_setup.py:229` | XXE risk -- `xml.etree.ElementTree.fromstring()` used instead of `defusedxml` |

### Input Validation (5)

| # | File | Summary |
|---|------|---------|
| M33 | Multiple route files | **Missing string length limits** on 20+ Pydantic `str` fields (`file_path`, `description`, `source_type`, `cron`, etc.) |
| M34 | Multiple route files | **Unbounded `dict` fields** in Pydantic models (`config`, `conditions`, `credentials`) -- deep nesting DoS |
| M35 | `routes/enumerate.py:94` | `page_size` allows up to 500 (standard is 100) -- amplified external API load |
| M36 | `detectors/orchestrator.py:234` | No maximum text length enforcement -- dispatches to all detectors in parallel without bounds |
| M37 | `detectors/ml_onnx.py:139-154` | ONNX `model_name` allows directory traversal in file path construction |

### ML Model Security (4)

| # | File | Summary |
|---|------|---------|
| M38 | `detectors/gliner.py:219-221` | GLiNER `from_pretrained` downloads from HuggingFace without revision pinning |
| M39 | `detectors/phi_detector.py:195-202` | StanfordPHI has no integrity verification at all |
| M40 | `detectors/model_registry.py:114-136` | Registry files have no SHA-256 checksums -- all downloads skip integrity verification |
| M41 | `detectors/config.py:41-52` | Configurable model names allow loading arbitrary models from HuggingFace Hub |

### Rate Limiting & DoS (5)

| # | File | Summary |
|---|------|---------|
| M42 | `routes/scans.py:199` | No rate limit on scan retry endpoint |
| M43 | Multiple monitoring routes | No rate limits on retention purge, remote test/configure, WEF init/subscriptions |
| M44 | Multiple target routes | No rate limits on target CRUD and test-connection endpoints |
| M45 | `routes/reporting.py:298-306` | Report builder loads 50K full ORM objects into memory -- OOM with concurrent requests |
| M46 | `middleware/stack.py:111-150` | Chunked transfer encoding bypasses request body size limit |

### Logging & Information Disclosure (5)

| # | File | Summary |
|---|------|---------|
| M47 | `routes/enumerate.py:483-484` | OAuth error_description relayed to client (reveals Azure AD config details) |
| M48 | `routes/m365.py:137,235,256` | M365 token response body logged in warning messages (may contain partial tokens) |
| M49 | `server/logging.py:122-129` | JSONFormatter includes all `extra` fields without sensitive field filtering |
| M50 | `jobs/worker.py:754-797` | Full exception `str(e)` stored in job `error` column and exposed via API |
| M51 | `routes/credentials.py:378-420` | No audit trail for credential decryption/usage -- only CRUD operations are logged |

### Infrastructure (4)

| # | File | Summary |
|---|------|---------|
| M52 | `docker-compose.yml:88,112` | Third-party images not pinned by digest (`postgres:15-alpine`, `redis:7-alpine`) |
| M53 | `docker-compose.yml:120` | Redis HEALTHCHECK leaks password in process table (`redis-cli -a`) |
| M54 | `Dockerfile:33` | Production image installs `libmupdf-dev` (development headers) |
| M55 | `.dockerignore` | Missing `docker-compose*.yml`, `scripts/` from Docker build context |

### Dependencies (4)

| # | File | Summary |
|---|------|---------|
| M56 | `pyproject.toml` | 29+ dependencies with open-ended `>=` ranges (no upper bounds) |
| M57 | `pyproject.toml:46` | `python-multipart>=0.0.6` minimum includes CVE-2024-24762 (ReDoS) |
| M58 | `pyproject.toml:98` | `numpy>=1.24.0,<2` forces EOL-approaching 1.x branch |
| M59 | `pyproject.toml:73,79` | `pymupdf>=1.23.0` and `pillow>=10.2.0` minimums allow known-vulnerable versions |

### Job Queue (3)

| # | File | Summary |
|---|------|---------|
| M60 | `jobs/queue.py:780-822` | `dequeue_next_job()` crosses tenant boundaries -- global singletons may leak state |
| M61 | `server/routes/jobs.py:30-48` | Job payload and result dicts exposed in API response (internal identifiers, control flags) |
| M62 | `jobs/scheduler.py:302-326` | No rate limiting on job enqueue -- queue flooding possible |

### WebSocket (2)

| # | File | Summary |
|---|------|---------|
| M63 | `routes/ws.py:317-349` | Redis pub/sub has no auth or message integrity -- injection allows spoofed scan progress |
| M64 | `routes/ws_events.py:447-463` | `file_access` events broadcast `user_name` to all tenant users regardless of role |

---

## LOW Findings (55)

### Authentication & Sessions (5)

| # | Summary |
|---|---------|
| L1 | No maximum session limit per user -- `count_user_sessions()` exists but is never called |
| L2 | CSRF token not rotated after state-changing requests (valid for 7 days) |
| L3 | CSRF cookie `httponly=False` increases XSS impact (necessary for double-submit pattern) |
| L4 | Unicode CSRF tokens cause unhandled `TypeError` (500 instead of 403) |
| L5 | Dev login `admin/admin` accessible in staging if `debug=True` + `AUTH_PROVIDER=none` |

### Database (3)

| # | Summary |
|---|---------|
| L6 | `SensitivityLabel.parent_id` lacks foreign key constraint -- orphaned references possible |
| L7 | `DirectoryTree.sd_hash` lacks foreign key to `SecurityDescriptor` -- dangling references |
| L8 | No upper bounds on `pool_size`/`max_overflow` config -- operator could exhaust `max_connections` |

### ML Models (5)

| # | Summary |
|---|---------|
| L9 | Model manifest stored in package directory with no signing |
| L10 | Null byte check only in ONNX detector, not ML/GLiNER/PHI detectors |
| L11 | ONNX optimized cache has no integrity protection (`.ort_optimized` file) |
| L12 | No input sanitization for BERT special tokens before model inference |
| L13 | ONNX session enables all graph optimizations including external initializers |

### File Operations (6)

| # | Summary |
|---|---------|
| L14 | `_collect_entries` follows file symlinks without validating they stay within scan root |
| L15 | Temporary file in predictable location for WEF setup (symlink attack) |
| L16 | Compaction lock file in world-writable `/tmp` |
| L17 | `ast.literal_eval()` fallback on legacy ACL backup data |
| L18 | Labeling engine ZIP operations without decompression bomb protection |
| L19 | `os.path.normpath` in target validation does not resolve symlinks |

### Cloud Adapters (3)

| # | Summary |
|---|---------|
| L20 | GCS label application requires full object re-upload (metadata-only update possible) |
| L21 | No bucket/container name validation in any adapter |
| L22 | Azure connection string stored in memory without masking |

### Logging & Info Disclosure (5)

| # | Summary |
|---|---------|
| L23 | SQLAlchemy error logged with full exception (may contain query text with PII) |
| L24 | Cache health endpoint exposes internal error details (`str(e)`) to authenticated users |
| L25 | M365 consent callback sends error description to browser via HTML popup |
| L26 | User email logged on every authenticated request (PII in logs) |
| L27 | MIP client stores `client_secret` as plain instance attribute (Sentry stack frame leak risk) |

### Job Queue (4)

| # | Summary |
|---|---------|
| L28 | Cache key generation uses MD5 truncated to 8 hex chars -- high collision probability |
| L29 | Redis URL logged in plaintext on connect (password may be included) |
| L30 | Cron expression not length-limited in scheduler |
| L31 | `datetime.fromisoformat()` in export task without range validation |

### WebSocket (4)

| # | Summary |
|---|---------|
| L32 | Full server-side file paths broadcast to clients via WebSocket |
| L33 | No outbound message size limit on server-to-client WebSocket messages |
| L34 | `deliver_local` does not filter by tenant_id (defense-in-depth gap) |
| L35 | Frontend does not validate WebSocket message schema (type assertions only) |

### Command Injection (4)

| # | Summary |
|---|---------|
| L36 | Shell script via `sh -c` with partially unescaped paths in echo statements (`registry.py:508`) |
| L37 | PowerShell interpolation with deny-list path validation (fragile blocklist approach) |
| L38 | PowerShell interpolation in history query with partial escaping |
| L39 | DuckDB catalog_root interpolated via f-string (config-level, escaped) |

### Input Validation (5)

| # | Summary |
|---|---------|
| L40 | `entity_type` query parameter not validated against known types |
| L41 | Filter parser has no input length limit |
| L42 | Webhook `validationToken` reflection allows `<>` chars despite `text/plain` |
| L43 | No max length on cron expressions in `ReportScheduleRequest` |
| L44 | Integer overflow potential in filter parser `_read_number` |

### SSRF & Network (2)

| # | Summary |
|---|---------|
| L45 | SIEM export adapters accept unchecked host/URL parameters (secondary SSRF via data exfil) |
| L46 | Redis URL configurable via env -- redirect to attacker's Redis for cache poisoning |

### Rate Limiting & DoS (4)

| # | Summary |
|---|---------|
| L47 | CSV extractor has no row limit (unlike XLSX which caps at 100K rows) |
| L48 | Browse endpoint allows up to 1000 rows (standard is 100) |
| L49 | Address regex patterns have potential catastrophic backtracking |
| L50 | Company/employer patterns use `\s` (includes newlines) with lazy quantifiers |

### Infrastructure (4)

| # | Summary |
|---|---------|
| L51 | `curl` installed in production image solely for healthcheck (data exfil tool) |
| L52 | Test infrastructure uses hardcoded weak passwords (`test`) |
| L53 | CI Redis has no authentication (unlike docker-compose.test.yml) |
| L54 | Test script modifies system `pg_hba.conf` to weaken auth from `peer` to `trust` |

### Dependencies (1)

| # | Summary |
|---|---------|
| L55 | `ebcdic` package (transitive via `extract-msg`) abandoned since 2019 |

### Frontend (4 -- all Low/Informational)

The XSS/Frontend audit found no critical, high, or medium issues. Low findings:
- CSP uses `unsafe-inline` for styles (migration to nonces recommended)
- Unvalidated `window.open` URL for M365 consent
- Overly broad `connect-src` CSP directive
- WebSocket permitting missing Origin headers (cross-referenced with H2)

---

## Top 10 Priority Remediations

| Priority | Issue | Impact | Effort |
|----------|-------|--------|--------|
| **1** | Add RLS policies to all 10 missing tables + set RLS context in worker sessions | Closes cross-tenant data leakage for credentials, policies, reports | Medium |
| **2** | Escape password in migration SQL + fail if env var unset | Eliminates SQL injection during database setup | Low |
| **3** | Add `X-CSRF-Token` to CORS `allow_headers` | Fixes silently broken CSRF in cross-origin deployments | Trivial |
| **4** | Enforce `use_safetensors=True` on all `from_pretrained()` calls + make integrity failures blocking | Eliminates pickle deserialization RCE vector | Low |
| **5** | Add rate limits to report generation, SIEM export, and enumeration endpoints | Prevents resource exhaustion and SSRF amplification | Low |
| **6** | Validate S3 `endpoint_url` against private IP ranges (reuse existing `_validate_endpoint_url`) | Blocks SSRF to cloud metadata and internal services | Low |
| **7** | Default WinRM to `use_ssl=True` in API schemas + enforce DB `require_ssl` in production | Prevents credential interception on the wire | Low |
| **8** | Add container resource limits + security hardening (`cap_drop`, `no-new-privileges`) | Limits blast radius of container compromise | Low |
| **9** | Add secret scanning + SAST to pre-commit hooks + image scanning in Docker CI | Catches secrets and CVEs before merge | Medium |
| **10** | Use clearly invalid `.env.example` placeholders + raise minimum `python-multipart` | Prevents copyable weak passwords and known CVE | Trivial |

---

## Security Controls Done Well

The audit identified many well-implemented security controls:

1. **JWT algorithm pinning** -- RS256 only for Azure AD; explicit allowlist blocking `none` and HMAC for OIDC
2. **OAuth state with atomic consume** -- `SELECT FOR UPDATE` + `DELETE` prevents replay attacks
3. **Session fixation prevention** -- old sessions deleted before creating new ones in both auth flows
4. **Open redirect prevention** -- comprehensive URL validation including protocol-relative, path traversal, scheme injection
5. **CSRF double-submit cookies** -- `secrets.token_urlsafe(32)` (256 bits), constant-time comparison, SameSite=Lax
6. **Parameterized SQL everywhere** -- all ORM queries use `text()` with bind parameters; zero raw string concat of user input in PostgreSQL queries
7. **SQL query endpoint** -- multi-layered validation (comment stripping, keyword blocking, function blocking, tenant `$1` param, 30s timeout, 10K row limit)
8. **Path traversal prevention** -- centralized `validate_path()` with null bytes, `..`, system directories, symlink escape detection
9. **Credential encryption** -- Fernet with HKDF-SHA256 key derivation + MultiFernet for key rotation support
10. **Credential masking** -- `mask_config_credentials()` replaces secrets with `"******"` in API responses
11. **Webhook security** -- `hmac.compare_digest` for clientState, SHA-256 dedup cache with time window
12. **Non-root Docker** -- runs as `openlabels:1000`, multi-stage build, localhost-only port binding
13. **Database isolation** -- internal-only Docker network, `scram-sha-256` auth, required passwords
14. **Tenant isolation** -- consistent `tenant_id` filtering via DI across all API routes
15. **Admin-only mutations** -- destructive operations require `require_admin` dependency
16. **Audit logging** -- comprehensive trail for CRUD, login, settings, remediation, credential management
17. **Decompression bomb protection** -- DOCX/XLSX/PPTX extractors track cumulative size + 100x extraction ratio limit
18. **Memory budget for pipeline** -- `MemoryBudgetSemaphore` with 512MB cap prevents OOM during concurrent file processing
19. **GitHub Actions pinned to SHA** -- all actions use commit hashes (not mutable tags)
20. **`yaml.safe_load` everywhere** -- no unsafe YAML deserialization found
21. **Credentials via env vars** -- `smbclient`, `pg_dump`, `psql` pass passwords via env, not CLI args
22. **CSV injection prevention** -- formula-trigger character prefixing in report exports
23. **`defusedxml` available** -- included as dependency, used in some paths (should be used everywhere)
24. **pip-audit in CI** -- dependency vulnerability scanning present in test workflow

---

## Methodology

20 specialized security agents were deployed in parallel, each auditing a different attack surface with full source code access:

| # | Agent | Focus | Files Examined | Findings |
|---|-------|-------|----------------|----------|
| 1 | SQL Injection | Raw queries, ORM bypasses, LIKE injection | All `.py` files | 6 |
| 2 | Auth/AuthZ | JWT, OAuth, OIDC, sessions, RBAC | auth/, middleware/, routes/ | 8 |
| 3 | XSS/Frontend | dangerouslySetInnerHTML, CSP, CORS, DOM XSS | All `.ts`/`.tsx` files | 4 (low) |
| 4 | Command Injection | subprocess, eval, exec, deserialization | All `.py` files | 13 |
| 5 | Secrets/Config | Hardcoded creds, weak defaults, key mgmt | Config, env, Docker files | 12 |
| 6 | API Route Security | Missing auth, IDOR, mass assignment | All route files | 20 |
| 7 | SSRF/Network | URL injection, webhook fetches, DNS rebinding | Adapters, auth, monitoring | 8 |
| 8 | File Operations | Path traversal, symlinks, zip bombs | Filesystem, extractors, remediation | 14 |
| 9 | Database Security | RLS bypass, tenant isolation, migrations | DB, models, all migrations | 10 |
| 10 | Cryptography | Weak hashing, JWT confusion, cert bypass | Crypto, auth, export | 13 |
| 11 | Docker/Infra | Dockerfile, compose, CI, pre-commit | Infrastructure files | 20 |
| 12 | Dependencies | CVEs, unpinned versions, supply chain | pyproject.toml, lockfiles | 19 |
| 13 | WebSocket | Auth, message injection, CSWSH | ws.py, ws_events.py, frontend | 10 |
| 14 | Input Validation | ReDoS, missing limits, type coercion | Schemas, routes, detectors | 14 |
| 15 | Cloud Adapters | S3/Azure/GCS creds, cross-tenant | All adapter files | 13 |
| 16 | Logging/Errors | PII in logs, stack traces, info disclosure | Logging, errors, sentry | 10 |
| 17 | Rate Limiting/DoS | Resource exhaustion, unbounded queries | Middleware, routes, extractors | 15 |
| 18 | CSRF Protection | Token bypass, CORS config, SameSite | CSRF middleware, config | 9 |
| 19 | ML Model Security | Pickle deser, integrity, poisoning | All detector files | 16 |
| 20 | Job Queue | Serialization, tenant isolation, Redis | Jobs, worker, scheduler | 14 |

Each agent performed deep file-level analysis reading individual source files and tracing data flows from input to output. Findings were deduplicated and consolidated into this report with cross-references where multiple agents identified the same issue.
