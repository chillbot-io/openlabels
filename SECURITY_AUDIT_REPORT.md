# OpenLabels Security Audit Report

**Date:** 2026-03-02
**Scope:** Full codebase red team (~568 source files across Python backend, TypeScript frontend, Docker/CI, database migrations)
**Method:** 20 parallel security agents, each specializing in a different attack surface

---

## Executive Summary

The OpenLabels codebase demonstrates **generally strong security awareness**. Authentication flows are properly implemented with JWKS validation, OIDC discovery, session fixation prevention, and CSRF protection. Tenant isolation is consistently enforced via dependency injection. The codebase uses parameterized SQL queries, path traversal validation, credential encryption with Fernet, and security headers (HSTS, CSP, X-Frame-Options).

However, the audit identified **~190 unique findings** across 20 security domains. The most impactful issues are:

1. **Row-Level Security is inert** -- RLS policies exist but the app connects as table owner, bypassing them entirely
2. **Raw PII stored in scan results** -- the system designed to detect PII stores the actual PII values in plaintext
3. **Silent plaintext credential fallback** -- when `secret_key` is unconfigured, credentials are stored unencrypted
4. **SSRF via S3 `endpoint_url`** -- admins can point cloud adapters at internal infrastructure (169.254.169.254)
5. **WinRM credentials sent over HTTP by default** -- privileged Windows credentials transmitted in cleartext
6. **Supply chain risk** -- all GitHub Actions pinned to mutable tags, not SHA hashes

---

## Findings by Severity

### CRITICAL (8 findings)

| # | Domain | File | Issue |
|---|--------|------|-------|
| C1 | Database/RLS | `2fdd60bab56c_.py:82` | **RLS policies not enforced at runtime** -- app connects as table owner, bypassing all RLS. Zero database-level tenant isolation. |
| C2 | Database/RLS | `2fdd60bab56c_.py:68` | **20+ tenant-scoped tables missing RLS** -- `saved_credentials`, `tenant_settings`, `directory_tree`, `security_descriptors`, `policies`, etc. have no RLS policies at all. |
| C3 | Database/RLS | `jobs/worker.py:505` | **Background workers bypass tenant context** -- scheduled tasks iterate all tenants without setting RLS context, no defense-in-depth. |
| C4 | Privacy | `jobs/tasks/scan.py:1250` | **Raw PII stored in database** -- actual SSNs, credit cards, emails stored verbatim in `findings` JSONB column and exposed via API. Undermines the privacy protection goals of the product. |
| C5 | Supply Chain | `.github/workflows/*.yml` | **All 12 GitHub Actions pinned to mutable tags** (`@v3`, `@v4`) not SHA hashes. Tag mutation attack could inject malicious code into CI/CD. |
| C6 | Supply Chain | `Dockerfile:5,22` | **Base images not pinned to digest** -- `python:3.11-slim` referenced by tag only. Registry compromise could substitute backdoored image. |
| C7 | Remediation | `manifest.py:40` | **DEFAULT_ALLOWED_BASES = [Path("/")]** -- quarantine restore can write files to any path on the filesystem, nullifying path traversal protections. |
| C8 | Windows/WinRM | `winrm_remote.py:37` | **WinRM defaults to HTTP** -- privileged domain credentials (with `SeSecurityPrivilege`) transmitted in cleartext over port 5985 by default. |

### HIGH (28 findings)

| # | Domain | File | Issue |
|---|--------|------|-------|
| H1 | Secrets | `crypto.py:126` | Silent plaintext credential fallback when `secret_key` not configured |
| H2 | Secrets | `config.py:35` | `secret_key` defaults to empty string, no startup validation |
| H3 | Crypto | `crypto.py:65` | Weak KDF -- single SHA-256, no iterations, hardcoded salt for Fernet key derivation |
| H4 | Crypto | `crypto.py:49` | No key rotation support (no MultiFernet) |
| H5 | Crypto | `crypto.py:126` | Credential encryption fails open to plaintext in production |
| H6 | SSRF | `s3.py:453` | Unvalidated S3 `endpoint_url` -- SSRF to cloud metadata (169.254.169.254) |
| H7 | SSRF | `targets.py:300` | Missing `endpoint_url` validation in S3 target config |
| H8 | SSRF | `config.py:35` | Empty default `secret_key` allows derivation of predictable Fernet key |
| H9 | Database | `config.py:52` | No SSL/TLS enforcement on database connections |
| H10 | Database | `a2b3c4d5e6f7_.py:31` | `saved_credentials.encrypted_data` has no CHECK constraint for encryption prefix |
| H11 | Database | `ws.py:343` | WebSocket sessions bypass tenant-scoped DB sessions and RLS context |
| H12 | Database | `d4e5f6a7b8c9_.py:126` | Partitioning migration uses unbatched copy + CASCADE DROP |
| H13 | Info Disclosure | `error_handlers.py:267` | Debug mode returns raw `str(exc)` to clients (may contain DB URLs, secrets) |
| H14 | Info Disclosure | `app.py:285` | OpenAPI/Swagger docs accessible without authentication |
| H15 | Privacy | `reporting.py:752` | Report distribution allows arbitrary email addresses (data exfiltration) |
| H16 | Privacy | `reporting.py:778` | Report distribution endpoint missing path traversal validation |
| H17 | Privacy | `results.py:180` | Results export has no row limit (unbounded data extraction) |
| H18 | Privacy | `storage.py:91` | Parquet analytics files stored unencrypted at rest |
| H19 | DoS | `ws.py:123` | WebSocket connection exhaustion -- no per-tenant or global limits |
| H20 | DoS | `middleware/stack.py:111` | Request body size check bypassed by chunked transfer encoding |
| H21 | DoS | `extractors.py:358` | CSV extractor has no row or size limit (OOM via crafted file) |
| H22 | Infra | `docker-compose.test.yml:29` | Test Redis exposed on all interfaces without authentication |
| H23 | Infra | `.gitignore` | `config.yaml` not in `.gitignore` -- users instructed to create it with secrets |
| H24 | Infra | `scripts/run-tests.sh:140` | `eval` with constructed commands in shell script |
| H25 | Supply Chain | `pyproject.toml:37-101` | 35+ Python deps with no upper version bounds |
| H26 | Supply Chain | `test.yml:23` | CI installs from PyPI, not lockfile (`pip install` instead of `uv sync`) |
| H27 | Concurrency | `auth.py:480` | OAuth state token double-spend -- non-atomic consume allows replay |
| H28 | Windows | `winrm_remote.py:53` | Host parameter injection in WinRM endpoint URL (SSRF-to-credential-theft) |

### MEDIUM (72 findings)

| # | Domain | Summary |
|---|--------|---------|
| M1 | Auth | Hardcoded dev credentials `admin/admin` in auth.py:764 |
| M2 | Auth | Empty `server.secret_key` allows silent plaintext session storage |
| M3 | Auth | Session encryption key optional in production (tokens stored plaintext) |
| M4 | Auth | `server.secret_key` typed as `str` not `SecretStr` (leaks in logs/repr) |
| M5 | Auth | 7-day session TTL without periodic IdP re-validation |
| M6 | Crypto | Timing attack on M365 consent state (`!=` instead of `hmac.compare_digest`) |
| M7 | Crypto | Timing attack on OIDC nonce validation |
| M8 | Crypto | Timing attack on Graph webhook clientState validation |
| M9 | Crypto | Ephemeral random cursor signing key (not cached per process) |
| M10 | Crypto | Session encryption optional in production |
| M11 | SQLi | ILIKE wildcard injection in browse file search (browse.py:226) |
| M12 | SQLi | ILIKE wildcard injection in remediation search (remediation.py:339) |
| M13 | Injection | OData filter injection in OneDrive enumeration (enumerate.py:581) |
| M14 | SSRF | Azure `storage_account` not validated (DNS to attacker domain) |
| M15 | SSRF | Graph API `@odata.nextLink` following leaks Bearer token to arbitrary URLs |
| M16 | SSRF | GCS `credentials_path` allows arbitrary file read |
| M17 | Secrets | Debug mode exception details leaked to clients |
| M18 | Secrets | Redis URL logged with potential password (cache.py:219) |
| M19 | Secrets | `config.yaml` not in `.gitignore` |
| M20 | Secrets | `database.url` typed as `str` not `SecretStr` |
| M21 | Secrets | DuckDB credentials interpolated via f-strings (engine.py:77) |
| M22 | Secrets | Sentry `before_send` doesn't scrub exception values/stack vars |
| M23 | Secrets | M365 per-tenant `client_secret` stored unencrypted in session data |
| M24 | Secrets | M365 route logs OAuth response body containing potential secrets |
| M25 | Infra | Test Postgres password hardcoded, port bound to 0.0.0.0 |
| M26 | Infra | Codecov action not pinned to SHA, has history of compromise |
| M27 | Infra | All GitHub Actions pinned by tag, not SHA |
| M28 | Infra | `python-multipart>=0.0.6` allows CVE-2024-24762 (ReDoS) |
| M29 | Infra | `pillow>=10.2.0` allows CVE-2024-28219 (buffer overflow) |
| M30 | Infra | `pymupdf>=1.23.0` allows pre-security-fix versions |
| M31 | Infra | Sample config uses `openlabels:openlabels` as DB credentials |
| M32 | Info | `/metrics` endpoint unauthenticated (Prometheus data exposed) |
| M33 | Info | SQLAlchemy error handler logs full exception (may contain PII) |
| M34 | Info | Query endpoint leaks partial error messages to clients |
| M35 | Info | Logging framework has no denylist for sensitive `extra` fields |
| M36 | Info | OpenTelemetry auto-instruments SQLAlchemy/HTTPX without sanitization |
| M37 | API | Unvalidated `filters: dict` in report generation (arbitrary dict accepted) |
| M38 | API | `record_types` list in SIEM export not validated |
| M39 | API | Email addresses not validated in report distribution (SMTP injection) |
| M40 | API | Scan status filter, action_type, entity_type not Literal-typed |
| M41 | API | Request size enforcement bypassable via missing Content-Length |
| M42 | API | CSRF exempt paths use exact match, miss versioned `/api/v1/` paths |
| M43 | API | Webhook CSRF exemption missing (may block legitimate webhooks) |
| M44 | API | Permissions export endpoint has no row limit (unbounded query) |
| M45 | DoS | TextExtractor, RTFExtractor, HTMLExtractor have no size limits |
| M46 | DoS | Analytics `export_scan_results` has no LIMIT clause |
| M47 | DoS | Report generation loads 50K rows into memory, no rate limiting |
| M48 | DoS | Rate limiting degrades silently to per-instance on Redis failure |
| M49 | DoS | No per-item timeout in classification worker |
| M50 | DoS | No rate limiting on report generation endpoint |
| M51 | DoS | Default max request size is 100MB (should match 50MB upload limit) |
| M52 | Concurrency | TOCTOU in session creation (check-then-act without lock) |
| M53 | Concurrency | DuckDB single connection used from 4-thread pool (not thread-safe) |
| M54 | Concurrency | Non-atomic flush state file read-modify-write |
| M55 | Concurrency | No explicit transaction isolation level for critical ops |
| M56 | Remediation | `ast.literal_eval` fallback in permission restore |
| M57 | Remediation | Bulk remediation endpoint missing `FOR UPDATE` (TOCTOU) |
| M58 | Remediation | Rollback endpoint missing rate limiting |
| M59 | Remediation | `shutil.move` follows symlinks on destination |
| M60 | Remediation | Quarantine directory auto-creation without containment check |
| M61 | Remediation | Quarantine path (`/var/`) blocked by API path validation |
| M62 | Remediation | CLI remediation commands lack path validation |
| M63 | Remediation | Unbounded `os.chmod` with user-controlled mode (setuid/setgid) |
| M64 | Remediation | Rollback endpoint lacks path re-validation |
| M65 | Windows | Incomplete PowerShell injection blocklist (missing `(){}%#`) |
| M66 | Windows | Docker Compose service runs as SYSTEM with env-var-controlled path |
| M67 | Windows | WinRM `server_cert_validation` can be set to "ignore" |
| M68 | Windows | WEF default SDDL overly permissive (all Domain Computers) |
| M69 | Windows | No rate limiting on WinRM authentication endpoints |
| M70 | Windows | WinRM provider optional `tenant_id` allows cross-tenant credential loading |
| M71 | Privacy | Policy violation `matched_entities` may contain raw PII values |
| M72 | Privacy | Context text in findings exposes adjacent PII |

### LOW (82 findings)

Key themes in LOW findings:

- **Timing attacks** on non-critical comparisons (M365 state, auth callbacks)
- **WebSocket origin validation** allows missing Origin header
- **Log injection** via f-string logging with user-controlled paths
- **Information disclosure** in health endpoints (Python version, platform)
- **Internal file paths** in structured JSON logs
- **Cache error messages** expose Redis connection details
- **MD5 for cache keys** (non-security use but triggers scanners)
- **TOFU model integrity** without cryptographic signing
- **Hardcoded dev credentials** (mitigated by 3-layer guards)
- **Migration chain** has documented bogus merge nodes
- **Advisory locks** globally scoped (not per-tenant)
- **Various CLI issues**: ReDoS on Windows, config key not sanitized, recursive scan without depth limit
- **Docker compose** deprecated version field
- **npm dependencies** use caret ranges (mitigated by lockfile)
- **Rust dependencies** use partial semver (mitigated by Cargo.lock)
- **Various TOCTOU** in filesystem operations (mitigated by secondary checks)
- **Thread safety** in circuit breaker stats, pool stats, singleton init

---

## Top 10 Priority Remediations

| Priority | Issue | Impact | Effort |
|----------|-------|--------|--------|
| **1** | Enforce RLS with separate DB role + `FORCE ROW LEVEL SECURITY` | Eliminates entire class of cross-tenant data leakage | Medium |
| **2** | Redact PII in scan findings before storage | Prevents the PII detection tool from becoming a PII exposure tool | Low |
| **3** | Require `secret_key` in production; fail-closed on missing encryption | Prevents plaintext credential storage | Low |
| **4** | Pin GitHub Actions to SHA hashes | Blocks supply chain attacks on CI/CD | Low |
| **5** | Validate S3 `endpoint_url` against private IP ranges | Blocks SSRF to cloud metadata | Low |
| **6** | Default WinRM to HTTPS (`use_ssl=True`) | Prevents credential interception on the wire | Low |
| **7** | Use proper KDF (HKDF/PBKDF2) for Fernet key derivation | Prevents brute-force of weak secret keys | Low |
| **8** | Add WebSocket connection limits and request body streaming size check | Prevents DoS via connection/memory exhaustion | Medium |
| **9** | Restrict report distribution to admin + domain allowlist | Prevents data exfiltration via email | Low |
| **10** | Disable OpenAPI docs in production | Prevents unauthenticated API reconnaissance | Low |

---

## Security Controls Done Well

The audit also identified many well-implemented security controls:

1. **JWT algorithm pinning** -- RS256 only, rejects `alg: none` and HMAC confusion
2. **TOCTOU prevention** -- `SELECT FOR UPDATE` on first-user admin creation
3. **Session fixation prevention** -- old sessions deleted before creating new ones
4. **Open redirect prevention** -- comprehensive URL validation on auth redirects
5. **CSRF double-submit cookies** -- constant-time comparison via `secrets.compare_digest`
6. **OData injection protection** -- input escaping for Graph API filter queries
7. **CORS wildcard+credentials validation** -- model validator prevents dangerous combination
8. **SQL query endpoint** -- multi-layered validation (comment stripping, allowlist, forbidden patterns, row limits, timeouts)
9. **Token refresh race prevention** -- per-session `asyncio.Lock` with bounded OrderedDict
10. **CSV injection prevention** -- formula-trigger character prefixing in report exports
11. **Webhook replay protection** -- SHA-256 dedup cache with bounded size and time window
12. **Credential masking** -- `mask_config_credentials()` replaces secrets with `"******"` in API responses
13. **Path traversal prevention** -- centralized `validate_path()` with null bytes, `..`, system directories, sensitive files
14. **Filesystem symlink escape detection** -- `is_relative_to(scan_root)` checks
15. **Non-root Docker container** -- runs as `openlabels:1000`, multi-stage build
16. **Database isolation** -- internal-only Docker network, `scram-sha-256` auth, required passwords
17. **Tenant isolation** -- consistent `tenant_id` filtering via dependency injection across all routes
18. **Admin-only mutations** -- all destructive operations require `require_admin` dependency
19. **Audit logging** -- comprehensive trail for all security-relevant operations
20. **`yaml.safe_load` everywhere** -- no unsafe YAML deserialization

---

## Methodology

20 specialized security agents were deployed in parallel, each auditing a different attack surface:

1. SQL Injection
2. Authentication & Authorization
3. Command Injection & Path Traversal
4. XSS & Frontend Security
5. Secrets & Credential Exposure
6. API Security & Input Validation
7. Docker & Infrastructure Security
8. Database Security & Row-Level Security
9. Cloud Adapter & SSRF
10. Denial of Service & Resource Exhaustion
11. Logging & Information Disclosure
12. Cryptography & Key Management
13. Async Concurrency & Race Conditions
14. Dependency & Supply Chain
15. Policy Engine & RBAC
16. Monitoring & Event Processing
17. Remediation & Quarantine
18. CLI Security
19. Data Exfiltration & Privacy
20. Windows Service & WinRM

Each agent performed deep file-level analysis of relevant source code, reading individual files and tracing data flows from input to output. Findings were deduplicated and consolidated in this report.
