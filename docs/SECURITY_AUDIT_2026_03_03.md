# OpenLabels Security Audit Report

**Date:** 2026-03-03
**Scope:** Full codebase red team audit (backend, frontend, infrastructure, dependencies)
**Method:** 20 parallel automated security agents covering all OWASP categories
**Codebase:** Python/FastAPI backend + React/TypeScript frontend

---

## Executive Summary

A comprehensive security audit was performed across 20 security domains using parallel automated agents. The audit examined ~200 Python source files, ~100 TypeScript/React files, Docker/CI infrastructure, and all project dependencies.

**The codebase demonstrates a mature security posture** with many best practices already in place: parameterized SQL queries, Pydantic v2 strict validation, `defusedxml` globally applied, Fernet encryption at rest, HMAC-signed cursors, CSRF double-submit cookies, RLS policies, UUIDv7 keys, and comprehensive security test suites.

However, the audit identified **129 total findings** across severity levels:

| Severity | Count | Description |
|----------|-------|-------------|
| **CRITICAL** | 4 | Vulnerable dependencies (Pillow RCE, authlib floor), dev password logged at import |
| **HIGH** | 12 | Missing tenant filters, SSRF bypass, missing rate limits on webhooks, no malware scanning, vulnerable deps |
| **MEDIUM** | 35 | Auth bypasses, missing rate limits, CSP weaknesses, credential exposure, DNS rebinding |
| **LOW** | 60 | Defense-in-depth gaps, timing attacks, missing escaping, test correctness issues |
| **INFO** | 18 | Hardening recommendations, acceptable design trade-offs |

---

## CRITICAL Findings

### C-1: Pillow 12.1.0 — Out-of-Bounds Write / Potential RCE
- **CVE:** CVE-2026-25990
- **File:** `pyproject.toml:79` (locked at 12.1.0, fix in 12.1.1)
- **Impact:** Heap corruption via crafted PSD images. Potential remote code execution.
- **Fix:** `uv lock --upgrade-package pillow` and set floor to `>=12.1.1`

### C-2: Authlib Floor Constraint Allows Vulnerable Versions
- **CVEs:** CVE-2025-68158 (account takeover), CVE-2025-59420, CVE-2025-61920, CVE-2025-62706
- **File:** `pyproject.toml:56` — `authlib>=1.3.1` allows 1.3.x–1.6.5 on fresh installs
- **Impact:** 1-click account takeover via CSRF, JWS header bypass, DoS
- **Fix:** Raise floor to `authlib>=1.6.6`

### C-3: Dev Password Logged at Module Import Time (Even in Production)
- **File:** `src/openlabels/server/routes/auth.py:56-58`
- **Impact:** Password generated and logged via `logger.warning()` unconditionally at import — written to all log aggregation systems even when dev mode is disabled
- **Fix:** Move inside dev-mode guard; never log secrets through the logging framework

### C-4: cryptography 46.0.4 — Elliptic Curve Key Disclosure
- **CVE:** CVE-2026-26007
- **File:** Transitive dep via authlib/PyJWT (locked at 46.0.4, fix in 46.0.5)
- **Impact:** Partial private key recovery via EC public key operations
- **Fix:** `uv lock --upgrade-package cryptography`

---

## HIGH Findings

### H-1: Missing Tenant Filter in Report Generation (Cross-Tenant Data Leak)
- **File:** `src/openlabels/server/routes/reporting.py:359`
- **Impact:** `ScanJob` lookup by `job_id` without `tenant_id` filter — leaks cross-tenant job metadata
- **Fix:** Add `.where(ScanJob.tenant_id == tenant_id)` to the query

### H-2: Analytics S3 Storage Missing SSRF Validation
- **File:** `src/openlabels/analytics/storage.py:190-191`
- **Impact:** `S3CatalogStorage` accepts `endpoint_url` without calling `_validate_endpoint_url()` — allows SSRF to cloud metadata (169.254.169.254)
- **Fix:** Import and call `_validate_endpoint_url` before using endpoint URL

### H-3: Missing Rate Limits on Webhook Endpoints
- **File:** `src/openlabels/server/routes/webhooks.py:135-257`
- **Impact:** `/webhooks/m365` and `/webhooks/graph` are publicly accessible with zero rate limiting — CPU/IO exhaustion via flood
- **Fix:** Add `@limiter.limit("100/minute")` to both endpoints

### H-4: No Pillow Decompression Bomb Limit
- **Files:** `src/openlabels/core/extractors.py:547,587`, `processor.py:366`, `pipeline/tiered.py:639`
- **Impact:** Crafted image with small file size but huge pixel dimensions causes OOM
- **Fix:** Set `Image.MAX_IMAGE_PIXELS = 25_000_000` at startup

### H-5: No Content-Type / Magic Byte Validation
- **File:** `src/openlabels/core/processor.py:186`
- **Impact:** File type determined solely by extension — type spoofing bypasses routing
- **Fix:** Add `python-magic` validation against actual file content

### H-6: No Virus/Malware Scanning Integration
- **Files:** All file processing paths
- **Impact:** Malicious files processed without any AV scanning
- **Fix:** Integrate ClamAV or equivalent as first pipeline step

### H-7: Missing Cache-Control Headers on Sensitive Exports
- **Files:** `routes/results.py:286-310`, `routes/reporting.py:854`, `routes/query.py:648`, `middleware/stack.py:163-205`
- **Impact:** Browser/proxy caching of exported PII scan results
- **Fix:** Add `Cache-Control: no-store` to global security headers middleware

### H-8: GraphClient Stores client_secret as Public Instance Attribute
- **File:** `src/openlabels/auth/graph.py:159`
- **Impact:** Plaintext client secret exposed via stack traces, memory dumps, `repr()`
- **Fix:** Use `self._client_secret` (private), add `clear_credentials()`, override `__repr__`

### H-9: Redis Server CVE-2025-49844 "RediShell" (Operational)
- **CVSS:** 10.0 — Use-After-Free in Lua engine, RCE on all Redis < 8.2.2
- **Impact:** Full compromise of Redis server and cached data
- **Fix:** Upgrade Redis server to 8.2.2+

### H-10: Default DB Password in Installer Config
- **File:** `installer/config.sample.yaml:19`
- **Impact:** `openlabels:openlabels` — trivially guessable, operators may copy without changing
- **Fix:** Replace with clearly invalid placeholder like `<GENERATE_A_STRONG_PASSWORD>`

### H-11: Dev Password Logged in Plaintext
- **File:** `src/openlabels/server/routes/auth.py:58`
- **Impact:** Random dev password written to WARNING log — persists in log aggregation
- **Fix:** Never log credentials; print to stderr only

### H-12: SSRF Validation Vulnerable to DNS Rebinding
- **File:** `src/openlabels/adapters/s3.py:89-108`
- **Impact:** DNS resolution check is TOCTOU — hostname can rebind to internal IP after validation
- **Fix:** Pin resolved IP in custom urllib3 adapter or use IP directly

---

## MEDIUM Findings

### Authentication & Authorization
| # | Finding | File | Fix |
|---|---------|------|-----|
| M-1 | OIDC nonce validation skipped when nonce not stored | `auth.py:601,688` | Make nonce mandatory, fail if missing |
| M-2 | OIDC algorithm from token header (not server config) | `oidc_provider.py:278-285` | Configure allowed algorithms per provider |
| M-3 | Dev mode disables CSRF entirely | `middleware/csrf.py:130-134` | Add startup warning, log bypassed requests |
| M-4 | M365 consent callback no admin auth check | `routes/m365.py:426-434` | Add `Depends(require_admin)` |

### Database & Tenant Isolation
| # | Finding | File | Fix |
|---|---------|------|-----|
| M-5 | Routes use `get_session()` without RLS context | All route files | Switch to `TenantDbSessionDep` |
| M-6 | Schedule target name lookup missing tenant filter | `routes/schedules.py:139-142` | Add `tenant_id` to WHERE clause |
| M-7 | `$1` tenant placeholder in query endpoint bypassable | `routes/query.py:524-532` | Auto-inject WHERE tenant filter |
| M-8 | Session encryption not enforced in staging | `server/session.py:46-58` | Enforce encryption in staging too |

### Rate Limiting & DoS
| # | Finding | File | Fix |
|---|---------|------|-----|
| M-9 | ~80% of API endpoints missing rate limits | Multiple route files | Apply `TenantRateLimitDep` universally |
| M-10 | HTTP client without timeout in Graph token acquisition | `graph_client.py:295` | Add `timeout=30.0` |
| M-11 | Scan retry endpoint missing rate limit | `routes/scans.py:199` | Add `@limiter.limit("10/minute")` |
| M-12 | Results apply-label endpoint missing rate limit | `routes/results.py:418` | Add `@limiter.limit("20/minute")` |
| M-13 | Export results endpoint missing rate limit | `routes/results.py:185-310` | Add `@limiter.limit("5/minute")` |

### Cloud Storage & SSRF
| # | Finding | File | Fix |
|---|---------|------|-----|
| M-14 | No SSE enforcement on S3/GCS writes | `adapters/s3.py:452`, `gcs.py:389` | Preserve original encryption settings |
| M-15 | No path traversal validation on cloud object keys | `adapters/base.py:490-493` | Add `..` check in `resolve_prefix()` |
| M-16 | Insufficient audit logging for cloud write ops | Multiple adapter files | Add structured audit logging |

### Secrets & Credentials
| # | Finding | File | Fix |
|---|---------|------|-----|
| M-17 | DuckDB credentials in SQL string interpolation | `analytics/engine.py:79-102` | Disable DuckDB query logging, wrap in try/except |
| M-18 | Hardcoded fallback HMAC key for WS pub/sub | `routes/ws.py:58` | Raise error in non-dev, generate ephemeral key |
| M-19 | Plaintext session tokens in non-production | `server/session.py:46-58` | Enforce encryption in staging |
| M-20 | Hardcoded test password in docker-compose.test.yml | `docker-compose.test.yml:15` | Use env var without default |

### Frontend & Headers
| # | Finding | File | Fix |
|---|---------|------|-----|
| M-21 | CSP `style-src 'unsafe-inline'` | `middleware/stack.py:184` | Migrate to nonce-based CSP |
| M-22 | CSP `connect-src wss: ws:` allows any WebSocket host | `middleware/stack.py:187` | Restrict to specific hosts |
| M-23 | Health endpoint leaks global job counts unauthenticated | `routes/health.py:164-183` | Scope to authenticated tenant |

### Information Disclosure
| # | Finding | File | Fix |
|---|---------|------|-----|
| M-24 | Token error leaks IdP error_description to clients | `routes/enumerate.py:493-495` | Return generic error, log details server-side |
| M-25 | Exception `str(e)` passed to API clients | `routes/query.py:550`, `enumerate.py:638`, `monitoring.py:284` | Map to user-friendly messages |

### File Processing
| # | Finding | File | Fix |
|---|---------|------|-----|
| M-26 | XLS processing without decompression bomb protection | `extractors.py:453-488` | Add `total_chars` tracking |
| M-27 | Unbounded CSV/TSV processing | `extractors.py:358-385` | Apply row limits and size caps |
| M-28 | PDF processing without page content size limits | `extractors.py:114-226` | Add accumulated text size limit |

### Path Traversal
| # | Finding | File | Fix |
|---|---------|------|-----|
| M-29 | Missing `validate_path()` in `remove_pdf_label` | `labeling/engine.py:504-536` | Add validation call |
| M-30 | Missing `validate_path()` in `get_local_label` | `labeling/engine.py:539-613` | Add validation call |

### Infrastructure
| # | Finding | File | Fix |
|---|---------|------|-----|
| M-31 | Pre-commit hooks not enforced in CI | `.github/workflows/test.yml` | Add `detect-secrets` and `bandit` to CI |
| M-32 | Unsigned Windows installer | `installer/build.ps1` | Add code signing |

### Dependencies
| # | Finding | File | Fix |
|---|---------|------|-----|
| M-33 | numpy pinned to EOL 1.x series | `pyproject.toml:98` | Plan migration to numpy 2.x |
| M-34 | Dependency confusion: `openlabels_matcher` not on PyPI | `src/openlabels/core/_rust/pyproject.toml` | Register placeholder on PyPI |
| M-35 | Overly permissive version constraints | `pyproject.toml` (multiple) | Raise floors to patched versions |

---

## LOW Findings (60)

### SQL & Database (4)
- LIKE wildcard injection in scan results search (`routes/results.py:140-142`)
- Incomplete LIKE escaping in monitoring routes — missing backslash (`routes/monitoring.py:393,443,448,527`)
- `get_or_404()` timing side-channel for tenant enumeration (`routes/__init__.py:18-27`)
- Database URL hardcoded in `alembic.ini:92`

### Authentication (7)
- Dev login credential comparison not constant-time (`auth.py:801`)
- `verify_at_hash` disabled in OIDC validation (`oidc_provider.py:288`)
- M365 consent callback no admin dependency (`m365.py:426-434`)
- Static HKDF salt not unique per deployment (`crypto.py:72`)
- Session encryption key no rotation support (`session.py:35-64`)
- CSRF cookie not cleared on logout (`auth.py:904,915,920`)
- CSRF token not rotated after login (`csrf.py:139-141`)

### Rate Limiting (4)
- Report generation rate limit too generous (`reporting.py:592`)
- SIEM export test endpoint missing rate limit (`export.py:127-145`)
- Permissions export endpoint missing rate limit (`permissions.py:718`)
- Policy import endpoint missing rate limit (`policies.py:483`)

### WebSocket (8)
- No per-user connection limit, only per-tenant (`ws.py:46-47`)
- No outbound message size limit (`ws.py:211-223`)
- Error strings sent to clients verbatim via `publish_scan_failed` (`ws_events.py:431-443`)
- Full server file paths exposed via WS messages (`ws.py:587-603`, `scan.py:614-619`)
- Stale connections on non-disconnect errors (`ws.py:531-569`)
- No client-side WS message schema validation (`use-websocket.ts:13-33`)
- Incorrect test: missing origin allowed in production (`test_ws.py:258-270`)
- Incorrect test: same-origin via Host header allowed (`test_ws.py:307-323`)

### Infrastructure (10)
- Hardcoded default test password in docker-compose.test.yml
- CI Redis has no password (`.github/workflows/test.yml:76-83`)
- Test containers missing security hardening
- No read-only root filesystem in docker-compose
- Postgres/Redis images not pinned by digest
- Missing `.secrets.baseline` file
- Missing explicit permissions in test.yml workflow
- Codecov action missing upload token
- Redis health check exposes password in process list
- Installer ships placeholder credentials

### Path Traversal (7)
- `FilesystemAdapter.read_file` `base_directory` never passed by callers (`filesystem.py:325`)
- File-level symlinks not validated in `_collect_entries` (`filesystem.py:246-264`)
- `_collect_entries` follows symlinks via `entry.stat()` (`filesystem.py:249`)
- `remove_sidecar` does not validate path (`labeling/engine.py:617`)
- Compaction lock file path from unsanitized table name (`compaction.py:60-61`)
- TOCTOU race in quarantine symlink check (`quarantine.py:323-331`)
- `ast.literal_eval` fallback in permission restore (`permissions.py:594-599`)

### Frontend & Headers (5)
- CSP `img-src` permits all HTTPS origins (`stack.py:185`)
- CSP `connect-src` allows all WebSocket origins (`stack.py:187`)
- CSP missing `object-src` directive (`stack.py:181-191`)
- HSTS missing `preload` directive (`stack.py:170-172`)
- `delete_cookie` calls missing `path` parameter in login flows (`auth.py:367,636,754,836`)

### Cloud Storage (4)
- `auth/graph.py` singleton never rotates token cache (`auth/graph.py:444-460`)
- Configurable `verify_ssl=False` for SIEM exports (`splunk.py:61`, `elastic.py:158`)
- Empty `secret_key` allowed in development (`config.py:42-57`)
- Delta token cache not bounded or persistence-secured (`graph_client.py:499-522`)

### Information Disclosure (5)
- Version number exposed in unauthenticated endpoints (`app.py:151-197`)
- System info exposed to any authenticated user (`health.py:302-359`)
- Cache error response includes raw exception details (`health.py:428-435`)
- Jinja2 CSS class injection via unescaped attribute context (multiple templates)
- `window.open()` with server-provided URL without client validation (`m365-step.tsx:26`)

### IDOR & Access Control (6)
- Most request models lack `extra="forbid"` (multiple route files)
- In-memory alert rules volatile across restarts (`health.py:824`)
- `PolicyService.update_policy` uses `setattr` with dict input (`policy_service.py:89-100`)
- `LabelService.update_label_rule` accepts raw dict (`label_service.py:294-347`)
- Query endpoint tenant `$1` check bypassable (`query.py:524-532`)
- `ResultService.get_result` returns None vs raising (`result_service.py`)

---

## INFO Findings (18)

- Unicode CSRF tokens cause 500 instead of 403 (`csrf.py:96-109`)
- CSRF exempt path matching — exact match is correct (`csrf.py:144-146`)
- WS origin validation allows missing Origin in dev (`ws.py:106-115`)
- CSRF cookie `httponly=False` by design for double-submit (`csrf.py:188`)
- Session cookie missing explicit `path` attribute (`auth.py:211-218`)
- No `X-Permitted-Cross-Domain-Policies` header (`stack.py:163-205`)
- No COOP/CORP headers (`stack.py:163-205`)
- HSTS not set in development (intentional) (`stack.py:169-172`)
- DB credentials in docker-compose env vars (acceptable for dev)
- AWS example credentials in tests (intentional for testing)
- Fake credentials in test fixtures (intentional)
- Frontend example access key as placeholder (`constants.ts:99`)
- MD5 used for cache key generation (non-security use) (`cache.py:610,617`)
- Dev password logged (duplicate of C-3/H-11)
- Webhook endpoints no auth (by design, mitigated by clientState HMAC)
- Circuit breaker status exposed to non-admin users (`health.py:302-318`)
- `Span.to_dict()` includes raw detected entity text (`types.py:452-466`)
- No WS idle timeout / max connection duration (`ws.py`, `ws_events.py`)

---

## Positive Security Controls (What's Done Well)

The audit confirmed extensive well-implemented security controls:

1. **Zero SQL injection** — Parameterized queries throughout, ORM used correctly
2. **Zero XSS** — No `dangerouslySetInnerHTML`, no `eval()`, no `innerHTML`
3. **Zero pickle/unsafe YAML** — `yaml.safe_load` everywhere, no pickle usage
4. **defusedxml globally applied** — XXE protection via `defuse_stdlib()` at import
5. **Fernet encryption at rest** — HKDF key derivation, MultiFernet key rotation
6. **HMAC-signed cursors** — Pagination cursors tamper-proof with constant-time comparison
7. **CSRF double-submit cookies** — 256-bit tokens, origin validation, SameSite=Lax
8. **UUIDv7 primary keys** — No sequential enumeration possible
9. **PostgreSQL RLS** — FORCE on 27 tables with restricted `openlabels_app` role
10. **Consistent tenant isolation** — `get_or_404` returns 404 (not 403) for IDOR prevention
11. **JWKS-based JWT validation** — Asymmetric RS256/ES256 with algorithm allowlists
12. **Secure session cookies** — HttpOnly, SameSite=Lax, Secure, database-backed
13. **Open redirect prevention** — Comprehensive URL validation with protocol/domain checks
14. **CSV injection prevention** — Cell sanitization in report exports
15. **WebSocket HMAC signing** — Redis pub/sub messages signed and verified
16. **SSRF protection** — Private IP blocklist with DNS resolution in S3 adapter
17. **Decompression bomb protection** — Size limits, extraction ratios, page count caps
18. **Credential masking** — `SecretStr` + `mask_config_credentials()` in API responses
19. **GitHub Actions pinned by SHA** — Supply chain protection for CI
20. **Trivy + pip-audit in CI** — Automated vulnerability scanning
21. **Rate limiting with proxy-aware IP extraction** — Trusted proxy CIDR allowlist
22. **Container hardening** — no-new-privileges, cap_drop ALL, resource limits, internal networks

---

## Priority Remediation Roadmap

### Immediate (This Week)
1. Upgrade `pillow>=12.1.1` and `cryptography>=46.0.5` — `uv lock --upgrade-package pillow --upgrade-package cryptography`
2. Raise `authlib>=1.6.6` floor constraint
3. Fix missing tenant filter in `reporting.py:359`
4. Move dev password logging inside dev-mode guard
5. Add rate limiting to webhook endpoints

### Short-Term (This Sprint)
6. Add `Cache-Control: no-store` to security headers middleware
7. Fix SSRF in analytics S3 storage
8. Set `Image.MAX_IMAGE_PIXELS` at startup
9. Add file content-type validation via magic bytes
10. Make OIDC nonce mandatory

### Medium-Term (Next Sprint)
11. Apply rate limits to all unprotected endpoints
12. Switch routes to `TenantDbSessionDep` for RLS enforcement
13. Add decompression bomb limits to CSV/XLS/PDF extractors
14. Migrate CSP to nonce-based styles
15. Register `openlabels_matcher` on PyPI

### Long-Term (Backlog)
16. Integrate ClamAV malware scanning
17. Plan numpy 2.x migration
18. Add COOP/CORP headers
19. Add structured audit logging for cloud operations
20. Session encryption key rotation support

---

*This report was generated by 20 parallel security audit agents examining the full OpenLabels codebase on 2026-03-03.*
