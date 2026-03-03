# Security Audit Report: OpenLabels

**Date:** 2026-02-11
**Auditor:** Automated Security Review (Claude)
**Branch:** `claude/security-audit-fYzkZ`
**Scope:** Full codebase review — authentication, authorization, input validation, data exposure, cryptography, configuration, dependencies, and business logic.

---

## Executive Summary

OpenLabels is a FastAPI-based data classification and auto-labeling platform using Azure AD (MSAL) OAuth2, async SQLAlchemy with PostgreSQL, Redis caching, and multi-tenant isolation. The codebase demonstrates **generally strong security practices** — proper JWT validation, CSRF double-submit cookies, session fixation prevention, path traversal guards, and consistent use of SQLAlchemy ORM to prevent SQL injection. However, 20 findings were identified across configuration defaults, error handling, input validation, and transport security.

| Severity | Count |
|----------|-------|
| Critical | 1     |
| High     | 4     |
| Medium   | 7     |
| Low      | 5     |
| Info     | 3     |

---

## Critical Findings

### C1: Default PostgreSQL Password in Docker Compose

- **File:** `docker-compose.yml:19,47`
- **Description:** `POSTGRES_PASSWORD` uses a default fallback of `openlabels` via `${POSTGRES_PASSWORD:-openlabels}`. If the operator does not set this environment variable, the database runs with a trivially guessable password. A container escape or compromise of the API container would give full database access.
- **Recommendation:** Remove the default fallback. Require `POSTGRES_PASSWORD` to be explicitly set and fail startup if it is not provided or matches a known-weak value.

---

## High Findings

### H1: SMTP Credentials Sent in Plaintext When TLS is Disabled

- **File:** `src/openlabels/reporting/engine.py:250-254`
- **Description:** When `smtp_use_tls` is `False`, SMTP login credentials are sent over an unencrypted connection. An attacker with network access can intercept these credentials.
- **Recommendation:** Enforce TLS when SMTP credentials are provided, or at minimum log a warning. Consider refusing to send credentials over plaintext entirely.

### H2: QRadar and Syslog CEF Default to Plaintext Transport (No TLS)

- **File:** `src/openlabels/server/config.py:639,654`
- **Description:** Both `qradar_use_tls` and `syslog_use_tls` default to `False`. Security event data (file paths, risk scores, entity types, policy violations, tenant identifiers) is transmitted in cleartext by default.
- **Recommendation:** Default these to `True`, or at minimum log a prominent warning at startup when TLS is disabled for SIEM transports.

### H3: Internal Exception Details Exposed in Report Distribution Response

- **File:** `src/openlabels/server/routes/reporting.py:581`
- **Description:** When report distribution fails, the raw exception message is returned directly to the client: `detail=f"Distribution failed: {exc}"`. This can expose SMTP server hostnames, file paths, and infrastructure details.
- **Recommendation:** Return a generic error message. Log the full exception server-side only.

### H4: Report Generation Error Stored in Database and Returned via API

- **File:** `src/openlabels/server/routes/reporting.py:437`
- **Description:** When report generation fails, `str(exc)` is stored in `report.error` which is serialized into the `ReportResponse` model. This can leak internal paths, database errors, or configuration details.
- **Recommendation:** Store a sanitized/generic error message. Log full details server-side.

---

## Medium Findings

### M1: LIKE Wildcard Injection in Monitoring Queries

- **File:** `src/openlabels/server/routes/monitoring.py:257,337`
- **Description:** The `user_name` query parameter is interpolated directly into `ilike()` patterns: `query.where(FileAccessEvent.user_name.ilike(f"%{user_name}%"))`. While SQLAlchemy parameterizes the value (preventing classic SQL injection), the LIKE wildcards `%` and `_` are not escaped. An attacker can supply `user_name=%` to match all rows or `_` to enumerate data.
- **Recommendation:** Escape LIKE special characters in user input before passing to `ilike()`: `user_name.replace('%', r'\%').replace('_', r'\_')`.

### M2: Target Config Update in Web UI Bypasses Validation

- **File:** `src/openlabels/web/routes.py:541-578`
- **Description:** The `update_target_form` endpoint accepts arbitrary `config[key]=value` form fields and stores them directly into `target.config` without calling `validate_target_config()`. In contrast, the API route for creating targets does validate. An attacker could inject arbitrary configuration keys (e.g., malicious paths, SSRF-targeting URLs) used during scan execution.
- **Recommendation:** Call `validate_target_config(adapter, config)` in the web form handler, matching the API route.

### M3: Scan Settings Lack Input Validation Bounds

- **File:** `src/openlabels/server/routes/settings.py:78-79`
- **Description:** `max_file_size_mb` and `concurrent_files` accept arbitrary integer values with no upper or lower bounds. An admin could set `concurrent_files` to an extremely high value, causing resource exhaustion during scans.
- **Recommendation:** Add validation constraints (e.g., `max_file_size_mb` 1-10000, `concurrent_files` 1-100).

### M4: `ast.literal_eval` on Externally-Sourced ACL Data

- **File:** `src/openlabels/remediation/permissions.py:516`
- **Description:** `_restore_permissions_unix` uses `ast.literal_eval()` on `acl_data` from stored ACL backups. While safer than `eval()`, it can parse arbitrarily complex nested structures causing memory exhaustion if backup data is tampered with.
- **Recommendation:** Use `json.loads()` instead, or validate size/structure before parsing.

### M5: Session Cookie `samesite` Inconsistency

- **File:** `src/openlabels/server/routes/auth.py:250,438`
- **Description:** Session cookie uses `samesite="strict"` on dev-mode login but `samesite="lax"` on the OAuth callback. The production path has weaker CSRF protection.
- **Recommendation:** Document the difference. Consider `strict` for the OAuth flow if the app doesn't rely on external top-level navigations to carry the session cookie. CSRF middleware provides supplementary protection.

### M6: HSTS Header Only Set in Production Environment

- **File:** `src/openlabels/server/middleware/stack.py:99-102`
- **Description:** `Strict-Transport-Security` header is only added when `environment == "production"`. Staging environments using HTTPS are left without HSTS, exposing them to protocol downgrade attacks.
- **Recommendation:** Set HSTS in staging as well, or make it independently configurable.

### M7: Webhook Endpoints Rely on Shared Secret Without HMAC

- **File:** `src/openlabels/server/routes/webhooks.py:68-170`
- **Description:** M365/Graph webhook endpoints rely solely on `clientState` shared-secret validation via simple string match rather than HMAC over the request body. An attacker who obtains the `clientState` value can forge arbitrary notifications.
- **Recommendation:** Implement request body signature verification. For Graph, validate signed tokens in the notification payload per Microsoft's recommendations.

---

## Low Findings

### L1: Webhook Validation Token Reflection

- **File:** `src/openlabels/server/routes/webhooks.py:74-86`
- **Description:** The M365 webhook validation handshake reflects the `validationToken` query parameter directly in the response. While `media_type="text/plain"` mitigates XSS in modern browsers, older browsers may MIME-sniff the content.
- **Recommendation:** Add `X-Content-Type-Options: nosniff` header. Validate token contains only expected characters.

### L2: Auth Error Messages Leak Validation Details

- **File:** `src/openlabels/auth/dependencies.py:132-137`
- **Description:** Token validation failures pass the exception message directly to the HTTP response (e.g., "Token expired: ...", "Invalid signature: ..."), revealing specific failure reasons that aid token crafting or replay attacks.
- **Recommendation:** Return a generic "Authentication failed" message. Log specifics server-side.

### L3: RBAC Information Disclosure in 403 Response

- **File:** `src/openlabels/auth/dependencies.py:208-211`
- **Description:** Error response reveals both the allowed roles for the endpoint and the user's current role: `f"Requires one of roles: {allowed_roles}. User has: {user.role}"`. Discloses the authorization model to attackers.
- **Recommendation:** Return a generic "Insufficient permissions" message.

### L4: Health Endpoint Exposes Detailed System Information Without Authentication

- **File:** `src/openlabels/server/routes/health.py:96-347,380`
- **Description:** The `/health/status` endpoint uses `get_optional_user`, so unauthenticated requests receive Python version, platform, database status, queue status, ML model availability, and circuit breaker states. The cache stats endpoint also returns raw exception strings revealing Redis connection details.
- **Recommendation:** Return only minimal health info for unauthenticated requests. Return generic error indicators instead of raw exceptions.

### L5: First User Auto-Assigned Admin (TOCTOU Race Condition)

- **File:** `src/openlabels/auth/dependencies.py:77-87`
- **Description:** The first user to authenticate for a new tenant is automatically made admin based on a count query. Two concurrent requests could both see zero users and both be assigned admin.
- **Recommendation:** Use a database-level unique constraint or advisory lock to ensure only one initial admin per tenant.

---

## Informational Findings

### I1: Session/CSRF Cookie `secure` Flag Depends on Request Scheme Detection

- **Files:** `src/openlabels/server/routes/auth.py:250-251,438-439`, `src/openlabels/server/middleware/csrf.py:182`
- **Description:** The `secure` flag is set conditionally: `secure=request.url.scheme == "https"`. Behind a TLS-terminating reverse proxy, FastAPI may see `http`, causing cookies to be sent without the `secure` flag.
- **Recommendation:** Use `X-Forwarded-Proto` header or a configuration setting to force `secure=True` in production.

### I2: Test Database Credentials in `pyproject.toml`

- **File:** `pyproject.toml:282-286`
- **Description:** Test database URL with password `test` and Redis URL are hardcoded in pytest configuration. Not secret, but could cause confusion.
- **Recommendation:** No action strictly required. Consider environment variable overrides.

### I3: CSP Allows `unsafe-inline` for Styles

- **File:** `src/openlabels/server/middleware/stack.py:112`
- **Description:** Content Security Policy includes `style-src 'self' 'unsafe-inline'`, weakening CSP by allowing inline styles that could be leveraged in CSS injection.
- **Recommendation:** Migrate to hash-based or nonce-based CSP for styles if feasible.

---

## Positive Security Observations

The codebase demonstrates strong security practices in many areas:

1. **JWT validation** — RS256 algorithm restriction, audience/issuer validation, JWKS caching with rotation (`auth/oauth.py`)
2. **CSRF protection** — Double-submit cookie pattern with `secrets.compare_digest` and Origin header validation (`middleware/csrf.py`)
3. **YAML loading** — Consistently uses `yaml.safe_load()` across all Python files
4. **No pickle/eval/exec** — No dangerous deserialization found on user-controlled input
5. **Session IDs** — Generated using `secrets.token_urlsafe(32)` with proper entropy
6. **Session fixation prevention** — Existing sessions invalidated before creating new ones during login
7. **Open redirect prevention** — Thorough validation blocking protocol-relative URLs, path traversal, and unauthorized origins
8. **Docker container** — Runs as non-root user
9. **Database network isolation** — Behind internal Docker network with no exposed ports
10. **Sentry** — Configured with `send_default_pii=False` and data scrubbing hooks
11. **Subprocess calls** — Remediation modules use list-form arguments (not `shell=True`), preventing command injection
12. **TrustedHostMiddleware** — Configured to prevent Host header injection
13. **Path traversal prevention** — Centralized `validate_path()` blocks `..`, null bytes, and system directories
14. **CORS** — Validator prevents wildcard origins with credentials
15. **Rate limiting** — Applied to auth endpoints and scan creation via slowapi
16. **Multi-tenant isolation** — Nearly all queries filter by `tenant_id` with `get_or_404` enforcing boundaries
17. **SQLAlchemy ORM** — Consistent use prevents classic SQL injection throughout most of the codebase
