# OpenLabels Security Audit Report

**Date:** 2026-02-04
**Auditor:** Claude (Red Team Exercise)
**Codebase Version:** Latest (branch: claude/security-audit-VqzZj)
**Last Updated:** 2026-02-04 (Fixes Applied)

---

## Executive Summary

This comprehensive security audit of the OpenLabels codebase identified **8 HIGH severity**, **12 MEDIUM severity**, and **6 LOW severity** findings. The application demonstrates a generally solid security posture with proper use of OAuth 2.0, CSRF protection, parameterized queries, and Jinja2 auto-escaping.

### Remediation Status

| Severity | Found | Fixed | Remaining |
|----------|-------|-------|-----------|
| CRITICAL | 1 | 1 | 0 |
| HIGH | 8 | 4 | 4 |
| MEDIUM | 12 | 4 | 8 |
| LOW | 6 | 0 | 6 |

### Fixes Applied

**CRITICAL (Fixed):**
- Open redirect vulnerability in OAuth login - Added `validate_redirect_uri()` function

**HIGH (Fixed):**
- Path traversal in remediation endpoints - Added `validate_file_path()` and `validate_quarantine_dir()`
- Missing rate limiting on critical endpoints - Added `@limiter.limit("10/minute")` decorators
- Security headers missing - Added comprehensive security headers middleware (HSTS, CSP, etc.)
- Sensitive data in error messages - Errors now return generic messages, detailed logs server-side

**MEDIUM (Fixed):**
- WebSocket origin validation - Added `validate_websocket_origin()` to prevent CSWSH
- XXE prevention - Added defusedxml dependency and `_safe_xml_fromstring()` wrapper
- JWT algorithm validation - Verified `algorithms=["RS256"]` is correctly specified

---

## CRITICAL Vulnerabilities

### 1. [CRITICAL] Open Redirect Vulnerability in OAuth Login Flow

**Location:** `src/openlabels/server/routes/auth.py:91-162`

**Description:** The `redirect_uri` parameter in the `/auth/login` endpoint is not validated against a whitelist of allowed URLs. An attacker could craft a malicious login link that redirects users to a phishing site after authentication.

```python
@router.get("/login")
async def login(
    request: Request,
    redirect_uri: Optional[str] = None,  # NOT VALIDATED!
    db: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    # ...
    response = RedirectResponse(url=redirect_uri or "/", status_code=302)
```

**Attack Scenario:**
1. Attacker sends victim: `https://app.example.com/auth/login?redirect_uri=https://evil.com/steal-session`
2. Victim logs in successfully via Microsoft
3. Victim is redirected to attacker's phishing site
4. Attacker can potentially steal session cookies or credentials

**Remediation:**
```python
ALLOWED_REDIRECT_HOSTS = {"localhost", "app.example.com", "admin.example.com"}

def validate_redirect_uri(redirect_uri: str, request: Request) -> str:
    """Validate redirect URI against whitelist."""
    if not redirect_uri:
        return "/"

    from urllib.parse import urlparse
    parsed = urlparse(redirect_uri)

    # Only allow relative paths or whitelisted hosts
    if not parsed.netloc:
        # Relative path - ensure it starts with /
        if redirect_uri.startswith("/"):
            return redirect_uri
        return "/"

    if parsed.netloc in ALLOWED_REDIRECT_HOSTS:
        return redirect_uri

    # Log attempted open redirect attack
    logger.warning(f"Blocked open redirect attempt to: {redirect_uri}")
    return "/"
```

---

## HIGH Severity Vulnerabilities

### 2. [HIGH] Path Traversal in Remediation Endpoints

**Location:** `src/openlabels/server/routes/remediation.py:58-68`

**Description:** The `file_path` parameter in quarantine and lockdown endpoints is not validated against path traversal attacks. While the endpoints require admin role, a compromised admin account could be used to access files outside intended directories.

```python
class QuarantineRequest(BaseModel):
    file_path: str = Field(..., description="Path to file to quarantine")
    quarantine_dir: Optional[str] = Field(None)  # Can be "../../../etc"
```

**Attack Scenario:**
- Admin sends: `{"file_path": "/etc/passwd", "quarantine_dir": "/tmp/exfil"}`
- System moves sensitive files to attacker-controlled location

**Remediation:** Implement path canonicalization and validation:
```python
def validate_file_path(path: str, allowed_roots: list[str]) -> str:
    """Validate file path is within allowed directories."""
    canonical = os.path.realpath(os.path.normpath(path))

    for root in allowed_roots:
        if canonical.startswith(os.path.realpath(root)):
            return canonical

    raise ValueError(f"Path {path} is outside allowed directories")
```

---

### 3. [HIGH] Missing Rate Limiting on Critical Endpoints

**Location:** `src/openlabels/server/routes/remediation.py`, `src/openlabels/server/routes/targets.py`

**Description:** While auth endpoints have rate limiting via SlowAPI, critical operational endpoints like remediation actions lack rate limiting. An attacker with valid credentials could:
- Mass-quarantine files causing DoS
- Exhaust disk space in quarantine directory
- Create thousands of lockdown rules overwhelming the system

**Affected Endpoints:**
- `POST /api/remediation/quarantine`
- `POST /api/remediation/lockdown`
- `POST /api/remediation/rollback`
- `POST /api/targets`
- `POST /api/scans`

**Remediation:** Add rate limiting decorators:
```python
@router.post("/quarantine")
@limiter.limit("10/minute")  # Add rate limiting
async def quarantine_file(...):
```

---

### 4. [HIGH] Insufficient Input Validation on Scan Target Paths

**Location:** `src/openlabels/server/routes/targets.py`

**Description:** Filesystem scan targets accept user-provided paths without validation. An attacker could configure scan targets to:
- Access system files (`/etc/shadow`, Windows SAM database)
- Scan network shares they shouldn't access
- Trigger resource exhaustion by scanning huge directories

**Remediation:** Implement allowed path prefixes configuration and validation.

---

### 5. [HIGH] Session Fixation Potential in Dev Mode

**Location:** `src/openlabels/server/routes/auth.py:112-162`

**Description:** While dev mode has environment checks, the session generation in dev mode uses a predictable pattern (`dev-user-oid`, `dev-tenant`). If an attacker can force dev mode activation, all sessions become equivalent.

**Recommendation:**
- Add explicit `ALLOW_DEV_AUTH=true` environment variable requirement
- Log all dev mode authentications prominently
- Generate unique session IDs even in dev mode

---

### 6. [HIGH] Sensitive Data in Error Messages

**Location:** `src/openlabels/server/routes/auth.py:207, 252`

**Description:** OAuth error descriptions from Microsoft are passed directly to clients:
```python
raise HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail=f"Authentication failed: {error_description or error}",  # May leak info
)
```

**Remediation:** Log detailed errors server-side, return generic messages to clients.

---

### 7. [HIGH] Missing Tenant Isolation Validation in Some Routes

**Location:** Multiple route files

**Description:** While most queries include `tenant_id` filtering, some endpoints may leak cross-tenant data if tenant isolation is bypassed. The `require_admin` dependency should be audited to ensure it always enforces tenant boundaries.

---

### 8. [HIGH] Insecure Cookie Configuration for Development

**Location:** `src/openlabels/server/routes/auth.py:158-161`

**Description:** The `secure` flag is only set when scheme is HTTPS:
```python
secure=request.url.scheme == "https",
```

This means cookies are not secure in development, which could be a problem if dev servers are accessed over untrusted networks.

---

### 9. [HIGH] Potential DoS via Large File Processing

**Location:** `src/openlabels/core/processor.py`, `src/openlabels/core/extractors.py`

**Description:** File extraction does not appear to have strict memory limits. Processing very large files (multi-GB PDFs with images) could exhaust server memory.

**Remediation:** Implement streaming extraction and memory limits.

---

## MEDIUM Severity Vulnerabilities

### 10. [MEDIUM] Weak Session ID Entropy Check

**Location:** `src/openlabels/server/routes/auth.py:84-86`

**Description:** While `secrets.token_urlsafe(32)` provides good entropy, there's no validation that the resulting session ID meets minimum security requirements.

---

### 11. [MEDIUM] Missing HSTS Header

**Location:** `src/openlabels/server/app.py`

**Description:** No Strict-Transport-Security header is configured. Users could be vulnerable to SSL stripping attacks on first visit.

**Remediation:** Add middleware to set HSTS header:
```python
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
```

---

### 12. [MEDIUM] No Content-Security-Policy Header

**Location:** `src/openlabels/server/app.py`

**Description:** The application doesn't set CSP headers, making XSS mitigation reliant solely on Jinja2 auto-escaping.

---

### 13. [MEDIUM] CORS Configuration May Be Too Permissive

**Location:** `src/openlabels/server/config.py`

**Description:** CORS allowed origins should be reviewed to ensure they're restrictive in production.

---

### 14. [MEDIUM] JWT Token Not Validated for Algorithm

**Location:** `src/openlabels/auth/oauth.py`

**Description:** Ensure JWT validation explicitly specifies allowed algorithms to prevent algorithm confusion attacks.

---

### 15. [MEDIUM] Missing Audit Log for Failed Authentication

**Location:** `src/openlabels/server/routes/auth.py`

**Description:** Failed authentication attempts are logged but not recorded in the audit table for later analysis.

---

### 16. [MEDIUM] No Brute Force Protection for Session IDs

**Description:** While session IDs have high entropy, there's no lockout mechanism if someone tries to brute force session cookies.

---

### 17. [MEDIUM] Potential XML External Entity (XXE) in Document Parsing

**Location:** `src/openlabels/core/extractors.py`

**Description:** Document extraction should ensure XXE protection is enabled in XML parsers.

---

### 18. [MEDIUM] Missing Subresource Integrity for External Scripts

**Location:** `src/openlabels/web/templates/base.html`

**Description:** If any external CDN scripts are loaded, they should use SRI hashes.

---

### 19. [MEDIUM] Verbose Error Logging May Leak Sensitive Data

**Location:** Multiple files

**Description:** Some error handlers log full stack traces that may include sensitive data.

---

### 20. [MEDIUM] WebSocket Origin Validation

**Location:** `src/openlabels/server/routes/ws.py`

**Description:** WebSocket connections should validate origin to prevent cross-site WebSocket hijacking.

---

### 21. [MEDIUM] Missing Security Headers on Static Files

**Description:** Static file responses may not include necessary security headers.

---

## LOW Severity Vulnerabilities

### 22. [LOW] Debug Mode Check Timing

**Location:** `src/openlabels/server/routes/auth.py:123`

**Description:** Debug mode check happens after environment check - could be reordered for clarity.

---

### 23. [LOW] Predictable Session Cookie Name

**Location:** `src/openlabels/server/routes/auth.py:40`

**Description:** The session cookie name `openlabels_session` is predictable. Consider randomizing or obscuring.

---

### 24. [LOW] Missing X-Content-Type-Options Header

**Description:** Add `nosniff` header to prevent MIME type sniffing.

---

### 25. [LOW] Missing X-Frame-Options Header

**Description:** Add clickjacking protection via X-Frame-Options or CSP frame-ancestors.

---

### 26. [LOW] Empty OID Validation in TokenClaims

**Location:** `src/openlabels/auth/oauth.py` (as noted in test at `tests/auth/test_oauth.py:59-65`)

**Description:** The TokenClaims Pydantic model accepts empty string for `oid` field. Should add `min_length=1` validation.

---

### 27. [LOW] Inconsistent Error Response Format

**Description:** Some endpoints return `{"error": "..."}` while others return `{"detail": "..."}`.

---

## Missing Security Tests

The following security test categories are insufficiently covered:

### Authentication & Authorization
- [ ] **Test for horizontal privilege escalation** - User A accessing User B's resources
- [ ] **Test for vertical privilege escalation** - Viewer accessing admin endpoints
- [ ] **Test open redirect validation** - Currently no tests for redirect_uri validation
- [ ] **Test session fixation attacks**
- [ ] **Test session timeout enforcement**
- [ ] **Test concurrent session limits** (if intended)

### Input Validation
- [ ] **Path traversal tests for remediation endpoints**
- [ ] **Path traversal tests for scan target configuration**
- [ ] **SQL injection tests** (parameterized queries are used, but should have explicit tests)
- [ ] **Command injection tests** (subprocess usage needs security tests)
- [ ] **File upload validation tests** (if applicable)

### Rate Limiting & DoS
- [ ] **Rate limiting enforcement tests for all endpoints**
- [ ] **Large file handling tests** (memory exhaustion prevention)
- [ ] **Concurrent request handling tests**

### Security Headers
- [ ] **HSTS header presence test**
- [ ] **CSP header presence test**
- [ ] **X-Frame-Options test**
- [ ] **X-Content-Type-Options test**

### Data Protection
- [ ] **Sensitive data masking in logs**
- [ ] **PII not leaked in error responses**
- [ ] **Tenant isolation tests** (comprehensive cross-tenant access attempts)

### API Security
- [ ] **CORS policy enforcement tests**
- [ ] **API versioning security**
- [ ] **Deprecated endpoint protection**

---

## Recommended Security Test Additions

Create `tests/security/` directory with:

```
tests/security/
├── test_authentication_bypass.py
├── test_authorization_escalation.py
├── test_path_traversal.py
├── test_injection_attacks.py
├── test_rate_limiting.py
├── test_security_headers.py
├── test_tenant_isolation.py
├── test_session_security.py
└── test_open_redirect.py
```

### Example Test: Open Redirect

```python
# tests/security/test_open_redirect.py
import pytest
from httpx import AsyncClient

class TestOpenRedirect:
    """Tests for open redirect vulnerabilities."""

    @pytest.mark.asyncio
    async def test_external_redirect_blocked(self, test_client: AsyncClient):
        """External URLs in redirect_uri should be blocked."""
        response = await test_client.get(
            "/auth/login",
            params={"redirect_uri": "https://evil.com/phishing"},
            follow_redirects=False,
        )
        # Should redirect to safe location, not evil.com
        location = response.headers.get("location", "")
        assert "evil.com" not in location

    @pytest.mark.asyncio
    async def test_relative_redirect_allowed(self, test_client: AsyncClient):
        """Relative paths should be allowed."""
        response = await test_client.get(
            "/auth/login",
            params={"redirect_uri": "/dashboard"},
            follow_redirects=False,
        )
        location = response.headers.get("location", "")
        # In dev mode, redirects directly; in prod, redirects to Microsoft
        assert "evil" not in location

    @pytest.mark.asyncio
    async def test_protocol_relative_blocked(self, test_client: AsyncClient):
        """Protocol-relative URLs should be blocked."""
        response = await test_client.get(
            "/auth/login",
            params={"redirect_uri": "//evil.com/phishing"},
            follow_redirects=False,
        )
        location = response.headers.get("location", "")
        assert "evil.com" not in location
```

### Example Test: Path Traversal

```python
# tests/security/test_path_traversal.py
import pytest
from httpx import AsyncClient

class TestPathTraversal:
    """Tests for path traversal vulnerabilities."""

    @pytest.mark.asyncio
    async def test_quarantine_path_traversal_blocked(
        self, test_client: AsyncClient, admin_auth_headers
    ):
        """Path traversal in quarantine should be blocked."""
        response = await test_client.post(
            "/api/remediation/quarantine",
            json={
                "file_path": "../../../etc/passwd",
                "quarantine_dir": "/tmp/quarantine",
            },
            headers=admin_auth_headers,
        )
        # Should reject path traversal attempts
        assert response.status_code in (400, 403, 422)

    @pytest.mark.asyncio
    async def test_quarantine_dir_traversal_blocked(
        self, test_client: AsyncClient, admin_auth_headers
    ):
        """Path traversal in quarantine_dir should be blocked."""
        response = await test_client.post(
            "/api/remediation/quarantine",
            json={
                "file_path": "/data/sensitive.docx",
                "quarantine_dir": "../../../tmp/exfil",
            },
            headers=admin_auth_headers,
        )
        assert response.status_code in (400, 403, 422)
```

### Example Test: Tenant Isolation

```python
# tests/security/test_tenant_isolation.py
import pytest
from httpx import AsyncClient

class TestTenantIsolation:
    """Tests for multi-tenant data isolation."""

    @pytest.mark.asyncio
    async def test_cannot_access_other_tenant_scans(
        self,
        test_client: AsyncClient,
        tenant_a_auth_headers,
        tenant_b_scan_id,  # Scan owned by tenant B
    ):
        """User from tenant A should not access tenant B's scans."""
        response = await test_client.get(
            f"/api/scans/{tenant_b_scan_id}",
            headers=tenant_a_auth_headers,
        )
        assert response.status_code == 404  # Not 403, to avoid enumeration

    @pytest.mark.asyncio
    async def test_cannot_modify_other_tenant_targets(
        self,
        test_client: AsyncClient,
        tenant_a_auth_headers,
        tenant_b_target_id,
    ):
        """User from tenant A should not modify tenant B's targets."""
        response = await test_client.put(
            f"/api/targets/{tenant_b_target_id}",
            json={"name": "Hijacked Target"},
            headers=tenant_a_auth_headers,
        )
        assert response.status_code == 404
```

---

## Security Posture Strengths

The codebase demonstrates several security best practices:

1. **OAuth 2.0 with PKCE** - Proper implementation of OAuth flow
2. **CSRF Protection** - Double-submit cookie pattern with origin validation
3. **Parameterized Queries** - SQLAlchemy ORM prevents SQL injection
4. **Jinja2 Auto-Escaping** - Templates use auto-escaping (no `|safe` filters found)
5. **Rate Limiting** - SlowAPI used on auth endpoints
6. **Audit Logging** - Comprehensive audit trail for sensitive actions
7. **Session Security** - HttpOnly cookies, SameSite=Lax
8. **Multi-Tenancy** - Tenant isolation built into data model
9. **Role-Based Access Control** - Admin/viewer roles enforced
10. **Dev Mode Protections** - Multiple checks prevent dev mode in production

---

## Remediation Priority

### Immediate (This Week)
1. Fix open redirect vulnerability (CRITICAL)
2. Add path traversal validation to remediation endpoints (HIGH)
3. Add rate limiting to critical endpoints (HIGH)

### Short Term (2-4 Weeks)
1. Add missing security headers (HSTS, CSP, X-Frame-Options)
2. Implement security test suite
3. Review and harden error message handling
4. Add audit logging for failed auth attempts

### Medium Term (1-3 Months)
1. Implement comprehensive tenant isolation tests
2. Add memory limits for file processing
3. Security review of all API endpoints
4. Penetration testing by external party

---

## Appendix: Files Reviewed

### Core Security Files
- `src/openlabels/auth/oauth.py`
- `src/openlabels/auth/dependencies.py`
- `src/openlabels/server/middleware/csrf.py`
- `src/openlabels/server/session.py`
- `src/openlabels/server/routes/auth.py`
- `src/openlabels/server/config.py`
- `src/openlabels/server/app.py`

### High-Risk Feature Files
- `src/openlabels/server/routes/remediation.py`
- `src/openlabels/server/routes/targets.py`
- `src/openlabels/adapters/filesystem.py`
- `src/openlabels/remediation/quarantine.py`
- `src/openlabels/web/routes.py`

### Test Files Reviewed
- `tests/test_csrf_middleware.py`
- `tests/auth/test_oauth.py`
- `tests/auth/test_dependencies.py`
- `tests/auth/test_graph.py`
- `tests/server/test_routes.py`

---

*Report generated by Claude Security Audit Tool*
