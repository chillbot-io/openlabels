# OpenLabels Codebase Audit Report

**Date:** 2026-02-02
**Auditor:** Claude (Opus 4.5)
**Verdict:** NOT PRODUCTION READY

---

## Executive Summary

This codebase is a **poorly integrated frankenstein** of three separate projects (OpenLabels, OpenRisk, ScrubIQ) that have been combined without proper architectural unification. There are critical security issues, significant code duplication, incomplete implementations, and production-blocking problems throughout.

---

## CRITICAL ISSUES (Production Blockers)

### 0. Missing `sys` Import Causes NameError (RUNTIME CRASH)

**File:** `src/openlabels/adapters/filesystem.py`

**Lines:** 359, 433, 438, 514

```python
async def get_acl(self, file_info: FileInfo) -> Optional[dict]:
    path = Path(file_info.path)
    if sys.platform == "win32":  # NameError: name 'sys' is not defined
        return self._get_windows_acl(path)
```

**Issue:** The `sys` module is used for platform detection (`sys.platform`) in the `get_acl`, `set_acl`, and `lockdown_file` methods, but `sys` is never imported at the top of the file. This will cause a `NameError` at runtime when these methods are called.

**Fix:** Add `import sys` to the imports at the top of the file.

---

### 1. CORS Wildcard with Credentials (SECURITY)

**Files:**
- `src/openlabels/server/app.py:51`
- `openrisk/openlabels/api/server.py:46`

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,  # DANGEROUS WITH WILDCARD!
)
```

**Issue:** `allow_credentials=True` with `allow_origins=["*"]` is a security vulnerability. Browsers should reject this per CORS spec, but misconfigured proxies may not. Production APIs should never use wildcard origins with credentials.

---

### 2. In-Memory Session Storage (NOT SCALABLE)

**File:** `src/openlabels/server/routes/auth.py:33-39`

```python
# Session storage (in production, use Redis or database)
# Maps session_id -> {access_token, refresh_token, expires_at, claims}
_sessions: dict[str, dict] = {}

# PKCE state storage (temporary, for login flow)
_pending_auth: dict[str, dict] = {}
```

**Issue:** Sessions stored in Python dict will be lost on restart and don't work with multiple workers. The comment explicitly acknowledges this isn't production-ready.

---

### 3. NotImplementedError Landmines

**Active exceptions that will crash in production:**

| File | Line | Error |
|------|------|-------|
| `openrisk/openlabels/api/scanner.py` | 275 | `raise NotImplementedError("S3 scanning via API not yet implemented")` |
| `scrubiq/scrubiq/llm_client.py` | 76 | `raise NotImplementedError(f"Provider '{provider}' not yet implemented")` for Google, Gemini, Azure, Azure_OpenAI |
| `openrisk/openlabels/output/virtual.py` | 282-288 | Abstract methods that crash if base class used directly |

---

### 4. Massive Code Duplication (3x Maintenance Burden)

**IDENTICAL FILES between openrisk and scrubiq:**
- `pipeline/allowlist.py` - 28,429 bytes (MD5: `89d37fc2c64c2db085d332b0f402a786`)
- `pipeline/normalizer.py` - 9,289 bytes
- `pipeline/repeats.py` - 12,061 bytes

**Detector classes implemented 3 times with different code:**

| Class | openlabels | openrisk | scrubiq |
|-------|------------|----------|---------|
| BaseDetector | 58 lines | 326 lines | 39 lines |
| ChecksumDetector | 220 lines | 490 lines | 439 lines |
| SecretsDetector | 220 lines | 491 lines | 373 lines |
| FinancialDetector | 11.5KB | 21.7KB | 20.6KB |
| DetectorOrchestrator | 14.5KB | 34.7KB | 33.1KB |

**Type definitions duplicated 4 times:**
- `src/openlabels/core/types.py` (440 lines)
- `openrisk/openlabels/core/types.py` (314 lines)
- `openrisk/openlabels/adapters/scanner/types.py` (351 lines)
- `scrubiq/scrubiq/types.py` (606 lines)

---

### 5. Three Separate Package Systems

Each package has its own:
- `pyproject.toml` with different build systems (hatchling, maturin, setuptools)
- `tests/` directory with no cross-package integration tests
- Configuration system
- Type definitions
- Entry points

**No imports between packages** - they don't share any code despite having identical functionality.

---

## HIGH SEVERITY ISSUES

### 6. Silent Exception Swallowing

Found **100+ instances** of:
```python
except Exception:
    pass
```

This hides bugs and makes debugging impossible. Examples throughout:
- `scrubiq/scrubiq/api/app.py`
- `src/openlabels/labeling/mip.py`
- `openrisk/openlabels/gui/workers/`

---

### 7. Hardcoded Dev Mode Bypasses

**File:** `src/openlabels/server/routes/auth.py:127-150`

When `AUTH_PROVIDER=none`, creates a fake admin session with full privileges:
```python
if settings.auth.provider == "none":
    session_id = _generate_session_id()
    _sessions[session_id] = {
        "access_token": "dev-token",
        "claims": {
            "preferred_username": "dev@localhost",
            "roles": ["admin"],
        },
    }
```

This should be explicitly disabled in production builds.

---

### 8. Debug Print Statements in Production Code

**File:** `src/openlabels/core/policies/engine.py:76-78`
```python
print(f"Risk: {result.risk_level}")
print(f"Categories: {result.categories}")
print(f"Requires encryption: {result.requires_encryption}")
```

Multiple `print()` statements scattered throughout the codebase that should use logging.

---

### 9. Default Host Binding to 0.0.0.0

**File:** `src/openlabels/__main__.py:29`
```python
@click.option("--host", default="0.0.0.0", help="Host to bind to")
```

**File:** `src/openlabels/server/config.py:22`
```python
host: str = "0.0.0.0"
```

Binding to all interfaces by default is dangerous. Should default to `127.0.0.1`.

---

## MEDIUM SEVERITY ISSUES

### 10. Inconsistent Error Exposure

**File:** `src/openlabels/server/app.py:60-68`
```python
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": str(exc) if get_settings().server.debug else "An unexpected error occurred",
        },
    )
```

In debug mode, full exception messages are exposed which could leak sensitive information.

---

### 11. Empty/Stub Functions

Found **120+ functions** that are just `pass` or contain only docstrings:
- `src/openlabels/__main__.py` - 9 empty group functions
- `src/openlabels/core/detectors/base.py:42` - abstract method stub
- `src/openlabels/monitoring/base.py:158-164` - empty exception classes
- Many more in GUI widgets and handlers

---

### 12. Leftover Project References

README.md still references:
- `https://github.com/chillbot-io/OpenRisk` (original repo)
- `https://github.com/chillbot-io/scrubiq` (original repo)
- `https://github.com/privplay/scrubiq` (different org!)

Multiple license inconsistencies:
- Root: MIT
- OpenRisk: Apache-2.0
- ScrubIQ: Listed as both "Proprietary" (pyproject.toml) and "MIT" (README)

---

### 13. Test Data in Production Code

**Files with test placeholders that could be mistakenly used:**
- `tests/conftest.py` fixtures used for "sample" data
- Hardcoded example SSNs: `123-45-6789`
- Hardcoded example AWS keys: `AKIAIOSFODNN7EXAMPLE`
- `example.com` email domains throughout

---

### 14. Deprecated datetime Usage

Multiple files use `datetime.utcnow()` which is deprecated in Python 3.12+:
- `src/openlabels/server/routes/auth.py` (multiple occurrences)
- `src/openlabels/jobs/queue.py` (6 occurrences)
- `src/openlabels/server/session.py` (6 occurrences)
- `src/openlabels/adapters/graph_client.py` (2 occurrences)
- `src/openlabels/auth/sid_resolver.py` (4 occurrences)
- `src/openlabels/server/routes/health.py` (4 occurrences)
- `src/openlabels/server/routes/dashboard.py` (4 occurrences)
- `src/openlabels/server/routes/remediation.py` (5 occurrences)
- And 20+ more files

**Total:** 50+ occurrences across the codebase.
- Should use `datetime.now(timezone.utc)` instead

---

### 15. Redundant Imports Inside Methods

**File:** `src/openlabels/labeling/engine.py`

```python
# Line 15: already imports asyncio at top level
import asyncio

# Lines 263, 280, 286, 323, 332: redundantly imports asyncio again inside methods
async def _get_access_token(self) -> str:
    ...
    import asyncio  # Redundant!
    await asyncio.sleep(retry_after)
```

**Issue:** The `asyncio` module is imported at the top of the file but then re-imported inside multiple methods. While not a bug, this is a code smell indicating copy-paste development.

---

## LOW SEVERITY ISSUES

### 16. Missing Type Hints

Many public functions lack proper type hints, making the code harder to maintain and verify.

### 17. Inconsistent Logging

Mix of:
- `logger.debug()` / `logger.info()` / `logger.error()`
- `print()` statements
- Silent `pass` blocks

No consistent logging strategy across the three packages.

### 18. Magic Numbers

Hardcoded values without constants:
- Session cookie max age: `60 * 60 * 24 * 7`
- PKCE expiry: `timedelta(minutes=10)`
- Various timeouts and limits

### 19. Unused Imports

Multiple files have `# noqa: F401` comments suppressing unused import warnings, suggesting code that was planned but never implemented.

---

## ARCHITECTURAL ISSUES

### 20. No Shared Core

The three packages should share:
- Base types (`Span`, `Tier`, entity types)
- Detector interfaces
- Pipeline components
- Configuration management

Instead, each package reinvents these independently.

### 21. No Integration Tests

- `tests/` - Main package tests
- `openrisk/tests/` - OpenRisk tests (separate)
- `scrubiq/tests/` - ScrubIQ tests (separate)

No tests verify the packages work together.

### 22. Mixed Async/Sync Patterns

The codebase inconsistently uses:
- `async def` functions that don't await anything
- `ThreadPoolExecutor` mixed with `asyncio`
- Blocking calls in async contexts

---

## RECOMMENDATIONS

### Immediate (Before Any Production Use)

1. **Fix CORS configuration** - Remove wildcard origins or disable credentials
2. **Implement proper session storage** - Redis or database-backed sessions
3. **Remove NotImplementedError paths** - Either implement or remove advertised features
4. **Audit exception handling** - Replace silent `pass` blocks with proper error handling
5. **Disable dev mode bypasses** - Add explicit production guards

### Short-term (Next Sprint)

6. **Create shared `openlabels-core` package** - Unify types, interfaces, utilities
7. **Deduplicate detector implementations** - Pick best version, consolidate
8. **Add integration tests** - Test cross-package interactions
9. **Fix logging** - Replace prints with proper logging, add structured logs
10. **Security audit** - Review all auth flows, input validation, output encoding

### Long-term

11. **Monorepo restructure** - Proper workspace with shared dependencies
12. **CI/CD pipeline** - Automated testing across all packages
13. **Documentation** - API docs, architecture diagrams, deployment guides
14. **Performance testing** - Load testing before production deployment

---

## FILE INVENTORY

| Location | Files | Lines | Purpose |
|----------|-------|-------|---------|
| `src/openlabels/` | 94 | ~15K | Main server, CLI, GUI |
| `openrisk/` | 185 | ~35K | Risk scanning (mostly duplicated) |
| `scrubiq/` | ~100 | ~25K | Redaction (mostly duplicated) |
| `tests/` | ~50 | ~10K | Main tests only |

**Estimated duplication:** 40-50% of code is duplicated across packages.

---

## CONCLUSION

This codebase is **not production-ready**. It's a merge of three independent projects that hasn't been properly integrated. The security issues alone would be grounds for rejection in any serious security review.

Before going to production, the team needs to:
1. Fix the critical security issues (1-3 days)
2. Implement proper session management (1-2 days)
3. Decide on a single implementation for duplicated code (1-2 weeks)
4. Add integration tests (1 week)
5. Conduct a proper security audit (ongoing)

Total estimated remediation time: **3-4 weeks** for a competent team.
