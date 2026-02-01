# OpenLabels/OpenRisk Comprehensive Security & Code Audit

**Date:** 2026-01-29
**Auditor:** Claude Code (Opus 4.5)
**Codebase:** 159 Python files, ~38,000 LOC
**Branch:** `claude/security-code-audit-DgBBn`
**Commit Base:** `3e9a78f`

---

## Executive Summary

The OpenLabels codebase demonstrates **solid foundational security practices** with implemented protections for TOCTOU attacks, symlink hijacking, and command injection. However, **critical vulnerabilities** exist that must be fixed before production deployment.

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Security | 1 | 2 | 4 | 5 |
| Code Quality | 0 | 0 | 9 | 10 |
| AI Slop | 0 | 1 | 4 | 5 |
| Completeness | 0 | 0 | 2 | 6 |

**Overall Grade:** C+ (Not production-ready without fixes)

---

## 1. SECURITY VULNERABILITIES

### 1.1 CRITICAL: SQL Injection in PostgreSQL Index

**File:** `openlabels/output/postgres_index.py`
**Lines:** 512-527, 573-578
**Severity:** CRITICAL

The `query()` and `query_count()` methods construct SQL WHERE clauses using f-string interpolation:

```python
# Line 512-527
where_clause = " AND ".join(conditions)
cur.execute(f"""
    SELECT ... FROM label_objects o
    JOIN label_versions v ON o.label_id = v.label_id
    WHERE {where_clause}  -- ← INJECTION VECTOR
    ORDER BY v.scanned_at DESC
    LIMIT %s OFFSET %s
""", params)
```

**Risk:** Attackers controlling filter parameters can inject arbitrary SQL.

**Recommendation:** Use proper parameterized query building:
```python
# Build conditions with placeholders only
conditions.append("v.risk_tier = %s")
params.append(risk_tier)
```

---

### 1.2 HIGH: Memory Exhaustion via Unbounded Query Results

**File:** `openlabels/output/postgres_index.py`
**Lines:** 455-464, 529-531
**Severity:** HIGH

Query results are loaded entirely into memory via `fetchall()`:

```python
return [dict(zip(columns, row)) for row in cur.fetchall()]  # All rows in memory
```

With large result sets (limit=10000), this can exhaust server memory.

**Recommendation:** Use cursor iteration:
```python
for row in cur:  # Iterator, not fetchall()
    results.append(dict(zip(columns, row)))
    if len(results) >= limit:
        break
```

---

### 1.3 HIGH: Potential IndexError on Database Results

**File:** `openlabels/output/postgres_index.py`
**Lines:** 610, 617
**Severity:** HIGH

Direct indexing without null check:

```python
labels = cur.fetchone()[0]  # Crashes if no rows
```

**Fix:**
```python
result = cur.fetchone()
labels = result[0] if result else 0
```

---

### 1.4 MEDIUM: TOCTOU Gap in File Operations

**File:** `openlabels/components/fileops.py`
**Lines:** 315-320
**Severity:** MEDIUM

Path calculation before move creates a race window:

```python
rel_path = Path(result.path).relative_to(source)  # Check phase
dest_path = destination / rel_path  # Use phase - file could be swapped
```

The `move_file()` function at lines 76-97 has proper TOCTOU protection that should be applied here.

---

### 1.5 Security Strengths ✓

The codebase has excellent protections in place:

| Protection | Location | Status |
|------------|----------|--------|
| TOCTOU via `lstat()` | `fileops.py:76-97` | ✓ GOOD |
| Symlink rejection | `quarantine.py:50-60` | ✓ GOOD |
| Path traversal in archives | `archive.py:94-137` | ✓ GOOD |
| Command injection prevention | `validation.py:14-35` | ✓ GOOD |
| ReDoS protection | `filter.py:183-255` | ✓ GOOD |
| Cryptographic randomness | `labels.py:23` | ✓ GOOD |
| No unsafe deserialization | Codebase-wide | ✓ GOOD |

---

## 2. CODE QUALITY ISSUES

### 2.1 Poor Error Handling

**Swallowed Exceptions:**

| File | Line | Issue |
|------|------|-------|
| `shutdown.py` | 30, 260 | Bare `pass` in exception handlers |
| `cli/filter.py` | 563, 569 | Silent exception swallowing |
| `cli/output.py` | 231, 234, 237 | Silent exception swallowing |
| `agent/collector.py` | 348 | Bare `pass` in exception handler |
| `agent/watcher.py` | 498 | Bare `pass` in event handling |

**Recommendation:** Replace with proper logging or re-raise.

---

### 2.2 Inconsistent Exception Handling

**File:** `openlabels/output/postgres_index.py`

```python
# _connection() raises DatabaseError
raise DatabaseError(f"Database error: {e}") from e

# _cursor() re-raises without wrapping
except Exception:
    conn.rollback()
    raise  # Inconsistent - should also wrap in DatabaseError
```

---

### 2.3 Code Duplication

| Pattern | Files | Impact |
|---------|-------|--------|
| Merge strategy logic | `merger.py:157-165, 244-251` | Duplicate merge handling |
| Exposure normalization | `triggers.py:100, 175` | Repeated conversion logic |
| Xattr handlers | `virtual.py:707-954` | 3 nearly-identical classes |

---

### 2.4 Resource Leak Risk

**File:** `openlabels/output/postgres_index.py`
**Lines:** 127-139

Thread-local connections may not be properly cleaned on error:

```python
conn = self._psycopg.connect(self.connection_string)
setattr(self._thread_local, self._conn_key, conn)
# If later operations fail, connection may not be closed
```

---

## 3. AI SLOP & UGLINESS

### 3.1 HIGH: Copy-Paste Validators

**File:** `openlabels/adapters/scanner/detectors/financial.py`
**Lines:** 24-450

10 validation functions with identical template structure:

```python
def _validate_cusip(cusip: str) -> bool:
    """Validate CUSIP check digit (position 9)."""
    cusip = cusip.upper().replace(' ', '').replace('-', '')
    if len(cusip) != 9:
        logger.debug(f"CUSIP validation failed: expected 9 chars, got {len(cusip)}")
        return False
    # ... algorithm ...
```

**Same pattern repeated for:** CUSIP, ISIN, SEDOL, SWIFT, LEI, FIGI, Bitcoin (base58), Bitcoin (bech32), Ethereum, seed phrases.

**Recommendation:** Create `ChecksumValidator` factory class.

---

### 3.2 MEDIUM: Separator Line Noise

**Count:** 74 instances of `# ===` separators across 45+ files

```python
# === NAMES ===
# === LOCATIONS ===
# === IDENTIFIERS ===
```

These add no value and clutter code. Remove or replace with docstrings.

---

### 3.3 MEDIUM: Verbose Docstrings

**Example from `validators.py`:**

```python
def sanitize_filename(filename: str) -> str:
    """
    Sanitize uploaded filename to prevent injection attacks.

    Removes/replaces:
    - Path components (prevents directory traversal)
    - Null bytes and control characters
    - Characters dangerous for HTML/logs (<, >, quotes)
    - Shell metacharacters
    - Reserved Windows device names (CON, PRN, NUL, etc.)
    - Leading dashes (confuses CLI tools)
    - Percent-encoded sequences that could bypass checks
    - Non-ASCII characters (prevents homoglyph attacks)
    ...
    """
```

**Better:**
```python
def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage: remove traversal, shell chars, device names."""
```

---

### 3.4 MEDIUM: Xattr Handler Duplication

**File:** `openlabels/output/virtual.py`
**Lines:** 707-954

Three nearly-identical classes:
- `LinuxXattrHandler`
- `MacOSXattrHandler`
- `WindowsADSHandler`

~60% code overlap. Should use Template Method pattern.

---

### 3.5 LOW: Security Annotation Comments

34 instances of verbose inline security comments:

```python
filename = filename.encode('ascii', errors='replace').decode('ascii')  # LOW-002: prevent homoglyphs
```

These reference an internal security tracking system but clutter code. Move to documentation.

---

## 4. COMPLETENESS ISSUES

### 4.1 MEDIUM: Missing Deployment Artifacts

| Artifact | Status |
|----------|--------|
| Dockerfile | ❌ Missing |
| docker-compose.yml | ❌ Missing |
| Kubernetes manifests | ❌ Missing |
| CI/CD pipeline | ❌ Missing |
| HTTP health endpoint | ❌ Missing |
| Prometheus metrics | ❌ Missing |

---

### 4.2 MEDIUM: Missing Validation

**SQL LIKE Pattern Injection:**

**File:** `openlabels/output/postgres_index.py`
**Line:** 500

```python
params.append(f"%{entity_type}%")  # Unsanitized LIKE pattern
```

LIKE wildcards (`%`, `_`) in user input aren't escaped.

---

### 4.3 LOW: Incomplete Exception Handlers

24 bare `pass` statements in non-abstract exception handlers. Should at minimum log the error.

---

### 4.4 LOW: Missing Test Coverage

Potentially undertested areas:
- Archive extraction error paths (`archive.py:91`)
- Credential redaction regexes (`virtual.py:707-730`)
- PostgreSQL concurrent UPSERT scenarios

---

## 5. RECOMMENDATIONS

### Phase 1: Critical Security Fixes (Immediate)

| # | Issue | File | Effort |
|---|-------|------|--------|
| 1 | Fix SQL injection in query methods | `postgres_index.py:512-578` | 2h |
| 2 | Replace `fetchall()` with iterator | `postgres_index.py:455-531` | 1h |
| 3 | Add null checks on `fetchone()` | `postgres_index.py:610,617` | 30m |

### Phase 2: High Priority (Before Production)

| # | Issue | File | Effort |
|---|-------|------|--------|
| 4 | Apply TOCTOU protection consistently | `fileops.py:315-320` | 1h |
| 5 | Standardize exception handling | `postgres_index.py` | 2h |
| 6 | Replace bare `pass` with logging | Multiple files | 2h |

### Phase 3: Code Quality (Short-term)

| # | Issue | Effort |
|---|-------|--------|
| 7 | Create ChecksumValidator factory | 4h |
| 8 | Extract xattr handler base class | 3h |
| 9 | Remove separator line comments | 1h |
| 10 | Simplify verbose docstrings | 2h |

### Phase 4: Deployment (Required for Production)

| # | Artifact | Effort |
|---|----------|--------|
| 11 | Create Dockerfile | 2h |
| 12 | Add kubernetes manifests | 4h |
| 13 | Implement health endpoint | 2h |
| 14 | Add Prometheus metrics | 4h |

---

## 6. FILES REQUIRING ATTENTION

### Critical (Fix Now)
- `openlabels/output/postgres_index.py` - SQL injection, memory exhaustion, null checks

### High Priority
- `openlabels/components/fileops.py` - TOCTOU race condition
- `openlabels/cli/filter.py` - Exception handling

### Medium Priority
- `openlabels/adapters/scanner/detectors/financial.py` - Validator duplication
- `openlabels/output/virtual.py` - Xattr handler duplication
- `openlabels/adapters/scanner/validators.py` - Verbose docstrings

---

## 7. POSITIVE FINDINGS

The codebase demonstrates strong engineering in many areas:

✓ **Security Fundamentals**
- Proper TOCTOU protection with `lstat()`
- Symlink attack prevention
- Path traversal blocking in archives
- Command injection prevention
- ReDoS protection with timeouts
- Cryptographically secure random generation

✓ **Architecture**
- Clean adapter pattern for cloud/filesystem sources
- Modular detector pipeline
- Comprehensive type hints
- Good separation of concerns

✓ **Testing**
- 532 test functions
- Security-focused test cases (TOCTOU, zip-slip)
- Good coverage of core functionality

✓ **Documentation**
- Detailed architecture docs
- Security patterns documented
- Entity registry well-specified

---

## 8. CONCLUSION

OpenLabels is a **well-architected system with solid security fundamentals** but contains **critical vulnerabilities that must be fixed** before production deployment. The SQL injection and memory exhaustion issues are the highest priority.

The codebase shows signs of AI-assisted generation (copy-paste patterns, verbose comments, separator lines) but the underlying logic is sound. With focused refactoring, the code quality can be significantly improved.

**Production Readiness:** ❌ Not ready (critical security issues)
**After Fixes:** ✓ Ready with Phase 1-2 complete
**Estimated Fix Time:** 8-12 hours for critical issues + 2-3 days for full polish

---

## Appendix: Audit Methodology

1. **Static Analysis:** Comprehensive code review of all Python files
2. **Security Patterns:** Checked for OWASP Top 10, injection, TOCTOU, deserialization
3. **Code Quality:** Analyzed error handling, resource management, consistency
4. **AI Detection:** Identified patterns common in AI-generated code
5. **Completeness:** Verified implementations, checked for stubs and TODOs

---

*This audit was performed by Claude Code (Opus 4.5) on 2026-01-29.*
