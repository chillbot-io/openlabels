# OpenRisk Security Red Team Assessment Report

**Date:** 2026-01-27
**Auditor:** Automated Security Analysis
**Scope:** Full codebase security review
**Version Analyzed:** v0.1.0 (Alpha)

---

## Executive Summary

This report presents findings from a comprehensive red team security assessment of the OpenRisk/OpenLabels codebase. The assessment covered:

- Input validation and boundary conditions
- Injection vulnerabilities (SQL, command, path traversal)
- Regular expression denial of service (ReDoS)
- Race conditions and TOCTOU vulnerabilities
- Deserialization and type confusion
- Secrets and credential exposure
- Dependency security
- Resource exhaustion / DoS vectors
- Cryptographic implementations

### Risk Summary

| Severity | Count | Description |
|----------|-------|-------------|
| **CRITICAL** | 5 | Immediate action required |
| **HIGH** | 14 | Address before production |
| **MEDIUM** | 12 | Address in next sprint |
| **LOW** | 8 | Backlog items |

### Overall Assessment: **MEDIUM-HIGH RISK**

The codebase shows strong security awareness with comprehensive input validation, parameterized SQL queries, and safe subprocess usage. However, several critical vulnerabilities exist around race conditions, resource exhaustion, and incomplete security implementations.

---

## Critical Vulnerabilities (P0)

### CVE-READY-001: Unbounded stdin Read - Memory Exhaustion
**File:** `openlabels/cli/main.py:90`
**Type:** CWE-400 Uncontrolled Resource Consumption

```python
if text == "-":
    text = sys.stdin.read()  # NO SIZE LIMIT
```

**Impact:** Denial of service via memory exhaustion. An attacker can pipe unlimited data to crash the process.

**Recommendation:**
```python
MAX_STDIN_SIZE = 10 * 1024 * 1024  # 10MB
text = sys.stdin.read(MAX_STDIN_SIZE + 1)
if len(text) > MAX_STDIN_SIZE:
    raise ValueError("Input exceeds maximum size")
```

---

### CVE-READY-002: TOCTOU Race Conditions in File Operations
**Files:**
- `openlabels/components/fileops.py:386-399`
- `openlabels/components/fileops.py:188-252`
- `openlabels/cli/commands/quarantine.py:36-52`

**Type:** CWE-367 Time-of-check Time-of-use Race Condition

```python
if not source.exists():  # CHECK
    return OperationResult(...)
# ... 13 lines of code ...
shutil.move(str(source), str(destination))  # USE
```

**Impact:** An attacker can exploit the race window to:
- Replace source file with symlink to sensitive file
- Delete file causing operation to fail inconsistently
- Perform privilege escalation via symlink attacks

**Recommendation:** Use atomic operations, handle errors gracefully, avoid existence checks:
```python
try:
    os.replace(source, destination)  # Atomic on same filesystem
except FileNotFoundError:
    return OperationResult(success=False, ...)
```

---

### CVE-READY-003: ReDoS Timeout Not Actually Enforced
**File:** `openlabels/cli/filter.py:181-253`
**Type:** CWE-1333 Inefficient Regular Expression Complexity

```python
def _safe_regex_match(self, pattern: str, text: str, timeout_ms: int = 100):
    # ... timeout_ms parameter exists but is NOT enforced when 'regex' module unavailable
    try:
        import regex
        # timeout works here
    except ImportError:
        # FALLS BACK TO STANDARD 're' WITH NO TIMEOUT!
        return bool(re.search(pattern, text, re.IGNORECASE))
```

**Impact:** User-controlled regex patterns can cause ReDoS, hanging the process indefinitely.

**Recommendation:**
1. Make `regex` package a required dependency (not optional)
2. Or implement signal-based timeout for standard `re` module
3. Reject patterns without the optional package

---

### CVE-READY-004: Unbounded Event Queue - Memory Exhaustion
**File:** `openlabels/agent/watcher.py:472`
**Type:** CWE-770 Allocation of Resources Without Limits

```python
event_queue: queue.Queue = queue.Queue()  # No maxsize!
```

**Impact:** Rapid file system changes can fill the queue unboundedly, causing OOM crash.

**Recommendation:**
```python
event_queue: queue.Queue = queue.Queue(maxsize=10000)
```

---

### CVE-READY-005: Timing Attack in Cryptographic Comparison
**File:** `openlabels/adapters/scanner/detectors/financial.py:335`
**Type:** CWE-208 Observable Timing Discrepancy

```python
return hash2[:4] == checksum  # Non-constant-time comparison
```

**Impact:** Timing side-channel can leak checksum bytes, enabling forgery of Bitcoin addresses in validation context.

**Recommendation:**
```python
import secrets
return secrets.compare_digest(hash2[:4], checksum)
```

---

## High Severity Vulnerabilities (P1)

### HIGH-001: Lock-Free Shared State in FileWatcher
**File:** `openlabels/agent/watcher.py:170,191,209,230`

The `_running` flag is accessed from multiple threads without synchronization, causing potential race conditions and inconsistent state.

**Recommendation:** Use `threading.Event()` instead of boolean flag.

---

### HIGH-002: Symlink Following in shutil.move()
**Files:** `openlabels/components/fileops.py:252`, `openlabels/cli/commands/quarantine.py:51`

`shutil.move()` follows symlinks by default, allowing symlink attacks.

**Recommendation:** Validate files are not symlinks before operations, or use `os.rename()` for same-filesystem moves.

---

### HIGH-003: CSV Reading Without Row Limits
**File:** `openlabels/adapters/scanner/extractors/office.py:132-156`

CSV files are read without row limits, unlike XLSX which has `MAX_SPREADSHEET_ROWS`.

**Recommendation:** Add row limit check matching XLSX behavior.

---

### HIGH-004: Database Export Without Pagination
**File:** `openlabels/output/index.py:630-642`

`fetchall()` loads entire result set into memory, causing OOM for large datasets.

**Recommendation:** Use cursor iteration or LIMIT/OFFSET pagination.

---

### HIGH-005: Decompression Bomb Warning Only
**File:** `openlabels/adapters/scanner/extractors/office.py:202-208`

High extraction ratio only logs warning but continues processing.

**Recommendation:** Raise exception for ratios exceeding safe threshold.

---

### HIGH-006: Type Confusion via setattr()
**Files:**
- `openlabels/adapters/scanner/scanner_adapter.py:73`
- `openlabels/adapters/scanner/adapter.py:214`

User-supplied kwargs bypass `__post_init__()` validation when set via `setattr()`.

**Recommendation:** Re-run validation after dynamic attribute assignment.

---

### HIGH-007: Missing File Size Check Before Read
**File:** `openlabels/adapters/scanner/adapter.py:140`

```python
path.read_bytes()  # No size validation
```

Config has `max_file_size` but it's not enforced before reading.

**Recommendation:** Check `path.stat().st_size` against `config.max_file_size` before reading.

---

### HIGH-008: Unbounded Span Creation in Dictionary Detection
**File:** `openlabels/adapters/scanner/detectors/dictionaries.py:349-370`

No limit on number of matches created, allowing memory exhaustion with repetitive input.

**Recommendation:** Add `MAX_MATCHES_PER_TERM` limit.

---

### HIGH-009: Unbounded Span Creation in Orchestrator
**File:** `openlabels/adapters/scanner/detectors/orchestrator.py:534-560`

Same issue as dictionary detection - no match limits.

---

### HIGH-010: PollingWatcher TOCTOU - Type Check Race
**File:** `openlabels/agent/watcher.py:624-635`

`is_file()` check followed by `stat()` and `_quick_hash()` creates race window for type confusion.

---

### HIGH-011: PollingWatcher Double Stat Race
**File:** `openlabels/agent/watcher.py:654-665`

File size obtained via `stat()` but file opened separately - content could change.

---

### HIGH-012: Module-Level List Without Lock
**File:** `openlabels/adapters/scanner/temp_storage.py:26-124`

`_active_temp_dirs` accessed from multiple threads without synchronization.

**Recommendation:** Wrap with `threading.Lock()`.

---

### HIGH-013: Permission Functions Return Stale Data
**Files:** `openlabels/agent/ntfs.py:154-246`, `openlabels/agent/posix.py:127-180`

Permission checks become stale by time of actual file access - classic TOCTOU.

---

### HIGH-014: Undeclared Dependencies
**Packages not in pyproject.toml:**
- `intervaltree` (required for OCR)
- `xlrd` (used for XLS)
- `striprtf` (used for RTF)

Users installing from pyproject.toml get missing dependency errors.

---

## Medium Severity Vulnerabilities (P2)

### MED-001: Optional 'regex' Package for Security
The ReDoS timeout protection requires `regex` package which is optional. Default install has no protection.

### MED-002: Version Constraints Too Loose
All dependencies use `>=` only, allowing major version upgrades with breaking changes.

### MED-003: Known CVEs in Dependencies
- PyMuPDF: CVE-2024-29054 (path traversal)
- Pillow: CVE-2024-28219 (heap buffer overflow)

### MED-004: Incomplete JSON Validation in LabelSet
No type checking on deserialized values before use.

### MED-005: Concurrent Dictionary Access Race
`_pending_events` dict iteration/deletion race in watcher.

### MED-006: PIL Image Objects Not Closed
Image files opened without explicit close in extractors.

### MED-007: Non-Constant-Time Checksum Comparisons
Multiple instances in `checksum.py` validation functions.

### MED-008: Negative Index Calculation
`dictionaries.py:321` - `start_idx` calculation can produce negative values.

### MED-009: Queue Status Inconsistent Locking
`_status` field sometimes accessed with lock, sometimes without.

### MED-010: Seek Error Handling
No validation of `f.seek()` success before reading in hashing functions.

### MED-011: Insecure Random for Sampling
Using `random` module instead of `secrets` (acceptable for non-security context but worth noting).

### MED-012: Transitive Dependencies Unmanaged
onnxruntime brings in protobuf, flatbuffers - not explicitly declared.

---

## Low Severity Issues (P3)

### LOW-001: Git Remote URL Contains Username
**File:** `.git/config` - `local_proxy` username in URL.

### LOW-002: Filename Sanitization Could Be Stricter
Current implementation is good but could be more restrictive.

### LOW-003: Entity Type Normalization Inconsistent
Some code normalizes to uppercase, some to lowercase.

### LOW-004: Detector Failures Don't Propagate
Individual detector exceptions logged but don't fail scan.

### LOW-005: Timeout Handling Can't Kill Threads
Python threads can't be forcibly killed - only cancelled gracefully.

### LOW-006: Extended Attribute Reads Not Validated
Writes are validated but reads accept any attribute.

### LOW-007: Polling Watcher Sleep Ignores Stop
`_running` flag change not noticed during `time.sleep()`.

### LOW-008: Context Singleton Leakage
`get_default_context()` creates process-wide singleton, causing state leaks.

---

## Security Strengths

The codebase demonstrates several security best practices:

1. **SQL Injection Prevention:** All queries use parameterized statements
2. **Command Injection Prevention:** All subprocess calls use list arguments, no `shell=True`
3. **Path Traversal Protection:** Comprehensive validation against forbidden paths
4. **File Type Validation:** Magic byte verification prevents spoofing
5. **Filename Sanitization:** Removes dangerous characters and path components
6. **Strong Hash Algorithms:** Uses SHA-256 and BLAKE2b appropriately
7. **Secure Token Generation:** Uses `secrets` module for label IDs
8. **Input Length Limits:** Many operations have size bounds
9. **Comprehensive Exception Hierarchy:** Clear distinction between error types
10. **No Pickle/YAML Vulnerabilities:** Avoids dangerous deserialization

---

## Recommended Remediation Roadmap

### Immediate (Before Any Production Use)
1. Fix unbounded stdin read (CVE-READY-001)
2. Add maxsize to event queue (CVE-READY-004)
3. Enforce file size limits before reading
4. Make `regex` package required, not optional
5. Fix timing attack in Bitcoin validation

### Short-Term (Next 2 Sprints)
1. Refactor file operations to avoid TOCTOU patterns
2. Add thread synchronization for shared state
3. Implement span/match limits in detectors
4. Add database query pagination
5. Declare all dependencies properly
6. Pin dependency versions with upper bounds

### Medium-Term (Next Quarter)
1. Add comprehensive security test suite
2. Implement `pip-audit` in CI/CD
3. Create lock file for reproducible builds
4. Document security assumptions
5. Add pre-commit hooks for secret scanning
6. Consider async/await for better timeout control

### Ongoing
1. Regular dependency updates
2. Security-focused code reviews
3. Periodic penetration testing
4. Monitor CVE databases for dependencies

---

## Appendix: Files Requiring Immediate Attention

| Priority | File | Issue |
|----------|------|-------|
| P0 | `openlabels/cli/main.py` | Unbounded stdin |
| P0 | `openlabels/agent/watcher.py` | Queue size, races |
| P0 | `openlabels/cli/filter.py` | ReDoS timeout |
| P0 | `openlabels/components/fileops.py` | TOCTOU races |
| P1 | `openlabels/adapters/scanner/adapter.py` | Size limits |
| P1 | `openlabels/adapters/scanner/detectors/dictionaries.py` | Match limits |
| P1 | `openlabels/adapters/scanner/detectors/orchestrator.py` | Match limits |
| P1 | `openlabels/adapters/scanner/detectors/financial.py` | Timing attack |
| P1 | `openlabels/output/index.py` | Pagination |
| P1 | `pyproject.toml` | Dependencies |

---

## Conclusion

OpenRisk demonstrates security-conscious development with many defensive measures in place. However, several critical vulnerabilities exist that must be addressed before production deployment. The most pressing concerns are:

1. **Resource exhaustion vectors** that could enable DoS attacks
2. **Race conditions** in file operations that could enable privilege escalation
3. **Incomplete security implementations** (ReDoS timeout not enforced)

With focused remediation of the critical and high-severity issues, the security posture can be significantly improved. The existing codebase provides a solid foundation with its comprehensive input validation and safe API usage patterns.

---

*This report was generated as part of a security red team exercise. All vulnerabilities should be verified and remediated according to your organization's security policies.*
