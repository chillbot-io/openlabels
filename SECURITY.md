# Security Patterns

This document explains the security patterns used throughout the OpenLabels codebase.

## TOCTOU Race Condition Prevention

**Pattern ID:** TOCTOU-001

Time-of-check to time-of-use (TOCTOU) vulnerabilities occur when file state is checked, then used later - allowing an attacker to swap the file between check and use.

**Vulnerable pattern:**
```python
if path.is_file():      # Check
    process(path)        # Use - file could be swapped to symlink!
```

**Safe pattern:**
```python
st = path.lstat()                    # Atomic stat, no symlink follow
if stat.S_ISREG(st.st_mode):         # Check mode from same stat call
    process(path)                     # Use - consistent with check
```

**Key points:**
- Use `lstat()` instead of `stat()`, `exists()`, `is_file()`, `is_dir()`, `is_symlink()`
- `lstat()` never follows symlinks
- Check `S_ISREG()` for regular files, `S_ISDIR()` for directories
- Reject symlinks with `S_ISLNK()` check

## Symlink Attack Prevention

**Pattern ID:** HIGH-002

Symlinks can be used to trick the application into reading/writing unintended files.

**Safe pattern:**
```python
st = path.lstat()
if stat.S_ISLNK(st.st_mode):
    raise SecurityError("Symlinks not allowed")
```

## Memory Exhaustion Prevention

**Pattern ID:** HIGH-004, HIGH-008, HIGH-009, CVE-READY-004

Unbounded data structures can cause out-of-memory crashes.

**Patterns:**
- Use cursor iteration instead of `fetchall()` for database queries
- Set `maxsize` on queues to bound memory usage
- Limit matches per search term in detectors
- Limit stdin read size

## ReDoS Protection

**Pattern ID:** CVE-READY-003

Regular expression denial of service via catastrophic backtracking.

**Safe pattern:**
```python
import regex  # Not re - regex module supports timeout
regex.search(pattern, text, timeout=1.0)
```

## Input Validation

**Pattern ID:** LOW-002

Filename sanitization to prevent injection attacks:
- Remove path components (directory traversal)
- Decode percent-encoded sequences
- Replace non-ASCII (homoglyph attacks)
- Remove shell metacharacters
- Block Windows reserved names (CON, PRN, NUL, etc.)
- Remove leading dashes (CLI injection)

## Resource Cleanup

**Pattern ID:** MED-006

Always close file handles and PIL images in finally blocks:
```python
img = Image.open(path)
try:
    process(img)
finally:
    img.close()
```

## Extended Attribute Limits

**Pattern ID:** LOW-006

Validate xattr names and values before reading:
- Maximum attribute name length
- Maximum attribute value size
- Maximum number of attributes to collect

## Thread Safety

**Pattern ID:** HIGH-001, LOW-007, MED-009

Use thread-safe primitives:
- `threading.Event` for stop flags (not boolean)
- Lock around shared state access
- Thread-local connections for SQLite

## Type Normalization

**Pattern ID:** LOW-003

Normalize entity types to uppercase for consistent comparison:
```python
entity_type = entity_type.upper()
```

## Timing Attack Prevention

**Pattern ID:** CVE-READY-005

Use constant-time comparison for security-sensitive values:
```python
import hmac
hmac.compare_digest(a, b)  # Not a == b
```

## Error Handling Without Information Leak

Never log actual sensitive values (PHI, credentials):
```python
logger.info(f"Detected {entity_type} at position {start}")  # OK
logger.info(f"Found SSN: {value}")  # NEVER - leaks PHI
```
