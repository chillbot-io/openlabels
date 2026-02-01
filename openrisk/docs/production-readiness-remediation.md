# Production Readiness Remediation Plan

**Created:** 2026-01-27
**Source:** PRODUCTION_READINESS_REVIEW.md
**Purpose:** Guide systematic remediation of production readiness issues

---

## Overview

This document provides a structured remediation plan for the 29 issues identified in the Production Readiness Review. Issues are organized into 6 phases based on:

1. **Risk/Impact Priority** - Critical safety issues first
2. **Dependencies** - Foundational fixes before dependent ones
3. **Logical Grouping** - Related changes together for coherent PRs
4. **Complexity** - Quick wins early to build momentum

Each phase includes the issue description, exact file locations, the problem, and implementation guidance.

---

## Phase 1: Critical Input Validation & Safety

**Goal:** Prevent catastrophic failures (OOM, DoS) from adversarial input
**Priority:** IMMEDIATE - These can cause production outages

### Issue 1.1: No Size Limits on Text Input

**Location:** `openlabels/adapters/scanner/adapter.py:54-106`

**Problem:** The `Detector.detect(text)` method accepts arbitrarily large text input. An adversarial multi-gigabyte string would be processed, causing OOM.

**Fix:**
```python
# In Detector.detect() method, add at the start:
MAX_TEXT_SIZE = 10 * 1024 * 1024  # 10 MB default, make configurable

def detect(self, text: str, ...) -> DetectionResult:
    if len(text) > MAX_TEXT_SIZE:
        raise ValueError(f"Text input exceeds maximum size of {MAX_TEXT_SIZE} bytes")
    # ... existing code
```

**Considerations:**
- Make the limit configurable via Config class
- Consider returning a structured error instead of raising
- Add to config.py: `max_text_size: int = 10 * 1024 * 1024`

---

### Issue 1.2: File Content Read Without Size Check

**Location:** `openlabels/adapters/scanner/adapter.py:140`

**Problem:** `path.read_bytes()` reads entire file into memory. The config has `max_file_size` but it's not enforced before reading.

**Current Code:**
```python
content = path.read_bytes()
```

**Fix:**
```python
# Check file size BEFORE reading
file_size = path.stat().st_size
if file_size > self.config.max_file_size:
    raise ValueError(f"File size {file_size} exceeds limit {self.config.max_file_size}")
content = path.read_bytes()
```

**Considerations:**
- The config already has `max_file_size` - just need to enforce it
- This is a one-line addition
- Consider returning a structured error with the file path

---

### Issue 1.3: ReDoS Timeout Not Enforced

**Location:** `openlabels/cli/filter.py:172-194`

**Problem:** The `_safe_regex_match` function has a `timeout_ms: int = 100` parameter that is completely ignored. No actual timeout enforcement exists.

**Current Code:**
```python
def _safe_regex_match(pattern: str, text: str, timeout_ms: int = 100) -> bool:
    # timeout_ms is never used!
    if len(pattern) > 500:
        return False
    # ... pattern checking but no timeout
    return bool(re.search(pattern, text))
```

**Fix Options:**

**Option A: Use regex module with timeout (recommended)**
```python
import regex  # pip install regex - supports timeout

def _safe_regex_match(pattern: str, text: str, timeout_ms: int = 100) -> bool:
    if len(pattern) > 500:
        return False
    # ... existing pattern safety checks ...
    try:
        return bool(regex.search(pattern, text, timeout=timeout_ms/1000))
    except regex.error:
        return False
    except TimeoutError:
        logger.warning(f"Regex match timed out after {timeout_ms}ms")
        return False
```

**Option B: Use multiprocessing with timeout (heavier)**
```python
from multiprocessing import Process, Queue

def _safe_regex_match(pattern: str, text: str, timeout_ms: int = 100) -> bool:
    # Run regex in subprocess with timeout
    # More overhead but works with standard library
```

**Option C: Use signal-based timeout (Unix only)**
```python
import signal

def _safe_regex_match(pattern: str, text: str, timeout_ms: int = 100) -> bool:
    def handler(signum, frame):
        raise TimeoutError()

    signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, timeout_ms / 1000)
    try:
        result = bool(re.search(pattern, text))
    except TimeoutError:
        result = False
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    return result
```

**Recommendation:** Option A with the `regex` module is cleanest and cross-platform.

---

### Issue 1.4: No Validation on Cloud URI Parsing

**Location:** `openlabels/output/virtual.py:601-620`

**Problem:** Cloud URIs are parsed by simple string splitting without validation. A crafted URI like `s3://bucket/../../etc/passwd` passes through.

**Current Code:**
```python
if uri.startswith('s3://'):
    parts = uri[5:].split('/', 1)
    bucket, key = parts[0], parts[1] if len(parts) > 1 else ''
```

**Fix:**
```python
import re

# Valid bucket name pattern (AWS S3 rules)
BUCKET_PATTERN = re.compile(r'^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$')
# Key cannot contain path traversal
KEY_FORBIDDEN = re.compile(r'(^|/)\.\.(/|$)')

def _parse_cloud_uri(uri: str) -> tuple[str, str, str]:
    """Parse and validate cloud URI. Returns (provider, bucket, key)."""
    if uri.startswith('s3://'):
        parts = uri[5:].split('/', 1)
        bucket = parts[0]
        key = parts[1] if len(parts) > 1 else ''

        if not BUCKET_PATTERN.match(bucket):
            raise ValueError(f"Invalid S3 bucket name: {bucket}")
        if KEY_FORBIDDEN.search(key):
            raise ValueError(f"Invalid S3 key (path traversal detected): {key}")

        return ('s3', bucket, key)
    # ... similar for gs:// and azure://
```

**Considerations:**
- Add validation for GCS and Azure URIs as well
- Consider using a URI parsing library
- Add unit tests for path traversal attempts

---

## Phase 2: Data Integrity & Transaction Safety

**Goal:** Prevent corruption and inconsistent state under crashes or concurrent use
**Priority:** HIGH - Data integrity issues are hard to recover from

### Issue 2.1: SQLite Operations Not Wrapped in Transactions

**Location:** `openlabels/output/index.py:165-221`

**Problem:** Multiple `execute()` calls before `commit()`. If process crashes between them, database is inconsistent. No explicit `BEGIN TRANSACTION`.

**Current Code:**
```python
with self._get_connection() as conn:
    conn.execute(...)
    conn.execute(...)
    conn.execute(...)
    conn.commit()
```

**Fix:**
```python
with self._get_connection() as conn:
    conn.execute("BEGIN IMMEDIATE")  # Explicit transaction with write lock
    try:
        conn.execute(...)
        conn.execute(...)
        conn.execute(...)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
```

**Alternative - Context Manager:**
```python
from contextlib import contextmanager

@contextmanager
def _transaction(self, conn):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise

# Usage:
with self._get_connection() as conn:
    with self._transaction(conn):
        conn.execute(...)
```

**Considerations:**
- Use `BEGIN IMMEDIATE` for write transactions to avoid deadlocks
- Add the transaction helper as a method on LabelIndex
- Apply to all multi-statement operations

---

### Issue 2.2: File Operations Not Idempotent

**Location:** `openlabels/components/fileops.py:128`

**Problem:** `shutil.move()` for quarantine is not idempotent. If operation fails partway and is retried, already-moved files cause errors.

**Current Code:**
```python
shutil.move(result.path, dest_path)
```

**Fix - Use Manifest Files:**
```python
def _quarantine_file(self, source: Path, dest: Path) -> bool:
    """Idempotent quarantine using manifest tracking."""
    manifest_path = dest.parent / ".quarantine_manifest.json"

    # Check if already processed
    if dest.exists():
        # Verify it's the same file by hash
        if self._files_match(source, dest):
            return True  # Already done
        else:
            raise FileExistsError(f"Different file exists at {dest}")

    # Check if source was already moved (retry scenario)
    if not source.exists():
        manifest = self._load_manifest(manifest_path)
        if str(source) in manifest.get('processed', []):
            return True  # Already processed in previous attempt
        raise FileNotFoundError(f"Source missing and not in manifest: {source}")

    # Perform move
    shutil.move(source, dest)

    # Record in manifest
    self._update_manifest(manifest_path, source)
    return True
```

**Alternative - Content Hash Tracking:**
```python
def _quarantine_file(self, source: Path, dest: Path) -> bool:
    """Use content hash to detect already-processed files."""
    source_hash = self._hash_file(source) if source.exists() else None

    if dest.exists():
        dest_hash = self._hash_file(dest)
        if source_hash == dest_hash or source_hash is None:
            return True  # Same file or source already moved

    if not source.exists():
        raise FileNotFoundError(source)

    shutil.move(source, dest)
    return True
```

---

### Issue 2.3: No Protection Against Concurrent File Modification

**Location:** `openlabels/components/scanner.py:188-224`

**Problem:** Between detecting content and recording metadata, the file could be modified. No file locking or content-hash verification.

**Current Code:**
```python
detection_result = detect_file(path)
# ... file could change here ...
stat = path.stat()
```

**Fix - Hash Verification:**
```python
import hashlib

def _scan_file(self, path: Path) -> ScanResult:
    # Capture hash before detection
    pre_hash = self._quick_hash(path)

    detection_result = detect_file(path)
    stat = path.stat()

    # Verify file unchanged
    post_hash = self._quick_hash(path)
    if pre_hash != post_hash:
        raise FileModifiedError(f"File modified during scan: {path}")

    return ScanResult(
        path=str(path),
        content_hash=post_hash,
        # ... rest of fields
    )

def _quick_hash(self, path: Path, block_size: int = 65536) -> str:
    """Fast hash using first and last blocks + size."""
    size = path.stat().st_size
    hasher = hashlib.blake2b()
    hasher.update(str(size).encode())

    with open(path, 'rb') as f:
        hasher.update(f.read(block_size))
        if size > block_size * 2:
            f.seek(-block_size, 2)
            hasher.update(f.read(block_size))

    return hasher.hexdigest()[:32]
```

---

### Issue 2.4: Deserialization Without Schema Validation

**Location:** `openlabels/output/index.py:261, 289`

**Problem:** JSON from database is deserialized directly into objects without schema validation.

**Current Code:**
```python
return LabelSet.from_json(row['labels_json'])
```

**Fix - Add Schema Validation:**
```python
from jsonschema import validate, ValidationError

LABEL_SET_SCHEMA = {
    "type": "object",
    "required": ["labels", "version"],
    "properties": {
        "labels": {"type": "array"},
        "version": {"type": "string"},
        # ... full schema
    }
}

def _deserialize_label_set(self, json_str: str) -> LabelSet:
    """Deserialize with schema validation."""
    try:
        data = json.loads(json_str)
        validate(data, LABEL_SET_SCHEMA)
        return LabelSet.from_dict(data)
    except ValidationError as e:
        raise CorruptedDataError(f"Invalid label data in database: {e.message}")
    except json.JSONDecodeError as e:
        raise CorruptedDataError(f"Malformed JSON in database: {e}")
```

**Considerations:**
- Define JSON schemas for all persisted types
- Consider using pydantic for validation
- Log corrupted records for investigation

---

### Issue 2.5: Extended Attribute Not Validated on Read

**Location:** `openlabels/output/virtual.py:107, 196`

**Problem:** Validation exists for writes but not reads. Manually crafted xattr could inject unexpected data.

**Current Code:**
```python
value = xattr.getxattr(path, self.ATTR_NAME)
return value.decode('utf-8')
```

**Fix:**
```python
def _read_xattr(self, path: Path) -> Optional[str]:
    """Read and validate extended attribute."""
    try:
        value = xattr.getxattr(path, self.ATTR_NAME)
        decoded = value.decode('utf-8')

        # Validate format: should be "labelID:content_hash"
        if not self._validate_label_pointer(decoded):
            logger.warning(f"Invalid xattr format on {path}: {decoded[:50]}")
            return None

        return decoded
    except OSError:
        return None

def _validate_label_pointer(self, value: str) -> bool:
    """Validate label pointer format."""
    # Expected format: UUID:hex_hash
    pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[0-9a-f]{32,64}$'
    return bool(re.match(pattern, value, re.IGNORECASE))
```

---

## Phase 3: Error Handling & Observability

**Goal:** Make failures visible and actionable instead of silent
**Priority:** HIGH - Silent failures cause hard-to-debug production issues

### Issue 3.1: Swallowed Exceptions in LabelIndex

**Location:** `openlabels/output/index.py:224-226, 264-266, 330-331, 401-403`

**Problem:** Database errors are logged and converted to `False` return values. Callers cannot distinguish "not found" from "database error."

**Current Code:**
```python
except Exception as e:
    logger.error(f"Failed to store label: {e}")
    return False
```

**Fix - Structured Error Types:**
```python
# New exceptions in openlabels/core/exceptions.py
class OpenLabelsError(Exception):
    """Base exception for OpenLabels."""
    pass

class TransientError(OpenLabelsError):
    """Error that may succeed on retry (network, timeout, lock)."""
    pass

class PermanentError(OpenLabelsError):
    """Error that will not succeed on retry (validation, not found)."""
    pass

class DatabaseError(TransientError):
    """Database operation failed."""
    pass

class NotFoundError(PermanentError):
    """Requested resource not found."""
    pass

# Updated code:
def get_label(self, label_id: str) -> Optional[LabelSet]:
    try:
        with self._get_connection() as conn:
            row = conn.execute(...).fetchone()
            if row is None:
                return None  # Not found - valid result
            return LabelSet.from_json(row['labels_json'])
    except sqlite3.OperationalError as e:
        raise DatabaseError(f"Database error retrieving label: {e}") from e
    except sqlite3.IntegrityError as e:
        raise DatabaseError(f"Database integrity error: {e}") from e
```

**Apply Pattern To:**
- `store_label()` - lines 224-226
- `get_label()` - lines 264-266
- `get_labels_for_path()` - lines 330-331
- `delete_label()` - lines 401-403

---

### Issue 3.2: Silent Continuation After Extractor Failure

**Location:** `openlabels/adapters/scanner/detectors/orchestrator.py:398-402`

**Problem:** If structured extractor crashes, detection continues with degraded accuracy but no indication is returned.

**Current Code:**
```python
except Exception as e:
    logger.error(f"Structured extractor failed: {e}")
    processed_text = text
    char_map = []
```

**Fix - Track Degraded State:**
```python
@dataclass
class DetectionResult:
    entities: List[Entity]
    # ... existing fields ...
    warnings: List[str] = field(default_factory=list)
    degraded: bool = False  # NEW: indicates reduced accuracy

# In orchestrator:
try:
    processed_text, char_map = self._structured_extract(text)
except Exception as e:
    logger.error(f"Structured extractor failed: {e}")
    processed_text = text
    char_map = []
    result.degraded = True
    result.warnings.append(f"Structured extraction failed: {type(e).__name__}")
```

---

### Issue 3.3: Detector Failures Don't Propagate

**Location:** `openlabels/adapters/scanner/detectors/orchestrator.py:611-612, 657-658`

**Problem:** Individual detector failures are logged but don't affect overall result. A scan could return "no entities" when all detectors crashed.

**Current Code:**
```python
except Exception as e:
    logger.error(f"Detector {detector.name} failed: {e}")
```

**Fix - Track Failed Detectors:**
```python
@dataclass
class DetectionResult:
    entities: List[Entity]
    detectors_run: List[str]  # Already exists
    detectors_failed: List[str] = field(default_factory=list)  # NEW
    all_detectors_failed: bool = False  # NEW

# In orchestrator:
failed_detectors = []
successful_detectors = []

for detector in detectors:
    try:
        entities.extend(detector.detect(text))
        successful_detectors.append(detector.name)
    except Exception as e:
        logger.error(f"Detector {detector.name} failed: {e}")
        failed_detectors.append(detector.name)

result.detectors_run = successful_detectors
result.detectors_failed = failed_detectors
result.all_detectors_failed = len(successful_detectors) == 0 and len(failed_detectors) > 0

if result.all_detectors_failed:
    logger.error("All detectors failed - results unreliable")
```

---

### Issue 3.4: Timeout Handling Doesn't Cancel Work

**Location:** `openlabels/adapters/scanner/detectors/orchestrator.py:646-656`

**Problem:** Timed-out detectors continue running in background. Under adversarial input, threads accumulate.

**Current Code:**
```python
except TimeoutError:
    cancelled = future.cancel()
    logger.warning(...)
```

**Fix - Track Runaway Threads:**
```python
# Add monitoring for runaway detections
_RUNAWAY_DETECTIONS = 0
_RUNAWAY_LOCK = threading.Lock()
MAX_RUNAWAY_DETECTIONS = 5

def _handle_timeout(self, future, detector_name: str):
    global _RUNAWAY_DETECTIONS

    cancelled = future.cancel()
    if not cancelled:
        # Thread still running - track it
        with _RUNAWAY_LOCK:
            _RUNAWAY_DETECTIONS += 1
            count = _RUNAWAY_DETECTIONS

        logger.warning(
            f"Detector {detector_name} timed out and could not be cancelled. "
            f"Runaway threads: {count}"
        )

        if count >= MAX_RUNAWAY_DETECTIONS:
            logger.critical(
                f"Too many runaway detections ({count}). "
                "System may be under attack or detector has bug."
            )
            # Optionally: stop accepting new detections
```

**Long-term Fix:** Use multiprocessing instead of threading for detectors that can timeout, allowing actual process termination.

---

### Issue 3.5: File Operations Don't Distinguish Error Types

**Location:** `openlabels/components/fileops.py:135-136`

**Problem:** Permission errors, disk full, and network timeouts all become string errors.

**Current Code:**
```python
except Exception as e:
    errors.append({"path": result.path, "error": str(e)})
```

**Fix:**
```python
from dataclasses import dataclass
from enum import Enum

class FileErrorType(Enum):
    PERMISSION_DENIED = "permission_denied"
    DISK_FULL = "disk_full"
    NOT_FOUND = "not_found"
    NETWORK_ERROR = "network_error"
    UNKNOWN = "unknown"

@dataclass
class FileOperationError:
    path: str
    error_type: FileErrorType
    message: str
    retryable: bool

def _classify_error(self, e: Exception, path: str) -> FileOperationError:
    if isinstance(e, PermissionError):
        return FileOperationError(path, FileErrorType.PERMISSION_DENIED, str(e), False)
    elif isinstance(e, OSError) and e.errno == errno.ENOSPC:
        return FileOperationError(path, FileErrorType.DISK_FULL, str(e), False)
    elif isinstance(e, FileNotFoundError):
        return FileOperationError(path, FileErrorType.NOT_FOUND, str(e), False)
    elif isinstance(e, (TimeoutError, ConnectionError)):
        return FileOperationError(path, FileErrorType.NETWORK_ERROR, str(e), True)
    else:
        return FileOperationError(path, FileErrorType.UNKNOWN, str(e), False)
```

---

## Phase 4: State Isolation & Context Safety

**Goal:** Enable true multi-client isolation and prevent resource leakage
**Priority:** MEDIUM-HIGH - Required for multi-tenant and long-running deployments

### Issue 4.1: Hidden Global State in Orchestrator

**Location:** `openlabels/adapters/scanner/detectors/orchestrator.py:80-88`

**Problem:** Module-level globals are shared across all contexts. Multiple `Client` instances share detection concurrency limits.

**Current Code:**
```python
_SHARED_EXECUTOR: Optional[ThreadPoolExecutor] = None
_DETECTION_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_DETECTIONS)
_QUEUE_DEPTH = 0
_QUEUE_LOCK = threading.Lock()
```

**Fix - Move to Context:**
```python
# In context.py - add detection resources
@dataclass
class Context:
    # ... existing fields ...
    _detection_executor: Optional[ThreadPoolExecutor] = field(default=None, init=False)
    _detection_semaphore: Optional[threading.BoundedSemaphore] = field(default=None, init=False)
    _queue_depth: int = field(default=0, init=False)
    _queue_lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    @property
    def detection_executor(self) -> ThreadPoolExecutor:
        if self._detection_executor is None:
            self._detection_executor = ThreadPoolExecutor(
                max_workers=self.config.max_detection_workers
            )
        return self._detection_executor

    @property
    def detection_semaphore(self) -> threading.BoundedSemaphore:
        if self._detection_semaphore is None:
            self._detection_semaphore = threading.BoundedSemaphore(
                self.config.max_concurrent_detections
            )
        return self._detection_semaphore

# In orchestrator.py - accept context
class DetectorOrchestrator:
    def __init__(self, config: Config, context: Context):
        self.config = config
        self.context = context

    def detect(self, text: str) -> DetectionResult:
        # Use self.context.detection_executor instead of global
        # Use self.context.detection_semaphore instead of global
```

---

### Issue 4.2: Default Singleton in context.py and index.py

**Location:** `openlabels/context.py:182-193`, `openlabels/output/index.py:496-508`

**Problem:** `get_default_context()` creates process-wide singletons that leak state.

**Fix - Add Warnings and Scoping:**
```python
import warnings

_default_context: Optional[Context] = None
_default_context_warning_issued = False

def get_default_context() -> Context:
    """Get or create the default context.

    WARNING: Default context shares state across all callers.
    For isolated operation, create explicit Context instances.
    """
    global _default_context, _default_context_warning_issued

    if not _default_context_warning_issued:
        warnings.warn(
            "Using default context shares state across all callers. "
            "Create explicit Context for isolation.",
            UserWarning,
            stacklevel=2
        )
        _default_context_warning_issued = True

    if _default_context is None:
        _default_context = Context()
    return _default_context

def reset_default_context():
    """Reset default context. Useful for testing."""
    global _default_context
    if _default_context is not None:
        _default_context.close()
        _default_context = None
```

---

### Issue 4.3: atexit Handlers Leak

**Location:** `openlabels/context.py:69`

**Problem:** Every Context registers an atexit handler. Frequent context creation causes unbounded accumulation.

**Current Code:**
```python
def __post_init__(self):
    atexit.register(self.close)
```

**Fix - Use Weak References:**
```python
import weakref

_context_refs: List[weakref.ref] = []

def _cleanup_contexts():
    """atexit handler that cleans up all live contexts."""
    for ref in _context_refs:
        ctx = ref()
        if ctx is not None:
            ctx.close()

# Register once at module load
atexit.register(_cleanup_contexts)

@dataclass
class Context:
    def __post_init__(self):
        # Don't register individual handlers - add to weak ref list
        _context_refs.append(weakref.ref(self))

    def close(self):
        if self._closed:
            return
        self._closed = True
        # ... cleanup resources ...
```

---

### Issue 4.4: Cloud Handler Singletons

**Location:** `openlabels/output/virtual.py:281-289, 547-571`

**Problem:** Module-level singletons for cloud handlers persist across requests.

**Current Code:**
```python
_handler = None
_s3_handler = None
_gcs_handler = None
_azure_handler = None
```

**Fix - Move to Context:**
```python
# In context.py
@dataclass
class Context:
    # ... existing fields ...
    _cloud_handlers: Dict[str, Any] = field(default_factory=dict, init=False)

    def get_cloud_handler(self, provider: str):
        if provider not in self._cloud_handlers:
            self._cloud_handlers[provider] = self._create_cloud_handler(provider)
        return self._cloud_handlers[provider]

    def _create_cloud_handler(self, provider: str):
        if provider == 's3':
            return S3Handler(self.config)
        # ... etc

# Remove module-level singletons from virtual.py
```

---

### Issue 4.5: Detection Queue Counter Could Leak

**Location:** `openlabels/adapters/scanner/detectors/orchestrator.py:117-125`

**Problem:** Narrow window where semaphore may not release if exception occurs between acquire and inner try.

**Current Code:**
```python
try:
    _DETECTION_SEMAPHORE.acquire()
    try:
        yield current_depth
    finally:
        _DETECTION_SEMAPHORE.release()
finally:
    with _QUEUE_LOCK:
        _QUEUE_DEPTH = max(0, _QUEUE_DEPTH - 1)
```

**Fix - Safer Ordering:**
```python
@contextmanager
def _detection_slot(self):
    """Acquire detection slot with guaranteed cleanup."""
    with self.context._queue_lock:
        self.context._queue_depth += 1
        current_depth = self.context._queue_depth

    acquired = False
    try:
        self.context.detection_semaphore.acquire()
        acquired = True
        yield current_depth
    finally:
        if acquired:
            self.context.detection_semaphore.release()
        with self.context._queue_lock:
            self.context._queue_depth = max(0, self.context._queue_depth - 1)
```

---

## Phase 5: Contract Consistency & Type Safety

**Goal:** Eliminate ambiguity and prevent subtle bugs from inconsistent assumptions
**Priority:** MEDIUM - These cause hard-to-debug issues

### Issue 5.1: Entity Type Normalization Inconsistent

**Location:** `core/scorer.py:111`, `components/scorer.py:143`, `core/scorer.py:122`

**Problem:** Entity types normalized to uppercase in some places, lowercase in others.

**Fix - Centralize Normalization:**
```python
# In openlabels/core/entity_types.py (new file)
def normalize_entity_type(entity_type: str) -> str:
    """Canonical normalization for entity types. Always UPPERCASE."""
    return entity_type.strip().upper()

# Update all usages to call this function
# In core/scorer.py:
from openlabels.core.entity_types import normalize_entity_type

entity_type = normalize_entity_type(entity.type)
```

---

### Issue 5.2: Exposure Level Strings vs Enum Inconsistency

**Location:** `adapters/base.py`, `context.py:47`, `core/scorer.py:228`

**Problem:** Some code uses enum, some uses strings. No enforcement of valid values.

**Fix - Enforce Enum Everywhere:**
```python
# In context.py - use enum, not string
from openlabels.adapters.base import ExposureLevel

@dataclass
class ContextConfig:
    default_exposure: ExposureLevel = ExposureLevel.PRIVATE  # Not str

# Add validation
def __post_init__(self):
    if isinstance(self.default_exposure, str):
        try:
            self.default_exposure = ExposureLevel[self.default_exposure.upper()]
        except KeyError:
            raise ValueError(f"Invalid exposure level: {self.default_exposure}")
```

---

### Issue 5.3: Optional vs Required Fields Ambiguous

**Location:** `openlabels/core/types.py:53-110`

**Problem:** `score=0` meaning unclear - minimal risk or not scanned?

**Fix - Use Sentinel or Optional:**
```python
from typing import Optional

@dataclass
class ScanResult:
    path: str
    size_bytes: int
    score: Optional[int] = None  # None = not scanned, 0 = minimal risk
    error: Optional[str] = None

    @property
    def was_scanned(self) -> bool:
        return self.score is not None and self.error is None

    @property
    def has_error(self) -> bool:
        return self.error is not None
```

---

### Issue 5.4: Filter Expression Errors Not Validated

**Location:** `openlabels/cli/filter.py:400-404`

**Problem:** Invalid field names silently pass. Typos like `scroe > 50` never match.

**Current Code:**
```python
if field not in self.FIELDS:
    # Allow unknown fields for extensibility
    pass
```

**Fix - Warn on Unknown Fields:**
```python
KNOWN_FIELDS = {'score', 'path', 'size', 'scanned_at', 'entity_type', ...}

def _validate_field(self, field: str, strict: bool = False) -> bool:
    if field not in self.KNOWN_FIELDS:
        if strict:
            raise FilterParseError(f"Unknown field: {field}. Valid fields: {self.KNOWN_FIELDS}")
        else:
            logger.warning(f"Unknown field in filter: {field}. This may be a typo.")
    return True
```

---

### Issue 5.5: No Schema Versioning on Configuration

**Location:** `openlabels/adapters/scanner/config.py`

**Problem:** No version field. Old configs may produce unexpected behavior.

**Fix:**
```python
@dataclass
class Config:
    schema_version: int = 1  # Current schema version

    # ... existing fields ...

    def __post_init__(self):
        if self.schema_version != CURRENT_SCHEMA_VERSION:
            self._migrate_config()

    def _migrate_config(self):
        """Migrate old config to current schema."""
        if self.schema_version < 1:
            # Apply v0 -> v1 migrations
            pass
        # Update version
        self.schema_version = CURRENT_SCHEMA_VERSION
```

---

### Issue 5.6: Confidence Threshold Magic Default

**Location:** `openlabels/core/scorer.py:154`, `components/scorer.py:151`

**Problem:** 0.90 default used inconsistently.

**Fix - Define Constant:**
```python
# In openlabels/core/constants.py
DEFAULT_CONFIDENCE_THRESHOLD = 0.90
CONFIDENCE_WHEN_NO_SPANS = 0.90  # Explicit about this choice

# In scorer.py:
from openlabels.core.constants import DEFAULT_CONFIDENCE_THRESHOLD, CONFIDENCE_WHEN_NO_SPANS

def calculate_content_score(entities, confidence: float = DEFAULT_CONFIDENCE_THRESHOLD):
    if not spans:
        return CONFIDENCE_WHEN_NO_SPANS  # Document why this value
```

---

## Phase 6: Concurrency Robustness & Long-term

**Goal:** Handle edge cases and prepare for scale
**Priority:** MEDIUM - Important for production stability at scale

### Issue 6.1: Watcher Event Queue Fills Without Feedback

**Location:** `openlabels/agent/watcher.py:141`

**Problem:** Queue fills silently, events dropped without error.

**Fix:**
```python
def _enqueue_event(self, event):
    try:
        self._event_queue.put_nowait(event)
    except queue.Full:
        self._dropped_events += 1
        if self._dropped_events == 1 or self._dropped_events % 100 == 0:
            logger.error(
                f"Event queue full - dropped {self._dropped_events} events. "
                "Processing may be falling behind."
            )
        # Optionally: callback or metric for monitoring
        if self._on_queue_full:
            self._on_queue_full(self._dropped_events)
```

---

### Issue 6.2: Polling Watcher Race Condition

**Location:** `openlabels/agent/watcher.py:501-521`

**Problem:** File modified during poll scan could be seen as unchanged.

**Fix - Use Checksums:**
```python
def _poll_directory(self):
    current_state = {}
    for path in self._walk_directory():
        try:
            stat = path.stat()
            # Include content hash for small files
            if stat.st_size < 1024 * 1024:  # 1MB
                content_hash = self._quick_hash(path)
            else:
                content_hash = None
            current_state[path] = (stat.st_mtime, stat.st_size, content_hash)
        except OSError:
            continue

    # Compare with previous state using all three values
    for path, (mtime, size, hash) in current_state.items():
        if path not in self._previous_state:
            self._emit_created(path)
        elif (mtime, size, hash) != self._previous_state[path]:
            self._emit_modified(path)
```

---

### Issue 6.3: Request-Scoped Detection Queue Not Isolated

**Location:** `openlabels/adapters/scanner/detectors/orchestrator.py:107-125`

**Problem:** Independent scan requests compete for same backpressure limits.

**Fix:** This is addressed by Issue 4.1 (moving globals to Context). Each Context gets its own semaphore and queue depth tracking.

---

## Long-term Recommendations

These are architectural changes for future consideration:

### 1. Async/Await Migration
- Convert I/O-bound operations to async
- Better concurrency control than threads
- Easier cancellation and timeout handling

### 2. OpenTelemetry Tracing
- Add distributed tracing for production debugging
- Track request flow across components
- Enable performance profiling

### 3. Distributed Locking
- For multi-instance deployments
- Redis or ZooKeeper based locks
- Required for clustered scanner deployments

### 4. Configuration Schema Versioning
- Formal JSON Schema for all configs
- Migration scripts between versions
- Validation on load

---

## Implementation Checklist

Use this checklist to track remediation progress:

### Phase 1: Input Validation & Safety
- [x] 1.1 Add text input size limits
- [x] 1.2 Enforce file size limit before read
- [x] 1.3 Implement ReDoS timeout enforcement
- [x] 1.4 Add Cloud URI validation

### Phase 2: Data Integrity & Transactions
- [x] 2.1 Wrap SQLite operations in transactions
- [x] 2.2 Make file operations idempotent
- [x] 2.3 Add file modification detection
- [x] 2.4 Add schema validation for deserialization
- [x] 2.5 Validate extended attributes on read

### Phase 3: Error Handling & Observability
- [x] 3.1 Create structured error types for LabelIndex
- [x] 3.2 Track degraded detection state
- [x] 3.3 Track failed detectors in results
- [x] 3.4 Monitor runaway detection threads
- [x] 3.5 Classify file operation errors

### Phase 4: State Isolation & Context
- [x] 4.1 Move orchestrator globals to Context
- [x] 4.2 Add warnings for default singletons
- [x] 4.3 Fix atexit handler leakage
- [x] 4.4 Move cloud handlers to Context
- [x] 4.5 Fix detection queue counter leak

### Phase 5: Contract Consistency
- [x] 5.1 Centralize entity type normalization
- [x] 5.2 Enforce ExposureLevel enum everywhere
- [x] 5.3 Clarify optional vs required fields
- [x] 5.4 Warn on unknown filter fields
- [x] 5.5 Add config schema versioning
- [x] 5.6 Define confidence threshold constants

### Phase 6: Concurrency & Long-term
- [x] 6.1 Add feedback for queue overflow
- [x] 6.2 Fix polling watcher race condition
- [x] 6.3 Isolate detection queue per context (addressed by Phase 4.1)

---

## Testing Strategy

For each fix, ensure:

1. **Unit Tests** - Test the specific fix in isolation
2. **Integration Tests** - Test interaction with other components
3. **Adversarial Tests** - Test with malicious/edge-case inputs
4. **Concurrency Tests** - Test under parallel load
5. **Regression Tests** - Ensure existing functionality preserved

### Key Test Scenarios

```python
# Phase 1 tests
def test_text_input_size_limit():
    detector = Detector()
    huge_text = "a" * (10 * 1024 * 1024 + 1)  # Just over limit
    with pytest.raises(ValueError, match="exceeds maximum size"):
        detector.detect(huge_text)

def test_file_size_limit_enforced():
    # Create temp file larger than limit
    # Verify detect_file raises before reading

def test_redos_timeout():
    # Craft regex that causes catastrophic backtracking
    # Verify it times out rather than hanging

def test_cloud_uri_path_traversal():
    with pytest.raises(ValueError, match="path traversal"):
        parse_cloud_uri("s3://bucket/../../../etc/passwd")
```

---

## References

- Original review: `PRODUCTION_READINESS_REVIEW.md`
- Architecture docs: `docs/openlabels-architecture-v2.md`
- Scoring calibration: `docs/calibration-plan.md`
