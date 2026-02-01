# OpenRisk Remediation Plan: Path to 85%

**Goal:** Raise Security from 75→85 and Code Quality from 65→85
**Excludes:** Test coverage (intentionally deferred)
**Estimated Total Effort:** 2 days

---

## Current State

| Category | Current | Target | Gap |
|----------|---------|--------|-----|
| Security | 75/100 | 85/100 | +10 |
| Code Quality | 65/100 | 85/100 | +20 |
| Production Readiness | 85/100 | 85/100 | ✅ |

---

## PHASE 1: Security (75 → 85)

**Total: +10 points | ~6.5 hours**

### S1: Fix Dangerous Silent Exception Handlers
**Impact:** +4 points | **Effort:** 2 hours

Three locations silently swallow exceptions that hide production bugs:

#### S1.1: `context.py:135-136`
```python
# BEFORE (dangerous)
except Exception:
    pass  # Shutdown coordinator may not be available

# AFTER (safe)
except Exception as e:
    logger.debug(f"Shutdown coordinator not available: {e}")
```

#### S1.2: `fileops.py:141-142`
```python
# BEFORE (dangerous - loses manifest silently)
except (json.JSONDecodeError, OSError):
    pass

# AFTER (safe)
except (json.JSONDecodeError, OSError) as e:
    logger.warning(f"Could not load quarantine manifest {manifest_path}: {e}")
```

#### S1.3: `output/index.py:289-290`
```python
# BEFORE (dangerous)
def __del__(self):
    try:
        self.close()
    except Exception:
        pass

# AFTER (safe)
def __del__(self):
    try:
        self.close()
    except Exception as e:
        # Can't use logger reliably in __del__
        import sys
        print(f"LabelIndex cleanup warning: {e}", file=sys.stderr)
```

---

### S2: Add Connection Health Checks
**Impact:** +3 points | **Effort:** 3 hours

SQLite connections can go stale. Add connection validation.

**File:** `output/index.py`

```python
def _validate_connection(self, conn: sqlite3.Connection) -> bool:
    """Validate connection is still usable."""
    try:
        conn.execute("SELECT 1").fetchone()
        return True
    except sqlite3.Error:
        return False

@contextmanager
def _get_connection(self):
    """Get database connection with validation."""
    if self._closed:
        raise DatabaseError("LabelIndex has been closed")

    conn = self._get_thread_connection()

    # Validate connection before use
    if not self._validate_connection(conn):
        conn_key = f"conn_{self.db_path}"
        try:
            conn.close()
        except sqlite3.Error:
            pass
        delattr(self._thread_local, conn_key)
        conn = self._get_thread_connection()

    try:
        yield conn
    except sqlite3.Error as e:
        # ... existing error handling
```

---

### S3: Transaction Rollback Logging
**Impact:** +2 points | **Effort:** 30 minutes

**File:** `output/index.py:326-327, 332-333`

```python
# BEFORE
except sqlite3.Error:
    pass  # Rollback failed

# AFTER
except sqlite3.Error as rollback_err:
    logger.warning(f"Transaction rollback also failed: {rollback_err}")
```

---

### S4: TOCTOU Window in PollingWatcher
**Impact:** +1 point | **Effort:** 1 hour

**File:** `agent/watcher.py` - `_scan_directory` method

```python
# BEFORE
for file_path in walker:
    if file_path.is_file():  # TOCTOU: file could change here
        try:
            st = file_path.stat()
            ...

# AFTER - use stat() result directly
import stat as stat_module

for file_path in walker:
    try:
        st = file_path.stat()
        if not stat_module.S_ISREG(st.st_mode):
            continue  # Not a regular file
        ...
    except OSError:
        continue  # File doesn't exist or can't be accessed
```

---

## PHASE 2: Code Quality (65 → 85)

**Total: +20 points | ~9 hours**

### Q1: Split Long Orchestrator Function
**Impact:** +10 points | **Effort:** 3-4 hours

**Problem:** `_detect_impl_with_metadata()` is 150 lines with 10+ responsibilities. This is the single biggest code quality issue - it makes the core detection logic untestable.

**File:** `openlabels/adapters/scanner/detectors/orchestrator.py`

**Solution:** Extract into focused helper methods:

```python
# BEFORE: One 150-line method doing everything

# AFTER: Coordinator + focused methods
def _detect_impl_with_metadata(self, text, timeout, known_entities, metadata):
    """Main detection orchestration - coordinates the pipeline."""
    all_spans = []

    # Step 1: Known entity detection
    all_spans.extend(self._detect_known_entities_step(text, known_entities))

    # Step 2: Structured extraction + OCR post-processing
    processed_text, char_map = self._structured_extraction_step(text, metadata)

    # Step 3: Run detectors (parallel or sequential)
    detector_spans = self._run_detectors_step(processed_text, timeout, metadata)

    # Step 4: Map coordinates back to original text
    mapped_spans = self._map_coordinates_step(detector_spans, char_map, text)
    all_spans.extend(mapped_spans)

    # Step 5: Post-processing pipeline
    return self._postprocess_spans(all_spans, text, metadata)


def _detect_known_entities_step(self, text, known_entities):
    """Step 1: Detect previously-identified entities."""
    # ~15 lines - extracted from main method


def _structured_extraction_step(self, text, metadata):
    """Step 2: Run structured extractor with OCR post-processing."""
    # ~25 lines - extracted from main method


def _run_detectors_step(self, text, timeout, metadata):
    """Step 3: Run pattern/ML detectors."""
    # ~15 lines - extracted from main method


def _map_coordinates_step(self, spans, char_map, original_text):
    """Step 4: Map span coordinates back to original text."""
    # ~20 lines - extracted from main method


def _postprocess_spans(self, spans, text, metadata):
    """Step 5: Filter, dedupe, normalize, and enhance spans."""
    # ~30 lines - the post-processing pipeline
```

**Before:** 1 method × 150 lines = impossible to unit test individual steps
**After:** 6 methods × ~25 lines avg = each step testable in isolation

---

### Q2: Externalize Weights to Config
**Impact:** +5 points | **Effort:** 2 hours

**Problem:** `weights.py` is 530 lines of Python dict literals. Unlike patterns (which rarely change), weights ARE tuned frequently during risk model calibration.

**New file:** `openlabels/core/registry/weights.yaml`
```yaml
# Entity weights for risk scoring (1-10 scale)
# 10 = Critical direct identifier
# 1 = Minimal risk

direct_identifiers:
  SSN: 10
  PASSPORT: 10
  DRIVERS_LICENSE: 7
  STATE_ID: 7
  TAX_ID: 8
  AADHAAR: 10
  NHS_NUMBER: 8
  MEDICARE_ID: 8

healthcare:
  MRN: 8
  HEALTH_PLAN_ID: 8
  NPI: 7
  DEA: 7
  DIAGNOSIS: 8
  MEDICATION: 6
  # ... etc
```

**Simplified `weights.py`:**
```python
"""Entity weights loader."""
import yaml
from pathlib import Path
from functools import lru_cache

@lru_cache(maxsize=1)
def _load_weights():
    yaml_path = Path(__file__).parent / "weights.yaml"
    with open(yaml_path) as f:
        return yaml.safe_load(f)

def get_weight(entity_type: str) -> int:
    """Get weight for an entity type."""
    weights = _load_weights()
    for category in weights.values():
        if entity_type in category:
            return category[entity_type]
    return 1  # Default minimal weight

# Backward compatibility
def get_all_weights() -> dict:
    weights = _load_weights()
    flat = {}
    for category in weights.values():
        flat.update(category)
    return flat

# Expose constants for backward compatibility
ALL_WEIGHTS = get_all_weights()
```

**Benefits:**
- Compliance team can review/adjust weights without touching Python
- Weights can be environment-specific (dev vs prod)
- Changes don't require code deployment

---

### Q3: Improve Exception Handler Logging
**Impact:** +3 points | **Effort:** 1 hour

Add logging to remaining questionable exception handlers.

**Files to update:**
- `output/index.py:326-327` - Log rollback failure (covered in S3)
- `output/index.py:332-333` - Log rollback failure (covered in S3)

---

### Q4: Add Type Hints to Public API
**Impact:** +2 points | **Effort:** 2 hours

Ensure all public methods in `Client`, `Context`, and `Scanner` have complete type hints.

**Files:**
- `client.py` - Main public API
- `context.py` - Context management
- `components/scanner.py` - Scanner interface

---

## Implementation Order

| Order | Task | Points | Hours | Notes |
|-------|------|--------|-------|-------|
| 1 | S1: Fix silent exceptions | +4 | 2h | Quick wins, do first |
| 2 | S3: Rollback logging | +2 | 0.5h | Quick win |
| 3 | Q1: Split orchestrator | +10 | 4h | Biggest quality win |
| 4 | S2: Connection health | +3 | 3h | Production stability |
| 5 | Q2: Weights to YAML | +5 | 2h | Config externalization |
| 6 | S4: TOCTOU fix | +1 | 1h | Minor security fix |
| 7 | Q3: Exception logging | +3 | 1h | Observability |
| 8 | Q4: Type hints | +2 | 2h | Polish |

**Total:** +30 points
**Total time:** ~15.5 hours (~2 days)

---

## Quick Wins (Day 1 Morning)

Do these first - high value, low effort:

| Task | Time | Points |
|------|------|--------|
| S1.1: Log in `context.py:135` | 10 min | |
| S1.2: Log in `fileops.py:141` | 10 min | |
| S1.3: Stderr in `index.py:289` | 10 min | |
| S3: Rollback logging | 30 min | |
| **Subtotal** | **1 hour** | **+6** |

---

## Verification Checklist

After each fix:

- [ ] `pytest tests/` passes
- [ ] No new exceptions swallowed silently
- [ ] All error paths logged at appropriate level
- [ ] No regressions in scan functionality

---

## Expected Final Scores

| Category | Before | After | Change |
|----------|--------|-------|--------|
| Security | 75 | 85 | +10 |
| Code Quality | 65 | 85 | +20 |

---

## Files Modified Summary

| File | Changes |
|------|---------|
| `context.py` | Add exception logging (1 line) |
| `fileops.py` | Add exception logging (2 lines) |
| `output/index.py` | Connection validation, rollback logging, `__del__` fix |
| `agent/watcher.py` | Fix TOCTOU in `_scan_directory` |
| `orchestrator.py` | Split 150-line function into 6 methods |
| `weights.py` | Replace with YAML loader (~30 lines) |
| `client.py` | Add type hints |
| **NEW:** `weights.yaml` | ~200 lines config |

---

## What's NOT in This Plan

**Intentionally excluded:**

1. **Pattern files refactor** - 1,950 lines but low technical debt. Works, rarely changes, only developers edit it.

2. **Test coverage** - Deferred per your request.

3. **Duplicate code in validators** - Minor issue, not worth the refactor risk.
