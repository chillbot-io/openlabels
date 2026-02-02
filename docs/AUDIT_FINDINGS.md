# OpenLabels Codebase Audit Report

**Date:** February 2, 2026
**Auditor:** Claude Code
**Scope:** Full codebase audit for AI slop, bad code, dead code, errors, missed implementations, and TODOs

---

## Executive Summary

The OpenLabels codebase is generally well-structured with comprehensive functionality. However, I identified several issues across different categories ranging from potential bugs to missed spec implementations. Below is a detailed breakdown.

---

## 1. CRITICAL ISSUES (Potential Bugs/Errors)

### 1.1 Missing Import in health.py (Line 249)

**File:** `src/openlabels/server/routes/health.py:249`

```python
# Import is at the BOTTOM of the file after it's used
from sqlalchemy import Integer  # Line 249
```

**Issue:** `Integer` is imported at the bottom of the file but used earlier in lines 110-111 and 226. This will cause a `NameError` at runtime.

**Lines using Integer before import:**
- Line 110: `func.cast(JobQueue.status == "pending", Integer)`
- Line 111: `func.cast(JobQueue.status == "failed", Integer)`
- Line 226: `func.cast(ScanJob.status == "completed", Integer)`

---

### 1.2 Incorrect ML Detector Import in health.py (Line 142)

**File:** `src/openlabels/server/routes/health.py:142-154`

```python
from openlabels.core.detectors.ml import ONNXDetector
# ...
detector = ONNXDetector(model_name="pii-bert")
```

**Issue:** The import tries to get `ONNXDetector` from `ml.py`, but:
1. `ml.py` contains `MLDetector`, `PHIBertDetector`, and `PIIBertDetector` - not `ONNXDetector`
2. The ONNX detectors are in `ml_onnx.py` as `PHIBertONNXDetector` and `PIIBertONNXDetector`
3. These detectors don't accept `model_name` parameter

---

### 1.3 Potential API Mismatch in remediation.py (Line 331)

**File:** `src/openlabels/server/routes/remediation.py:331`

```python
success, _ = await adapter.lockdown_file(
    file_info,
    allowed_sids=request.allowed_principals,
)
```

**Issue:** The `FilesystemAdapter` protocol in `base.py` doesn't define `lockdown_file()` method. The protocol defines:
- `get_acl()`
- `set_acl()`
- `move_file()`

The `lockdown_file` method exists in `permissions.py` as a standalone function, not as an adapter method.

---

### 1.4 Unused Variable in remediation.py (Line 315)

**File:** `src/openlabels/server/routes/remediation.py:315`

```python
file_name = os.path.basename(request.file_path)
```

The variable `file_name` is computed but never used in the lockdown flow.

---

## 2. CODE QUALITY ISSUES

### 2.1 Broad Exception Handling

The codebase has **200+ instances** of bare `except Exception:` or `except Exception as e:` patterns. While defensive programming is good, many silently swallow errors:

**Examples from `__main__.py`:**
```python
except Exception:  # Line 655, 668, 679, 692, 706 - silent swallowing
    pass
```

**Recommendation:** Add logging or more specific exception types.

---

### 2.2 Global Mutable State

**File:** `src/openlabels/jobs/tasks/scan.py:43`

```python
_processor: Optional[FileProcessor] = None

def get_processor(enable_ml: bool = False) -> FileProcessor:
    global _processor
    if _processor is None:
        # ...creates processor
```

**Issue:** The `enable_ml` parameter is only used on first call. Subsequent calls with different `enable_ml` values will get the cached processor with original settings.

---

### 2.3 Stub Classes for Non-Windows

**File:** `src/openlabels/windows/service.py:46-64`

```python
# Stub classes for non-Windows development
class win32serviceutil:
    class ServiceFramework:
        pass
class win32service:
    SERVICE_STOP_PENDING = 0
    # ...
```

**Assessment:** This is acceptable for cross-platform development but could cause confusion. Consider moving to a separate `_stubs.py` module with clearer documentation.

---

### 2.4 Hard-coded Constants

**File:** `src/openlabels/server/routes/health.py:126-129`

```python
if failed_count > 10:      # Magic number
    status["queue"] = "error"
elif pending_count > 100:  # Magic number
    status["queue"] = "warning"
```

**Recommendation:** Move to configuration constants.

---

## 3. DEAD CODE / UNUSED IMPORTS

### 3.1 Unused Import in base.py

**File:** `src/openlabels/adapters/base.py:11`

```python
import re
```

The `re` module is imported but never used in this file.

---

### 3.2 Unused Query in health.py (Lines 108-112)

**File:** `src/openlabels/server/routes/health.py:108-112`

```python
queue_query = select(
    func.count().label("total"),
    func.sum(func.cast(JobQueue.status == "pending", Integer)).label("pending"),
    func.sum(func.cast(JobQueue.status == "failed", Integer)).label("failed"),
)
```

This query is constructed but never executed. The code immediately builds and executes separate queries instead.

---

## 4. SPEC vs IMPLEMENTATION GAPS

Based on `openlabels-architecture-v3.md` and `openlabels-spec-v2.md`:

### 4.1 Monitor CLI Commands - PARTIALLY IMPLEMENTED

**Spec CLI commands:**
```bash
openlabels monitor enable <file>
openlabels monitor disable <file>
openlabels monitor list
openlabels monitor history <file>
openlabels monitor status <file>
```

**Current implementation:** The `__main__.py` CLI module appears to have these as stubs or partial implementations based on the monitoring module's capabilities.

---

### 4.2 Report/Heatmap CLI Commands - STATUS UNKNOWN

**Spec CLI commands:**
```bash
openlabels report <path> --format html
openlabels heatmap <path> --depth 2
```

Need verification these are fully implemented.

---

### 4.3 Batch Remediation with Filters - STATUS UNKNOWN

**Spec CLI commands:**
```bash
openlabels quarantine --where "score > 75" --scan-path /data
openlabels lock-down --where "has(SSN)" --scan-path /hr
```

The filter grammar parser exists (`cli/filter_parser.py`, `cli/filter_executor.py`), but integration with batch remediation commands needs verification.

---

## 5. ARCHITECTURE CONCERNS

### 5.1 Adapter Protocol Mismatch

The `Adapter` protocol in `base.py` uses `Protocol` but concrete adapters may not implement all methods:

```python
class Adapter(Protocol):
    async def move_file(...) -> bool: ...
    async def get_acl(...) -> Optional[dict]: ...
    async def set_acl(...) -> bool: ...
    def supports_remediation(self) -> bool: ...
```

Some adapters return `False` for `supports_remediation()` but the route code doesn't consistently check this before calling remediation methods.

---

### 5.2 Inconsistent Async Patterns

Some files mix sync and async patterns:

**Example in `scan.py`:**
```python
async def execute_scan_task(...):
    # ...
    content = await adapter.read_file(file_info)
    result = await _detect_and_score(content, file_info)  # But this calls sync detectors
```

The orchestrator uses `ThreadPoolExecutor` for sync detectors, wrapped in async context.

---

## 6. AI SLOP INDICATORS

### 6.1 Overly Verbose Comments

Some files have excessive inline comments that explain obvious code:

**Example from patterns.py:**
```python
# Single character "names" are almost always false positives
if len(words) == 1 and len(words[0]) == 1:
    return True

# Very short matches (< 3 chars) are usually false positives
if len(value.replace(' ', '')) < 3:
    return True
```

The code is self-explanatory; comments add noise.

---

### 6.2 Redundant Status Assignment

**File:** `src/openlabels/server/routes/remediation.py:217`

```python
action = RemediationAction(
    # ...
    status="pending" if request.dry_run else "pending",  # Always "pending"
)
```

The conditional is pointless - both branches return `"pending"`.

---

## 7. DOCUMENTATION ISSUES

### 7.1 Outdated Documentation Reference

The architecture doc mentions `~32%` overall test coverage (line 994 in architecture doc). The actual coverage should be verified and this should be updated if improved.

---

### 7.2 Missing API Documentation

Some routes lack OpenAPI documentation for error responses. FastAPI generates docs but custom error schemas aren't always specified.

---

## 8. RECOMMENDATIONS (Priority Order)

### HIGH PRIORITY
1. **Fix `Integer` import in health.py** - Move import to top of file
2. **Fix `ONNXDetector` import** - Use correct class from `ml_onnx.py`
3. **Fix `lockdown_file` API mismatch** - Either add to adapter protocol or use existing `set_acl`

### MEDIUM PRIORITY
4. Add specific exception handling instead of bare `except Exception:`
5. Fix global processor caching to respect `enable_ml` parameter
6. Remove unused imports and dead code

### LOW PRIORITY
7. Move magic numbers to configuration
8. Clean up verbose comments
9. Improve test coverage

---

## Files Audited

- `src/openlabels/__main__.py`
- `src/openlabels/core/detectors/orchestrator.py`
- `src/openlabels/core/detectors/ml.py`
- `src/openlabels/core/detectors/patterns.py`
- `src/openlabels/adapters/base.py`
- `src/openlabels/server/models.py`
- `src/openlabels/server/routes/health.py`
- `src/openlabels/server/routes/remediation.py`
- `src/openlabels/jobs/tasks/scan.py`
- `src/openlabels/labeling/engine.py`
- `src/openlabels/gui/widgets/dashboard_widget.py`
- `src/openlabels/windows/service.py`
- Plus: All spec and architecture documentation

---

**End of Audit Report**
