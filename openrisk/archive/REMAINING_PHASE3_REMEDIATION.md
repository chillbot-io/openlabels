# Remaining Phase 3 Remediation Work

**Date:** 2026-01-27
**Previous Session:** Completed initial Phase 3 refactoring
**Branch:** `claude/implement-audit-phase-3-PEeKC`

---

## Completed Work

### 1. Registry Split ✅
**File:** `openlabels/core/registry.py` (1,054 lines) → Package

Split into:
- `registry/weights.py` - Entity weights organized by category (340 entities)
- `registry/categories.py` - Entity categories for co-occurrence rules
- `registry/vendor_aliases.py` - Vendor type mappings (AWS, GCP, Azure)
- `registry/__init__.py` - Public API with full backward compatibility

**Verification:** All imports from `openlabels.core.registry` work unchanged.

### 2. Confidence Tier Constants ✅
**File:** `openlabels/adapters/scanner/confidence_tiers.py`

Created standardized confidence levels:
- `Confidence.VERY_HIGH` = 0.98 (checksummed IDs, unique prefixes)
- `Confidence.HIGH` = 0.92 (labeled fields, validated formats)
- `Confidence.MEDIUM_HIGH` = 0.88
- `Confidence.MEDIUM` = 0.85 (unlabeled patterns)
- `Confidence.LOW` = 0.75
- `Confidence.MINIMAL` = 0.65

Also includes:
- Adjustment factors (LABELED_BOOST, TEST_CREDENTIAL_PENALTY)
- Detector-specific floors (DETECTOR_CONFIDENCE_FLOORS)
- Filtering thresholds

### 3. PatternBasedDetector Base Class ✅
**File:** `openlabels/adapters/scanner/detectors/base.py`

Extended with:
- `PatternBasedDetector` class - extracts duplicate `_add()` and `detect()` logic
- `create_pattern_list()` - factory for pattern lists
- `create_pattern_adder()` - factory for `_add()` helper functions
- Support for entity-specific validators

**Note:** Detectors not yet refactored to use the new base class (see remaining work).

### 4. Metrics Collection Module ✅
**File:** `openlabels/adapters/scanner/metrics.py`

Features:
- Thread-safe `MetricsCollector` class
- Timing stats with p50/p95/p99 percentiles
- Context managers: `track_detector()`, `track_pipeline()`
- Entity count tracking
- File processing stats
- Global singleton via `get_metrics()`

---

## Remaining Work

### 1. Refactor Detectors to Use PatternBasedDetector (HIGH PRIORITY)

The following detectors have duplicate `_add()` and `detect()` code that should use the new `PatternBasedDetector` base class:

| File | Current Lines | Potential Reduction |
|------|---------------|---------------------|
| `detectors/secrets.py` | 374 | ~50 lines (detect method) |
| `detectors/government.py` | ~285 | ~50 lines |
| `detectors/additional_patterns.py` | 244 | ~50 lines |

**How to refactor:**
```python
# Before (in each detector file):
class SecretsDetector(BaseDetector):
    def detect(self, text: str) -> List[Span]:
        spans = []
        seen = set()
        for pattern, entity_type, confidence, group_idx in SECRETS_PATTERNS:
            # ... 40+ lines of duplicate logic

# After:
from .base import PatternBasedDetector

class SecretsDetector(PatternBasedDetector):
    name = "secrets"
    tier = Tier.PATTERN

    def __init__(self):
        super().__init__(SECRETS_PATTERNS)
        # Add any entity-specific validators
        self.add_validator('JWT', self._validate_jwt)
```

### 2. Update Patterns to Use Confidence Constants (MEDIUM PRIORITY)

Currently, patterns use magic numbers like `0.85`, `0.90`, `0.98`. Should use:
```python
from ..confidence_tiers import Confidence

# Before:
_add(r'\b(ghp_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', 0.99, 1)

# After:
_add(r'\b(ghp_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', Confidence.VERY_HIGH, 1)
```

Files to update:
- `detectors/secrets.py`
- `detectors/government.py`
- `detectors/additional_patterns.py`
- `detectors/financial.py`
- `detectors/patterns/definitions.py` (1,067 lines - largest)

### 3. Integrate Metrics into Orchestrator (MEDIUM PRIORITY)

**File:** `openlabels/adapters/scanner/detectors/orchestrator.py`

Add metrics tracking to detector execution:
```python
from ..metrics import track_detector, record_entities

# In _run_detector():
with track_detector(detector.name):
    spans = detector.detect(text)

# After detection:
for span in spans:
    record_entities(span.entity_type)
```

### 4. Split definitions.py by Category (LOW PRIORITY - OPTIONAL)

**File:** `detectors/patterns/definitions.py` (1,067 lines)

The file is already well-organized with section comments. Splitting is optional but would improve maintainability:

| Section | Lines | Potential File |
|---------|-------|----------------|
| Phone patterns | ~20 | `patterns/phone.py` |
| Email patterns | ~5 | `patterns/email.py` |
| Date/Time patterns | ~70 | `patterns/datetime.py` |
| Name patterns | ~250 | `patterns/names.py` |
| Address patterns | ~180 | `patterns/address.py` |
| Medical IDs | ~60 | `patterns/medical.py` |
| Financial IDs | ~40 | `patterns/financial.py` |
| Driver's License | ~120 | `patterns/license.py` |
| Healthcare-specific | ~40 | `patterns/healthcare.py` |
| International IDs | ~25 | `patterns/international.py` |

**Note:** This is lower priority since the current file is already readable with good section markers.

### 5. Config-Driven Pattern Loading (LOW PRIORITY)

Move pattern definitions to YAML/JSON config files for easier maintenance:
```yaml
# patterns/secrets.yaml
patterns:
  - pattern: '\b(ghp_[a-zA-Z0-9]{36})\b'
    entity_type: GITHUB_TOKEN
    confidence: very_high
    group: 1
```

This would require:
- Pattern loader class
- Config file format definition
- Migration of existing patterns

### 6. Split embed.py by Format (LOW PRIORITY - OPTIONAL)

**File:** `openlabels/output/embed.py` (467 lines)

Currently handles PDF, Office, and Image formats. Could split into:
- `embed/pdf.py` - PDFLabelWriter
- `embed/office.py` - OfficeLabelWriter
- `embed/image.py` - ImageLabelWriter
- `embed/__init__.py` - Common utilities and exports

**Note:** The current file is manageable at 467 lines with clear class separation.

---

## Testing Checklist

After any changes, verify:

```bash
# 1. Registry imports work
python -c "from openlabels.core.registry import get_weight, ENTITY_WEIGHTS; print(len(ENTITY_WEIGHTS))"

# 2. Scanner adapter works
python -c "from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter; print('OK')"

# 3. Detectors import correctly
python -c "from openlabels.adapters.scanner.detectors.orchestrator import DetectorOrchestrator; print('OK')"

# 4. Run existing tests
pytest tests/ -v --tb=short
```

---

## Files Changed in This Session

| File | Change |
|------|--------|
| `openlabels/core/registry.py` | DELETED (replaced by package) |
| `openlabels/core/registry/__init__.py` | NEW |
| `openlabels/core/registry/weights.py` | NEW |
| `openlabels/core/registry/categories.py` | NEW |
| `openlabels/core/registry/vendor_aliases.py` | NEW |
| `openlabels/adapters/scanner/confidence_tiers.py` | NEW |
| `openlabels/adapters/scanner/metrics.py` | NEW |
| `openlabels/adapters/scanner/detectors/base.py` | MODIFIED (added PatternBasedDetector) |

---

## Reference: Audit Report Phase 3 Items

From `COMPREHENSIVE_AUDIT_REPORT.md`:

> ### Phase 3: MEDIUM (Next Quarter)
>
> 9. **Code quality refactoring**
>    - Split god files (3 files, ~3,000 LOC) ✅ registry done, others optional
>    - Extract duplicate detector code ✅ base class created, refactoring pending
>    - Define confidence tier constants ✅ done
>    - Estimate: 3-5 days
>
> 10. **Architecture improvements**
>     - Separate embed.py by format ⏸️ optional
>     - Config-driven pattern loading ⏸️ optional
>     - Estimate: 2-3 days
>
> 11. **Monitoring instrumentation**
>     - Add metrics collection ✅ done
>     - Performance tracking (p50, p95, p99) ✅ done
>     - Estimate: 2 days
