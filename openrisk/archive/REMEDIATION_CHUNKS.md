# OpenRisk Remediation Chunks

Granular task breakdown for working through issues one at a time.

---

## Phase 1: CRITICAL (Production Blockers)

### Chunk 1.1: CLI Logging Migration
**Scope:** Replace print() with logger in CLI commands
**Files:** 12 files, ~200 print statements
```
openlabels/cli/commands/scan.py        (9 prints)
openlabels/cli/commands/find.py        (7 prints)
openlabels/cli/commands/report.py      (7 prints)
openlabels/cli/commands/heatmap.py     (10 prints)
openlabels/cli/commands/tag.py         (14 prints)
openlabels/cli/commands/delete.py      (23 prints)
openlabels/cli/commands/move.py        (21 prints)
openlabels/cli/commands/quarantine.py  (22 prints)
openlabels/cli/commands/encrypt.py     (23 prints)
openlabels/cli/commands/restrict.py    (26 prints)
openlabels/cli/commands/shell.py       (57 prints)
openlabels/cli/main.py                 (31 prints)
```
**Task:** Add `import logging; logger = logging.getLogger(__name__)` and replace prints with appropriate log levels (INFO for user output, DEBUG for verbose).

---

### Chunk 1.2: Library Logging Migration
**Scope:** Replace print() with logger in library code
**Files:** 16 files, ~100 print statements
```
openlabels/client.py                   (3 prints)
openlabels/__init__.py                 (2 prints)
openlabels/context.py                  (1 print)
openlabels/core/scorer.py              (8 prints)
openlabels/core/orchestrator.py        (1 print)
openlabels/core/triggers.py            (16 prints)
openlabels/components/scanner.py       (1 print)
openlabels/components/scorer.py        (1 print)
openlabels/output/embed.py             (1 print)
openlabels/output/reader.py            (5 prints)
openlabels/output/__init__.py          (2 prints)
openlabels/agent/watcher.py            (4 prints)
openlabels/agent/collector.py          (2 prints)
openlabels/agent/__init__.py           (1 print)
openlabels/adapters/scanner/adapter.py (2 prints)
openlabels/adapters/scanner/scanner_adapter.py (1 print)
```
**Task:** Same pattern - structured logging with context where applicable.

---

### Chunk 1.3: Logging Configuration
**Scope:** Add centralized logging setup
**Files:** New or modify existing
```
openlabels/logging.py                  (NEW - logging config)
openlabels/cli/main.py                 (add --log-level, --log-file flags)
```
**Task:** Create logging configuration module with:
- JSON structured logging option
- Console vs file output
- Log level configuration
- Correlation ID support for request tracing

---

### Chunk 1.4: Health Check Endpoint
**Scope:** Add health check capability
**Files:** 2-3 new/modified files
```
openlabels/health.py                   (NEW - health check logic)
openlabels/cli/commands/health.py      (NEW - CLI command)
openlabels/cli/main.py                 (register command)
```
**Task:** Create health check that verifies:
- SQLite database accessible and writable
- Temp directory exists and writable
- Configuration valid
- Optional dependencies available
- Return JSON with status and details

---

### Chunk 1.5: Graceful Shutdown
**Scope:** Add signal handling for clean shutdown
**Files:** 3-4 files
```
openlabels/cli/main.py                 (signal handlers)
openlabels/context.py                  (shutdown method)
openlabels/agent/watcher.py            (stop watching gracefully)
openlabels/components/scanner.py       (cancel in-flight scans)
```
**Task:**
- Register SIGTERM/SIGINT handlers
- Add `Context.shutdown()` method
- Wait for in-flight operations (with timeout)
- Close database connections
- Clean up temp files

---

### Chunk 1.6: Database Pagination Fix
**Scope:** Fix remaining unbounded queries
**Files:** 1 file
```
openlabels/output/index.py             (lines ~630-650)
```
**Task:** Convert `fetchall()` to cursor iteration with batching in export paths.

---

## Phase 2: HIGH (GA Blockers)

### Chunk 2.1: Structured Error Returns
**Scope:** Replace boolean returns with result objects
**Files:** 4-5 files
```
openlabels/components/fileops.py       (quarantine, move, delete)
openlabels/components/scanner.py       (scan operations)
openlabels/output/index.py             (store/retrieve)
```
**Task:** Create `Result` dataclass with success/error/details. Update callers.

---

### Chunk 2.2: Detector Error Propagation
**Scope:** Surface detector failures to callers
**Files:** 2-3 files
```
openlabels/adapters/scanner/detectors/orchestrator.py  (lines ~398-402)
openlabels/adapters/scanner/adapter.py
openlabels/components/scanner.py
```
**Task:** Add `warnings` or `errors` field to scan results. Track which detectors failed. Let caller decide how to handle degraded results.

---

### Chunk 2.3: Database Connection Pooling
**Scope:** Reuse SQLite connections
**Files:** 1-2 files
```
openlabels/output/index.py             (connection management)
```
**Task:** Implement simple connection pool or reuse pattern. Consider thread-local storage for thread safety.

---

### Chunk 2.4: Scanner Detector Tests
**Scope:** Add tests for detector logic
**Files:** New test files
```
tests/test_scanner/test_financial_detector.py    (NEW)
tests/test_scanner/test_government_detector.py   (NEW)
tests/test_scanner/test_secrets_detector.py      (NEW)
tests/test_scanner/test_patterns_detector.py     (NEW)
```
**Task:** Test pattern matching, validation logic, confidence scoring, edge cases.

---

### Chunk 2.5: CLI Command Tests
**Scope:** Add integration tests for CLI
**Files:** New test files
```
tests/test_cli/test_scan_command.py      (NEW)
tests/test_cli/test_find_command.py      (NEW)
tests/test_cli/test_quarantine_command.py (NEW)
tests/test_cli/test_report_command.py    (NEW)
```
**Task:** Test CLI arg parsing, output format, error handling.

---

### Chunk 2.6: Deployment Documentation
**Scope:** Create deployment guides
**Files:** New documentation
```
docs/deployment/docker.md               (NEW - Docker guide)
docs/deployment/kubernetes.md           (NEW - K8s manifests)
docs/deployment/systemd.md              (NEW - Systemd service)
docs/deployment/configuration.md        (NEW - Env var reference)
Dockerfile                              (NEW or verify existing)
```
**Task:** Document deployment patterns with examples.

---

## Phase 3: MEDIUM (Code Quality)

### Chunk 3.1: Split registry.py God File
**Scope:** Reorganize 1,054-line registry
**Files:** Split into multiple
```
openlabels/core/registry.py            (SPLIT)
  -> openlabels/core/entities.py       (NEW - entity definitions)
  -> openlabels/core/weights.py        (NEW - weight mappings)
  -> openlabels/core/vendors.py        (NEW - vendor aliases)
  -> openlabels/core/registry.py       (keep as facade)
```
**Task:** Extract logical sections, maintain backward compatibility via imports.

---

### Chunk 3.2: Split orchestrator.py God File
**Scope:** Reorganize 1,064-line orchestrator
**Files:** Split into multiple
```
openlabels/adapters/scanner/detectors/orchestrator.py  (SPLIT)
  -> .../detectors/thread_pool.py      (NEW - threading logic)
  -> .../detectors/detection.py        (NEW - core detection)
  -> .../detectors/orchestrator.py     (keep as coordinator)
```
**Task:** Extract threading and core detection logic.

---

### Chunk 3.3: Split definitions.py God File
**Scope:** Reorganize 1,067-line pattern definitions
**Files:** Split by domain
```
openlabels/adapters/scanner/detectors/patterns/definitions.py  (SPLIT)
  -> .../patterns/financial.py         (NEW)
  -> .../patterns/government.py        (NEW)
  -> .../patterns/healthcare.py        (NEW)
  -> .../patterns/credentials.py       (NEW)
  -> .../patterns/pii.py               (NEW)
  -> .../patterns/definitions.py       (keep as aggregator)
```
**Task:** Group patterns by domain, single import point.

---

### Chunk 3.4: Deduplicate Detector Code
**Scope:** Extract common detector patterns
**Files:** 3-4 files
```
openlabels/adapters/scanner/detectors/base.py          (enhance)
openlabels/adapters/scanner/detectors/government.py    (refactor)
openlabels/adapters/scanner/detectors/secrets.py       (refactor)
openlabels/adapters/scanner/detectors/additional_patterns.py (refactor)
```
**Task:** Move duplicate `_add()` and `detect()` logic to base class. Detectors only define patterns.

---

### Chunk 3.5: Confidence Constants
**Scope:** Replace magic numbers with named constants
**Files:** Multiple detector files
```
openlabels/adapters/scanner/detectors/constants.py     (NEW)
  CONFIDENCE_VERY_HIGH = 0.98
  CONFIDENCE_HIGH = 0.95
  CONFIDENCE_MEDIUM = 0.90
  CONFIDENCE_LOW = 0.85
  CONFIDENCE_MINIMAL = 0.70
```
**Task:** Define constants, update all detector files to use them.

---

### Chunk 3.6: Split embed.py by Format
**Scope:** Separate concerns in 459-line embed.py
**Files:** Split into format-specific handlers
```
openlabels/output/embed.py             (SPLIT)
  -> openlabels/output/embed/base.py   (NEW - base class)
  -> openlabels/output/embed/pdf.py    (NEW - PDF handler)
  -> openlabels/output/embed/office.py (NEW - Office handler)
  -> openlabels/output/embed/image.py  (NEW - Image handler)
  -> openlabels/output/embed/__init__.py (facade)
```
**Task:** Each format gets its own module. Main module re-exports.

---

## Chunk Summary

| Phase | Chunks | Est. Total |
|-------|--------|------------|
| Phase 1 (Critical) | 6 chunks | 5-8 days |
| Phase 2 (High) | 6 chunks | 5-8 days |
| Phase 3 (Medium) | 6 chunks | 5-8 days |
| **Total** | **18 chunks** | **15-24 days** |

---

## Recommended Order

Start with these in sequence:

1. **Chunk 1.3** (Logging Config) - Foundation for all logging
2. **Chunk 1.1** (CLI Logging) - Biggest impact, user-visible
3. **Chunk 1.2** (Library Logging) - Complete the logging story
4. **Chunk 1.4** (Health Check) - Enable deployment
5. **Chunk 1.5** (Graceful Shutdown) - Production safety
6. **Chunk 1.6** (Pagination Fix) - Quick win

Then Phase 2, then Phase 3.

---

## Working With Claude

For each chunk, tell Claude:

```
Work on Chunk X.Y: [Name]
Files: [list from above]
Task: [description from above]

Please implement this chunk. Show me the changes before committing.
```

Claude will:
1. Read the relevant files
2. Make the changes
3. Show you for review
4. Commit when approved
