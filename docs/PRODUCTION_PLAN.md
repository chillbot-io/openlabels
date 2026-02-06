# Production Readiness Plan

**Total Estimated Effort:** 50-65 hours

**Architecture Note:** This is a single-server deployment with multiple worker processes. The PostgreSQL job queue handles scan-level orchestration (low volume - maybe 10-100 jobs/day). File processing happens in-memory within workers using ThreadPoolExecutor/asyncio. No external message broker needed.

---

## Phase 1: Critical Bug Fixes (IMMEDIATE) ✅ COMPLETED

### 1.1 Fix Use-After-Close Bug in Extractors ✅
**File:** `src/openlabels/core/extractors.py:425-438`

Fixed by storing sheet count before closing workbook.

### 1.2 Fix Scan Cancel Endpoint ✅
**File:** `src/openlabels/server/routes/scans.py:140-160`

Fixed: Added `await session.flush()` and proper status update. Also added
cancellation checks to both scan tasks to handle race conditions.

---

## Phase 2: Security Fixes (HIGH - Week 1) ✅ COMPLETED

### 2.1 Replace In-Memory Session Storage ✅
Implemented `SessionStore` and `PendingAuthStore` classes in `src/openlabels/server/session.py`.
Added `Session` and `PendingAuth` models in `models.py`. Updated `auth.py` to use database-backed sessions.

### 2.2 Configure Proper CORS ✅
Added `CORSSettings` to `config.py`. Updated `app.py` to read allowed origins from settings
instead of using wildcards.

### 2.3 Add Rate Limiting ✅
Added `slowapi>=0.1.9` dependency. Implemented rate limiting middleware:
- Auth endpoints: 10 requests/minute
- Scan creation: 20 requests/minute
- General API: 100 requests/minute

### 2.4 Add Request Size Limits ✅
Added `ContentSizeLimitMiddleware` to `app.py` (default 100MB, configurable).

---

## Phase 3: Missing Features (HIGH - Week 1-2) ✅ COMPLETED

### 3.1 Add /api/users Router ✅
Created `src/openlabels/server/routes/users.py` with full CRUD:
- `GET /api/users` - List users (admin only, paginated)
- `POST /api/users` - Create user (admin only)
- `GET /api/users/{id}` - Get user details
- `PUT /api/users/{id}` - Update user (admin only)
- `DELETE /api/users/{id}` - Delete user (admin only, prevents self-deletion)

Router registered in `routes/__init__.py`.

### 3.2 Implement Config Set Command ✅
Updated `src/openlabels/__main__.py` to properly persist config changes to YAML file.
Supports nested keys (e.g., `server.port 8080`).

---

## Phase 4: Code Cleanup (MEDIUM - Week 2) ✅ COMPLETED

### 4.1 Remove Dead Code from processor.py ✅
Removed ~430 lines of dead extraction methods from `processor.py`.
All extraction now properly handled by `extractors.py` module.

### 4.2 Remove Unused Variable ✅
Removed `_EXTRACTORS: List[BaseExtractor] = []` from `extractors.py`.

### 4.3 Update Stale References ✅
Removed all stale project name references from source code, tests, and docs.

### 4.4 Clean Up Empty Exception Handlers ✅
**Reviewed and documented:** The empty exception handlers are intentional patterns:
- `mip.py`: Cleanup in `finally` blocks (standard .NET interop pattern)
- `pool.py`: Queue.get timeout handling in retry loops
- `scan.py`: Non-critical WebSocket status updates (failures shouldn't break scans)

No changes needed - these are defensive programming patterns, not bugs.

---

## Phase 5: Test Coverage (HIGH - Week 2-4)

### Current State
**Tested:** detectors, pipeline, scoring, monitoring, remediation
**NOT Tested:** server routes, adapters, jobs, labeling, GUI

### 5.1 Server Routes Tests (16-20 hours)
**Create:** `tests/server/`
- `test_auth_routes.py`
- `test_scans_routes.py`
- `test_results_routes.py`
- `test_targets_routes.py`
- `test_labels_routes.py`
- `test_health.py`

### 5.2 Adapters Tests (8-10 hours)
**Create:** `tests/adapters/`
- `test_filesystem.py`
- `test_sharepoint.py` (mock Graph API)
- `test_onedrive.py` (mock Graph API)

### 5.3 Jobs Tests (8-10 hours)
**Create:** `tests/jobs/`
- `test_queue.py`
- `test_worker.py`
- `test_scheduler.py`
- `test_scan_task.py`

### 5.4 Labeling Tests (6-8 hours)
**Create:** `tests/labeling/`
- `test_mip.py` (mock pythonnet)
- `test_engine.py`

---

## Phase 6: Observability (MEDIUM - Week 4+)

### 6.1 Enhanced Health Check (2 hours)
Add dependency checks (database connectivity) to `/health` endpoint.

### 6.2 Structured Logging (3-4 hours)
Replace basic logging with `structlog`. Add request ID middleware.

### 6.3 API Versioning (2-3 hours)
Add `/api/v1/` prefix. Maintain `/api/` as alias for latest.

---

## Dependencies to Add

```toml
[project.optional-dependencies]
production = [
    "slowapi>=0.1.9",
    "structlog>=23.2.0",
]
```

---

## Execution Order

| Week | Tasks | Time | Status |
|------|-------|------|--------|
| **Day 1** | Phase 1 (Critical bugs) | 1 hour | ✅ DONE |
| **Week 1** | Phase 2 (Security) | 6-8 hours | ✅ DONE |
| **Week 1-2** | Phase 3 (Missing features) | 6-7 hours | ✅ DONE |
| **Week 2** | Phase 4 (Cleanup) | 3-4 hours | ✅ DONE |
| **Week 2-4** | Phase 5 (Tests) | 40-50 hours | PENDING |
| **Week 4+** | Phase 6 (Observability) | 7-9 hours | PENDING |

---

## Quick Start Commands

After implementing each phase, validate with:

```bash
# Run tests
pytest tests/ -v --cov=openlabels

# Type check
mypy src/openlabels

# Lint
ruff check src/openlabels

# Start server (dev mode)
python -m openlabels serve --debug
```
