# Production Readiness Plan

**Total Estimated Effort:** 50-65 hours

**Architecture Note:** This is a single-server deployment with multiple worker processes. The PostgreSQL job queue handles scan-level orchestration (low volume - maybe 10-100 jobs/day). File processing happens in-memory within workers using ThreadPoolExecutor/asyncio. No external message broker needed.

---

## Phase 1: Critical Bug Fixes (IMMEDIATE)

### 1.1 Fix Use-After-Close Bug in Extractors
**File:** `src/openlabels/core/extractors.py:425-438`
**Time:** 30 min

Store sheet count before closing workbook:
```python
sheet_count = len(wb.sheetnames) if hasattr(wb, 'sheetnames') else 1
wb.close()
# Later use sheet_count instead of wb.sheetnames
```

### 1.2 Fix Scan Cancel Endpoint
**File:** `src/openlabels/server/routes/scans.py:140-160`
**Time:** 30 min

The function ends without committing or returning. Add proper cleanup.

---

## Phase 2: Security Fixes (HIGH - Week 1)

### 2.1 Replace In-Memory Session Storage
**Time:** 2-3 hours

Use existing PostgreSQL - no new dependencies needed.

**Add table to schema:**
```sql
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    tenant_id UUID REFERENCES tenants(id),
    data JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
```

**Create:** `src/openlabels/server/session.py`
```python
class DatabaseSessionStore:
    async def get(self, session_id: str) -> dict | None: ...
    async def set(self, session_id: str, data: dict, ttl: int) -> None: ...
    async def delete(self, session_id: str) -> None: ...
    async def cleanup_expired(self) -> int: ...  # Called periodically
```

**Update:** `src/openlabels/server/routes/auth.py` to use DatabaseSessionStore instead of dict.

### 2.2 Configure Proper CORS
**Time:** 1 hour

**Add to config.py:**
```python
class CORSSettings(BaseSettings):
    allowed_origins: list[str] = ["http://localhost:3000"]
    allow_credentials: bool = True
```

**Update app.py** to use settings instead of wildcards.

### 2.3 Add Rate Limiting
**Time:** 2-3 hours

**Add dependency:** `slowapi>=0.1.9`

**Create:** `src/openlabels/server/middleware/rate_limit.py`

Apply limits:
- `/auth/*` - 10 requests/minute
- `/api/scans` POST - 20 requests/minute
- General API - 100 requests/minute

### 2.4 Add Request Size Limits
**Time:** 30 min

Add `ContentSizeLimitMiddleware` to app.py with configurable max size.

---

## Phase 3: Missing Features (HIGH - Week 1-2)

### 3.1 Add /api/users Router
**Time:** 3-4 hours

**Create:** `src/openlabels/server/routes/users.py`

Endpoints needed (CLI depends on these):
- `GET /api/users` - List users
- `POST /api/users` - Create user
- `GET /api/users/{id}` - Get user
- `DELETE /api/users/{id}` - Delete user

**Update:** `app.py` to register the router.

### 3.2 Implement Config Set Command
**Time:** 2-3 hours

**File:** `src/openlabels/__main__.py:105-112`

Current command prints but doesn't save. Implement YAML file writing with nested key support (e.g., `server.port`).

---

## Phase 4: Code Cleanup (MEDIUM - Week 2)

### 4.1 Remove Dead Code from processor.py
**Time:** 1 hour

**Remove lines 353-782 (~430 lines):**
- `_extract_office()`, `_extract_docx()`, `_extract_docx_fallback()`
- `_extract_xlsx()`, `_extract_xlsx_fallback()`
- `_extract_pptx()`, `_extract_pptx_fallback()`
- `_extract_odf()`, `_extract_rtf()`, `_extract_legacy_office()`
- `_extract_pdf()`, `_extract_pdf_with_ocr()`

These are unused - main code uses `extractors.py` instead.

### 4.2 Remove Unused Variable
**File:** `src/openlabels/core/extractors.py:691`

Remove: `_EXTRACTORS: List[BaseExtractor] = []`

### 4.3 Update Scrubiq Reference
**File:** `src/openlabels/core/extractors.py:7`

Remove or update "Adapted from scrubiq" comment.

### 4.4 Clean Up Empty Exception Handlers
**Time:** 1-2 hours

**Files:**
- `labeling/mip.py` (lines 621, 629, 731, 794, 837)
- `jobs/tasks/scan.py` (line 331)
- `core/agents/pool.py` (lines 285, 339)

Add logging instead of silent `pass`.

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

| Week | Tasks | Time |
|------|-------|------|
| **Day 1** | Phase 1 (Critical bugs) | 1 hour |
| **Week 1** | Phase 2 (Security) | 6-8 hours |
| **Week 1-2** | Phase 3 (Missing features) | 6-7 hours |
| **Week 2** | Phase 4 (Cleanup) | 3-4 hours |
| **Week 2-4** | Phase 5 (Tests) | 40-50 hours |
| **Week 4+** | Phase 6 (Observability) | 7-9 hours |

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
