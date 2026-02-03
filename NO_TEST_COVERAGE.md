# Files With No Test Coverage

This file tracks modules with 0% test coverage. Update the "Coverage %" column as tests are added.

## Summary

| Category | Files | Status |
|----------|-------|--------|
| Auth | 3 | **Completed** (72 tests) |
| Client | 2 | **Completed** (34 tests) |
| Core/_rust | 3 | **In Progress** (95 tests) |
| GUI | 17 | Not Started |
| Jobs | 8 | **Completed** (251 tests) |
| Server routes | 16 | **In Progress** (431 tests for 13 routes) |
| Server other | 2 | **In Progress** (45 tests) |
| Web | 2 | **In Progress** (85 tests) |
| Windows | 3 | Not Started |
| **Total** | **53** | |

---

## Auth (3 files)

| File | Stmts | Coverage % | Notes |
|------|-------|------------|-------|
| `src/openlabels/auth/dependencies.py` | 58 | ~70% | FastAPI auth dependencies - TESTED |
| `src/openlabels/auth/graph.py` | 126 | ~80% | Microsoft Graph API client - TESTED |
| `src/openlabels/auth/oauth.py` | 42 | ~85% | OAuth/OIDC token validation - TESTED |

---

## Client (2 files)

| File | Stmts | Coverage % | Notes |
|------|-------|------------|-------|
| `src/openlabels/client/__init__.py` | 2 | 100% | Package init - TESTED |
| `src/openlabels/client/client.py` | 88 | ~90% | API client library - TESTED (34 tests) |

---

## Core - Rust Bindings (3 files)

| File | Stmts | Coverage % | Notes |
|------|-------|------------|-------|
| `src/openlabels/core/_rust/__init__.py` | 86 | ~80% | Rust binding loader - TESTED (45 tests) |
| `src/openlabels/core/_rust/patterns_py.py` | 1 | ~90% | Pattern fallback - TESTED (8 tests) |
| `src/openlabels/core/_rust/validators_py.py` | 120 | ~85% | Validator fallback - TESTED (42 tests) |

---

## GUI (17 files)

| File | Stmts | Coverage % | Notes |
|------|-------|------------|-------|
| `src/openlabels/gui/__init__.py` | 2 | 0% | Package init |
| `src/openlabels/gui/main.py` | 17 | 0% | GUI entry point |
| `src/openlabels/gui/main_window.py` | 308 | 0% | Main window |
| `src/openlabels/gui/widgets/__init__.py` | 15 | 0% | Widgets init |
| `src/openlabels/gui/widgets/charts_widget.py` | 231 | 0% | Charts widget |
| `src/openlabels/gui/widgets/dashboard_widget.py` | 132 | 0% | Dashboard widget |
| `src/openlabels/gui/widgets/file_detail_widget.py` | 209 | 0% | File detail widget |
| `src/openlabels/gui/widgets/health_widget.py` | 139 | 0% | Health widget |
| `src/openlabels/gui/widgets/labels_widget.py` | 205 | 0% | Labels widget |
| `src/openlabels/gui/widgets/monitoring_widget.py` | 246 | 0% | Monitoring widget |
| `src/openlabels/gui/widgets/results_widget.py` | 208 | 0% | Results widget |
| `src/openlabels/gui/widgets/scan_widget.py` | 174 | 0% | Scan widget |
| `src/openlabels/gui/widgets/schedules_widget.py` | 265 | 0% | Schedules widget |
| `src/openlabels/gui/widgets/settings_widget.py` | 156 | 0% | Settings widget |
| `src/openlabels/gui/widgets/targets_widget.py` | 172 | 0% | Targets widget |
| `src/openlabels/gui/workers/__init__.py` | 5 | 0% | Workers init |
| `src/openlabels/gui/workers/scan_worker.py` | 246 | 0% | Scan worker thread |

---

## Jobs (8 files)

| File | Stmts | Coverage % | Notes |
|------|-------|------------|-------|
| `src/openlabels/jobs/__init__.py` | 4 | 100% | Package init - TESTED |
| `src/openlabels/jobs/inventory.py` | 128 | ~85% | File inventory tracking - TESTED (52 tests) |
| `src/openlabels/jobs/queue.py` | 129 | 98% | Job queue management - TESTED (63 tests) |
| `src/openlabels/jobs/scheduler.py` | 116 | ~35% | Cron scheduler - TESTED (requires APScheduler) |
| `src/openlabels/jobs/tasks/label.py` | 269 | ~45% | Labeling task - TESTED (36 tests) |
| `src/openlabels/jobs/tasks/label_sync.py` | 154 | ~50% | Label sync task - TESTED (28 tests) |
| `src/openlabels/jobs/tasks/scan.py` | 395 | ~30% | Scan task - TESTED (30 tests) |
| `src/openlabels/jobs/worker.py` | 122 | ~68% | Background worker - TESTED (42 tests) |

---

## Server - Routes (16 files)

| File | Stmts | Coverage % | Notes |
|------|-------|------------|-------|
| `src/openlabels/server/routes/__init__.py` | 2 | 100% | Routes init - TESTED |
| `src/openlabels/server/routes/audit.py` | 76 | ~80% | Audit log endpoints - TESTED (30 tests) |
| `src/openlabels/server/routes/auth.py` | 218 | ~25% | Auth endpoints - partial coverage |
| `src/openlabels/server/routes/dashboard.py` | 159 | ~75% | Dashboard endpoints - TESTED (45 tests) |
| `src/openlabels/server/routes/health.py` | 141 | ~75% | Health endpoints - TESTED (24 tests) |
| `src/openlabels/server/routes/jobs.py` | 112 | ~85% | Jobs endpoints - TESTED (28 tests) |
| `src/openlabels/server/routes/labels.py` | 196 | ~75% | Labels endpoints - TESTED (40 tests) |
| `src/openlabels/server/routes/monitoring.py` | 186 | ~75% | Monitoring endpoints - TESTED (40 tests) |
| `src/openlabels/server/routes/remediation.py` | 191 | ~70% | Remediation endpoints - TESTED (45 tests) |
| `src/openlabels/server/routes/results.py` | 186 | ~75% | Results endpoints - TESTED (45 tests) |
| `src/openlabels/server/routes/scans.py` | 114 | ~85% | Scans endpoints - TESTED (18 tests) |
| `src/openlabels/server/routes/schedules.py` | 90 | ~75% | Schedules endpoints - TESTED (35 tests) |
| `src/openlabels/server/routes/settings.py` | 33 | ~85% | Settings endpoints - TESTED (25 tests) |
| `src/openlabels/server/routes/targets.py` | 83 | ~85% | Targets endpoints - TESTED (21 tests) |
| `src/openlabels/server/routes/users.py` | 76 | ~80% | Users endpoints - TESTED (35 tests) |
| `src/openlabels/server/routes/ws.py` | 131 | ~25% | WebSocket endpoints - partial coverage |

---

## Server - Other (2 files)

| File | Stmts | Coverage % | Notes |
|------|-------|------------|-------|
| `src/openlabels/server/app.py` | 93 | ~70% | FastAPI app setup - TESTED (20 tests) |
| `src/openlabels/server/logging.py` | 94 | ~75% | Structured logging - TESTED (25 tests) |

---

## Web (2 files)

| File | Stmts | Coverage % | Notes |
|------|-------|------------|-------|
| `src/openlabels/web/__init__.py` | 2 | 100% | Package init - TESTED |
| `src/openlabels/web/routes.py` | 470 | ~75% | Web UI routes - TESTED (85 tests) |

---

## Windows (3 files)

| File | Stmts | Coverage % | Notes |
|------|-------|------------|-------|
| `src/openlabels/windows/__init__.py` | 3 | 0% | Package init |
| `src/openlabels/windows/service.py` | 127 | 0% | Windows service |
| `src/openlabels/windows/tray.py` | 159 | 0% | System tray icon |

---

*Last updated: 2026-02-03*

## Recent Test Additions

### 2026-02-03 - Server Routes Expansion
Added comprehensive tests for 5 additional server routes:
- **settings.py**: 25 tests covering Azure, scan, and entity settings
- **dashboard.py**: 45 tests covering stats, trends, heatmaps
- **users.py**: 35 tests covering CRUD operations and tenant isolation
- **schedules.py**: 35 tests covering CRUD and trigger operations
- **remediation.py**: 45 tests covering quarantine, lockdown, and rollback

### 2026-02-03 - Server Other & Additional Routes
Added comprehensive tests for server infrastructure and 3 more routes:
- **app.py**: 20 tests covering middleware, request ID, CORS, health endpoints
- **logging.py**: 25 tests covering JSONFormatter, DevelopmentFormatter, ContextLogger
- **labels.py**: 40 tests covering label CRUD, sync status, rules, mappings
- **monitoring.py**: 40 tests covering monitored files, access events, anomaly detection
- **results.py**: 45 tests covering results listing, stats, export, rescan actions

### 2026-02-03 - Core Rust Bindings
Added comprehensive tests for pattern matching and validation:
- **_rust/__init__.py**: 45 tests covering PatternMatcherWrapper, MatchResult, find_matches, batch processing
- **validators_py.py**: 42 tests covering all validators (Luhn, SSN, phone, email, IPv4, IBAN, NPI, CUSIP, ISIN)
- **patterns_py.py**: 8 tests covering BUILTIN_PATTERNS definitions and regex validation

### 2026-02-03 - Web UI Routes
Added comprehensive tests for web UI module:
- **routes.py**: 85 tests covering:
  - Helper functions (format_relative_time, truncate_string)
  - Page routes (dashboard, targets, scans, results, labels, monitoring, settings)
  - Detail pages (target, scan, result, schedule edit pages)
  - Form handlers (create/update targets, schedules, scans)
  - HTMX partials (dashboard stats, lists, health status, job queue)
  - Tenant isolation and pagination
