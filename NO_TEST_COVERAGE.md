# Files With No Test Coverage

This file tracks modules with 0% test coverage. Update the "Coverage %" column as tests are added.

## Summary

| Category | Files | Status |
|----------|-------|--------|
| Auth | 3 | **Completed** (72 tests) |
| Client | 2 | **Completed** (34 tests) |
| Core/_rust | 3 | Not Started |
| GUI | 17 | Not Started |
| Jobs | 8 | **In Progress** (105 tests) |
| Server routes | 16 | Not Started |
| Server other | 2 | Not Started |
| Web | 2 | Not Started |
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
| `src/openlabels/core/_rust/__init__.py` | 86 | 0% | Rust binding loader |
| `src/openlabels/core/_rust/patterns_py.py` | 1 | 0% | Pattern fallback |
| `src/openlabels/core/_rust/validators_py.py` | 120 | 0% | Validator fallback |

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
| `src/openlabels/jobs/inventory.py` | 128 | 0% | File inventory tracking |
| `src/openlabels/jobs/queue.py` | 129 | 98% | Job queue management - TESTED (63 tests) |
| `src/openlabels/jobs/scheduler.py` | 116 | 35% | Cron scheduler - TESTED (requires APScheduler) |
| `src/openlabels/jobs/tasks/label.py` | 269 | 12% | Labeling task |
| `src/openlabels/jobs/tasks/label_sync.py` | 154 | 13% | Label sync task |
| `src/openlabels/jobs/tasks/scan.py` | 395 | 7% | Scan task |
| `src/openlabels/jobs/worker.py` | 122 | 68% | Background worker - TESTED (42 tests) |

---

## Server - Routes (16 files)

| File | Stmts | Coverage % | Notes |
|------|-------|------------|-------|
| `src/openlabels/server/routes/__init__.py` | 2 | 0% | Routes init |
| `src/openlabels/server/routes/audit.py` | 76 | 0% | Audit log endpoints |
| `src/openlabels/server/routes/auth.py` | 218 | 0% | Auth endpoints |
| `src/openlabels/server/routes/dashboard.py` | 159 | 0% | Dashboard endpoints |
| `src/openlabels/server/routes/health.py` | 141 | 0% | Health endpoints |
| `src/openlabels/server/routes/jobs.py` | 112 | 0% | Jobs endpoints |
| `src/openlabels/server/routes/labels.py` | 196 | 0% | Labels endpoints |
| `src/openlabels/server/routes/monitoring.py` | 186 | 0% | Monitoring endpoints |
| `src/openlabels/server/routes/remediation.py` | 191 | 0% | Remediation endpoints |
| `src/openlabels/server/routes/results.py` | 186 | 0% | Results endpoints |
| `src/openlabels/server/routes/scans.py` | 114 | 0% | Scans endpoints |
| `src/openlabels/server/routes/schedules.py` | 90 | 0% | Schedules endpoints |
| `src/openlabels/server/routes/settings.py` | 33 | 0% | Settings endpoints |
| `src/openlabels/server/routes/targets.py` | 83 | 0% | Targets endpoints |
| `src/openlabels/server/routes/users.py` | 76 | 0% | Users endpoints |
| `src/openlabels/server/routes/ws.py` | 131 | 0% | WebSocket endpoints |

---

## Server - Other (2 files)

| File | Stmts | Coverage % | Notes |
|------|-------|------------|-------|
| `src/openlabels/server/app.py` | 93 | 0% | FastAPI app setup |
| `src/openlabels/server/logging.py` | 94 | 0% | Structured logging |

---

## Web (2 files)

| File | Stmts | Coverage % | Notes |
|------|-------|------------|-------|
| `src/openlabels/web/__init__.py` | 2 | 0% | Package init |
| `src/openlabels/web/routes.py` | 470 | 0% | Web UI routes |

---

## Windows (3 files)

| File | Stmts | Coverage % | Notes |
|------|-------|------------|-------|
| `src/openlabels/windows/__init__.py` | 3 | 0% | Package init |
| `src/openlabels/windows/service.py` | 127 | 0% | Windows service |
| `src/openlabels/windows/tray.py` | 159 | 0% | System tray icon |

---

*Last updated: 2026-02-03*
