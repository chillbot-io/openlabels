# Open Labels — Workstream Plan

**Goal:** Ship a fully working React frontend, remove legacy Jinja/HTMX templates, get every page functional
**Approach:** Small completable work sessions (~2-4 hours each), ordered by dependency chain
**Estimated total:** 55-75 hours across ~20 sessions

---

## Where Things Stand Right Now

| Area | Status | Notes |
|------|--------|-------|
| **Core detection engine** | ✅ Solid | Well-tested, 50+ entity types, multi-tier pipeline |
| **Backend API** | ✅ Built | 20+ route modules, services, job queue, all wired up |
| **CLI** | ✅ Functional | classify, scan, find, heatmap, report, remediation, etc. |
| **Adapters** | ✅ Built | Filesystem, SharePoint, OneDrive, S3, Azure Blob, GCS |
| **Labeling engine** | ✅ Built | MIP SDK via pythonnet, Graph API, metadata fallback chain |
| **Legacy Jinja UI** | 🗑 Removing | 1,944-line web/routes.py + 30 templates — being replaced |
| **React Frontend** | 🔴 Broken | Cannot compile — 4 critical blockers, 14 high, 16 medium issues |
| **Tests (Phase 5)** | ⏸ Pending | Core tested; server routes, adapters, jobs, labeling need coverage |
| **Observability (Phase 6)** | ⏸ Pending | Health checks, structured logging, API versioning |

---

## Full Page Inventory

Every React route that needs to be working:

| Route | Page | Feature Dir | Key Backend Routes | Complexity |
|-------|------|------------|-------------------|------------|
| `/dashboard` | Dashboard stats + charts | `dashboard/` | `dashboard.py` | Medium |
| `/explorer` | Resource file browser | `resource-explorer/` | `browse.py` | High |
| `/events` | File access events + live feed | `events/` | `monitoring.py` (events) | High |
| `/results` | Results list + filters | `results/list-page` | `results.py` | Medium |
| `/results/:id` | Result detail + entities | `results/detail-page` | `results.py` | Medium |
| `/scans` | Scan history list | `scans/list-page` | `scans.py` | Low |
| `/scans/:id` | Scan detail + progress | `scans/detail-page` | `scans.py` | Medium |
| `/labels` | Label list + entity mapping | `labels/list-page` | `labels.py` | Medium |
| `/labels/sync` | MIP label sync flow | `labels/sync-page` | `labels.py` | Medium |
| `/permissions` | Exposure / ACL browser | `permissions/` | `permissions.py`, `browse.py` | High |
| `/remediation` | Quarantine / lockdown / rollback | `remediation/` | `remediation.py` | Medium |
| `/policies` | Policy CRUD | `policies/` | `policies.py` | Low |
| `/targets` | Target list | `targets/list-page` | `targets.py` | Low |
| `/targets/new`, `/targets/:id` | Target create / edit form | `targets/form-page` | `targets.py` | High (743 lines) |
| `/schedules` | Schedule list | `schedules/list-page` | `schedules.py` | Low |
| `/schedules/new`, `/schedules/:id` | Schedule form | `schedules/form-page` | `schedules.py` | Medium |
| `/monitoring` | Health + jobs + activity | `monitoring/` | `health.py`, `jobs.py`, `monitoring.py` | Medium |
| `/reports` | SQL query + CSV export | `reports/` | `query.py`, `export.py` | Medium |
| `/settings` | Azure / scan / entities / fanout | `settings/` | `settings.py` | High |
| `/config/resources` | Targets + health combo | `config-resources/` | `targets.py`, `health.py` | Medium |
| `/scan-config` | Schedules + scan settings | `scan-config/` | `schedules.py`, `settings.py` | Medium |
| `/users` | User management | `users/` | `users.py` | Medium |
| `/login` | OAuth login | `auth/` | `auth.py` | Low |
| `/setup` | First-run wizard | `setup/` | multiple | Medium |

---

## Workstream 1: React Build Unblocked

**Time:** 3-4 hours | **Blocked by:** Nothing | **Unblocks:** Everything
**Priority:** CRITICAL — no page can render without this

The React app cannot compile because `frontend/src/lib/` is missing. Create four files:

| File | Exports Needed | Imported By |
|------|----------------|-------------|
| `lib/utils.ts` | `cn()`, `formatRelativeTime`, `formatNumber`, `truncatePath` | 25+ files |
| `lib/constants.ts` | `STATUS_COLORS`, `RISK_COLORS`, `RISK_TIERS`, `NAV_GROUPS`, `ADAPTER_TYPES`, `ADAPTER_LABELS`, `ENTITY_TYPES`, `EXPOSURE_LEVELS`, `SOURCE_TYPES`, `SOURCE_LABELS`, `SOURCE_DESCRIPTIONS`, `SOURCE_CREDENTIAL_FIELDS`, `sourceToAdapter`, type exports (`RiskTier`, `ScanStatus`, `AdapterType`, `SourceType`) | 12+ files |
| `lib/date.ts` | `formatDateTime`, `formatDuration`, `describeCron` | 5+ files |
| `lib/websocket.ts` | `wsClient` singleton (connect, disconnect, subscribe, _connection event) | 3 files |

Also verify the `api/client.ts` header merging bug is fixed (lines 44-47 — current code looks correct).

**Done when:** `npm run dev` starts, app shell renders with sidebar navigation.

---

## Workstream 2: Remove Jinja/HTMX Legacy Frontend

**Time:** 2-3 hours | **Blocked by:** WS1 | **Unblocks:** Clean codebase

Remove the legacy Jinja/HTMX frontend entirely:

1. **Delete:** `src/openlabels/web/` directory (routes.py + 30 templates + partials)
2. **Remove:** `/ui` route mount in `server/app.py` (`app.include_router(web_router, prefix="/ui", ...)`)
3. **Clean up:** `htmx_notify()` helper in `server/routes/__init__.py` (remove function + export)
4. **Audit:** Every backend route that uses `htmx_notify` — they already dual-path with `if request.headers.get("HX-Request")` checks. Remove the HTMX branch from each:
   - `routes/scans.py` — cancel, retry
   - `routes/results.py` — clear, delete, apply label, rescan
   - `routes/labels.py` — save mappings
   - `routes/schedules.py` — delete
   - `routes/settings.py` — fanout, adapters, reset
   - `routes/targets.py` — delete
5. **Remove:** `HTMLResponse` imports and HTMX-specific endpoints (`POST /settings/fanout`, `POST /settings/adapters` if they only serve HTMX)
6. **Update:** SPA serving — ensure the React `dist/` is served at `/` with proper catch-all for client-side routing

**Done when:** No Jinja templates remain, backend returns JSON only, React SPA serves from root.

---

## Workstream 3: Core API Contract Alignment

**Time:** 6-8 hours | **Blocked by:** WS1 | **Unblocks:** WS4-WS12

Systematically align frontend types with backend Pydantic models for ALL endpoints. This is the root cause of most runtime errors. Work through every endpoint file and its corresponding backend route.

### Strategy

For each endpoint, read the backend Pydantic response model, then fix the frontend type and/or endpoint to match. Prefer fixing the frontend — it's cheaper than redeploying the backend.

### 3a. Dashboard (`api/endpoints/dashboard.ts` ↔ `routes/dashboard.py`)

- **Stats:** Frontend `DashboardStats` → Backend `OverallStats`. Field-by-field alignment.
- **Entity trends:** Frontend expects `Record<string, number[]>` → Backend returns `{ series: dict[str, list[tuple]], truncated, total_records }`. Fix frontend type.
- **Dashboard page components:** `stats-cards.tsx`, `risk-distribution-chart.tsx`, `findings-by-type-chart.tsx`, `recent-scans-table.tsx`, `activity-feed.tsx` — verify all consume the aligned types.

### 3b. Targets (`api/endpoints/targets.ts` ↔ `routes/targets.py`)

- Verify field names (`adapter` not `adapter_type`, presence of `created_at`/`updated_at`)
- Verify create payload matches `TargetCreate` Pydantic model
- Fix `form-page.tsx` (743 lines) — SOURCE_TYPES/ADAPTER_TYPES mapping, credential fields

### 3c. Scans (`api/endpoints/scans.ts` ↔ `routes/scans.py`)

- Verify create sends `{ target_id, name? }` (singular) and handles single object response
- Verify `ScanJob` type fields match backend response (progress, status, timestamps)
- Check cancel endpoint path

### 3d. Results (`api/endpoints/results.ts` ↔ `routes/results.py`)

- Verify using `/results/cursor` endpoint with correct param names
- Check if `scan_id` vs `job_id` param name is aligned
- Verify `ScanResult` and `ScanResultDetail` types match backend
- Check entity detail data — does backend return detected entities per result?

### 3e. Labels (`api/endpoints/labels.ts` ↔ `routes/labels.py`)

- **Sync:** `POST /labels/sync` — align response type
- **Sync status:** `GET /labels/sync/status` — align `LabelSyncStatus` type
- **Mappings:** `GET /labels/mappings` — align `LabelMappingsResponse` type (backend returns `{ CRITICAL, HIGH, MEDIUM, LOW, labels }`)
- **List:** Verify label list pagination

### 3f. Health (`routes/health.py`)

- Health endpoint is at `/health/status` not `/health`
- Backend returns flat fields (`api`, `api_text`, `db`, `db_text`, etc.)
- Frontend `HealthStatus` type needs to match this flat structure
- Used by: monitoring page, config-resources page

### 3g. Settings (`api/endpoints/settings.ts` ↔ `routes/settings.py`)

- Backend uses structured sub-endpoints: `GET /settings` → `AllSettingsResponse`, `POST /settings/azure`, `POST /settings/scan`, `POST /settings/entities`
- Frontend already has `AllSettings` type and `settingsApi.update(category, settings)` pattern
- Verify the category-based POST matches backend expectations
- Remove any HTMX-only endpoints after WS2

### 3h. Browse (`api/endpoints/browse.ts` ↔ `routes/browse.py`)

- Frontend sends `?path=<string>` → Backend expects `?parent_id=<UUID>`
- Frontend expects flat `DirectoryEntry[]` → Backend returns wrapped `BrowseResponse`
- Field names: `path` vs `dir_path`, `name` vs `dir_name`
- Used by: resource-explorer, events page (FolderTreePanel), permissions page

### 3i. Permissions (`api/endpoints/permissions.ts` ↔ `routes/permissions.py`)

- Exposure summary: frontend expects `{ PUBLIC, ORG_WIDE, INTERNAL, PRIVATE }` → backend returns directory security stats
- Directory fields: `path` vs `dir_path`, `name` vs `dir_name`, `children_count` vs `child_dir_count + child_file_count`

### 3j. Remediation (`api/endpoints/remediation.ts` ↔ `routes/remediation.py`)

- Field names: `file_path` vs `source_path`, missing `performed_by`/`details`
- Rollback: frontend sends to `/{actionId}/rollback` → backend expects `/rollback` with `{ action_id, dry_run }` in body
- Quarantine: frontend sends `reason` → backend expects `quarantine_dir`
- Lockdown: frontend sends `principals` → backend expects `allowed_principals`

### 3k. Events / Audit (`api/endpoints/events.ts` ↔ `routes/monitoring.py`)

- Frontend calls `GET /audit/events` → actual path is `GET /monitoring/events`
- Cursor pagination at `GET /monitoring/events/cursor`
- Query params: frontend sends `start_date`/`end_date` → backend accepts `since`

### 3l. Monitoring / Jobs (`api/endpoints/monitoring.ts`, `jobs.ts` ↔ `routes/health.py`, `jobs.py`, `monitoring.py`)

- Frontend calls `GET /monitoring/jobs` → actual path is `GET /jobs` or `GET /jobs/stats`
- Deduplicate: `jobs.ts` `stats()` vs `monitoring.ts` `jobQueue()`
- Deduplicate: `monitoring.ts` `activityLog()` vs `audit.ts` `list()`

### 3m. Remaining: Schedules, Policies, Users, Query, Export, Reporting

- Check each endpoint file against its backend route
- Fix URL paths (export: `GET /export/results` → `GET /results/export`, reporting: `/export` → `/download`)
- Fix export client to use shared `apiFetch` instead of custom `fetchBlob()` (H13)

**Done when:** Every endpoint file and type file matches its backend counterpart. No 404s, no 422s from type mismatches.

---

## Workstream 4: Core Workflow — Targets + Scans + Results

**Time:** 4-5 hours | **Blocked by:** WS1, WS3 | **Unblocks:** Demo-ready happy path

Walk the primary user journey end-to-end through the React UI:

1. **Create a filesystem target** (`/targets/new`) pointing at a test directory with synthetic PII files
2. **Verify target appears** in list (`/targets`) with correct adapter label
3. **Trigger a scan** against that target (from scans page or target detail)
4. **Watch scan progress** via WebSocket — verify events flow from backend → ws_events.py → frontend `useWebSocketSync` hook
5. **View scan detail** (`/scans/:id`) — progress bar, file counts, timing
6. **View results list** (`/results`) — cursor pagination, risk tier filters
7. **View result detail** (`/results/:id`) — entity counts, risk score, label recommendation
8. **Verify dashboard updates** — stats cards reflect new scan data

Debug whatever breaks. Common integration issues:
- Job queue not picking up scan (check worker process)
- WebSocket events not firing (check ws_events.py event types match frontend subscriptions)
- Results not written to DB (check scan pipeline completion)
- Dashboard stats stale (check cache invalidation)

**Done when:** Full scan lifecycle works: create target → scan → view results → dashboard reflects data.

---

## Workstream 5: Labels + MIP Integration Workflow

**Time:** 3-4 hours | **Blocked by:** WS4 | **Unblocks:** The E3 auto-labeling demo story

This is the money feature — what differentiates Open Labels from a generic PII scanner:

1. **Label sync page** (`/labels/sync`) — trigger MIP label sync or mock without Azure AD
2. **Labels list** (`/labels`) — verify synced labels display with entity type mapping
3. **Label ↔ risk tier mappings** — configure which MIP labels map to which risk tiers
4. **Results show recommendations** — verify results display recommended labels based on risk tier
5. **Label application** — test applying a label from results detail page
6. **Verify labeling engine path** — MIP SDK (if Windows), Graph API (if SharePoint target), or metadata fallback (if filesystem)

If no Azure AD credentials available, create a mock mode:
- Seed fake labels in the DB
- Skip actual MIP SDK / Graph API calls
- Still demonstrate the recommendation → mapping → application flow

**Done when:** Labels page shows labels, results show recommendations, label application succeeds (or is properly mocked).

---

## Workstream 6: Resource Explorer + Permissions

**Time:** 4-5 hours | **Blocked by:** WS3 (browse contract), WS4 | **Unblocks:** Full data browsing

Both pages depend heavily on the browse API and `FolderTreePanel` component:

1. **FolderTreePanel** (`components/folder-tree.tsx`) — fix to use `parent_id` instead of `path`, handle `BrowseResponse` wrapper
2. **Resource explorer** (`/explorer`) — folder tree navigation, file list with risk badges, file detail cards
3. **Permissions page** (`/permissions`) — exposure summary stats, directory ACL browser, security descriptor display
4. **Events page** (`/events`) — also uses FolderTreePanel, fix event query params (`since` not `start_date`/`end_date`)

**Done when:** Can navigate folder trees, see files with risk data, view permissions/exposure data.

---

## Workstream 7: Remediation Workflow

**Time:** 2-3 hours | **Blocked by:** WS3 (remediation contract), WS4 | **Unblocks:** Full governance story

1. **Fix request payloads** — quarantine (`quarantine_dir` not `reason`), lockdown (`allowed_principals` not `principals`)
2. **Fix rollback** — URL and request body alignment
3. **Fix field names** — `source_path` not `file_path` in display
4. **Test full flow** — quarantine a file from results, verify it moves, rollback, verify restoration
5. **Verify cache invalidation** — rollback should invalidate both `['remediation']` and `['results']` (M8)

**Done when:** Can quarantine, lockdown, and rollback files through the UI.

---

## Workstream 8: Scheduling + Scan Config

**Time:** 2-3 hours | **Blocked by:** WS3, WS4 | **Unblocks:** Automated scanning story

1. **Schedules list** (`/schedules`) — verify CRUD works, cron display
2. **Schedule form** (`/schedules/new`, `/schedules/:id`) — `describeCron` from lib/date.ts, target selection
3. **Scan config page** (`/scan-config`) — combo view of schedules + scan settings (max file size, concurrent files, OCR/ML toggles)
4. **Scan config form** — create/edit scheduled scans
5. **Fix `useSchedule('')` guard** (M3) — ensure hooks have `enabled: !!id` for create mode

**Done when:** Can create, edit, delete schedules. Scan config page shows settings and schedule list.

---

## Workstream 9: Monitoring + System Health

**Time:** 2-3 hours | **Blocked by:** WS3 (health/jobs contracts) | **Unblocks:** Ops visibility

1. **Health status section** — fix to use flat field structure from backend
2. **Job queue stats** — fix endpoint path (`/jobs/stats` not `/monitoring/jobs`)
3. **Activity log** — fix endpoint path and pagination
4. **Fix `healthColor` undefined lookup** (M5)
5. **Fix missing pagination setter** (M6 — `const [activityPage] = useState(1)`)
6. **Config resources page** (`/config/resources`) — targets table + health panel combo

**Done when:** Monitoring page shows health, job stats, and activity. Config resources shows targets with health.

---

## Workstream 10: Policies + Reports + Users

**Time:** 3-4 hours | **Blocked by:** WS3 | **Unblocks:** Complete feature set

1. **Policies** (`/policies`) — CRUD, fix missing `onError` handlers (M7), fix `confirm()` to use ConfirmDialog (L1)
2. **Reports** (`/reports`) — SQL query interface, fix export to use `apiFetch` (H13), fix CSV header escaping (M15), fix hardcoded SQL query (L6)
3. **Users** (`/users`) — user management CRUD
4. **Fix column array re-render** issue in all list pages (M16 — wrap in `useMemo`)

**Done when:** Can manage policies, run queries + export, manage users.

---

## Workstream 11: Settings Page

**Time:** 2-3 hours | **Blocked by:** WS2 (HTMX cleanup), WS3 | **Unblocks:** Configuration management

The settings page has the most significant architecture mismatch — handle it as its own workstream:

1. **Fix to use structured sub-endpoints** — `POST /settings/azure`, `POST /settings/scan`, `POST /settings/entities`
2. **Remove HTMX-only endpoints** — `/settings/fanout`, `/settings/adapters` (or convert to JSON)
3. **Fix controlled vs uncontrolled inputs** (M4 — `defaultValue` won't update on refetch)
4. **Verify all settings categories render and save correctly**

**Done when:** Can view and update all settings categories (Azure AD, scan params, entity types, fanout/performance).

---

## Workstream 12: Auth + Setup Wizard

**Time:** 2-3 hours | **Blocked by:** WS1, WS3 | **Unblocks:** First-run experience

1. **Login page** — verify OAuth flow redirects correctly
2. **Auth guard** — fix to distinguish auth failure from network error (M10)
3. **Setup wizard** (`/setup`) — first-run detection, Azure AD configuration (or skip), first target creation, first scan trigger
4. **CSRF handling** — verify token flow works for all mutating requests

**Done when:** Fresh install → setup wizard → first scan works.

---

## Workstream 13: Polish + Quality

**Time:** 4-6 hours | **Blocked by:** WS4-WS12 | **Unblocks:** Ship-ready

### Error states (L12)
- Audit every page — replace `data ? <Content> : null` with proper error/loading states
- Add `ErrorBoundary` wrappers where missing

### Accessibility (M11-M14)
- Clickable table rows: add `tabIndex`, `role="button"`, `onKeyDown`
- Delete buttons: add `aria-label="Delete {name}"`
- Filter inputs: add proper `<label>` elements
- Toast: use `role="status"` for info/success, `role="alert"` for errors only

### Event deduplication (M1, M2)
- Fix duplicate live event IDs (use crypto.randomUUID or counter)
- Deduplicate live vs API events by ID

### Cache invalidation gaps (M8, M9)
- Rollback should invalidate `['results']`
- Cancel scan should invalidate `['dashboard']`

### Code quality (L1-L12)
- Replace `confirm()` with ConfirmDialog everywhere
- Remove duplicate endpoint definitions (L2)
- Add `vite-env.d.ts` for env var types (L8)
- Fix ESLint ecmaVersion (L9)
- Make toast timeout configurable for error messages (L7)

---

## Workstream 14: Test Data + Demo Prep

**Time:** 3-4 hours | **Blocked by:** WS4, WS5 | **Unblocks:** Showing people

1. **Seed script** — Create `scripts/seed_demo_data.py` that:
   - Creates `/tmp/openlabels-demo/` with ~50 files across subdirectories
   - Mix of file types (.txt, .csv, .docx, .pdf)
   - Realistic synthetic PII: SSNs, credit cards, emails, phones, names, addresses, DOBs
   - HIPAA-specific: MRNs, diagnosis codes, insurance IDs
   - Mix of density: some files clean, some with 1-2 entities, some with 20+
   - Some files with mixed entity types to trigger co-occurrence rules

2. **Demo walkthrough script** — Document the 5-minute story:
   - "Here's a file share with 50 files. We don't know what's in them."
   - Create target → scan → results show PII everywhere → risk tiers assigned
   - Labels synced from M365 → recommendations shown → labels applied
   - Dashboard shows the full picture
   - "Your E3 customers get auto-labeling without the $42K/year license upgrade."

3. **Screenshots for README**

**Done when:** Can run seed script, execute full demo, capture screenshots.

---

## Workstream 15: OpenAPI Type Generation

**Time:** 4-6 hours | **Blocked by:** WS3 | **Unblocks:** No more type drift

The permanent fix for the type mismatches that caused most issues:

1. Export OpenAPI spec from FastAPI backend
2. Set up `openapi-typescript` or similar codegen
3. Generate frontend types from spec
4. Replace hand-maintained `api/types.ts` with generated types
5. Add to build pipeline so types stay in sync

**Done when:** `npm run generate-types` produces correct TypeScript from backend models.

---

## Dependency Graph

```
WS1 (Build Unblocked)
 ├── WS2 (Remove Jinja)
 ├── WS3 (API Contract Alignment)
 │    ├── WS4 (Core Workflow: Targets → Scans → Results)
 │    │    ├── WS5 (Labels + MIP)
 │    │    ├── WS6 (Explorer + Permissions)
 │    │    ├── WS7 (Remediation)
 │    │    └── WS14 (Demo Prep)
 │    ├── WS8 (Scheduling)
 │    ├── WS9 (Monitoring)
 │    ├── WS10 (Policies + Reports + Users)
 │    ├── WS11 (Settings)
 │    └── WS15 (OpenAPI Codegen)
 └── WS12 (Auth + Setup)

WS13 (Polish) ← after WS4-WS12
```

---

## Suggested Schedule

| Week | Sessions | Workstreams | Milestone |
|------|----------|-------------|-----------|
| **Week 1** | 3 evenings | WS1, WS2, WS3 (start) | React compiles, Jinja removed, contract work begins |
| **Week 2** | 3 evenings | WS3 (finish), WS4 | All types aligned, core scan workflow works |
| **Week 3** | 3 evenings | WS5, WS6, WS7 | Labels + explorer + remediation working |
| **Week 4** | 3 evenings | WS8, WS9, WS10 | Scheduling + monitoring + policies/reports |
| **Week 5** | 2 evenings | WS11, WS12 | Settings + auth/setup |
| **Week 6** | 2 evenings | WS13, WS14 | Polish + demo prep |
| **Week 7** | 1-2 evenings | WS15 | OpenAPI codegen (insurance against future drift) |

~20 sessions × 2-3 hours = 40-60 hours active work over 7 weeks.

---

## Backend Routes That Return HTMX (Remove in WS2)

These routes currently have `if request.headers.get("HX-Request")` branches that return `htmx_notify()`. After removing Jinja, strip the HTMX branch and keep only the JSON return:

| Route File | Endpoints with HTMX branches |
|-----------|------------------------------|
| `routes/scans.py` | `POST /{id}/cancel`, `POST /{id}/retry` |
| `routes/results.py` | `DELETE /` (clear all), `DELETE /{id}`, `POST /{id}/apply-label`, `POST /{id}/rescan` |
| `routes/labels.py` | `POST /mappings` |
| `routes/schedules.py` | `DELETE /{id}` |
| `routes/settings.py` | `POST /fanout`, `POST /adapters`, `POST /reset` |
| `routes/targets.py` | `DELETE /{id}` |

Also remove:
- `htmx_notify()` function from `routes/__init__.py`
- `HTMLResponse` imports where no longer needed
- Any endpoint that ONLY serves HTMX (no JSON fallback)

---

## Known Issue Reference

All issues from FRONTEND_REVIEW.md mapped to workstreams:

| Issue | Workstream | Description |
|-------|-----------|-------------|
| C1 | WS1 | Missing `src/lib/` directory |
| C2 | WS3c | Scan creation request/response mismatch |
| C3 | WS3d | Results wrong endpoint + pagination |
| C4 | WS3 (various) | Seven wrong URL paths |
| H1 | WS3 (various) | Field name drift across all entities |
| H2 | WS3a | Dashboard stats structure |
| H3 | WS3a | Entity trends structure |
| H4 | WS3e | Label endpoint response shapes |
| H5 | WS3i | Exposure summary structure |
| H6 | WS3f | Health status structure |
| H7 | WS3g / WS11 | Settings architecture mismatch |
| H8 | WS3j / WS7 | Remediation rollback URL |
| H9 | WS3j / WS7 | Remediation field names |
| H10 | WS3h | Browse param mismatch |
| H11 | WS3h | Browse response wrapper |
| H12 | WS3k | Events wrong router + pagination |
| H13 | WS3m / WS10 | Export client bypasses auth |
| H14 | WS1 | Header merging bug (already fixed) |
| M1 | WS13 | Duplicate live event IDs |
| M2 | WS13 | No live/API event deduplication |
| M3 | WS8 | `useSchedule('')` missing guard |
| M4 | WS11 | Settings uncontrolled inputs |
| M5 | WS9 | `healthColor` undefined lookup |
| M6 | WS9 | Monitoring pagination broken |
| M7 | WS10 | Policy mutations missing onError |
| M8 | WS13 | Rollback doesn't invalidate results |
| M9 | WS13 | Cancel scan doesn't invalidate dashboard |
| M10 | WS12 | Auth redirect on network error |
| M11 | WS13 | Table rows not keyboard accessible |
| M12 | WS13 | Delete buttons missing aria-label |
| M13 | WS13 | Filter inputs missing labels |
| M14 | WS13 | Toast role contradiction |
| M15 | WS10 | CSV header escaping |
| M16 | WS10 | Column array re-renders |
| L1 | WS13 | `confirm()` instead of ConfirmDialog |
| L2 | WS9 | Duplicate endpoint definitions |
| L3 | WS13 | `Partial<T>` includes server fields |
| L4 | WS13 | Redundant query invalidation |
| L5 | WS13 | Hardcoded chart colors |
| L6 | WS10 | Hardcoded SQL query |
| L7 | WS13 | Toast timeout not configurable |
| L8 | WS13 | Missing vite-env.d.ts |
| L9 | WS13 | ESLint ecmaVersion mismatch |
| L10 | WS4 | form.watch in map() |
| L11 | WS1 | Content-Type on bodyless requests |
| L12 | WS13 | Inconsistent error states |
