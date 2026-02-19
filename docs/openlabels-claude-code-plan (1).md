# Open Labels — Claude Code Execution Plan

## Context

Open Labels is an enterprise sensitivity labeling and PII detection tool for M365 environments. The backend (FastAPI + PostgreSQL + async workers + multi-tier detection engine) is solid and well-tested. The React frontend (Vite + React 19 + TanStack Query + Zustand + Radix UI + Tailwind CSS 4) **cannot compile** because the `frontend/src/lib/` directory is missing — 4 files that 55+ imports reference.

This plan covers getting the entire React frontend working, removing the legacy Jinja/HTMX templates, and aligning all API contracts between frontend and backend.

**IMPORTANT:** Read `FRONTEND_REVIEW.md` in the repo root before starting any phase. It's the definitive bug list with 46 catalogued issues (4 Critical, 14 High, 16 Medium, 12 Low).

**IMPORTANT:** Read the workstream plan doc (`openlabels-workstream-plan.md`) for strategic context, dependency graph, and issue-to-workstream mapping.

---

## Phase 1: Create Missing `frontend/src/lib/` Directory (WS1 — BUILD BLOCKER)

The app cannot compile without these 4 files. Every page imports from them.

### Task 1.1: Create `frontend/src/lib/utils.ts`

**Imported by:** 25+ files
**Required exports:**

```typescript
// cn() — className merger (standard shadcn pattern)
// Uses clsx + tailwind-merge which are already in package.json
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
```

Other exports needed — scan all usages to determine exact signatures:
- `formatRelativeTime(dateString: string): string` — used in activity-feed, recent-scans-table, config-resources, monitoring, scans list, targets list, users, scan-config. Should return human-readable relative time like "2 hours ago", "3 days ago".
- `formatNumber(n: number): string` — used in stats-cards, results detail, monitoring. Should format with locale separators (e.g., "1,234,567").
- `truncatePath(path: string, maxLength?: number): string` — used in results list, scans detail, remediation. Should truncate long file paths, keeping the filename visible (e.g., `...\subfolder\file.docx`).

### Task 1.2: Create `frontend/src/lib/constants.ts`

**Imported by:** 12+ files
**Required exports (infer exact values from consuming components):**

```typescript
// Types
export type RiskTier = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'MINIMAL';
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type AdapterType = 'filesystem' | 'sharepoint' | 'onedrive' | 's3' | 'azure_blob' | 'gcs';
```

**Source types:** Check `frontend/src/features/targets/form-page.tsx` lines 20-27 for the full SourceType system:
```typescript
export type SourceType = string;  // determine exact union from form-page.tsx
export const SOURCE_TYPES: SourceType[];
export const SOURCE_LABELS: Record<SourceType, string>;
export const SOURCE_DESCRIPTIONS: Record<SourceType, string>;
export const SOURCE_CREDENTIAL_FIELDS: Record<SourceType, string[]>;
export function sourceToAdapter(source: SourceType): AdapterType;
```

**Color maps:** Check `risk-badge.tsx` and `status-badge.tsx` for how these are consumed. They map to Tailwind className strings:
```typescript
export const RISK_COLORS: Record<RiskTier, string>;  // e.g. { CRITICAL: 'text-red-600 bg-red-50', ... }
export const STATUS_COLORS: Record<ScanStatus, string>;
export const RISK_TIERS: RiskTier[];  // ordered array for filter dropdowns
```

**Navigation:** Check `sidebar.tsx` ICON_MAP keys and `app.tsx` route paths to build:
```typescript
export const NAV_GROUPS: Array<{
  label?: string;
  items: Array<{ path: string; label: string; icon: string }>;
}>;
```

Group routes logically:
- Overview: Dashboard, Explorer
- Discovery: Scans, Results, Events
- Governance: Labels, Policies, Permissions
- Operations: Targets, Schedules, Remediation
- System: Monitoring, Reports, Settings, Users

**Other constants:**
```typescript
export const ADAPTER_TYPES: AdapterType[];
export const ADAPTER_LABELS: Record<AdapterType, string>;
export const ENTITY_TYPES: string[];  // check labels/list-page.tsx
export const EXPOSURE_LEVELS: string[];
```

### Task 1.3: Create `frontend/src/lib/date.ts`

**Imported by:** 5+ files
**Required exports:**

- `formatDateTime(dateString: string): string` — format ISO strings to readable local datetime
- `formatDuration(seconds: number): string` — format to "Xh Ym Zs" style
- `describeCron(cronExpr: string): string` — human-readable cron descriptions. Simple implementation covering common patterns is fine.

### Task 1.4: Create `frontend/src/lib/websocket.ts`

**Imported by:** 3 files (events/page.tsx, hooks/use-websocket.ts, stores/websocket-store.ts)

```typescript
// Required interface (infer from consumers):
interface WSClient {
  connect(): void;
  disconnect(): void;
  subscribe(eventType: string, callback: (data: unknown) => void): () => void;
  // _connection event is special — emits { connected: boolean }
}
export const wsClient: WSClient;
```

**Implementation notes:**
- WS proxy in `frontend/vite.config.ts`: `/ws` → `ws://localhost:8000`
- Check `src/openlabels/server/routes/ws.py` for backend WebSocket protocol
- Subscribe returns an unsubscribe function (used in useEffect cleanup)
- Parse incoming JSON messages and dispatch by `type` field
- Handle reconnection with backoff
- Emit `_connection` events for connection state changes

### Task 1.5: Verify `api/client.ts` Header Bug

Check line 44-47. **Current state appears already fixed** — Content-Type is only set when `body !== undefined` and headers are properly separated from fetchOptions via destructuring. Verify and move on.

Also fix L11: Don't send `Content-Type: application/json` on bodyless GET/DELETE requests (already handled if the fix is in place).

### Verification

```bash
cd frontend
npm install
npm run dev
# Should compile and show the app shell with sidebar navigation
# Pages will show data-loading errors — that's expected at this stage
```

---

## Phase 2: Remove Jinja/HTMX Legacy Frontend (WS2)

### Task 2.1: Delete Web Module

```bash
rm -rf src/openlabels/web/
```

This removes:
- `web/routes.py` (1,944 lines)
- `web/templates/` (30 HTML templates + partials)
- `web/__init__.py`

### Task 2.2: Remove `/ui` Route Mount

In `src/openlabels/server/app.py`, find and remove:
```python
app.include_router(web_router, prefix="/ui", tags=["Web UI"])
```
And the import of `web_router`. Search for any other references to the web module.

### Task 2.3: Remove `htmx_notify()` Helper

In `src/openlabels/server/routes/__init__.py`:
- Remove the `htmx_notify()` function
- Remove it from `__all__`
- Remove `HTMLResponse` import if no longer needed
- Remove `json` import if only used by htmx_notify

### Task 2.4: Strip HTMX Branches from API Routes

These routes dual-path with `if request.headers.get("HX-Request")`. Remove the HTMX branch, keep only the JSON return. Also remove the `Request` parameter if it was only used for the HX-Request check, and remove the `htmx_notify` import.

| File | Endpoints to Clean |
|------|-------------------|
| `routes/scans.py` | `cancel_scan`, `retry_scan` |
| `routes/results.py` | `clear_all_results`, `delete_result`, `apply_recommended_label`, `rescan_file` |
| `routes/labels.py` | Label mappings save endpoint |
| `routes/schedules.py` | Schedule delete |
| `routes/settings.py` | `POST /fanout`, `POST /adapters`, `POST /reset` |
| `routes/targets.py` | Target delete |

**For settings specifically:** Check if `POST /settings/fanout` and `POST /settings/adapters` have JSON return paths. If they ONLY return `HTMLResponse` / `htmx_notify`, convert them to return JSON (e.g., `{"status": "ok", "message": "..."}`).

### Task 2.5: Update SPA Serving

Ensure the React `frontend/dist/` directory is served at `/` with a catch-all that returns `index.html` for client-side routing. Check `server/app.py` for existing SPA mount logic — there's likely already a StaticFiles mount for `/assets`. Add a catch-all route that serves `index.html` for any non-API, non-WS path.

### Verification

```bash
# Backend should start without importing web module
python -m openlabels.server  # or however it starts
# No errors about missing web templates
# API routes still return JSON
# React SPA serves from /
```

---

## Phase 3: API Contract Alignment — All Endpoints (WS3)

Systematically align frontend types with backend Pydantic models. For each endpoint group: read the backend route file, compare with frontend endpoint + types, fix mismatches. **Prefer fixing the frontend** — it's cheaper than redeploying.

### Task 3.1: Dashboard

**Files:** `routes/dashboard.py` ↔ `api/endpoints/dashboard.ts` + `api/types.ts` (DashboardStats)

Compare `OverallStats` Pydantic model field-by-field with `DashboardStats` TypeScript interface. They should both have: `total_scans`, `total_files_scanned`, `files_with_pii`, `labels_applied`, `critical_files`, `high_files`, `medium_files`, `low_files`, `minimal_files`, `active_scans`.

**Then check page components:**
- `stats-cards.tsx` — does it use fields that exist on the type?
- `findings-by-type-chart.tsx` — expects `entity_type_counts` which doesn't exist on `OverallStats`. Check if `/dashboard/entity-distribution` endpoint exists and wire it up, or show placeholder.
- `risk-distribution-chart.tsx` — hardcoded colors (L5), fine for now. Verify data shape.
- `recent-scans-table.tsx` — verify it fetches scan list correctly
- `activity-feed.tsx` — verify it fetches recent events correctly

**Entity trends (H3):** Frontend expects `Record<string, number[]>` → Backend returns `{ series: dict[str, list[tuple[str, int]]], truncated, total_records }`. Fix the frontend `EntityTrendsResponse` type and the chart component that consumes it.

### Task 3.2: Targets

**Files:** `routes/targets.py` ↔ `api/endpoints/targets.ts` + `api/types.ts` (Target)

- Verify field names: `adapter` (not `adapter_type`), `created_at`, `updated_at`
- Read the backend `TargetCreate` Pydantic model and verify the frontend POST payload matches
- Check `form-page.tsx` (743 lines) — verify SOURCE_TYPES/ADAPTER_TYPES mapping works with the constants from Phase 1
- Fix L10: `form.watch('config')` inside `.map()` — extract watched value above the map

### Task 3.3: Scans

**Files:** `routes/scans.py` ↔ `api/endpoints/scans.ts` + `api/types.ts` (ScanJob)

- Verify create sends `{ target_id: string, name?: string }` (singular) → returns single `ScanJob`
- Verify `ScanJob` type fields match: `progress`, `files_scanned`, `files_with_pii`, `error`, timestamps
- Verify cancel endpoint: `POST /scans/{id}/cancel`
- Verify retry endpoint: `POST /scans/{id}/retry`

### Task 3.4: Results

**Files:** `routes/results.py` ↔ `api/endpoints/results.ts` + `api/types.ts` (ScanResult, ScanResultDetail)

- Verify endpoint is `/results/cursor` with cursor pagination params
- Check query param names: frontend sends `scan_id` → backend may expect `job_id`
- Verify `ScanResult` fields match backend response
- Verify `ScanResultDetail` fields — especially: does backend return entities array? findings? policy_violations?
- Check result export: frontend calls `GET /export/results` → backend has `GET /results/export` (inverted path). Fix frontend endpoint.

### Task 3.5: Labels

**Files:** `routes/labels.py` ↔ `api/endpoints/labels.ts` + `api/types.ts` (Label, LabelSyncStatus, LabelMappingsResponse)

- **List:** Verify pagination type matches
- **Sync:** `POST /labels/sync` response — align with actual backend return shape
- **Sync status:** `GET /labels/sync/status` — backend returns `{ label_count, last_synced_at, cache }`. Align `LabelSyncStatus` type.
- **Mappings:** `GET /labels/mappings` — backend returns `{ CRITICAL, HIGH, MEDIUM, LOW, labels }`. Align `LabelMappingsResponse` type.
- **Apply:** `POST /labels/apply` — verify request/response shape

### Task 3.6: Health

**Files:** `routes/health.py` ↔ `api/types.ts` (HealthStatus)

- Backend endpoint is `GET /health/status` (not `GET /health`)
- Backend returns flat fields: `api`, `api_text`, `db`, `db_text`, `queue`, `queue_text`, `ml`, `ml_text`, `mip`, `mip_text`, `ocr`, `ocr_text`, `scans_today`, `files_processed`, `success_rate`, plus optional `circuit_breakers`, `job_metrics`, `python_version`, `platform`, `uptime_seconds`
- Verify `HealthStatus` type matches this flat structure
- Used by: monitoring page (`features/monitoring/page.tsx`), config-resources page (`features/config-resources/page.tsx`)
- Fix monitoring page endpoint call to use correct path

### Task 3.7: Settings

**Files:** `routes/settings.py` ↔ `api/endpoints/settings.ts` + `api/types.ts` (AllSettings, SettingsUpdateResponse)

- Backend: `GET /settings` → `AllSettingsResponse`, `POST /settings/azure`, `POST /settings/scan`, `POST /settings/entities`
- Frontend already has `settingsApi.update(category, settings)` which calls `POST /settings/{category}`
- Verify the category names match backend endpoint paths (`azure`, `scan`, `entities`)
- After Phase 2 cleanup: verify `POST /settings/fanout` and `POST /settings/adapters` still exist as JSON endpoints. If removed, either restore them as JSON-only or update frontend to use different endpoints.
- The `AllSettings` type should match `AllSettingsResponse` from backend

### Task 3.8: Browse

**Files:** `routes/browse.py` ↔ `api/endpoints/browse.ts` + `api/types.ts` (BrowseResponse, BrowseFolder, BrowseFile, BrowseFilesResponse)

- **Critical mismatch (H10, H11):** Frontend sends `?path=<string>` → Backend expects `?parent_id=<UUID>`
- Frontend expects flat array → Backend returns wrapped `BrowseResponse { target_id, parent_id, parent_path, folders, total }`
- Field names differ: `path` → `dir_path`, `name` → `dir_name`
- Read the backend browse route carefully. Decide: adapt frontend to use `parent_id` navigation (requires changing `FolderTreePanel` and all consumers), OR add a path-based lookup on the backend
- **Used by:** resource-explorer page, events page (FolderTreePanel), permissions page

### Task 3.9: Permissions

**Files:** `routes/permissions.py` ↔ `api/endpoints/permissions.ts` + `api/types.ts` (ExposureSummary, DirectoryACL, etc.)

- Exposure summary (H5): Frontend expects `{ PUBLIC, ORG_WIDE, INTERNAL, PRIVATE }` → Backend returns `{ total_directories, with_security_descriptor, world_accessible, authenticated_users, custom_acl, private }`
- Align `ExposureSummary` type with backend model
- Directory field names: `path` → `dir_path`, `name` → `dir_name`, `children_count` → `child_dir_count + child_file_count`

### Task 3.10: Remediation

**Files:** `routes/remediation.py` ↔ `api/endpoints/remediation.ts` + `api/types.ts` (RemediationAction)

- Field names (H9): `file_path` → `source_path`, missing `performed_by`/`details` on backend
- Rollback URL (H8): Frontend sends `POST /{actionId}/rollback` → Backend expects `POST /rollback` with `{ action_id, dry_run }` body
- Quarantine (H9): Frontend sends `reason` → Backend expects `quarantine_dir`
- Lockdown (H9): Frontend sends `principals` → Backend expects `allowed_principals`
- Fix the endpoint file and page component to use correct field names and URL patterns

### Task 3.11: Events / Audit

**Files:** `routes/monitoring.py` ↔ `api/endpoints/events.ts`

- Frontend calls `GET /audit/events` → Actual path is `GET /monitoring/events` (H12)
- Cursor pagination variant at `GET /monitoring/events/cursor`
- Query params: Frontend sends `start_date`/`end_date` → Backend accepts `since`
- Fix endpoint URL and query param names
- Also check `api/endpoints/audit.ts` for overlap — may need to consolidate with events endpoint

### Task 3.12: Monitoring / Jobs

**Files:** `routes/health.py`, `routes/jobs.py`, `routes/monitoring.py` ↔ `api/endpoints/monitoring.ts`, `api/endpoints/jobs.ts`

- Frontend calls `GET /monitoring/jobs` → Actual path is `GET /jobs` or `GET /jobs/stats`
- Deduplicate: `jobs.ts` `stats()` duplicates `monitoring.ts` `jobQueue()` (L2)
- Deduplicate: `monitoring.ts` `activityLog()` duplicates `audit.ts` `list()` (L2)
- Consolidate into one clean set of endpoint calls

### Task 3.13: Remaining Endpoints

**Schedules:** `routes/schedules.py` ↔ `api/endpoints/schedules.ts` — verify CRUD and field names
**Policies:** `routes/policies.py` ↔ `api/endpoints/policies.ts` — verify CRUD and field names
**Users:** `routes/users.py` ↔ `api/endpoints/users.ts` — verify CRUD and field names
**Query:** `routes/query.py` ↔ `api/endpoints/query.ts` — verify SQL execution endpoint
**Export:** Fix URL inversion: `GET /export/results` → `GET /results/export`
**Reporting:** Fix: `GET /reporting/{id}/export` → `GET /reporting/{id}/download`
**Export client (H13):** `api/endpoints/export.ts` has custom `fetchBlob()` that bypasses `apiFetch`. Rewrite to use `apiFetch` with proper error handling, or at minimum ensure it handles 401 correctly.
**Credentials:** `routes/credentials.py` ↔ `api/endpoints/credentials.ts` — verify if used
**Enumerate:** `routes/enumerate.py` ↔ `api/endpoints/enumerate.ts` — verify if used

### Verification

```bash
# Start backend + frontend dev server
# Open browser devtools Network tab
# Navigate to every page and check:
# - No 404 responses
# - No 422 validation errors
# - Response bodies parse correctly (no undefined fields in console)
```

---

## Phase 4: Core Workflow Integration Test (WS4)

Walk the primary user journey end-to-end. This surfaces integration bugs that static contract alignment misses.

### Task 4.1: Create Filesystem Target

1. Navigate to `/targets/new`
2. Select filesystem adapter
3. Point at a test directory (create one with a few text files containing PII patterns)
4. Submit form
5. **Verify:** Target appears in `/targets` list with correct adapter label

### Task 4.2: Trigger Scan

1. From scans page or target detail, create a new scan
2. **Verify:** Scan appears in `/scans` list with `pending` status
3. **Debug if stuck:** Check job queue pickup — does the worker process see the job?

### Task 4.3: Watch Scan Progress

1. Open scan detail page (`/scans/:id`)
2. **Verify:** Progress updates via WebSocket
3. **Debug WebSocket flow:** Backend `ws_events.py` → event type strings → frontend `useWebSocketSync` subscriptions
4. **Verify:** `scan_progress`, `scan_completed`, `scan_failed` events match between backend and frontend

### Task 4.4: View Results

1. After scan completes, navigate to `/results`
2. **Verify:** Results list populates with cursor pagination
3. **Verify:** Risk tier filter works
4. Click a result → detail page
5. **Verify:** Entity counts, risk score, label recommendation display

### Task 4.5: Verify Dashboard

1. Navigate to `/dashboard`
2. **Verify:** Stats cards show numbers from the scan
3. **Verify:** Charts render (risk distribution, recent scans)

**Fix L10 here:** `form.watch('config')` in targets `form-page.tsx` — extract watched value above the `.map()` call.

---

## Phase 5: Labels + MIP Integration (WS5)

### Task 5.1: Label Sync

1. Navigate to `/labels/sync`
2. If Azure AD configured: trigger sync, verify labels populate
3. If no Azure AD: create mock/seed data:
   - Insert labels directly into DB
   - OR add a `--seed-labels` CLI command that creates sample labels
   - Labels needed: "Public", "General", "Confidential", "Highly Confidential", "Restricted"

### Task 5.2: Label Mappings

1. Navigate to `/labels` → mappings section
2. Configure risk tier → label mapping (e.g., CRITICAL → "Highly Confidential", HIGH → "Confidential")
3. **Verify:** Mappings save via `POST /labels/mappings`

### Task 5.3: Label Recommendations in Results

1. Navigate to results from Phase 4 scan
2. **Verify:** Results show `recommended_label_name` based on risk tier → mapping
3. **Verify:** Detail page shows current label vs recommended label

### Task 5.4: Label Application

1. From result detail, apply recommended label
2. **Verify:** Labeling engine path is correct:
   - Filesystem target → tries MIP SDK → falls back to Office metadata / PDF metadata / sidecar
   - SharePoint target → Graph API
3. **Verify:** Result record updates with `label_applied: true`

---

## Phase 6: Resource Explorer + Events + Permissions (WS6)

### Task 6.1: Fix FolderTreePanel

**File:** `frontend/src/components/folder-tree.tsx`

This component is shared by resource-explorer, events, and permissions pages. Fix it to work with the backend browse API:
- Use `parent_id` (UUID) navigation instead of `path` (string)
- Handle `BrowseResponse` wrapper (extract `folders` array)
- Map backend field names: `dir_path`, `dir_name`, `child_dir_count`, `child_file_count`

### Task 6.2: Resource Explorer Page

**File:** `frontend/src/features/resource-explorer/page.tsx`

1. Folder tree navigation works
2. File list loads for selected folder (uses `browseApi.files()` or similar)
3. Risk badges display on files
4. File detail cards show entity counts

### Task 6.3: Permissions Page

**File:** `frontend/src/features/permissions/page.tsx`

1. Exposure summary stats render with correct field names
2. Directory ACL browser works with tree navigation
3. Security descriptor details display

### Task 6.4: Events Page

**File:** `frontend/src/features/events/page.tsx`

1. FolderTreePanel works for folder selection
2. Fix event query: endpoint should be `GET /monitoring/events` with `since` param
3. Live events via WebSocket (`wsClient.subscribe('file_access', ...)`)
4. Fix M1: Use `crypto.randomUUID()` for live event IDs instead of `Date.now()`
5. Fix M2: Deduplicate live events against API events by ID

---

## Phase 7: Remediation Workflow (WS7)

### Task 7.1: Fix Endpoint Contract

**Files:** `api/endpoints/remediation.ts`, `features/remediation/page.tsx`

- Quarantine request: send `quarantine_dir` not `reason`
- Lockdown request: send `allowed_principals` not `principals`
- Rollback: change from `POST /{actionId}/rollback` to `POST /rollback` with body `{ action_id, dry_run }`
- Display: use `source_path` not `file_path`

### Task 7.2: Test Full Flow

1. From a result, initiate quarantine
2. Verify file moves to quarantine directory
3. View remediation action in `/remediation` list
4. Rollback the quarantine
5. Verify file restored

### Task 7.3: Fix Cache Invalidation (M8)

In `api/hooks/use-remediation.ts`, rollback mutation should invalidate both `['remediation']` AND `['results']`.

---

## Phase 8: Scheduling + Scan Config (WS8)

### Task 8.1: Schedules CRUD

**Files:** `features/schedules/list-page.tsx`, `features/schedules/form-page.tsx`

1. List page loads schedules
2. Create new schedule with cron expression
3. `describeCron()` from `lib/date.ts` shows human-readable description
4. Edit existing schedule
5. Delete schedule (fix L1: use ConfirmDialog instead of `confirm()`)

### Task 8.2: Fix `useSchedule('')` Guard (M3)

In schedule and target form pages, ensure hooks have `enabled: !!id` guard when creating new entities (id is empty string).

### Task 8.3: Scan Config Page

**File:** `features/scan-config/page.tsx`, `features/scan-config/form-page.tsx`

1. Combo view: schedules list + scan settings
2. Settings section: max file size, concurrent files, OCR toggle, ML toggle
3. Verify settings save to correct backend endpoints

---

## Phase 9: Monitoring + System Health (WS9)

### Task 9.1: Health Status

**File:** `features/monitoring/page.tsx`

1. Fix endpoint path to `GET /health/status`
2. Render flat field structure: iterate over component pairs (api/api_text, db/db_text, etc.)
3. Fix M5: `healthColor[status]` — add fallback for unknown status values

### Task 9.2: Job Queue Stats

1. Fix endpoint: `GET /jobs/stats` (not `GET /monitoring/jobs`)
2. Display pending, running, completed, failed counts

### Task 9.3: Activity Log

1. Fix endpoint path (consolidate with audit/events)
2. Fix M6: Restore pagination setter — change `const [activityPage] = useState(1)` to `const [activityPage, setActivityPage] = useState(1)`
3. Add pagination controls

### Task 9.4: Deduplicate Endpoints (L2)

- Remove `jobs.ts` `stats()` if it duplicates `monitoring.ts` `jobQueue()`
- Remove `monitoring.ts` `activityLog()` if it duplicates `audit.ts` `list()`
- Update all consumers to use the canonical endpoint

### Task 9.5: Config Resources Page

**File:** `features/config-resources/page.tsx`

1. Targets table renders
2. Health panel renders with flat field structure
3. Tabs work correctly

---

## Phase 10: Policies + Reports + Users (WS10)

### Task 10.1: Policies Page

**File:** `features/policies/list-page.tsx`

1. CRUD works
2. Fix M7: Add `onError` callbacks to `createPolicy` and `deletePolicy` mutations
3. Fix L1: Replace `confirm()` with `ConfirmDialog` component
4. Fix M16: Wrap `columns` array in `useMemo`

### Task 10.2: Reports Page

**File:** `features/reports/page.tsx`

1. SQL query execution works (verify endpoint)
2. Fix H13: Rewrite export to use `apiFetch` instead of custom `fetchBlob()`
3. Fix M15: Quote CSV column headers that contain commas
4. Fix L6: Change default query from `SELECT * FROM scan_results LIMIT 100` to something less schema-coupled

### Task 10.3: Users Page

**File:** `features/users/page.tsx`

1. User list loads
2. User CRUD works
3. Role badges display correctly

### Task 10.4: Fix Column Re-renders (M16)

In ALL list pages that define `columns` inside the component body, wrap in `useMemo`:
- `schedules/list-page.tsx`
- `policies/list-page.tsx`
- Any others found

---

## Phase 11: Settings Page (WS11)

### Task 11.1: Fix Architecture

**File:** `features/settings/page.tsx`

1. Verify `GET /settings` returns `AllSettings` shape
2. Verify category-based saves: `POST /settings/azure`, `POST /settings/scan`, `POST /settings/entities`
3. After Phase 2 cleanup: check if fanout/adapters settings endpoints still exist. If not, either restore as JSON or integrate into the `scan` category.

### Task 11.2: Fix Input Controls (M4)

Replace uncontrolled `defaultValue` inputs with controlled `value` + `onChange` pattern. Settings should re-render when backend data changes (e.g., after save + refetch).

### Task 11.3: Verify All Categories

Walk through each tab:
- **Azure AD:** tenant_id, client_id, client_secret (masked)
- **Scan:** max_file_size_mb, concurrent_files, enable_ocr, enable_ml
- **Entities:** enabled_entities list
- **Performance/Fanout:** fanout_enabled, fanout_threshold, fanout_max_partitions, pipeline settings

---

## Phase 12: Auth + Setup Wizard (WS12)

### Task 12.1: Login Flow

1. Navigate to `/login`
2. Verify OAuth redirect to `/api/v1/auth/login`
3. Verify callback handling
4. Verify session + CSRF token are set

### Task 12.2: Fix Auth Guard (M10)

**File:** `components/layout/auth-guard.tsx`

Currently, ANY failure in `checkAuth()` (including network timeout) redirects to login. Fix to distinguish:
- 401 response → redirect to login
- Network error / timeout → show error state, don't redirect

### Task 12.3: Setup Wizard

**File:** `features/setup/wizard-page.tsx`

1. First-run detection works
2. Azure AD configuration step (or skip)
3. First target creation step
4. First scan trigger step
5. Completion → redirect to dashboard

### Task 12.4: CSRF Flow

Verify CSRF token handling across all mutating requests:
- Token read from cookie (`openlabels_csrf`)
- Sent as `X-CSRF-Token` header on POST/PUT/DELETE/PATCH
- Backend validates and returns 403 on mismatch

---

## Phase 13: Polish + Quality (WS13)

### Task 13.1: Error States (L12)

Audit every page. Replace `data ? <Content> : null` with:
```tsx
if (query.isError) return <ErrorBoundary message={query.error.message} />;
if (query.isLoading) return <LoadingSkeleton />;
if (!query.data) return <EmptyState ... />;
```

Pages that need this treatment (check each one):
- All list pages (targets, scans, results, schedules, policies, users, remediation)
- All detail pages (scan detail, result detail)
- Dashboard widgets
- Monitoring sections

### Task 13.2: Accessibility (M11-M14)

**M11 — Keyboard accessible table rows:**
In `components/data-table/data-table.tsx`, for rows with `onRowClick`:
```tsx
tabIndex={0}
role="button"
onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onRowClick(row); }}
```

**M12 — Delete button labels:**
In all pages with trash icon buttons, add `aria-label={`Delete ${item.name}`}`:
- `policies/list-page.tsx`
- `schedules/list-page.tsx`
- `targets/list-page.tsx`

**M13 — Filter input labels:**
Add `<label>` elements or `aria-label` to filter inputs in:
- `events/page.tsx`
- `results/list-page.tsx`
- `permissions/page.tsx`

**M14 — Toast roles:**
In `components/layout/toast-container.tsx`: Use `role="status"` for info/success toasts, `role="alert"` only for error/warning toasts. Remove contradictory `aria-live="polite"` when using `role="alert"`.

### Task 13.3: Cache Invalidation Gaps

**M8:** In `api/hooks/use-remediation.ts`, rollback `onSuccess` should add:
```typescript
queryClient.invalidateQueries({ queryKey: ['results'] });
```

**M9:** In `api/hooks/use-scans.ts`, `cancelScan` `onSuccess` should add:
```typescript
queryClient.invalidateQueries({ queryKey: ['dashboard'] });
```

### Task 13.4: Remaining Code Quality

- **L1:** Replace all `confirm()` calls with `ConfirmDialog` component (policies, schedules, targets)
- **L2:** Already handled in Phase 9 (endpoint deduplication)
- **L3:** Change `Partial<T>` update types to `Omit<Partial<T>, 'id' | 'tenant_id' | 'created_at'>` in policies, schedules, targets endpoint files
- **L4:** Remove redundant query invalidations (invalidating `['key']` already covers `['key', id]`)
- **L5:** Hardcoded chart colors — leave for now unless theming is needed
- **L7:** Make toast auto-dismiss configurable: error toasts should stay longer (8-10s) vs info (5s)
- **L8:** Create `frontend/src/vite-env.d.ts`:
  ```typescript
  /// <reference types="vite/client" />
  interface ImportMetaEnv {
    readonly VITE_API_URL: string;
  }
  ```
- **L9:** Fix ESLint config `ecmaVersion` from 2020 to 2022 to match build target

---

## Phase 14: Test Data + Demo Prep (WS14)

### Task 14.1: Seed Script

Create `scripts/seed_demo_data.py`:

```
/tmp/openlabels-demo/
├── hr/
│   ├── employee_roster.csv          # Names, SSNs, DOBs, addresses
│   ├── benefits_enrollment.txt      # Insurance IDs, dependents
│   └── performance_reviews.docx     # Names, employee IDs
├── finance/
│   ├── expense_reports.csv          # Credit card numbers, amounts
│   ├── vendor_payments.txt          # Bank routing numbers, EINs
│   └── tax_forms.pdf                # SSNs, addresses, income
├── clinical/
│   ├── patient_intake.txt           # MRNs, diagnosis codes, DOBs
│   ├── lab_results.csv              # Patient names, test results
│   ├── discharge_summary.txt        # Full SOAP-note-style PHI
│   └── insurance_claims.csv         # Insurance IDs, procedure codes
├── legal/
│   ├── client_contacts.csv          # Names, emails, phones
│   ├── case_notes.txt               # Client names, case numbers
│   └── retainer_agreement.txt       # Addresses, bank details
├── clean/
│   ├── company_handbook.txt         # No PII
│   ├── meeting_notes.txt            # No PII
│   └── project_plan.csv             # No PII
```

Mix entity density: clean files (0 entities), light (1-5), moderate (5-15), heavy (20+).
Use realistic but synthetic data — never real PII.

### Task 14.2: Demo Walkthrough Document

Write `docs/DEMO_WALKTHROUGH.md` with the 5-minute story:
1. Show the file share (seed data)
2. Create filesystem target
3. Run scan → watch progress
4. View results → risk tiers → entity types
5. Sync labels → configure mappings
6. Apply labels → show metadata written
7. Dashboard → full picture
8. Pitch: "E3 customers get auto-labeling without the $42K/year upgrade"

### Task 14.3: README Screenshots

After demo works, capture screenshots of:
- Dashboard with data
- Results list with risk tiers
- Result detail with entities
- Labels page with mappings
- Scan in progress

---

## Phase 15: OpenAPI Type Generation (WS15)

### Task 15.1: Export OpenAPI Spec

FastAPI auto-generates an OpenAPI spec. Access it at `/api/v1/openapi.json` (or wherever it's mounted). Save it.

### Task 15.2: Set Up Codegen

```bash
cd frontend
npm install -D openapi-typescript
```

Add to `package.json` scripts:
```json
"generate-types": "openapi-typescript http://localhost:8000/api/v1/openapi.json -o src/api/generated-types.ts"
```

### Task 15.3: Replace Hand-Maintained Types

1. Generate types
2. Compare generated types with hand-maintained `api/types.ts`
3. Gradually replace imports — start with the most-used types
4. Keep `api/types.ts` for any frontend-only types (like `WSEvent`, `WSFileAccess`, etc.)

### Task 15.4: CI Integration

Add type generation check to CI/pre-commit:
```bash
# Generate and diff — fail if types have drifted
npm run generate-types
git diff --exit-code src/api/generated-types.ts
```

---

## File Reference — All Backend ↔ Frontend Mappings

| Area | Backend Route File | Frontend Endpoint | Frontend Types |
|------|-------------------|-------------------|----------------|
| Dashboard | `server/routes/dashboard.py` | `api/endpoints/dashboard.ts` | `DashboardStats` |
| Targets | `server/routes/targets.py` | `api/endpoints/targets.ts` | `Target` |
| Scans | `server/routes/scans.py` | `api/endpoints/scans.ts` | `ScanJob`, `ScanProgress` |
| Results | `server/routes/results.py` | `api/endpoints/results.ts` | `ScanResult`, `ScanResultDetail`, `DetectedEntity` |
| Labels | `server/routes/labels.py` | `api/endpoints/labels.ts` | `Label`, `LabelSyncStatus`, `LabelMappingsResponse` |
| Health | `server/routes/health.py` | (via monitoring hooks) | `HealthStatus` |
| Settings | `server/routes/settings.py` | `api/endpoints/settings.ts` | `AllSettings`, `SettingsUpdateResponse` |
| Browse | `server/routes/browse.py` | `api/endpoints/browse.ts` | `BrowseResponse`, `BrowseFolder`, `BrowseFile` |
| Permissions | `server/routes/permissions.py` | `api/endpoints/permissions.ts` | `ExposureSummary`, `DirectoryACL`, `DirectoryEntry` |
| Remediation | `server/routes/remediation.py` | `api/endpoints/remediation.ts` | `RemediationAction` |
| Events | `server/routes/monitoring.py` | `api/endpoints/events.ts` | `FileAccessEvent` |
| Jobs | `server/routes/jobs.py` | `api/endpoints/jobs.ts` | `JobInfo`, `JobQueueStats` |
| Monitoring | `server/routes/monitoring.py` | `api/endpoints/monitoring.ts` | `AuditLogEntry` |
| Policies | `server/routes/policies.py` | `api/endpoints/policies.ts` | `Policy`, `PolicyRule` |
| Schedules | `server/routes/schedules.py` | `api/endpoints/schedules.ts` | `Schedule` |
| Users | `server/routes/users.py` | `api/endpoints/users.ts` | `User` |
| Query | `server/routes/query.py` | `api/endpoints/query.ts` | `QuerySchema`, `QueryResult`, `AIQueryResponse` |
| Export | `server/routes/export.py` | `api/endpoints/export.ts` | (blob download) |
| Reporting | `server/routes/reporting.py` | (via export) | (blob download) |
| Audit | `server/routes/audit.py` | `api/endpoints/audit.ts` | `AuditLogEntry` |
| Auth | `server/routes/auth.py` | (redirect-based) | `User` |
| Credentials | `server/routes/credentials.py` | `api/endpoints/credentials.ts` | (varies) |
| Enumerate | `server/routes/enumerate.py` | `api/endpoints/enumerate.ts` | (varies) |
| WebSocket | `server/routes/ws.py`, `ws_events.py` | `lib/websocket.ts` | `WSEvent`, `WSScanProgress`, etc. |

---

## Architecture Notes

- **API prefix:** All routes under `/api/v1/`. Frontend `apiFetch` prepends this.
- **Auth:** OAuth2 via Azure AD. Session-based with CSRF tokens. Login redirect at `/api/v1/auth/login`.
- **WebSocket:** Mounted at `/ws` (not versioned). Proxy in vite.config.ts.
- **Jinja/HTMX is being removed** (Phase 2). After removal, only React SPA remains.
- **DB:** PostgreSQL with async SQLAlchemy. Models in `server/models.py`.
- **Job queue:** PostgreSQL-based (no Redis/RabbitMQ). Jobs in `jobs/` module.
- **Detection engine:** Multi-tier pipeline — regex, checksums, ML (GLiNER, ONNX), Rust acceleration (Hyperscan). In `core/` module.
- **Labeling engine:** Three-tier — MIP SDK via pythonnet (Windows), Graph API (SharePoint/OneDrive), metadata fallback (Office XML, PDF, sidecar). In `labeling/` module.
- **Route prefixes:** Routes are mounted in `server/app.py` → `_ROUTE_MODULES` list. Each gets `/api/v1/{prefix}`.
