# Frontend Architecture Review

**Date:** 2026-02-12
**Scope:** Frontend code, backend API routes, architecture docs, cross-cutting consistency
**Files Reviewed:** ~90 frontend source files, ~25 backend route files, 8 architecture docs

---

## Executive Summary

The frontend is a well-structured React 19 SPA using modern tooling (Vite, TanStack Query, Zustand, Radix UI, Tailwind CSS 4). The architecture follows good separation of concerns with a clean API layer, feature-based organization, and proper lazy loading. However, this review uncovered **critical blockers** that prevent the application from compiling, along with **pervasive API contract mismatches** between the frontend TypeScript types and the backend Pydantic models. These must be resolved before the frontend can function.

### Issue Count Summary

| Severity | Count | Description |
|----------|-------|-------------|
| **CRITICAL** | 4 | Build blockers and fundamental API incompatibilities |
| **HIGH** | 14 | Wrong URL paths, wrong response structures, field name mismatches |
| **MEDIUM** | 16 | Missing error handling, accessibility gaps, logic bugs |
| **LOW** | 12 | Code quality, hardcoded values, minor inconsistencies |

---

## CRITICAL Issues (Build Blockers)

### C1. Missing `src/lib/` directory — application cannot compile

The entire `frontend/src/lib/` directory is missing. **55+ import statements** across virtually every component and page reference four modules that do not exist:

- `@/lib/utils.ts` — `cn()`, `formatRelativeTime`, `formatNumber`, `truncatePath` (imported by 20+ files)
- `@/lib/websocket.ts` — `wsClient` singleton (imported by 3 files)
- `@/lib/constants.ts` — `STATUS_COLORS`, `RISK_COLORS`, `RISK_TIERS`, `NAV_GROUPS`, `ADAPTER_TYPES`, `ADAPTER_LABELS`, `EXPOSURE_LEVELS`, type exports (imported by 12+ files)
- `@/lib/date.ts` — `formatDateTime`, `formatDuration`, `describeCron` (imported by 5+ files)

**Impact:** `npm run build`, `npm run dev`, and `tsc` all fail. No page can render.

**Action:** Create all four modules with the expected exports.

### C2. Scan creation request body does not match backend

| | Frontend | Backend |
|--|----------|---------|
| **Request** | `{ target_ids: string[] }` | `ScanCreate { target_id: UUID, name?: str }` |
| **Response** | `ScanJob[]` (array) | `ScanResponse` (single object) |

The frontend sends `target_ids` (plural array); the backend expects `target_id` (singular UUID). The frontend expects an array response; the backend returns a single object. Both the request and response are incompatible — scan creation will fail with a 422 validation error.

**File:** `frontend/src/api/endpoints/scans.ts:12`

### C3. Results list uses wrong pagination model and wrong endpoint

The frontend calls `GET /results` expecting `CursorPaginatedResponse` with `cursor`, `scan_id`, `entity_type`, `search` query params. The backend:
- Returns `PaginatedResponse` (offset-based) at `GET /results`
- The cursor-based endpoint is at `GET /results/cursor`
- Accepts `job_id` (not `scan_id`), `risk_tier` (not `entity_type`/`search`)

**File:** `frontend/src/api/endpoints/results.ts:4-8`

### C4. Seven API endpoints hit wrong URL paths (404 errors)

| Frontend URL | Actual Backend URL | Issue |
|---|---|---|
| `GET /health` | `GET /health/status` | Missing `/status` |
| `GET /monitoring/jobs` | `GET /jobs` or `GET /jobs/stats` | Wrong router prefix |
| `GET /audit/events` | `GET /monitoring/events` | Wrong router entirely |
| `GET /export/results` | `GET /results/export` | Inverted path segments |
| `GET /reporting/{id}/export` | `GET /reporting/{id}/download` | `/export` vs `/download` |
| `GET /settings/{key}` | _(does not exist)_ | No per-key endpoint |
| `PUT /settings/{key}` | `POST /settings/azure`, etc. | Wrong method + path structure |

---

## HIGH Issues (Runtime Failures)

### H1. Response type mismatches — every major entity has field name drift

The frontend TypeScript interfaces diverge significantly from backend Pydantic response models. Key patterns:

**Scan fields:**
| Frontend Field | Backend Field |
|---|---|
| `target_name` | `name` |
| `error_message` | `error` |
| `files_skipped` | _(missing)_ |
| `created_by` | _(missing)_ |
| `tenant_id` | _(missing)_ |

**Result fields:**
| Frontend Field | Backend Field |
|---|---|
| `scan_id` | `job_id` |
| `entities: DetectedEntity[]` | _(missing)_ |
| `labels: string[]` | `current_label_name`, `recommended_label_name`, `label_applied` |
| `adapter_type` | _(missing)_ |
| `target_name` | _(missing)_ |

**Target fields:**
| Frontend Field | Backend Field |
|---|---|
| `adapter_type` | `adapter` |
| `created_at` | _(missing)_ |
| `updated_at` | _(missing)_ |

**Permissions directory fields:**
| Frontend Field | Backend Field |
|---|---|
| `path` | `dir_path` |
| `name` | `dir_name` |
| `children_count` | `child_dir_count` + `child_file_count` |
| `is_directory` | _(missing)_ |

**Remediation fields:**
| Frontend Field | Backend Field |
|---|---|
| `file_path` | `source_path` |
| `performed_by` | _(missing)_ |
| `details` | _(missing)_ |

### H2. Dashboard stats response structure mismatch

Frontend expects:
```typescript
{ total_files_scanned, total_findings, critical_findings, active_scans,
  risk_breakdown: Record<string, number>, entity_type_counts: Record<string, number> }
```

Backend returns:
```python
{ total_scans, total_files_scanned, files_with_pii, labels_applied, active_scans,
  critical_files, high_files, medium_files, low_files, minimal_files }
```

`total_findings`, `critical_findings`, `risk_breakdown`, and `entity_type_counts` don't exist on the backend. Individual `*_files` fields aren't consumed by the frontend.

### H3. Entity trends response structure mismatch

Frontend expects `Record<string, number[]>`. Backend returns `{ series: dict[str, list[tuple[str, int]]], truncated, total_records }`. The data is nested under `series` and contains tuples of `(date, count)`, not plain number arrays.

### H4. Label endpoints have completely different response shapes

- **Label sync** (`POST /labels/sync`): Frontend expects `LabelSync { id, status, labels_synced, labels_failed, started_at, completed_at }`. Backend returns ad-hoc dict from service.
- **Sync status** (`GET /labels/sync/status`): Frontend expects `LabelSync`. Backend returns `{ label_count, last_synced_at, cache }`.
- **Mappings** (`GET /labels/mappings`): Frontend expects `Array<{ label_name, risk_tier }>`. Backend returns `{ CRITICAL, HIGH, MEDIUM, LOW, labels }`.

### H5. Exposure summary structure mismatch

Frontend expects `{ PUBLIC, ORG_WIDE, INTERNAL, PRIVATE }` (4 exposure levels as keys).
Backend returns `{ total_directories, with_security_descriptor, world_accessible, authenticated_users, custom_acl, private }` (directory-level security stats).

### H6. Health status response structure mismatch

Frontend expects `{ status, components: Record<string, ComponentHealth>, uptime_seconds }`.
Backend returns flat fields: `{ api, api_text, db, db_text, queue, queue_text, ml, ml_text, ... scans_today, files_processed, success_rate }`.

### H7. Settings endpoint architecture mismatch

Frontend assumes a key-value store pattern (`GET /settings` → `Setting[]`, `GET /settings/{key}`, `PUT /settings/{key}`).
Backend uses structured sub-endpoints (`GET /settings` → `AllSettingsResponse`, `POST /settings/azure`, `POST /settings/scan`, `POST /settings/entities`).

### H8. Remediation rollback URL mismatch

Frontend: `POST /remediation/{actionId}/rollback` (action ID in path, no body).
Backend: `POST /remediation/rollback` (action ID in request body as `RollbackRequest { action_id, dry_run }`).

### H9. Remediation request field name mismatches

- Quarantine: Frontend sends `reason`; backend expects `quarantine_dir`
- Lockdown: Frontend sends `principals`; backend expects `allowed_principals`

### H10. Browse endpoint query param mismatch

Frontend sends `?path=<string>`. Backend expects `?parent_id=<UUID>`. Completely different parameter semantics — path-based vs ID-based navigation.

### H11. Browse response wrapper mismatch

Frontend expects `DirectoryEntry[]` (flat array). Backend returns `BrowseResponse { target_id, parent_id, parent_path, folders: BrowseFolder[], total }` (wrapped object). Field names also differ (`path` vs `dir_path`, `name` vs `dir_name`).

### H12. Events endpoint — wrong router and wrong pagination

Frontend calls `GET /audit/events` with cursor pagination. The endpoint is actually `GET /monitoring/events` with offset pagination (cursor variant at `GET /monitoring/events/cursor`). Query params also differ: frontend sends `start_date`/`end_date`; backend accepts `since`.

### H13. Export endpoints — client bypasses auth handling

`frontend/src/api/endpoints/export.ts` implements its own `fetchBlob()` function instead of using the shared `apiFetch` client. This bypasses:
- 401 auto-redirect to login
- `ApiError` class (throws generic `Error` instead)
- Credential inclusion (though it does use `credentials: 'include'`)

### H14. Header merging bug in API client

`frontend/src/api/client.ts:44-47`: The header merge pattern is:
```typescript
headers: { 'Content-Type': 'application/json', ...fetchOptions.headers },
...fetchOptions,  // ← this re-spreads fetchOptions.headers, overwriting the merged object
```
The second spread of `fetchOptions` overwrites the `headers` key with the original un-merged headers, silently dropping `Content-Type: application/json` when custom headers are provided.

---

## MEDIUM Issues (Functional Bugs & UX Problems)

### M1. Duplicate live event IDs (`features/events/page.tsx:39`)

Live events use `id: live-${Date.now()}`. Two events arriving in the same millisecond get the same ID, causing React key collisions and incorrect DOM updates.

### M2. No deduplication between live and API events (`features/events/page.tsx:49-52`)

`allEvents` is `[...liveEvents, ...apiEvents]` with no deduplication. When the API refetches, events that arrived live and were persisted appear twice.

### M3. `useSchedule('')` and `useTarget('')` on create pages

`features/schedules/form-page.tsx:28` and `features/targets/form-page.tsx:56` call hooks with empty string when creating new entities. If hooks lack `enabled: !!id` guards, this fires invalid API requests.

### M4. Settings inputs use `defaultValue` — won't update on data refetch

`features/settings/page.tsx:42-53`: Uncontrolled inputs with `defaultValue` don't re-render when backend data changes, showing stale values.

### M5. `healthColor` lookup can produce `undefined` CSS class

`features/monitoring/page.tsx:40`: `healthColor[status]` returns `undefined` for unexpected status values, injecting the literal string "undefined" as a CSS class.

### M6. Monitoring activity page has no pagination controls

`features/monitoring/page.tsx:13`: `const [activityPage] = useState(1)` — setter is destructured away, so pagination is non-functional.

### M7. Missing `onError` handlers on policy mutations

`features/policies/list-page.tsx:28-45`: `createPolicy` and `deletePolicy` mutations have no `onError` callback. Failed mutations produce no user-visible feedback.

### M8. `useRollback` doesn't invalidate results queries

`api/hooks/use-remediation.ts:33-40`: Quarantine and lockdown invalidate `['results']`, but rollback only invalidates `['remediation']`. After rollback, result data shows stale remediation status.

### M9. `useCancelScan` doesn't invalidate dashboard

`api/hooks/use-scans.ts:39-42`: Creating a scan invalidates `['dashboard']`, but cancelling doesn't, leaving `active_scans` count stale.

### M10. Auth redirect doesn't distinguish auth failure from network error

`components/layout/auth-guard.tsx:14`: Any failure in `checkAuth()` (including network timeout) redirects to login, even when the user is authenticated.

### M11. Clickable table rows not keyboard accessible

`components/data-table/data-table.tsx:107-114`: Rows with `onRowClick` have no `tabIndex`, `role`, or `onKeyDown`. Keyboard users can't activate them.

### M12. Icon-only delete buttons missing `aria-label`

`features/policies/list-page.tsx:56-63`, `features/schedules/list-page.tsx:32-47`, `features/targets/list-page.tsx:31-46`: Trash icon buttons have no accessible label.

### M13. Filter inputs missing accessible labels

`features/events/page.tsx:59-60`, `features/results/list-page.tsx:78`, `features/permissions/page.tsx:122-126`: Inputs use `placeholder` as the only label, which disappears on focus.

### M14. Toast `role="alert"` + `aria-live="polite"` is contradictory

`components/layout/toast-container.tsx:32`: `role="alert"` implies `aria-live="assertive"`, overriding the explicit `polite`. Use `role="status"` for info/success toasts.

### M15. CSV export doesn't escape column headers

`features/reports/page.tsx:40`: Column headers are `.join(',')`-ed without quoting. Headers containing commas produce malformed CSV.

### M16. `columns` array defined inside component body causes re-renders

`features/schedules/list-page.tsx:20-48`, `features/policies/list-page.tsx:47-64`: New column reference on every render causes TanStack Table to re-initialize state. Should use `useMemo`.

---

## LOW Issues (Code Quality)

### L1. `confirm()` used for destructive actions

`features/policies/list-page.tsx:59`, `features/schedules/list-page.tsx:38`, `features/targets/list-page.tsx:37`: Browser `confirm()` is inconsistent with the app's custom Dialog component and can't be styled.

### L2. Duplicate API endpoint definitions

- `jobs.ts` `stats()` duplicates `monitoring.ts` `jobQueue()` (both call `/monitoring/jobs`)
- `monitoring.ts` `activityLog()` duplicates `audit.ts` `list()` (both call `/audit`)

### L3. `Partial<T>` update types include server-generated fields

`policies.ts:14`, `schedules.ts:14`, `targets.ts:14`: Update functions accept `Partial<T>` which includes `id`, `tenant_id`, `created_at`. Should use `Pick` or `Omit` to exclude server-controlled fields.

### L4. Redundant query invalidation in mutation hooks

`use-scans.ts:39-41`, `use-schedules.ts:37-38`, `use-targets.ts:37-38`: Invalidating `['key']` already matches `['key', id]`, making the second invalidation redundant.

### L5. Hardcoded chart colors won't adapt to themes

`features/dashboard/findings-by-type-chart.tsx:37`: `fill="#3b82f6"` and `features/dashboard/risk-distribution-chart.tsx:5-11`: hardcoded hex values instead of CSS variables.

### L6. Hardcoded default SQL query exposes table name

`features/reports/page.tsx:52`: `'SELECT * FROM scan_results LIMIT 100'` couples the UI to internal schema.

### L7. Toast auto-dismiss timeout not configurable

`stores/ui-store.ts:45`: 5-second timeout is hardcoded. Error messages may need more reading time.

### L8. Missing `vite-env.d.ts` for environment variable types

`import.meta.env.VITE_API_URL` is untyped (`any`) without this file.

### L9. ESLint `ecmaVersion: 2020` inconsistent with `target: ES2022`

`eslint.config.js`: Parser configured for ES2020 but build target is ES2022. Modern syntax may not be parsed correctly by ESLint.

### L10. `form.watch('config')` causes excessive re-renders

`features/targets/form-page.tsx:136`: Called inside a `.map()` iteration, causing all config fields to re-render on every keystroke.

### L11. `Content-Type: application/json` sent on bodyless requests

`api/client.ts:44`: GET and DELETE requests send `Content-Type: application/json` unnecessarily.

### L12. Error states inconsistently handled across pages

Many pages use `data ? <Content> : null` pattern, silently rendering nothing on query errors instead of showing an error message. Dashboard uses `ErrorBoundary` per widget (good), but most other pages don't.

---

## Architectural Observations (Not Bugs)

### Good Patterns

1. **Feature-based organization** — Clean separation of concerns with `features/`, `api/`, `components/`, `stores/`, `hooks/` directories
2. **Lazy loading** — All routes use `lazy: () => import()` with React Router v7 conventions
3. **Zustand + TanStack Query separation** — Client state (auth, UI) vs server state (API data) properly separated
4. **WebSocket → query invalidation** — `useWebSocketSync` hook correctly bridges real-time events to cache updates
5. **ErrorBoundary per widget** — Dashboard gracefully degrades if individual widgets fail
6. **Cursor pagination for large datasets** — Results use infinite scrolling pattern

### Architecture Debt

1. **No shared API types** — Frontend and backend types are independently maintained with no code generation or shared schema. This is the root cause of most HIGH issues.
2. **Missing hook files** — `jobs`, `policies`, `settings`, `users`, `audit`, `browse`, `events` endpoints have no React Query hooks, so mutations lack proper cache invalidation.
3. **HTMX legacy endpoints** — Some backend endpoints (settings/fanout, settings/adapters, scan retry, target/schedule delete) return `HTMLResponse` for HTMX, creating inconsistency in the API surface.

---

## Recommended Priority Order

1. **Create `src/lib/` modules** (C1) — Unblocks everything
2. **Align API URL paths** (C4, H8, H10, H12) — Fix 404s
3. **Align request/response types** (C2, C3, H1-H7, H9, H11) — Fix runtime errors
4. **Add missing React Query hooks** — For policies, settings, users, browse, events
5. **Fix functional bugs** (M1-M10) — Event dedup, form state, error handling
6. **Address accessibility** (M11-M14) — Keyboard nav, ARIA labels
7. **Code quality cleanup** (L1-L12) — As time permits

Consider generating frontend types from backend Pydantic models (e.g., via OpenAPI spec export + `openapi-typescript`) to prevent future type drift.
