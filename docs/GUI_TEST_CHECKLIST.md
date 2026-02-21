# Open Labels GUI Integration Test Checklist

**Purpose:** Systematic verification that every React page works against the FastAPI backend.
Walk this in order — later sections depend on earlier ones succeeding.

**Setup required before starting:**
- Backend running: `uvicorn openlabels.server.app:create_app --factory --reload`
- Frontend running: `cd frontend && npm run dev` (Vite proxied to backend)
- Database migrated: `alembic upgrade head`
- Auth provider set to `none` (dev mode) in config

---

## PHASE 0: PRE-FLIGHT (do this before touching pages)

### 0.1 Jinja/HTMX Cleanup (BLOCKING — must do first)

These issues will cause runtime errors if not fixed.

- [ ] **Delete Jinja web module**: Remove `src/openlabels/web/` directory entirely
- [ ] **Remove web_router mount**: In `server/app.py`, remove `from openlabels.web import router as web_router` and the `app.include_router(web_router, prefix="/ui")` line
- [ ] **Convert `POST /settings/fanout`**: Currently uses `Form()` params + `HTMLResponse`. Change to accept JSON body with Pydantic model, return JSON `SettingsUpdateResponse`
  - Frontend sends: `{ fanout_enabled: bool, fanout_threshold: int, fanout_max_partitions: int, pipeline_max_concurrent_files: int, pipeline_memory_budget_mb: int }`
  - Used by: Settings page fanout tab AND Scan Config advanced tab
- [ ] **Convert `POST /settings/adapters`**: Same pattern — Form() → JSON body
  - Frontend doesn't currently have UI for this but the route exists
- [ ] **Strip HX-Request branches** (10 total):
  - [ ] `labels.py` line 533-534: HX-Request branch in `update_label_mappings`
  - [ ] `results.py` line 339-340: HX-Request in `clear_all_results`
  - [ ] `results.py` line 368-369: HX-Request in `delete_result`
  - [ ] `results.py` line 411-412: HX-Request in `apply_recommended_label`
  - [ ] `results.py` line 478-479: HX-Request in `rescan_file`
  - [ ] `scans.py` line 155-156: HX-Request in `cancel_scan`
  - [ ] `scans.py` line 179-180: HX-Request in `retry_scan`
  - [ ] `schedules.py` line 189-190: HX-Request in `delete_schedule`
  - [ ] `settings.py` line 357-358: HX-Request in `reset_settings`
  - [ ] `targets.py` line 525-526: HX-Request in `delete_target`
- [ ] **Remove `htmx_notify()`** from `routes/__init__.py` and all imports of it
- [ ] **Verify SPA catch-all** still works: `GET /dashboard` should serve `index.html`, not 404

### 0.2 Known Bug: WebSocket Event Format Mismatch (BLOCKING)

**Bug:** Backend sends flat messages, frontend expects nested `data` field.

Backend sends:
```json
{"type": "scan_progress", "scan_id": "...", "status": "...", "progress": {...}}
```

Frontend `websocket.ts` line 51 parses:
```typescript
const message = JSON.parse(event.data) as { type: string; data: unknown };
handlers?.forEach((handler) => handler(message.data));  // message.data is undefined!
```

**Fix option A (recommended — change backend):** Wrap all publish payloads in `data`:
```python
await global_broadcaster.publish(tenant_id, {
    "type": "scan_progress",
    "data": {"scan_id": str(scan_id), "status": status_value, "progress": progress}
})
```
Apply to all 8 publish functions in `ws_events.py`.

**Fix option B (change frontend):** In `websocket.ts`, pass entire message:
```typescript
handlers?.forEach((handler) => handler(message));
```
Then update all `useWebSocketSync` handlers to destructure from top level.

- [ ] Fix applied and verified (pick A or B, apply consistently)

### 0.3 Verify Frontend Build

- [ ] `cd frontend && npx tsc --noEmit` — zero errors
- [ ] `cd frontend && npx vite build` — builds successfully
- [ ] `npm run dev` starts and serves at localhost:5173

---

## PHASE 1: AUTH FLOW

Everything depends on this working. Test first.

### 1.1 Auth Config Endpoint

- [ ] `GET /api/v1/auth/config` returns JSON:
  ```
  { provider: "none", display_name: "Development", button_style: "generic", login_url: "/api/v1/auth/login" }
  ```
- [ ] No CORS errors in browser console

### 1.2 Login Page (`/login`)

- [ ] Page renders (logo, title "openlabels", sign-in button)
- [ ] Button text shows "Sign in with Development"
- [ ] Helper text shows "Development mode — no authentication required"
- [ ] Clicking button navigates to `/api/v1/auth/login`

### 1.3 Dev Mode Auth Flow

- [ ] `GET /api/v1/auth/login` (dev mode) creates dev tenant + user and redirects to `/`
- [ ] Session cookie `openlabels_session` is set
- [ ] CSRF cookie `openlabels_csrf` is set
- [ ] Redirect lands on `/dashboard` (via `Navigate to="/dashboard"` in router)

### 1.4 Auth Guard

- [ ] `GET /api/v1/auth/me` returns user info:
  ```
  { id: "...", email: "dev@localhost", name: "Developer", tenant_id: "...", roles: ["admin"] }
  ```
- [ ] Frontend `auth-store.ts` maps `roles: ["admin"]` → `role: "admin"` correctly
- [ ] AppShell renders (sidebar visible, header visible)
- [ ] WebSocket connects to `/ws/events` (check Network tab → WS)

### 1.5 Logout

- [ ] Click user menu → Logout
- [ ] `POST /api/v1/auth/logout` called
- [ ] Redirects to `/login`
- [ ] Subsequent API calls get 401 (session cleared)

---

## PHASE 2: DASHBOARD

The landing page. All data will be empty/zero on fresh install — that's OK, verify empty states.

### 2.1 Stats Cards

- [ ] Four cards render: Files Scanned, Files with PII, Critical Files, Active Scans
- [ ] All show "0" on fresh install (not NaN, not undefined, not loading forever)
- [ ] `GET /api/v1/dashboard/stats` returns:
  ```
  Backend model: OverallStats
  Frontend type: DashboardStats
  Fields: total_scans, total_files_scanned, files_with_pii, labels_applied,
          critical_files, high_files, medium_files, low_files, minimal_files, active_scans
  ```
- [ ] Stats cards read: `total_files_scanned`, `files_with_pii`, `critical_files`, `active_scans`
- [ ] Auto-refreshes every 30 seconds (check Network tab)

### 2.2 Risk Distribution Chart (Recharts PieChart)

- [ ] Shows "No data available" on fresh install (not crash, not empty chart)
- [ ] Data source: computed from dashboard stats `{ CRITICAL: n, HIGH: n, MEDIUM: n, LOW: n, MINIMAL: n }`
- [ ] CSS custom properties exist: `--color-risk-critical` through `--color-risk-minimal`
  - [ ] Check `frontend/src/styles/globals.css` defines these
  - [ ] If missing, charts will render with invisible/wrong colors

### 2.3 Top Entity Types Chart (Recharts BarChart)

- [ ] Shows "No data available" on fresh install
- [ ] `GET /api/v1/dashboard/entity-trends?days=30` returns:
  ```
  Backend model: EntityTrendsResponse
  Fields: series (Record<string, Array<[string, number]>>), truncated, total_records
  ```
- [ ] Frontend aggregates series into counts per entity type

### 2.4 Recent Scans Table

- [ ] Shows "No scans yet" on fresh install
- [ ] `GET /api/v1/scans?page=1&page_size=5` returns PaginatedResponse<ScanJob>
- [ ] Each row shows: target_name, files_scanned, relative time, status badge
- [ ] Rows clickable → navigate to `/scans/{id}`

### 2.5 Activity Feed

- [ ] Shows "No activity yet" on fresh install
- [ ] `GET /api/v1/audit?page=1&page_size=10` returns PaginatedResponse<AuditLogEntry>
- [ ] Each entry shows: action, user_email (or "system"), resource_type, relative time

### 2.6 System Status

- [ ] `GET /api/v1/health/status` returns HealthStatus
- [ ] Shows 5 components: db, queue, ml, mip, ocr with status dots
- [ ] Each shows `{name}_text` description
- [ ] Overall status derived: any "error" → unhealthy, any "warning" → degraded, else healthy
- [ ] Uptime display: `{hours}h {mins}m`
- [ ] **Check**: Does `uptime_seconds` field exist in backend response? Frontend reads it.

### 2.7 Attention Banner

- [ ] Hidden when critical_files + high_files = 0
- [ ] Shows when > 0 with count and "Review Now" button → navigates to `/results?risk_tier=CRITICAL`

---

## PHASE 3: TARGETS (must work before scans)

### 3.1 Target List Page (`/targets`)

- [ ] `GET /api/v1/targets?page=1&page_size=50` returns PaginatedResponse<Target>
- [ ] Empty state: "No scan targets configured yet" or similar
- [ ] "New Target" button → navigates to `/targets/new`
- [ ] Fields per row: name, adapter (mapped via `ADAPTER_LABELS`), enabled badge, created_at relative time

### 3.2 Target Create Form (`/targets/new`)

- [ ] Source type picker shows all 7 types: SMB, NFS, SharePoint, OneDrive, S3, GCS, Azure Blob
- [ ] Selecting source type shows correct credential fields (defined in `SOURCE_CREDENTIAL_FIELDS`)
- [ ] SMB: host, username, password fields
- [ ] SharePoint/OneDrive: tenant_id, client_id, client_secret fields
- [ ] S3: access_key, secret_key, region, endpoint_url fields
- [ ] "Store Credentials" calls `POST /api/v1/credentials` with:
  ```
  { source_type: string, credentials: Record<string, string>, save: boolean }
  ```
- [ ] "Enumerate" calls `POST /api/v1/enumerate` with:
  ```
  { source_type: string, credentials?: Record<string, string> }
  ```
- [ ] Enumerated resources display with checkboxes
- [ ] Selecting resources and submitting calls `POST /api/v1/targets` with:
  ```
  { name: string, adapter: string, enabled: boolean, config: Record<string, unknown> }
  ```
  - [ ] `adapter` field uses backend enum value (e.g., "filesystem" not "smb")
  - [ ] `sourceToAdapter()` mapping: smb → filesystem, nfs → filesystem, rest → identity
- [ ] Toast notification on success
- [ ] Redirects to target list

### 3.3 Target Edit (`/targets/:targetId`)

- [ ] Loads existing target via `GET /api/v1/targets/{id}`
- [ ] Form pre-fills with existing values
- [ ] Folder picker tree loads via `GET /api/v1/browse/{target_id}`
- [ ] Save calls `PUT /api/v1/targets/{id}`

### 3.4 Target Delete

- [ ] Delete button shows confirmation dialog
- [ ] `DELETE /api/v1/targets/{id}` called
- [ ] **VERIFY**: Backend returns JSON (not HTMLResponse) after HTMX cleanup
- [ ] Target list refreshes (query invalidation)

---

## PHASE 4: SCANS (depends on targets existing)

### 4.1 Scan List Page (`/scans`)

- [ ] `GET /api/v1/scans?page=1&page_size=50` returns PaginatedResponse<ScanJob>
- [ ] Columns: target_name, status, files_scanned, files_with_pii, started_at, actions
- [ ] Status badges render correctly for all states: pending, running, completed, failed, cancelled
- [ ] Row click → `/scans/{id}`

### 4.2 Create Scan

- [ ] "New Scan" button or mechanism to create scan
- [ ] `POST /api/v1/scans` with: `{ target_id: string, name?: string }`
- [ ] Returns ScanJob with status "pending"
- [ ] Scan appears in list immediately (cache invalidation)

### 4.3 Scan Detail Page (`/scans/:scanId`)

- [ ] `GET /api/v1/scans/{id}` returns ScanJob
- [ ] Shows: target_name, scan ID, status badge
- [ ] **Running scan:**
  - [ ] Progress bar with percentage
  - [ ] "Scanning: {current_file}" text
  - [ ] Three stats: Scanned, With PII, Skipped
  - [ ] Cancel button visible and functional
  - [ ] **WebSocket (per-scan):** Connects to `ws://host/ws/scans/{scanId}`
    - [ ] Receives `file_result` messages
    - [ ] Live Findings table populates with: file_path (truncated), risk tier badge, risk score, entity tags
    - [ ] "Streaming" indicator with pulsing dot
- [ ] **Completed scan:**
  - [ ] "Scan Complete" card with file count
  - [ ] "View Results" button → `/results`
  - [ ] Duration calculated: `formatDuration(started_at, completed_at)`
- [ ] **Failed scan:**
  - [ ] Red error card with error message
- [ ] Auto-refresh: 3s when running/pending, stops when completed/failed

### 4.4 Cancel Scan

- [ ] `POST /api/v1/scans/{id}/cancel`
- [ ] **VERIFY**: Returns JSON after HTMX cleanup
- [ ] Status updates to "cancelled"
- [ ] Toast notification

---

## PHASE 5: RESULTS (depends on at least one completed scan with findings)

### 5.1 Results List Page (`/results`)

- [ ] `GET /api/v1/results/cursor` returns CursorPaginatedResponse<ScanResult>
  ```
  Fields: items[], next_cursor, previous_cursor, has_next, has_previous, page_size
  ```
- [ ] Each result shows: file_name, file_path, risk tier badge, risk score, entity count tags, owner, scanned_at
- [ ] **Cursor pagination**: Load More / Next page works (not offset-based)
- [ ] **Filters work**:
  - [ ] `?risk_tier=CRITICAL` — filters correctly
  - [ ] `?entity_type=SSN` — filters correctly
  - [ ] `?search=filename` — filters correctly
  - [ ] `?scan_id=xxx` — filters to specific scan
- [ ] Row click → `/results/{id}`

### 5.2 Result Detail Page (`/results/:resultId`)

- [ ] `GET /api/v1/results/{id}` returns ScanResultDetail
- [ ] **Summary cards (5):** Risk Tier (badge), Risk Score (number), File Size (formatted), Owner, Scanned date
- [ ] **Label card:**
  - [ ] Shows current label or "No Label" badge
  - [ ] Shows recommended label if available
  - [ ] Shows "Applied {date}" if labeled
- [ ] **Entity Summary:** Entity type tags with counts from `entity_counts` dict
- [ ] **Detected Entities table:**
  - [ ] Populated from `findings` field (JSONB)
  - [ ] **VERIFY data shape:** Frontend expects `findings` as `Record<string, Array<{value, confidence, context}>>`
  - [ ] Backend stores findings — what exact shape? May need mapping.
  - [ ] Columns: Type (EntityTag), Value (masked by default), Confidence (%), Context
  - [ ] "Reveal values" / "Mask values" toggle works
- [ ] **Policy violations:** Renders if present, skips if null/empty
- [ ] **Actions dropdown:**
  - [ ] Apply Label → opens dialog
  - [ ] Quarantine → confirmation dialog → `POST /api/v1/remediation/quarantine`
  - [ ] Lockdown → confirmation dialog → `POST /api/v1/remediation/lockdown`
  - [ ] Export Entities → downloads CSV blob

### 5.3 Apply Label Dialog

- [ ] Loads labels via `GET /api/v1/labels?page=1&page_size=50`
- [ ] Shows file path, current label, recommended label
- [ ] Select dropdown populated with label options
- [ ] "Apply" calls `POST /api/v1/labels/apply` with `{ result_id, label_id }`
- [ ] Toast on success, dialog closes

---

## PHASE 6: LABELS

### 6.1 Labels List (`/labels`)

- [ ] `GET /api/v1/labels?page=1&page_size=50` returns PaginatedResponse<Label>
- [ ] Fields per row: name, description, priority, color swatch, parent_id
- [ ] Empty state if no labels synced

### 6.2 Label Sync (`/labels/sync`)

- [ ] "Sync from M365" button calls `POST /api/v1/labels/sync`
- [ ] `GET /api/v1/labels/sync/status` shows: label_count, last_synced_at, cache info
- [ ] In dev mode without Azure AD, this will return empty/error — verify graceful handling

### 6.3 Label Mappings

- [ ] `GET /api/v1/labels/mappings` returns:
  ```
  { CRITICAL: label_id|null, HIGH: label_id|null, MEDIUM: label_id|null, LOW: label_id|null, labels: Label[] }
  ```
- [ ] Can map risk tiers to labels
- [ ] Save calls `POST /api/v1/labels/mappings`
- [ ] **VERIFY**: After HTMX cleanup, this returns JSON (not HTMLResponse)

---

## PHASE 7: EXPLORER

### 7.1 Resource Explorer (`/explorer`)

- [ ] Loads targets for selection
- [ ] After selecting target, `GET /api/v1/browse/{target_id}` returns BrowseResponse:
  ```
  { target_id, parent_id, parent_path, folders: BrowseFolder[], total }
  ```
- [ ] Folder tree renders with: dir_name, child counts, modified date
- [ ] Security indicators: world_accessible, authenticated_users, custom_acl
- [ ] Risk indicators: has_sensitive_files, highest_risk_tier, total_entities_found
- [ ] Click folder → loads children (same endpoint with `parent_id` param)
- [ ] File list: `GET /api/v1/browse/{target_id}/files?folder_path=...`
- [ ] **NOTE**: Requires FolderInventory + DirectoryTree to be populated (needs at least one completed scan with browse data)

---

## PHASE 8: REMEDIATION

### 8.1 Remediation List (`/remediation`)

- [ ] `GET /api/v1/remediation?page=1&page_size=50` returns PaginatedResponse<RemediationAction>
- [ ] Fields: action_type, status, source_path, dest_path, dry_run, created_at
- [ ] Status badges: pending, completed, failed, rolled_back
- [ ] Empty state when no actions taken

### 8.2 Rollback

- [ ] Rollback button on completed actions
- [ ] `POST /api/v1/remediation/rollback` with `{ action_id: string }`
- [ ] Status changes to "rolled_back"

---

## PHASE 9: SCHEDULES

### 9.1 Schedule List (`/schedules`)

- [ ] `GET /api/v1/schedules?page=1&page_size=50` returns PaginatedResponse<Schedule>
- [ ] Fields: name, cron expression, enabled badge, next_run_at, last_run_at

### 9.2 Schedule Create (`/schedules/new`)

- [ ] Form fields: name, cron expression, target_id (dropdown), enabled toggle
- [ ] `POST /api/v1/schedules` with `{ name, cron, target_id, enabled }`
- [ ] Returns Schedule with calculated next_run_at

### 9.3 Schedule Edit (`/schedules/:scheduleId`)

- [ ] Loads via `GET /api/v1/schedules/{id}`
- [ ] Pre-fills form
- [ ] Save calls `PUT /api/v1/schedules/{id}`

### 9.4 Schedule Delete

- [ ] Confirmation dialog
- [ ] `DELETE /api/v1/schedules/{id}`
- [ ] **VERIFY**: Returns JSON after HTMX cleanup
- [ ] List refreshes

---

## PHASE 10: SCAN CONFIG

### 10.1 Scan Config Page (`/scan-config`)

- [ ] Two tabs: "Create Scan Schedule" and "Advanced"
- [ ] Schedule tab reuses same schedule list/CRUD as Phase 9
- [ ] Advanced tab shows fanout settings form

### 10.2 Fanout Settings (Advanced tab)

- [ ] Loads current settings from `GET /api/v1/settings` (fanout section)
- [ ] Form fields: fanout_enabled (checkbox), fanout_threshold, fanout_max_partitions, pipeline_max_concurrent_files, pipeline_memory_budget_mb
- [ ] Save calls `POST /api/v1/settings/fanout` with JSON body
- [ ] **CRITICAL**: This endpoint MUST be converted from Form() to JSON in Phase 0
- [ ] Toast on success

---

## PHASE 11: MONITORING

### 11.1 Monitoring Page (`/monitoring`)

- [ ] `GET /api/v1/health/status` — system health
- [ ] `GET /api/v1/jobs/stats` — job queue stats:
  ```
  { pending, running, completed, failed, cancelled, failed_by_type }
  ```
- [ ] `GET /api/v1/audit?page=1&page_size=20` — activity log
- [ ] All three sections render with appropriate empty states

---

## PHASE 12: EVENTS

### 12.1 Events Page (`/events`)

- [ ] `GET /api/v1/monitoring/events/cursor` returns CursorPaginatedResponse<FileAccessEvent>
- [ ] Fields: file_path, user_name, action, event_time, details
- [ ] Cursor pagination (not offset)
- [ ] Filters: file_path, user_name, action, since

---

## PHASE 13: PERMISSIONS

### 13.1 Permissions Page (`/permissions`)

- [ ] `GET /api/v1/permissions/exposure` returns ExposureSummary:
  ```
  { total_directories, with_security_descriptor, world_accessible, authenticated_users, custom_acl, private }
  ```
- [ ] Directory list: `GET /api/v1/permissions/{target_id}/directories` (requires target selection)
- [ ] ACL detail: `GET /api/v1/permissions/{target_id}/acl/{dir_id}`
- [ ] Principal lookup: `GET /api/v1/permissions/principal/{principal}`
- [ ] **NOTE**: Requires SecurityDescriptor + DirectoryTree populated (filesystem scan with ACL enumeration)

---

## PHASE 14: POLICIES

### 14.1 Policies List (`/policies`)

- [ ] `GET /api/v1/policies?page=1&page_size=50` returns PaginatedResponse<Policy>
- [ ] Fields: name, description, framework, risk_level, enabled, priority
- [ ] Frontend Policy type includes `rules: PolicyRule[]` — verify backend returns this

### 14.2 Policy CRUD

- [ ] Create: `POST /api/v1/policies`
- [ ] Get: `GET /api/v1/policies/{id}`
- [ ] Update: `PUT /api/v1/policies/{id}`
- [ ] Delete: `DELETE /api/v1/policies/{id}`
- [ ] **Check**: Frontend `Policy` type has `rules` field. Backend `PolicyResponse` — does it include rules?

---

## PHASE 15: REPORTS

### 15.1 Reports Page (`/reports`)

- [ ] `GET /api/v1/reports?page=1&page_size=50` returns PaginatedResponse<Report>
- [ ] "Generate Report" calls `POST /api/v1/reports/generate`
- [ ] Download: `GET /api/v1/reports/{id}/download` — returns binary (PDF/HTML)
- [ ] **Check**: Frontend export.ts `fetchBlob()` function handles binary download correctly

---

## PHASE 16: SETTINGS

### 16.1 Settings Page (`/settings`)

- [ ] Admin-only check works (non-admin sees "Settings are only accessible to administrators")
- [ ] `GET /api/v1/settings` returns AllSettingsResponse:
  ```
  {
    azure: { azure_tenant_id, azure_client_id, azure_client_secret_set (bool) },
    scan: { max_file_size_mb, concurrent_files, enable_ocr, enable_ml },
    entities: { enabled_entities (string[]) },
    fanout: { fanout_enabled, fanout_threshold, fanout_max_partitions, pipeline_max_concurrent_files, pipeline_memory_budget_mb }
  }
  ```
- [ ] Four tabs: Azure AD, Scan, Entities, Fanout

### 16.2 Settings Updates

- [ ] Azure: `POST /api/v1/settings/azure` with `{ tenant_id, client_id, client_secret }`
  - [ ] **Check**: Frontend sends `azure_tenant_id` or `tenant_id`? Backend expects `tenant_id`/`client_id`/`client_secret`
  - [ ] The generic `SettingsTab` component sends field names as-is from the response. If response has `azure_tenant_id`, it sends `azure_tenant_id`, but backend `AzureSettingsRequest` expects `tenant_id`. **Likely mismatch — verify.**
- [ ] Scan: `POST /api/v1/settings/scan` — JSON body
- [ ] Entities: `POST /api/v1/settings/entities` — JSON body with `{ entities: string[] }`
  - [ ] **Check**: Frontend sends key `enabled_entities`, backend `EntitySettingsRequest` expects `entities`. **Likely mismatch.**
- [ ] Fanout: `POST /api/v1/settings/fanout` — JSON body (after Phase 0 conversion)
- [ ] Reset: `POST /api/v1/settings/reset`
- [ ] Toast notifications on success/error

---

## PHASE 17: USERS

### 17.1 Users Page (`/users`)

- [ ] `GET /api/v1/users?page=1&page_size=50` returns PaginatedResponse<User>
- [ ] Fields: name, email, role
- [ ] Create user: `POST /api/v1/users` with `{ name, email, role, auth_type, password? }`
  - [ ] **Check**: Frontend `create` endpoint does `body: JSON.stringify(payload)` but the `apiFetch` wrapper ALSO calls `JSON.stringify(body)`. This would **double-encode** the JSON. Verify.
- [ ] Delete user: `DELETE /api/v1/users/{id}`

---

## PHASE 18: QUERY CONSOLE

### 18.1 Query Page (check route — may be `/query` or integrated elsewhere)

- [ ] Schema: `GET /api/v1/query/schema` returns QuerySchema with tables + columns
- [ ] Execute: `POST /api/v1/query` with `{ sql: string }` returns QueryResult:
  ```
  { columns: string[], rows: unknown[][], row_count, execution_time_ms }
  ```
- [ ] AI Query: `POST /api/v1/query/ai` with `{ question: string, execute?: boolean }` returns:
  ```
  { sql: string, explanation: string, result?: QueryResult }
  ```
- [ ] **NOTE**: DuckDB/Parquet must be initialized. Query may fail on fresh install if no data flushed to catalog.

---

## PHASE 19: CONFIG RESOURCES

### 19.1 Config Resources Page (`/config/resources`)

- [ ] Two tabs: "Add Resources" (target table) and "Resource Health"
- [ ] Target table reuses same target list from Phase 3
- [ ] Resource Health shows same health components as dashboard system status
- [ ] System metrics: scans_today, files_processed, success_rate
- [ ] "Add Resource" button → `/targets/new`

---

## PHASE 20: SETUP WIZARD

### 20.1 Setup Wizard (`/setup`)

- [ ] Step indicator: Welcome → Azure AD → Scan Target → Review
- [ ] Welcome step: branding, description
- [ ] Azure AD step: tenant_id, client_id, client_secret fields
  - [ ] "Test Connection" calls `POST /api/v1/settings/azure`
  - [ ] "Skip" button works
- [ ] Scan Target step: adapter type picker (filesystem, SharePoint, OneDrive)
  - [ ] Filesystem: path input
  - [ ] SP/OneDrive: uses Azure creds from previous step
  - [ ] "Skip" button works
- [ ] Review step: summary of selections
  - [ ] "Finish" creates target + starts scan:
    - [ ] `POST /api/v1/targets` → `POST /api/v1/scans`
  - [ ] Navigates to dashboard on completion

---

## PHASE 21: WEBSOCKETS (cross-cutting verification)

### 21.1 Global WebSocket (`/ws/events`)

- [ ] Connects on AppShell mount (check Network → WS tab)
- [ ] Authentication passes (dev mode uses dev tenant lookup)
- [ ] Heartbeat received periodically
- [ ] Reconnect on disconnect (exponential backoff: 1s → 2s → 4s → ... → 30s max)

### 21.2 Event Handlers (verify after Phase 0.2 fix)

For each event type, trigger the action and verify the handler fires:

- [ ] `scan_progress`: Start scan → scan list updates in real-time (query cache update)
- [ ] `scan_completed`: Complete scan → toast "Scan completed", dashboard + scan list refresh
- [ ] `scan_failed`: Fail scan → toast with error, scan list refresh
- [ ] `label_applied`: Apply label → results + labels queries invalidated
- [ ] `remediation_completed`: Complete remediation → toast, remediation list refresh
- [ ] `job_status`: Job state change → monitoring jobs refresh
- [ ] `health_update`: Health change → health query refresh

### 21.3 Per-Scan WebSocket (`/ws/scans/{scanId}`)

- [ ] Only connects when scan status is running/pending
- [ ] Receives `file_result` messages with: file_path, risk_score, risk_tier, entity_counts
- [ ] Live Findings table updates (prepend, max 200 entries)
- [ ] Disconnects when scan completes

---

## PHASE 22: CROSS-CUTTING CONCERNS

### 22.1 Error Handling

For each page, verify behavior when backend returns errors:

- [ ] **401**: Redirects to `/login` (handled globally in `apiFetch`)
- [ ] **403**: CSRF token missing → "Session expired" error message
- [ ] **404**: Appropriate "not found" message (not blank screen)
- [ ] **422**: Validation errors displayed to user (not silent failure)
- [ ] **500**: Error boundary catches, shows fallback UI
- [ ] **Network timeout**: 30s timeout → error state (not infinite loading)
- [ ] **Backend down**: Loading skeleton → error state (not infinite loading)

### 22.2 Navigation

- [ ] Sidebar links all navigate correctly (19 nav items in `NAV_GROUPS`)
- [ ] Breadcrumbs update on each page
- [ ] Back buttons work (scans detail → scans list, results detail → results list)
- [ ] Browser back/forward works (client-side routing)
- [ ] Direct URL access works for all routes (SPA catch-all serves index.html)
- [ ] 404 page shows for unknown routes

### 22.3 Loading States

- [ ] Every page shows skeleton/spinner while data loads (not blank screen)
- [ ] No flash of content then loading (React Suspense configured)
- [ ] Stale data shows while refetching (TanStack Query default)

### 22.4 Cache Invalidation

After each mutation, verify the relevant query refreshes:

| Mutation | Queries that should refresh |
|---|---|
| Create target | `['targets']` |
| Delete target | `['targets']` |
| Create scan | `['scans']`, `['dashboard']` |
| Cancel scan | `['scans']`, `['scans', id]`, `['dashboard']` |
| Apply label | `['results']`, `['labels']` |
| Quarantine/Lockdown | `['remediation']` |
| Create schedule | `['schedules']` |
| Delete schedule | `['schedules']` |
| Update settings | `['settings']` |

### 22.5 Responsive Layout

- [ ] Sidebar collapses on mobile (if implemented)
- [ ] Tables don't overflow horizontally
- [ ] Charts resize in containers

---

## KNOWN ISSUES TO WATCH FOR

### Confirmed Bugs (fix in Phase 0)

1. **WebSocket `data` nesting mismatch** — See Phase 0.2
2. **Settings fanout/adapters routes return HTML** — See Phase 0.1
3. **10 HTMX branches return HTML on HX-Request header** — See Phase 0.1

### Probable Bugs (verify during testing)

4. **Settings field name mismatch**: Backend `AzureSettingsRequest` fields (`tenant_id`, `client_id`, `client_secret`) don't match response field names (`azure_tenant_id`, `azure_client_id`). The generic `SettingsTab` component sends response field names back. **Fix: either rename request fields or add mapping in frontend.**

5. **Settings entities mismatch**: Backend `EntitySettingsRequest` expects `entities`, frontend sends `enabled_entities` (the response field name). **Fix: rename one side.**

6. **Users create double-JSON**: `usersApi.create` does `body: JSON.stringify(payload)`, but `apiFetch` also calls `JSON.stringify(body)`. Result: `"\"{'name':'...'}\"` sent to server. **Fix: remove `JSON.stringify` from `usersApi.create`.**

7. ~~**CSS custom property risk colors**~~: **VERIFIED OK** — `globals.css` defines `--color-risk-critical` through `--color-risk-minimal` in both light and dark themes.

8. **DashboardStats `labels_applied`**: Backend returns it, frontend `DashboardStats` type includes it, but no card displays it. Not a bug, just unused.

9. **health.data status values**: Backend HealthStatus uses "healthy"/"warning"/"error". Frontend SystemStatus checks for "healthy"/"warning" in dots but "healthy"/"degraded"/"unhealthy" for overall badge. The mapping `any error → unhealthy, any warning → degraded` is correct for overall, but individual dots check `data[name] === 'error'` which matches. **Should work, verify.**

---

## COMPLETION CRITERIA

All phases verified → the GUI is ready for demo recording.

**Minimum viable demo path:**
1. Login (Phase 1) ✓
2. Dashboard empty state (Phase 2) ✓
3. Create filesystem target (Phase 3.2) ✓
4. Run scan (Phase 4.2) ✓
5. Watch scan progress via WebSocket (Phase 4.3) ✓
6. View results (Phase 5.1) ✓
7. View result detail with findings (Phase 5.2) ✓
8. Apply label (Phase 5.3) ✓
9. Dashboard with data (Phase 2 re-verify) ✓
