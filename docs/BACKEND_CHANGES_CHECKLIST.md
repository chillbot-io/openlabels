# Open Labels Backend Code Changes Checklist

**Companion to:** `GUI_TEST_CHECKLIST.md` (testing/verification)
**This doc:** All code changes needed before and during GUI integration

---

## How to Use This

Work top to bottom. Section 1 is **blocking** — the GUI literally won't function until these are done. Section 2 is bugs that will cause silent data loss. Section 3 is the WebSocket plumbing. Section 4 is a small frontend fix list (included here because they're one-liners discovered during the backend audit). Section 5 is cleanup.

---

## 1. BLOCKING: Jinja/HTMX Removal

The old Jinja/HTMX web UI is dead code. Two settings routes can only return HTML. Ten route handlers have early-return branches that send HTML instead of JSON when an `HX-Request` header is present (browsers don't send this, but it's dead weight and confusion).

### 1.1 Delete the Jinja Web Module

**What:** Remove the entire `src/openlabels/web/` directory.

**Why:** 1,944 lines of Python routes + 30 Jinja templates that duplicate every API endpoint. The React SPA replaces this entirely.

```
rm -rf src/openlabels/web/
```

### 1.2 Remove Web Router from `app.py`

**File:** `src/openlabels/server/app.py`

**Line 60 — delete:**
```python
from openlabels.web import router as web_router
```

**Line 131 — delete:**
```python
app.include_router(web_router, prefix="/ui", tags=["Web UI"])
```

**Verify:** App starts without import error. SPA catch-all at `_register_spa_serving()` (line 227) still works — it's independent of the web router.

### 1.3 Remove `htmx_notify()` from Routes Init

**File:** `src/openlabels/server/routes/__init__.py`

**Delete** the entire `htmx_notify` function (lines 53-73):
```python
def htmx_notify(
    message: str,
    type: str = "success",
    **extra_triggers: object,
) -> HTMLResponse:
    ...
```

**Delete** from `__all__` list: `"htmx_notify",`

**Delete** unused imports: `import json`, `from fastapi.responses import HTMLResponse`
(Keep `json` if used elsewhere in file — it's not.)

### 1.4 Strip HX-Request Branches from 6 Route Files

Every one of these has a JSON fallthrough path already. Removing the HX-Request branch just means the JSON path always runs. No behavior change for the React frontend.

**Pattern:** In each file, delete the import and each `if request.headers.get("HX-Request")` block (2 lines each).

---

#### `labels.py`

**Line 34 — remove `htmx_notify` from import:**
```python
# Before:
from openlabels.server.routes import audit_log, htmx_notify
# After:
from openlabels.server.routes import audit_log
```

**Lines 533-534 — delete:**
```python
    if request.headers.get("HX-Request"):
        return htmx_notify("Label mappings saved")
```

**Verify:** `update_label_mappings` continues to the JSON return on line 536+.

---

#### `results.py`

**Line 23 — delete entire import:**
```python
from openlabels.server.routes import htmx_notify
```

**Lines 339-340 — delete (in `clear_all_results`):**
```python
    if request.headers.get("HX-Request"):
        return htmx_notify(f"{deleted_count} results cleared")
```
Falls through to: `return {"deleted_count": deleted_count}`

**Lines 368-369 — delete (in `delete_result`):**
```python
    if request.headers.get("HX-Request"):
        return htmx_notify(f'Result for "{file_name}" deleted', refreshResults=True)
```
Falls through to: `return JSONResponse(status_code=200, content={"message": ...})`

**Lines 411-412 — delete (in `apply_recommended_label`):**
```python
        if request.headers.get("HX-Request"):
            return htmx_notify("Label application queued")
```
Falls through to: `return {"message": "Label application queued", "job_id": str(job_id)}`

**Lines 478-479 — delete (in `rescan_file`):**
```python
    if request.headers.get("HX-Request"):
        return htmx_notify("Rescan queued")
```
Falls through to: `return {"message": "Rescan queued", "job_id": str(new_job.id)}`

---

#### `scans.py`

**Line 27 — remove `htmx_notify` from import:**
```python
# Before:
from openlabels.server.routes import htmx_notify
# After: (delete line entirely, nothing else imported from routes in this file)
```
Wait — check if anything else is imported. If not, delete the line.

**Lines 155-156 — delete (in `cancel_scan`):**
```python
    if request.headers.get("HX-Request"):
        return htmx_notify("Scan cancelled", refreshScans=True)
```
Falls through to: `return {"message": "Scan cancelled", "scan_id": str(scan_id)}`

**Lines 179-180 — delete (in `retry_scan`):**
```python
        if request.headers.get("HX-Request"):
            return htmx_notify("Scan retry queued", refreshScans=True)
```
Falls through to: `return {"message": "Scan retry created", "new_job_id": str(new_job.id)}`

---

#### `schedules.py`

**Line 22 — remove `htmx_notify` from import:**
```python
# Before:
from openlabels.server.routes import audit_log, get_or_404, htmx_notify
# After:
from openlabels.server.routes import audit_log, get_or_404
```

**Lines 189-190 — delete (in `delete_schedule`):**
```python
    if request.headers.get("HX-Request"):
        return htmx_notify(f'Schedule "{schedule_name}" deleted', refreshSchedules=True)
```
Falls through to: `return Response(status_code=204)`

---

#### `settings.py`

**Line 15 — delete:**
```python
from fastapi.responses import HTMLResponse
```

**Line 23 — remove `htmx_notify` from import:**
```python
# Before:
from openlabels.server.routes import audit_log, htmx_notify
# After:
from openlabels.server.routes import audit_log
```

**Lines 357-358 — delete (in `reset_settings`):**
```python
    if request.headers.get("HX-Request"):
        return htmx_notify("Settings reset to defaults")
```
Falls through to: `return SettingsUpdateResponse(message="Settings reset to defaults")`

**(Lines 250 and 290 — the fanout/adapters routes are handled separately in Section 1.5 below.)**

---

#### `targets.py`

**Line 29 — remove `htmx_notify` from import:**
```python
# Before:
from openlabels.server.routes import audit_log, get_or_404, htmx_notify
# After:
from openlabels.server.routes import audit_log, get_or_404
```

**Lines 525-526 — delete (in `delete_target`):**
```python
        if request.headers.get("HX-Request"):
            return htmx_notify(f'Target "{target_name}" deleted', refreshTargets=True)
```
Falls through to: `return Response(status_code=204)`

---

### 1.5 Convert Settings Routes from Form → JSON

These two routes accept HTML form posts and return `HTMLResponse`. The React frontend sends JSON. They will 422 as-is.

#### `POST /settings/fanout`

**File:** `src/openlabels/server/routes/settings.py`, line 250

**Current signature (Form params, HTMLResponse):**
```python
@router.post("/fanout", response_class=HTMLResponse)
async def update_fanout_settings(
    fanout_enabled: str | None = Form(None),
    fanout_threshold: int = Form(10000),
    fanout_max_partitions: int = Form(16),
    pipeline_max_concurrent_files: int = Form(8),
    pipeline_memory_budget_mb: int = Form(512),
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
```

**Change to (Pydantic JSON body):**
```python
class FanoutSettingsRequest(BaseModel):
    fanout_enabled: bool = True
    fanout_threshold: int = Field(default=10000, ge=100, le=1_000_000)
    fanout_max_partitions: int = Field(default=16, ge=1, le=128)
    pipeline_max_concurrent_files: int = Field(default=8, ge=1, le=64)
    pipeline_memory_budget_mb: int = Field(default=512, ge=64, le=8192)

@router.post("/fanout", response_model=SettingsUpdateResponse)
async def update_fanout_settings(
    request: FanoutSettingsRequest,
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> SettingsUpdateResponse:
```

**Update body to read from `request.` instead of raw params:**
```python
    settings.fanout_enabled = request.fanout_enabled
    settings.fanout_threshold = request.fanout_threshold
    # ... etc
```

**Replace return:**
```python
    # Before:
    return htmx_notify("Performance settings updated")
    # After:
    return SettingsUpdateResponse(message="Performance settings updated")
```

**Frontend callers (2 places):**
- `frontend/src/features/settings/page.tsx` — generic SettingsTab sends JSON ✓
- `frontend/src/features/scan-config/page.tsx` — AdvancedSettings sends JSON ✓

---

#### `POST /settings/adapters`

**File:** `src/openlabels/server/routes/settings.py`, line 290

**Same pattern as fanout.** Current uses `Form()` params.

**Create request model:**
```python
class AdapterDefaultsRequest(BaseModel):
    exclude_extensions: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=list)
    exclude_accounts: list[str] = Field(default_factory=list)
    min_size_bytes: int = Field(default=0, ge=0, le=1_073_741_824)
    max_size_bytes: int = Field(default=0, ge=0, le=10_737_418_240)
    exclude_temp_files: bool = False
    exclude_system_dirs: bool = False
```

**Change decorator:**
```python
@router.post("/adapters", response_model=SettingsUpdateResponse)
async def update_adapter_defaults(
    request: AdapterDefaultsRequest,
    ...
```

**Replace return:**
```python
    return SettingsUpdateResponse(message="Adapter defaults updated")
```

**Note:** The frontend doesn't currently have UI for this route, but fixing it prevents 500s if someone calls it via API or if UI is added later.

---

## 2. SILENT DATA LOSS: Settings Field Name Mismatches

These bugs won't crash. They'll silently reset settings to defaults because Pydantic drops unknown fields and uses empty defaults.

### 2.1 Azure Settings: Response Fields ≠ Request Fields

**The bug:**
- `GET /settings` returns: `{ azure_tenant_id: "xxx", azure_client_id: "yyy", azure_client_secret_set: true }`
- Frontend sends back: `{ azure_tenant_id: "xxx", azure_client_id: "yyy", azure_client_secret_set: true }`
- `AzureSettingsRequest` expects: `{ tenant_id: "...", client_id: "...", client_secret: "..." }`
- Pydantic ignores unknown fields → `tenant_id=""`, `client_id=""`, `client_secret=""`
- **Result: Azure AD settings wiped to blank on every save**

**Fix (pick one):**

**Option A — Rename request model fields to match response (recommended):**

```python
class AzureSettingsRequest(BaseModel):
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""   # Note: was "client_secret", keep "azure_" prefix but drop "_set"
```

Then update `update_azure_settings` body:
```python
    settings.azure_tenant_id = request.azure_tenant_id or None
    settings.azure_client_id = request.azure_client_id or None
    if request.azure_client_secret:
        settings.azure_client_secret_set = True
```

**Option B — Add aliases:** Use `Field(alias="azure_tenant_id")` on the request model.

**Option C — Fix in frontend:** Map field names in the SettingsTab before sending. Less clean since the generic component works for all other tabs.

### 2.2 Entity Settings: `enabled_entities` vs `entities`

**The bug:**
- `GET /settings` returns: `{ entities: { enabled_entities: ["SSN", "EMAIL", ...] } }`
- Frontend sends back: `{ enabled_entities: ["SSN", "EMAIL", ...] }`
- `EntitySettingsRequest` expects: `{ entities: ["SSN", ...] }`
- Pydantic drops `enabled_entities`, uses default `entities: []`
- **Result: All entity types disabled on every save**

**Fix (pick one):**

**Option A — Rename request field (recommended):**
```python
class EntitySettingsRequest(BaseModel):
    enabled_entities: list[str] = Field(default_factory=list)
```

Then update handler:
```python
    settings.enabled_entities = request.enabled_entities
```

**Option B — Add alias:**
```python
class EntitySettingsRequest(BaseModel):
    entities: list[str] = Field(default_factory=list, alias="enabled_entities")
    model_config = ConfigDict(populate_by_name=True)
```

---

## 3. WEBSOCKET: Event Format Mismatch

### 3.1 Global WebSocket Events Don't Reach Frontend Handlers

**The bug:**

Backend `ws_events.py` publish functions send **flat** messages:
```python
await global_broadcaster.publish(tenant_id, {
    "type": "scan_progress",
    "scan_id": str(scan_id),
    "status": status_value,
    "progress": progress,
})
```

Frontend `websocket.ts` expects a **nested `data` field**:
```typescript
const message = JSON.parse(event.data) as { type: string; data: unknown };
handlers?.forEach((handler) => handler(message.data));
// message.data is undefined → every handler receives undefined
```

**Impact:** No real-time updates work. Scan progress, completion toasts, health updates, label notifications, remediation notifications — all silently broken.

**Fix — pick one approach, apply consistently:**

#### Option A: Wrap Backend Payloads (conventional WebSocket API pattern)

Change all 8 publish functions in `ws_events.py` to nest payload under `data`:

```python
# Before:
await global_broadcaster.publish(tenant_id, {
    "type": "scan_progress",
    "scan_id": str(scan_id),
    "status": status_value,
    "progress": progress,
})

# After:
await global_broadcaster.publish(tenant_id, {
    "type": "scan_progress",
    "data": {
        "scan_id": str(scan_id),
        "status": status_value,
        "progress": progress,
    },
})
```

**Apply to all 8 functions:**
- [ ] `publish_scan_progress` — wrap `scan_id`, `status`, `progress`
- [ ] `publish_scan_completed` — wrap `scan_id`, `status`, `summary`
- [ ] `publish_scan_failed` — wrap `scan_id`, `error`
- [ ] `publish_label_applied` — wrap `result_id`, `label_name`
- [ ] `publish_remediation_completed` — wrap `action_id`, `action_type`, `status`
- [ ] `publish_job_status` — wrap `job_id`, `status`
- [ ] `publish_file_access` — wrap `file_path`, `user_name`, `action`, `event_time`
- [ ] `publish_health_update` — wrap `component`, `status`

Also update `publish_to_all` in `publish_health_update` — same pattern.

**Also check:** The Redis pub/sub `_on_message` handler that rebroadcasts — it should pass through the `data` field as-is after deserializing.

#### Option B: Fix Frontend to Read Flat Messages

Change `websocket.ts` line 51:
```typescript
// Before:
handlers?.forEach((handler) => handler(message.data));

// After:
const { type, ...payload } = message as Record<string, unknown>;
handlers?.forEach((handler) => handler(payload));
```

Then update `useWebSocketSync` handlers:
```typescript
// Before:
wsClient.subscribe('scan_progress', (raw) => {
    const data = raw as WSScanProgress;
    // reads data.scan_id, data.progress

// After (same — works because payload IS {scan_id, status, progress}):
wsClient.subscribe('scan_progress', (raw) => {
    const data = raw as WSScanProgress;
    // reads data.scan_id, data.progress
```

**This actually works as-is** because the destructured payload has the same shape the handlers expect. Option B is fewer changes.

**Recommendation:** Option B (frontend fix) is 3 lines changed. Option A (backend fix) is 8 functions changed. Either works. Pick one. Don't mix.

### 3.2 Per-Scan WebSocket: Verify Format

The per-scan WebSocket at `/ws/scans/{scanId}` uses a **different** client (`useScanWebSocket` hook) that reads the flat message directly:

```typescript
const msg = JSON.parse(event.data) as { type: string; [key: string]: unknown };
if (msg.type === 'file_result') {
    // reads msg.file_path, msg.risk_score, etc directly
```

**This already works with the flat format.** If you pick Option A (backend nesting), you do NOT need to change the per-scan WebSocket publisher in `ws.py` — it's a separate code path. Only change `ws_events.py`.

---

## 4. FRONTEND FIXES (one-liners, included for completeness)

### 4.1 Users API: Double JSON.stringify

**File:** `frontend/src/api/endpoints/users.ts`, line 10

```typescript
// Before (body gets JSON.stringify'd twice — once here, once in apiFetch):
create: (payload: CreateUserPayload) =>
    apiFetch<User>('/users', { method: 'POST', body: JSON.stringify(payload) }),

// After:
create: (payload: CreateUserPayload) =>
    apiFetch<User>('/users', { method: 'POST', body: payload }),
```

**Impact without fix:** Creating users sends `"\"{'name':'...'}\"` to the backend → 422 validation error.

### 4.2 WebSocket Fix (if choosing Option B from Section 3)

**File:** `frontend/src/lib/websocket.ts`, line 51

```typescript
// Before:
const message = JSON.parse(event.data as string) as { type: string; data: unknown };
if (typeof message.type !== 'string' || !KNOWN_EVENT_TYPES.has(message.type)) return;
const handlers = this.listeners.get(message.type);
handlers?.forEach((handler) => handler(message.data));

// After:
const message = JSON.parse(event.data as string) as Record<string, unknown>;
const eventType = message.type as string;
if (typeof eventType !== 'string' || !KNOWN_EVENT_TYPES.has(eventType)) return;
const { type: _, ...payload } = message;
const handlers = this.listeners.get(eventType);
handlers?.forEach((handler) => handler(payload));
```

---

## 5. CLEANUP (non-blocking, do after testing)

### 5.1 Remove Unused `request: Request` Parameters

After stripping HX-Request branches, several route handlers still accept `request: Request` that's no longer used. Not blocking, but clean up when convenient:

- `results.py`: `clear_all_results`, `delete_result`, `apply_recommended_label`, `rescan_file`
- `scans.py`: `cancel_scan`, `retry_scan`
- `schedules.py`: `delete_schedule`
- `settings.py`: `reset_settings`
- `targets.py`: `delete_target`

FastAPI won't complain about unused params, but it's dead code.

### 5.2 Remove `request: Request` from `update_label_mappings` in `labels.py`

Same pattern — was only used for the HX-Request check.

### 5.3 Consider Adding `model_config = ConfigDict(extra="forbid")` to Settings Request Models

This would have caught the field name mismatches at request time (422) instead of silently dropping unknown fields. Worth adding to all request models as a defensive measure:

```python
class AzureSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ...
```

---

## Summary: Change Count

| Section | Files Changed | Lines Changed (approx) |
|---|---|---|
| 1.1 Delete web module | 1 dir deleted | -1,944 + templates |
| 1.2 Remove web_router | 1 file (app.py) | -2 |
| 1.3 Remove htmx_notify | 1 file (__init__.py) | -25 |
| 1.4 Strip HX-Request | 6 files | -20 (10 blocks × 2 lines) |
| 1.5 Convert fanout/adapters | 1 file (settings.py) | ~+30 / -20 |
| 2.1 Azure field names | 1 file (settings.py) | ~6 |
| 2.2 Entity field names | 1 file (settings.py) | ~3 |
| 3.1 WebSocket fix | 1 file (ws_events.py OR websocket.ts) | ~8-16 |
| 4.1 Users double-JSON | 1 file (users.ts) | 1 |
| **Total** | **~10 files** | **~110 lines net reduction** |

**Estimated time:** 2-3 hours for a Claude Code session. Mechanical changes, no architectural decisions.
