# Backend Changes Checklist — Execution Plan

## Overview

The backend checklist has 5 sections. Sections 1–3 are backend changes, section 4 is frontend fixes, and section 5 is cleanup. I'll work top-to-bottom as the doc prescribes. Here's the exact plan:

---

## Phase 1: BLOCKING — Jinja/HTMX Removal

### Step 1.1: Delete the Jinja web module
- `rm -rf src/openlabels/web/`
- This removes ~1,944 lines of Python + 30 Jinja templates

### Step 1.2: Remove web_router from `app.py`
- **File:** `src/openlabels/server/app.py`
- Delete the import: `from openlabels.web import router as web_router`
- Delete the mount: `app.include_router(web_router, prefix="/ui", tags=["Web UI"])`
- Verify the SPA catch-all in `_register_spa_serving()` is unaffected (it's independent)

### Step 1.3: Remove `htmx_notify()` from routes `__init__.py`
- **File:** `src/openlabels/server/routes/__init__.py`
- Delete the entire `htmx_notify` function (lines 53-74)
- Remove `"htmx_notify"` from the `__all__` list
- Remove unused imports: `import json`, `from fastapi.responses import HTMLResponse`

### Step 1.4: Strip HX-Request branches from 6 route files
For each file, remove `htmx_notify` imports and all `if request.headers.get("HX-Request")` blocks:

| File | Import line | HX-Request blocks |
|------|------------|-------------------|
| `labels.py` | Line 34 (remove `htmx_notify` from import) | Line 533-534 |
| `results.py` | Line 23 (delete entire import line) | Lines 339-340, 368-369, 411-412, 478-479 |
| `scans.py` | Line 27 (delete entire import line) | Lines 155-156, 179-180 |
| `schedules.py` | Line 22 (remove `htmx_notify` from import) | Lines 189-190 |
| `settings.py` | Line 23 (remove `htmx_notify` from import), Line 15 (`HTMLResponse` import) | Lines 357-358 |
| `targets.py` | Line 29 (remove `htmx_notify` from import) | Lines 525-526 |

### Step 1.5: Convert `POST /settings/fanout` and `POST /settings/adapters` from Form → JSON
- **File:** `src/openlabels/server/routes/settings.py`
- Create `FanoutSettingsRequest` Pydantic model with validated fields
- Change `update_fanout_settings` to accept JSON body instead of `Form()` params
- Change return to `SettingsUpdateResponse`
- Create `AdapterDefaultsRequest` Pydantic model
- Change `update_adapter_defaults` similarly
- Remove the `HTMLResponse` import (already done in 1.4) and `Form` import if no longer needed

---

## Phase 2: SILENT DATA LOSS — Settings Field Name Mismatches

### Step 2.1: Fix Azure Settings request model
- **File:** `src/openlabels/server/routes/settings.py`
- Rename `AzureSettingsRequest` fields to match what the frontend sends:
  - `tenant_id` → `azure_tenant_id`
  - `client_id` → `azure_client_id`
  - `client_secret` → `azure_client_secret`
- Update handler body to use new field names (Option A from checklist — recommended)

### Step 2.2: Fix Entity Settings request model
- **File:** `src/openlabels/server/routes/settings.py`
- Rename `EntitySettingsRequest` field: `entities` → `enabled_entities`
- Update handler body to use `request.enabled_entities`

---

## Phase 3: WEBSOCKET — Event Format Mismatch

### Step 3.1: Wrap backend WS payloads with `data` field (Option A)
- **File:** `src/openlabels/server/routes/ws_events.py`
- Update all 8 `publish_*` functions to nest payload fields under a `data` key
- This matches the frontend's expectation of `{ type: string, data: unknown }`
- The per-scan WebSocket in `ws.py` is a separate code path and does NOT need changes

**Rationale for Option A over Option B:** Option A (backend fix) is the conventional WebSocket API pattern — `{ type, data }` is a clean, well-structured envelope. The checklist recommends Option B for fewer lines changed, but Option A produces a better API contract long-term and doesn't require touching the frontend TypeScript at all.

---

## Phase 4: FRONTEND FIXES (one-liners)

### Step 4.1: Fix double JSON.stringify in users API
- **File:** `frontend/src/api/endpoints/users.ts`
- Change `body: JSON.stringify(payload)` to `body: payload`

*(No 4.2 needed since we're doing Option A for WebSocket in Phase 3)*

---

## Phase 5: CLEANUP

### Step 5.1: Remove unused `request: Request` parameters
After stripping HX-Request branches, these handlers no longer use `request`:
- `results.py`: `clear_all_results`, `delete_result`, `apply_recommended_label`, `rescan_file`
- `scans.py`: `cancel_scan`, `retry_scan`
- `schedules.py`: `delete_schedule`
- `settings.py`: `reset_settings`
- `targets.py`: `delete_target`
- `labels.py`: `update_label_mappings`

### Step 5.2: Consider adding `model_config = ConfigDict(extra="forbid")` to settings request models
- Add to `AzureSettingsRequest`, `EntitySettingsRequest`, `FanoutSettingsRequest`, `AdapterDefaultsRequest`
- This makes field name mismatches fail loudly (422) instead of silently dropping fields

---

## Execution Order

1. Phase 1 (steps 1.1 → 1.5) — blocking changes first
2. Phase 2 (steps 2.1 → 2.2) — fix silent data loss
3. Phase 3 (step 3.1) — fix WebSocket event format
4. Phase 4 (step 4.1) — frontend one-liner
5. Phase 5 (steps 5.1 → 5.2) — cleanup
6. Verify the app starts cleanly
7. Commit and push

---

## Risk Notes

- **Phase 1.1** (deleting `web/`) is safe — the React SPA fully replaces it and the SPA catch-all is independent
- **Phase 1.5** (Form → JSON conversion) changes the API contract for 2 endpoints — the frontend already sends JSON to these, so this is a fix, not a break
- **Phase 3** (Option A) changes the WS message shape — the frontend already expects the nested format, so this aligns backend to frontend
- All changes are mechanical with clear fallthrough paths already in place
