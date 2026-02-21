# Open Labels Frontend Code Changes Checklist

**Companion to:** `GUI_TEST_CHECKLIST.md` (testing) and `BACKEND_CHANGES_CHECKLIST.md` (backend work)
**This doc:** All frontend code changes needed before integration testing

**Total scope:** 3 confirmed bugs, all one-liners or near-one-liners. Under 30 minutes of work.

---

## 1. CONFIRMED BUG: Users API Double JSON.stringify

**File:** `frontend/src/api/endpoints/users.ts`, line 20

**The bug:** `usersApi.create` pre-stringifies the payload before passing it to `apiFetch`, which stringifies again. The backend receives a JSON string wrapped in a JSON string — `"\"{'name':'Dev User'}\"` — and returns 422.

**How `apiFetch` works** (from `client.ts` line 78):
```typescript
body: body ? JSON.stringify(body) : undefined,
```
It already stringifies whatever you pass as `body`. Every other endpoint passes raw objects. Only `users.ts` pre-stringifies.

**Fix:**

```typescript
// Line 20 — Before:
create: (payload: CreateUserPayload) =>
    apiFetch<User>('/users', { method: 'POST', body: JSON.stringify(payload) }),

// After:
create: (payload: CreateUserPayload) =>
    apiFetch<User>('/users', { method: 'POST', body: payload }),
```

**Impact without fix:** "Add User" dialog always fails with 422 validation error.

---

## 2. CONFIRMED BUG: WebSocket Global Events Never Reach Handlers

**File:** `frontend/src/lib/websocket.ts`, lines 49-53

**The bug:** Backend sends flat messages like `{"type": "scan_progress", "scan_id": "...", "progress": {...}}`. The WebSocket client parses the message and passes `message.data` to handlers — but there IS no `data` field. Every handler receives `undefined`.

**Impact without fix:** No real-time updates work. Scan progress bars don't move, completion toasts never fire, dashboard doesn't refresh on scan complete, health updates don't propagate.

**Fix:**

```typescript
// Lines 49-53 — Before:
this.ws.onmessage = (event) => {
  try {
    const message = JSON.parse(event.data as string) as { type: string; data: unknown };
    if (typeof message.type !== 'string' || !KNOWN_EVENT_TYPES.has(message.type)) return;
    const handlers = this.listeners.get(message.type);
    handlers?.forEach((handler) => handler(message.data));
  } catch {

// After:
this.ws.onmessage = (event) => {
  try {
    const message = JSON.parse(event.data as string) as Record<string, unknown>;
    const eventType = message.type as string | undefined;
    if (typeof eventType !== 'string' || !KNOWN_EVENT_TYPES.has(eventType)) return;
    const { type: _, ...payload } = message;
    const handlers = this.listeners.get(eventType);
    handlers?.forEach((handler) => handler(payload));
  } catch {
```

**Why this works:** The destructured `payload` has the exact shape the handlers expect. For example, `scan_progress` handler casts to `WSScanProgress` and reads `data.scan_id` and `data.progress` — the payload object IS `{scan_id, status, progress}`.

**Alternative:** Fix on backend instead (wrap all publish payloads in `"data": {...}` in `ws_events.py`). See `BACKEND_CHANGES_CHECKLIST.md` Section 3 for that approach. **Pick one side, not both.**

> **NOTE:** The per-scan WebSocket (`use-scan-websocket.ts`) reads the flat message directly and already works. This fix only affects the global WebSocket client.

---

## 3. CONFIRMED BUG: Settings Field Name Mismatches

This is a frontend/backend contract mismatch. It can be fixed on EITHER side. The backend checklist covers the backend fix option. Here's the frontend fix option if you prefer that.

### 3a. Azure Settings: Response Fields ≠ Request Fields

**The bug:** Settings page GET returns `{azure_tenant_id, azure_client_id, azure_client_secret_set}`. The generic `SettingsTab` component sends those exact field names back on save. But `AzureSettingsRequest` on the backend expects `{tenant_id, client_id, client_secret}`. Pydantic silently drops unknown fields and uses empty defaults. **Every save wipes Azure AD config to blank.**

**Affected pages (2):**
- `frontend/src/features/settings/page.tsx` — generic SettingsTab sends response field names
- `frontend/src/features/setup/wizard-page.tsx` — hardcodes `azure_tenant_id`, `azure_client_id`, `azure_client_secret`

**Frontend fix option — add field mapping in `settingsApi.update`:**

```typescript
// frontend/src/api/endpoints/settings.ts

// Field name mapping: response keys → request keys
const SETTINGS_FIELD_MAP: Record<string, Record<string, string>> = {
  azure: {
    azure_tenant_id: 'tenant_id',
    azure_client_id: 'client_id',
    azure_client_secret: 'client_secret',
    azure_client_secret_set: '__DROP__',  // read-only field, don't send back
  },
  entities: {
    enabled_entities: 'entities',
  },
};

function mapSettingsFields(category: string, settings: Record<string, unknown>): Record<string, unknown> {
  const fieldMap = SETTINGS_FIELD_MAP[category];
  if (!fieldMap) return settings;

  const mapped: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(settings)) {
    const mappedKey = fieldMap[key];
    if (mappedKey === '__DROP__') continue;  // skip read-only fields
    mapped[mappedKey ?? key] = value;
  }
  return mapped;
}

export const settingsApi = {
  list: () => apiFetch<AllSettings>('/settings'),

  update: (category: string, settings: Record<string, unknown>) =>
    apiFetch<SettingsUpdateResponse>(`/settings/${category}`, {
      method: 'POST',
      body: mapSettingsFields(category, settings),
    }),

  reset: () => apiFetch<SettingsUpdateResponse>('/settings/reset', { method: 'POST' }),
};
```

**Also fix setup wizard** (if using frontend fix):

```typescript
// frontend/src/features/setup/wizard-page.tsx — handleTestAzure and handleSaveAzure
// Change field names to match backend request model:
await settingsApi.update('azure', {
    tenant_id: tenantId,     // was: azure_tenant_id
    client_id: clientId,     // was: azure_client_id
    client_secret: clientSecret, // was: azure_client_secret
});
```

### 3b. Entity Settings: `enabled_entities` vs `entities`

**The bug:** Same pattern. Response has `enabled_entities`, request expects `entities`. The `SETTINGS_FIELD_MAP` above already handles this.

**Impact without fix:** Every save to the Entities tab wipes all enabled entity types to an empty array. Detection stops finding anything.

---

### Recommendation: Fix on Backend

The backend fix (rename request model fields to match response fields) is simpler — 2 models changed, ~9 lines, no frontend mapping layer needed. See `BACKEND_CHANGES_CHECKLIST.md` Section 2. The setup wizard and settings page both work automatically because they already use the response field names.

**If you fix on backend, skip this entire Section 3.** If you fix on frontend, use the mapping approach above.

---

## 4. NOT A BUG BUT WORTH NOTING: Hidden Pages

These pages exist in the router but have NO sidebar navigation links:

| Route | Page | How to Reach |
|---|---|---|
| `/config/resources` | Config Resources (targets + health) | Direct URL only |
| `/scan-config` | Scan Config (schedules + fanout) | Direct URL only |
| `/scan-config/new` | New schedule via scan-config | Direct URL only |
| `/setup` | Setup wizard | Direct URL, outside AppShell |

These are intentional — `/config/resources` and `/scan-config` appear to be alternate entry points to the same data shown in Targets, Schedules, and Settings. The setup wizard is a first-run experience. No fix needed, just be aware they exist during testing.

---

## 5. NOT A BUG BUT WORTH NOTING: Reports Page Is Actually Query Console

The `/reports` route renders a **SQL Editor + AI Query Assistant** powered by DuckDB, not a traditional reports/export page. The sidebar label says "Reports" and the icon is `BarChart3`. The `exportApi.report()` function exists in `export.ts` but no page calls it.

No fix needed — just know that "Reports" = "Query Console" during testing.

---

## Summary

| # | Bug | File | Lines Changed | Severity |
|---|---|---|---|---|
| 1 | Users double-stringify | `endpoints/users.ts` | 1 | **Breaks** user creation |
| 2 | WebSocket data nesting | `lib/websocket.ts` | 4 | **Breaks** all real-time updates |
| 3a | Azure settings field names | `endpoints/settings.ts` + `setup/wizard-page.tsx` | ~25 | **Silently wipes** Azure config |
| 3b | Entity settings field name | (covered by 3a mapping) | 0 | **Silently wipes** entity config |

**If fixing settings on backend instead:** Only bugs 1 and 2 need frontend changes = **5 lines total**.
