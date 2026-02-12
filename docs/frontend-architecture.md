# Frontend Architecture

**OpenLabels — React SPA for Windows Server Deployment**

This document defines the frontend architecture for OpenLabels. The new frontend replaces the current Jinja2/HTMX server-rendered UI with a React single-page application optimized for on-premises Windows Server environments.

---

## Table of Contents

1. [Design Goals](#design-goals)
2. [Deployment Model](#deployment-model)
3. [Technology Stack](#technology-stack)
4. [Project Structure](#project-structure)
5. [Backend Integration](#backend-integration)
6. [Routing & Navigation](#routing--navigation)
7. [State Management](#state-management)
8. [Authentication](#authentication)
9. [Real-Time Updates](#real-time-updates)
10. [Pages & Components](#pages--components)
11. [Data Fetching & Caching](#data-fetching--caching)
12. [Styling & Theming](#styling--theming)
13. [Tables, Pagination & Large Datasets](#tables-pagination--large-datasets)
14. [Forms & Validation](#forms--validation)
15. [Error Handling](#error-handling)
16. [Build & Bundling](#build--bundling)
17. [Testing Strategy](#testing-strategy)
18. [Accessibility](#accessibility)
19. [Migration Plan](#migration-plan)

---

## Design Goals

| Goal | Rationale |
|------|-----------|
| **Self-contained** | Zero runtime CDN dependencies. Everything bundled at build time. Critical for air-gapped Windows Server networks. |
| **Single process** | FastAPI serves the built SPA as static files. One Windows Service, one port, one installer. |
| **Windows-first** | Designed for admins accessing `https://server:8443` from Edge/Chrome on their workstation. No client install. |
| **Real-time** | Live scan progress, job queue updates, and file access events via WebSocket. |
| **Enterprise scale** | Efficient rendering of 100k+ scan results with cursor-based pagination and virtualized tables. |
| **Type-safe** | Full TypeScript coverage. API types generated from the OpenAPI spec. |

---

## Deployment Model

```
┌─────────────────────────────────────────────────────┐
│                  Windows Server                      │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │           OpenLabels Windows Service            │  │
│  │                                                  │  │
│  │  ┌──────────────────────────────────────────┐   │  │
│  │  │           FastAPI (uvicorn)               │   │  │
│  │  │                                            │   │  │
│  │  │  /api/v1/*     → JSON API routes           │   │  │
│  │  │  /ws/*         → WebSocket endpoints       │   │  │
│  │  │  /assets/*     → Vite-built static files   │   │  │
│  │  │  /*            → index.html (SPA fallback) │   │  │
│  │  └──────────────────────────────────────────┘   │  │
│  └────────────────────────────────────────────────┘  │
│                                                      │
│  PostgreSQL ─── Redis (optional)                     │
└─────────────────────────────────────────────────────┘

         ▲  HTTPS (port 8443)
         │
    ┌────┴────┐
    │  Admin  │  Edge/Chrome on LAN workstation
    │ Browser │
    └─────────┘
```

**Key deployment facts:**

- The React app is built at **package time** (MSI/installer build), not at runtime. The Windows Server never runs Node.js.
- FastAPI serves `index.html` for all non-API routes, enabling client-side routing.
- All npm dependencies are resolved at build time. Production has zero internet requirements.
- CORS is configured for same-origin since the API and SPA are served from the same host:port.

---

## Technology Stack

### Core

| Layer | Technology | Version | Rationale |
|-------|-----------|---------|-----------|
| **Framework** | React | 19+ | Component model, ecosystem, TypeScript support |
| **Language** | TypeScript | 5.5+ | Type safety, API contract enforcement |
| **Build** | Vite | 6+ | Fast builds, ESM-native, excellent DX |
| **Routing** | React Router | 7+ | File-system routing conventions, data loaders |

### State & Data

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Server state** | TanStack Query (React Query) | Cache invalidation, optimistic updates, WebSocket integration |
| **Client state** | Zustand | Lightweight, TypeScript-native, no boilerplate |
| **Forms** | React Hook Form + Zod | Performant forms with schema-based validation |

### UI

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Component library** | shadcn/ui | Copy-paste components built on Radix UI primitives. Full ownership, no version lock-in. |
| **Styling** | Tailwind CSS 4 | Utility-first, consistent with existing templates. Zero runtime CSS-in-JS overhead. |
| **Icons** | Lucide React | Tree-shakeable, consistent with shadcn/ui |
| **Charts** | Recharts | Composable chart components for dashboard visualizations |
| **Tables** | TanStack Table | Headless table logic for sorting, filtering, column visibility, virtualization |
| **Virtualization** | TanStack Virtual | Render 100k+ rows without DOM thrashing |

### Developer Experience

| Tool | Purpose |
|------|---------|
| **ESLint** | Linting with `@typescript-eslint` rules |
| **Prettier** | Code formatting |
| **Vitest** | Unit and integration tests (Vite-native) |
| **Playwright** | E2E browser tests |
| **openapi-typescript** | Generate TypeScript types from OpenAPI spec |
| **MSW** | Mock Service Worker for API mocking in tests and development |

---

## Project Structure

```
frontend/
├── index.html                    # SPA entry point
├── package.json
├── tsconfig.json
├── vite.config.ts
├── tailwind.config.ts            # May not be needed with Tailwind CSS 4 (@theme in CSS)
├── .env.development              # Dev proxy config (VITE_API_URL=http://localhost:8000)
├── .env.production               # Prod config (API is same-origin, no URL needed)
│
├── public/
│   └── favicon.ico
│
├── src/
│   ├── main.tsx                  # App entry, provider tree
│   ├── app.tsx                   # Root component, router outlet
│   ├── vite-env.d.ts
│   │
│   ├── api/                      # API client layer
│   │   ├── client.ts             # Fetch wrapper with auth, error handling
│   │   ├── types.ts              # Generated from OpenAPI spec
│   │   ├── endpoints/            # One file per API domain
│   │   │   ├── scans.ts
│   │   │   ├── results.ts
│   │   │   ├── targets.ts
│   │   │   ├── labels.ts
│   │   │   ├── schedules.ts
│   │   │   ├── dashboard.ts
│   │   │   ├── remediation.ts
│   │   │   ├── monitoring.ts
│   │   │   ├── policies.ts
│   │   │   ├── reporting.ts
│   │   │   ├── permissions.ts
│   │   │   ├── query.ts
│   │   │   ├── export.ts
│   │   │   ├── users.ts
│   │   │   ├── settings.ts
│   │   │   ├── browse.ts
│   │   │   ├── audit.ts
│   │   │   └── jobs.ts
│   │   └── hooks/                # TanStack Query hooks per domain
│   │       ├── use-scans.ts
│   │       ├── use-results.ts
│   │       ├── use-targets.ts
│   │       ├── use-labels.ts
│   │       ├── use-dashboard.ts
│   │       ├── use-remediation.ts
│   │       ├── use-monitoring.ts
│   │       ├── use-permissions.ts
│   │       ├── use-query.ts
│   │       └── ...
│   │
│   ├── components/               # Shared UI components
│   │   ├── ui/                   # shadcn/ui primitives (button, dialog, table, etc.)
│   │   ├── layout/               # App shell, sidebar, header, breadcrumbs
│   │   │   ├── app-shell.tsx
│   │   │   ├── sidebar.tsx
│   │   │   ├── header.tsx
│   │   │   └── breadcrumbs.tsx
│   │   ├── data-table/           # Reusable table with sorting, filtering, pagination
│   │   │   ├── data-table.tsx
│   │   │   ├── column-header.tsx
│   │   │   ├── pagination.tsx
│   │   │   └── toolbar.tsx
│   │   ├── risk-badge.tsx        # CRITICAL/HIGH/MEDIUM/LOW badge
│   │   ├── status-badge.tsx      # pending/running/completed/failed badge
│   │   ├── entity-tag.tsx        # SSN, CREDIT_CARD, etc. display
│   │   ├── file-icon.tsx         # File type icon mapping
│   │   ├── empty-state.tsx       # No data placeholder
│   │   └── loading-skeleton.tsx  # Skeleton loaders
│   │
│   ├── features/                 # Feature modules (page-level)
│   │   ├── dashboard/
│   │   │   ├── page.tsx
│   │   │   ├── stats-cards.tsx
│   │   │   ├── risk-distribution-chart.tsx
│   │   │   ├── findings-by-type-chart.tsx
│   │   │   ├── recent-scans-table.tsx
│   │   │   ├── activity-feed.tsx
│   │   │   └── system-status.tsx
│   │   │
│   │   ├── resource-explorer/    # Folder tree browser (layout.pptx slide 2)
│   │   │   ├── page.tsx
│   │   │   ├── folder-tree.tsx
│   │   │   ├── file-list.tsx
│   │   │   ├── file-detail-panel.tsx
│   │   │   ├── permissions-panel.tsx
│   │   │   └── risk-heatmap.tsx
│   │   │
│   │   ├── scans/
│   │   │   ├── list-page.tsx
│   │   │   ├── detail-page.tsx
│   │   │   ├── new-scan-dialog.tsx
│   │   │   ├── scan-progress.tsx  # Real-time WebSocket progress
│   │   │   └── scan-results-table.tsx
│   │   │
│   │   ├── results/
│   │   │   ├── list-page.tsx
│   │   │   ├── detail-page.tsx
│   │   │   ├── entity-detail-dialog.tsx
│   │   │   └── results-filters.tsx
│   │   │
│   │   ├── events/               # Sensitive data events timeline (layout.pptx slide 3)
│   │   │   ├── page.tsx
│   │   │   ├── event-timeline.tsx
│   │   │   ├── event-filters.tsx
│   │   │   └── event-detail-dialog.tsx
│   │   │
│   │   ├── permissions/          # Permissions explorer (layout.pptx slide 4)
│   │   │   ├── page.tsx
│   │   │   ├── acl-viewer.tsx
│   │   │   ├── exposure-summary.tsx
│   │   │   └── principal-lookup.tsx
│   │   │
│   │   ├── labels/
│   │   │   ├── list-page.tsx
│   │   │   ├── sync-page.tsx
│   │   │   ├── label-rules-table.tsx
│   │   │   └── label-mapping-editor.tsx
│   │   │
│   │   ├── remediation/          # Remediation jobs (layout.pptx slide 5)
│   │   │   ├── page.tsx
│   │   │   ├── remediation-table.tsx
│   │   │   ├── quarantine-dialog.tsx
│   │   │   ├── lockdown-dialog.tsx
│   │   │   └── rollback-dialog.tsx
│   │   │
│   │   ├── reports/              # Reports with SQL editor (layout.pptx slides 6-7)
│   │   │   ├── page.tsx
│   │   │   ├── report-builder.tsx
│   │   │   ├── sql-editor.tsx     # Monaco-based SQL query editor
│   │   │   ├── ai-assistant.tsx   # Natural language → SQL via Anthropic/OpenAI
│   │   │   ├── chart-builder.tsx
│   │   │   └── export-dialog.tsx
│   │   │
│   │   ├── targets/
│   │   │   ├── list-page.tsx
│   │   │   ├── form-page.tsx
│   │   │   └── adapter-config-fields.tsx
│   │   │
│   │   ├── schedules/
│   │   │   ├── list-page.tsx
│   │   │   ├── form-page.tsx
│   │   │   └── cron-builder.tsx
│   │   │
│   │   ├── monitoring/
│   │   │   ├── page.tsx
│   │   │   ├── job-queue-table.tsx
│   │   │   ├── system-health.tsx
│   │   │   └── activity-log.tsx
│   │   │
│   │   ├── policies/
│   │   │   ├── list-page.tsx
│   │   │   ├── policy-editor.tsx
│   │   │   └── violation-table.tsx
│   │   │
│   │   └── settings/             # Settings tabs (layout.pptx slide 8)
│   │       ├── page.tsx
│   │       ├── general-tab.tsx
│   │       ├── azure-tab.tsx
│   │       ├── detection-tab.tsx
│   │       ├── entities-tab.tsx
│   │       ├── adapters-tab.tsx
│   │       └── users-tab.tsx
│   │
│   ├── hooks/                    # Shared custom hooks
│   │   ├── use-websocket.ts      # WebSocket connection manager
│   │   ├── use-debounce.ts
│   │   ├── use-local-storage.ts
│   │   └── use-media-query.ts
│   │
│   ├── lib/                      # Utilities
│   │   ├── utils.ts              # cn() classname merge, formatters
│   │   ├── constants.ts          # Risk tiers, entity types, status values
│   │   ├── websocket.ts          # WebSocket client with reconnection
│   │   └── date.ts               # Date/time formatting helpers
│   │
│   ├── stores/                   # Zustand client state
│   │   ├── auth-store.ts         # Current user, tenant
│   │   ├── ui-store.ts           # Sidebar collapsed, theme, preferences
│   │   └── websocket-store.ts    # Connection status, subscriptions
│   │
│   └── styles/
│       └── globals.css           # Tailwind base + custom CSS variables
│
└── tests/
    ├── setup.ts                  # Vitest global setup, MSW handlers
    ├── components/               # Component unit tests
    ├── features/                 # Feature integration tests
    └── e2e/                      # Playwright E2E tests
```

---

## Backend Integration

### API Client

The frontend communicates exclusively through the versioned REST API (`/api/v1/*`) and WebSocket (`/ws/*`). No server-rendered HTML.

```typescript
// src/api/client.ts
const BASE_URL = import.meta.env.VITE_API_URL ?? '';

interface ApiFetchOptions extends RequestInit {
  params?: Record<string, string | number | boolean | undefined>;
}

async function apiFetch<T>(
  path: string,
  options?: ApiFetchOptions,
): Promise<T> {
  let url = `${BASE_URL}/api/v1${path}`;

  // Build query string from params
  if (options?.params) {
    const searchParams = new URLSearchParams();
    for (const [key, value] of Object.entries(options.params)) {
      if (value !== undefined) {
        searchParams.set(key, String(value));
      }
    }
    const qs = searchParams.toString();
    if (qs) url += `?${qs}`;
  }

  // Separate params from RequestInit (params is not a valid fetch option)
  const { params: _, ...fetchOptions } = options ?? {};

  const response = await fetch(url, {
    credentials: 'include',  // Send session cookie
    headers: {
      'Content-Type': 'application/json',
      ...fetchOptions.headers,
    },
    ...fetchOptions,
  });

  if (!response.ok) {
    throw new ApiError(response.status, await response.json());
  }

  return response.json();
}
```

### Type Generation

API types are generated from the FastAPI OpenAPI spec to ensure frontend-backend type alignment:

```bash
# Generate types from running server
npx openapi-typescript http://localhost:8000/api/openapi.json -o src/api/types.ts

# Or from saved spec file
npx openapi-typescript ../api/openapi.json -o src/api/types.ts
```

This produces strongly-typed request/response interfaces for every endpoint:

```typescript
// Auto-generated — do not edit
export interface ScanJob {
  id: string;
  tenant_id: string;
  target_name: string | null;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  files_scanned: number;
  files_with_pii: number;
  progress: { files_scanned: number; files_total: number; current_file: string } | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}
```

### Endpoint Modules

Each API domain gets a dedicated endpoint file that wraps raw fetch calls:

```typescript
// src/api/endpoints/scans.ts
import { apiFetch } from '../client';
import type { ScanJob, PaginatedResponse } from '../types';

export const scansApi = {
  list: (params?: { status?: string; page?: number }) =>
    apiFetch<PaginatedResponse<ScanJob>>('/scans', { params }),

  get: (id: string) =>
    apiFetch<ScanJob>(`/scans/${id}`),

  create: (payload: { target_ids: string[] }) =>
    apiFetch<ScanJob>('/scans', { method: 'POST', body: JSON.stringify(payload) }),

  cancel: (id: string) =>
    apiFetch<void>(`/scans/${id}/cancel`, { method: 'POST' }),
};
```

### TanStack Query Hooks

Each endpoint module has corresponding React Query hooks:

```typescript
// src/api/hooks/use-scans.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { scansApi } from '../endpoints/scans';

export function useScans(params?: { status?: string }) {
  return useQuery({
    queryKey: ['scans', params],
    queryFn: () => scansApi.list(params),
    refetchInterval: 10_000,  // Poll every 10s for active scans
  });
}

export function useScan(id: string) {
  return useQuery({
    queryKey: ['scans', id],
    queryFn: () => scansApi.get(id),
  });
}

export function useCreateScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: scansApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });
}
```

---

## Routing & Navigation

### Route Map

Routes mirror the existing `/ui/*` paths for backward compatibility. All routes use React Router with lazy-loaded feature modules.

```typescript
// src/app.tsx
import { createBrowserRouter } from 'react-router-dom';
import { AppShell } from './components/layout/app-shell';

const router = createBrowserRouter([
  {
    element: <AppShell />,
    children: [
      { index: true,                   lazy: () => import('./features/dashboard/page') },
      { path: 'dashboard',             lazy: () => import('./features/dashboard/page') },
      { path: 'explorer',              lazy: () => import('./features/resource-explorer/page') },
      { path: 'events',                lazy: () => import('./features/events/page') },
      { path: 'permissions',           lazy: () => import('./features/permissions/page') },
      { path: 'scans',                 lazy: () => import('./features/scans/list-page') },
      { path: 'scans/new',             lazy: () => import('./features/scans/new-scan-dialog') },
      { path: 'scans/:scanId',         lazy: () => import('./features/scans/detail-page') },
      { path: 'results',               lazy: () => import('./features/results/list-page') },
      { path: 'results/:resultId',     lazy: () => import('./features/results/detail-page') },
      { path: 'labels',                lazy: () => import('./features/labels/list-page') },
      { path: 'labels/sync',           lazy: () => import('./features/labels/sync-page') },
      { path: 'remediation',           lazy: () => import('./features/remediation/page') },
      { path: 'reports',               lazy: () => import('./features/reports/page') },
      { path: 'targets',               lazy: () => import('./features/targets/list-page') },
      { path: 'targets/new',           lazy: () => import('./features/targets/form-page') },
      { path: 'targets/:targetId',     lazy: () => import('./features/targets/form-page') },
      { path: 'schedules',             lazy: () => import('./features/schedules/list-page') },
      { path: 'schedules/new',         lazy: () => import('./features/schedules/form-page') },
      { path: 'schedules/:scheduleId', lazy: () => import('./features/schedules/form-page') },
      { path: 'monitoring',            lazy: () => import('./features/monitoring/page') },
      { path: 'policies',              lazy: () => import('./features/policies/list-page') },
      { path: 'settings',              lazy: () => import('./features/settings/page') },
    ],
  },
  { path: 'login', lazy: () => import('./features/auth/login-page') },
]);
```

### Sidebar Navigation

The sidebar organizes pages into logical groups matching the PowerPoint layout:

```
OVERVIEW
  Dashboard
  Resource Explorer
  Events

DATA PROTECTION
  Scan Results
  Scans
  Labels

SECURITY
  Permissions
  Remediation
  Policies

OPERATIONS
  Targets
  Schedules
  Monitoring
  Reports

CONFIGURATION
  Settings
```

### FastAPI SPA Fallback

FastAPI must serve `index.html` for all non-API routes to support client-side routing:

```python
# In the FastAPI app, after API routes are mounted:
from fastapi.staticfiles import StaticFiles

# Serve built assets
app.mount("/assets", StaticFiles(directory="frontend/dist/assets"), name="assets")

# SPA fallback: serve index.html for all other routes
@app.get("/{path:path}", include_in_schema=False)
async def spa_fallback(path: str):
    return FileResponse("frontend/dist/index.html")
```

---

## State Management

### State Architecture

State is divided into three categories based on ownership:

```
┌─────────────────────────────────────────────────────┐
│                   React App                          │
│                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │ Server State │  │ Client State │  │  URL State  │ │
│  │              │  │              │  │             │ │
│  │ TanStack     │  │ Zustand      │  │ React       │ │
│  │ Query        │  │              │  │ Router      │ │
│  │              │  │              │  │             │ │
│  │ • API data   │  │ • Sidebar    │  │ • Filters   │ │
│  │ • Cache      │  │   collapsed  │  │ • Pagination│ │
│  │ • Mutations  │  │ • Theme      │  │ • Sort      │ │
│  │ • WebSocket  │  │ • User prefs │  │ • Tab       │ │
│  │   updates    │  │ • Toast      │  │ • Search    │ │
│  │              │  │   queue      │  │             │ │
│  └──────────────┘  └──────────────┘  └────────────┘ │
└─────────────────────────────────────────────────────┘
```

**Server state (TanStack Query):** All data from the API. Scans, results, targets, labels, dashboard stats. Automatically cached, refetched on focus, invalidated on mutations.

**Client state (Zustand):** UI preferences that don't belong in the URL or on the server. Sidebar collapsed, dark/light theme, toast notifications.

**URL state (React Router):** Filter parameters, pagination cursors, sort columns, active tabs. Bookmarkable, shareable, survives refresh.

### Server State: TanStack Query Configuration

```typescript
// src/main.tsx
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,         // Data is fresh for 30 seconds
      gcTime: 5 * 60_000,        // Garbage collect after 5 minutes
      retry: 1,                  // Retry failed requests once
      refetchOnWindowFocus: true, // Refetch when admin tabs back
    },
  },
});
```

### Client State: Zustand Store

```typescript
// src/stores/ui-store.ts
interface UIState {
  sidebarCollapsed: boolean;
  theme: 'light' | 'dark' | 'system';
  toggleSidebar: () => void;
  setTheme: (theme: 'light' | 'dark' | 'system') => void;
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      theme: 'system',
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      setTheme: (theme) => set({ theme }),
    }),
    { name: 'openlabels-ui' },  // localStorage key
  ),
);
```

---

## Authentication

### Flow

OpenLabels uses Azure AD OAuth. The frontend delegates authentication entirely to the backend:

```
1. User visits /dashboard
2. React checks auth state (GET /api/v1/auth/me)
3. If 401 → redirect to /api/v1/auth/login (server-side OAuth redirect)
4. Azure AD login → callback to /api/v1/auth/callback
5. Server sets HttpOnly session cookie
6. Server redirects to /dashboard
7. React picks up session, loads data
```

The SPA never handles tokens directly. The session cookie (`openlabels_session`) is HttpOnly and Secure, managed entirely by the FastAPI backend. All HTTP requests use `credentials: 'include'` and all WebSocket connections inherit the same session cookie for authentication. The backend also supports Bearer tokens via the `Authorization` header for API clients, but the frontend should always use cookies.

```typescript
// src/stores/auth-store.ts
interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  checkAuth: () => Promise<void>;
  logout: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: false,
  isLoading: true,

  checkAuth: async () => {
    try {
      const user = await apiFetch<User>('/auth/me');
      set({ user, isAuthenticated: true, isLoading: false });
    } catch {
      set({ user: null, isAuthenticated: false, isLoading: false });
    }
  },

  logout: async () => {
    await apiFetch('/auth/logout', { method: 'POST' });
    set({ user: null, isAuthenticated: false });
    window.location.href = '/login';
  },
}));
```

### Route Protection

```typescript
// src/components/layout/auth-guard.tsx
function AuthGuard({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuthStore();

  if (isLoading) return <LoadingSkeleton />;
  if (!isAuthenticated) {
    window.location.href = '/api/v1/auth/login';
    return null;
  }

  return children;
}
```

### Role-Based Access

Admin-only features (settings, user management) check the user's role:

```typescript
function AdminOnly({ children }: { children: React.ReactNode }) {
  const { user } = useAuthStore();
  if (user?.role !== 'admin') return null;
  return children;
}
```

---

## Real-Time Updates

### WebSocket Architecture

The backend provides two WebSocket endpoints:

1. **`/ws/scans/{scan_id}`** — Per-scan progress updates (original, pre-existing)
2. **`/ws/events`** — Global event bus for all tenant events (new, multiplexed)

The frontend uses the global `/ws/events` endpoint for a single persistent connection that delivers all event types for the authenticated user's tenant. Authentication uses the same session cookie as HTTP requests.

```typescript
// src/lib/websocket.ts
class OpenLabelsWebSocket {
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectDelay = 1000;
  private maxReconnectDelay = 30000;
  private listeners = new Map<string, Set<(data: any) => void>>();

  connect() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    this.ws = new WebSocket(`${protocol}//${location.host}/ws/events`);

    this.ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      const handlers = this.listeners.get(message.type);
      handlers?.forEach((handler) => handler(message.data));
    };

    this.ws.onclose = () => {
      this.scheduleReconnect();
    };
  }

  subscribe(eventType: string, handler: (data: any) => void) {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set());
    }
    this.listeners.get(eventType)!.add(handler);
    return () => this.listeners.get(eventType)?.delete(handler);
  }

  private scheduleReconnect() {
    this.reconnectTimer = setTimeout(() => {
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
      this.connect();
    }, this.reconnectDelay);
  }
}
```

### WebSocket → Query Cache Integration

WebSocket events invalidate TanStack Query caches for automatic UI updates:

```typescript
// src/hooks/use-websocket.ts
export function useWebSocketSync() {
  const queryClient = useQueryClient();
  const ws = useWebSocket();

  useEffect(() => {
    const unsubscribers = [
      ws.subscribe('scan_progress', (data) => {
        // Update specific scan in cache
        queryClient.setQueryData(['scans', data.job_id], (old: ScanJob) => ({
          ...old,
          files_scanned: data.files_scanned,
          progress: data.progress,
        }));
      }),

      ws.subscribe('scan_completed', (data) => {
        queryClient.invalidateQueries({ queryKey: ['scans'] });
        queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      }),

      ws.subscribe('label_applied', () => {
        queryClient.invalidateQueries({ queryKey: ['results'] });
        queryClient.invalidateQueries({ queryKey: ['labels'] });
      }),

      ws.subscribe('remediation_completed', () => {
        queryClient.invalidateQueries({ queryKey: ['remediation'] });
      }),
    ];

    return () => unsubscribers.forEach((unsub) => unsub());
  }, [queryClient, ws]);
}
```

### Event Types

Events pushed from the backend to the frontend:

| Event | Payload | Triggers |
|-------|---------|----------|
| `scan_progress` | `{ job_id, files_scanned, files_total, current_file }` | Progress bar updates on scan detail page |
| `scan_completed` | `{ job_id, status, files_scanned, files_with_pii }` | Scan list refresh, dashboard stats refresh |
| `scan_failed` | `{ job_id, error }` | Error toast, scan list refresh |
| `label_applied` | `{ result_id, label_name }` | Results table cell update |
| `remediation_completed` | `{ action_id, action_type, status }` | Remediation table refresh |
| `job_status` | `{ job_id, status }` | Job queue table in monitoring |
| `file_access` | `{ file_path, user_name, action, event_time }` | Events timeline (live) |
| `health_update` | `{ component, status }` | System health indicators |

---

## Pages & Components

### Page Inventory

Mapping from the PowerPoint layout mockups (`docs/layout.pptx`) and existing templates to React feature modules:

#### Slide 1: Dashboard

**File:** `features/dashboard/page.tsx`

| Section | Component | Data Source |
|---------|-----------|-------------|
| Stats cards (files scanned, findings, critical, active scans) | `stats-cards.tsx` | `GET /api/v1/dashboard/stats` |
| Risk distribution donut chart | `risk-distribution-chart.tsx` | `GET /api/v1/dashboard/stats` (risk breakdown in response) |
| Findings by entity type bar chart | `findings-by-type-chart.tsx` | `GET /api/v1/dashboard/entity-trends?days=30` |
| Recent scans table | `recent-scans-table.tsx` | `GET /api/v1/scans?limit=5` |
| Activity feed | `activity-feed.tsx` | `GET /api/v1/audit?limit=10` |
| System status indicators | `system-status.tsx` | `GET /api/v1/health` + WebSocket |

#### Slide 2: Resource Explorer

**File:** `features/resource-explorer/page.tsx`

Three-panel layout:
- **Left:** Folder tree (expandable, lazy-loaded via `GET /api/v1/browse/{target_id}`)
- **Center:** File list for selected folder with risk badges and entity counts
- **Right:** Detail panel for selected file — risk score, entity breakdown, permissions, label status

Uses the `DirectoryTree`, `SecurityDescriptor`, and `FileInventory` models from the backend.

#### Slide 3: Events on Sensitive Data

**File:** `features/events/page.tsx`

Timeline view of file access events from `file_access_events` table:
- Filterable by file path, user, action type, date range
- Real-time events via WebSocket `file_access` messages
- Grouped by day with expandable detail

#### Slide 4: Permissions Explorer

**File:** `features/permissions/page.tsx`

**Backend endpoints (new — `/api/v1/permissions/`):**
- `GET /permissions/exposure` — Tenant-wide exposure summary (counts by level)
- `GET /permissions/{target_id}/directories` — Paginated directory list with ACL flags, filterable by exposure level
- `GET /permissions/{target_id}/acl/{dir_id}` — Full ACL detail for a directory (owner, group, DACL SDDL, permissions JSON)
- `GET /permissions/principal/{principal}` — Find all directories accessible by a principal (SID or name)

- ACL viewer showing NTFS/POSIX permissions per directory
- Exposure level summary (PRIVATE/INTERNAL/ORG_WIDE/PUBLIC)
- Principal lookup — search by SID/name to find all accessible directories
- "World accessible" and "Authenticated Users" quick filters

#### Slide 5: Remediation

**File:** `features/remediation/page.tsx`

Table of remediation actions with columns: file path, action type, status, performed by, timestamp.
- **Quarantine:** Dialog to move file to secure location
- **Lockdown:** Dialog to restrict permissions to specific principals
- **Rollback:** Reverse a previous quarantine or lockdown
- Dry-run toggle for preview mode

#### Slides 6-7: Reports

**File:** `features/reports/page.tsx`

Two-mode report builder:
1. **SQL mode:** Monaco-based SQL editor querying the DuckDB analytics layer. Syntax highlighting, autocomplete for table/column names, results grid below.
2. **AI mode:** Natural language query box. User types "Show me all files with SSN in the Finance share from last week." Backend translates to SQL via Anthropic/OpenAI, shows results.

**Backend endpoints (new — `/api/v1/query/`):**
- `GET /query/schema` — Returns all analytics tables and their columns for Monaco autocomplete
- `POST /query` — Execute read-only SQL (SELECT/WITH only) against DuckDB. Uses `$1` parameter for tenant isolation. Row-limited, time-bounded.
- `POST /query/ai` — Natural language → SQL via Anthropic Claude (or OpenAI fallback). Validates generated SQL, optionally executes it. Requires `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` env var.

Available analytics tables: `scan_results`, `file_inventory`, `folder_inventory`, `directory_tree`, `access_events`, `audit_log`, `remediation_actions`.

Shared features: export to PDF/Excel/CSV, chart builder for visualizations, save/load report templates.

#### Slide 8: Settings

**File:** `features/settings/page.tsx`

Tab-based layout:
- **General:** Server environment, logging, CORS
- **Azure AD:** Tenant ID, client ID, secret status
- **Detection:** Confidence threshold, OCR, max file size
- **Entities:** Toggle individual entity types on/off
- **Adapters:** Configure filesystem, SharePoint, OneDrive, S3, GCS, Azure Blob
- **Users:** User management (admin only)

### Shared Components

#### Risk Badge

Color-coded badge used across all tables and detail views:

| Tier | Color | Background |
|------|-------|------------|
| CRITICAL | White | Red-600 |
| HIGH | White | Orange-500 |
| MEDIUM | Gray-900 | Yellow-400 |
| LOW | Gray-700 | Green-100 |
| MINIMAL | Gray-500 | Gray-100 |

#### Status Badge

For scan and job statuses:

| Status | Style |
|--------|-------|
| pending | Gray outline |
| running | Blue with pulse animation |
| completed | Green solid |
| failed | Red solid |
| cancelled | Gray solid |

#### Data Table

Reusable table built on TanStack Table with:
- Sortable columns (click header to toggle asc/desc)
- Column visibility toggle
- Row selection (for bulk actions)
- Keyboard navigation
- Responsive: horizontal scroll on narrow viewports

---

## Data Fetching & Caching

### Pagination Strategy

The backend supports both offset-based and cursor-based pagination:

- **Offset-based** (`PaginatedResponse`): Returns `{ items, total, page, page_size, total_pages, has_next, has_previous }`. Used by most endpoints. Query params: `page=1&page_size=50`.
- **Cursor-based** (`CursorPaginatedResponse`): Returns `{ items, next_cursor, previous_cursor, has_next, has_previous, page_size }`. Available for large datasets (results, events). Uses HMAC-signed opaque cursors.

The frontend uses:
- **Cursor-based** for results and events — large datasets where offset counting is expensive. Uses `useInfiniteQuery`.
- **Offset-based** for targets, schedules, labels, permissions — smaller datasets where page numbers are useful.

```typescript
// Cursor-based pagination hook (for results, events)
export function useResultsCursor(filters: ResultFilters) {
  return useInfiniteQuery({
    queryKey: ['results', filters],
    queryFn: ({ pageParam }) =>
      resultsApi.list({ ...filters, cursor: pageParam }),
    getNextPageParam: (lastPage) =>
      lastPage.has_next ? lastPage.next_cursor : undefined,
    initialPageParam: undefined as string | undefined,
  });
}

// Offset-based pagination hook (for targets, permissions, etc.)
export function useTargets(page: number = 1) {
  return useQuery({
    queryKey: ['targets', { page }],
    queryFn: () => targetsApi.list({ page, page_size: 50 }),
  });
}
```

### Cache Invalidation Matrix

| Mutation | Invalidates |
|----------|-------------|
| Create scan | `['scans']`, `['dashboard']` |
| Cancel scan | `['scans']`, `['scans', id]` |
| Create target | `['targets']` |
| Update target | `['targets']`, `['targets', id]` |
| Delete target | `['targets']` |
| Sync labels | `['labels']` |
| Apply label | `['results', id]`, `['labels']` |
| Create schedule | `['schedules']` |
| Execute remediation | `['remediation']`, `['results']` |
| Update settings | `['settings']` |

### Stale Time by Data Type

| Data | Stale Time | Rationale |
|------|-----------|-----------|
| Dashboard stats | 30s | Should update frequently but not hammered |
| Scan list | 10s | Active scans change often |
| Active scan progress | 0s (WebSocket) | Real-time requirement |
| Results list | 60s | Static after scan completes |
| Targets | 5min | Rarely change |
| Labels | 5min | Sync is manual |
| Settings | 10min | Almost never changes |

---

## Styling & Theming

### Tailwind CSS Configuration

Tailwind 4 with CSS-first configuration:

```css
/* src/styles/globals.css */
@import 'tailwindcss';

@theme {
  --color-primary-50: #eff6ff;
  --color-primary-100: #dbeafe;
  --color-primary-500: #3b82f6;
  --color-primary-600: #2563eb;
  --color-primary-700: #1d4ed8;

  --color-risk-critical: #dc2626;
  --color-risk-high: #f97316;
  --color-risk-medium: #eab308;
  --color-risk-low: #22c55e;
  --color-risk-minimal: #6b7280;

  --color-status-pending: #6b7280;
  --color-status-running: #3b82f6;
  --color-status-completed: #22c55e;
  --color-status-failed: #dc2626;
  --color-status-cancelled: #9ca3af;
}
```

### Dark Mode

Supports `light`, `dark`, and `system` (follows OS preference via `prefers-color-scheme`):

```css
@media (prefers-color-scheme: dark) {
  :root {
    --background: #0a0a0a;
    --foreground: #fafafa;
    --card: #141414;
    --border: #262626;
  }
}

[data-theme='dark'] {
  --background: #0a0a0a;
  --foreground: #fafafa;
  /* ... same dark vars but forced regardless of OS */
}
```

### Responsive Breakpoints

| Breakpoint | Width | Target |
|------------|-------|--------|
| `sm` | 640px | — |
| `md` | 768px | — |
| `lg` | 1024px | Sidebar collapses below this |
| `xl` | 1280px | Three-panel layouts (resource explorer) |
| `2xl` | 1536px | Wide dashboard charts |

The primary target is `xl`+ (admin on a workstation monitor). Smaller breakpoints are for admins with split screens or laptop displays, not mobile.

---

## Tables, Pagination & Large Datasets

### TanStack Table Integration

All data tables share a reusable `<DataTable>` component:

```typescript
// src/components/data-table/data-table.tsx
interface DataTableProps<TData> {
  columns: ColumnDef<TData>[];
  data: TData[];
  pagination: PaginationState;
  onPaginationChange: (pagination: PaginationState) => void;
  sorting?: SortingState;
  onSortingChange?: (sorting: SortingState) => void;
  isLoading?: boolean;
  emptyMessage?: string;
}
```

### Virtualized Tables

For the results list (100k+ rows), TanStack Virtual renders only visible rows:

```typescript
// Only render ~30 visible rows, regardless of total dataset size
const virtualizer = useVirtualizer({
  count: results.length,
  getScrollElement: () => parentRef.current,
  estimateSize: () => 48,  // Row height in px
  overscan: 10,
});
```

### Infinite Scroll

Results and events pages use infinite scroll with cursor-based pagination:

```
User scrolls → hits bottom → useInfiniteQuery fetches next cursor page → appends to list
```

The scroll position and loaded pages are preserved when navigating away and back (TanStack Query cache).

---

## Forms & Validation

### React Hook Form + Zod

Forms use React Hook Form for performance (no re-renders on every keystroke) with Zod schemas for validation:

```typescript
// Target form schema
const targetSchema = z.object({
  name: z.string().min(1, 'Name is required').max(255),
  adapter: z.enum(['filesystem', 'sharepoint', 'onedrive', 's3', 'gcs', 'azure_blob']),
  enabled: z.boolean().default(true),
  config: z.record(z.string()).default({}),
});

type TargetFormData = z.infer<typeof targetSchema>;

function TargetForm({ target }: { target?: Target }) {
  const form = useForm<TargetFormData>({
    resolver: zodResolver(targetSchema),
    defaultValues: target ?? { name: '', adapter: 'filesystem', enabled: true, config: {} },
  });
  // ...
}
```

### Adapter-Specific Config Fields

The target form dynamically renders config fields based on the selected adapter type:

| Adapter | Fields |
|---------|--------|
| `filesystem` | Root path, file extensions filter, exclude patterns |
| `sharepoint` | Site URL(s), document libraries, scan all sites toggle |
| `onedrive` | User emails, scan all users toggle |
| `s3` | Bucket name, region, access key, secret key, endpoint URL |
| `gcs` | Bucket name, project, credentials path |
| `azure_blob` | Container, storage account, connection string |

### Cron Builder

The schedule form includes an interactive cron expression builder:

```
┌─────────────────────────────────────────┐
│ Every [ Monday ▼] at [ 02:00 ▼]        │
│                                          │
│ Cron expression: 0 2 * * 1              │
│ Next 3 runs:                             │
│   Mon, Feb 17 at 02:00 AM               │
│   Mon, Feb 24 at 02:00 AM               │
│   Mon, Mar 03 at 02:00 AM               │
└─────────────────────────────────────────┘
```

---

## Error Handling

### API Error Handling

```typescript
// src/api/client.ts
class ApiError extends Error {
  constructor(
    public status: number,
    public body: { error: string; message: string; details?: unknown },
  ) {
    super(body.message);
  }
}
```

### Error Boundaries

Feature-level error boundaries prevent one broken page from crashing the whole app:

```typescript
// Each route is wrapped:
<ErrorBoundary fallback={<PageErrorFallback />}>
  <ScanDetailPage />
</ErrorBoundary>
```

### Toast Notifications

Non-blocking notifications for mutations and WebSocket events:

| Level | When |
|-------|------|
| Success | Scan created, label applied, settings saved |
| Error | API failure, WebSocket disconnect |
| Warning | Session expiring, rate limited |
| Info | Scan completed, new findings detected |

### Offline / Disconnected State

When the WebSocket disconnects or API calls fail:

1. Banner at top: "Connection lost. Retrying..."
2. WebSocket reconnects with exponential backoff (1s → 2s → 4s → ... → 30s max)
3. TanStack Query retries failed requests once, then shows stale data with a "stale" indicator
4. When connection restores, all active queries are refetched

---

## Build & Bundling

### Vite Configuration

```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,          // No sourcemaps in production (Windows Server)
    target: 'es2022',          // Edge 109+ (modern Windows)
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          router: ['react-router'],
          query: ['@tanstack/react-query'],
          charts: ['recharts'],
          table: ['@tanstack/react-table', '@tanstack/react-virtual'],
          ui: ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu'],
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
      '/ws': { target: 'ws://localhost:8000', ws: true },
    },
  },
});
```

### Build Output

```
dist/
├── index.html                    # ~1 KB
├── assets/
│   ├── vendor-[hash].js          # React, ReactDOM (~140 KB gzipped)
│   ├── app-[hash].js             # Application code (~80 KB gzipped)
│   ├── charts-[hash].js          # Recharts (lazy-loaded, ~45 KB gzipped)
│   ├── table-[hash].js           # TanStack Table (lazy-loaded, ~15 KB gzipped)
│   └── style-[hash].css          # Tailwind + component styles (~25 KB gzipped)
└── favicon.ico
```

Total initial load: ~250 KB gzipped (vendor + app + styles). Charts and table chunks lazy-load on first use.

### Browser Targets

- Microsoft Edge 109+ (Chromium-based, ships with Windows Server 2022)
- Google Chrome 109+
- Firefox 115+ (ESR)

No IE11 support. No Safari requirement (this is a Windows Server app).

### Integration with Python Build

The frontend build integrates into the Python package build pipeline:

```toml
# pyproject.toml (addition)
[tool.setuptools.package-data]
openlabels = ["frontend/dist/**/*"]
```

The MSI installer / Docker build runs `npm run build` during the packaging step and includes the `dist/` directory alongside the Python code.

---

## Testing Strategy

### Unit Tests (Vitest)

Component and hook tests using Vitest + React Testing Library:

```typescript
// tests/components/risk-badge.test.tsx
import { render, screen } from '@testing-library/react';
import { RiskBadge } from '@/components/risk-badge';

test('renders CRITICAL badge with red background', () => {
  render(<RiskBadge tier="CRITICAL" />);
  const badge = screen.getByText('CRITICAL');
  expect(badge).toHaveClass('bg-red-600');
});
```

### Integration Tests (Vitest + MSW)

API integration tests mock the backend with MSW:

```typescript
// tests/features/scans.test.tsx
import { server } from '../mocks/server';
import { http, HttpResponse } from 'msw';

test('shows scan list from API', async () => {
  server.use(
    http.get('/api/v1/scans', () =>
      HttpResponse.json({ items: [mockScan], total: 1 }),
    ),
  );

  render(<ScansListPage />);
  await screen.findByText('Finance Share Scan');
});
```

### E2E Tests (Playwright)

Full browser tests against the real backend:

```typescript
// tests/e2e/scan-flow.spec.ts
test('create and monitor a scan', async ({ page }) => {
  await page.goto('/scans');
  await page.click('text=New Scan');
  await page.check('text=Finance Share');
  await page.click('text=Start Scan');

  // Wait for scan to appear in list
  await expect(page.locator('text=running')).toBeVisible();

  // Wait for completion (WebSocket updates)
  await expect(page.locator('text=completed')).toBeVisible({ timeout: 60_000 });
});
```

### Test Coverage Targets

| Layer | Coverage Target |
|-------|----------------|
| API hooks | 90% |
| Shared components | 85% |
| Feature pages | 70% |
| E2E critical paths | Login, scan CRUD, results, remediation |

---

## Accessibility

### Standards

WCAG 2.1 Level AA compliance. shadcn/ui components (built on Radix UI) provide accessible primitives out of the box:

- Keyboard navigation on all interactive elements
- Focus management in dialogs and dropdowns
- ARIA labels on icon-only buttons
- Color contrast ratios meet AA standards in both light and dark themes
- Screen reader announcements for loading states and toast notifications

### Specific Considerations

| Feature | Accessibility |
|---------|--------------|
| Data tables | Arrow key navigation between cells, sortable column headers |
| Risk badges | Color + text label (not color alone) |
| Scan progress | `aria-valuenow` / `aria-valuemax` on progress bar |
| Folder tree | `role="tree"` / `role="treeitem"` with expand/collapse states |
| Toast notifications | `role="alert"` with `aria-live="polite"` |

---

## New Backend Endpoints (Added for Frontend)

The following API endpoints were added to support features described in this architecture doc:

### Global WebSocket Event Bus — `/ws/events`

Single multiplexed WebSocket connection for all tenant events. Replaces the need to open per-scan connections from the frontend.

| Event Type | Payload | Published When |
|-----------|---------|----------------|
| `scan_progress` | `{ scan_id, status, progress: { files_scanned, files_with_pii, files_skipped, current_file } }` | Every 10 files during scan |
| `scan_completed` | `{ scan_id, status, summary: { files_scanned, risk_breakdown, ... } }` | Scan finishes |
| `scan_failed` | `{ scan_id, error }` | Scan errors out |
| `label_applied` | `{ result_id, label_name }` | Label applied to a file |
| `remediation_completed` | `{ action_id, action_type, status }` | Quarantine/lockdown/rollback finishes |
| `job_status` | `{ job_id, status }` | Job queue status change |
| `file_access` | `{ file_path, user_name, action, event_time }` | File access event detected |
| `health_update` | `{ component, status }` | System component health change (broadcast to all tenants) |

Publishing helpers: `ws_events.publish_scan_progress()`, `ws_events.publish_label_applied()`, etc.

### Permissions Explorer — `/api/v1/permissions/`

| Endpoint | Description |
|----------|-------------|
| `GET /permissions/exposure` | Tenant-wide exposure summary (counts of PUBLIC, ORG_WIDE, INTERNAL, PRIVATE dirs) |
| `GET /permissions/{target_id}/directories` | Paginated directory list with ACL flags, filterable by `exposure` and `parent_id` |
| `GET /permissions/{target_id}/acl/{dir_id}` | Full ACL detail (owner_sid, group_sid, dacl_sddl, permissions_json) |
| `GET /permissions/principal/{principal}` | All directories accessible by a principal (SID or name) |

### SQL Query & AI Assistant — `/api/v1/query/`

| Endpoint | Description |
|----------|-------------|
| `GET /query/schema` | Analytics table metadata for Monaco autocomplete |
| `POST /query` | Execute read-only SQL against DuckDB. Uses `$1` for tenant_id param. Max 10K rows. |
| `POST /query/ai` | NL → SQL via Anthropic Claude (or OpenAI fallback). Validates + optionally executes. |

---

## Migration Plan

### Phase 1: Foundation (Parallel Operation)

1. Scaffold the `frontend/` directory with Vite + React + TypeScript
2. Set up shadcn/ui, Tailwind, TanStack Query, React Router
3. Build the app shell (sidebar, header, routing)
4. Implement auth flow (session cookie check, login redirect)
5. Create shared components (DataTable, RiskBadge, StatusBadge)
6. **Deploy alongside existing Jinja2 UI** — new React app on `/app/*`, old Jinja2 on `/ui/*`

### Phase 2: Core Pages

7. Dashboard with stats cards and charts
8. Scans list + detail with WebSocket progress
9. Results list + detail with entity breakdown
10. Targets CRUD forms with adapter-specific config
11. Schedules CRUD with cron builder
12. Labels list + sync

### Phase 3: Advanced Features

13. Resource Explorer (three-panel folder tree browser)
14. Events timeline (real-time file access events)
15. Permissions Explorer (ACL viewer, exposure analysis)
16. Remediation workflows (quarantine, lockdown, rollback)
17. Policies list + editor
18. Monitoring (job queue, system health, activity log)

### Phase 4: Reports & AI

19. Reports page with SQL editor (Monaco)
20. AI assistant for natural language queries
21. Chart builder and export (PDF/Excel/CSV)

### Phase 5: Cutover

22. Set React app as default route (`/` → React, `/legacy/*` → Jinja2)
23. Redirect old `/ui/*` paths to React equivalents
24. Remove Jinja2 templates, HTMX partials, and `web/` module
25. Final MSI installer packages React build as the sole frontend
