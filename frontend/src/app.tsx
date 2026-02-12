import { createBrowserRouter, Navigate } from 'react-router';
import { AppShell } from '@/components/layout/app-shell.tsx';
import { NotFoundPage } from '@/features/auth/not-found-page.tsx';

export const router = createBrowserRouter([
  {
    element: <AppShell />,
    children: [
      { index: true, element: <Navigate to="/dashboard" replace /> },
      { path: 'dashboard', lazy: () => import('@/features/dashboard/page.tsx') },
      { path: 'explorer', lazy: () => import('@/features/resource-explorer/page.tsx') },
      { path: 'events', lazy: () => import('@/features/events/page.tsx') },
      { path: 'results', lazy: () => import('@/features/results/list-page.tsx') },
      { path: 'results/:resultId', lazy: () => import('@/features/results/detail-page.tsx') },
      { path: 'scans', lazy: () => import('@/features/scans/list-page.tsx') },
      { path: 'scans/:scanId', lazy: () => import('@/features/scans/detail-page.tsx') },
      { path: 'labels', lazy: () => import('@/features/labels/list-page.tsx') },
      { path: 'labels/sync', lazy: () => import('@/features/labels/sync-page.tsx') },
      { path: 'permissions', lazy: () => import('@/features/permissions/page.tsx') },
      { path: 'remediation', lazy: () => import('@/features/remediation/page.tsx') },
      { path: 'policies', lazy: () => import('@/features/policies/list-page.tsx') },
      { path: 'targets', lazy: () => import('@/features/targets/list-page.tsx') },
      { path: 'targets/new', lazy: () => import('@/features/targets/form-page.tsx') },
      { path: 'targets/:targetId', lazy: () => import('@/features/targets/form-page.tsx') },
      { path: 'schedules', lazy: () => import('@/features/schedules/list-page.tsx') },
      { path: 'schedules/new', lazy: () => import('@/features/schedules/form-page.tsx') },
      { path: 'schedules/:scheduleId', lazy: () => import('@/features/schedules/form-page.tsx') },
      { path: 'monitoring', lazy: () => import('@/features/monitoring/page.tsx') },
      { path: 'reports', lazy: () => import('@/features/reports/page.tsx') },
      { path: 'settings', lazy: () => import('@/features/settings/page.tsx') },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
  { path: 'login', lazy: () => import('@/features/auth/login-page.tsx') },
]);
