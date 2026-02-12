import { apiFetch } from '../client.ts';
import type { DashboardStats } from '../types.ts';

export const dashboardApi = {
  stats: () =>
    apiFetch<DashboardStats>('/dashboard/stats'),

  entityTrends: (params?: { days?: number }) =>
    apiFetch<Record<string, number[]>>('/dashboard/entity-trends', { params }),
};
