import { apiFetch } from '../client.ts';
import type { DashboardStats } from '../types.ts';

export interface EntityTrendsResponse {
  series: Record<string, Array<[string, number]>>;
  truncated: boolean;
  total_records: number;
}

export const dashboardApi = {
  stats: () =>
    apiFetch<DashboardStats>('/dashboard/stats'),

  entityTrends: (params?: { days?: number }) =>
    apiFetch<EntityTrendsResponse>('/dashboard/entity-trends', { params }),
};
