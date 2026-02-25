import { apiFetch } from '../client.ts';
import type { DashboardStats } from '../types.ts';

export interface EntityTrendsResponse {
  series: Record<string, Array<[string, number]>>;
  truncated: boolean;
  total_records: number;
}

export interface PeriodStats {
  files_scanned: number;
  files_with_pii: number;
  critical_files: number;
  high_files: number;
  medium_files: number;
}

export interface TrendComparisonResponse {
  current: PeriodStats;
  previous: PeriodStats;
  deltas: Record<string, number>;
}

export const dashboardApi = {
  stats: () =>
    apiFetch<DashboardStats>('/dashboard/stats'),

  entityTrends: (params?: { days?: number }) =>
    apiFetch<EntityTrendsResponse>('/dashboard/entity-trends', { params }),

  statsComparison: (params?: { days?: number }) =>
    apiFetch<TrendComparisonResponse>('/dashboard/stats/comparison', { params }),
};
