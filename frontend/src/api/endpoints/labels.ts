import { apiFetch } from '../client.ts';
import type { Label, LabelRule, LabelStats, LabelSyncStatus, LabelMappingsResponse, PaginatedResponse } from '../types.ts';

export const labelsApi = {
  list: (params?: { page?: number; page_size?: number }) =>
    apiFetch<PaginatedResponse<Label>>('/labels', { params }),

  get: (id: string) =>
    apiFetch<Label>(`/labels/${id}`),

  sync: () =>
    apiFetch<{ job_id?: string; message?: string }>('/labels/sync', { method: 'POST' }),

  syncStatus: () =>
    apiFetch<LabelSyncStatus>('/labels/sync/status'),

  mappings: () =>
    apiFetch<LabelMappingsResponse>('/labels/mappings'),

  updateMappings: (payload: { CRITICAL?: string | null; HIGH?: string | null; MEDIUM?: string | null; LOW?: string | null }) =>
    apiFetch<{ message: string }>('/labels/mappings', { method: 'POST', body: payload }),

  apply: (payload: { result_id: string; label_id: string }) =>
    apiFetch<{ job_id?: string; message?: string }>('/labels/apply', { method: 'POST', body: payload }),

  bulkApply: (payload: { result_ids: string[] }) =>
    apiFetch<{ queued: number; skipped: number; message: string }>('/labels/bulk-apply', { method: 'POST', body: payload }),

  stats: () =>
    apiFetch<LabelStats>('/labels/stats'),

  // Label rules
  listRules: (params?: { page?: number; page_size?: number }) =>
    apiFetch<PaginatedResponse<LabelRule>>('/labels/rules', { params }),

  createRule: (payload: { rule_type: string; match_value: string; label_id: string; priority?: number }) =>
    apiFetch<LabelRule>('/labels/rules', { method: 'POST', body: payload }),

  deleteRule: (ruleId: string) =>
    apiFetch<void>(`/labels/rules/${ruleId}`, { method: 'DELETE' }),
};
