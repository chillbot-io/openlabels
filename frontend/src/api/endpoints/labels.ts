import { apiFetch } from '../client.ts';
import type { Label, LabelSync, PaginatedResponse } from '../types.ts';

export const labelsApi = {
  list: (params?: { page?: number; page_size?: number }) =>
    apiFetch<PaginatedResponse<Label>>('/labels', { params }),

  get: (id: string) =>
    apiFetch<Label>(`/labels/${id}`),

  sync: () =>
    apiFetch<LabelSync>('/labels/sync', { method: 'POST' }),

  syncStatus: () =>
    apiFetch<LabelSync>('/labels/sync/status'),

  mappings: () =>
    apiFetch<Array<{ label_name: string; risk_tier: string }>>('/labels/mappings'),
};
