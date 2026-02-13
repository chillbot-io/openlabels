import { apiFetch } from '../client.ts';
import type { Label, LabelSyncStatus, LabelMappingsResponse, PaginatedResponse } from '../types.ts';

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
};
