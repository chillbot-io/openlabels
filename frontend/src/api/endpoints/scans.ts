import { apiFetch } from '../client.ts';
import type { ScanJob, PaginatedResponse } from '../types.ts';

export const scansApi = {
  list: (params?: { status?: string; page?: number; page_size?: number }) =>
    apiFetch<PaginatedResponse<ScanJob>>('/scans', { params }),

  get: (id: string) =>
    apiFetch<ScanJob>(`/scans/${id}`),

  create: (payload: { target_id: string; name?: string }) =>
    apiFetch<ScanJob>('/scans', { method: 'POST', body: payload }),

  cancel: (id: string) =>
    apiFetch<void>(`/scans/${id}/cancel`, { method: 'POST' }),
};
