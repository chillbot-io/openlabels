import { apiFetch } from '../client.ts';
import type { ScanResult, CursorPaginatedResponse } from '../types.ts';

export const resultsApi = {
  list: (params?: {
    cursor?: string;
    page_size?: number;
    risk_tier?: string;
    entity_type?: string;
    scan_id?: string;
    search?: string;
  }) => apiFetch<CursorPaginatedResponse<ScanResult>>('/results', { params }),

  get: (id: string) =>
    apiFetch<ScanResult>(`/results/${id}`),
};
