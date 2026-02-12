import { apiFetch } from '../client.ts';
import type { ScanResult, ScanResultDetail, CursorPaginatedResponse } from '../types.ts';

export const resultsApi = {
  list: (params?: {
    cursor?: string;
    page_size?: number;
    risk_tier?: string;
    entity_type?: string;
    scan_id?: string;
    search?: string;
  }) => apiFetch<CursorPaginatedResponse<ScanResult>>('/results/cursor', { params }),

  get: (id: string) =>
    apiFetch<ScanResultDetail>(`/results/${id}`),
};
