import { apiFetch } from '../client.ts';

export const exportApi = {
  results: (params?: { format?: 'csv' | 'xlsx' | 'pdf'; scan_id?: string; risk_tier?: string }) =>
    apiFetch<Blob>('/export/results', {
      params,
      headers: { Accept: 'application/octet-stream' },
    }),

  report: (reportId: string, format: 'pdf' | 'xlsx' | 'csv') =>
    apiFetch<Blob>(`/reporting/${reportId}/export`, {
      params: { format },
      headers: { Accept: 'application/octet-stream' },
    }),
};
