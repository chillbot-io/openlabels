import { apiFetch } from '../client.ts';
import type { RemediationAction, PaginatedResponse } from '../types.ts';

export const remediationApi = {
  list: (params?: { page?: number; page_size?: number; status?: string }) =>
    apiFetch<PaginatedResponse<RemediationAction>>('/remediation', { params }),

  get: (id: string) =>
    apiFetch<RemediationAction>(`/remediation/${id}`),

  quarantine: (payload: { file_path: string; reason?: string; dry_run?: boolean }) =>
    apiFetch<RemediationAction>('/remediation/quarantine', { method: 'POST', body: payload }),

  lockdown: (payload: { file_path: string; principals: string[]; dry_run?: boolean }) =>
    apiFetch<RemediationAction>('/remediation/lockdown', { method: 'POST', body: payload }),

  rollback: (actionId: string) =>
    apiFetch<RemediationAction>(`/remediation/${actionId}/rollback`, { method: 'POST' }),
};
