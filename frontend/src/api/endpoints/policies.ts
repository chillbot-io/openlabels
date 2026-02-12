import { apiFetch } from '../client.ts';
import type { Policy, PaginatedResponse } from '../types.ts';

export const policiesApi = {
  list: (params?: { page?: number; page_size?: number }) =>
    apiFetch<PaginatedResponse<Policy>>('/policies', { params }),

  get: (id: string) =>
    apiFetch<Policy>(`/policies/${id}`),

  create: (payload: Omit<Policy, 'id' | 'tenant_id' | 'created_at' | 'updated_at'>) =>
    apiFetch<Policy>('/policies', { method: 'POST', body: payload }),

  update: (id: string, payload: Partial<Policy>) =>
    apiFetch<Policy>(`/policies/${id}`, { method: 'PUT', body: payload }),

  delete: (id: string) =>
    apiFetch<void>(`/policies/${id}`, { method: 'DELETE' }),
};
