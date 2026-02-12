import { apiFetch } from '../client.ts';
import type { Target, PaginatedResponse } from '../types.ts';

export const targetsApi = {
  list: (params?: { page?: number; page_size?: number }) =>
    apiFetch<PaginatedResponse<Target>>('/targets', { params }),

  get: (id: string) =>
    apiFetch<Target>(`/targets/${id}`),

  create: (payload: Omit<Target, 'id' | 'tenant_id' | 'created_at' | 'updated_at'>) =>
    apiFetch<Target>('/targets', { method: 'POST', body: payload }),

  update: (id: string, payload: Partial<Target>) =>
    apiFetch<Target>(`/targets/${id}`, { method: 'PUT', body: payload }),

  delete: (id: string) =>
    apiFetch<void>(`/targets/${id}`, { method: 'DELETE' }),
};
