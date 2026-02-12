import { apiFetch } from '../client.ts';
import type { Schedule, PaginatedResponse } from '../types.ts';

export const schedulesApi = {
  list: (params?: { page?: number; page_size?: number }) =>
    apiFetch<PaginatedResponse<Schedule>>('/schedules', { params }),

  get: (id: string) =>
    apiFetch<Schedule>(`/schedules/${id}`),

  create: (payload: { name: string; cron: string; target_id: string; enabled: boolean }) =>
    apiFetch<Schedule>('/schedules', { method: 'POST', body: payload }),

  update: (id: string, payload: Partial<Schedule>) =>
    apiFetch<Schedule>(`/schedules/${id}`, { method: 'PUT', body: payload }),

  delete: (id: string) =>
    apiFetch<void>(`/schedules/${id}`, { method: 'DELETE' }),
};
