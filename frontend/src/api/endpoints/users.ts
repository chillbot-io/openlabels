import { apiFetch } from '../client.ts';
import type { User, PaginatedResponse } from '../types.ts';

export const usersApi = {
  list: (params?: { page?: number; page_size?: number }) =>
    apiFetch<PaginatedResponse<User>>('/users', { params }),

  get: (id: string) =>
    apiFetch<User>(`/users/${id}`),

  me: () =>
    apiFetch<User>('/auth/me'),

  logout: () =>
    apiFetch<void>('/auth/logout', { method: 'POST' }),
};
