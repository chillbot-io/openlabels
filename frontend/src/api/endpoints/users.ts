import { apiFetch } from '../client.ts';
import type { User, PaginatedResponse } from '../types.ts';

export interface CreateUserPayload {
  name: string;
  email: string;
  role: 'admin' | 'user';
  auth_type: 'local' | 'sso';
  password?: string;
}

export const usersApi = {
  list: (params?: { page?: number; page_size?: number }) =>
    apiFetch<PaginatedResponse<User>>('/users', { params }),

  get: (id: string) =>
    apiFetch<User>(`/users/${id}`),

  create: (payload: CreateUserPayload) =>
    apiFetch<User>('/users', { method: 'POST', body: JSON.stringify(payload) }),

  delete: (id: string) =>
    apiFetch<void>(`/users/${id}`, { method: 'DELETE' }),

  me: () =>
    apiFetch<User>('/auth/me'),

  logout: () =>
    apiFetch<void>('/auth/logout', { method: 'POST' }),
};
