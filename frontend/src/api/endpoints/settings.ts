import { apiFetch } from '../client.ts';
import type { Setting } from '../types.ts';

export const settingsApi = {
  list: () =>
    apiFetch<Setting[]>('/settings'),

  get: (key: string) =>
    apiFetch<Setting>(`/settings/${key}`),

  update: (key: string, value: unknown) =>
    apiFetch<Setting>(`/settings/${key}`, { method: 'PUT', body: { value } }),
};
