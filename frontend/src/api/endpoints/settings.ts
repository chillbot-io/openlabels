import { apiFetch } from '../client.ts';
import type { Setting } from '../types.ts';

export const settingsApi = {
  list: () =>
    apiFetch<Setting[]>('/settings'),

  update: (category: string, settings: Record<string, unknown>) =>
    apiFetch<Setting[]>(`/settings/${category}`, { method: 'POST', body: settings }),

  reset: () =>
    apiFetch<Setting[]>('/settings/reset', { method: 'POST' }),
};
