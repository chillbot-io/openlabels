import { apiFetch } from '../client.ts';
import type { AllSettings, SettingsUpdateResponse } from '../types.ts';

export const settingsApi = {
  list: () =>
    apiFetch<AllSettings>('/settings'),

  update: (category: string, settings: Record<string, unknown>) =>
    apiFetch<SettingsUpdateResponse>(`/settings/${category}`, { method: 'POST', body: settings }),

  reset: () =>
    apiFetch<SettingsUpdateResponse>('/settings/reset', { method: 'POST' }),
};
