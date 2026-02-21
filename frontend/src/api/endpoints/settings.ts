import { apiFetch } from '../client.ts';
import type { AllSettings, SettingsUpdateResponse } from '../types.ts';

// Fields that must be dropped or renamed before sending to the backend.
// Response field names don't always match request field names (e.g. read-only
// indicators like azure_client_secret_set have no corresponding request field).
const SETTINGS_FIELD_MAP: Record<string, Record<string, string>> = {
  azure: {
    azure_client_secret_set: '__DROP__', // read-only indicator, never send back
  },
};

function mapSettingsFields(category: string, settings: Record<string, unknown>): Record<string, unknown> {
  const fieldMap = SETTINGS_FIELD_MAP[category];
  if (!fieldMap) return settings;
  const mapped: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(settings)) {
    const mappedKey = fieldMap[key];
    if (mappedKey === '__DROP__') continue;
    mapped[mappedKey ?? key] = value;
  }
  return mapped;
}

export const settingsApi = {
  list: () =>
    apiFetch<AllSettings>('/settings'),

  update: (category: string, settings: Record<string, unknown>) =>
    apiFetch<SettingsUpdateResponse>(`/settings/${category}`, {
      method: 'POST',
      body: mapSettingsFields(category, settings),
    }),

  reset: () =>
    apiFetch<SettingsUpdateResponse>('/settings/reset', { method: 'POST' }),
};
