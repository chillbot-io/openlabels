import { apiFetch } from '../client.ts';

export interface M365Status {
  connected: boolean;
  tenant_id: string | null;
  tenant_name: string | null;
  has_dedicated_app: boolean;
}

export interface M365ConsentStart {
  consent_url: string;
}

export const m365Api = {
  status: () =>
    apiFetch<M365Status>('/m365/status'),

  startConsent: () =>
    apiFetch<M365ConsentStart>('/m365/consent/start', { method: 'POST' }),

  disconnect: () =>
    apiFetch<{ status: string }>('/m365/disconnect', { method: 'POST' }),
};
