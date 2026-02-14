import { apiFetch } from '../client.ts';

export interface EnumeratedResource {
  id: string;
  name: string;
  path: string;
  resource_type: string;
  description: string | null;
  size: string | null;
}

export interface EnumerateResponse {
  source_type: string;
  resources: EnumeratedResource[];
  total: number;
  error: string | null;
}

export const enumerateApi = {
  enumerate: (payload: {
    source_type: string;
    credentials?: Record<string, string>;
  }) =>
    apiFetch<EnumerateResponse>('/enumerate', {
      method: 'POST',
      body: payload,
    }),
};
