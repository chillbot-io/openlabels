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
  has_more: boolean;
  error: string | null;
}

export interface EnumerateParams {
  source_type: string;
  credentials?: Record<string, string>;
  search?: string;
  page?: number;
  page_size?: number;
  use_m365_session?: boolean;
}

export const enumerateApi = {
  enumerate: (payload: EnumerateParams) =>
    apiFetch<EnumerateResponse>('/enumerate', {
      method: 'POST',
      body: payload,
    }),
};
