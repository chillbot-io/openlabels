import { apiFetch } from '../client.ts';

export interface CredentialStoreResponse {
  source_type: string;
  saved: boolean;
  fields_stored: string[];
}

export interface CredentialCheckResponse {
  source_type: string;
  has_credentials: boolean;
  fields_stored: string[];
}

export const credentialsApi = {
  store: (payload: {
    source_type: string;
    credentials: Record<string, string>;
    save: boolean;
  }) =>
    apiFetch<CredentialStoreResponse>('/credentials', {
      method: 'POST',
      body: payload,
    }),

  check: (sourceType: string) =>
    apiFetch<CredentialCheckResponse>(`/credentials/${sourceType}`),

  delete: (sourceType: string) =>
    apiFetch<{ status: string }>(`/credentials/${sourceType}`, {
      method: 'DELETE',
    }),
};
