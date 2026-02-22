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

export interface SavedCredentialResponse {
  id: string;
  source_type: string;
  name: string;
  fields_stored: string[];
  target_id: string | null;
  created_at: string;
  updated_at: string;
}

export const credentialsApi = {
  // Session-scoped credentials
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

  // Persistent (database-backed) credentials
  save: (payload: {
    source_type: string;
    name: string;
    credentials: Record<string, string>;
    target_id?: string;
  }) =>
    apiFetch<SavedCredentialResponse>('/credentials/saved', {
      method: 'POST',
      body: payload,
    }),

  listSaved: (sourceType?: string) => {
    const params = sourceType ? `?source_type=${sourceType}` : '';
    return apiFetch<SavedCredentialResponse[]>(`/credentials/saved${params}`);
  },

  deleteSaved: (id: string) =>
    apiFetch<{ status: string }>(`/credentials/saved/${id}`, {
      method: 'DELETE',
    }),
};
