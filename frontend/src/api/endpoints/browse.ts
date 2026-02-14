import { apiFetch } from '../client.ts';
import type { BrowseResponse, BrowseFilesResponse } from '../types.ts';

export const browseApi = {
  list: (targetId: string, parentId?: string) =>
    apiFetch<BrowseResponse>(`/browse/${targetId}`, { params: { parent_id: parentId } }),
  files: (targetId: string, params?: { folder_path?: string; risk_tier?: string }) =>
    apiFetch<BrowseFilesResponse>(`/browse/${targetId}/files`, { params }),
};
