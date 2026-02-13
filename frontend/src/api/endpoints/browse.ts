import { apiFetch } from '../client.ts';
import type { BrowseResponse } from '../types.ts';

export const browseApi = {
  list: (targetId: string, parentId?: string) =>
    apiFetch<BrowseResponse>(`/browse/${targetId}`, { params: { parent_id: parentId } }),
};
