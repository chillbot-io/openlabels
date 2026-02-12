import { apiFetch } from '../client.ts';
import type { DirectoryEntry } from '../types.ts';

export const browseApi = {
  list: (targetId: string, path?: string) =>
    apiFetch<DirectoryEntry[]>(`/browse/${targetId}`, { params: { path: path ?? '' } }),
};
