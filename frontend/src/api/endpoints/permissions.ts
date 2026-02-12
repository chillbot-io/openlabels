import { apiFetch } from '../client.ts';
import type { ExposureSummary, DirectoryEntry, DirectoryACL, PaginatedResponse } from '../types.ts';

export const permissionsApi = {
  exposure: () =>
    apiFetch<ExposureSummary>('/permissions/exposure'),

  directories: (targetId: string, params?: { page?: number; page_size?: number; exposure?: string; parent_id?: string }) =>
    apiFetch<PaginatedResponse<DirectoryEntry>>(`/permissions/${targetId}/directories`, { params }),

  acl: (targetId: string, dirId: string) =>
    apiFetch<DirectoryACL>(`/permissions/${targetId}/acl/${dirId}`),

  principal: (principal: string) =>
    apiFetch<DirectoryEntry[]>(`/permissions/principal/${encodeURIComponent(principal)}`),
};
