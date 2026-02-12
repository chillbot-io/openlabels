import { apiFetch } from '../client.ts';
import type { AuditLogEntry, PaginatedResponse } from '../types.ts';

export const auditApi = {
  list: (params?: { page?: number; page_size?: number; action?: string; resource_type?: string }) =>
    apiFetch<PaginatedResponse<AuditLogEntry>>('/audit', { params }),
};
