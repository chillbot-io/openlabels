import { apiFetch } from '../client.ts';
import type { HealthStatus, JobQueueStats, AuditLogEntry, PaginatedResponse } from '../types.ts';

export const monitoringApi = {
  health: () =>
    apiFetch<HealthStatus>('/health'),

  jobQueue: () =>
    apiFetch<JobQueueStats>('/monitoring/jobs'),

  activityLog: (params?: { page?: number; page_size?: number; action?: string }) =>
    apiFetch<PaginatedResponse<AuditLogEntry>>('/audit', { params }),
};
