import { apiFetch } from '../client.ts';
import type { HealthStatus, JobQueueStats, AuditLogEntry, PaginatedResponse } from '../types.ts';

export const monitoringApi = {
  health: () =>
    apiFetch<HealthStatus>('/health/status'),

  jobQueue: () =>
    apiFetch<JobQueueStats>('/jobs/stats'),

  activityLog: (params?: { page?: number; page_size?: number; action?: string }) =>
    apiFetch<PaginatedResponse<AuditLogEntry>>('/audit', { params }),
};
