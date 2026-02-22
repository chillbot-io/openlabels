import { apiFetch } from '../client.ts';
import type { HealthStatus, JobQueueStats, AuditLogEntry, PaginatedResponse } from '../types.ts';

export interface RemoteTestResponse {
  success: boolean;
  message: string;
  hostname: string | null;
  os: string | null;
  has_audit_privilege: boolean | null;
  audit_policy_enabled: boolean | null;
  error: string | null;
}

export interface RemoteConfigureResponse {
  success: boolean;
  message: string;
  paths: Array<{ path: string; status: string; error?: string }> | null;
  error: string | null;
}

export const monitoringApi = {
  health: () =>
    apiFetch<HealthStatus>('/health/status'),

  jobQueue: () =>
    apiFetch<JobQueueStats>('/jobs/stats'),

  activityLog: (params?: { page?: number; page_size?: number; action?: string }) =>
    apiFetch<PaginatedResponse<AuditLogEntry>>('/audit', { params }),

  testRemote: (payload: {
    host: string;
    username: string;
    password: string;
    use_ssl?: boolean;
  }) =>
    apiFetch<RemoteTestResponse>('/monitoring/remote/test', {
      method: 'POST',
      body: payload,
    }),

  configureRemote: (payload: {
    host: string;
    username: string;
    password: string;
    share_paths: string[];
    use_ssl?: boolean;
  }) =>
    apiFetch<RemoteConfigureResponse>('/monitoring/remote/configure', {
      method: 'POST',
      body: payload,
    }),
};
