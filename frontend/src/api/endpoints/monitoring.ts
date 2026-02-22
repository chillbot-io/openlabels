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

export interface WEFSetupResponse {
  success: boolean;
  message: string;
  gpo_config: string | null;
}

export interface WEFSubscriptionResponse {
  name: string;
  enabled: boolean;
  source_count: number;
  delivery_mode: string;
  status: string;
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

  // WEF (Windows Event Forwarding)
  wefInit: () =>
    apiFetch<WEFSetupResponse>('/monitoring/wef/init', { method: 'POST' }),

  wefCreateSubscription: (payload?: {
    subscription_name?: string;
    transport?: string;
  }) =>
    apiFetch<WEFSetupResponse>('/monitoring/wef/subscriptions', {
      method: 'POST',
      body: payload ?? {},
    }),

  wefListSubscriptions: () =>
    apiFetch<WEFSubscriptionResponse[]>('/monitoring/wef/subscriptions'),

  wefDeleteSubscription: (name: string) =>
    apiFetch<WEFSetupResponse>(`/monitoring/wef/subscriptions/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    }),

  wefGpoConfig: () =>
    apiFetch<{ gpo_path: string; value: string }>('/monitoring/wef/gpo-config'),
};
