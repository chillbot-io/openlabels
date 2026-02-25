import { apiFetch } from '../client.ts';
import type {
  HealthStatus,
  JobQueueStats,
  AuditLogEntry,
  PaginatedResponse,
  SystemResourceUsage,
  WorkersResponse,
  ScanThroughputResponse,
  ErrorLogResponse,
  SystemAlertRule,
  BackgroundTasksResponse,
} from '../types.ts';

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

  // Service identity / gMSA
  serviceIdentity: () =>
    apiFetch<{
      account_name: string;
      domain: string | null;
      is_gmsa: boolean;
      is_local_system: boolean;
      is_network_service: boolean;
      sid: string | null;
    }>('/monitoring/identity'),

  gmsaSetupScript: (payload?: {
    account_name?: string;
    server_group?: string;
    domain?: string;
  }) =>
    apiFetch<{ script: string }>('/monitoring/gmsa/setup-script', {
      method: 'POST',
      body: payload ?? {},
    }),

  auditPolicyScript: (payload?: { share_paths?: string[] }) =>
    apiFetch<{ script: string }>('/monitoring/audit-policy/script', {
      method: 'POST',
      body: payload ?? {},
    }),

  // System monitoring & health (Story 13)
  resources: () =>
    apiFetch<SystemResourceUsage>('/health/resources'),

  workers: () =>
    apiFetch<WorkersResponse>('/health/workers'),

  throughput: (params?: { hours?: number; bucket_size?: number }) =>
    apiFetch<ScanThroughputResponse>('/health/throughput', { params }),

  errors: (params?: { source?: string; severity?: string; hours?: number; page?: number; page_size?: number }) =>
    apiFetch<ErrorLogResponse>('/health/errors', { params }),

  tasks: () =>
    apiFetch<BackgroundTasksResponse>('/health/tasks'),

  systemAlerts: () =>
    apiFetch<SystemAlertRule[]>('/health/alerts'),

  createSystemAlert: (payload: {
    name: string;
    component: string;
    condition: string;
    threshold?: number;
    actions?: string[];
    enabled?: boolean;
  }) =>
    apiFetch<SystemAlertRule>('/health/alerts', {
      method: 'POST',
      body: payload,
    }),

  deleteSystemAlert: (id: string) =>
    apiFetch<void>(`/health/alerts/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
};
