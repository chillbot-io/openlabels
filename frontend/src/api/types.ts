// API Types — matches FastAPI backend response schemas
// In production, generate from OpenAPI spec with `npx openapi-typescript`

export interface User {
  id: string;
  email: string;
  name: string;
  tenant_id: string;
  role: 'admin' | 'user' | 'viewer';
  created_at: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  has_next: boolean;
  has_previous: boolean;
}

export interface CursorPaginatedResponse<T> {
  items: T[];
  next_cursor: string | null;
  previous_cursor: string | null;
  has_next: boolean;
  has_previous: boolean;
  page_size: number;
}

export interface ScanJob {
  id: string;
  target_id: string | null;
  target_name: string | null;
  name: string | null;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  files_scanned: number;
  files_with_pii: number;
  error: string | null;
  progress: ScanProgress | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface ScanProgress {
  files_scanned: number;
  files_total: number;
  files_with_pii: number;
  files_skipped: number;
  current_file: string;
}

export interface ScanResult {
  id: string;
  job_id: string;
  file_path: string;
  file_name: string;
  file_size: number | null;
  risk_score: number;
  risk_tier: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'MINIMAL';
  entity_counts: Record<string, number>;
  total_entities: number;
  exposure_level: string | null;
  owner: string | null;
  current_label_name: string | null;
  recommended_label_name: string | null;
  label_applied: boolean;
  scanned_at: string;
}

export interface ScanResultDetail extends ScanResult {
  content_score: number | null;
  exposure_multiplier: number | null;
  co_occurrence_rules: string[] | null;
  findings: Record<string, unknown> | null;
  policy_violations: Record<string, unknown>[] | null;
  label_applied_at: string | null;
  label_error: string | null;
}

export interface DetectedEntity {
  entity_type: string;
  value: string;
  confidence: number;
  start_offset: number;
  end_offset: number;
  context: string;
}

export interface Target {
  id: string;
  name: string;
  adapter: string;
  enabled: boolean;
  config: Record<string, unknown>;
  created_at: string;
}

export interface Schedule {
  id: string;
  name: string;
  cron: string | null;
  target_id: string;
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
}

export interface Label {
  id: string;
  tenant_id: string;
  name: string;
  color: string;
  description: string;
  priority: number | null;
  auto_apply: boolean;
  risk_tier_mapping: string | null;
  synced_at: string | null;
  created_at: string;
}

export interface LabelSync {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  labels_synced: number;
  labels_failed: number;
  started_at: string | null;
  completed_at: string | null;
}

export interface DashboardStats {
  total_scans: number;
  total_files_scanned: number;
  files_with_pii: number;
  labels_applied: number;
  critical_files: number;
  high_files: number;
  medium_files: number;
  low_files: number;
  minimal_files: number;
  active_scans: number;
}

export interface AuditLogEntry {
  id: string;
  tenant_id: string;
  user_id: string | null;
  user_email: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  details: Record<string, unknown>;
  ip_address: string | null;
  created_at: string;
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  components: Record<string, ComponentHealth>;
  uptime_seconds: number;
}

export interface ComponentHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  message?: string;
  latency_ms?: number;
}

export interface JobQueueStats {
  pending: number;
  running: number;
  completed: number;
  failed: number;
  cancelled: number;
  failed_by_type: Record<string, number>;
}

export interface JobInfo {
  id: string;
  task_type: string;
  status: string;
  priority: number;
  worker_id: string | null;
  error: string | null;
  retry_count: number;
  created_at: string;
  started_at: string | null;
}

export interface RemediationAction {
  id: string;
  tenant_id: string;
  file_path: string;
  action_type: 'quarantine' | 'lockdown' | 'rollback';
  status: 'pending' | 'completed' | 'failed' | 'rolled_back';
  performed_by: string;
  dry_run: boolean;
  details: Record<string, unknown>;
  created_at: string;
  completed_at: string | null;
}

export interface Policy {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  enabled: boolean;
  framework: string;
  risk_level: string;
  priority: number;
  config: Record<string, unknown>;
  rules: PolicyRule[];
  created_at: string;
  updated_at: string;
}

export interface PolicyRule {
  entity_type: string;
  min_risk_tier: string;
  action: string;
}

export interface DirectoryEntry {
  id: string;
  target_id: string;
  path: string;
  name: string;
  is_directory: boolean;
  file_size: number | null;
  risk_score: number | null;
  risk_tier: string | null;
  exposure_level: string | null;
  children_count: number;
  entity_count: number;
}

export interface DirectoryACL {
  id: string;
  path: string;
  owner_sid: string | null;
  group_sid: string | null;
  dacl_sddl: string | null;
  exposure_level: string;
  permissions_json: Record<string, unknown>;
}

export interface ExposureSummary {
  PUBLIC: number;
  ORG_WIDE: number;
  INTERNAL: number;
  PRIVATE: number;
}

export interface FileAccessEvent {
  id: string;
  file_path: string;
  user_name: string;
  action: string;
  event_time: string;
  details: Record<string, unknown>;
}

export interface QuerySchema {
  tables: QueryTable[];
}

export interface QueryTable {
  name: string;
  columns: QueryColumn[];
}

export interface QueryColumn {
  name: string;
  type: string;
  description: string;
}

export interface QueryResult {
  columns: string[];
  rows: unknown[][];
  row_count: number;
  execution_time_ms: number;
}

export interface AIQueryResponse {
  sql: string;
  explanation: string;
  result?: QueryResult;
}

export interface Setting {
  key: string;
  value: unknown;
  category: string;
  description: string;
}

// WebSocket event types
export interface WSEvent<T = unknown> {
  type: string;
  data: T;
}

export interface WSScanProgress {
  scan_id: string;
  status: string;
  progress: ScanProgress;
}

export interface WSScanCompleted {
  scan_id: string;
  status: string;
  summary: {
    files_scanned: number;
    risk_breakdown: Record<string, number>;
  };
}

export interface WSLabelApplied {
  result_id: string;
  label_name: string;
}

export interface WSRemediationCompleted {
  action_id: string;
  action_type: string;
  status: string;
}

export interface WSJobStatus {
  job_id: string;
  status: string;
}

export interface WSFileAccess {
  file_path: string;
  user_name: string;
  action: string;
  event_time: string;
}

export interface WSHealthUpdate {
  component: string;
  status: string;
}
