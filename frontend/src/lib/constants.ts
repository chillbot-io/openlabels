export const RISK_TIERS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'MINIMAL'] as const;
export type RiskTier = (typeof RISK_TIERS)[number];

export const RISK_COLORS: Record<RiskTier, { bg: string; text: string }> = {
  CRITICAL: { bg: 'bg-red-600', text: 'text-white' },
  HIGH: { bg: 'bg-orange-500', text: 'text-white' },
  MEDIUM: { bg: 'bg-yellow-400', text: 'text-gray-900' },
  LOW: { bg: 'bg-green-100', text: 'text-gray-700' },
  MINIMAL: { bg: 'bg-gray-100', text: 'text-gray-500' },
};

export const SCAN_STATUSES = ['pending', 'running', 'completed', 'failed', 'cancelled'] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

export const STATUS_COLORS: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-700 border-gray-300',
  running: 'bg-blue-100 text-blue-700 border-blue-300',
  completed: 'bg-green-100 text-green-700 border-green-300',
  failed: 'bg-red-100 text-red-700 border-red-300',
  cancelled: 'bg-gray-100 text-gray-500 border-gray-300',
  rolled_back: 'bg-purple-100 text-purple-700 border-purple-300',
};

export const ENTITY_TYPES = [
  'SSN', 'CREDIT_CARD', 'EMAIL', 'PHONE', 'ADDRESS', 'DATE_OF_BIRTH',
  'DRIVERS_LICENSE', 'PASSPORT', 'BANK_ACCOUNT', 'MEDICAL_RECORD',
  'IP_ADDRESS', 'AWS_KEY', 'API_KEY', 'PASSWORD', 'CUSTOM',
] as const;
export type EntityType = (typeof ENTITY_TYPES)[number];

export const ADAPTER_TYPES = [
  'filesystem', 'sharepoint', 'onedrive', 's3', 'gcs', 'azure_blob',
] as const;
export type AdapterType = (typeof ADAPTER_TYPES)[number];

export const ADAPTER_LABELS: Record<AdapterType, string> = {
  filesystem: 'File System',
  sharepoint: 'SharePoint',
  onedrive: 'OneDrive',
  s3: 'Amazon S3',
  gcs: 'Google Cloud Storage',
  azure_blob: 'Azure Blob Storage',
};

// Source types shown in the Add Resource UI.
// SMB and NFS both map to the 'filesystem' backend adapter.
export const SOURCE_TYPES = [
  'smb', 'nfs', 'sharepoint', 'onedrive', 's3', 'gcs', 'azure_blob',
] as const;
export type SourceType = (typeof SOURCE_TYPES)[number];

export const SOURCE_LABELS: Record<SourceType, string> = {
  smb: 'SMB',
  nfs: 'NFS',
  sharepoint: 'SharePoint',
  onedrive: 'OneDrive',
  s3: 'Amazon S3',
  gcs: 'Google Cloud Storage',
  azure_blob: 'Azure Blob Storage',
};

export const SOURCE_DESCRIPTIONS: Record<SourceType, string> = {
  smb: 'Windows / Samba file shares',
  nfs: 'Unix / Linux NFS exports',
  sharepoint: 'Microsoft SharePoint Online sites',
  onedrive: 'Microsoft OneDrive for Business',
  s3: 'AWS S3 or S3-compatible storage',
  gcs: 'Google Cloud Storage buckets',
  azure_blob: 'Azure Blob Storage containers',
};

/** Map UI source type to backend adapter type */
export function sourceToAdapter(source: SourceType): AdapterType {
  if (source === 'smb' || source === 'nfs') return 'filesystem';
  return source;
}

/** Credential fields required per source type */
export const SOURCE_CREDENTIAL_FIELDS: Record<SourceType, { key: string; label: string; placeholder: string; type?: string }[]> = {
  smb: [
    { key: 'host', label: 'Host', placeholder: 'server.example.com or IP address' },
    { key: 'username', label: 'Username', placeholder: 'DOMAIN\\user or user@domain' },
    { key: 'password', label: 'Password', placeholder: '', type: 'password' },
  ],
  nfs: [
    { key: 'host', label: 'Host', placeholder: 'server.example.com or IP address' },
  ],
  sharepoint: [
    { key: 'tenant_id', label: 'Azure Tenant ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    { key: 'client_id', label: 'Client ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    { key: 'client_secret', label: 'Client Secret', placeholder: '', type: 'password' },
  ],
  onedrive: [
    { key: 'tenant_id', label: 'Azure Tenant ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    { key: 'client_id', label: 'Client ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    { key: 'client_secret', label: 'Client Secret', placeholder: '', type: 'password' },
  ],
  s3: [
    { key: 'access_key', label: 'Access Key ID', placeholder: 'AKIAIOSFODNN7EXAMPLE' },
    { key: 'secret_key', label: 'Secret Access Key', placeholder: '', type: 'password' },
    { key: 'region', label: 'Region', placeholder: 'us-east-1' },
    { key: 'endpoint_url', label: 'Endpoint URL (optional)', placeholder: 'https://s3.example.com' },
  ],
  gcs: [
    { key: 'project', label: 'Project ID', placeholder: 'my-gcp-project' },
    { key: 'credentials_json', label: 'Service Account JSON', placeholder: 'Paste service account key JSON', type: 'textarea' },
  ],
  azure_blob: [
    { key: 'storage_account', label: 'Storage Account', placeholder: 'mystorageaccount' },
    { key: 'account_key', label: 'Account Key', placeholder: '', type: 'password' },
  ],
};

export const EXPOSURE_LEVELS = ['PUBLIC', 'ORG_WIDE', 'INTERNAL', 'PRIVATE'] as const;
export type ExposureLevel = (typeof EXPOSURE_LEVELS)[number];

export const REMEDIATION_ACTIONS = ['quarantine', 'lockdown', 'rollback'] as const;
export type RemediationAction = (typeof REMEDIATION_ACTIONS)[number];

export const NAV_GROUPS = [
  {
    label: '',
    items: [
      { label: 'Dashboard', path: '/dashboard', icon: 'LayoutDashboard' },
    ],
  },
  {
    label: 'Scanning',
    items: [
      { label: 'Scan Targets', path: '/targets', icon: 'Target' },
      { label: 'Scans', path: '/scans', icon: 'Scan' },
      { label: 'Schedules', path: '/schedules', icon: 'Calendar' },
    ],
  },
  {
    label: 'Findings',
    items: [
      { label: 'Results', path: '/results', icon: 'FileSearch' },
      { label: 'Explorer', path: '/explorer', icon: 'FolderTree' },
      { label: 'Labels', path: '/labels', icon: 'Tag' },
      { label: 'Remediation', path: '/remediation', icon: 'ShieldAlert' },
    ],
  },
  {
    label: 'Compliance',
    items: [
      { label: 'Policies', path: '/policies', icon: 'BookOpen' },
      { label: 'Reports', path: '/reports', icon: 'BarChart3' },
    ],
  },
  {
    label: 'System',
    items: [
      { label: 'Monitoring', path: '/monitoring', icon: 'Monitor' },
      { label: 'Events', path: '/events', icon: 'Activity' },
      { label: 'Permissions', path: '/permissions', icon: 'Shield' },
      { label: 'Users', path: '/users', icon: 'Users' },
      { label: 'Settings', path: '/settings', icon: 'Settings' },
    ],
  },
] as const;
