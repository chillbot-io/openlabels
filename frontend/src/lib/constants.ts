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

export const EXPOSURE_LEVELS = ['PUBLIC', 'ORG_WIDE', 'INTERNAL', 'PRIVATE'] as const;
export type ExposureLevel = (typeof EXPOSURE_LEVELS)[number];

export const REMEDIATION_ACTIONS = ['quarantine', 'lockdown', 'rollback'] as const;
export type RemediationAction = (typeof REMEDIATION_ACTIONS)[number];

export const NAV_GROUPS = [
  {
    label: 'Overview',
    items: [
      { label: 'Dashboard', path: '/dashboard', icon: 'LayoutDashboard' },
      { label: 'Resource Explorer', path: '/explorer', icon: 'FolderTree' },
      { label: 'Events', path: '/events', icon: 'Activity' },
    ],
  },
  {
    label: 'Data Protection',
    items: [
      { label: 'Scan Results', path: '/results', icon: 'FileSearch' },
      { label: 'Scans', path: '/scans', icon: 'Scan' },
      { label: 'Labels', path: '/labels', icon: 'Tag' },
    ],
  },
  {
    label: 'Security',
    items: [
      { label: 'Permissions', path: '/permissions', icon: 'Shield' },
      { label: 'Remediation', path: '/remediation', icon: 'ShieldAlert' },
      { label: 'Policies', path: '/policies', icon: 'BookOpen' },
    ],
  },
  {
    label: 'Operations',
    items: [
      { label: 'Targets', path: '/targets', icon: 'Target' },
      { label: 'Schedules', path: '/schedules', icon: 'Calendar' },
      { label: 'Monitoring', path: '/monitoring', icon: 'Monitor' },
      { label: 'Reports', path: '/reports', icon: 'BarChart3' },
    ],
  },
  {
    label: 'Configuration',
    items: [
      { label: 'Settings', path: '/settings', icon: 'Settings' },
    ],
  },
] as const;
