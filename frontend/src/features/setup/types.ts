import type { EnumeratedResource } from '@/api/endpoints/enumerate.ts';

export type WizardStep =
  | 'welcome'
  | 'm365'
  | 'pick_source'
  | 'select_sites'
  | 'smb_setup'
  | 'add_more'
  | 'monitoring'
  | 'review';

export type SourceChoice = 'sharepoint' | 'onedrive' | 'smb';

export type CollectionMethod = 'wef' | 'winrm' | null;

export interface M365Connection {
  connected: boolean;
  tenantId: string | null;
  tenantName: string | null;
  hasDedicatedApp: boolean;
}

export interface SiteSelection {
  sourceType: 'sharepoint' | 'onedrive';
  mode: 'all' | 'individual';
  selectedSites: EnumeratedResource[];
}

export interface SmbConfig {
  host: string;
  username: string;
  password: string;
  savePassword: boolean;
  selectedShares: EnumeratedResource[];
}

export const STEP_LABELS: Record<WizardStep, string> = {
  welcome: 'Welcome',
  m365: 'Microsoft 365',
  pick_source: 'Data Source',
  select_sites: 'Select Sites',
  smb_setup: 'File Share',
  add_more: 'Additional',
  monitoring: 'Monitoring',
  review: 'Review',
};
