import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router';
import {
  Check, ArrowRight, ArrowLeft, FolderOpen, Globe, Cloud,
  SkipForward, Loader2, Search, Server, Eye, EyeOff, Shield,
  Plus, X,
} from 'lucide-react';
import { m365Api } from '@/api/endpoints/m365.ts';
import { enumerateApi } from '@/api/endpoints/enumerate.ts';
import { targetsApi } from '@/api/endpoints/targets.ts';
import { credentialsApi } from '@/api/endpoints/credentials.ts';
import { monitoringApi } from '@/api/endpoints/monitoring.ts';
import type { EnumeratedResource } from '@/api/endpoints/enumerate.ts';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { LogoIcon } from '@/components/brand/logo.tsx';
import { useUIStore } from '@/stores/ui-store.ts';
import { cn } from '@/lib/utils.ts';

/*
 * Setup Wizard — first-run experience.
 *
 * Flow:
 *   welcome → m365 → pick_source → select_sites|smb_setup → add_more →
 *   [select_sites|smb_setup for second source] → monitoring → review
 */

type WizardStep =
  | 'welcome'
  | 'm365'
  | 'pick_source'
  | 'select_sites'
  | 'smb_setup'
  | 'add_more'
  | 'monitoring'
  | 'review';

type SourceChoice = 'sharepoint' | 'onedrive' | 'smb';

interface M365Connection {
  connected: boolean;
  tenantId: string | null;
  tenantName: string | null;
}

interface SiteSelection {
  sourceType: 'sharepoint' | 'onedrive';
  mode: 'all' | 'individual';
  selectedSites: EnumeratedResource[];
}

interface SmbConfig {
  host: string;
  username: string;
  password: string;
  savePassword: boolean;
  selectedShares: EnumeratedResource[];
}

// ── Step indicator ──────────────────────────────────────────────────

const STEP_LABELS: Record<WizardStep, string> = {
  welcome: 'Welcome',
  m365: 'Microsoft 365',
  pick_source: 'Data Source',
  select_sites: 'Select Sites',
  smb_setup: 'File Share',
  add_more: 'Additional',
  monitoring: 'Monitoring',
  review: 'Review',
};

function StepIndicator({ steps, currentStep }: { steps: WizardStep[]; currentStep: WizardStep }) {
  const currentIdx = steps.indexOf(currentStep);
  return (
    <div className="flex items-center justify-center gap-1.5 flex-wrap">
      {steps.map((step, i) => (
        <div key={step} className="flex items-center gap-1.5">
          <div
            className={cn(
              'flex h-7 w-7 items-center justify-center rounded-full text-xs font-medium',
              i < currentIdx ? 'bg-green-500 text-white' :
              i === currentIdx ? 'bg-blue-600 text-white' :
              'bg-gray-200 text-gray-500',
            )}
          >
            {i < currentIdx ? <Check className="h-3.5 w-3.5" /> : i + 1}
          </div>
          <span className={cn(
            'text-xs hidden sm:inline',
            i === currentIdx ? 'font-medium' : 'text-gray-400',
          )}>
            {STEP_LABELS[step]}
          </span>
          {i < steps.length - 1 && <div className="h-px w-6 bg-gray-300" />}
        </div>
      ))}
    </div>
  );
}

// ── Welcome step ────────────────────────────────────────────────────

function WelcomeStep({ onNext }: { onNext: () => void }) {
  return (
    <Card>
      <CardContent className="space-y-6 p-8 text-center">
        <LogoIcon className="mx-auto h-16 w-auto" />
        <div>
          <h1 className="text-3xl font-bold">Welcome to OpenLabels</h1>
          <p className="mt-2 text-[var(--muted-foreground)]">
            Sensitive data discovery and protection for your files.
            Let's connect your data sources.
          </p>
        </div>
        <Button size="lg" onClick={onNext}>
          Get Started <ArrowRight className="ml-2 h-4 w-4" />
        </Button>
      </CardContent>
    </Card>
  );
}

// ── M365 connect step ───────────────────────────────────────────────

function M365Step({
  connection,
  onConnect,
  onSkip,
  onBack,
}: {
  connection: M365Connection;
  onConnect: () => void;
  onSkip: () => void;
  onBack: () => void;
}) {
  const [connecting, setConnecting] = useState(false);

  const handleConnect = async () => {
    setConnecting(true);
    try {
      const { consent_url } = await m365Api.startConsent();
      // Open consent flow in a popup
      const popup = window.open(consent_url, 'm365_consent', 'width=600,height=700');

      // Listen for the popup's postMessage
      const handler = (event: MessageEvent) => {
        if (event.origin !== window.location.origin) return;
        if (event.data?.type !== 'm365_consent_result') return;
        window.removeEventListener('message', handler);
        setConnecting(false);

        if (event.data.success) {
          onConnect();
        }
      };
      window.addEventListener('message', handler);

      // Also poll in case postMessage fails (popup blockers, cross-origin)
      const pollInterval = setInterval(async () => {
        if (popup?.closed) {
          clearInterval(pollInterval);
          window.removeEventListener('message', handler);
          setConnecting(false);
          // Check if consent succeeded by polling status
          try {
            const status = await m365Api.status();
            if (status.connected) onConnect();
          } catch { /* ignore */ }
        }
      }, 1000);
    } catch {
      setConnecting(false);
    }
  };

  return (
    <Card>
      <CardContent className="space-y-5 p-8">
        <div>
          <h2 className="text-xl font-bold">Connect to Microsoft 365</h2>
          <p className="mt-1 text-sm text-[var(--muted-foreground)]">
            Connect your organization's Microsoft 365 tenant to scan
            SharePoint sites and OneDrive accounts.
          </p>
        </div>

        {connection.connected ? (
          <div className="flex items-center gap-3 rounded-lg border-2 border-green-200 bg-green-50 p-4">
            <Check className="h-5 w-5 text-green-600" />
            <div>
              <p className="font-medium text-green-800">Connected</p>
              <p className="text-sm text-green-700">
                {connection.tenantName || connection.tenantId}
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="rounded-lg border-2 border-dashed border-gray-300 p-6 text-center">
              <Globe className="mx-auto h-10 w-10 text-gray-400" />
              <p className="mt-3 text-sm text-[var(--muted-foreground)]">
                A Global Administrator will need to sign in and grant permissions.
                OpenLabels will be able to read files and site information.
              </p>
              <Button
                className="mt-4"
                onClick={handleConnect}
                disabled={connecting}
              >
                {connecting ? (
                  <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Waiting for admin...</>
                ) : (
                  <>Connect to Microsoft 365</>
                )}
              </Button>
            </div>
          </div>
        )}

        <div className="flex justify-between pt-2">
          <Button variant="ghost" onClick={onBack}>
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Button>
          {connection.connected ? (
            <Button onClick={onSkip}>
              Next <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          ) : (
            <Button variant="ghost" onClick={onSkip}>
              <SkipForward className="mr-2 h-4 w-4" /> Skip
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ── Source picker step ───────────────────────────────────────────────

function PickSourceStep({
  m365Connected,
  disabledSources,
  onPick,
  onBack,
}: {
  m365Connected: boolean;
  disabledSources: Set<SourceChoice>;
  onPick: (source: SourceChoice) => void;
  onBack: () => void;
}) {
  const sources: { type: SourceChoice; icon: typeof Globe; label: string; desc: string; needsM365: boolean }[] = [
    { type: 'sharepoint', icon: Globe, label: 'SharePoint Online', desc: 'Scan document libraries across SharePoint sites', needsM365: true },
    { type: 'onedrive', icon: Cloud, label: 'OneDrive for Business', desc: 'Scan user OneDrive accounts', needsM365: true },
    { type: 'smb', icon: FolderOpen, label: 'SMB File Share', desc: 'Scan Windows or Samba network file shares', needsM365: false },
  ];

  return (
    <Card>
      <CardContent className="space-y-5 p-8">
        <div>
          <h2 className="text-xl font-bold">Choose a Data Source</h2>
          <p className="mt-1 text-sm text-[var(--muted-foreground)]">
            What would you like to scan?
          </p>
        </div>

        <div className="grid gap-3">
          {sources.map(({ type, icon: Icon, label, desc, needsM365 }) => {
            const disabled = disabledSources.has(type) || (needsM365 && !m365Connected);
            return (
              <button
                key={type}
                type="button"
                disabled={disabled}
                className={cn(
                  'flex items-start gap-4 rounded-lg border-2 p-4 text-left transition-colors',
                  disabled
                    ? 'cursor-not-allowed border-gray-100 bg-gray-50 opacity-50'
                    : 'border-gray-200 hover:border-blue-400 hover:bg-blue-50/50',
                )}
                onClick={() => !disabled && onPick(type)}
              >
                <Icon className="mt-0.5 h-6 w-6 shrink-0 text-[var(--muted-foreground)]" />
                <div>
                  <span className="text-sm font-medium">{label}</span>
                  <p className="text-xs text-[var(--muted-foreground)]">{desc}</p>
                  {needsM365 && !m365Connected && (
                    <p className="mt-1 text-xs text-amber-600">Requires Microsoft 365 connection</p>
                  )}
                  {disabledSources.has(type) && (
                    <p className="mt-1 text-xs text-green-600">Already configured</p>
                  )}
                </div>
              </button>
            );
          })}
        </div>

        <div className="flex justify-between pt-2">
          <Button variant="ghost" onClick={onBack}>
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Site selection step (SharePoint / OneDrive) ─────────────────────

function SelectSitesStep({
  sourceType,
  onDone,
  onBack,
}: {
  sourceType: 'sharepoint' | 'onedrive';
  onDone: (selection: SiteSelection) => void;
  onBack: () => void;
}) {
  const [mode, setMode] = useState<'all' | 'individual' | null>(null);
  const [search, setSearch] = useState('');
  const [results, setResults] = useState<EnumeratedResource[]>([]);
  const [loading, setLoading] = useState(false);
  const [hasMore, setHasMore] = useState(false);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Map<string, EnumeratedResource>>(new Map());
  const [initialLoaded, setInitialLoaded] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>();

  const label = sourceType === 'sharepoint' ? 'sites' : 'users';

  const doSearch = useCallback(async (query: string, pageNum: number, append: boolean) => {
    setLoading(true);
    try {
      const resp = await enumerateApi.enumerate({
        source_type: sourceType,
        search: query || undefined,
        page: pageNum,
        page_size: 50,
        use_m365_session: true,
      });
      if (append) {
        setResults(prev => [...prev, ...resp.resources]);
      } else {
        setResults(resp.resources);
      }
      setHasMore(resp.has_more);
      setPage(pageNum);
    } catch { /* toast handled by apiFetch */ } finally {
      setLoading(false);
    }
  }, [sourceType]);

  // Load initial results when selecting "individual"
  useEffect(() => {
    if (mode === 'individual' && !initialLoaded) {
      setInitialLoaded(true);
      doSearch('', 1, false);
    }
  }, [mode, initialLoaded, doSearch]);

  // Debounced search
  const handleSearchChange = (value: string) => {
    setSearch(value);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      doSearch(value, 1, false);
    }, 300);
  };

  const toggleSite = (resource: EnumeratedResource) => {
    setSelected(prev => {
      const next = new Map(prev);
      if (next.has(resource.id)) {
        next.delete(resource.id);
      } else {
        next.set(resource.id, resource);
      }
      return next;
    });
  };

  const handleDone = () => {
    if (mode === 'all') {
      onDone({ sourceType, mode: 'all', selectedSites: [] });
    } else {
      onDone({ sourceType, mode: 'individual', selectedSites: Array.from(selected.values()) });
    }
  };

  return (
    <Card>
      <CardContent className="space-y-5 p-8">
        <div>
          <h2 className="text-xl font-bold">
            Select {sourceType === 'sharepoint' ? 'SharePoint Sites' : 'OneDrive Users'}
          </h2>
          <p className="mt-1 text-sm text-[var(--muted-foreground)]">
            Choose which {label} to scan.
          </p>
        </div>

        {/* Mode selector */}
        <div className="grid grid-cols-2 gap-3">
          <button
            type="button"
            className={cn(
              'rounded-lg border-2 p-4 text-left transition-colors',
              mode === 'all' ? 'border-blue-600 bg-blue-50' : 'border-gray-200 hover:border-blue-400',
            )}
            onClick={() => setMode('all')}
          >
            <span className="text-sm font-medium">Select all</span>
            <p className="text-xs text-[var(--muted-foreground)]">
              All current and future {label}
            </p>
          </button>
          <button
            type="button"
            className={cn(
              'rounded-lg border-2 p-4 text-left transition-colors',
              mode === 'individual' ? 'border-blue-600 bg-blue-50' : 'border-gray-200 hover:border-blue-400',
            )}
            onClick={() => setMode('individual')}
          >
            <span className="text-sm font-medium">Select individual</span>
            <p className="text-xs text-[var(--muted-foreground)]">
              Choose specific {label}
            </p>
          </button>
        </div>

        {/* Individual selection: search + list */}
        {mode === 'individual' && (
          <div className="space-y-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--muted-foreground)]" />
              <Input
                className="pl-9"
                placeholder={`Search ${label}...`}
                value={search}
                onChange={e => handleSearchChange(e.target.value)}
              />
            </div>

            {selected.size > 0 && (
              <p className="text-sm font-medium text-blue-600">
                {selected.size} {label} selected
              </p>
            )}

            <div className="max-h-72 space-y-1 overflow-y-auto rounded-md border p-2">
              {loading && results.length === 0 ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-5 w-5 animate-spin text-[var(--muted-foreground)]" />
                </div>
              ) : results.length === 0 ? (
                <p className="py-4 text-center text-sm text-[var(--muted-foreground)]">
                  {search ? `No ${label} found matching "${search}"` : `No ${label} found`}
                </p>
              ) : (
                <>
                  {results.map(resource => (
                    <label
                      key={resource.id}
                      className={cn(
                        'flex cursor-pointer items-start gap-3 rounded-md px-3 py-2 transition-colors hover:bg-[var(--muted)]',
                        selected.has(resource.id) && 'bg-[var(--accent)]',
                      )}
                    >
                      <input
                        type="checkbox"
                        className="mt-0.5 rounded"
                        checked={selected.has(resource.id)}
                        onChange={() => toggleSite(resource)}
                      />
                      <div className="min-w-0 flex-1">
                        <span className="text-sm font-medium">{resource.name}</span>
                        <p className="truncate text-xs text-[var(--muted-foreground)]">{resource.path}</p>
                        {resource.description && (
                          <p className="truncate text-xs text-[var(--muted-foreground)]">{resource.description}</p>
                        )}
                      </div>
                    </label>
                  ))}
                  {hasMore && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="w-full"
                      disabled={loading}
                      onClick={() => doSearch(search, page + 1, true)}
                    >
                      {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                      Load more
                    </Button>
                  )}
                </>
              )}
            </div>
          </div>
        )}

        <div className="flex justify-between pt-2">
          <Button variant="ghost" onClick={onBack}>
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Button>
          <Button
            onClick={handleDone}
            disabled={!mode || (mode === 'individual' && selected.size === 0)}
          >
            Next <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── SMB setup step ──────────────────────────────────────────────────

function SmbSetupStep({
  config,
  onChange,
  onDone,
  onBack,
}: {
  config: SmbConfig;
  onChange: (config: SmbConfig) => void;
  onDone: () => void;
  onBack: () => void;
}) {
  const [showPassword, setShowPassword] = useState(false);
  const [validating, setValidating] = useState(false);
  const [validated, setValidated] = useState(false);
  const [shares, setShares] = useState<EnumeratedResource[]>([]);
  const [selectedShares, setSelectedShares] = useState<Set<string>>(new Set());
  const [error, setError] = useState('');

  const handleValidate = async () => {
    setValidating(true);
    setError('');
    try {
      const creds = {
        host: config.host,
        username: config.username,
        password: config.password,
      };
      const resp = await enumerateApi.enumerate({
        source_type: 'smb',
        credentials: creds,
      });
      setShares(resp.resources);
      setValidated(true);
      // Auto-select all shares
      setSelectedShares(new Set(resp.resources.map(r => r.id)));
      if (resp.resources.length === 0) {
        setError('Connected successfully but no shares were found.');
      }

      // Persist credentials if "save password" is checked
      if (config.savePassword) {
        await credentialsApi.save({
          source_type: 'smb',
          name: `SMB — ${config.host}`,
          credentials: creds,
        }).catch(() => {
          // Non-fatal: credentials will still work inline for this session
        });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Connection failed');
    } finally {
      setValidating(false);
    }
  };

  const toggleShare = (id: string) => {
    setSelectedShares(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleDone = () => {
    const selected = shares.filter(s => selectedShares.has(s.id));
    onChange({ ...config, selectedShares: selected });
    onDone();
  };

  const canValidate = config.host.trim().length > 0;

  return (
    <Card>
      <CardContent className="space-y-5 p-8">
        <div>
          <h2 className="text-xl font-bold">Setup SMB File Share</h2>
          <p className="mt-1 text-sm text-[var(--muted-foreground)]">
            Enter the server details and credentials to connect.
          </p>
        </div>

        <div className="space-y-3">
          <div>
            <label className="text-sm font-medium" htmlFor="smb-host">Server / Host</label>
            <Input
              id="smb-host"
              placeholder="fileserver.contoso.com or 10.0.0.5"
              value={config.host}
              onChange={e => onChange({ ...config, host: e.target.value })}
            />
          </div>
          <div>
            <label className="text-sm font-medium" htmlFor="smb-user">Service Account</label>
            <Input
              id="smb-user"
              placeholder="DOMAIN\svc-openlabels or user@domain"
              value={config.username}
              onChange={e => onChange({ ...config, username: e.target.value })}
            />
          </div>
          <div>
            <label className="text-sm font-medium" htmlFor="smb-pass">Password</label>
            <div className="relative">
              <Input
                id="smb-pass"
                type={showPassword ? 'text' : 'password'}
                value={config.password}
                onChange={e => onChange({ ...config, password: e.target.value })}
              />
              <button
                type="button"
                className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                onClick={() => setShowPassword(p => !p)}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              className="rounded"
              checked={config.savePassword}
              onChange={e => onChange({ ...config, savePassword: e.target.checked })}
            />
            <span className="text-sm">Save password securely</span>
          </label>
        </div>

        <Button
          onClick={handleValidate}
          disabled={!canValidate || validating}
          variant="outline"
        >
          {validating ? (
            <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Validating...</>
          ) : (
            <><Server className="mr-2 h-4 w-4" /> Validate &amp; Browse Shares</>
          )}
        </Button>

        {error && (
          <p className="text-sm text-red-600">{error}</p>
        )}

        {validated && shares.length > 0 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium">
                Select shares ({selectedShares.size} of {shares.length})
              </p>
              <Button
                type="button" variant="outline" size="sm"
                onClick={() => {
                  if (selectedShares.size === shares.length) {
                    setSelectedShares(new Set());
                  } else {
                    setSelectedShares(new Set(shares.map(s => s.id)));
                  }
                }}
              >
                {selectedShares.size === shares.length ? 'Deselect All' : 'Select All'}
              </Button>
            </div>
            <div className="max-h-48 space-y-1 overflow-y-auto rounded-md border p-2">
              {shares.map(share => (
                <label
                  key={share.id}
                  className={cn(
                    'flex cursor-pointer items-start gap-3 rounded-md px-3 py-2 transition-colors hover:bg-[var(--muted)]',
                    selectedShares.has(share.id) && 'bg-[var(--accent)]',
                  )}
                >
                  <input
                    type="checkbox"
                    className="mt-0.5 rounded"
                    checked={selectedShares.has(share.id)}
                    onChange={() => toggleShare(share.id)}
                  />
                  <div className="min-w-0 flex-1">
                    <span className="text-sm font-medium">{share.name}</span>
                    <p className="truncate text-xs text-[var(--muted-foreground)]">{share.description || share.path}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>
        )}

        <div className="flex justify-between pt-2">
          <Button variant="ghost" onClick={onBack}>
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Button>
          <Button
            onClick={handleDone}
            disabled={!validated || selectedShares.size === 0}
          >
            Next <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Add more sources step ───────────────────────────────────────────

function AddMoreStep({
  m365Connected,
  configuredSources,
  onAdd,
  onSkip,
  onBack,
}: {
  m365Connected: boolean;
  configuredSources: Set<SourceChoice>;
  onAdd: (source: SourceChoice) => void;
  onSkip: () => void;
  onBack: () => void;
}) {
  const remaining: { type: SourceChoice; icon: typeof Globe; label: string; needsM365: boolean }[] = [
    { type: 'sharepoint', icon: Globe, label: 'SharePoint Online', needsM365: true },
    { type: 'onedrive', icon: Cloud, label: 'OneDrive for Business', needsM365: true },
    { type: 'smb', icon: FolderOpen, label: 'SMB File Share', needsM365: false },
  ].filter(s => !configuredSources.has(s.type));

  const available = remaining.filter(s => !s.needsM365 || m365Connected);

  return (
    <Card>
      <CardContent className="space-y-5 p-8">
        <div>
          <h2 className="text-xl font-bold">Add Additional Sources</h2>
          <p className="mt-1 text-sm text-[var(--muted-foreground)]">
            Want to scan additional data sources? You can also add more later.
          </p>
        </div>

        {available.length > 0 ? (
          <div className="grid gap-3">
            {available.map(({ type, icon: Icon, label }) => (
              <button
                key={type}
                type="button"
                className="flex items-center gap-3 rounded-lg border-2 border-gray-200 p-4 text-left transition-colors hover:border-blue-400 hover:bg-blue-50/50"
                onClick={() => onAdd(type)}
              >
                <Plus className="h-4 w-4 text-[var(--muted-foreground)]" />
                <Icon className="h-5 w-5 text-[var(--muted-foreground)]" />
                <span className="text-sm font-medium">{label}</span>
              </button>
            ))}
          </div>
        ) : (
          <p className="text-sm text-[var(--muted-foreground)]">
            All available source types have been configured.
          </p>
        )}

        <div className="flex justify-between pt-2">
          <Button variant="ghost" onClick={onBack}>
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Button>
          <Button onClick={onSkip}>
            {available.length > 0 ? 'Skip' : 'Next'} <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Monitoring step ─────────────────────────────────────────────────

function MonitoringStep({
  enabled,
  onToggle,
  onNext,
  onBack,
  smbConfig,
}: {
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onNext: () => void;
  onBack: () => void;
  smbConfig: SmbConfig | null;
}) {
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
    hostname?: string;
    has_audit_privilege?: boolean;
  } | null>(null);
  const [configuring, setConfiguring] = useState(false);
  const [configResult, setConfigResult] = useState<{
    success: boolean;
    message: string;
  } | null>(null);

  const hasSmbTarget = smbConfig && smbConfig.host.trim().length > 0;

  const handleTestConnection = async () => {
    if (!smbConfig) return;
    setTesting(true);
    setTestResult(null);
    try {
      const resp = await monitoringApi.testRemote({
        host: smbConfig.host,
        username: smbConfig.username,
        password: smbConfig.password,
      });
      setTestResult({
        success: resp.success,
        message: resp.message,
        hostname: resp.hostname ?? undefined,
        has_audit_privilege: resp.has_audit_privilege ?? undefined,
      });
    } catch (e) {
      setTestResult({
        success: false,
        message: e instanceof Error ? e.message : 'Connection test failed',
      });
    } finally {
      setTesting(false);
    }
  };

  const handleConfigureAudit = async () => {
    if (!smbConfig) return;
    setConfiguring(true);
    setConfigResult(null);
    try {
      const sharePaths = smbConfig.selectedShares.map(s => s.path);
      const resp = await monitoringApi.configureRemote({
        host: smbConfig.host,
        username: smbConfig.username,
        password: smbConfig.password,
        share_paths: sharePaths,
      });
      setConfigResult({
        success: resp.success,
        message: resp.message,
      });
    } catch (e) {
      setConfigResult({
        success: false,
        message: e instanceof Error ? e.message : 'Configuration failed',
      });
    } finally {
      setConfiguring(false);
    }
  };

  return (
    <Card>
      <CardContent className="space-y-5 p-8">
        <div>
          <h2 className="text-xl font-bold">Event Monitoring</h2>
          <p className="mt-1 text-sm text-[var(--muted-foreground)]">
            Monitor file access events in real-time to detect
            suspicious activity and track who accesses sensitive files.
          </p>
        </div>

        <div className="space-y-3">
          <button
            type="button"
            className={cn(
              'flex w-full items-start gap-4 rounded-lg border-2 p-4 text-left transition-colors',
              enabled ? 'border-blue-600 bg-blue-50' : 'border-gray-200 hover:border-blue-400',
            )}
            onClick={() => onToggle(true)}
          >
            <Shield className="mt-0.5 h-6 w-6 text-blue-600" />
            <div>
              <span className="text-sm font-medium">Enable monitoring</span>
              <p className="text-xs text-[var(--muted-foreground)]">
                OpenLabels will configure audit logging on your file servers
                via WinRM and stream access events for analysis.
              </p>
            </div>
          </button>
          <button
            type="button"
            className={cn(
              'flex w-full items-start gap-4 rounded-lg border-2 p-4 text-left transition-colors',
              !enabled ? 'border-blue-600 bg-blue-50' : 'border-gray-200 hover:border-gray-400',
            )}
            onClick={() => onToggle(false)}
          >
            <X className="mt-0.5 h-6 w-6 text-gray-400" />
            <div>
              <span className="text-sm font-medium">Skip for now</span>
              <p className="text-xs text-[var(--muted-foreground)]">
                You can enable monitoring later from Settings.
              </p>
            </div>
          </button>
        </div>

        {/* WinRM configuration panel — shown when monitoring is enabled and SMB target exists */}
        {enabled && hasSmbTarget && (
          <div className="space-y-3 rounded-lg border p-4">
            <p className="text-sm font-medium">Configure {smbConfig.host}</p>
            <p className="text-xs text-[var(--muted-foreground)]">
              Test WinRM connectivity to your file server, then configure
              audit policies on the selected shares. The service account
              needs SeSecurityPrivilege on the target server.
            </p>

            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleTestConnection}
                disabled={testing}
              >
                {testing ? (
                  <><Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" /> Testing...</>
                ) : (
                  <>Test Connection</>
                )}
              </Button>

              {testResult?.success && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleConfigureAudit}
                  disabled={configuring}
                >
                  {configuring ? (
                    <><Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" /> Configuring...</>
                  ) : (
                    <>Configure Audit Policy</>
                  )}
                </Button>
              )}
            </div>

            {testResult && (
              <p className={cn(
                'text-xs',
                testResult.success ? 'text-green-600' : 'text-red-600',
              )}>
                {testResult.success ? (
                  <>Connected to {testResult.hostname || smbConfig.host}
                    {testResult.has_audit_privilege === false && (
                      <span className="text-amber-600"> (warning: account lacks SeSecurityPrivilege)</span>
                    )}
                  </>
                ) : testResult.message}
              </p>
            )}

            {configResult && (
              <p className={cn(
                'text-xs',
                configResult.success ? 'text-green-600' : 'text-red-600',
              )}>
                {configResult.message}
              </p>
            )}
          </div>
        )}

        <div className="flex justify-between pt-2">
          <Button variant="ghost" onClick={onBack}>
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Button>
          <Button onClick={onNext}>
            Next <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Review step ─────────────────────────────────────────────────────

function ReviewStep({
  m365: m365Connection,
  siteSelections,
  smbConfig,
  monitoringEnabled,
  onBack,
  onFinish,
  submitting,
}: {
  m365: M365Connection;
  siteSelections: SiteSelection[];
  smbConfig: SmbConfig | null;
  monitoringEnabled: boolean;
  onBack: () => void;
  onFinish: () => void;
  submitting: boolean;
}) {
  return (
    <Card>
      <CardContent className="space-y-5 p-8">
        <div>
          <h2 className="text-xl font-bold">Review &amp; Start</h2>
          <p className="mt-1 text-sm text-[var(--muted-foreground)]">
            Review your configuration before starting.
          </p>
        </div>

        <div className="space-y-3">
          {/* M365 */}
          <div className="flex items-center justify-between rounded-md bg-[var(--muted)] px-4 py-3">
            <span className="text-sm font-medium">Microsoft 365</span>
            {m365Connection.connected ? (
              <span className="flex items-center gap-1.5 text-sm text-green-600">
                <Check className="h-4 w-4" /> {m365Connection.tenantName || 'Connected'}
              </span>
            ) : (
              <span className="text-sm text-gray-400">Skipped</span>
            )}
          </div>

          {/* Site selections */}
          {siteSelections.map((sel, i) => (
            <div key={i} className="flex items-center justify-between rounded-md bg-[var(--muted)] px-4 py-3">
              <span className="text-sm font-medium">
                {sel.sourceType === 'sharepoint' ? 'SharePoint' : 'OneDrive'}
              </span>
              <span className="text-sm">
                {sel.mode === 'all'
                  ? 'All sites'
                  : `${sel.selectedSites.length} site${sel.selectedSites.length !== 1 ? 's' : ''} selected`
                }
              </span>
            </div>
          ))}

          {/* SMB */}
          {smbConfig && smbConfig.host && (
            <div className="flex items-center justify-between rounded-md bg-[var(--muted)] px-4 py-3">
              <span className="text-sm font-medium">SMB File Share</span>
              <span className="text-sm">
                {smbConfig.host} — {smbConfig.selectedShares.length} share{smbConfig.selectedShares.length !== 1 ? 's' : ''}
              </span>
            </div>
          )}

          {/* Monitoring */}
          <div className="flex items-center justify-between rounded-md bg-[var(--muted)] px-4 py-3">
            <span className="text-sm font-medium">Event Monitoring</span>
            <span className={cn('text-sm', monitoringEnabled ? 'text-green-600' : 'text-gray-400')}>
              {monitoringEnabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
        </div>

        <div className="flex justify-between pt-2">
          <Button variant="ghost" onClick={onBack}>
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Button>
          <Button onClick={onFinish} disabled={submitting}>
            {submitting ? (
              <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Setting up...</>
            ) : (
              <>Finish Setup <ArrowRight className="ml-2 h-4 w-4" /></>
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Main wizard ─────────────────────────────────────────────────────

export function Component() {
  const navigate = useNavigate();
  const addToast = useUIStore(s => s.addToast);

  // Wizard state
  const [step, setStep] = useState<WizardStep>('welcome');

  // M365 connection
  const [m365, setM365] = useState<M365Connection>({
    connected: false, tenantId: null, tenantName: null,
  });

  // Sources configured so far
  const [configuredSources, setConfiguredSources] = useState<Set<SourceChoice>>(new Set());

  // First source choice (determines whether we go to select_sites or smb_setup)
  const [currentSource, setCurrentSource] = useState<SourceChoice | null>(null);
  // Whether we're configuring a second source (from add_more)
  const [isSecondSource, setIsSecondSource] = useState(false);

  // Site selections (one per M365 source configured)
  const [siteSelections, setSiteSelections] = useState<SiteSelection[]>([]);

  // SMB config
  const [smbConfig, setSmbConfig] = useState<SmbConfig>({
    host: '', username: '', password: '', savePassword: false, selectedShares: [],
  });

  // Monitoring
  const [monitoringEnabled, setMonitoringEnabled] = useState(false);

  // Submit state
  const [submitting, setSubmitting] = useState(false);

  // Check M365 status on mount (in case already connected from a previous attempt)
  useEffect(() => {
    m365Api.status().then(status => {
      if (status.connected) {
        setM365({
          connected: true,
          tenantId: status.tenant_id,
          tenantName: status.tenant_name,
        });
      }
    }).catch(() => {});
  }, []);

  // Compute which steps to show in the indicator
  const visibleSteps: WizardStep[] = ['welcome', 'm365', 'pick_source'];
  if (currentSource === 'smb') visibleSteps.push('smb_setup');
  else if (currentSource) visibleSteps.push('select_sites');
  visibleSteps.push('add_more', 'monitoring', 'review');

  // Navigation helpers
  const handleM365Connected = async () => {
    try {
      const status = await m365Api.status();
      setM365({
        connected: status.connected,
        tenantId: status.tenant_id,
        tenantName: status.tenant_name,
      });
    } catch { /* ignore */ }
    setStep('pick_source');
  };

  const handlePickSource = (source: SourceChoice) => {
    setCurrentSource(source);
    if (source === 'smb') {
      setStep('smb_setup');
    } else {
      setStep('select_sites');
    }
  };

  const handleSiteSelectionDone = (selection: SiteSelection) => {
    setSiteSelections(prev => {
      // Replace if same source type already exists
      const filtered = prev.filter(s => s.sourceType !== selection.sourceType);
      return [...filtered, selection];
    });
    setConfiguredSources(prev => new Set([...prev, selection.sourceType]));

    if (isSecondSource) {
      setIsSecondSource(false);
      setStep('monitoring');
    } else {
      setStep('add_more');
    }
  };

  const handleSmbDone = () => {
    setConfiguredSources(prev => new Set([...prev, 'smb']));
    if (isSecondSource) {
      setIsSecondSource(false);
      setStep('monitoring');
    } else {
      setStep('add_more');
    }
  };

  const handleAddMore = (source: SourceChoice) => {
    setCurrentSource(source);
    setIsSecondSource(true);
    if (source === 'smb') {
      setStep('smb_setup');
    } else {
      setStep('select_sites');
    }
  };

  const handleFinish = async () => {
    setSubmitting(true);
    try {
      // Create targets for each configured source
      for (const sel of siteSelections) {
        const adapter = sel.sourceType;
        const config: Record<string, unknown> = { source_type: sel.sourceType };

        if (sel.mode === 'all') {
          if (sel.sourceType === 'sharepoint') config.scan_all_sites = true;
          else config.scan_all_users = true;
        } else {
          config.selected_resources = sel.selectedSites.map(s => ({
            id: s.id, name: s.name, path: s.path, resource_type: s.resource_type,
          }));
        }

        await targetsApi.create({
          name: sel.sourceType === 'sharepoint' ? 'SharePoint Online' : 'OneDrive for Business',
          adapter,
          enabled: true,
          config,
        });
      }

      if (smbConfig.host && smbConfig.selectedShares.length > 0) {
        const smbTarget = await targetsApi.create({
          name: `SMB — ${smbConfig.host}`,
          adapter: 'filesystem',
          enabled: true,
          config: {
            source_type: 'smb',
            resource: smbConfig.host,
            selected_resources: smbConfig.selectedShares.map(s => ({
              id: s.id, name: s.name, path: s.path, resource_type: s.resource_type,
            })),
            root_path: smbConfig.selectedShares[0]?.path,
            path: smbConfig.selectedShares[0]?.path,
            monitoring_enabled: monitoringEnabled,
          },
        });

        // Associate saved credentials with the target
        if (smbConfig.savePassword && smbTarget?.id) {
          await credentialsApi.save({
            source_type: 'smb',
            name: `SMB — ${smbConfig.host}`,
            credentials: {
              host: smbConfig.host,
              username: smbConfig.username,
              password: smbConfig.password,
            },
            target_id: smbTarget.id,
          }).catch(() => {});
        }
      }

      addToast({ level: 'success', message: 'Setup complete!' });
      navigate('/dashboard');
    } catch (e) {
      addToast({ level: 'error', message: e instanceof Error ? e.message : 'Setup failed' });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-gray-50 p-4">
      <div className="w-full max-w-lg space-y-6">
        {step !== 'welcome' && (
          <StepIndicator steps={visibleSteps} currentStep={step} />
        )}

        {step === 'welcome' && (
          <WelcomeStep onNext={() => setStep('m365')} />
        )}

        {step === 'm365' && (
          <M365Step
            connection={m365}
            onConnect={handleM365Connected}
            onSkip={() => setStep('pick_source')}
            onBack={() => setStep('welcome')}
          />
        )}

        {step === 'pick_source' && (
          <PickSourceStep
            m365Connected={m365.connected}
            disabledSources={configuredSources}
            onPick={handlePickSource}
            onBack={() => setStep('m365')}
          />
        )}

        {step === 'select_sites' && currentSource && currentSource !== 'smb' && (
          <SelectSitesStep
            sourceType={currentSource}
            onDone={handleSiteSelectionDone}
            onBack={() => {
              if (isSecondSource) {
                setIsSecondSource(false);
                setStep('add_more');
              } else {
                setStep('pick_source');
              }
            }}
          />
        )}

        {step === 'smb_setup' && (
          <SmbSetupStep
            config={smbConfig}
            onChange={setSmbConfig}
            onDone={handleSmbDone}
            onBack={() => {
              if (isSecondSource) {
                setIsSecondSource(false);
                setStep('add_more');
              } else {
                setStep('pick_source');
              }
            }}
          />
        )}

        {step === 'add_more' && (
          <AddMoreStep
            m365Connected={m365.connected}
            configuredSources={configuredSources}
            onAdd={handleAddMore}
            onSkip={() => setStep('monitoring')}
            onBack={() => {
              // Go back to last configured source step
              if (configuredSources.has('smb')) setStep('smb_setup');
              else setStep('select_sites');
            }}
          />
        )}

        {step === 'monitoring' && (
          <MonitoringStep
            enabled={monitoringEnabled}
            onToggle={setMonitoringEnabled}
            onNext={() => setStep('review')}
            onBack={() => setStep('add_more')}
            smbConfig={smbConfig.host ? smbConfig : null}
          />
        )}

        {step === 'review' && (
          <ReviewStep
            m365={m365}
            siteSelections={siteSelections}
            smbConfig={smbConfig.host ? smbConfig : null}
            monitoringEnabled={monitoringEnabled}
            onBack={() => setStep('monitoring')}
            onFinish={handleFinish}
            submitting={submitting}
          />
        )}
      </div>
    </div>
  );
}
