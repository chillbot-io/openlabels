import { useState, useEffect } from 'react';
import {
  Check, ArrowRight, ArrowLeft, Loader2, Shield, X, Copy, FileCode, Terminal,
} from 'lucide-react';
import { monitoringApi } from '@/api/endpoints/monitoring.ts';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { cn } from '@/lib/utils.ts';
import type { CollectionMethod, SmbConfig } from '../types.ts';

function ScriptBlock({ script, label }: { script: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(script).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {});
  };
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium">{label}</span>
        <button
          type="button"
          className="flex items-center gap-1 text-xs text-blue-600 hover:text-blue-800"
          onClick={handleCopy}
        >
          {copied ? <><Check className="h-3 w-3" /> Copied</> : <><Copy className="h-3 w-3" /> Copy</>}
        </button>
      </div>
      <pre className="max-h-48 overflow-auto rounded-md bg-gray-900 p-3 text-xs text-green-400 leading-relaxed">
        {script}
      </pre>
    </div>
  );
}

export function MonitoringStep({
  enabled,
  onToggle,
  method,
  onMethodChange,
  onNext,
  onBack,
  smbConfig,
}: {
  enabled: boolean;
  onToggle: (v: boolean) => void;
  method: CollectionMethod;
  onMethodChange: (m: CollectionMethod) => void;
  onNext: () => void;
  onBack: () => void;
  smbConfig: SmbConfig | null;
}) {
  // Service identity
  const [identity, setIdentity] = useState<{
    account_name: string;
    domain: string | null;
    is_gmsa: boolean;
  } | null>(null);

  // WEF state
  const [wefIniting, setWefIniting] = useState(false);
  const [wefInited, setWefInited] = useState(false);
  const [wefCreating, setWefCreating] = useState(false);
  const [wefCreated, setWefCreated] = useState(false);
  const [gpoConfig, setGpoConfig] = useState<string | null>(null);
  const [wefError, setWefError] = useState('');
  const [copiedGpo, setCopiedGpo] = useState(false);

  // Script generation
  const [gmsaScript, setGmsaScript] = useState<string | null>(null);
  const [auditScript, setAuditScript] = useState<string | null>(null);
  const [loadingScript, setLoadingScript] = useState('');

  // Detect service identity on mount
  useEffect(() => {
    if (enabled && !identity) {
      monitoringApi.serviceIdentity()
        .then(setIdentity)
        .catch(() => {});
    }
  }, [enabled, identity]);

  // WEF handlers
  const handleWefInit = async () => {
    setWefIniting(true);
    setWefError('');
    try {
      const resp = await monitoringApi.wefInit();
      if (resp.success) {
        setWefInited(true);
      } else {
        setWefError(resp.message);
      }
    } catch (e) {
      setWefError(e instanceof Error ? e.message : 'Failed to initialize collector');
    } finally {
      setWefIniting(false);
    }
  };

  const handleWefCreate = async () => {
    setWefCreating(true);
    setWefError('');
    try {
      const resp = await monitoringApi.wefCreateSubscription();
      if (resp.success) {
        setWefCreated(true);
        setGpoConfig(resp.gpo_config);
      } else {
        setWefError(resp.message);
      }
    } catch (e) {
      setWefError(e instanceof Error ? e.message : 'Failed to create subscription');
    } finally {
      setWefCreating(false);
    }
  };

  const handleCopyGpo = () => {
    if (!gpoConfig) return;
    navigator.clipboard.writeText(gpoConfig).then(() => {
      setCopiedGpo(true);
      setTimeout(() => setCopiedGpo(false), 2000);
    }).catch(() => {});
  };

  const handleGenerateGmsaScript = async () => {
    setLoadingScript('gmsa');
    try {
      const resp = await monitoringApi.gmsaSetupScript();
      setGmsaScript(resp.script);
    } catch { /* ignore */ } finally {
      setLoadingScript('');
    }
  };

  const handleGenerateAuditScript = async () => {
    setLoadingScript('audit');
    try {
      const paths = smbConfig?.selectedShares.map(s => s.path) ?? [];
      const resp = await monitoringApi.auditPolicyScript({
        share_paths: paths,
      });
      setAuditScript(resp.script);
    } catch { /* ignore */ } finally {
      setLoadingScript('');
    }
  };

  return (
    <Card>
      <CardContent className="space-y-5 p-8">
        <div>
          <h2 className="text-xl font-bold">Event Monitoring</h2>
          <p className="mt-1 text-sm text-[var(--muted-foreground)]">
            Track who accesses sensitive files using Windows Event
            Forwarding. File servers push events to this collector
            automatically — no polling, no stored passwords.
          </p>
        </div>

        {/* Enable / skip toggle */}
        <div className="space-y-3">
          <button
            type="button"
            className={cn(
              'flex w-full items-start gap-4 rounded-lg border-2 p-4 text-left transition-colors',
              enabled ? 'border-blue-600 bg-blue-50' : 'border-gray-200 hover:border-blue-400',
            )}
            onClick={() => { onToggle(true); onMethodChange('wef'); }}
          >
            <Shield className="mt-0.5 h-6 w-6 text-blue-600" />
            <div>
              <span className="text-sm font-medium">Enable monitoring</span>
              <p className="text-xs text-[var(--muted-foreground)]">
                Configure WEF event collection from your file servers.
              </p>
            </div>
          </button>
          <button
            type="button"
            className={cn(
              'flex w-full items-start gap-4 rounded-lg border-2 p-4 text-left transition-colors',
              !enabled ? 'border-blue-600 bg-blue-50' : 'border-gray-200 hover:border-gray-400',
            )}
            onClick={() => { onToggle(false); onMethodChange(null); }}
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

        {/* WEF setup flow — shown when monitoring is enabled */}
        {enabled && (
          <div className="space-y-4">
            {/* Service identity banner */}
            {identity && (
              <div className={cn(
                'flex items-center gap-3 rounded-lg border px-4 py-2.5',
                identity.is_gmsa ? 'border-green-200 bg-green-50' : 'border-amber-200 bg-amber-50',
              )}>
                <Shield className={cn('h-4 w-4', identity.is_gmsa ? 'text-green-600' : 'text-amber-600')} />
                <div className="min-w-0 flex-1">
                  <span className="text-xs font-medium">
                    Running as: {identity.domain ? `${identity.domain}\\` : ''}{identity.account_name}
                  </span>
                  {identity.is_gmsa ? (
                    <p className="text-xs text-green-600">gMSA detected — passwords managed by AD</p>
                  ) : (
                    <p className="text-xs text-amber-600">
                      Consider running as a gMSA for automatic password management
                    </p>
                  )}
                </div>
                {!identity.is_gmsa && !gmsaScript && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleGenerateGmsaScript}
                    disabled={loadingScript === 'gmsa'}
                  >
                    {loadingScript === 'gmsa' ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <><Terminal className="mr-1.5 h-3.5 w-3.5" /> Setup Script</>
                    )}
                  </Button>
                )}
              </div>
            )}

            {/* gMSA setup script (expanded) */}
            {gmsaScript && (
              <ScriptBlock script={gmsaScript} label="gMSA Setup — run on a Domain Controller" />
            )}

            {/* WEF collector setup */}
            <div className="space-y-3 rounded-lg border p-4">
              <p className="text-sm font-medium">Collector Setup</p>

              {/* Step 1: Init collector */}
              <div className="flex items-center gap-3">
                <div className={cn(
                  'flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-medium',
                  wefInited ? 'bg-green-500 text-white' : 'bg-gray-200 text-gray-600',
                )}>
                  {wefInited ? <Check className="h-3.5 w-3.5" /> : '1'}
                </div>
                {wefInited ? (
                  <span className="text-xs text-green-600">Collector service initialized</span>
                ) : (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleWefInit}
                    disabled={wefIniting}
                  >
                    {wefIniting ? (
                      <><Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" /> Initializing...</>
                    ) : (
                      <>Initialize Collector Service</>
                    )}
                  </Button>
                )}
              </div>

              {/* Step 2: Create subscription */}
              <div className="flex items-center gap-3">
                <div className={cn(
                  'flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-medium',
                  wefCreated ? 'bg-green-500 text-white' : 'bg-gray-200 text-gray-600',
                )}>
                  {wefCreated ? <Check className="h-3.5 w-3.5" /> : '2'}
                </div>
                {wefCreated ? (
                  <span className="text-xs text-green-600">Subscription created</span>
                ) : (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleWefCreate}
                    disabled={!wefInited || wefCreating}
                  >
                    {wefCreating ? (
                      <><Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" /> Creating...</>
                    ) : (
                      <>Create Subscription</>
                    )}
                  </Button>
                )}
              </div>

              {/* Step 3: GPO config for WEF forwarding */}
              {gpoConfig && (
                <div className="space-y-2">
                  <div className="flex items-center gap-3">
                    <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-blue-100 text-xs font-medium text-blue-700">
                      3
                    </div>
                    <span className="text-xs font-medium">
                      Deploy this GPO value to your file servers:
                    </span>
                  </div>
                  <div className="relative rounded-md bg-gray-900 p-3">
                    <code className="block break-all text-xs text-green-400">
                      {gpoConfig}
                    </code>
                    <button
                      type="button"
                      className="absolute right-2 top-2 rounded p-1 text-gray-400 hover:text-white"
                      onClick={handleCopyGpo}
                    >
                      {copiedGpo ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                  <p className="text-xs text-[var(--muted-foreground)]">
                    Computer Configuration &gt; Administrative Templates &gt;
                    Windows Components &gt; Event Forwarding &gt;
                    Configure target Subscription Manager
                  </p>
                </div>
              )}

              {wefError && (
                <p className="text-xs text-red-600">{wefError}</p>
              )}
            </div>

            {/* Audit policy script */}
            <div className="space-y-2 rounded-lg border p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium">Audit Policy</p>
                  <p className="text-xs text-[var(--muted-foreground)]">
                    Enable file access auditing on your file servers via GPO.
                  </p>
                </div>
                {!auditScript && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleGenerateAuditScript}
                    disabled={loadingScript === 'audit'}
                  >
                    {loadingScript === 'audit' ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <><FileCode className="mr-1.5 h-3.5 w-3.5" /> Generate Script</>
                    )}
                  </Button>
                )}
              </div>
              {auditScript && (
                <ScriptBlock script={auditScript} label="Audit Policy — deploy via GPO or run on file servers" />
              )}
            </div>
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
