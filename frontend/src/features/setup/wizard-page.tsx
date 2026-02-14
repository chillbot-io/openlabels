import { useState } from 'react';
import { useNavigate } from 'react-router';
import { Check, ArrowRight, ArrowLeft, FolderOpen, Globe, Cloud, SkipForward, Loader2 } from 'lucide-react';
import { settingsApi } from '@/api/endpoints/settings.ts';
import { targetsApi } from '@/api/endpoints/targets.ts';
import { scansApi } from '@/api/endpoints/scans.ts';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { LogoIcon } from '@/components/brand/logo.tsx';
import { useUIStore } from '@/stores/ui-store.ts';
import { cn } from '@/lib/utils.ts';

type Step = 'welcome' | 'azure' | 'target' | 'review';
type AdapterType = 'filesystem' | 'sharepoint' | 'onedrive' | null;

const STEPS: { key: Step; label: string }[] = [
  { key: 'welcome', label: 'Welcome' },
  { key: 'azure', label: 'Azure AD' },
  { key: 'target', label: 'Scan Target' },
  { key: 'review', label: 'Review' },
];

function StepIndicator({ current }: { current: Step }) {
  const currentIdx = STEPS.findIndex((s) => s.key === current);
  return (
    <div className="flex items-center justify-center gap-2">
      {STEPS.map((step, i) => (
        <div key={step.key} className="flex items-center gap-2">
          <div
            className={cn(
              'flex h-8 w-8 items-center justify-center rounded-full text-xs font-medium',
              i < currentIdx ? 'bg-green-500 text-white' : i === currentIdx ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-500',
            )}
          >
            {i < currentIdx ? <Check className="h-4 w-4" /> : i + 1}
          </div>
          <span className={cn('text-sm hidden sm:inline', i === currentIdx ? 'font-medium' : 'text-gray-400')}>{step.label}</span>
          {i < STEPS.length - 1 && <div className="h-px w-8 bg-gray-300" />}
        </div>
      ))}
    </div>
  );
}

export function Component() {
  const navigate = useNavigate();
  const addToast = useUIStore((s) => s.addToast);

  const [step, setStep] = useState<Step>('welcome');

  // Azure AD state
  const [tenantId, setTenantId] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [azureTesting, setAzureTesting] = useState(false);
  const [azureConnected, setAzureConnected] = useState(false);
  const [azureError, setAzureError] = useState('');
  const [azureSaving, setAzureSaving] = useState(false);

  // Target state
  const [adapterType, setAdapterType] = useState<AdapterType>(null);
  const [targetName, setTargetName] = useState('');
  const [targetPath, setTargetPath] = useState('');
  const [skippedTarget, setSkippedTarget] = useState(false);

  // Submit state
  const [submitting, setSubmitting] = useState(false);

  const handleTestAzure = async () => {
    setAzureTesting(true);
    setAzureError('');
    try {
      await settingsApi.update('azure', {
        azure_tenant_id: tenantId,
        azure_client_id: clientId,
        azure_client_secret: clientSecret,
      });
      setAzureConnected(true);
    } catch (e: unknown) {
      setAzureError(e instanceof Error ? e.message : 'Connection failed');
    } finally {
      setAzureTesting(false);
    }
  };

  const handleSaveAzure = async () => {
    setAzureSaving(true);
    try {
      await settingsApi.update('azure', {
        azure_tenant_id: tenantId,
        azure_client_id: clientId,
        azure_client_secret: clientSecret,
      });
      setStep('target');
    } catch (e: unknown) {
      setAzureError(e instanceof Error ? e.message : 'Failed to save');
    } finally {
      setAzureSaving(false);
    }
  };

  const handleSkipTarget = () => {
    setSkippedTarget(true);
    setAdapterType(null);
    setStep('review');
  };

  const handleFinish = async () => {
    setSubmitting(true);
    try {
      if (!skippedTarget && adapterType && targetName && targetPath) {
        const config: Record<string, unknown> =
          adapterType === 'filesystem' ? { root_path: targetPath }
            : adapterType === 'sharepoint' ? { site_url: targetPath }
              : { user_email: targetPath };

        const target = await targetsApi.create({
          name: targetName,
          adapter: adapterType,
          enabled: true,
          config,
        });

        // Start the first scan
        await scansApi.create({ target_id: target.id });
        addToast({ level: 'success', message: 'First scan started!' });
      }
      navigate('/dashboard');
    } catch (e: unknown) {
      addToast({ level: 'error', message: e instanceof Error ? e.message : 'Setup failed' });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-gray-50 p-4">
      <div className="w-full max-w-lg space-y-6">
        {step !== 'welcome' && <StepIndicator current={step} />}

        {/* Welcome */}
        {step === 'welcome' && (
          <Card>
            <CardContent className="space-y-6 p-8 text-center">
              <LogoIcon className="mx-auto h-16 w-auto" />
              <div>
                <h1 className="text-3xl font-bold">Welcome to OpenLabels</h1>
                <p className="mt-2 text-[var(--muted-foreground)]">
                  Let's get you set up in 3 steps.
                </p>
              </div>
              <Button size="lg" onClick={() => setStep('azure')}>
                Get Started <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Step 1: Azure AD */}
        {step === 'azure' && (
          <Card>
            <CardContent className="space-y-5 p-8">
              <div>
                <h2 className="text-xl font-bold">Step 1: Azure AD</h2>
                <p className="mt-1 text-sm text-[var(--muted-foreground)]">
                  Connect your Azure AD tenant to enable label sync and authentication.
                </p>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="text-sm font-medium" htmlFor="tenant-id">Tenant ID</label>
                  <Input id="tenant-id" value={tenantId} onChange={(e) => setTenantId(e.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
                </div>
                <div>
                  <label className="text-sm font-medium" htmlFor="client-id">Client ID</label>
                  <Input id="client-id" value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
                </div>
                <div>
                  <label className="text-sm font-medium" htmlFor="client-secret">Client Secret</label>
                  <Input id="client-secret" type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} />
                </div>
              </div>
              <Button variant="outline" onClick={handleTestAzure} disabled={!tenantId || !clientId || !clientSecret || azureTesting}>
                {azureTesting ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Testing...</> : 'Test Connection'}
              </Button>
              {azureConnected && (
                <p className="text-sm font-medium text-green-600">Connected successfully</p>
              )}
              {azureError && (
                <p className="text-sm text-red-600">{azureError}</p>
              )}
              <div className="flex justify-between pt-2">
                <Button variant="ghost" onClick={() => setStep('welcome')}>
                  <ArrowLeft className="mr-2 h-4 w-4" /> Back
                </Button>
                <Button onClick={handleSaveAzure} disabled={!tenantId || !clientId || !clientSecret || azureSaving}>
                  {azureSaving ? 'Saving...' : 'Next: Targets'} <ArrowRight className="ml-2 h-4 w-4" />
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Step 2: First Scan Target */}
        {step === 'target' && (
          <Card>
            <CardContent className="space-y-5 p-8">
              <div>
                <h2 className="text-xl font-bold">Step 2: First Scan Target</h2>
                <p className="mt-1 text-sm text-[var(--muted-foreground)]">
                  What do you want to scan first?
                </p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                {([
                  { type: 'filesystem' as const, icon: FolderOpen, label: 'File Share', desc: 'UNC paths, local directories' },
                  { type: 'sharepoint' as const, icon: Globe, label: 'SharePoint', desc: 'Sites & document libraries' },
                  { type: 'onedrive' as const, icon: Cloud, label: 'OneDrive', desc: 'User drives' },
                ]).map(({ type, icon: Icon, label, desc }) => (
                  <button
                    key={type}
                    type="button"
                    className={cn(
                      'flex flex-col items-center gap-2 rounded-lg border-2 p-4 text-center transition-colors hover:border-blue-400',
                      adapterType === type ? 'border-blue-600 bg-blue-50' : 'border-gray-200',
                    )}
                    onClick={() => { setAdapterType(type); setSkippedTarget(false); }}
                  >
                    <Icon className="h-6 w-6" />
                    <span className="text-sm font-medium">{label}</span>
                    <span className="text-xs text-[var(--muted-foreground)]">{desc}</span>
                  </button>
                ))}
                <button
                  type="button"
                  className={cn(
                    'flex flex-col items-center gap-2 rounded-lg border-2 p-4 text-center transition-colors hover:border-gray-400',
                    'border-gray-200',
                  )}
                  onClick={handleSkipTarget}
                >
                  <SkipForward className="h-6 w-6 text-gray-400" />
                  <span className="text-sm font-medium text-gray-500">Skip for now</span>
                  <span className="text-xs text-[var(--muted-foreground)]">Set up later</span>
                </button>
              </div>

              {adapterType && (
                <div className="space-y-3">
                  <div>
                    <label className="text-sm font-medium" htmlFor="target-name">Target Name</label>
                    <Input id="target-name" value={targetName} onChange={(e) => setTargetName(e.target.value)} placeholder="Finance Department Share" />
                  </div>
                  <div>
                    <label className="text-sm font-medium" htmlFor="target-path">
                      {adapterType === 'filesystem' ? 'Path' : adapterType === 'sharepoint' ? 'Site URL' : 'User Email'}
                    </label>
                    <Input
                      id="target-path"
                      value={targetPath}
                      onChange={(e) => setTargetPath(e.target.value)}
                      placeholder={
                        adapterType === 'filesystem' ? '\\\\server\\share' :
                        adapterType === 'sharepoint' ? 'https://contoso.sharepoint.com/sites/finance' :
                        'user@contoso.com or "all"'
                      }
                    />
                  </div>
                </div>
              )}

              <div className="flex justify-between pt-2">
                <Button variant="ghost" onClick={() => setStep('azure')}>
                  <ArrowLeft className="mr-2 h-4 w-4" /> Back
                </Button>
                <Button
                  onClick={() => setStep('review')}
                  disabled={!adapterType || !targetName || !targetPath}
                >
                  Next: Review <ArrowRight className="ml-2 h-4 w-4" />
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Step 3: Review & Start */}
        {step === 'review' && (
          <Card>
            <CardContent className="space-y-5 p-8">
              <div>
                <h2 className="text-xl font-bold">Step 3: Review & Start</h2>
                <p className="mt-1 text-sm text-[var(--muted-foreground)]">
                  Review your configuration before starting.
                </p>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between rounded-md bg-[var(--muted)] px-4 py-3">
                  <span className="text-sm font-medium">Azure AD</span>
                  <span className="flex items-center gap-1.5 text-sm text-green-600">
                    <Check className="h-4 w-4" /> Connected
                  </span>
                </div>
                <div className="flex items-center justify-between rounded-md bg-[var(--muted)] px-4 py-3">
                  <span className="text-sm font-medium">Scan Target</span>
                  <span className="text-sm">
                    {skippedTarget ? (
                      <span className="text-gray-400">Skipped</span>
                    ) : (
                      <span>{targetName} ({targetPath})</span>
                    )}
                  </span>
                </div>
              </div>

              {!skippedTarget && (
                <p className="text-sm text-[var(--muted-foreground)]">
                  Ready to run your first scan? We'll create the target and start scanning immediately.
                </p>
              )}

              <div className="flex justify-between pt-2">
                <Button variant="ghost" onClick={() => setStep('target')}>
                  <ArrowLeft className="mr-2 h-4 w-4" /> Back
                </Button>
                <Button onClick={handleFinish} disabled={submitting}>
                  {submitting ? (
                    <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Setting up...</>
                  ) : skippedTarget ? (
                    'Go to Dashboard'
                  ) : (
                    <>Start Scan <ArrowRight className="ml-2 h-4 w-4" /></>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
