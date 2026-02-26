import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router';
import { m365Api } from '@/api/endpoints/m365.ts';
import { targetsApi } from '@/api/endpoints/targets.ts';
import { scansApi } from '@/api/endpoints/scans.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type {
  WizardStep,
  SourceChoice,
  M365Connection,
  SiteSelection,
  SmbConfig,
  CollectionMethod,
} from './types.ts';
import {
  StepIndicator,
  WelcomeStep,
  M365Step,
  PickSourceStep,
  SelectSitesStep,
  SmbSetupStep,
  AddMoreStep,
  MonitoringStep,
  ReviewStep,
} from './steps/index.ts';

/*
 * Setup Wizard — first-run experience.
 *
 * Flow:
 *   welcome -> m365 -> pick_source -> select_sites|smb_setup -> add_more ->
 *   [select_sites|smb_setup for second source] -> monitoring -> review
 *
 * Step components have been extracted into features/setup/steps/ for
 * maintainability. This file contains only the wizard orchestration logic.
 */

export function Component() {
  const navigate = useNavigate();
  const addToast = useUIStore(s => s.addToast);

  // Wizard state
  const [step, setStep] = useState<WizardStep>('welcome');

  // M365 connection
  const [m365, setM365] = useState<M365Connection>({
    connected: false, tenantId: null, tenantName: null, hasDedicatedApp: false,
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
  const [monitoringMethod, setMonitoringMethod] = useState<CollectionMethod>(null);

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
          hasDedicatedApp: status.has_dedicated_app,
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
        hasDedicatedApp: status.has_dedicated_app,
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
    // SECURITY: Clear sensitive credential fields from React state immediately
    // after the SMB step completes. Credentials have already been sent to the
    // backend during validation; only `host` and `selectedShares` are needed
    // for target creation in handleFinish.
    setSmbConfig(prev => ({ ...prev, username: '', password: '' }));

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
      // Create targets for each configured source, collecting IDs for scan kickoff
      const createdTargetIds: string[] = [];

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

        const target = await targetsApi.create({
          name: sel.sourceType === 'sharepoint' ? 'SharePoint Online' : 'OneDrive for Business',
          adapter,
          enabled: true,
          config,
        });
        if (target?.id) createdTargetIds.push(target.id);
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

        if (smbTarget?.id) {
          createdTargetIds.push(smbTarget.id);

          // NOTE: Credential persistence (if savePassword was checked) already
          // happened during the SMB setup step's validate flow. Sensitive
          // credential fields (username, password) were cleared from React
          // state in handleSmbDone immediately after that step completed.
        }
      }

      // Kick off initial scans for all created targets
      if (createdTargetIds.length > 0) {
        try {
          await scansApi.createBulk(createdTargetIds);
          addToast({ level: 'success', message: 'Setup complete — scans are starting!' });
        } catch {
          // Targets were created but scan kickoff failed — still navigate
          addToast({ level: 'success', message: 'Setup complete! Start scans from the dashboard.' });
        }
      } else {
        addToast({ level: 'success', message: 'Setup complete!' });
      }

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
            method={monitoringMethod}
            onMethodChange={setMonitoringMethod}
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
            monitoringMethod={monitoringMethod}
            onBack={() => setStep('monitoring')}
            onFinish={handleFinish}
            submitting={submitting}
          />
        )}
      </div>
    </div>
  );
}
