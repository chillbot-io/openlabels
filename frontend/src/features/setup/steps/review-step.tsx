import { Check, ArrowRight, ArrowLeft, Loader2 } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { cn } from '@/lib/utils.ts';
import type { M365Connection, SiteSelection, SmbConfig, CollectionMethod } from '../types.ts';

export function ReviewStep({
  m365: m365Connection,
  siteSelections,
  smbConfig,
  monitoringEnabled,
  monitoringMethod,
  onBack,
  onFinish,
  submitting,
}: {
  m365: M365Connection;
  siteSelections: SiteSelection[];
  smbConfig: SmbConfig | null;
  monitoringEnabled: boolean;
  monitoringMethod: CollectionMethod;
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
              {monitoringEnabled
                ? monitoringMethod === 'wef' ? 'WEF (Event Forwarding)'
                  : monitoringMethod === 'winrm' ? 'WinRM (Direct)'
                  : 'Enabled'
                : 'Disabled'}
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
