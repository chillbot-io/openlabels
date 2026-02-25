import { useState } from 'react';
import { Check, Globe, ArrowRight, ArrowLeft, SkipForward, Loader2 } from 'lucide-react';
import { m365Api } from '@/api/endpoints/m365.ts';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import type { M365Connection } from '../types.ts';

export function M365Step({
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
