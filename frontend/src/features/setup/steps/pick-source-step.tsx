import { FolderOpen, Globe, Cloud, ArrowLeft } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { cn } from '@/lib/utils.ts';
import type { SourceChoice } from '../types.ts';

export function PickSourceStep({
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
