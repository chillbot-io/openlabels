import { FolderOpen, Globe, Cloud, ArrowRight, ArrowLeft, Plus } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import type { SourceChoice } from '../types.ts';

export function AddMoreStep({
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
