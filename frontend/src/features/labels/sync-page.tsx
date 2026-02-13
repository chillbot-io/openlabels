import { useLabelSyncStatus } from '@/api/hooks/use-labels.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { formatDateTime } from '@/lib/date.ts';

export function Component() {
  const syncStatus = useLabelSyncStatus();

  if (syncStatus.isLoading) return <LoadingSkeleton />;
  if (!syncStatus.data) return <p className="p-6">No sync status available</p>;

  const s = syncStatus.data;

  return (
    <div className="mx-auto max-w-2xl space-y-6 p-6">
      <h1 className="text-2xl font-bold">Label Sync</h1>

      <Card>
        <CardHeader>
          <CardTitle>Sync Status</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4 text-center">
            <div>
              <p className="text-2xl font-bold text-green-600">{s.label_count}</p>
              <p className="text-xs text-[var(--muted-foreground)]">Labels Available</p>
            </div>
            <div>
              <p className="text-sm font-medium">
                {s.last_synced_at ? formatDateTime(s.last_synced_at) : 'Never'}
              </p>
              <p className="text-xs text-[var(--muted-foreground)]">Last Synced</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
