import { useLabelSyncStatus } from '@/api/hooks/use-labels.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Progress } from '@/components/ui/progress.tsx';
import { StatusBadge } from '@/components/status-badge.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { formatDateTime } from '@/lib/date.ts';
import type { ScanStatus } from '@/lib/constants.ts';

export function Component() {
  const syncStatus = useLabelSyncStatus();

  if (syncStatus.isLoading) return <LoadingSkeleton />;
  if (!syncStatus.data) return <p className="p-6">No sync status available</p>;

  const s = syncStatus.data;
  const total = s.labels_synced + s.labels_failed;
  const pct = total > 0 ? Math.round((s.labels_synced / total) * 100) : 0;

  return (
    <div className="mx-auto max-w-2xl space-y-6 p-6">
      <h1 className="text-2xl font-bold">Label Sync</h1>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Sync Status</CardTitle>
            <StatusBadge status={s.status as ScanStatus} />
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {(s.status === 'running' || s.status === 'pending') && (
            <Progress value={pct} aria-label={`Sync progress: ${pct}%`} />
          )}

          <div className="grid grid-cols-2 gap-4 text-center">
            <div>
              <p className="text-2xl font-bold text-green-600">{s.labels_synced}</p>
              <p className="text-xs text-[var(--muted-foreground)]">Synced</p>
            </div>
            <div>
              <p className="text-2xl font-bold text-red-600">{s.labels_failed}</p>
              <p className="text-xs text-[var(--muted-foreground)]">Failed</p>
            </div>
          </div>

          <div className="space-y-1 text-sm">
            <p><span className="text-[var(--muted-foreground)]">Started:</span> {formatDateTime(s.started_at)}</p>
            <p><span className="text-[var(--muted-foreground)]">Completed:</span> {formatDateTime(s.completed_at)}</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
