import { useParams } from 'react-router';
import { useScan, useCancelScan } from '@/api/hooks/use-scans.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Progress } from '@/components/ui/progress.tsx';
import { StatusBadge } from '@/components/status-badge.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { formatDateTime, formatDuration } from '@/lib/date.ts';
import { truncatePath } from '@/lib/utils.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { ScanStatus } from '@/lib/constants.ts';

export function Component() {
  const { scanId } = useParams<{ scanId: string }>();
  const scan = useScan(scanId!);
  const cancelScan = useCancelScan();
  const addToast = useUIStore((s) => s.addToast);

  if (scan.isLoading) return <LoadingSkeleton />;
  if (!scan.data) return <p className="p-6">Scan not found</p>;

  const s = scan.data;
  const progress = s.progress;
  const pct = progress && progress.files_total > 0
    ? Math.min(100, Math.round((progress.files_scanned / progress.files_total) * 100))
    : 0;

  const handleCancel = () => {
    cancelScan.mutate(s.id, {
      onSuccess: () => addToast({ level: 'info', message: 'Scan cancelled' }),
      onError: (err) => addToast({ level: 'error', message: err.message }),
    });
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{s.target_name ?? 'Scan'}</h1>
          <p className="text-sm text-[var(--muted-foreground)]">ID: {s.id}</p>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge status={s.status as ScanStatus} />
          {(s.status === 'running' || s.status === 'pending') && (
            <Button variant="destructive" size="sm" onClick={handleCancel} disabled={cancelScan.isPending}>
              Cancel
            </Button>
          )}
        </div>
      </div>

      {s.status === 'running' && progress && (
        <Card>
          <CardContent className="space-y-3 p-6">
            <div className="flex items-center justify-between text-sm">
              <span>Progress</span>
              <span>{pct}%</span>
            </div>
            <Progress value={pct} aria-label="Scan progress" />
            <p className="text-xs text-[var(--muted-foreground)]">
              Scanning: {truncatePath(progress.current_file)}
            </p>
            <div className="grid grid-cols-3 gap-4 text-center text-sm">
              <div>
                <p className="text-lg font-bold">{progress.files_scanned}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Scanned</p>
              </div>
              <div>
                <p className="text-lg font-bold">{progress.files_with_pii}</p>
                <p className="text-xs text-[var(--muted-foreground)]">With PII</p>
              </div>
              <div>
                <p className="text-lg font-bold">{progress.files_skipped}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Skipped</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-2 gap-6 lg:grid-cols-4">
        <Card>
          <CardHeader><CardTitle className="text-sm">Files Scanned</CardTitle></CardHeader>
          <CardContent><p className="text-2xl font-bold">{s.files_scanned}</p></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Files with PII</CardTitle></CardHeader>
          <CardContent><p className="text-2xl font-bold">{s.files_with_pii}</p></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Started</CardTitle></CardHeader>
          <CardContent><p className="text-sm">{formatDateTime(s.started_at)}</p></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Duration</CardTitle></CardHeader>
          <CardContent>
            <p className="text-sm">
              {s.started_at ? formatDuration(s.started_at, s.completed_at) : '—'}
            </p>
          </CardContent>
        </Card>
      </div>

      {s.error && (
        <Card className="border-[var(--destructive)]/30 bg-[var(--destructive)]/10" role="alert">
          <CardContent className="p-6">
            <p className="text-sm font-medium text-[var(--destructive)]">Error</p>
            <p className="mt-1 text-sm text-[var(--destructive)]/80">{s.error}</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
