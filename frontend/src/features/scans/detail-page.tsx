import { useParams, useNavigate } from 'react-router';
import { ArrowLeft } from 'lucide-react';
import { useScan, useCancelScan } from '@/api/hooks/use-scans.ts';
import { useScanWebSocket, type LiveFinding } from '@/hooks/use-scan-websocket.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Progress } from '@/components/ui/progress.tsx';
import { StatusBadge } from '@/components/status-badge.tsx';
import { RiskBadge } from '@/components/risk-badge.tsx';
import { EntityTag } from '@/components/entity-tag.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { formatDateTime, formatDuration } from '@/lib/date.ts';
import { truncatePath } from '@/lib/utils.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { ScanStatus, RiskTier } from '@/lib/constants.ts';

function LiveFindingsTable({ findings }: { findings: LiveFinding[] }) {
  if (findings.length === 0) {
    return (
      <Card>
        <CardHeader><CardTitle>Live Findings</CardTitle></CardHeader>
        <CardContent>
          <p className="py-6 text-center text-sm text-[var(--muted-foreground)]">
            Waiting for results...
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Live Findings ({findings.length})</CardTitle>
        <span className="flex items-center gap-1.5 text-xs text-blue-600">
          <span className="h-2 w-2 animate-pulse rounded-full bg-blue-500" />
          Streaming
        </span>
      </CardHeader>
      <CardContent className="p-0">
        <div className="max-h-96 overflow-y-auto">
          <table className="w-full text-sm" aria-label="Live scan findings">
            <thead className="sticky top-0 bg-[var(--muted)]">
              <tr>
                <th className="px-4 py-2 text-left font-medium">File</th>
                <th className="px-4 py-2 text-left font-medium">Risk</th>
                <th className="px-4 py-2 text-left font-medium">Score</th>
                <th className="px-4 py-2 text-left font-medium">Entities</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={`${f.file_path}-${f.timestamp}`} className="border-t hover:bg-[var(--muted)]/50">
                  <td className="max-w-xs truncate px-4 py-2 font-mono text-xs">
                    {truncatePath(f.file_path)}
                  </td>
                  <td className="px-4 py-2">
                    <RiskBadge tier={f.risk_tier as RiskTier} />
                  </td>
                  <td className="px-4 py-2 font-bold">{f.risk_score}</td>
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap gap-1">
                      {Object.entries(f.entity_counts).slice(0, 3).map(([type, count]) => (
                        <EntityTag key={type} type={type} count={count} />
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

export function Component() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const scan = useScan(scanId!);
  const cancelScan = useCancelScan();
  const addToast = useUIStore((s) => s.addToast);

  const isRunning = scan.data?.status === 'running' || scan.data?.status === 'pending';
  const findings = useScanWebSocket(scanId, isRunning);

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
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={() => navigate('/scans')} aria-label="Back to scans">
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold">{s.target_name ?? 'Scan'}</h1>
            <p className="text-sm text-[var(--muted-foreground)]">ID: {s.id}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge status={s.status as ScanStatus} />
          {isRunning && (
            <Button variant="destructive" size="sm" onClick={handleCancel} disabled={cancelScan.isPending}>
              Cancel Scan
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

      {/* Live findings table - shows during running scan */}
      {isRunning && <LiveFindingsTable findings={findings} />}

      {/* Completed scan - link to results */}
      {s.status === 'completed' && s.files_with_pii > 0 && (
        <Card>
          <CardContent className="flex items-center justify-between p-6">
            <div>
              <p className="font-medium">Scan Complete</p>
              <p className="text-sm text-[var(--muted-foreground)]">
                {s.files_with_pii} file{s.files_with_pii !== 1 ? 's' : ''} with sensitive data found
              </p>
            </div>
            <Button onClick={() => navigate('/results')}>
              View Results
            </Button>
          </CardContent>
        </Card>
      )}

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
