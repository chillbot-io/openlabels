import { useJobQueue, useScanThroughput } from '@/api/hooks/use-monitoring.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatNumber } from '@/lib/utils.ts';

export function JobsTab() {
  const jobQueue = useJobQueue();
  const throughput = useScanThroughput({ hours: 24 });

  return (
    <div className="space-y-4">
      {jobQueue.isLoading ? (
        <Skeleton className="h-32" />
      ) : jobQueue.data ? (
        <>
          <div className="grid grid-cols-4 gap-4">
            {(['pending', 'running', 'completed', 'failed'] as const).map((key) => (
              <Card key={key}>
                <CardContent className="p-4 text-center">
                  <p className="text-2xl font-bold">{formatNumber(jobQueue.data[key])}</p>
                  <p className="text-xs text-[var(--muted-foreground)] capitalize">{key}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Processing rate */}
          {throughput.data && (
            <div className="grid grid-cols-3 gap-4">
              <Card>
                <CardContent className="p-4 text-center">
                  <p className="text-2xl font-bold">{formatNumber(throughput.data.total_scans)}</p>
                  <p className="text-xs text-[var(--muted-foreground)]">Scans (24h)</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4 text-center">
                  <p className="text-2xl font-bold">{throughput.data.avg_files_per_hour.toFixed(0)}</p>
                  <p className="text-xs text-[var(--muted-foreground)]">Files/Hour</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4 text-center">
                  <p className="text-2xl font-bold">
                    {throughput.data.avg_scan_duration_seconds
                      ? `${(throughput.data.avg_scan_duration_seconds / 60).toFixed(1)}m`
                      : '--'}
                  </p>
                  <p className="text-xs text-[var(--muted-foreground)]">Avg Duration</p>
                </CardContent>
              </Card>
            </div>
          )}

          {Object.keys(jobQueue.data.failed_by_type ?? {}).length > 0 && (
            <Card>
              <CardHeader><CardTitle>Failed Jobs by Type</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {Object.entries(jobQueue.data.failed_by_type).map(([type, count]) => (
                    <div key={type} className="flex items-center justify-between rounded-md bg-[var(--muted)] p-3">
                      <p className="text-sm font-medium">{type}</p>
                      <span className="text-sm font-bold text-red-600">{count}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </>
      ) : null}
    </div>
  );
}
