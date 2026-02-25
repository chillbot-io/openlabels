import { useWorkers } from '@/api/hooks/use-monitoring.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatNumber } from '@/lib/utils.ts';

const workerStatusColor: Record<string, string> = {
  running: 'bg-green-500',
  idle: 'bg-yellow-500',
  error: 'bg-red-500',
  crashed: 'bg-red-500',
  stopped: 'bg-gray-400',
};

export function WorkersTab() {
  const workers = useWorkers();

  return (
    <div className="space-y-4">
      {workers.isLoading ? (
        <Skeleton className="h-32" />
      ) : workers.data ? (
        <>
          <div className="grid grid-cols-3 gap-4">
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold text-green-600">{workers.data.total_active}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Active</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold text-yellow-600">{workers.data.total_idle}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Idle</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold text-red-600">{workers.data.total_error}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Error</p>
              </CardContent>
            </Card>
          </div>

          {workers.data.workers.length > 0 ? (
            <Card>
              <CardHeader><CardTitle className="text-sm">Worker Details</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {workers.data.workers.map((w) => (
                    <div key={w.worker_id} className="flex items-center justify-between rounded-md bg-[var(--muted)] p-3">
                      <div className="flex items-center gap-3">
                        <span className={`h-2.5 w-2.5 rounded-full ${workerStatusColor[w.status] ?? 'bg-gray-400'}`} />
                        <div>
                          <p className="text-sm font-medium">{w.worker_id.slice(0, 12)}</p>
                          <p className="text-xs text-[var(--muted-foreground)]">
                            {w.hostname ?? 'local'} {w.pid ? `(PID ${w.pid})` : ''}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-[var(--muted-foreground)]">
                        <span>Concurrency: {w.concurrency}/{w.target_concurrency}</span>
                        <span>{formatNumber(w.jobs_completed)} jobs</span>
                        <Badge variant={w.status === 'running' ? 'default' : w.status === 'error' ? 'destructive' : 'secondary'}>
                          {w.status}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-8 text-center text-sm text-[var(--muted-foreground)]">
                No workers currently registered. Workers register when they start processing jobs.
              </CardContent>
            </Card>
          )}
        </>
      ) : null}
    </div>
  );
}
