import { useHealth, useBackgroundTasks } from '@/api/hooks/use-monitoring.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatNumber } from '@/lib/utils.ts';

const healthColor: Record<string, string> = {
  healthy: 'bg-green-500',
  warning: 'bg-yellow-500',
  error: 'bg-red-500',
};

const HEALTH_COMPONENTS = ['db', 'queue', 'ml', 'mip', 'ocr'] as const;

const taskStatusColor: Record<string, string> = {
  running: 'text-green-600',
  starting: 'text-blue-600',
  stopped: 'text-gray-500',
  crashed: 'text-red-600',
  restarting: 'text-yellow-600',
  stopping: 'text-orange-600',
};

export function HealthTab() {
  const health = useHealth();
  const tasks = useBackgroundTasks();

  const overallStatus = health.data
    ? HEALTH_COMPONENTS.some((c) => health.data[c] === 'error')
      ? 'error'
      : HEALTH_COMPONENTS.some((c) => health.data[c] === 'warning')
        ? 'warning'
        : 'healthy'
    : 'healthy';

  return (
    <div className="space-y-4">
      {health.isLoading ? (
        <Skeleton className="h-32" />
      ) : health.data ? (
        <>
          <Card>
            <CardContent className="flex items-center gap-4 p-6">
              <span className={`h-4 w-4 rounded-full ${healthColor[overallStatus] ?? 'bg-gray-400'}`} role="img" aria-label={`System status: ${overallStatus}`} />
              <div>
                <p className="text-lg font-semibold capitalize">{overallStatus}</p>
                {health.data.uptime_seconds != null && (
                  <p className="text-sm text-[var(--muted-foreground)]">
                    Uptime: {Math.floor(health.data.uptime_seconds / 3600)}h {Math.floor((health.data.uptime_seconds % 3600) / 60)}m
                  </p>
                )}
              </div>
              {health.data.python_version && (
                <div className="ml-auto text-right text-xs text-[var(--muted-foreground)]">
                  <p>Python {health.data.python_version}</p>
                  <p>{health.data.platform}</p>
                </div>
              )}
            </CardContent>
          </Card>

          <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <span className={`h-2.5 w-2.5 rounded-full ${healthColor[health.data.api] ?? 'bg-gray-400'}`} />
                  <p className="text-sm font-medium uppercase">API</p>
                </div>
                <p className="mt-1 text-xs text-[var(--muted-foreground)]">{health.data.api_text}</p>
              </CardContent>
            </Card>
            {HEALTH_COMPONENTS.map((name) => (
              <Card key={name}>
                <CardContent className="p-4">
                  <div className="flex items-center gap-2">
                    <span className={`h-2.5 w-2.5 rounded-full ${healthColor[health.data[name]] ?? 'bg-gray-400'}`} />
                    <p className="text-sm font-medium uppercase">{name}</p>
                  </div>
                  <p className="mt-1 text-xs text-[var(--muted-foreground)]">{health.data[`${name}_text` as keyof typeof health.data] as string}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="grid grid-cols-3 gap-4">
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold">{formatNumber(health.data.scans_today)}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Scans Today</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold">{formatNumber(health.data.files_processed)}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Files Processed</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold">{health.data.success_rate.toFixed(1)}%</p>
                <p className="text-xs text-[var(--muted-foreground)]">Success Rate</p>
              </CardContent>
            </Card>
          </div>

          {health.data.db_pool && (
            <Card>
              <CardHeader><CardTitle className="text-sm">Database Pool</CardTitle></CardHeader>
              <CardContent>
                <div className="grid grid-cols-4 gap-4 text-center text-sm">
                  {Object.entries(health.data.db_pool as Record<string, number>).map(([key, val]) => (
                    <div key={key}>
                      <p className="font-bold">{val}</p>
                      <p className="text-xs text-[var(--muted-foreground)]">{key.replace(/_/g, ' ')}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </>
      ) : null}

      {/* Background Tasks */}
      {tasks.data && tasks.data.tasks.length > 0 && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm">Background Tasks</CardTitle>
              <Badge variant={tasks.data.healthy ? 'default' : 'destructive'}>
                {tasks.data.healthy ? 'Healthy' : 'Degraded'}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {tasks.data.tasks.map((t) => (
                <div key={t.name} className="flex items-center justify-between rounded-md bg-[var(--muted)] p-3">
                  <div className="flex items-center gap-3">
                    <span className={`text-sm font-medium ${taskStatusColor[t.status] ?? 'text-gray-500'}`}>
                      {t.status}
                    </span>
                    <p className="text-sm">{t.name}</p>
                  </div>
                  <div className="flex items-center gap-4 text-xs text-[var(--muted-foreground)]">
                    <span>{formatNumber(t.cycles_completed)} cycles</span>
                    {t.errors_total > 0 && (
                      <span className="text-red-500">{t.errors_total} errors</span>
                    )}
                    {t.uptime_seconds != null && (
                      <span>{Math.floor(t.uptime_seconds / 3600)}h up</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
