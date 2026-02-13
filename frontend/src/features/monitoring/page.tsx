import { useState } from 'react';
import { useHealth, useJobQueue, useActivityLog } from '@/api/hooks/use-monitoring.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatRelativeTime, formatNumber } from '@/lib/utils.ts';

const healthColor: Record<string, string> = {
  healthy: 'bg-green-500',
  warning: 'bg-yellow-500',
  error: 'bg-red-500',
};

const HEALTH_COMPONENTS = ['db', 'queue', 'ml', 'mip', 'ocr'] as const;

export function Component() {
  const health = useHealth();
  const jobQueue = useJobQueue();
  const [activityPage, setActivityPage] = useState(1);
  const activity = useActivityLog({ page: activityPage, page_size: 20 });

  // Derive overall status from component statuses
  const overallStatus = health.data
    ? HEALTH_COMPONENTS.some((c) => health.data[c] === 'error')
      ? 'error'
      : HEALTH_COMPONENTS.some((c) => health.data[c] === 'warning')
        ? 'warning'
        : 'healthy'
    : 'healthy';

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-bold">Monitoring</h1>

      <Tabs defaultValue="health">
        <TabsList aria-label="Monitoring views">
          <TabsTrigger value="health">System Health</TabsTrigger>
          <TabsTrigger value="jobs">Job Queue</TabsTrigger>
          <TabsTrigger value="activity">Activity Log</TabsTrigger>
        </TabsList>

        <TabsContent value="health" className="space-y-4 pt-4">
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
                        Uptime: {Math.floor(health.data.uptime_seconds / 3600)}h
                      </p>
                    )}
                  </div>
                </CardContent>
              </Card>

              <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
                {HEALTH_COMPONENTS.map((name) => (
                  <Card key={name}>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-2">
                        <span className={`h-2.5 w-2.5 rounded-full ${healthColor[health.data[name]] ?? 'bg-gray-400'}`} role="img" aria-label={`${name} status: ${health.data[name]}`} />
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
            </>
          ) : null}
        </TabsContent>

        <TabsContent value="jobs" className="space-y-4 pt-4">
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
        </TabsContent>

        <TabsContent value="activity" className="space-y-4 pt-4">
          <Card>
            <CardContent className="p-0">
              {activity.isLoading ? (
                <div className="space-y-2 p-4">
                  {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
                </div>
              ) : (
                <div className="divide-y" role="list" aria-label="Activity log entries">
                  {(activity.data?.items ?? []).map((entry) => (
                    <div key={entry.id} className="flex items-center justify-between px-4 py-3" role="listitem">
                      <div>
                        <p className="text-sm font-medium">{entry.action}</p>
                        <p className="text-xs text-[var(--muted-foreground)]">
                          {entry.user_email ?? 'system'} &middot; {entry.resource_type}
                          {entry.resource_id ? ` #${entry.resource_id.slice(0, 8)}` : ''}
                        </p>
                      </div>
                      <span className="text-xs text-[var(--muted-foreground)]">
                        {formatRelativeTime(entry.created_at)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
          {activity.data && (
            <div className="flex justify-center gap-2">
              <Button variant="outline" size="sm" disabled={activityPage <= 1} onClick={() => setActivityPage((p) => p - 1)}>
                Previous
              </Button>
              <span className="flex items-center text-sm text-[var(--muted-foreground)]">Page {activityPage}</span>
              <Button variant="outline" size="sm" disabled={!activity.data.has_next} onClick={() => setActivityPage((p) => p + 1)}>
                Next
              </Button>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
