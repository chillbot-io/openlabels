import { useState } from 'react';
import { useHealth, useJobQueue, useActivityLog } from '@/api/hooks/use-monitoring.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { StatusBadge } from '@/components/status-badge.tsx';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatRelativeTime, formatNumber } from '@/lib/utils.ts';
import type { ScanStatus } from '@/lib/constants.ts';

export function Component() {
  const health = useHealth();
  const jobQueue = useJobQueue();
  const [activityPage] = useState(1);
  const activity = useActivityLog({ page: activityPage, page_size: 20 });

  const healthColor = {
    healthy: 'bg-green-500',
    degraded: 'bg-yellow-500',
    unhealthy: 'bg-red-500',
  };

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
                  <span className={`h-4 w-4 rounded-full ${healthColor[health.data.status]}`} role="img" aria-label={`System status: ${health.data.status}`} />
                  <div>
                    <p className="text-lg font-semibold capitalize">{health.data.status}</p>
                    <p className="text-sm text-[var(--muted-foreground)]">
                      Uptime: {Math.floor(health.data.uptime_seconds / 3600)}h
                    </p>
                  </div>
                </CardContent>
              </Card>

              <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                {Object.entries(health.data.components).map(([name, comp]) => (
                  <Card key={name}>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-2">
                        <span className={`h-2.5 w-2.5 rounded-full ${healthColor[comp.status]}`} role="img" aria-label={`${name} status: ${comp.status}`} />
                        <p className="text-sm font-medium capitalize">{name}</p>
                      </div>
                      {comp.latency_ms !== undefined && (
                        <p className="mt-1 text-xs text-[var(--muted-foreground)]">{comp.latency_ms}ms</p>
                      )}
                      {comp.message && (
                        <p className="mt-1 text-xs text-[var(--muted-foreground)]">{comp.message}</p>
                      )}
                    </CardContent>
                  </Card>
                ))}
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
        </TabsContent>
      </Tabs>
    </div>
  );
}
