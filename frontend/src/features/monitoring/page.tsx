import { useState } from 'react';
import {
  useHealth,
  useJobQueue,
  useActivityLog,
  useSystemResources,
  useWorkers,
  useScanThroughput,
  useErrorLog,
  useBackgroundTasks,
  useSystemAlerts,
  useCreateSystemAlert,
  useDeleteSystemAlert,
} from '@/api/hooks/use-monitoring.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Progress } from '@/components/ui/progress.tsx';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatRelativeTime, formatNumber } from '@/lib/utils.ts';

const healthColor: Record<string, string> = {
  healthy: 'bg-green-500',
  warning: 'bg-yellow-500',
  error: 'bg-red-500',
};

const HEALTH_COMPONENTS = ['db', 'queue', 'ml', 'mip', 'ocr'] as const;

const severityColor: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  error: 'bg-red-500 text-white',
  warning: 'bg-yellow-500 text-black',
};

const workerStatusColor: Record<string, string> = {
  running: 'bg-green-500',
  idle: 'bg-yellow-500',
  error: 'bg-red-500',
  crashed: 'bg-red-500',
  stopped: 'bg-gray-400',
};

const taskStatusColor: Record<string, string> = {
  running: 'text-green-600',
  starting: 'text-blue-600',
  stopped: 'text-gray-500',
  crashed: 'text-red-600',
  restarting: 'text-yellow-600',
  stopping: 'text-orange-600',
};

// ── Helpers ──────────────────────────────────────────────────────────

function progressBarColor(percent: number): string {
  if (percent >= 90) return '[&>div>div]:bg-red-500';
  if (percent >= 70) return '[&>div>div]:bg-yellow-500';
  return '';
}

// ── Health Tab (existing, enhanced with Redis) ───────────────────────

function HealthTab() {
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

// ── Jobs Tab (enhanced with processing rate) ─────────────────────────

function JobsTab() {
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

// ── Workers Tab ──────────────────────────────────────────────────────

function WorkersTab() {
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

// ── Resources Tab ────────────────────────────────────────────────────

function ResourcesTab() {
  const resources = useSystemResources();

  return (
    <div className="space-y-4">
      {resources.isLoading ? (
        <Skeleton className="h-32" />
      ) : resources.data ? (
        <>
          <div className="grid grid-cols-3 gap-4">
            {/* CPU */}
            <Card>
              <CardHeader><CardTitle className="text-sm">CPU</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                <div className="text-center">
                  <p className="text-3xl font-bold">{resources.data.cpu_percent.toFixed(1)}%</p>
                  <p className="text-xs text-[var(--muted-foreground)]">{resources.data.cpu_count} cores</p>
                </div>
                <Progress value={resources.data.cpu_percent} className={progressBarColor(resources.data.cpu_percent)} />
                {resources.data.load_average && (
                  <p className="text-xs text-[var(--muted-foreground)] text-center">
                    Load: {resources.data.load_average.map((v) => v.toFixed(2)).join(' / ')}
                  </p>
                )}
              </CardContent>
            </Card>

            {/* Memory */}
            <Card>
              <CardHeader><CardTitle className="text-sm">Memory</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                <div className="text-center">
                  <p className="text-3xl font-bold">{resources.data.memory_percent.toFixed(1)}%</p>
                  <p className="text-xs text-[var(--muted-foreground)]">
                    {formatNumber(resources.data.memory_used_mb)} / {formatNumber(resources.data.memory_total_mb)} MB
                  </p>
                </div>
                <Progress value={resources.data.memory_percent} className={progressBarColor(resources.data.memory_percent)} />
              </CardContent>
            </Card>

            {/* Disk */}
            <Card>
              <CardHeader><CardTitle className="text-sm">Disk</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                <div className="text-center">
                  <p className="text-3xl font-bold">{resources.data.disk_percent.toFixed(1)}%</p>
                  <p className="text-xs text-[var(--muted-foreground)]">
                    {resources.data.disk_used_gb} / {resources.data.disk_total_gb} GB
                  </p>
                </div>
                <Progress value={resources.data.disk_percent} className={progressBarColor(resources.data.disk_percent)} />
                <p className="text-xs text-[var(--muted-foreground)] text-center">
                  {resources.data.disk_free_gb} GB free
                </p>
              </CardContent>
            </Card>
          </div>
        </>
      ) : null}
    </div>
  );
}

// ── Throughput Tab ───────────────────────────────────────────────────

function ThroughputTab() {
  const [hours, setHours] = useState(24);
  const throughput = useScanThroughput({ hours, bucket_size: hours <= 24 ? 1 : hours <= 72 ? 3 : 6 });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <span className="text-sm text-[var(--muted-foreground)]">Period:</span>
        {[24, 48, 72, 168].map((h) => (
          <Button key={h} variant={hours === h ? 'default' : 'outline'} size="sm" onClick={() => setHours(h)}>
            {h}h
          </Button>
        ))}
      </div>

      {throughput.isLoading ? (
        <Skeleton className="h-32" />
      ) : throughput.data ? (
        <>
          <div className="grid grid-cols-4 gap-4">
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold">{formatNumber(throughput.data.total_scans)}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Total Scans</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold">{formatNumber(throughput.data.total_files)}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Total Files</p>
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

          {/* Throughput timeline */}
          {throughput.data.buckets.length > 0 ? (
            <Card>
              <CardHeader><CardTitle className="text-sm">Throughput Timeline</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-1">
                  {throughput.data.buckets.map((b) => {
                    const maxFiles = Math.max(...throughput.data!.buckets.map((x) => x.files_scanned), 1);
                    const pct = Math.round((b.files_scanned / maxFiles) * 100);
                    return (
                      <div key={b.period} className="flex items-center gap-3">
                        <span className="w-32 shrink-0 text-xs text-[var(--muted-foreground)]">{b.period.slice(5)}</span>
                        <div className="flex-1">
                          <div className="h-4 rounded-sm bg-[var(--muted)]">
                            <div
                              className="h-full rounded-sm bg-primary-600 transition-all"
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                        </div>
                        <span className="w-20 shrink-0 text-right text-xs">
                          {formatNumber(b.files_scanned)} files
                        </span>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-8 text-center text-sm text-[var(--muted-foreground)]">
                No scans completed in the selected period.
              </CardContent>
            </Card>
          )}
        </>
      ) : null}
    </div>
  );
}

// ── Errors Tab ───────────────────────────────────────────────────────

function ErrorsTab() {
  const [source, setSource] = useState<string | undefined>();
  const [severity, setSeverity] = useState<string | undefined>();
  const [errorPage, setErrorPage] = useState(1);
  const errors = useErrorLog({ source, severity, page: errorPage, page_size: 30 });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <span className="text-sm text-[var(--muted-foreground)]">Source:</span>
        {[undefined, 'job', 'task', 'system'].map((s) => (
          <Button key={s ?? 'all'} variant={source === s ? 'default' : 'outline'} size="sm" onClick={() => { setSource(s); setErrorPage(1); }}>
            {s ?? 'All'}
          </Button>
        ))}
        <span className="ml-4 text-sm text-[var(--muted-foreground)]">Severity:</span>
        {[undefined, 'critical', 'error', 'warning'].map((s) => (
          <Button key={s ?? 'all'} variant={severity === s ? 'default' : 'outline'} size="sm" onClick={() => { setSeverity(s); setErrorPage(1); }}>
            {s ?? 'All'}
          </Button>
        ))}
      </div>

      <Card>
        <CardContent className="p-0">
          {errors.isLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
            </div>
          ) : errors.data && errors.data.entries.length > 0 ? (
            <div className="divide-y" role="list" aria-label="Error log entries">
              {errors.data.entries.map((entry) => (
                <div key={entry.id} className="px-4 py-3" role="listitem">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Badge className={severityColor[entry.severity] ?? 'bg-gray-500 text-white'}>
                        {entry.severity}
                      </Badge>
                      <Badge variant="secondary">{entry.source}</Badge>
                      <p className="text-sm font-medium">{entry.message}</p>
                    </div>
                    <span className="shrink-0 text-xs text-[var(--muted-foreground)]">
                      {formatRelativeTime(entry.timestamp)}
                    </span>
                  </div>
                  {entry.details && (
                    <div className="mt-1 flex gap-3 pl-8 text-xs text-[var(--muted-foreground)]">
                      {Object.entries(entry.details).map(([k, v]) => (
                        <span key={k}>{k}: {String(v)}</span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-sm text-[var(--muted-foreground)]">
              No errors found for the selected filters.
            </div>
          )}
        </CardContent>
      </Card>

      {errors.data && errors.data.total > 0 && (
        <div className="flex items-center justify-between">
          <span className="text-sm text-[var(--muted-foreground)]">{errors.data.total} total errors</span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={errorPage <= 1} onClick={() => setErrorPage((p) => p - 1)}>
              Previous
            </Button>
            <span className="flex items-center text-sm text-[var(--muted-foreground)]">Page {errorPage}</span>
            <Button variant="outline" size="sm" disabled={!errors.data.has_next} onClick={() => setErrorPage((p) => p + 1)}>
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Alerts Tab ───────────────────────────────────────────────────────

function AlertsTab() {
  const alerts = useSystemAlerts();
  const createAlert = useCreateSystemAlert();
  const deleteAlert = useDeleteSystemAlert();
  const [showForm, setShowForm] = useState(false);
  const [formName, setFormName] = useState('');
  const [formComponent, setFormComponent] = useState('db');
  const [formCondition, setFormCondition] = useState('unhealthy');
  const [formThreshold, setFormThreshold] = useState('');

  const handleCreate = () => {
    createAlert.mutate({
      name: formName,
      component: formComponent,
      condition: formCondition,
      threshold: formThreshold ? parseFloat(formThreshold) : undefined,
      actions: ['log', 'notify'],
    }, {
      onSuccess: () => {
        setShowForm(false);
        setFormName('');
        setFormThreshold('');
      },
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-[var(--muted-foreground)]">
          Configure alerts for system component failures and resource thresholds.
        </p>
        <Button size="sm" onClick={() => setShowForm(!showForm)}>
          {showForm ? 'Cancel' : 'Add Alert'}
        </Button>
      </div>

      {showForm && (
        <Card>
          <CardContent className="space-y-3 p-4">
            <div className="grid grid-cols-4 gap-3">
              <div>
                <label className="mb-1 block text-xs font-medium">Name</label>
                <Input value={formName} onChange={(e) => setFormName(e.target.value)} placeholder="Alert name" />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">Component</label>
                <select
                  className="h-9 w-full rounded-md border border-[var(--border)] bg-transparent px-3 text-sm"
                  value={formComponent}
                  onChange={(e) => setFormComponent(e.target.value)}
                >
                  {['api', 'db', 'queue', 'redis', 'worker', 'task', 'disk', 'memory', 'cpu'].map((c) => (
                    <option key={c} value={c}>{c.toUpperCase()}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">Condition</label>
                <select
                  className="h-9 w-full rounded-md border border-[var(--border)] bg-transparent px-3 text-sm"
                  value={formCondition}
                  onChange={(e) => setFormCondition(e.target.value)}
                >
                  <option value="unhealthy">Unhealthy</option>
                  <option value="threshold_exceeded">Threshold Exceeded</option>
                  <option value="offline">Offline</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">Threshold (%)</label>
                <div className="flex gap-2">
                  <Input
                    type="number"
                    value={formThreshold}
                    onChange={(e) => setFormThreshold(e.target.value)}
                    placeholder="e.g. 90"
                    disabled={formCondition !== 'threshold_exceeded'}
                  />
                  <Button size="sm" onClick={handleCreate} disabled={!formName || createAlert.isPending}>
                    {createAlert.isPending ? 'Creating...' : 'Create'}
                  </Button>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-0">
          {alerts.isLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
            </div>
          ) : alerts.data && alerts.data.length > 0 ? (
            <div className="divide-y" role="list" aria-label="System alert rules">
              {alerts.data.map((alert) => (
                <div key={alert.id} className="flex items-center justify-between px-4 py-3" role="listitem">
                  <div className="flex items-center gap-3">
                    <Badge variant={alert.enabled ? 'default' : 'secondary'}>
                      {alert.enabled ? 'Active' : 'Disabled'}
                    </Badge>
                    <div>
                      <p className="text-sm font-medium">{alert.name}</p>
                      <p className="text-xs text-[var(--muted-foreground)]">
                        {alert.component.toUpperCase()} &middot; {alert.condition}
                        {alert.threshold != null ? ` > ${alert.threshold}%` : ''}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-[var(--muted-foreground)]">
                      {alert.actions.join(', ')}
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => deleteAlert.mutate(alert.id)}
                      disabled={deleteAlert.isPending}
                    >
                      Delete
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-sm text-[var(--muted-foreground)]">
              No alert rules configured. Click "Add Alert" to create one.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── Activity Tab ─────────────────────────────────────────────────────

function ActivityTab() {
  const [activityPage, setActivityPage] = useState(1);
  const activity = useActivityLog({ page: activityPage, page_size: 20 });

  return (
    <div className="space-y-4">
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
    </div>
  );
}

// ── Main Page Component ──────────────────────────────────────────────

export function Component() {
  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-bold">System Monitoring</h1>

      <Tabs defaultValue="health">
        <TabsList aria-label="Monitoring views">
          <TabsTrigger value="health">Health</TabsTrigger>
          <TabsTrigger value="jobs">Jobs</TabsTrigger>
          <TabsTrigger value="workers">Workers</TabsTrigger>
          <TabsTrigger value="resources">Resources</TabsTrigger>
          <TabsTrigger value="throughput">Throughput</TabsTrigger>
          <TabsTrigger value="errors">Errors</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="activity">Activity</TabsTrigger>
        </TabsList>

        <TabsContent value="health" className="pt-4"><HealthTab /></TabsContent>
        <TabsContent value="jobs" className="pt-4"><JobsTab /></TabsContent>
        <TabsContent value="workers" className="pt-4"><WorkersTab /></TabsContent>
        <TabsContent value="resources" className="pt-4"><ResourcesTab /></TabsContent>
        <TabsContent value="throughput" className="pt-4"><ThroughputTab /></TabsContent>
        <TabsContent value="errors" className="pt-4"><ErrorsTab /></TabsContent>
        <TabsContent value="alerts" className="pt-4"><AlertsTab /></TabsContent>
        <TabsContent value="activity" className="pt-4"><ActivityTab /></TabsContent>
      </Tabs>
    </div>
  );
}
