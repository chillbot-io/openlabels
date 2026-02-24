import { useState } from 'react';
import { useNavigate, useParams } from 'react-router';
import { type ColumnDef } from '@tanstack/react-table';
import {
  ArrowLeft, Edit, Wifi, Loader2, CheckCircle2, AlertCircle,
  Play, Clock,
} from 'lucide-react';
import { useTarget, useTestConnection } from '@/api/hooks/use-targets.ts';
import { useScans } from '@/api/hooks/use-scans.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { ADAPTER_LABELS, type AdapterType } from '@/lib/constants.ts';
import { formatRelativeTime } from '@/lib/utils.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { ScanJob } from '@/api/types.ts';

const STATUS_VARIANTS: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  completed: 'default',
  running: 'secondary',
  pending: 'outline',
  failed: 'destructive',
  cancelled: 'outline',
};

const scanColumns: ColumnDef<ScanJob, unknown>[] = [
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) => (
      <Badge variant={STATUS_VARIANTS[row.original.status] ?? 'outline'}>
        {row.original.status}
      </Badge>
    ),
  },
  {
    accessorKey: 'files_scanned',
    header: 'Files Scanned',
  },
  {
    accessorKey: 'files_with_pii',
    header: 'Files w/ PII',
  },
  {
    accessorKey: 'created_at',
    header: 'Started',
    cell: ({ row }) => formatRelativeTime(row.original.created_at),
  },
  {
    accessorKey: 'completed_at',
    header: 'Completed',
    cell: ({ row }) =>
      row.original.completed_at ? formatRelativeTime(row.original.completed_at) : '—',
  },
];

export function Component() {
  const { targetId } = useParams<{ targetId: string }>();
  const navigate = useNavigate();
  const addToast = useUIStore((s) => s.addToast);
  const target = useTarget(targetId ?? '');
  const testConnection = useTestConnection();
  const [scanPage, setScanPage] = useState(0);
  const scans = useScans({ target_id: targetId, page: scanPage + 1, page_size: 10 });

  if (!targetId) return null;
  if (target.isLoading) return <LoadingSkeleton />;
  if (target.error || !target.data) {
    return (
      <div className="p-6">
        <p className="text-red-500">Failed to load target.</p>
        <Button variant="outline" className="mt-4" onClick={() => navigate('/targets')}>
          <ArrowLeft className="mr-2 h-4 w-4" /> Back to Targets
        </Button>
      </div>
    );
  }

  const t = target.data;
  const scanItems = scans.data?.items ?? [];

  // Compute stats from recent scans
  const totalScans = scans.data?.total ?? 0;
  const completedScans = scanItems.filter((s) => s.status === 'completed').length;
  const totalFilesScanned = scanItems.reduce((sum, s) => sum + s.files_scanned, 0);
  const totalFilesWithPii = scanItems.reduce((sum, s) => sum + s.files_with_pii, 0);
  const lastScan = scanItems.length > 0 ? scanItems[0] : null;

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={() => navigate('/targets')}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold">{t.name}</h1>
            <div className="flex items-center gap-2 text-sm text-[var(--muted-foreground)]">
              <span>{ADAPTER_LABELS[t.adapter as AdapterType] ?? t.adapter}</span>
              <span>&middot;</span>
              <Badge variant={t.enabled ? 'default' : 'secondary'}>
                {t.enabled ? 'Enabled' : 'Disabled'}
              </Badge>
            </div>
          </div>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            disabled={testConnection.isPending}
            onClick={() => {
              testConnection.mutate(targetId, {
                onSuccess: (result) => {
                  if (result.success) {
                    addToast({ level: 'success', message: `Connection OK (${result.latency_ms}ms)` });
                  } else {
                    addToast({ level: 'error', message: result.error ?? 'Connection test failed' });
                  }
                },
                onError: (err) => addToast({ level: 'error', message: err.message }),
              });
            }}
          >
            {testConnection.isPending ? (
              <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Testing...</>
            ) : (
              <><Wifi className="mr-2 h-4 w-4" />Test Connection</>
            )}
          </Button>
          <Button onClick={() => navigate(`/targets/${targetId}/edit`)}>
            <Edit className="mr-2 h-4 w-4" /> Edit
          </Button>
        </div>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Play className="h-5 w-5 text-[var(--muted-foreground)]" />
              <div>
                <p className="text-2xl font-bold">{totalScans}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Total Scans</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <CheckCircle2 className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-2xl font-bold">{completedScans}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Completed (this page)</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <AlertCircle className="h-5 w-5 text-orange-500" />
              <div>
                <p className="text-2xl font-bold">{totalFilesWithPii}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Files w/ PII (this page)</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Clock className="h-5 w-5 text-[var(--muted-foreground)]" />
              <div>
                <p className="text-sm font-medium">
                  {lastScan ? formatRelativeTime(lastScan.created_at) : 'Never'}
                </p>
                <p className="text-xs text-[var(--muted-foreground)]">Last Scan</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Configuration */}
      <Card>
        <CardHeader><CardTitle>Configuration</CardTitle></CardHeader>
        <CardContent>
          <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
            <div>
              <dt className="font-medium text-[var(--muted-foreground)]">Adapter</dt>
              <dd>{ADAPTER_LABELS[t.adapter as AdapterType] ?? t.adapter}</dd>
            </div>
            <div>
              <dt className="font-medium text-[var(--muted-foreground)]">Created</dt>
              <dd>{t.created_at ? formatRelativeTime(t.created_at) : '—'}</dd>
            </div>
            {t.config.path && (
              <div className="sm:col-span-2">
                <dt className="font-medium text-[var(--muted-foreground)]">Path</dt>
                <dd className="font-mono text-xs">{String(t.config.path)}</dd>
              </div>
            )}
            {t.config.site_url && (
              <div className="sm:col-span-2">
                <dt className="font-medium text-[var(--muted-foreground)]">Site URL</dt>
                <dd className="font-mono text-xs">{String(t.config.site_url)}</dd>
              </div>
            )}
            {t.config.bucket && (
              <div>
                <dt className="font-medium text-[var(--muted-foreground)]">Bucket</dt>
                <dd className="font-mono text-xs">{String(t.config.bucket)}</dd>
              </div>
            )}
            {t.config.container && (
              <div>
                <dt className="font-medium text-[var(--muted-foreground)]">Container</dt>
                <dd className="font-mono text-xs">{String(t.config.container)}</dd>
              </div>
            )}
            {t.config.extensions && (
              <div>
                <dt className="font-medium text-[var(--muted-foreground)]">File Extensions</dt>
                <dd>{String(t.config.extensions)}</dd>
              </div>
            )}
            {t.config.exclude_patterns && (
              <div>
                <dt className="font-medium text-[var(--muted-foreground)]">Exclude Patterns</dt>
                <dd>{String(t.config.exclude_patterns)}</dd>
              </div>
            )}
          </dl>
        </CardContent>
      </Card>

      {/* Scan History */}
      <Card>
        <CardHeader><CardTitle>Scan History</CardTitle></CardHeader>
        <CardContent>
          <DataTable
            columns={scanColumns}
            data={scanItems}
            totalRows={scans.data?.total}
            pagination={{ pageIndex: scanPage, pageSize: 10 }}
            onPaginationChange={(p) => setScanPage(p.pageIndex)}
            isLoading={scans.isLoading}
            emptyMessage="No scans yet"
            emptyDescription="Start a scan from the Scans page to see history here"
            onRowClick={(scan) => navigate(`/scans/${scan.id}`)}
          />
        </CardContent>
      </Card>
    </div>
  );
}
