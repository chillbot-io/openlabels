import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router';
import { type ColumnDef } from '@tanstack/react-table';
import { Plus, Trash2, HeartPulse, Server } from 'lucide-react';
import { useTargets, useDeleteTarget } from '@/api/hooks/use-targets.ts';
import { useHealth } from '@/api/hooks/use-monitoring.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import { ConfirmDialog } from '@/components/confirm-dialog.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { ADAPTER_LABELS, type AdapterType } from '@/lib/constants.ts';
import { formatRelativeTime } from '@/lib/utils.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { Target } from '@/api/types.ts';

const staticColumns: ColumnDef<Target, unknown>[] = [
  { accessorKey: 'name', header: 'Name' },
  {
    accessorKey: 'adapter',
    header: 'Adapter',
    cell: ({ row }) => ADAPTER_LABELS[row.original.adapter as AdapterType] ?? row.original.adapter,
  },
  {
    accessorKey: 'enabled',
    header: 'Status',
    cell: ({ row }) => (
      <Badge variant={row.original.enabled ? 'default' : 'secondary'}>
        {row.original.enabled ? 'Enabled' : 'Disabled'}
      </Badge>
    ),
  },
  {
    accessorKey: 'created_at',
    header: 'Created',
    cell: ({ row }) => formatRelativeTime(row.original.created_at),
  },
];

function ResourceHealth() {
  const health = useHealth();

  if (health.isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full" />
        ))}
      </div>
    );
  }

  const data = health.data;
  if (!data) return <p className="text-sm text-[var(--muted-foreground)]">Unable to load health data.</p>;

  const components = [
    { name: 'API Server', status: data.api, detail: data.api_text },
    { name: 'Database', status: data.db, detail: data.db_text },
    { name: 'Job Queue', status: data.queue, detail: data.queue_text },
    { name: 'ML Engine', status: data.ml, detail: data.ml_text },
    { name: 'MIP Integration', status: data.mip, detail: data.mip_text },
    { name: 'OCR Engine', status: data.ocr, detail: data.ocr_text },
  ];

  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {components.map((c) => (
          <Card key={c.name}>
            <CardContent className="flex items-center gap-3 p-4">
              <div
                className={`h-3 w-3 shrink-0 rounded-full ${
                  c.status === 'healthy' ? 'bg-green-500' : c.status === 'degraded' ? 'bg-yellow-500' : 'bg-red-500'
                }`}
              />
              <div className="min-w-0">
                <p className="text-sm font-medium">{c.name}</p>
                <p className="truncate text-xs text-[var(--muted-foreground)]">{c.detail}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">System Metrics</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 sm:grid-cols-3">
            <div>
              <p className="text-xs text-[var(--muted-foreground)]">Scans Today</p>
              <p className="text-lg font-semibold">{data.scans_today}</p>
            </div>
            <div>
              <p className="text-xs text-[var(--muted-foreground)]">Files Processed</p>
              <p className="text-lg font-semibold">{data.files_processed}</p>
            </div>
            <div>
              <p className="text-xs text-[var(--muted-foreground)]">Success Rate</p>
              <p className="text-lg font-semibold">{(data.success_rate * 100).toFixed(1)}%</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export function Component() {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const [pendingDelete, setPendingDelete] = useState<Target | null>(null);
  const targets = useTargets(page + 1);
  const deleteTarget = useDeleteTarget();
  const addToast = useUIStore((s) => s.addToast);

  const columns = useMemo<ColumnDef<Target, unknown>[]>(
    () => [
      ...staticColumns,
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <Button
            variant="ghost"
            size="icon"
            aria-label={`Delete resource ${row.original.name}`}
            onClick={(e) => {
              e.stopPropagation();
              setPendingDelete(row.original);
            }}
          >
            <Trash2 className="h-4 w-4 text-red-500" />
          </Button>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Resources</h1>
      </div>

      <Tabs defaultValue="resources">
        <TabsList aria-label="Resources sections">
          <TabsTrigger value="resources">
            <Server className="mr-1.5 h-4 w-4" />
            Add Resources
          </TabsTrigger>
          <TabsTrigger value="health">
            <HeartPulse className="mr-1.5 h-4 w-4" />
            Resource Health
          </TabsTrigger>
        </TabsList>

        <TabsContent value="resources" className="mt-4">
          <div className="mb-4 flex justify-end">
            <Button onClick={() => navigate('/targets/new')}>
              <Plus className="mr-2 h-4 w-4" /> Add Resource
            </Button>
          </div>
          <DataTable
            columns={columns}
            data={targets.data?.items ?? []}
            totalRows={targets.data?.total}
            pagination={{ pageIndex: page, pageSize: 50 }}
            onPaginationChange={(p) => setPage(p.pageIndex)}
            isLoading={targets.isLoading}
            emptyMessage="No resources configured"
            emptyDescription="Add a resource to start scanning for sensitive data"
            onRowClick={(t) => navigate(`/targets/${t.id}`)}
          />
        </TabsContent>

        <TabsContent value="health" className="mt-4">
          <ResourceHealth />
        </TabsContent>
      </Tabs>

      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => {
          if (!open) setPendingDelete(null);
        }}
        title="Delete Resource"
        description={`Are you sure you want to delete "${pendingDelete?.name}"? This action cannot be undone.`}
        onConfirm={() => {
          if (!pendingDelete) return;
          deleteTarget.mutate(pendingDelete.id, {
            onSuccess: () => {
              addToast({ level: 'success', message: 'Resource deleted' });
              setPendingDelete(null);
            },
            onError: (err) => addToast({ level: 'error', message: err.message }),
          });
        }}
        isPending={deleteTarget.isPending}
      />
    </div>
  );
}
