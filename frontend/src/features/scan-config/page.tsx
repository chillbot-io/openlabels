import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router';
import { type ColumnDef } from '@tanstack/react-table';
import { Plus, Trash2, Settings2 } from 'lucide-react';
import { useSchedules, useDeleteSchedule } from '@/api/hooks/use-schedules.ts';
import { useSettings, useUpdateSettings } from '@/api/hooks/use-settings.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import { ConfirmDialog } from '@/components/confirm-dialog.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatRelativeTime } from '@/lib/utils.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { Schedule } from '@/api/types.ts';

const staticColumns: ColumnDef<Schedule, unknown>[] = [
  { accessorKey: 'name', header: 'Name' },
  {
    accessorKey: 'cron',
    header: 'Frequency',
    cell: ({ row }) => (
      <code className="rounded bg-[var(--muted)] px-1.5 py-0.5 text-xs">{row.original.cron ?? '—'}</code>
    ),
  },
  {
    accessorKey: 'enabled',
    header: 'Status',
    cell: ({ row }) => (
      <Badge variant={row.original.enabled ? 'default' : 'secondary'}>
        {row.original.enabled ? 'Active' : 'Disabled'}
      </Badge>
    ),
  },
  {
    accessorKey: 'next_run_at',
    header: 'Next Run',
    cell: ({ row }) => (row.original.next_run_at ? formatRelativeTime(row.original.next_run_at) : '—'),
  },
  {
    accessorKey: 'last_run_at',
    header: 'Last Run',
    cell: ({ row }) => (row.original.last_run_at ? formatRelativeTime(row.original.last_run_at) : 'Never'),
  },
];

function AdvancedSettings() {
  const settings = useSettings();
  const updateSettings = useUpdateSettings();
  const addToast = useUIStore((s) => s.addToast);

  const [fanoutEnabled, setFanoutEnabled] = useState<boolean | null>(null);
  const [fanoutThreshold, setFanoutThreshold] = useState('');
  const [fanoutMaxPartitions, setFanoutMaxPartitions] = useState('');
  const [maxConcurrentFiles, setMaxConcurrentFiles] = useState('');
  const [memoryBudgetMb, setMemoryBudgetMb] = useState('');

  const fanout = settings.data?.fanout;
  const isEnabled = fanoutEnabled ?? fanout?.fanout_enabled ?? false;
  const threshold = fanoutThreshold || String(fanout?.fanout_threshold ?? '');
  const maxPartitions = fanoutMaxPartitions || String(fanout?.fanout_max_partitions ?? '');
  const concurrentFiles = maxConcurrentFiles || String(fanout?.pipeline_max_concurrent_files ?? '');
  const memBudget = memoryBudgetMb || String(fanout?.pipeline_memory_budget_mb ?? '');

  if (settings.isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    );
  }

  const handleSave = () => {
    updateSettings.mutate(
      {
        category: 'fanout',
        settings: {
          fanout_enabled: isEnabled,
          fanout_threshold: Number(threshold),
          fanout_max_partitions: Number(maxPartitions),
          pipeline_max_concurrent_files: Number(concurrentFiles),
          pipeline_memory_budget_mb: Number(memBudget),
        },
      },
      {
        onSuccess: () => addToast({ level: 'success', message: 'Fanout settings updated' }),
        onError: (err) => addToast({ level: 'error', message: err.message }),
      },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Fanout Settings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={isEnabled}
            onChange={(e) => setFanoutEnabled(e.target.checked)}
            className="rounded"
          />
          <span className="text-sm">Enable fanout processing</span>
        </label>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <Label htmlFor="fanout-threshold">Fanout Threshold (files)</Label>
            <Input
              id="fanout-threshold"
              type="number"
              value={threshold}
              onChange={(e) => setFanoutThreshold(e.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="fanout-max-partitions">Max Partitions</Label>
            <Input
              id="fanout-max-partitions"
              type="number"
              value={maxPartitions}
              onChange={(e) => setFanoutMaxPartitions(e.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="fanout-concurrent">Max Concurrent Files</Label>
            <Input
              id="fanout-concurrent"
              type="number"
              value={concurrentFiles}
              onChange={(e) => setMaxConcurrentFiles(e.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="fanout-memory">Memory Budget (MB)</Label>
            <Input
              id="fanout-memory"
              type="number"
              value={memBudget}
              onChange={(e) => setMemoryBudgetMb(e.target.value)}
            />
          </div>
        </div>
        <Button onClick={handleSave} disabled={updateSettings.isPending}>
          {updateSettings.isPending ? 'Saving...' : 'Save'}
        </Button>
      </CardContent>
    </Card>
  );
}

export function Component() {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const [pendingDelete, setPendingDelete] = useState<Schedule | null>(null);
  const schedules = useSchedules(page + 1);
  const deleteSchedule = useDeleteSchedule();
  const addToast = useUIStore((s) => s.addToast);

  const columns = useMemo<ColumnDef<Schedule, unknown>[]>(
    () => [
      ...staticColumns,
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <Button
            variant="ghost"
            size="icon"
            aria-label={`Delete schedule ${row.original.name}`}
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
        <h1 className="text-2xl font-bold">Scan Configuration</h1>
      </div>

      <Tabs defaultValue="schedules">
        <TabsList aria-label="Scan configuration sections">
          <TabsTrigger value="schedules">
            Create Scan Schedule
          </TabsTrigger>
          <TabsTrigger value="advanced">
            <Settings2 className="mr-1.5 h-4 w-4" />
            Advanced
          </TabsTrigger>
        </TabsList>

        <TabsContent value="schedules" className="mt-4">
          <p className="mb-4 text-sm text-[var(--muted-foreground)]">
            Configure scan schedules to automatically scan resources on a recurring basis.
            Each schedule specifies a resource, frequency, and optional path/file-type exclusions.
          </p>
          <div className="mb-4 flex justify-end">
            <Button onClick={() => navigate('/scan-config/new')}>
              <Plus className="mr-2 h-4 w-4" /> Create Scan Schedule
            </Button>
          </div>
          <DataTable
            columns={columns}
            data={schedules.data?.items ?? []}
            totalRows={schedules.data?.total}
            pagination={{ pageIndex: page, pageSize: 50 }}
            onPaginationChange={(p) => setPage(p.pageIndex)}
            isLoading={schedules.isLoading}
            emptyMessage="No scan schedules configured"
            emptyDescription="Create a scan schedule to automate recurring scans"
            onRowClick={(s) => navigate(`/scan-config/${s.id}`)}
          />
        </TabsContent>

        <TabsContent value="advanced" className="mt-4">
          <AdvancedSettings />
        </TabsContent>
      </Tabs>

      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => {
          if (!open) setPendingDelete(null);
        }}
        title="Delete Schedule"
        description={`Are you sure you want to delete "${pendingDelete?.name}"? This action cannot be undone.`}
        onConfirm={() => {
          if (!pendingDelete) return;
          deleteSchedule.mutate(pendingDelete.id, {
            onSuccess: () => {
              addToast({ level: 'success', message: 'Schedule deleted' });
              setPendingDelete(null);
            },
            onError: (err) => addToast({ level: 'error', message: err.message }),
          });
        }}
        isPending={deleteSchedule.isPending}
      />
    </div>
  );
}
