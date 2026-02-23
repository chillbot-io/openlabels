import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router';
import { type ColumnDef } from '@tanstack/react-table';
import { Plus, Trash2, CalendarPlus } from 'lucide-react';
import { useSchedules, useDeleteSchedule, useCreateBulkSchedules } from '@/api/hooks/use-schedules.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { ConfirmDialog } from '@/components/confirm-dialog.tsx';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog.tsx';
import { formatDateTime, describeCron } from '@/lib/date.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { Schedule } from '@/api/types.ts';

const CRON_PRESETS = [
  { label: 'Every night at 2 AM', value: '0 2 * * *' },
  { label: 'Weekly on Monday at 2 AM', value: '0 2 * * 1' },
  { label: 'Twice a week (Mon & Thu)', value: '0 3 * * 1,4' },
  { label: 'Daily at 6 AM', value: '0 6 * * *' },
  { label: 'Every 6 hours', value: '0 */6 * * *' },
] as const;

const staticColumns: ColumnDef<Schedule, unknown>[] = [
  { accessorKey: 'name', header: 'Name' },
  { accessorKey: 'cron', header: 'Schedule', cell: ({ row }) => (
    <code className="rounded bg-[var(--muted)] px-1.5 py-0.5 text-xs">{row.original.cron}</code>
  )},
  { accessorKey: 'enabled', header: 'Status', cell: ({ row }) => (
    <Badge variant={row.original.enabled ? 'default' : 'secondary'}>
      {row.original.enabled ? 'Active' : 'Paused'}
    </Badge>
  )},
  { accessorKey: 'next_run_at', header: 'Next Run', cell: ({ row }) => formatDateTime(row.original.next_run_at) },
  { accessorKey: 'last_run_at', header: 'Last Run', cell: ({ row }) => formatDateTime(row.original.last_run_at) },
];

export function Component() {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const [pendingDelete, setPendingDelete] = useState<Schedule | null>(null);
  const [bulkDialogOpen, setBulkDialogOpen] = useState(false);
  const [bulkCron, setBulkCron] = useState('0 2 * * 1');
  const schedules = useSchedules(page + 1);
  const deleteSchedule = useDeleteSchedule();
  const createBulkSchedules = useCreateBulkSchedules();
  const addToast = useUIStore((s) => s.addToast);

  const cronDescription = describeCron(bulkCron);

  const columns = useMemo<ColumnDef<Schedule, unknown>[]>(() => [
    ...staticColumns,
    { id: 'actions', header: '', cell: ({ row }) => (
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
    )},
  ], []);

  const handleBulkCreate = () => {
    createBulkSchedules.mutate({ cron: bulkCron, enabled: true }, {
      onSuccess: (created) => {
        setBulkDialogOpen(false);
        if (created.length > 0) {
          addToast({ level: 'success', message: `Created ${created.length} schedule${created.length > 1 ? 's' : ''}` });
        } else {
          addToast({ level: 'info', message: 'All targets already have schedules with this expression' });
        }
      },
      onError: (err) => addToast({ level: 'error', message: err.message }),
    });
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Schedules</h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setBulkDialogOpen(true)}>
            <CalendarPlus className="mr-2 h-4 w-4" /> Schedule All Targets
          </Button>
          <Button onClick={() => navigate('/schedules/new')}>
            <Plus className="mr-2 h-4 w-4" /> New Schedule
          </Button>
        </div>
      </div>

      <DataTable
        columns={columns}
        data={schedules.data?.items ?? []}
        totalRows={schedules.data?.total}
        pagination={{ pageIndex: page, pageSize: 50 }}
        onPaginationChange={(p) => setPage(p.pageIndex)}
        isLoading={schedules.isLoading}
        emptyMessage="No schedules configured"
        emptyDescription="Create a schedule to run scans automatically"
        onRowClick={(s) => navigate(`/schedules/${s.id}`)}
      />

      {/* Schedule All Targets dialog */}
      <Dialog open={bulkDialogOpen} onOpenChange={setBulkDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Schedule All Targets</DialogTitle>
            <DialogDescription>
              Create a recurring scan schedule for every enabled target. Targets that already
              have a schedule with the same expression will be skipped.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium" htmlFor="bulk-cron">Cron Expression</label>
              <Input
                id="bulk-cron"
                value={bulkCron}
                onChange={(e) => setBulkCron(e.target.value)}
                placeholder="0 2 * * 1"
              />
              <p className="mt-1 text-xs text-[var(--muted-foreground)]">{cronDescription.join(' | ')}</p>
            </div>

            <div className="space-y-1.5">
              <p className="text-sm font-medium">Quick presets</p>
              <div className="flex flex-wrap gap-1.5">
                {CRON_PRESETS.map((preset) => (
                  <button
                    key={preset.value}
                    type="button"
                    className={`rounded-full border px-2.5 py-1 text-xs transition-colors ${
                      bulkCron === preset.value
                        ? 'border-blue-500 bg-blue-50 text-blue-700'
                        : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                    }`}
                    onClick={() => setBulkCron(preset.value)}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={() => setBulkDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleBulkCreate} disabled={!bulkCron.trim() || createBulkSchedules.isPending}>
                {createBulkSchedules.isPending ? 'Creating...' : 'Schedule All'}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation */}
      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => { if (!open) setPendingDelete(null); }}
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
