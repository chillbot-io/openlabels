import { useState } from 'react';
import { useNavigate } from 'react-router';
import { type ColumnDef } from '@tanstack/react-table';
import { Plus, Trash2 } from 'lucide-react';
import { useSchedules, useDeleteSchedule } from '@/api/hooks/use-schedules.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { formatDateTime } from '@/lib/date.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { Schedule } from '@/api/types.ts';

export function Component() {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const schedules = useSchedules(page + 1);
  const deleteSchedule = useDeleteSchedule();
  const addToast = useUIStore((s) => s.addToast);

  const columns: ColumnDef<Schedule, unknown>[] = [
    { accessorKey: 'name', header: 'Name' },
    { accessorKey: 'cron_expression', header: 'Schedule', cell: ({ row }) => (
      <code className="rounded bg-[var(--muted)] px-1.5 py-0.5 text-xs">{row.original.cron_expression}</code>
    )},
    { accessorKey: 'enabled', header: 'Status', cell: ({ row }) => (
      <Badge variant={row.original.enabled ? 'default' : 'secondary'}>
        {row.original.enabled ? 'Active' : 'Paused'}
      </Badge>
    )},
    { accessorKey: 'next_run_at', header: 'Next Run', cell: ({ row }) => formatDateTime(row.original.next_run_at) },
    { accessorKey: 'last_run_at', header: 'Last Run', cell: ({ row }) => formatDateTime(row.original.last_run_at) },
    { id: 'actions', header: '', cell: ({ row }) => (
      <Button
        variant="ghost"
        size="icon"
        onClick={(e) => {
          e.stopPropagation();
          if (confirm('Delete this schedule?')) {
            deleteSchedule.mutate(row.original.id, {
              onSuccess: () => addToast({ level: 'success', message: 'Schedule deleted' }),
            });
          }
        }}
      >
        <Trash2 className="h-4 w-4 text-red-500" />
      </Button>
    )},
  ];

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Schedules</h1>
        <Button onClick={() => navigate('/schedules/new')}>
          <Plus className="mr-2 h-4 w-4" /> New Schedule
        </Button>
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
    </div>
  );
}
