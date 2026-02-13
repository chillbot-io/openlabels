import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router';
import { type ColumnDef } from '@tanstack/react-table';
import { Plus, Trash2 } from 'lucide-react';
import { useTargets, useDeleteTarget } from '@/api/hooks/use-targets.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { ConfirmDialog } from '@/components/confirm-dialog.tsx';
import { ADAPTER_LABELS, type AdapterType } from '@/lib/constants.ts';
import { formatRelativeTime } from '@/lib/utils.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { Target } from '@/api/types.ts';

const staticColumns: ColumnDef<Target, unknown>[] = [
  { accessorKey: 'name', header: 'Name' },
  { accessorKey: 'adapter', header: 'Adapter', cell: ({ row }) =>
    ADAPTER_LABELS[row.original.adapter as AdapterType] ?? row.original.adapter },
  { accessorKey: 'enabled', header: 'Status', cell: ({ row }) => (
    <Badge variant={row.original.enabled ? 'default' : 'secondary'}>
      {row.original.enabled ? 'Enabled' : 'Disabled'}
    </Badge>
  )},
  { accessorKey: 'created_at', header: 'Created', cell: ({ row }) => formatRelativeTime(row.original.created_at) },
];

export function Component() {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const [pendingDelete, setPendingDelete] = useState<Target | null>(null);
  const targets = useTargets(page + 1);
  const deleteTarget = useDeleteTarget();
  const addToast = useUIStore((s) => s.addToast);

  const columns = useMemo<ColumnDef<Target, unknown>[]>(() => [
    ...staticColumns,
    { id: 'actions', header: '', cell: ({ row }) => (
      <Button
        variant="ghost"
        size="icon"
        aria-label={`Delete target ${row.original.name}`}
        onClick={(e) => {
          e.stopPropagation();
          setPendingDelete(row.original);
        }}
      >
        <Trash2 className="h-4 w-4 text-red-500" />
      </Button>
    )},
  ], []);

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Targets</h1>
        <Button onClick={() => navigate('/targets/new')}>
          <Plus className="mr-2 h-4 w-4" /> Add Target
        </Button>
      </div>

      <DataTable
        columns={columns}
        data={targets.data?.items ?? []}
        totalRows={targets.data?.total}
        pagination={{ pageIndex: page, pageSize: 50 }}
        onPaginationChange={(p) => setPage(p.pageIndex)}
        isLoading={targets.isLoading}
        emptyMessage="No targets configured"
        emptyDescription="Add a target to scan for sensitive data"
        onRowClick={(t) => navigate(`/targets/${t.id}`)}
      />

      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => { if (!open) setPendingDelete(null); }}
        title="Delete Target"
        description={`Are you sure you want to delete "${pendingDelete?.name}"? This action cannot be undone.`}
        onConfirm={() => {
          if (!pendingDelete) return;
          deleteTarget.mutate(pendingDelete.id, {
            onSuccess: () => {
              addToast({ level: 'success', message: 'Target deleted' });
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
