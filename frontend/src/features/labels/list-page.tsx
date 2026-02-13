import { useState } from 'react';
import { useNavigate } from 'react-router';
import { type ColumnDef } from '@tanstack/react-table';
import { RefreshCw } from 'lucide-react';
import { useLabels, useSyncLabels } from '@/api/hooks/use-labels.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { useUIStore } from '@/stores/ui-store.ts';
import type { Label } from '@/api/types.ts';

const columns: ColumnDef<Label, unknown>[] = [
  { accessorKey: 'name', header: 'Label', cell: ({ row }) => (
    <div className="flex items-center gap-2">
      <span
        className="h-3 w-3 rounded-full"
        style={{ backgroundColor: row.original.color }}
        aria-hidden="true"
      />
      <span className="font-medium">{row.original.name}</span>
    </div>
  )},
  { accessorKey: 'description', header: 'Description' },
  { accessorKey: 'priority', header: 'Priority', cell: ({ row }) => row.original.priority ?? '—' },
];

export function Component() {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const labels = useLabels(page + 1);
  const syncLabels = useSyncLabels();
  const addToast = useUIStore((s) => s.addToast);

  const handleSync = () => {
    syncLabels.mutate(undefined, {
      onSuccess: () => {
        addToast({ level: 'info', message: 'Label sync started' });
        navigate('/labels/sync');
      },
      onError: (err) => addToast({ level: 'error', message: err.message }),
    });
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Labels</h1>
        <Button onClick={handleSync} disabled={syncLabels.isPending}>
          <RefreshCw className={`mr-2 h-4 w-4 ${syncLabels.isPending ? 'animate-spin' : ''}`} />
          Sync Labels
        </Button>
      </div>

      <DataTable
        columns={columns}
        data={labels.data?.items ?? []}
        totalRows={labels.data?.total}
        pagination={{ pageIndex: page, pageSize: 50 }}
        onPaginationChange={(p) => setPage(p.pageIndex)}
        isLoading={labels.isLoading}
        emptyMessage="No labels configured"
        emptyDescription="Sync labels from your sensitivity label provider"
      />
    </div>
  );
}
