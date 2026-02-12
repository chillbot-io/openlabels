import { useState } from 'react';
import { useNavigate } from 'react-router';
import { type ColumnDef } from '@tanstack/react-table';
import { Plus } from 'lucide-react';
import { useScans, useCreateScan } from '@/api/hooks/use-scans.ts';
import { useTargets } from '@/api/hooks/use-targets.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { StatusBadge } from '@/components/status-badge.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog.tsx';
import { formatRelativeTime } from '@/lib/utils.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { ScanJob, Target } from '@/api/types.ts';
import type { ScanStatus } from '@/lib/constants.ts';

const columns: ColumnDef<ScanJob, unknown>[] = [
  { accessorKey: 'target_name', header: 'Target', cell: ({ row }) => row.original.target_name ?? '—' },
  { accessorKey: 'status', header: 'Status', cell: ({ row }) => <StatusBadge status={row.original.status as ScanStatus} /> },
  { accessorKey: 'files_scanned', header: 'Files Scanned' },
  { accessorKey: 'files_with_pii', header: 'With PII' },
  { accessorKey: 'created_at', header: 'Started', cell: ({ row }) => formatRelativeTime(row.original.created_at) },
];

export function Component() {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selectedTargets, setSelectedTargets] = useState<string[]>([]);
  const scans = useScans({ page: page + 1, page_size: 20 });
  const targets = useTargets();
  const createScan = useCreateScan();
  const addToast = useUIStore((s) => s.addToast);

  const handleCreate = () => {
    if (selectedTargets.length === 0) return;
    createScan.mutate({ target_ids: selectedTargets }, {
      onSuccess: () => {
        setDialogOpen(false);
        setSelectedTargets([]);
        addToast({ level: 'success', message: 'Scan started' });
      },
      onError: (err) => addToast({ level: 'error', message: err.message }),
    });
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Scans</h1>
        <Button onClick={() => setDialogOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> New Scan
        </Button>
      </div>

      <DataTable
        columns={columns}
        data={scans.data?.items ?? []}
        totalRows={scans.data?.total}
        pagination={{ pageIndex: page, pageSize: 20 }}
        onPaginationChange={(p) => setPage(p.pageIndex)}
        isLoading={scans.isLoading}
        emptyMessage="No scans yet"
        emptyDescription="Start a new scan to discover sensitive data"
        onRowClick={(scan) => navigate(`/scans/${scan.id}`)}
      />

      <Dialog open={dialogOpen} onOpenChange={(open) => { setDialogOpen(open); if (!open) setSelectedTargets([]); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Scan</DialogTitle>
            <DialogDescription>Select targets to scan for sensitive data.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2 max-h-64 overflow-y-auto" role="group" aria-label="Select scan targets">
            {(targets.data?.items ?? []).map((target: Target) => (
              <label key={target.id} className="flex items-center gap-2 rounded-md p-2 hover:bg-[var(--muted)]">
                <input
                  type="checkbox"
                  checked={selectedTargets.includes(target.id)}
                  onChange={(e) =>
                    setSelectedTargets((prev) =>
                      e.target.checked ? [...prev, target.id] : prev.filter((id) => id !== target.id),
                    )
                  }
                  className="rounded"
                />
                <span className="text-sm">{target.name}</span>
                <span className="text-xs text-[var(--muted-foreground)]">{target.adapter}</span>
              </label>
            ))}
          </div>
          <Button onClick={handleCreate} disabled={selectedTargets.length === 0 || createScan.isPending}>
            {createScan.isPending ? 'Starting...' : `Start Scan (${selectedTargets.length})`}
          </Button>
        </DialogContent>
      </Dialog>
    </div>
  );
}
