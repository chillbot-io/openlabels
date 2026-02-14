import { useState } from 'react';
import { useNavigate } from 'react-router';
import { type ColumnDef } from '@tanstack/react-table';
import { Plus } from 'lucide-react';
import { useScans, useCreateScans } from '@/api/hooks/use-scans.ts';
import { useTargets } from '@/api/hooks/use-targets.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { StatusBadge } from '@/components/status-badge.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.tsx';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog.tsx';
import { formatRelativeTime } from '@/lib/utils.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { ScanJob } from '@/api/types.ts';
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
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [scanName, setScanName] = useState('');
  const scans = useScans({ page: page + 1, page_size: 20 });
  const targets = useTargets();
  const createScan = useCreateScans();
  const addToast = useUIStore((s) => s.addToast);

  const handleCreate = () => {
    if (!selectedTargetId) return;
    createScan.mutate([selectedTargetId], {
      onSuccess: (results) => {
        setDialogOpen(false);
        setSelectedTargetId('');
        setScanName('');
        addToast({ level: 'success', message: 'Scan started' });
        if (results.length > 0) {
          navigate(`/scans/${results[0].id}`);
        }
      },
      onError: (err) => addToast({ level: 'error', message: err.message }),
    });
  };

  const resetDialog = () => {
    setSelectedTargetId('');
    setScanName('');
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

      <Dialog open={dialogOpen} onOpenChange={(open) => { setDialogOpen(open); if (!open) resetDialog(); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Scan</DialogTitle>
            <DialogDescription>Select a target to scan for sensitive data.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium" htmlFor="scan-target">Target *</label>
              <Select value={selectedTargetId} onValueChange={setSelectedTargetId}>
                <SelectTrigger id="scan-target">
                  <SelectValue placeholder="Select a target" />
                </SelectTrigger>
                <SelectContent>
                  {(targets.data?.items ?? []).map((target) => (
                    <SelectItem key={target.id} value={target.id}>
                      {target.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium" htmlFor="scan-name">Scan Name (optional)</label>
              <Input
                id="scan-name"
                value={scanName}
                onChange={(e) => setScanName(e.target.value)}
                placeholder="Q1 2025 Audit"
              />
              <p className="mt-1 text-xs text-[var(--muted-foreground)]">Leave blank for auto-generated name</p>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={() => { setDialogOpen(false); resetDialog(); }}>
                Cancel
              </Button>
              <Button onClick={handleCreate} disabled={!selectedTargetId || createScan.isPending}>
                {createScan.isPending ? 'Starting...' : 'Start Scan'}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
