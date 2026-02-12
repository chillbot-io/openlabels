import { useState } from 'react';
import { type ColumnDef } from '@tanstack/react-table';
import { useRemediationActions, useQuarantine, useLockdown, useRollback } from '@/api/hooks/use-remediation.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { StatusBadge } from '@/components/status-badge.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { formatDateTime } from '@/lib/date.ts';
import { truncatePath } from '@/lib/utils.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import type { RemediationAction as RemAction } from '@/api/types.ts';
import type { ScanStatus } from '@/lib/constants.ts';

const columns: ColumnDef<RemAction, unknown>[] = [
  { accessorKey: 'file_path', header: 'File', cell: ({ row }) => (
    <span className="font-mono text-xs">{truncatePath(row.original.file_path)}</span>
  )},
  { accessorKey: 'action_type', header: 'Action', cell: ({ row }) => (
    <Badge variant="outline" className="capitalize">{row.original.action_type}</Badge>
  )},
  { accessorKey: 'status', header: 'Status', cell: ({ row }) => (
    <StatusBadge status={row.original.status as ScanStatus} />
  )},
  { accessorKey: 'performed_by', header: 'By' },
  { accessorKey: 'dry_run', header: 'Dry Run', cell: ({ row }) => row.original.dry_run ? 'Yes' : 'No' },
  { accessorKey: 'created_at', header: 'Date', cell: ({ row }) => formatDateTime(row.original.created_at) },
];

type DialogType = 'quarantine' | 'lockdown' | null;

export function Component() {
  const [page, setPage] = useState(0);
  const [dialog, setDialog] = useState<DialogType>(null);
  const [filePath, setFilePath] = useState('');
  const [principals, setPrincipals] = useState('');
  const [dryRun, setDryRun] = useState(false);

  const actions = useRemediationActions({ page: page + 1 });
  const quarantine = useQuarantine();
  const lockdown = useLockdown();
  const rollback = useRollback();
  const addToast = useUIStore((s) => s.addToast);

  const handleQuarantine = () => {
    quarantine.mutate({ file_path: filePath, dry_run: dryRun }, {
      onSuccess: () => { addToast({ level: 'success', message: 'Quarantine initiated' }); setDialog(null); },
      onError: (err) => addToast({ level: 'error', message: err.message }),
    });
  };

  const handleLockdown = () => {
    lockdown.mutate({ file_path: filePath, principals: principals.split(',').map((p) => p.trim()).filter(Boolean), dry_run: dryRun }, {
      onSuccess: () => { addToast({ level: 'success', message: 'Lockdown initiated' }); setDialog(null); },
      onError: (err) => addToast({ level: 'error', message: err.message }),
    });
  };

  const handleRollback = (actionId: string) => {
    rollback.mutate(actionId, {
      onSuccess: () => addToast({ level: 'success', message: 'Rollback initiated' }),
      onError: (err) => addToast({ level: 'error', message: err.message }),
    });
  };

  const columnsWithActions: ColumnDef<RemAction, unknown>[] = [
    ...columns,
    {
      id: 'actions',
      header: '',
      cell: ({ row }) =>
        (row.original.status === 'completed' && row.original.action_type !== 'rollback') ? (
          <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); handleRollback(row.original.id); }}>
            Rollback
          </Button>
        ) : null,
    },
  ];

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Remediation</h1>
        <div className="flex gap-2">
          <Button onClick={() => setDialog('quarantine')}>Quarantine</Button>
          <Button variant="outline" onClick={() => setDialog('lockdown')}>Lockdown</Button>
        </div>
      </div>

      <DataTable
        columns={columnsWithActions}
        data={actions.data?.items ?? []}
        totalRows={actions.data?.total}
        pagination={{ pageIndex: page, pageSize: 20 }}
        onPaginationChange={(p) => setPage(p.pageIndex)}
        isLoading={actions.isLoading}
        emptyMessage="No remediation actions"
        emptyDescription="Use quarantine or lockdown to protect sensitive files"
      />

      <Dialog open={dialog !== null} onOpenChange={() => setDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="capitalize">{dialog}</DialogTitle>
            <DialogDescription>
              {dialog === 'quarantine'
                ? 'Move a file to a secure quarantine location.'
                : 'Restrict file permissions to specific principals.'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>File Path</Label>
              <Input value={filePath} onChange={(e) => setFilePath(e.target.value)} placeholder="C:\Shares\sensitive-file.xlsx" />
            </div>
            {dialog === 'lockdown' && (
              <div>
                <Label>Principals (comma-separated)</Label>
                <Input value={principals} onChange={(e) => setPrincipals(e.target.value)} placeholder="DOMAIN\admin,DOMAIN\security-team" />
              </div>
            )}
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} className="rounded" />
              <span className="text-sm">Dry run (preview only)</span>
            </label>
            <Button
              onClick={dialog === 'quarantine' ? handleQuarantine : handleLockdown}
              disabled={!filePath || quarantine.isPending || lockdown.isPending}
            >
              {quarantine.isPending || lockdown.isPending ? 'Processing...' : `Execute ${dialog}`}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
