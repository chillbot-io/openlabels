import { useState } from 'react';
import { type ColumnDef } from '@tanstack/react-table';
import { Plus, Trash2 } from 'lucide-react';
import { usePolicies, useCreatePolicy, useDeletePolicy } from '@/api/hooks/use-policies.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog.tsx';
import { useUIStore } from '@/stores/ui-store.ts';
import type { Policy } from '@/api/types.ts';

export function Component() {
  const [page, setPage] = useState(0);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const addToast = useUIStore((s) => s.addToast);

  const policies = usePolicies(page + 1);
  const createPolicy = useCreatePolicy();
  const deletePolicy = useDeletePolicy();

  const handleCreate = () => {
    createPolicy.mutate(
      { name, description, enabled: true, rules: [], framework: '', risk_level: '', priority: 0, config: {} },
      {
        onSuccess: () => {
          setDialogOpen(false);
          setName('');
          setDescription('');
          addToast({ level: 'success', message: 'Policy created' });
        },
        onError: (err) => addToast({ level: 'error', message: err.message }),
      },
    );
  };

  const columns: ColumnDef<Policy, unknown>[] = [
    { accessorKey: 'name', header: 'Name', cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { accessorKey: 'description', header: 'Description' },
    { accessorKey: 'enabled', header: 'Status', cell: ({ row }) => (
      <Badge variant={row.original.enabled ? 'default' : 'secondary'}>
        {row.original.enabled ? 'Active' : 'Disabled'}
      </Badge>
    )},
    { accessorKey: 'rules', header: 'Rules', cell: ({ row }) => `${row.original.rules?.length ?? 0} rules` },
    { id: 'actions', header: '', cell: ({ row }) => (
      <Button variant="ghost" size="icon" aria-label={`Delete policy ${row.original.name}`} onClick={(e) => {
        e.stopPropagation();
        if (confirm('Delete this policy?')) {
          deletePolicy.mutate(row.original.id, {
            onSuccess: () => addToast({ level: 'success', message: 'Policy deleted' }),
          });
        }
      }}>
        <Trash2 className="h-4 w-4 text-red-500" />
      </Button>
    )},
  ];

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Policies</h1>
        <Button onClick={() => setDialogOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> New Policy
        </Button>
      </div>

      <DataTable
        columns={columns}
        data={policies.data?.items ?? []}
        totalRows={policies.data?.total}
        pagination={{ pageIndex: page, pageSize: 50 }}
        onPaginationChange={(p) => setPage(p.pageIndex)}
        isLoading={policies.isLoading}
        emptyMessage="No policies configured"
        emptyDescription="Create a policy to define automated data protection rules"
      />

      <Dialog open={dialogOpen} onOpenChange={(open) => { setDialogOpen(open); if (!open) { setName(''); setDescription(''); } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Policy</DialogTitle>
            <DialogDescription>Create a data protection policy with automated rules.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="policy-name">Name</Label>
              <Input id="policy-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="PCI-DSS Compliance" />
            </div>
            <div>
              <Label htmlFor="policy-description">Description</Label>
              <Input id="policy-description" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Quarantine files with credit card numbers" />
            </div>
            <Button onClick={handleCreate} disabled={!name || createPolicy.isPending}>
              Create Policy
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
