import { useState } from 'react';
import { type ColumnDef } from '@tanstack/react-table';
import { Plus, Trash2 } from 'lucide-react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { policiesApi } from '@/api/endpoints/policies.ts';
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
  const queryClient = useQueryClient();

  const policies = useQuery({
    queryKey: ['policies', { page: page + 1 }],
    queryFn: () => policiesApi.list({ page: page + 1, page_size: 50 }),
  });

  const createPolicy = useMutation({
    mutationFn: policiesApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
      setDialogOpen(false);
      setName('');
      setDescription('');
      addToast({ level: 'success', message: 'Policy created' });
    },
  });

  const deletePolicy = useMutation({
    mutationFn: policiesApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
      addToast({ level: 'success', message: 'Policy deleted' });
    },
  });

  const columns: ColumnDef<Policy, unknown>[] = [
    { accessorKey: 'name', header: 'Name', cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { accessorKey: 'description', header: 'Description' },
    { accessorKey: 'enabled', header: 'Status', cell: ({ row }) => (
      <Badge variant={row.original.enabled ? 'default' : 'secondary'}>
        {row.original.enabled ? 'Active' : 'Disabled'}
      </Badge>
    )},
    { accessorKey: 'rules', header: 'Rules', cell: ({ row }) => `${row.original.rules.length} rules` },
    { id: 'actions', header: '', cell: ({ row }) => (
      <Button variant="ghost" size="icon" onClick={(e) => {
        e.stopPropagation();
        if (confirm('Delete this policy?')) deletePolicy.mutate(row.original.id);
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

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Policy</DialogTitle>
            <DialogDescription>Create a data protection policy with automated rules.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="PCI-DSS Compliance" />
            </div>
            <div>
              <Label>Description</Label>
              <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Quarantine files with credit card numbers" />
            </div>
            <Button
              onClick={() => createPolicy.mutate({ name, description, enabled: true, rules: [] })}
              disabled={!name || createPolicy.isPending}
            >
              Create Policy
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
