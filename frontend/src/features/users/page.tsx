import { useState, useMemo } from 'react';
import { type ColumnDef } from '@tanstack/react-table';
import { Plus, Trash2 } from 'lucide-react';
import { useUsers, useCreateUser, useDeleteUser } from '@/api/hooks/use-users.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label } from '@/components/ui/label.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.tsx';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog.tsx';
import { ConfirmDialog } from '@/components/confirm-dialog.tsx';
import { useAuthStore } from '@/stores/auth-store.ts';
import { useUIStore } from '@/stores/ui-store.ts';
import { formatRelativeTime } from '@/lib/utils.ts';
import type { User } from '@/api/types.ts';

const staticColumns: ColumnDef<User, unknown>[] = [
  { accessorKey: 'name', header: 'Name' },
  { accessorKey: 'email', header: 'Email' },
  {
    accessorKey: 'role',
    header: 'Role',
    cell: ({ row }) => (
      <Badge variant={row.original.role === 'admin' ? 'default' : 'secondary'}>
        {row.original.role}
      </Badge>
    ),
  },
  {
    accessorKey: 'created_at',
    header: 'Created',
    cell: ({ row }) => formatRelativeTime(row.original.created_at),
  },
];

function AddUserDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const createUser = useCreateUser();
  const addToast = useUIStore((s) => s.addToast);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<'admin' | 'user'>('user');
  const [authType, setAuthType] = useState<'local' | 'sso'>('local');
  const [password, setPassword] = useState('');

  const resetForm = () => {
    setName('');
    setEmail('');
    setRole('user');
    setAuthType('local');
    setPassword('');
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createUser.mutate(
      { name, email, role, auth_type: authType, ...(authType === 'local' ? { password } : {}) },
      {
        onSuccess: () => {
          addToast({ level: 'success', message: 'User created' });
          resetForm();
          onOpenChange(false);
        },
        onError: (err) => addToast({ level: 'error', message: err.message }),
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add User</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <Label htmlFor="user-name">Name</Label>
            <Input id="user-name" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div>
            <Label htmlFor="user-email">Email</Label>
            <Input id="user-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div>
            <Label htmlFor="auth-type">Authentication</Label>
            <Select value={authType} onValueChange={(v) => setAuthType(v as 'local' | 'sso')}>
              <SelectTrigger id="auth-type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="local">Local</SelectItem>
                <SelectItem value="sso">SSO</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {authType === 'local' && (
            <div>
              <Label htmlFor="user-password">Password</Label>
              <Input
                id="user-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
          )}
          <div>
            <Label htmlFor="user-role">Role</Label>
            <Select value={role} onValueChange={(v) => setRole(v as 'admin' | 'user')}>
              <SelectTrigger id="user-role">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="admin">Admin</SelectItem>
                <SelectItem value="user">User</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={createUser.isPending}>
              {createUser.isPending ? 'Creating...' : 'Create User'}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function Component() {
  const user = useAuthStore((s) => s.user);
  const isAdmin = user?.role === 'admin';
  const [page, setPage] = useState(0);
  const [showAdd, setShowAdd] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<User | null>(null);
  const users = useUsers(page + 1);
  const deleteUser = useDeleteUser();
  const addToast = useUIStore((s) => s.addToast);

  const columns = useMemo<ColumnDef<User, unknown>[]>(
    () =>
      isAdmin
        ? [
            ...staticColumns,
            {
              id: 'actions',
              header: '',
              cell: ({ row }) =>
                row.original.id !== user?.id ? (
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label={`Delete user ${row.original.name}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      setPendingDelete(row.original);
                    }}
                  >
                    <Trash2 className="h-4 w-4 text-red-500" />
                  </Button>
                ) : null,
            },
          ]
        : staticColumns,
    [isAdmin, user?.id],
  );

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Users</h1>
        {isAdmin && (
          <Button onClick={() => setShowAdd(true)}>
            <Plus className="mr-2 h-4 w-4" /> Add User
          </Button>
        )}
      </div>

      <DataTable
        columns={columns}
        data={users.data?.items ?? []}
        totalRows={users.data?.total}
        pagination={{ pageIndex: page, pageSize: 50 }}
        onPaginationChange={(p) => setPage(p.pageIndex)}
        isLoading={users.isLoading}
        emptyMessage="No users found"
        emptyDescription="Add a user to get started"
      />

      <AddUserDialog open={showAdd} onOpenChange={setShowAdd} />

      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => {
          if (!open) setPendingDelete(null);
        }}
        title="Delete User"
        description={`Are you sure you want to delete "${pendingDelete?.name}"? This action cannot be undone.`}
        onConfirm={() => {
          if (!pendingDelete) return;
          deleteUser.mutate(pendingDelete.id, {
            onSuccess: () => {
              addToast({ level: 'success', message: 'User deleted' });
              setPendingDelete(null);
            },
            onError: (err) => addToast({ level: 'error', message: err.message }),
          });
        }}
        isPending={deleteUser.isPending}
      />
    </div>
  );
}
