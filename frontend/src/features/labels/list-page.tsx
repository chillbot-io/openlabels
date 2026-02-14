import { useState } from 'react';
import { useNavigate } from 'react-router';
import { type ColumnDef } from '@tanstack/react-table';
import { RefreshCw, Plus } from 'lucide-react';
import { useLabels, useSyncLabels } from '@/api/hooks/use-labels.ts';
import { useTargets } from '@/api/hooks/use-targets.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Label as FormLabel } from '@/components/ui/label.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.tsx';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog.tsx';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import { useUIStore } from '@/stores/ui-store.ts';
import { ENTITY_TYPES } from '@/lib/constants.ts';
import type { Label } from '@/api/types.ts';

const HEX_COLOR_RE = /^#[\da-fA-F]{3,8}$/;

function safeColor(color: string | null | undefined): string | undefined {
  if (!color) return undefined;
  return HEX_COLOR_RE.test(color) ? color : undefined;
}

const columns: ColumnDef<Label, unknown>[] = [
  { accessorKey: 'name', header: 'Label', cell: ({ row }) => (
    <div className="flex items-center gap-2">
      <span
        className="h-3 w-3 rounded-full"
        style={{ backgroundColor: safeColor(row.original.color) }}
        aria-hidden="true"
      />
      <span className="font-medium">{row.original.name}</span>
    </div>
  )},
  { accessorKey: 'description', header: 'Description' },
  { accessorKey: 'priority', header: 'Priority', cell: ({ row }) => row.original.priority ?? '—' },
];

function CreateLabelRuleDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const targets = useTargets();
  const labels = useLabels();
  const addToast = useUIStore((s) => s.addToast);
  const [selectedTargets, setSelectedTargets] = useState<string[]>([]);
  const [entityType, setEntityType] = useState('');
  const [labelId, setLabelId] = useState('');
  const [excludePaths, setExcludePaths] = useState('');

  const handleToggleTarget = (targetId: string) => {
    setSelectedTargets((prev) =>
      prev.includes(targetId) ? prev.filter((id) => id !== targetId) : [...prev, targetId],
    );
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedTargets.length === 0) {
      addToast({ level: 'error', message: 'Select at least one device' });
      return;
    }
    if (!entityType || !labelId) {
      addToast({ level: 'error', message: 'Select a classification type and label' });
      return;
    }
    addToast({ level: 'success', message: 'Label rule created' });
    setSelectedTargets([]);
    setEntityType('');
    setLabelId('');
    setExcludePaths('');
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Create Label Rule</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Select devices */}
          <div>
            <FormLabel>Select Device(s)</FormLabel>
            <div className="mt-1 max-h-40 space-y-1 overflow-y-auto rounded-md border p-2">
              {(targets.data?.items ?? []).length === 0 ? (
                <p className="py-2 text-center text-sm text-[var(--muted-foreground)]">
                  No resources configured
                </p>
              ) : (
                (targets.data?.items ?? []).map((t) => (
                  <label key={t.id} className="flex items-center gap-2 rounded px-2 py-1 hover:bg-[var(--muted)]">
                    <input
                      type="checkbox"
                      checked={selectedTargets.includes(t.id)}
                      onChange={() => handleToggleTarget(t.id)}
                      className="rounded"
                    />
                    <span className="text-sm">{t.name}</span>
                  </label>
                ))
              )}
            </div>
          </div>

          {/* Classification type / category → label */}
          <div>
            <FormLabel htmlFor="entity-type">Classification Type</FormLabel>
            <Select value={entityType} onValueChange={setEntityType}>
              <SelectTrigger id="entity-type">
                <SelectValue placeholder="Select classification type" />
              </SelectTrigger>
              <SelectContent>
                {ENTITY_TYPES.map((et) => (
                  <SelectItem key={et} value={et}>
                    {et.replace(/_/g, ' ')}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div>
            <FormLabel htmlFor="label-id">Associate Label</FormLabel>
            <Select value={labelId} onValueChange={setLabelId}>
              <SelectTrigger id="label-id">
                <SelectValue placeholder="Select label to apply" />
              </SelectTrigger>
              <SelectContent>
                {(labels.data?.items ?? []).map((l) => (
                  <SelectItem key={l.id} value={l.id}>
                    {l.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Exclude paths */}
          <div>
            <FormLabel htmlFor="rule-exclude-paths">Exclude Paths</FormLabel>
            <Input
              id="rule-exclude-paths"
              placeholder="/tmp,/var/log,*.bak"
              value={excludePaths}
              onChange={(e) => setExcludePaths(e.target.value)}
            />
            <p className="mt-1 text-xs text-[var(--muted-foreground)]">
              Comma-separated paths or patterns to exclude from this rule
            </p>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit">Create Rule</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function Component() {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const [showCreateRule, setShowCreateRule] = useState(false);
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
        <div className="flex gap-2">
          <Button variant="outline" onClick={handleSync} disabled={syncLabels.isPending}>
            <RefreshCw className={`mr-2 h-4 w-4 ${syncLabels.isPending ? 'animate-spin' : ''}`} />
            Sync Labels
          </Button>
          <Button onClick={() => setShowCreateRule(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Create Label Rule
          </Button>
        </div>
      </div>

      <Tabs defaultValue="labels">
        <TabsList aria-label="Labels sections">
          <TabsTrigger value="labels">Synced Labels</TabsTrigger>
          <TabsTrigger value="rules">Label Rules</TabsTrigger>
        </TabsList>

        <TabsContent value="labels" className="mt-4">
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
        </TabsContent>

        <TabsContent value="rules" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Label Rules</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-[var(--muted-foreground)]">
                Label rules automatically associate classification types with sensitivity labels for selected devices.
                Create a rule to define which labels should be applied based on detected data categories.
              </p>
              <div className="mt-4">
                <Button onClick={() => setShowCreateRule(true)}>
                  <Plus className="mr-2 h-4 w-4" />
                  Create Label Rule
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <CreateLabelRuleDialog open={showCreateRule} onOpenChange={setShowCreateRule} />
    </div>
  );
}
