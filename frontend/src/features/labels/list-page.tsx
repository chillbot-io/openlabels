import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router';
import { type ColumnDef } from '@tanstack/react-table';
import { RefreshCw, Plus, Trash2, BarChart3 } from 'lucide-react';
import {
  useLabels,
  useSyncLabels,
  useLabelRules,
  useCreateLabelRule,
  useDeleteLabelRule,
  useLabelMappings,
  useUpdateLabelMappings,
  useLabelStats,
} from '@/api/hooks/use-labels.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Label as FormLabel } from '@/components/ui/label.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.tsx';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog.tsx';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import { useUIStore } from '@/stores/ui-store.ts';
import { ENTITY_TYPES, RISK_TIERS, RISK_COLORS, type RiskTier } from '@/lib/constants.ts';
import type { Label, LabelRule } from '@/api/types.ts';

const HEX_COLOR_RE = /^#[\da-fA-F]{3,8}$/;

function safeColor(color: string | null | undefined): string | undefined {
  if (!color) return undefined;
  return HEX_COLOR_RE.test(color) ? color : undefined;
}

const labelColumns: ColumnDef<Label, unknown>[] = [
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

/* ── Create Label Rule Dialog ── */
function CreateLabelRuleDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const labels = useLabels();
  const createRule = useCreateLabelRule();
  const addToast = useUIStore((s) => s.addToast);
  const [ruleType, setRuleType] = useState<string>('entity_type');
  const [matchValue, setMatchValue] = useState('');
  const [labelId, setLabelId] = useState('');

  const RISK_TIER_VALUES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'MINIMAL'] as const;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!matchValue || !labelId) {
      addToast({ level: 'error', message: 'Select a match value and label' });
      return;
    }
    createRule.mutate(
      { rule_type: ruleType, match_value: matchValue, label_id: labelId },
      {
        onSuccess: () => {
          addToast({ level: 'success', message: 'Label rule created' });
          setMatchValue('');
          setLabelId('');
          onOpenChange(false);
        },
        onError: (err) => addToast({ level: 'error', message: err.message }),
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Create Label Rule</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <FormLabel htmlFor="rule-type">Rule Type</FormLabel>
            <Select value={ruleType} onValueChange={(v) => { setRuleType(v); setMatchValue(''); }}>
              <SelectTrigger id="rule-type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="entity_type">Entity Type</SelectItem>
                <SelectItem value="risk_tier">Risk Tier</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div>
            <FormLabel htmlFor="match-value">
              {ruleType === 'entity_type' ? 'Entity Type' : 'Risk Tier'}
            </FormLabel>
            <Select value={matchValue} onValueChange={setMatchValue}>
              <SelectTrigger id="match-value">
                <SelectValue placeholder={`Select ${ruleType === 'entity_type' ? 'entity type' : 'risk tier'}`} />
              </SelectTrigger>
              <SelectContent>
                {ruleType === 'entity_type'
                  ? ENTITY_TYPES.map((et) => (
                      <SelectItem key={et} value={et}>{et.replace(/_/g, ' ')}</SelectItem>
                    ))
                  : RISK_TIER_VALUES.map((rt) => (
                      <SelectItem key={rt} value={rt}>{rt}</SelectItem>
                    ))
                }
              </SelectContent>
            </Select>
          </div>

          <div>
            <FormLabel htmlFor="label-id">Apply Label</FormLabel>
            <Select value={labelId} onValueChange={setLabelId}>
              <SelectTrigger id="label-id">
                <SelectValue placeholder="Select label to apply" />
              </SelectTrigger>
              <SelectContent>
                {(labels.data?.items ?? []).map((l) => (
                  <SelectItem key={l.id} value={l.id}>{l.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={createRule.isPending}>
              {createRule.isPending ? 'Creating...' : 'Create Rule'}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/* ── Label Rules Tab ── */
function LabelRulesTab() {
  const [rulesPage, setRulesPage] = useState(0);
  const rules = useLabelRules(rulesPage + 1);
  const deleteRule = useDeleteLabelRule();
  const addToast = useUIStore((s) => s.addToast);

  const ruleColumns: ColumnDef<LabelRule, unknown>[] = [
    { accessorKey: 'rule_type', header: 'Type', cell: ({ row }) => (
      <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${
        row.original.rule_type === 'risk_tier'
          ? 'bg-orange-100 text-orange-700'
          : 'bg-blue-100 text-blue-700'
      }`}>
        {row.original.rule_type === 'risk_tier' ? 'Risk Tier' : 'Entity Type'}
      </span>
    )},
    { accessorKey: 'match_value', header: 'Match Value' },
    { accessorKey: 'label_name', header: 'Label', cell: ({ row }) => row.original.label_name ?? row.original.label_id },
    { accessorKey: 'priority', header: 'Priority' },
    { id: 'actions', header: '', cell: ({ row }) => (
      <Button
        variant="ghost"
        size="sm"
        onClick={() => {
          deleteRule.mutate(row.original.id, {
            onSuccess: () => addToast({ level: 'success', message: 'Rule deleted' }),
            onError: (err) => addToast({ level: 'error', message: err.message }),
          });
        }}
        disabled={deleteRule.isPending}
      >
        <Trash2 className="h-4 w-4 text-red-500" />
      </Button>
    )},
  ];

  return (
    <DataTable
      columns={ruleColumns}
      data={rules.data?.items ?? []}
      totalRows={rules.data?.total}
      pagination={{ pageIndex: rulesPage, pageSize: 50 }}
      onPaginationChange={(p) => setRulesPage(p.pageIndex)}
      isLoading={rules.isLoading}
      emptyMessage="No label rules configured"
      emptyDescription="Create rules to automatically assign labels based on entity types or risk tiers"
    />
  );
}

/* ── Label Mappings Tab ── */
function LabelMappingsTab() {
  const mappings = useLabelMappings();
  const updateMappings = useUpdateLabelMappings();
  const addToast = useUIStore((s) => s.addToast);

  const TIERS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

  const [values, setValues] = useState<Record<string, string | null>>({});

  // Initialize from data when it loads — use useEffect instead of
  // setting state during render to avoid React warnings
  const data = mappings.data;
  const initialized = Object.keys(values).length > 0;
  useEffect(() => {
    if (data && !initialized) {
      const init: Record<string, string | null> = {};
      for (const tier of TIERS) init[tier] = data[tier] ?? null;
      setValues(init);
    }
  }, [data, initialized]);

  const handleSave = () => {
    updateMappings.mutate(values, {
      onSuccess: () => addToast({ level: 'success', message: 'Label mappings updated' }),
      onError: (err) => addToast({ level: 'error', message: err.message }),
    });
  };

  const labels = data?.labels ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Risk Tier to Label Mappings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-[var(--muted-foreground)]">
          Map each risk tier to a sensitivity label. Files classified at a given risk tier
          will be recommended for the corresponding label.
        </p>
        <div className="space-y-3">
          {TIERS.map((tier) => (
            <div key={tier} className="flex items-center gap-4">
              <span className={`inline-flex w-24 justify-center rounded-full px-2 py-1 text-xs font-bold ${RISK_COLORS[tier as RiskTier].bg} ${RISK_COLORS[tier as RiskTier].text}`}>
                {tier}
              </span>
              <Select
                value={values[tier] ?? '__none__'}
                onValueChange={(v) => setValues((prev) => ({ ...prev, [tier]: v === '__none__' ? null : v }))}
              >
                <SelectTrigger className="w-64">
                  <SelectValue placeholder="No label assigned" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__none__">No label assigned</SelectItem>
                  {labels.map((l) => (
                    <SelectItem key={l.id} value={l.id}>
                      <div className="flex items-center gap-2">
                        <span
                          className="h-2.5 w-2.5 rounded-full"
                          style={{ backgroundColor: safeColor(l.color) }}
                          aria-hidden="true"
                        />
                        {l.name}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ))}
        </div>
        <div className="pt-2">
          <Button onClick={handleSave} disabled={updateMappings.isPending || mappings.isLoading}>
            {updateMappings.isPending ? 'Saving...' : 'Save Mappings'}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

/* ── Label Stats Tab ── */
function LabelStatsTab() {
  const stats = useLabelStats();
  const data = stats.data;

  if (stats.isLoading) {
    return <p className="py-8 text-center text-sm text-[var(--muted-foreground)]">Loading statistics...</p>;
  }

  if (!data) {
    return <p className="py-8 text-center text-sm text-[var(--muted-foreground)]">No statistics available</p>;
  }

  return (
    <div className="space-y-6">
      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {[
          { label: 'Total Results', value: data.total_results },
          { label: 'Labels Applied', value: data.labels_applied, color: 'text-green-600' },
          { label: 'Pending', value: data.labels_pending, color: 'text-yellow-600' },
          { label: 'Failed', value: data.labels_failed, color: 'text-red-600' },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-6 text-center">
              <p className={`text-2xl font-bold ${s.color ?? ''}`}>{s.value}</p>
              <p className="text-xs text-[var(--muted-foreground)]">{s.label}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* By risk tier */}
      {Object.keys(data.by_tier).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Labels by Risk Tier</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {RISK_TIERS.filter((t) => t !== 'MINIMAL').map((tier) => {
                const tierData = data.by_tier[tier];
                if (!tierData) return null;
                const total = tierData.applied + tierData.pending;
                const pct = total > 0 ? Math.round((tierData.applied / total) * 100) : 0;
                return (
                  <div key={tier} className="flex items-center gap-3">
                    <span className={`inline-flex w-20 justify-center rounded-full px-2 py-0.5 text-xs font-bold ${RISK_COLORS[tier as RiskTier].bg} ${RISK_COLORS[tier as RiskTier].text}`}>
                      {tier}
                    </span>
                    <div className="flex-1">
                      <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--muted)]">
                        <div
                          className="h-full rounded-full bg-green-500 transition-all"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                    <span className="w-24 text-right text-xs text-[var(--muted-foreground)]">
                      {tierData.applied} / {total} ({pct}%)
                    </span>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Per-label usage */}
      {data.per_label.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Label Usage</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {data.per_label.map((item) => (
                <div key={item.label_name} className="flex items-center justify-between rounded-md border px-3 py-2">
                  <span className="text-sm font-medium">{item.label_name}</span>
                  <span className="text-sm text-[var(--muted-foreground)]">{item.count} files</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/* ── Main Page ── */
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
            Create Rule
          </Button>
        </div>
      </div>

      <Tabs defaultValue="labels">
        <TabsList aria-label="Labels sections">
          <TabsTrigger value="labels">Synced Labels</TabsTrigger>
          <TabsTrigger value="rules">Label Rules</TabsTrigger>
          <TabsTrigger value="mappings">Mappings</TabsTrigger>
          <TabsTrigger value="stats">
            <BarChart3 className="mr-1.5 h-3.5 w-3.5" />
            Statistics
          </TabsTrigger>
        </TabsList>

        <TabsContent value="labels" className="mt-4">
          <DataTable
            columns={labelColumns}
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
          <LabelRulesTab />
        </TabsContent>

        <TabsContent value="mappings" className="mt-4">
          <LabelMappingsTab />
        </TabsContent>

        <TabsContent value="stats" className="mt-4">
          <LabelStatsTab />
        </TabsContent>
      </Tabs>

      <CreateLabelRuleDialog open={showCreateRule} onOpenChange={setShowCreateRule} />
    </div>
  );
}
