import { useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router';
import { ArrowLeft, ChevronDown, Tag, ShieldBan, Lock, Download } from 'lucide-react';
import { useResult } from '@/api/hooks/use-results.ts';
import { useLabels, useApplyLabel } from '@/api/hooks/use-labels.ts';
import { useQuarantine, useLockdown } from '@/api/hooks/use-remediation.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.tsx';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog.tsx';
import { ConfirmDialog } from '@/components/confirm-dialog.tsx';
import { RiskBadge } from '@/components/risk-badge.tsx';
import { EntityTag } from '@/components/entity-tag.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { useUIStore } from '@/stores/ui-store.ts';
import { formatDateTime } from '@/lib/date.ts';
import { formatNumber } from '@/lib/utils.ts';
import { downloadBlob } from '@/api/endpoints/export.ts';
import type { RiskTier } from '@/lib/constants.ts';

function maskValue(value: string): string {
  if (value.length <= 4) return '\u2022'.repeat(value.length);
  return '\u2022'.repeat(value.length - 4) + value.slice(-4);
}

function EntityTable({ entities }: { entities: Array<{ entity_type: string; value: string; confidence: number; context: string }> }) {
  const [revealed, setRevealed] = useState(false);
  const toggle = useCallback(() => setRevealed((v) => !v), []);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Detected Entities ({entities.length})</CardTitle>
        <button
          type="button"
          onClick={toggle}
          className="text-xs text-[var(--muted-foreground)] underline hover:text-[var(--foreground)]"
        >
          {revealed ? 'Mask values' : 'Reveal values'}
        </button>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-sm" aria-label="Detected entities">
            <thead className="bg-[var(--muted)]">
              <tr>
                <th className="px-4 py-2 text-left font-medium">Type</th>
                <th className="px-4 py-2 text-left font-medium">Value</th>
                <th className="px-4 py-2 text-left font-medium">Confidence</th>
                <th className="px-4 py-2 text-left font-medium">Context</th>
              </tr>
            </thead>
            <tbody>
              {entities.map((entity, i) => (
                <tr key={i} className="border-t">
                  <td className="px-4 py-2"><EntityTag type={entity.entity_type} /></td>
                  <td className="px-4 py-2 font-mono text-xs">{revealed ? entity.value : maskValue(entity.value)}</td>
                  <td className="px-4 py-2">{(entity.confidence * 100).toFixed(0)}%</td>
                  <td className="px-4 py-2 text-xs text-[var(--muted-foreground)] max-w-md truncate">{entity.context}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

function ApplyLabelDialog({
  open,
  onOpenChange,
  resultId,
  filePath,
  currentLabel,
  recommendedLabel,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  resultId: string;
  filePath: string;
  currentLabel: string | null;
  recommendedLabel: string | null;
}) {
  const labels = useLabels();
  const applyLabel = useApplyLabel();
  const addToast = useUIStore((s) => s.addToast);
  const [selectedLabelId, setSelectedLabelId] = useState('');

  const handleApply = () => {
    if (!selectedLabelId) return;
    applyLabel.mutate(
      { result_id: resultId, label_id: selectedLabelId },
      {
        onSuccess: () => {
          addToast({ level: 'success', message: `Label applied to ${filePath.split(/[\\/]/).pop()}` });
          onOpenChange(false);
          setSelectedLabelId('');
        },
        onError: (err) => addToast({ level: 'error', message: err.message }),
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Apply Sensitivity Label</DialogTitle>
          <DialogDescription>
            Select a label to apply to this file.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="rounded-md bg-[var(--muted)] p-3 text-sm">
            <p><span className="font-medium">File:</span> {filePath}</p>
            <p><span className="font-medium">Current Label:</span> {currentLabel ?? 'None'}</p>
            {recommendedLabel && (
              <p><span className="font-medium">Recommended:</span> {recommendedLabel}</p>
            )}
          </div>
          <div>
            <Select value={selectedLabelId} onValueChange={setSelectedLabelId}>
              <SelectTrigger>
                <SelectValue placeholder="Select a label" />
              </SelectTrigger>
              <SelectContent>
                {(labels.data?.items ?? []).map((label) => (
                  <SelectItem key={label.id} value={label.id}>
                    {label.name}
                    {recommendedLabel && label.name === recommendedLabel ? ' (recommended)' : ''}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button onClick={handleApply} disabled={!selectedLabelId || applyLabel.isPending}>
              {applyLabel.isPending ? 'Applying...' : 'Apply Label'}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function Component() {
  const { resultId } = useParams<{ resultId: string }>();
  const navigate = useNavigate();
  const result = useResult(resultId!);
  const quarantine = useQuarantine();
  const lockdown = useLockdown();
  const addToast = useUIStore((s) => s.addToast);

  const [actionsOpen, setActionsOpen] = useState(false);
  const [showLabelDialog, setShowLabelDialog] = useState(false);
  const [showQuarantineConfirm, setShowQuarantineConfirm] = useState(false);
  const [showLockdownConfirm, setShowLockdownConfirm] = useState(false);

  if (result.isLoading) return <LoadingSkeleton />;
  if (!result.data) return <p className="p-6">Result not found</p>;

  const r = result.data;
  const findings = r.findings as Record<string, unknown[]> | null;
  const entityList = findings
    ? Object.entries(findings).flatMap(([type, items]) =>
        (items as Array<{ value?: string; confidence?: number; context?: string }>).map((item) => ({
          entity_type: type,
          value: item.value ?? '',
          confidence: item.confidence ?? 0,
          context: item.context ?? '',
        })),
      )
    : [];

  const fileName = r.file_name || r.file_path.split(/[\\/]/).pop() || 'Unknown';

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={() => navigate('/results')} aria-label="Back to results">
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold">{fileName}</h1>
            <p className="text-sm text-[var(--muted-foreground)]">{r.file_path}</p>
          </div>
        </div>

        {/* Actions dropdown */}
        <div className="relative">
          <Button variant="outline" onClick={() => setActionsOpen((v) => !v)}>
            Actions <ChevronDown className="ml-2 h-4 w-4" />
          </Button>
          {actionsOpen && (
            <>
              <div className="fixed inset-0 z-40" onClick={() => setActionsOpen(false)} />
              <div className="absolute right-0 z-50 mt-1 w-48 rounded-md border bg-[var(--popover)] shadow-lg">
                <button
                  className="flex w-full items-center gap-2 px-4 py-2 text-sm hover:bg-[var(--muted)]"
                  onClick={() => { setActionsOpen(false); setShowLabelDialog(true); }}
                >
                  <Tag className="h-4 w-4" /> Apply Label
                </button>
                <button
                  className="flex w-full items-center gap-2 px-4 py-2 text-sm text-red-600 hover:bg-[var(--muted)]"
                  onClick={() => { setActionsOpen(false); setShowQuarantineConfirm(true); }}
                >
                  <ShieldBan className="h-4 w-4" /> Quarantine
                </button>
                <button
                  className="flex w-full items-center gap-2 px-4 py-2 text-sm text-orange-600 hover:bg-[var(--muted)]"
                  onClick={() => { setActionsOpen(false); setShowLockdownConfirm(true); }}
                >
                  <Lock className="h-4 w-4" /> Lockdown
                </button>
                <div className="border-t" />
                <button
                  className="flex w-full items-center gap-2 px-4 py-2 text-sm hover:bg-[var(--muted)]"
                  onClick={() => {
                    setActionsOpen(false);
                    const csv = [
                      'entity_type,value,confidence,context',
                      ...entityList.map((e) => `${e.entity_type},${JSON.stringify(e.value)},${e.confidence},${JSON.stringify(e.context)}`),
                    ].join('\n');
                    downloadBlob(new Blob([csv], { type: 'text/csv' }), `${fileName}-entities.csv`);
                  }}
                >
                  <Download className="h-4 w-4" /> Export Entities
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Card>
          <CardContent className="p-4">
            <p className="text-xs text-[var(--muted-foreground)]">Risk Tier</p>
            <RiskBadge tier={r.risk_tier as RiskTier} className="mt-1" />
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-xs text-[var(--muted-foreground)]">Risk Score</p>
            <p className="text-xl font-bold mt-1">{r.risk_score}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-xs text-[var(--muted-foreground)]">File Size</p>
            <p className="text-xl font-bold mt-1">{formatNumber(r.file_size ?? 0)}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-xs text-[var(--muted-foreground)]">Owner</p>
            <p className="text-sm font-medium mt-1">{r.owner ?? '—'}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-xs text-[var(--muted-foreground)]">Scanned</p>
            <p className="text-sm mt-1">{formatDateTime(r.scanned_at)}</p>
          </CardContent>
        </Card>
      </div>

      {/* Label info */}
      <Card>
        <CardHeader><CardTitle>Label</CardTitle></CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          {r.current_label_name ? (
            <>
              <Badge variant="secondary">{r.current_label_name}</Badge>
              {r.label_applied_at && (
                <span className="text-xs text-[var(--muted-foreground)]">Applied {formatDateTime(r.label_applied_at)}</span>
              )}
            </>
          ) : (
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="border-yellow-300 text-yellow-700">No Label</Badge>
              {r.recommended_label_name && (
                <span className="text-xs text-[var(--muted-foreground)]">
                  Recommended: <span className="font-medium">{r.recommended_label_name}</span>
                </span>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Entity summary */}
      <Card>
        <CardHeader><CardTitle>Entity Summary</CardTitle></CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {Object.entries(r.entity_counts).map(([type, count]) => (
            <EntityTag key={type} type={type} count={count} />
          ))}
        </CardContent>
      </Card>

      {entityList.length > 0 && (
        <EntityTable entities={entityList} />
      )}

      {r.policy_violations && r.policy_violations.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Policy Violations</CardTitle></CardHeader>
          <CardContent>
            <div className="space-y-2">
              {r.policy_violations.map((violation, i) => (
                <div key={i} role="alert" className="rounded-md border border-[var(--destructive)]/20 bg-[var(--destructive)]/10 px-4 py-3 text-sm">
                  <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                    {Object.entries(violation).map(([key, value]) => (
                      <div key={key} className="contents">
                        <dt className="font-medium text-[var(--destructive)]">{key.replace(/_/g, ' ')}</dt>
                        <dd className="text-[var(--foreground)]">{typeof value === 'object' ? JSON.stringify(value) : String(value)}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Apply Label dialog */}
      <ApplyLabelDialog
        open={showLabelDialog}
        onOpenChange={setShowLabelDialog}
        resultId={resultId!}
        filePath={r.file_path}
        currentLabel={r.current_label_name}
        recommendedLabel={r.recommended_label_name}
      />

      {/* Quarantine confirm */}
      <ConfirmDialog
        open={showQuarantineConfirm}
        onOpenChange={setShowQuarantineConfirm}
        title="Quarantine File?"
        description={`This will move "${r.file_path}" to a quarantine directory. Users will lose access immediately. This action can be reversed.`}
        confirmLabel="Quarantine File"
        onConfirm={() => {
          quarantine.mutate(
            { file_path: r.file_path },
            {
              onSuccess: () => {
                addToast({ level: 'success', message: 'File quarantined' });
                setShowQuarantineConfirm(false);
              },
              onError: (err) => addToast({ level: 'error', message: err.message }),
            },
          );
        }}
        isPending={quarantine.isPending}
      />

      {/* Lockdown confirm */}
      <ConfirmDialog
        open={showLockdownConfirm}
        onOpenChange={setShowLockdownConfirm}
        title="Lock Down File?"
        description={`This will restrict access to "${r.file_path}". Only administrators will retain access. This action can be reversed.`}
        confirmLabel="Lock Down File"
        onConfirm={() => {
          lockdown.mutate(
            { file_path: r.file_path, allowed_principals: [] },
            {
              onSuccess: () => {
                addToast({ level: 'success', message: 'File locked down' });
                setShowLockdownConfirm(false);
              },
              onError: (err) => addToast({ level: 'error', message: err.message }),
            },
          );
        }}
        isPending={lockdown.isPending}
      />
    </div>
  );
}
