import { useState, useCallback } from 'react';
import { useParams } from 'react-router';
import { useResult } from '@/api/hooks/use-results.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { RiskBadge } from '@/components/risk-badge.tsx';
import { EntityTag } from '@/components/entity-tag.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { LoadingSkeleton } from '@/components/loading-skeleton.tsx';
import { formatDateTime } from '@/lib/date.ts';
import { formatNumber } from '@/lib/utils.ts';
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

export function Component() {
  const { resultId } = useParams<{ resultId: string }>();
  const result = useResult(resultId!);

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

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">{r.file_name}</h1>
        <p className="text-sm text-[var(--muted-foreground)]">{r.file_path}</p>
      </div>

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

      {r.current_label_name && (
        <Card>
          <CardHeader><CardTitle>Label</CardTitle></CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            <Badge variant="secondary">{r.current_label_name}</Badge>
            {r.label_applied_at && (
              <span className="text-xs text-[var(--muted-foreground)]">Applied {formatDateTime(r.label_applied_at)}</span>
            )}
          </CardContent>
        </Card>
      )}

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
    </div>
  );
}
