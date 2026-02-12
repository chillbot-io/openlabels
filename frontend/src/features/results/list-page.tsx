import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { type ColumnDef } from '@tanstack/react-table';
import { useResultsCursor } from '@/api/hooks/use-results.ts';
import { DataTable } from '@/components/data-table/data-table.tsx';
import { RiskBadge } from '@/components/risk-badge.tsx';
import { EntityTag } from '@/components/entity-tag.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.tsx';
import { useDebounce } from '@/hooks/use-debounce.ts';
import { truncatePath } from '@/lib/utils.ts';
import type { ScanResult } from '@/api/types.ts';
import type { RiskTier } from '@/lib/constants.ts';
import { RISK_TIERS } from '@/lib/constants.ts';

const columns: ColumnDef<ScanResult, unknown>[] = [
  { accessorKey: 'file_name', header: 'File', cell: ({ row }) => (
    <div>
      <p className="font-medium">{row.original.file_name}</p>
      <p className="text-xs text-[var(--muted-foreground)]">{truncatePath(row.original.file_path)}</p>
    </div>
  )},
  { accessorKey: 'risk_tier', header: 'Risk', cell: ({ row }) => <RiskBadge tier={row.original.risk_tier as RiskTier} /> },
  { accessorKey: 'risk_score', header: 'Score' },
  { accessorKey: 'entity_counts', header: 'Entities', cell: ({ row }) => (
    <div className="flex flex-wrap gap-1">
      {Object.entries(row.original.entity_counts).slice(0, 3).map(([type, count]) => (
        <EntityTag key={type} type={type} count={count} />
      ))}
    </div>
  )},
  { accessorKey: 'target_name', header: 'Target', cell: ({ row }) => row.original.target_name ?? '—' },
];

export function Component() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [search, setSearch] = useState(searchParams.get('search') ?? '');
  const debouncedSearch = useDebounce(search);

  const riskTier = searchParams.get('risk_tier') ?? undefined;
  const entityType = searchParams.get('entity_type') ?? undefined;

  const results = useResultsCursor({
    risk_tier: riskTier,
    entity_type: entityType,
    search: debouncedSearch || undefined,
    page_size: 50,
  });

  const allResults = results.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-bold">Scan Results</h1>

      <div className="flex flex-wrap items-center gap-3">
        <Input
          placeholder="Search files..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-64"
        />
        <Select
          value={riskTier ?? 'all'}
          onValueChange={(v) => {
            const next = new URLSearchParams(searchParams);
            if (v === 'all') next.delete('risk_tier');
            else next.set('risk_tier', v);
            setSearchParams(next);
          }}
        >
          <SelectTrigger className="w-36"><SelectValue placeholder="Risk tier" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All tiers</SelectItem>
            {RISK_TIERS.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>

      <DataTable
        columns={columns}
        data={allResults}
        isLoading={results.isLoading}
        emptyMessage="No results found"
        emptyDescription="Run a scan to discover sensitive data in your files"
        onRowClick={(result) => navigate(`/results/${result.id}`)}
      />

      {results.hasNextPage && (
        <div className="flex justify-center">
          <Button
            variant="outline"
            onClick={() => results.fetchNextPage()}
            disabled={results.isFetchingNextPage}
          >
            {results.isFetchingNextPage ? 'Loading...' : 'Load more'}
          </Button>
        </div>
      )}
    </div>
  );
}
