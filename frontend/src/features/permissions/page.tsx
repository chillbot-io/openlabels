import { useState } from 'react';
import { useExposureSummary, useDirectories, useDirectoryACL, usePrincipalLookup } from '@/api/hooks/use-permissions.ts';
import { useTargets } from '@/api/hooks/use-targets.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { useDebounce } from '@/hooks/use-debounce.ts';
import { EXPOSURE_LEVELS } from '@/lib/constants.ts';

const EXPOSURE_COLORS: Record<string, string> = {
  PUBLIC: 'bg-red-100 text-red-800',
  ORG_WIDE: 'bg-orange-100 text-orange-800',
  INTERNAL: 'bg-yellow-100 text-yellow-800',
  PRIVATE: 'bg-green-100 text-green-800',
};

export function Component() {
  const targets = useTargets();
  const [targetId, setTargetId] = useState('');
  const [exposure, setExposure] = useState<string>('');
  const [page, setPage] = useState(1);
  const [selectedDirId, setSelectedDirId] = useState<string>('');
  const [principal, setPrincipal] = useState('');
  const debouncedPrincipal = useDebounce(principal);

  const exposureSummary = useExposureSummary();
  const directories = useDirectories(targetId, {
    page,
    exposure: exposure || undefined,
  });
  const acl = useDirectoryACL(targetId, selectedDirId);
  const principalLookup = usePrincipalLookup(debouncedPrincipal);

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-bold">Permissions Explorer</h1>

      {/* Exposure summary */}
      <div className="grid grid-cols-4 gap-4">
        {exposureSummary.isLoading ? (
          Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-20" />)
        ) : exposureSummary.data ? (
          EXPOSURE_LEVELS.map((level) => (
            <Card key={level}>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold">{exposureSummary.data[level]}</p>
                <Badge className={EXPOSURE_COLORS[level]}>{level}</Badge>
              </CardContent>
            </Card>
          ))
        ) : null}
      </div>

      <Tabs defaultValue="directories">
        <TabsList>
          <TabsTrigger value="directories">Directory ACLs</TabsTrigger>
          <TabsTrigger value="principal">Principal Lookup</TabsTrigger>
        </TabsList>

        <TabsContent value="directories" className="space-y-4 pt-4">
          <div className="flex flex-wrap items-center gap-3">
            <Select value={targetId} onValueChange={(v) => { setTargetId(v); setPage(1); }}>
              <SelectTrigger className="w-48"><SelectValue placeholder="Select target" /></SelectTrigger>
              <SelectContent>
                {(targets.data?.items ?? []).map((t) => (
                  <SelectItem key={t.id} value={t.id}>{t.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={exposure} onValueChange={(v) => { setExposure(v === 'all' ? '' : v); setPage(1); }}>
              <SelectTrigger className="w-36"><SelectValue placeholder="Exposure" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All levels</SelectItem>
                {EXPOSURE_LEVELS.map((l) => <SelectItem key={l} value={l}>{l}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>

          {directories.isLoading ? (
            <Skeleton className="h-48" />
          ) : (
            <div className="space-y-1">
              {(directories.data?.items ?? []).map((dir) => (
                <button
                  key={dir.id}
                  className="flex w-full items-center justify-between rounded-md px-4 py-3 text-left text-sm hover:bg-[var(--muted)]"
                  onClick={() => setSelectedDirId(dir.id)}
                >
                  <span className="font-mono">{dir.path}</span>
                  {dir.exposure_level && (
                    <Badge className={EXPOSURE_COLORS[dir.exposure_level] ?? ''}>{dir.exposure_level}</Badge>
                  )}
                </button>
              ))}
            </div>
          )}

          {selectedDirId && acl.data && (
            <Card>
              <CardHeader><CardTitle>ACL Detail</CardTitle></CardHeader>
              <CardContent className="space-y-2 text-sm">
                <p><strong>Path:</strong> {acl.data.path}</p>
                <p><strong>Owner:</strong> {acl.data.owner_sid ?? '—'}</p>
                <p><strong>Group:</strong> {acl.data.group_sid ?? '—'}</p>
                <p><strong>Exposure:</strong> <Badge className={EXPOSURE_COLORS[acl.data.exposure_level] ?? ''}>{acl.data.exposure_level}</Badge></p>
                {acl.data.dacl_sddl && (
                  <div>
                    <p><strong>DACL SDDL:</strong></p>
                    <pre className="mt-1 overflow-x-auto rounded-md bg-[var(--muted)] p-2 text-xs">{acl.data.dacl_sddl}</pre>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="principal" className="space-y-4 pt-4">
          <Input
            placeholder="Search by SID or principal name..."
            value={principal}
            onChange={(e) => setPrincipal(e.target.value)}
            className="w-96"
          />

          {principalLookup.isLoading && debouncedPrincipal ? (
            <Skeleton className="h-32" />
          ) : (principalLookup.data ?? []).length > 0 ? (
            <Card>
              <CardContent className="p-0">
                <div className="divide-y">
                  {principalLookup.data!.map((dir) => (
                    <div key={dir.id} className="flex items-center justify-between px-4 py-3 text-sm">
                      <span className="font-mono">{dir.path}</span>
                      {dir.exposure_level && <Badge className={EXPOSURE_COLORS[dir.exposure_level] ?? ''}>{dir.exposure_level}</Badge>}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          ) : debouncedPrincipal ? (
            <p className="text-sm text-[var(--muted-foreground)]">No directories found for this principal.</p>
          ) : null}
        </TabsContent>
      </Tabs>
    </div>
  );
}
