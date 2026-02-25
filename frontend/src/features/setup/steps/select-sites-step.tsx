import { useState, useEffect, useCallback, useRef } from 'react';
import { ArrowRight, ArrowLeft, Loader2, Search } from 'lucide-react';
import { enumerateApi } from '@/api/endpoints/enumerate.ts';
import type { EnumeratedResource } from '@/api/endpoints/enumerate.ts';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Input } from '@/components/ui/input.tsx';
import { cn } from '@/lib/utils.ts';
import type { SiteSelection } from '../types.ts';

export function SelectSitesStep({
  sourceType,
  onDone,
  onBack,
}: {
  sourceType: 'sharepoint' | 'onedrive';
  onDone: (selection: SiteSelection) => void;
  onBack: () => void;
}) {
  const [mode, setMode] = useState<'all' | 'individual' | null>(null);
  const [search, setSearch] = useState('');
  const [results, setResults] = useState<EnumeratedResource[]>([]);
  const [loading, setLoading] = useState(false);
  const [hasMore, setHasMore] = useState(false);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Map<string, EnumeratedResource>>(new Map());
  const [initialLoaded, setInitialLoaded] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>();

  const label = sourceType === 'sharepoint' ? 'sites' : 'users';

  const doSearch = useCallback(async (query: string, pageNum: number, append: boolean) => {
    setLoading(true);
    try {
      const resp = await enumerateApi.enumerate({
        source_type: sourceType,
        search: query || undefined,
        page: pageNum,
        page_size: 50,
        use_m365_session: true,
      });
      if (append) {
        setResults(prev => [...prev, ...resp.resources]);
      } else {
        setResults(resp.resources);
      }
      setHasMore(resp.has_more);
      setPage(pageNum);
    } catch { /* toast handled by apiFetch */ } finally {
      setLoading(false);
    }
  }, [sourceType]);

  // Load initial results when selecting "individual"
  useEffect(() => {
    if (mode === 'individual' && !initialLoaded) {
      setInitialLoaded(true);
      doSearch('', 1, false);
    }
  }, [mode, initialLoaded, doSearch]);

  // Debounced search
  const handleSearchChange = (value: string) => {
    setSearch(value);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      doSearch(value, 1, false);
    }, 300);
  };

  const toggleSite = (resource: EnumeratedResource) => {
    setSelected(prev => {
      const next = new Map(prev);
      if (next.has(resource.id)) {
        next.delete(resource.id);
      } else {
        next.set(resource.id, resource);
      }
      return next;
    });
  };

  const handleDone = () => {
    if (mode === 'all') {
      onDone({ sourceType, mode: 'all', selectedSites: [] });
    } else {
      onDone({ sourceType, mode: 'individual', selectedSites: Array.from(selected.values()) });
    }
  };

  return (
    <Card>
      <CardContent className="space-y-5 p-8">
        <div>
          <h2 className="text-xl font-bold">
            Select {sourceType === 'sharepoint' ? 'SharePoint Sites' : 'OneDrive Users'}
          </h2>
          <p className="mt-1 text-sm text-[var(--muted-foreground)]">
            Choose which {label} to scan.
          </p>
        </div>

        {/* Mode selector */}
        <div className="grid grid-cols-2 gap-3">
          <button
            type="button"
            className={cn(
              'rounded-lg border-2 p-4 text-left transition-colors',
              mode === 'all' ? 'border-blue-600 bg-blue-50' : 'border-gray-200 hover:border-blue-400',
            )}
            onClick={() => setMode('all')}
          >
            <span className="text-sm font-medium">Select all</span>
            <p className="text-xs text-[var(--muted-foreground)]">
              All current and future {label}
            </p>
          </button>
          <button
            type="button"
            className={cn(
              'rounded-lg border-2 p-4 text-left transition-colors',
              mode === 'individual' ? 'border-blue-600 bg-blue-50' : 'border-gray-200 hover:border-blue-400',
            )}
            onClick={() => setMode('individual')}
          >
            <span className="text-sm font-medium">Select individual</span>
            <p className="text-xs text-[var(--muted-foreground)]">
              Choose specific {label}
            </p>
          </button>
        </div>

        {/* Individual selection: search + list */}
        {mode === 'individual' && (
          <div className="space-y-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--muted-foreground)]" />
              <Input
                className="pl-9"
                placeholder={`Search ${label}...`}
                value={search}
                onChange={e => handleSearchChange(e.target.value)}
              />
            </div>

            {selected.size > 0 && (
              <p className="text-sm font-medium text-blue-600">
                {selected.size} {label} selected
              </p>
            )}

            <div className="max-h-72 space-y-1 overflow-y-auto rounded-md border p-2">
              {loading && results.length === 0 ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-5 w-5 animate-spin text-[var(--muted-foreground)]" />
                </div>
              ) : results.length === 0 ? (
                <p className="py-4 text-center text-sm text-[var(--muted-foreground)]">
                  {search ? `No ${label} found matching "${search}"` : `No ${label} found`}
                </p>
              ) : (
                <>
                  {results.map(resource => (
                    <label
                      key={resource.id}
                      className={cn(
                        'flex cursor-pointer items-start gap-3 rounded-md px-3 py-2 transition-colors hover:bg-[var(--muted)]',
                        selected.has(resource.id) && 'bg-[var(--accent)]',
                      )}
                    >
                      <input
                        type="checkbox"
                        className="mt-0.5 rounded"
                        checked={selected.has(resource.id)}
                        onChange={() => toggleSite(resource)}
                      />
                      <div className="min-w-0 flex-1">
                        <span className="text-sm font-medium">{resource.name}</span>
                        <p className="truncate text-xs text-[var(--muted-foreground)]">{resource.path}</p>
                        {resource.description && (
                          <p className="truncate text-xs text-[var(--muted-foreground)]">{resource.description}</p>
                        )}
                      </div>
                    </label>
                  ))}
                  {hasMore && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="w-full"
                      disabled={loading}
                      onClick={() => doSearch(search, page + 1, true)}
                    >
                      {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                      Load more
                    </Button>
                  )}
                </>
              )}
            </div>
          </div>
        )}

        <div className="flex justify-between pt-2">
          <Button variant="ghost" onClick={onBack}>
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Button>
          <Button
            onClick={handleDone}
            disabled={!mode || (mode === 'individual' && selected.size === 0)}
          >
            Next <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
