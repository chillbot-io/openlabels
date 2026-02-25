import { useState } from 'react';
import { useErrorLog } from '@/api/hooks/use-monitoring.ts';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatRelativeTime } from '@/lib/utils.ts';

const severityColor: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  error: 'bg-red-500 text-white',
  warning: 'bg-yellow-500 text-black',
};

export function ErrorsTab() {
  const [source, setSource] = useState<string | undefined>();
  const [severity, setSeverity] = useState<string | undefined>();
  const [errorPage, setErrorPage] = useState(1);
  const errors = useErrorLog({ source, severity, page: errorPage, page_size: 30 });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <span className="text-sm text-[var(--muted-foreground)]">Source:</span>
        {[undefined, 'job', 'task', 'system'].map((s) => (
          <Button key={s ?? 'all'} variant={source === s ? 'default' : 'outline'} size="sm" onClick={() => { setSource(s); setErrorPage(1); }}>
            {s ?? 'All'}
          </Button>
        ))}
        <span className="ml-4 text-sm text-[var(--muted-foreground)]">Severity:</span>
        {[undefined, 'critical', 'error', 'warning'].map((s) => (
          <Button key={s ?? 'all'} variant={severity === s ? 'default' : 'outline'} size="sm" onClick={() => { setSeverity(s); setErrorPage(1); }}>
            {s ?? 'All'}
          </Button>
        ))}
      </div>

      <Card>
        <CardContent className="p-0">
          {errors.isLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
            </div>
          ) : errors.data && errors.data.entries.length > 0 ? (
            <div className="divide-y" role="list" aria-label="Error log entries">
              {errors.data.entries.map((entry) => (
                <div key={entry.id} className="px-4 py-3" role="listitem">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Badge className={severityColor[entry.severity] ?? 'bg-gray-500 text-white'}>
                        {entry.severity}
                      </Badge>
                      <Badge variant="secondary">{entry.source}</Badge>
                      <p className="text-sm font-medium">{entry.message}</p>
                    </div>
                    <span className="shrink-0 text-xs text-[var(--muted-foreground)]">
                      {formatRelativeTime(entry.timestamp)}
                    </span>
                  </div>
                  {entry.details && (
                    <div className="mt-1 flex gap-3 pl-8 text-xs text-[var(--muted-foreground)]">
                      {Object.entries(entry.details).map(([k, v]) => (
                        <span key={k}>{k}: {String(v)}</span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-sm text-[var(--muted-foreground)]">
              No errors found for the selected filters.
            </div>
          )}
        </CardContent>
      </Card>

      {errors.data && errors.data.total > 0 && (
        <div className="flex items-center justify-between">
          <span className="text-sm text-[var(--muted-foreground)]">{errors.data.total} total errors</span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={errorPage <= 1} onClick={() => setErrorPage((p) => p - 1)}>
              Previous
            </Button>
            <span className="flex items-center text-sm text-[var(--muted-foreground)]">Page {errorPage}</span>
            <Button variant="outline" size="sm" disabled={!errors.data.has_next} onClick={() => setErrorPage((p) => p + 1)}>
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
