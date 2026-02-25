import { useState } from 'react';
import { useActivityLog } from '@/api/hooks/use-monitoring.ts';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatRelativeTime } from '@/lib/utils.ts';

export function ActivityTab() {
  const [activityPage, setActivityPage] = useState(1);
  const activity = useActivityLog({ page: activityPage, page_size: 20 });

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="p-0">
          {activity.isLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
            </div>
          ) : (
            <div className="divide-y" role="list" aria-label="Activity log entries">
              {(activity.data?.items ?? []).map((entry) => (
                <div key={entry.id} className="flex items-center justify-between px-4 py-3" role="listitem">
                  <div>
                    <p className="text-sm font-medium">{entry.action}</p>
                    <p className="text-xs text-[var(--muted-foreground)]">
                      {entry.user_email ?? 'system'} &middot; {entry.resource_type}
                      {entry.resource_id ? ` #${entry.resource_id.slice(0, 8)}` : ''}
                    </p>
                  </div>
                  <span className="text-xs text-[var(--muted-foreground)]">
                    {formatRelativeTime(entry.created_at)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
      {activity.data && (
        <div className="flex justify-center gap-2">
          <Button variant="outline" size="sm" disabled={activityPage <= 1} onClick={() => setActivityPage((p) => p - 1)}>
            Previous
          </Button>
          <span className="flex items-center text-sm text-[var(--muted-foreground)]">Page {activityPage}</span>
          <Button variant="outline" size="sm" disabled={!activity.data.has_next} onClick={() => setActivityPage((p) => p + 1)}>
            Next
          </Button>
        </div>
      )}
    </div>
  );
}
