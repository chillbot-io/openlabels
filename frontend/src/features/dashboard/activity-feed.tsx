import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatRelativeTime } from '@/lib/utils.ts';
import type { AuditLogEntry } from '@/api/types.ts';

interface Props {
  entries: AuditLogEntry[];
  isLoading: boolean;
}

export function ActivityFeed({ entries, isLoading }: Props) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Activity</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : entries.length === 0 ? (
          <p className="py-8 text-center text-sm text-[var(--muted-foreground)]">No activity yet</p>
        ) : (
          <div className="space-y-1">
            {entries.map((entry) => (
              <div key={entry.id} className="flex items-center justify-between rounded-md px-3 py-2 text-sm">
                <div>
                  <p className="font-medium">{entry.action}</p>
                  <p className="text-xs text-[var(--muted-foreground)]">
                    {entry.user_email ?? 'system'} &middot; {entry.resource_type}
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
  );
}
