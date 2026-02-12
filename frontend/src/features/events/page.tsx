import { useState, useEffect } from 'react';
import { useInfiniteQuery } from '@tanstack/react-query';
import { Activity } from 'lucide-react';
import { eventsApi } from '@/api/endpoints/events.ts';
import { Input } from '@/components/ui/input.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { EmptyState } from '@/components/empty-state.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { useDebounce } from '@/hooks/use-debounce.ts';
import { wsClient } from '@/lib/websocket.ts';
import { formatDateTime } from '@/lib/date.ts';
import type { FileAccessEvent, WSFileAccess } from '@/api/types.ts';

export function Component() {
  const [fileFilter, setFileFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const debouncedFile = useDebounce(fileFilter);
  const debouncedUser = useDebounce(userFilter);
  const [liveEvents, setLiveEvents] = useState<FileAccessEvent[]>([]);

  const events = useInfiniteQuery({
    queryKey: ['events', { file_path: debouncedFile || undefined, user_name: debouncedUser || undefined }],
    queryFn: ({ pageParam }) =>
      eventsApi.list({
        cursor: pageParam,
        page_size: 50,
        file_path: debouncedFile || undefined,
        user_name: debouncedUser || undefined,
      }),
    getNextPageParam: (lastPage) => lastPage.has_next ? lastPage.next_cursor : undefined,
    initialPageParam: undefined as string | undefined,
  });

  useEffect(() => {
    return wsClient.subscribe('file_access', (raw) => {
      const data = raw as WSFileAccess;
      setLiveEvents((prev) => [{
        id: `live-${Date.now()}`,
        file_path: data.file_path,
        user_name: data.user_name,
        action: data.action,
        event_time: data.event_time,
        details: {},
      }, ...prev].slice(0, 20));
    });
  }, []);

  const allEvents = [
    ...liveEvents,
    ...(events.data?.pages.flatMap((p) => p.items) ?? []),
  ];

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-bold">Sensitive Data Events</h1>

      <div className="flex flex-wrap items-center gap-3">
        <Input placeholder="Filter by file path..." value={fileFilter} onChange={(e) => setFileFilter(e.target.value)} className="w-64" />
        <Input placeholder="Filter by user..." value={userFilter} onChange={(e) => setUserFilter(e.target.value)} className="w-48" />
        {liveEvents.length > 0 && (
          <span className="flex items-center gap-1.5 text-xs text-green-600">
            <span className="h-2 w-2 animate-pulse rounded-full bg-green-500" />
            {liveEvents.length} live events
          </span>
        )}
      </div>

      {events.isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 10 }).map((_, i) => <Skeleton key={i} className="h-16 w-full" />)}
        </div>
      ) : allEvents.length === 0 ? (
        <EmptyState icon={Activity} title="No events" description="File access events will appear here in real-time" />
      ) : (
        <div className="space-y-2">
          {allEvents.map((event) => (
            <Card key={event.id}>
              <CardContent className="flex items-center justify-between p-4">
                <div>
                  <p className="text-sm font-medium">{event.file_path}</p>
                  <p className="text-xs text-[var(--muted-foreground)]">
                    {event.user_name} &middot; {event.action}
                  </p>
                </div>
                <span className="text-xs text-[var(--muted-foreground)]">
                  {formatDateTime(event.event_time)}
                </span>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {events.hasNextPage && (
        <div className="flex justify-center">
          <Button variant="outline" onClick={() => events.fetchNextPage()} disabled={events.isFetchingNextPage}>
            {events.isFetchingNextPage ? 'Loading...' : 'Load more'}
          </Button>
        </div>
      )}
    </div>
  );
}
