import { useState, useEffect, useMemo } from 'react';
import { Activity } from 'lucide-react';
import { useEvents } from '@/api/hooks/use-events.ts';
import { FolderTreePanel } from '@/components/folder-tree.tsx';
import { Input } from '@/components/ui/input.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { EmptyState } from '@/components/empty-state.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { useDebounce } from '@/hooks/use-debounce.ts';
import { wsClient } from '@/lib/websocket.ts';
import { formatDateTime } from '@/lib/date.ts';
import type { BrowseFolder, FileAccessEvent, WSFileAccess } from '@/api/types.ts';

export function Component() {
  const [targetId, setTargetId] = useState('');
  const [selectedFolder, setSelectedFolder] = useState<BrowseFolder | null>(null);
  const [userFilter, setUserFilter] = useState('');
  const debouncedUser = useDebounce(userFilter);
  const [liveEvents, setLiveEvents] = useState<FileAccessEvent[]>([]);

  const folderPath = selectedFolder?.dir_path;

  const events = useEvents({
    file_path: folderPath || undefined,
    user_name: debouncedUser || undefined,
    page_size: 50,
  });

  useEffect(() => {
    return wsClient.subscribe('file_access', (raw) => {
      const data = raw as WSFileAccess;
      setLiveEvents((prev) => [{
        id: `live-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        file_path: data.file_path,
        user_name: data.user_name,
        action: data.action,
        event_time: data.event_time,
        details: {},
      }, ...prev].slice(0, 50));
    });
  }, []);

  useEffect(() => {
    setLiveEvents([]);
  }, [folderPath, debouncedUser]);

  const historicalEvents = events.data?.pages.flatMap((p) => p.items) ?? [];
  const historicalIds = useMemo(
    () => new Set(historicalEvents.map((e) => e.id)),
    [historicalEvents],
  );

  // Filter live events to match selected folder
  const filteredLive = liveEvents.filter((e) => {
    if (historicalIds.has(e.id)) return false;
    if (folderPath && !e.file_path.startsWith(folderPath)) return false;
    return true;
  });

  const allEvents = [...filteredLive, ...historicalEvents];

  return (
    <div className="flex h-[calc(100vh-3.5rem)] overflow-hidden">
      <FolderTreePanel
        targetId={targetId}
        onTargetChange={(id) => { setTargetId(id); setSelectedFolder(null); }}
        onSelect={setSelectedFolder}
        selectedId={selectedFolder?.id ?? null}
      />

      <div className="flex flex-1 flex-col overflow-hidden">
        <div className="flex items-center gap-3 border-b px-6 py-3">
          <h1 className="text-lg font-semibold">Events</h1>
          <Input
            placeholder="Filter by user..."
            value={userFilter}
            onChange={(e) => setUserFilter(e.target.value)}
            className="w-48"
            aria-label="Filter by user"
          />
          {filteredLive.length > 0 && (
            <span className="flex items-center gap-1.5 text-xs text-green-600" aria-live="polite">
              <span className="h-2 w-2 animate-pulse rounded-full bg-green-500" />
              {filteredLive.length} live
            </span>
          )}
          {selectedFolder && (
            <span className="ml-auto truncate text-sm text-[var(--muted-foreground)]">{selectedFolder.dir_path}</span>
          )}
        </div>

        <div className="flex-1 overflow-y-auto p-6">
          {!selectedFolder ? (
            <EmptyState icon={Activity} title="Select a folder" description="Click a folder in the tree to see its events" />
          ) : events.isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 10 }).map((_, i) => <Skeleton key={i} className="h-16 w-full" />)}
            </div>
          ) : allEvents.length === 0 ? (
            <EmptyState icon={Activity} title="No events" description="No file access events found for this folder" />
          ) : (
            <>
              <div className="space-y-2" role="list" aria-label="File access events">
                {allEvents.map((event) => (
                  <Card key={event.id} role="listitem">
                    <CardContent className="flex items-center justify-between p-4">
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium">{event.file_path}</p>
                        <p className="text-xs text-[var(--muted-foreground)]">
                          {event.user_name} &middot; {event.action}
                        </p>
                      </div>
                      <span className="shrink-0 text-xs text-[var(--muted-foreground)]">
                        {formatDateTime(event.event_time)}
                      </span>
                    </CardContent>
                  </Card>
                ))}
              </div>

              {events.hasNextPage && (
                <div className="flex justify-center pt-4">
                  <Button variant="outline" onClick={() => events.fetchNextPage()} disabled={events.isFetchingNextPage}>
                    {events.isFetchingNextPage ? 'Loading...' : 'Load more'}
                  </Button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
