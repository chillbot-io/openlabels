import { useInfiniteQuery } from '@tanstack/react-query';
import { eventsApi } from '../endpoints/events.ts';

interface EventFilters {
  file_path?: string;
  user_name?: string;
  action?: string;
  since?: string;
  page_size?: number;
}

export function useEvents(filters: EventFilters) {
  return useInfiniteQuery({
    queryKey: ['events', filters],
    queryFn: ({ pageParam }) =>
      eventsApi.list({ ...filters, cursor: pageParam }),
    getNextPageParam: (lastPage) =>
      lastPage.has_next ? lastPage.next_cursor : undefined,
    initialPageParam: undefined as string | undefined,
    staleTime: 30_000,
  });
}
