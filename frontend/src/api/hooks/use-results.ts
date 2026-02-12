import { useQuery, useInfiniteQuery } from '@tanstack/react-query';
import { resultsApi } from '../endpoints/results.ts';

interface ResultFilters {
  risk_tier?: string;
  entity_type?: string;
  scan_id?: string;
  search?: string;
  page_size?: number;
}

export function useResultsCursor(filters: ResultFilters) {
  return useInfiniteQuery({
    queryKey: ['results', filters],
    queryFn: ({ pageParam }) =>
      resultsApi.list({ ...filters, cursor: pageParam }),
    getNextPageParam: (lastPage) =>
      lastPage.has_next ? lastPage.next_cursor : undefined,
    getPreviousPageParam: (firstPage) =>
      firstPage.has_previous ? firstPage.previous_cursor : undefined,
    initialPageParam: undefined as string | undefined,
    staleTime: 60_000,
  });
}

export function useResult(id: string) {
  return useQuery({
    queryKey: ['results', id],
    queryFn: () => resultsApi.get(id),
    staleTime: 60_000,
  });
}
