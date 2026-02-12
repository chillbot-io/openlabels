import { useQuery } from '@tanstack/react-query';
import { browseApi } from '../endpoints/browse.ts';

export function useBrowse(targetId: string, path = '') {
  return useQuery({
    queryKey: ['browse', targetId, path],
    queryFn: () => browseApi.list(targetId, path),
    enabled: !!targetId,
    staleTime: 60_000,
  });
}
