import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { scansApi } from '../endpoints/scans.ts';

export function useScans(params?: { status?: string; target_id?: string; page?: number; page_size?: number }) {
  return useQuery({
    queryKey: ['scans', params],
    queryFn: () => scansApi.list(params),
    staleTime: 10_000,
    refetchInterval: 10_000,
  });
}

export function useScan(id: string) {
  return useQuery({
    queryKey: ['scans', id],
    queryFn: () => scansApi.get(id),
    enabled: !!id,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'running' || status === 'pending' ? 3_000 : false;
    },
  });
}

export function useCreateScans() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (items: Array<{ target_id: string; name?: string }>) => {
      // Use Promise.allSettled to handle partial failures gracefully
      const settled = await Promise.allSettled(
        items.map((item) => scansApi.create(item)),
      );
      const fulfilled = settled
        .filter((r): r is PromiseFulfilledResult<Awaited<ReturnType<typeof scansApi.create>>> => r.status === 'fulfilled')
        .map((r) => r.value);
      const rejected = settled.filter((r) => r.status === 'rejected');
      if (rejected.length > 0) {
        console.warn(`${rejected.length} of ${items.length} scan creation(s) failed:`, rejected.map((r) => (r as PromiseRejectedResult).reason));
      }
      if (fulfilled.length === 0 && rejected.length > 0) {
        throw (rejected[0] as PromiseRejectedResult).reason;
      }
      return fulfilled;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });
}

export function useCancelScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: scansApi.cancel,
    onSuccess: (_data, id) => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['scans', id] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });
}
