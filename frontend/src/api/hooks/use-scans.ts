import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { scansApi } from '../endpoints/scans.ts';

export function useScans(params?: { status?: string; page?: number; page_size?: number }) {
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
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'running' || status === 'pending' ? 3_000 : false;
    },
  });
}

export function useCreateScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: scansApi.create,
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
    },
  });
}
