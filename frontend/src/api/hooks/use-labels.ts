import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { labelsApi } from '../endpoints/labels.ts';

export function useLabels(page = 1) {
  return useQuery({
    queryKey: ['labels', { page }],
    queryFn: () => labelsApi.list({ page, page_size: 50 }),
    staleTime: 5 * 60_000,
  });
}

export function useLabelMappings() {
  return useQuery({
    queryKey: ['labels', 'mappings'],
    queryFn: () => labelsApi.mappings(),
    staleTime: 5 * 60_000,
  });
}

export function useSyncLabels() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: labelsApi.sync,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['labels'] });
    },
  });
}

export function useLabelSyncStatus() {
  return useQuery({
    queryKey: ['labels', 'sync-status'],
    queryFn: () => labelsApi.syncStatus(),
  });
}
