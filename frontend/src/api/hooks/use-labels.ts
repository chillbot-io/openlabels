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

export function useUpdateLabelMappings() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: labelsApi.updateMappings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['labels'] });
    },
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

export function useApplyLabel() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: labelsApi.apply,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['results'] });
      queryClient.invalidateQueries({ queryKey: ['labels'] });
    },
  });
}

export function useBulkApplyLabels() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: labelsApi.bulkApply,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['results'] });
      queryClient.invalidateQueries({ queryKey: ['labels'] });
    },
  });
}

export function useLabelStats() {
  return useQuery({
    queryKey: ['labels', 'stats'],
    queryFn: () => labelsApi.stats(),
    staleTime: 60_000,
  });
}

export function useLabelRules(page = 1) {
  return useQuery({
    queryKey: ['labels', 'rules', { page }],
    queryFn: () => labelsApi.listRules({ page, page_size: 50 }),
    staleTime: 5 * 60_000,
  });
}

export function useCreateLabelRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: labelsApi.createRule,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['labels', 'rules'] });
    },
  });
}

export function useDeleteLabelRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: labelsApi.deleteRule,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['labels', 'rules'] });
    },
  });
}
