import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { remediationApi } from '../endpoints/remediation.ts';

export function useRemediationActions(params?: { page?: number; status?: string }) {
  return useQuery({
    queryKey: ['remediation', params],
    queryFn: () => remediationApi.list(params),
  });
}

export function useQuarantine() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: remediationApi.quarantine,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['remediation'] });
      queryClient.invalidateQueries({ queryKey: ['results'] });
    },
  });
}

export function useLockdown() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: remediationApi.lockdown,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['remediation'] });
      queryClient.invalidateQueries({ queryKey: ['results'] });
    },
  });
}

export function useRollback() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: remediationApi.rollback,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['remediation'] });
      queryClient.invalidateQueries({ queryKey: ['results'] });
    },
  });
}
