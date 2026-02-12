import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { targetsApi } from '../endpoints/targets.ts';
import type { Target } from '../types.ts';

export function useTargets(page = 1) {
  return useQuery({
    queryKey: ['targets', { page }],
    queryFn: () => targetsApi.list({ page, page_size: 50 }),
    staleTime: 5 * 60_000,
  });
}

export function useTarget(id: string) {
  return useQuery({
    queryKey: ['targets', id],
    queryFn: () => targetsApi.get(id),
    enabled: !!id,
    staleTime: 5 * 60_000,
  });
}

export function useCreateTarget() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: targetsApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
    },
  });
}

export function useUpdateTarget() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: Partial<Target> & { id: string }) =>
      targetsApi.update(id, data),
    onSuccess: (_data, vars) => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
      queryClient.invalidateQueries({ queryKey: ['targets', vars.id] });
    },
  });
}

export function useDeleteTarget() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: targetsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
    },
  });
}
