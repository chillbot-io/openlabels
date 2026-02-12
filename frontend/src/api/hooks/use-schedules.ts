import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { schedulesApi } from '../endpoints/schedules.ts';
import type { Schedule } from '../types.ts';

export function useSchedules(page = 1) {
  return useQuery({
    queryKey: ['schedules', { page }],
    queryFn: () => schedulesApi.list({ page, page_size: 50 }),
    staleTime: 5 * 60_000,
  });
}

export function useSchedule(id: string) {
  return useQuery({
    queryKey: ['schedules', id],
    queryFn: () => schedulesApi.get(id),
    enabled: !!id,
    staleTime: 5 * 60_000,
  });
}

export function useCreateSchedule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: schedulesApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] });
    },
  });
}

export function useUpdateSchedule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: Partial<Schedule> & { id: string }) =>
      schedulesApi.update(id, data),
    onSuccess: (_data, vars) => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] });
      queryClient.invalidateQueries({ queryKey: ['schedules', vars.id] });
    },
  });
}

export function useDeleteSchedule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: schedulesApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] });
    },
  });
}
