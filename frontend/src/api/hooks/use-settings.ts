import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { settingsApi } from '../endpoints/settings.ts';

export function useSettings() {
  return useQuery({
    queryKey: ['settings'],
    queryFn: () => settingsApi.list(),
    staleTime: 10 * 60_000,
  });
}

export function useUpdateSettings() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ category, settings }: { category: string; settings: Record<string, unknown> }) =>
      settingsApi.update(category, settings),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] });
    },
  });
}
