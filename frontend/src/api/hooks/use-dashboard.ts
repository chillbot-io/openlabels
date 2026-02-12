import { useQuery } from '@tanstack/react-query';
import { dashboardApi } from '../endpoints/dashboard.ts';

export function useDashboardStats() {
  return useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: () => dashboardApi.stats(),
    staleTime: 30_000,
    refetchInterval: 30_000,
  });
}

export function useEntityTrends(days = 30) {
  return useQuery({
    queryKey: ['dashboard', 'entity-trends', days],
    queryFn: () => dashboardApi.entityTrends({ days }),
    staleTime: 60_000,
  });
}
