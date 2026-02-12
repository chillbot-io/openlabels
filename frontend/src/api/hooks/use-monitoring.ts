import { useQuery } from '@tanstack/react-query';
import { monitoringApi } from '../endpoints/monitoring.ts';

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: () => monitoringApi.health(),
    staleTime: 15_000,
    refetchInterval: 15_000,
  });
}

export function useJobQueue() {
  return useQuery({
    queryKey: ['monitoring', 'jobs'],
    queryFn: () => monitoringApi.jobQueue(),
    staleTime: 10_000,
    refetchInterval: 10_000,
  });
}

export function useActivityLog(params?: { page?: number; page_size?: number; action?: string }) {
  return useQuery({
    queryKey: ['monitoring', 'activity', params],
    queryFn: () => monitoringApi.activityLog(params),
    staleTime: 30_000,
  });
}
