import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
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

export function useSystemResources() {
  return useQuery({
    queryKey: ['monitoring', 'resources'],
    queryFn: () => monitoringApi.resources(),
    staleTime: 10_000,
    refetchInterval: 10_000,
  });
}

export function useWorkers() {
  return useQuery({
    queryKey: ['monitoring', 'workers'],
    queryFn: () => monitoringApi.workers(),
    staleTime: 10_000,
    refetchInterval: 10_000,
  });
}

export function useScanThroughput(params?: { hours?: number; bucket_size?: number }) {
  return useQuery({
    queryKey: ['monitoring', 'throughput', params],
    queryFn: () => monitoringApi.throughput(params),
    staleTime: 30_000,
    refetchInterval: 30_000,
  });
}

export function useErrorLog(params?: { source?: string; severity?: string; hours?: number; page?: number; page_size?: number }) {
  return useQuery({
    queryKey: ['monitoring', 'errors', params],
    queryFn: () => monitoringApi.errors(params),
    staleTime: 15_000,
  });
}

export function useBackgroundTasks() {
  return useQuery({
    queryKey: ['monitoring', 'tasks'],
    queryFn: () => monitoringApi.tasks(),
    staleTime: 15_000,
    refetchInterval: 15_000,
  });
}

export function useSystemAlerts() {
  return useQuery({
    queryKey: ['monitoring', 'alerts'],
    queryFn: () => monitoringApi.systemAlerts(),
    staleTime: 30_000,
  });
}

export function useCreateSystemAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: monitoringApi.createSystemAlert,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['monitoring', 'alerts'] });
    },
  });
}

export function useDeleteSystemAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: monitoringApi.deleteSystemAlert,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['monitoring', 'alerts'] });
    },
  });
}
