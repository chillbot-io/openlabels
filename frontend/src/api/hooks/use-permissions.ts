import { useQuery } from '@tanstack/react-query';
import { permissionsApi } from '../endpoints/permissions.ts';

export function useExposureSummary() {
  return useQuery({
    queryKey: ['permissions', 'exposure'],
    queryFn: () => permissionsApi.exposure(),
    staleTime: 60_000,
  });
}

export function useDirectories(targetId: string, params?: { page?: number; exposure?: string; parent_id?: string }) {
  return useQuery({
    queryKey: ['permissions', targetId, 'directories', params],
    queryFn: () => permissionsApi.directories(targetId, params),
    enabled: !!targetId,
  });
}

export function useDirectoryACL(targetId: string, dirId: string) {
  return useQuery({
    queryKey: ['permissions', targetId, 'acl', dirId],
    queryFn: () => permissionsApi.acl(targetId, dirId),
    enabled: !!targetId && !!dirId,
  });
}

export function usePrincipalLookup(principal: string) {
  return useQuery({
    queryKey: ['permissions', 'principal', principal],
    queryFn: () => permissionsApi.principal(principal),
    enabled: !!principal,
  });
}
