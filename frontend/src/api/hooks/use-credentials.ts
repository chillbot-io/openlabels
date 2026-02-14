import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { credentialsApi } from '../endpoints/credentials.ts';
import { enumerateApi } from '../endpoints/enumerate.ts';

export function useCheckCredentials(sourceType: string) {
  return useQuery({
    queryKey: ['credentials', sourceType],
    queryFn: () => credentialsApi.check(sourceType),
    enabled: !!sourceType,
    staleTime: 30_000,
  });
}

export function useStoreCredentials() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: credentialsApi.store,
    onSuccess: (_data, vars) => {
      queryClient.invalidateQueries({ queryKey: ['credentials', vars.source_type] });
    },
  });
}

export function useDeleteCredentials() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: credentialsApi.delete,
    onSuccess: (_data, sourceType) => {
      queryClient.invalidateQueries({ queryKey: ['credentials', sourceType] });
    },
  });
}

export function useEnumerate() {
  return useMutation({
    mutationFn: enumerateApi.enumerate,
  });
}
