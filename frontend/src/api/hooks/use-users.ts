import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { usersApi, type CreateUserPayload } from '../endpoints/users.ts';

export function useUsers(page = 1) {
  return useQuery({
    queryKey: ['users', { page }],
    queryFn: () => usersApi.list({ page, page_size: 50 }),
    staleTime: 5 * 60_000,
  });
}

export function useCurrentUser() {
  return useQuery({
    queryKey: ['auth', 'me'],
    queryFn: () => usersApi.me(),
    staleTime: 5 * 60_000,
    retry: false,
  });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateUserPayload) => usersApi.create(payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  });
}

export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => usersApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  });
}
