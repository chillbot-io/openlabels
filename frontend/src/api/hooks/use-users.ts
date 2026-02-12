import { useQuery } from '@tanstack/react-query';
import { usersApi } from '../endpoints/users.ts';

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
