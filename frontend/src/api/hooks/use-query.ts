import { useQuery, useMutation } from '@tanstack/react-query';
import { queryApi } from '../endpoints/query.ts';

export function useQuerySchema() {
  return useQuery({
    queryKey: ['query', 'schema'],
    queryFn: () => queryApi.schema(),
    staleTime: 10 * 60_000,
  });
}

export function useExecuteQuery() {
  return useMutation({
    mutationFn: (sql: string) => queryApi.execute(sql),
  });
}

export function useAIQuery() {
  return useMutation({
    mutationFn: ({ question, execute }: { question: string; execute?: boolean }) =>
      queryApi.ai(question, execute),
  });
}
