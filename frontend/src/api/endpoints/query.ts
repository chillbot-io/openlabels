import { apiFetch } from '../client.ts';
import type { QuerySchema, QueryResult, AIQueryResponse } from '../types.ts';

export const queryApi = {
  schema: () =>
    apiFetch<QuerySchema>('/query/schema'),

  execute: (sql: string) =>
    apiFetch<QueryResult>('/query', { method: 'POST', body: { sql } }),

  ai: (question: string, execute?: boolean) =>
    apiFetch<AIQueryResponse>('/query/ai', { method: 'POST', body: { question, execute } }),
};
