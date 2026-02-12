import { apiFetch } from '../client.ts';
import type { JobQueueStats } from '../types.ts';

export const jobsApi = {
  stats: () =>
    apiFetch<JobQueueStats>('/monitoring/jobs'),

  cancel: (jobId: string) =>
    apiFetch<void>(`/jobs/${jobId}/cancel`, { method: 'POST' }),
};
