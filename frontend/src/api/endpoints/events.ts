import { apiFetch } from '../client.ts';
import type { FileAccessEvent, CursorPaginatedResponse } from '../types.ts';

export const eventsApi = {
  list: (params?: {
    cursor?: string;
    page_size?: number;
    file_path?: string;
    user_name?: string;
    action?: string;
    since?: string;
  }) => apiFetch<CursorPaginatedResponse<FileAccessEvent>>('/monitoring/events/cursor', { params }),
};
