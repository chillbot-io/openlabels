const BASE_URL = import.meta.env.VITE_API_URL ?? '';
const API_TIMEOUT_MS = 30_000;

const CSRF_COOKIE_NAME = 'openlabels_csrf';
const CSRF_HEADER_NAME = 'X-CSRF-Token';
const CSRF_PROTECTED_METHODS = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);

function getCsrfToken(): string | undefined {
  const match = document.cookie
    .split('; ')
    .find((row) => row.startsWith(`${CSRF_COOKIE_NAME}=`));
  return match?.split('=')[1];
}

export class ApiError extends Error {
  status: number;
  body: { error?: string; message?: string; detail?: string };

  constructor(
    status: number,
    body: { error?: string; message?: string; detail?: string },
  ) {
    super(body.message ?? body.detail ?? body.error ?? `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

interface ApiFetchOptions extends Omit<RequestInit, 'body'> {
  params?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
}

export async function apiFetch<T>(
  path: string,
  options?: ApiFetchOptions,
): Promise<T> {
  let url = `${BASE_URL}/api/v1${path}`;

  if (options?.params) {
    const searchParams = new URLSearchParams();
    for (const [key, value] of Object.entries(options.params)) {
      if (value !== undefined) {
        searchParams.set(key, String(value));
      }
    }
    const qs = searchParams.toString();
    if (qs) url += `?${qs}`;
  }

  const { params: _params, body, ...fetchOptions } = options ?? {};

  const headers: Record<string, string> = {
    ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    ...(fetchOptions.headers as Record<string, string>),
  };

  // Include CSRF token for state-changing requests
  const method = (fetchOptions.method ?? 'GET').toUpperCase();
  if (CSRF_PROTECTED_METHODS.has(method)) {
    const csrfToken = getCsrfToken();
    if (!csrfToken) {
      throw new ApiError(403, { message: 'Session expired. Please refresh the page and try again.' });
    }
    headers[CSRF_HEADER_NAME] = csrfToken;
  }

  const response = await fetch(url, {
    ...fetchOptions,
    credentials: 'include',
    headers,
    body: body ? JSON.stringify(body) : undefined,
    signal: fetchOptions.signal ?? AbortSignal.timeout(API_TIMEOUT_MS),
  });

  if (response.status === 401) {
    window.location.href = '/api/v1/auth/login';
    throw new ApiError(401, { message: 'Unauthorized' });
  }

  if (!response.ok) {
    let errorBody: Record<string, string>;
    try {
      errorBody = await response.json();
    } catch {
      errorBody = { message: response.statusText };
    }
    throw new ApiError(response.status, errorBody);
  }

  if (response.status === 204) return undefined as T;
  return response.json();
}
