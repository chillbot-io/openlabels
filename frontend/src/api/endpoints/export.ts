const BASE_URL = import.meta.env.VITE_API_URL ?? '';

async function fetchBlob(path: string, params?: Record<string, string | undefined>): Promise<Blob> {
  let url = `${BASE_URL}/api/v1${path}`;
  if (params) {
    const sp = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined) sp.set(k, v);
    }
    const qs = sp.toString();
    if (qs) url += `?${qs}`;
  }

  const response = await fetch(url, {
    credentials: 'include',
    headers: { Accept: 'application/octet-stream' },
  });

  if (!response.ok) {
    throw new Error(`Export failed: ${response.statusText}`);
  }

  return response.blob();
}

export const exportApi = {
  results: (params?: { format?: 'csv' | 'xlsx' | 'pdf'; scan_id?: string; risk_tier?: string; entity_type?: string; search?: string }) =>
    fetchBlob('/export/results', params),

  report: (reportId: string, format: 'pdf' | 'xlsx' | 'csv') =>
    fetchBlob(`/reporting/${reportId}/export`, { format }),
};

/** Trigger browser download for a blob */
export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
