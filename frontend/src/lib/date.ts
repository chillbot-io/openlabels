function isValidDate(d: Date): boolean {
  return !isNaN(d.getTime());
}

export function formatDateTime(dateStr: string | null | undefined): string {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  return isValidDate(d) ? d.toLocaleString() : '—';
}

export function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  return isValidDate(d) ? d.toLocaleDateString() : '—';
}

export function formatTime(dateStr: string | null | undefined): string {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  return isValidDate(d) ? d.toLocaleTimeString() : '—';
}

export function formatDuration(startStr: string, endStr: string | null | undefined): string {
  if (!endStr) return 'running...';
  const start = new Date(startStr).getTime();
  const end = new Date(endStr).getTime();
  if (isNaN(start) || isNaN(end)) return '—';
  const diffSec = Math.floor((end - start) / 1000);

  if (diffSec < 60) return `${diffSec}s`;
  const min = Math.floor(diffSec / 60);
  const sec = diffSec % 60;
  if (min < 60) return `${min}m ${sec}s`;
  const hr = Math.floor(min / 60);
  return `${hr}h ${min % 60}m`;
}

/** Describe next 3 cron run times in human-readable form */
export function describeCron(expression: string): string[] {
  // Simplified - in production you'd use a cron parser library
  const parts = expression.split(' ');
  if (parts.length !== 5) return ['Invalid cron expression'];

  const [minute, hour] = parts;
  const dayOfWeek = parts[4];

  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const dayName = dayOfWeek === '*' ? 'every day' : days[Number(dayOfWeek)] ?? dayOfWeek;
  const timeStr = `${hour?.padStart(2, '0')}:${minute?.padStart(2, '0')}`;

  return [`Runs ${dayName} at ${timeStr}`];
}
