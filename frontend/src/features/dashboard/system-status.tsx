import { useHealth } from '@/api/hooks/use-monitoring.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';

const STATUS_STYLES: Record<string, string> = {
  healthy: 'bg-green-100 text-green-700',
  degraded: 'bg-yellow-100 text-yellow-700',
  unhealthy: 'bg-red-100 text-red-700',
};

const HEALTH_COMPONENTS = ['db', 'queue', 'ml', 'mip', 'ocr'] as const;

const healthDot = (status: string) =>
  status === 'healthy' ? 'bg-green-500' : status === 'warning' ? 'bg-yellow-500' : 'bg-red-500';

export function SystemStatus() {
  const health = useHealth();

  if (health.isLoading) return <Skeleton className="h-32" />;
  if (!health.data) return null;

  const data = health.data;

  // Derive overall status from component statuses
  const overallStatus = HEALTH_COMPONENTS.some((c) => data[c] === 'error')
    ? 'unhealthy'
    : HEALTH_COMPONENTS.some((c) => data[c] === 'warning')
      ? 'degraded'
      : 'healthy';

  const uptimeHours = data.uptime_seconds != null ? Math.floor(data.uptime_seconds / 3600) : 0;
  const uptimeMins = data.uptime_seconds != null ? Math.floor((data.uptime_seconds % 3600) / 60) : 0;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm">System Status</CardTitle>
          <Badge className={STATUS_STYLES[overallStatus] ?? ''}>{overallStatus}</Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="space-y-2">
          {HEALTH_COMPONENTS.map((name) => (
            <div key={name} className="flex items-center justify-between text-sm">
              <span className="capitalize">{name}</span>
              <div className="flex items-center gap-2">
                <span className="text-xs text-[var(--muted-foreground)]">{data[`${name}_text` as keyof typeof data] as string}</span>
                <span className={`h-2 w-2 rounded-full ${healthDot(data[name])}`} aria-hidden="true" />
                <span className="sr-only">{data[name]}</span>
              </div>
            </div>
          ))}
        </div>
        <p className="text-xs text-[var(--muted-foreground)]">
          Uptime: {uptimeHours}h {uptimeMins}m
        </p>
      </CardContent>
    </Card>
  );
}
