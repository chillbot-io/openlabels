import { useHealth } from '@/api/hooks/use-monitoring.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Badge } from '@/components/ui/badge.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';

const STATUS_STYLES: Record<string, string> = {
  healthy: 'bg-green-100 text-green-700',
  degraded: 'bg-yellow-100 text-yellow-700',
  unhealthy: 'bg-red-100 text-red-700',
};

export function SystemStatus() {
  const health = useHealth();

  if (health.isLoading) return <Skeleton className="h-32" />;
  if (!health.data) return null;

  const { status, components, uptime_seconds } = health.data;
  const uptimeHours = Math.floor(uptime_seconds / 3600);
  const uptimeMins = Math.floor((uptime_seconds % 3600) / 60);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm">System Status</CardTitle>
          <Badge className={STATUS_STYLES[status] ?? ''}>{status}</Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="space-y-2">
          {Object.entries(components).map(([name, comp]) => (
            <div key={name} className="flex items-center justify-between text-sm">
              <span className="capitalize">{name}</span>
              <div className="flex items-center gap-2">
                {comp.latency_ms !== undefined && (
                  <span className="text-xs text-[var(--muted-foreground)]">{comp.latency_ms}ms</span>
                )}
                <span className={`h-2 w-2 rounded-full ${comp.status === 'healthy' ? 'bg-green-500' : comp.status === 'degraded' ? 'bg-yellow-500' : 'bg-red-500'}`} aria-hidden="true" />
                <span className="sr-only">{comp.status}</span>
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
