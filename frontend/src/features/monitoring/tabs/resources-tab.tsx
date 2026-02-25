import { useSystemResources } from '@/api/hooks/use-monitoring.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Progress } from '@/components/ui/progress.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatNumber } from '@/lib/utils.ts';

function progressBarColor(percent: number): string {
  if (percent >= 90) return '[&>div>div]:bg-red-500';
  if (percent >= 70) return '[&>div>div]:bg-yellow-500';
  return '';
}

export function ResourcesTab() {
  const resources = useSystemResources();

  return (
    <div className="space-y-4">
      {resources.isLoading ? (
        <Skeleton className="h-32" />
      ) : resources.data ? (
        <>
          <div className="grid grid-cols-3 gap-4">
            {/* CPU */}
            <Card>
              <CardHeader><CardTitle className="text-sm">CPU</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                <div className="text-center">
                  <p className="text-3xl font-bold">{resources.data.cpu_percent.toFixed(1)}%</p>
                  <p className="text-xs text-[var(--muted-foreground)]">{resources.data.cpu_count} cores</p>
                </div>
                <Progress value={resources.data.cpu_percent} className={progressBarColor(resources.data.cpu_percent)} />
                {resources.data.load_average && (
                  <p className="text-xs text-[var(--muted-foreground)] text-center">
                    Load: {resources.data.load_average.map((v) => v.toFixed(2)).join(' / ')}
                  </p>
                )}
              </CardContent>
            </Card>

            {/* Memory */}
            <Card>
              <CardHeader><CardTitle className="text-sm">Memory</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                <div className="text-center">
                  <p className="text-3xl font-bold">{resources.data.memory_percent.toFixed(1)}%</p>
                  <p className="text-xs text-[var(--muted-foreground)]">
                    {formatNumber(resources.data.memory_used_mb)} / {formatNumber(resources.data.memory_total_mb)} MB
                  </p>
                </div>
                <Progress value={resources.data.memory_percent} className={progressBarColor(resources.data.memory_percent)} />
              </CardContent>
            </Card>

            {/* Disk */}
            <Card>
              <CardHeader><CardTitle className="text-sm">Disk</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                <div className="text-center">
                  <p className="text-3xl font-bold">{resources.data.disk_percent.toFixed(1)}%</p>
                  <p className="text-xs text-[var(--muted-foreground)]">
                    {resources.data.disk_used_gb} / {resources.data.disk_total_gb} GB
                  </p>
                </div>
                <Progress value={resources.data.disk_percent} className={progressBarColor(resources.data.disk_percent)} />
                <p className="text-xs text-[var(--muted-foreground)] text-center">
                  {resources.data.disk_free_gb} GB free
                </p>
              </CardContent>
            </Card>
          </div>
        </>
      ) : null}
    </div>
  );
}
