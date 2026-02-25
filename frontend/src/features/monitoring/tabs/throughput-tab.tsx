import { useState } from 'react';
import { useScanThroughput } from '@/api/hooks/use-monitoring.ts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatNumber } from '@/lib/utils.ts';

export function ThroughputTab() {
  const [hours, setHours] = useState(24);
  const throughput = useScanThroughput({ hours, bucket_size: hours <= 24 ? 1 : hours <= 72 ? 3 : 6 });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <span className="text-sm text-[var(--muted-foreground)]">Period:</span>
        {[24, 48, 72, 168].map((h) => (
          <Button key={h} variant={hours === h ? 'default' : 'outline'} size="sm" onClick={() => setHours(h)}>
            {h}h
          </Button>
        ))}
      </div>

      {throughput.isLoading ? (
        <Skeleton className="h-32" />
      ) : throughput.data ? (
        <>
          <div className="grid grid-cols-4 gap-4">
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold">{formatNumber(throughput.data.total_scans)}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Total Scans</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold">{formatNumber(throughput.data.total_files)}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Total Files</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold">{throughput.data.avg_files_per_hour.toFixed(0)}</p>
                <p className="text-xs text-[var(--muted-foreground)]">Files/Hour</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <p className="text-2xl font-bold">
                  {throughput.data.avg_scan_duration_seconds
                    ? `${(throughput.data.avg_scan_duration_seconds / 60).toFixed(1)}m`
                    : '--'}
                </p>
                <p className="text-xs text-[var(--muted-foreground)]">Avg Duration</p>
              </CardContent>
            </Card>
          </div>

          {/* Throughput timeline */}
          {throughput.data.buckets.length > 0 ? (
            <Card>
              <CardHeader><CardTitle className="text-sm">Throughput Timeline</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-1">
                  {throughput.data.buckets.map((b) => {
                    const maxFiles = Math.max(...throughput.data!.buckets.map((x) => x.files_scanned), 1);
                    const pct = Math.round((b.files_scanned / maxFiles) * 100);
                    return (
                      <div key={b.period} className="flex items-center gap-3">
                        <span className="w-32 shrink-0 text-xs text-[var(--muted-foreground)]">{b.period.slice(5)}</span>
                        <div className="flex-1">
                          <div className="h-4 rounded-sm bg-[var(--muted)]">
                            <div
                              className="h-full rounded-sm bg-primary-600 transition-all"
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                        </div>
                        <span className="w-20 shrink-0 text-right text-xs">
                          {formatNumber(b.files_scanned)} files
                        </span>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-8 text-center text-sm text-[var(--muted-foreground)]">
                No scans completed in the selected period.
              </CardContent>
            </Card>
          )}
        </>
      ) : null}
    </div>
  );
}
