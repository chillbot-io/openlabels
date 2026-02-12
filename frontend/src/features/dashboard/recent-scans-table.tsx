import { useNavigate } from 'react-router';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { StatusBadge } from '@/components/status-badge.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatRelativeTime } from '@/lib/utils.ts';
import type { ScanJob } from '@/api/types.ts';
import type { ScanStatus } from '@/lib/constants.ts';

interface Props {
  scans: ScanJob[];
  isLoading: boolean;
}

export function RecentScansTable({ scans, isLoading }: Props) {
  const navigate = useNavigate();

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Scans</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : scans.length === 0 ? (
          <p className="py-8 text-center text-sm text-[var(--muted-foreground)]">No scans yet</p>
        ) : (
          <div className="space-y-1">
            {scans.map((scan) => (
              <button
                key={scan.id}
                className="flex w-full items-center justify-between rounded-md px-3 py-2 text-left text-sm hover:bg-[var(--muted)]"
                onClick={() => navigate(`/scans/${scan.id}`)}
              >
                <div>
                  <p className="font-medium">{scan.target_name ?? 'Scan'}</p>
                  <p className="text-xs text-[var(--muted-foreground)]">
                    {scan.files_scanned} files &middot; {formatRelativeTime(scan.created_at)}
                  </p>
                </div>
                <StatusBadge status={scan.status as ScanStatus} />
              </button>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
