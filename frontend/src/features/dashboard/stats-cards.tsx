import { FileSearch, AlertTriangle, ShieldAlert, Scan } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';
import { formatNumber } from '@/lib/utils.ts';
import type { DashboardStats } from '@/api/types.ts';

interface StatsCardsProps {
  stats?: DashboardStats;
  isLoading: boolean;
}

const STAT_CARDS = [
  { key: 'total_files_scanned', label: 'Files Scanned', icon: FileSearch, color: 'text-blue-600' },
  { key: 'total_findings', label: 'Total Findings', icon: AlertTriangle, color: 'text-orange-600' },
  { key: 'critical_findings', label: 'Critical Findings', icon: ShieldAlert, color: 'text-red-600' },
  { key: 'active_scans', label: 'Active Scans', icon: Scan, color: 'text-green-600' },
] as const;

export function StatsCards({ stats, isLoading }: StatsCardsProps) {
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {STAT_CARDS.map(({ key, label, icon: Icon, color }) => (
        <Card key={key}>
          <CardContent className="flex items-center gap-4 p-6">
            <div className={`rounded-lg bg-[var(--muted)] p-3 ${color}`}>
              <Icon className="h-5 w-5" />
            </div>
            <div>
              {isLoading ? (
                <Skeleton className="h-8 w-16" />
              ) : (
                <p className="text-2xl font-bold">
                  {formatNumber(stats?.[key] ?? 0)}
                </p>
              )}
              <p className="text-xs text-[var(--muted-foreground)]">{label}</p>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
