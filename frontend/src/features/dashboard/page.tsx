import { useMemo } from 'react';
import { useDashboardStats, useEntityTrends } from '@/api/hooks/use-dashboard.ts';
import { useScans } from '@/api/hooks/use-scans.ts';
import { useActivityLog } from '@/api/hooks/use-monitoring.ts';
import { StatsCards } from './stats-cards.tsx';
import { RiskDistributionChart } from './risk-distribution-chart.tsx';
import { FindingsByTypeChart } from './findings-by-type-chart.tsx';
import { RecentScansTable } from './recent-scans-table.tsx';
import { ActivityFeed } from './activity-feed.tsx';
import { SystemStatus } from './system-status.tsx';
import { ErrorBoundary } from '@/components/layout/error-boundary.tsx';

export function Component() {
  const stats = useDashboardStats();
  const entityTrends = useEntityTrends(30);
  const scans = useScans({ page_size: 5 });
  const activity = useActivityLog({ page_size: 10 });

  const riskBreakdown = useMemo(() => {
    if (!stats.data) return undefined;
    return {
      CRITICAL: stats.data.critical_files,
      HIGH: stats.data.high_files,
      MEDIUM: stats.data.medium_files,
      LOW: stats.data.low_files,
      MINIMAL: stats.data.minimal_files,
    };
  }, [stats.data]);

  const entityTypeTotals = useMemo(() => {
    if (!entityTrends.data?.series) return undefined;
    const totals: Record<string, number> = {};
    for (const [entityType, points] of Object.entries(entityTrends.data.series)) {
      totals[entityType] = points.reduce((sum, [, count]) => sum + count, 0);
    }
    return Object.keys(totals).length > 0 ? totals : undefined;
  }, [entityTrends.data]);

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>

      <ErrorBoundary>
        <StatsCards stats={stats.data} isLoading={stats.isLoading} />
      </ErrorBoundary>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <ErrorBoundary>
          <RiskDistributionChart data={riskBreakdown} isLoading={stats.isLoading} />
        </ErrorBoundary>
        <ErrorBoundary>
          <FindingsByTypeChart data={entityTypeTotals} isLoading={entityTrends.isLoading} />
        </ErrorBoundary>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <ErrorBoundary>
          <RecentScansTable scans={scans.data?.items ?? []} isLoading={scans.isLoading} />
        </ErrorBoundary>
        <ErrorBoundary>
          <ActivityFeed entries={activity.data?.items ?? []} isLoading={activity.isLoading} />
        </ErrorBoundary>
        <ErrorBoundary>
          <SystemStatus />
        </ErrorBoundary>
      </div>
    </div>
  );
}
