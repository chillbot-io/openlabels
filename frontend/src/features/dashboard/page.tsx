import { useDashboardStats } from '@/api/hooks/use-dashboard.ts';
import { useScans } from '@/api/hooks/use-scans.ts';
import { useActivityLog } from '@/api/hooks/use-monitoring.ts';
import { StatsCards } from './stats-cards.tsx';
import { RiskDistributionChart } from './risk-distribution-chart.tsx';
import { FindingsByTypeChart } from './findings-by-type-chart.tsx';
import { RecentScansTable } from './recent-scans-table.tsx';
import { ActivityFeed } from './activity-feed.tsx';
import { ErrorBoundary } from '@/components/layout/error-boundary.tsx';

export function Component() {
  const stats = useDashboardStats();
  const scans = useScans({ page_size: 5 });
  const activity = useActivityLog({ page_size: 10 });

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>

      <ErrorBoundary>
        <StatsCards stats={stats.data} isLoading={stats.isLoading} />
      </ErrorBoundary>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <ErrorBoundary>
          <RiskDistributionChart data={stats.data?.risk_breakdown} isLoading={stats.isLoading} />
        </ErrorBoundary>
        <ErrorBoundary>
          <FindingsByTypeChart data={stats.data?.entity_type_counts} isLoading={stats.isLoading} />
        </ErrorBoundary>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <ErrorBoundary>
          <RecentScansTable scans={scans.data?.items ?? []} isLoading={scans.isLoading} />
        </ErrorBoundary>
        <ErrorBoundary>
          <ActivityFeed entries={activity.data?.items ?? []} isLoading={activity.isLoading} />
        </ErrorBoundary>
      </div>
    </div>
  );
}
