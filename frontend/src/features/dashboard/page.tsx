import { useMemo } from 'react';
import { useNavigate } from 'react-router';
import { Plus } from 'lucide-react';
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
import { Button } from '@/components/ui/button.tsx';
import { Card, CardContent } from '@/components/ui/card.tsx';

export function Component() {
  const navigate = useNavigate();
  const stats = useDashboardStats();
  const recentScans = useScans({ page: 1, page_size: 5 });
  const activity = useActivityLog({ page: 1, page_size: 10 });
  const entityTrends = useEntityTrends(30);

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

  // Flatten entity trends series into top entity type counts for the bar chart
  const entityTypeCounts = useMemo(() => {
    if (!entityTrends.data?.series) return undefined;
    const counts: Record<string, number> = {};
    for (const [entityType, points] of Object.entries(entityTrends.data.series)) {
      counts[entityType] = points.reduce((sum, [, count]) => sum + count, 0);
    }
    return counts;
  }, [entityTrends.data]);

  const criticalOrHigh = (stats.data?.critical_files ?? 0) + (stats.data?.high_files ?? 0);

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <Button onClick={() => navigate('/scans')}>
          <Plus className="mr-2 h-4 w-4" /> New Scan
        </Button>
      </div>

      <ErrorBoundary>
        <StatsCards stats={stats.data} isLoading={stats.isLoading} />
      </ErrorBoundary>

      {/* Attention Required banner */}
      {criticalOrHigh > 0 && (
        <Card className="border-red-200 bg-red-50 dark:border-red-900 dark:bg-red-950">
          <CardContent className="flex items-center justify-between p-4">
            <div>
              <p className="font-semibold text-red-800 dark:text-red-200">Attention Required</p>
              <p className="text-sm text-red-600 dark:text-red-400">
                {criticalOrHigh} file{criticalOrHigh !== 1 ? 's' : ''} at Critical or High risk need review
              </p>
            </div>
            <Button variant="outline" size="sm" onClick={() => navigate('/results?risk_tier=CRITICAL')}>
              Review Now
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <ErrorBoundary>
          <RiskDistributionChart data={riskBreakdown} isLoading={stats.isLoading} />
        </ErrorBoundary>
        <ErrorBoundary>
          <FindingsByTypeChart data={entityTypeCounts} isLoading={entityTrends.isLoading} />
        </ErrorBoundary>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <ErrorBoundary>
            <RecentScansTable scans={recentScans.data?.items ?? []} isLoading={recentScans.isLoading} />
          </ErrorBoundary>
        </div>
        <ErrorBoundary>
          <ActivityFeed entries={activity.data?.items ?? []} isLoading={activity.isLoading} />
        </ErrorBoundary>
      </div>

      <ErrorBoundary>
        <SystemStatus />
      </ErrorBoundary>
    </div>
  );
}
