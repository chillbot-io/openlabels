import { useMemo } from 'react';
import { useDashboardStats } from '@/api/hooks/use-dashboard.ts';
import { StatsCards } from './stats-cards.tsx';
import { RiskDistributionChart } from './risk-distribution-chart.tsx';
import { SystemStatus } from './system-status.tsx';
import { ErrorBoundary } from '@/components/layout/error-boundary.tsx';

export function Component() {
  const stats = useDashboardStats();

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
          <SystemStatus />
        </ErrorBoundary>
      </div>
    </div>
  );
}
