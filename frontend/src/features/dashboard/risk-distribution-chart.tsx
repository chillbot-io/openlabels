import { PieChart, Pie, Cell, Legend, ResponsiveContainer, Tooltip } from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';

const COLORS: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  MINIMAL: '#6b7280',
};

interface Props {
  data?: Record<string, number>;
  isLoading: boolean;
}

export function RiskDistributionChart({ data, isLoading }: Props) {
  const chartData = data
    ? Object.entries(data).map(([name, value]) => ({ name, value }))
    : [];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Risk Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-64 w-full" />
        ) : chartData.length === 0 ? (
          <p className="flex h-64 items-center justify-center text-sm text-[var(--muted-foreground)]">
            No data available
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <PieChart role="img" aria-label={`Risk distribution: ${chartData.map((d) => `${d.name} ${d.value}`).join(', ')}`}>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={100}
                paddingAngle={2}
                dataKey="value"
              >
                {chartData.map((entry) => (
                  <Cell key={entry.name} fill={COLORS[entry.name] ?? '#9ca3af'} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
