import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card.tsx';
import { Skeleton } from '@/components/loading-skeleton.tsx';

interface Props {
  data?: Record<string, number>;
  isLoading: boolean;
}

export function FindingsByTypeChart({ data, isLoading }: Props) {
  const chartData = data
    ? Object.entries(data)
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10)
    : [];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Top Entity Types</CardTitle>
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
            <BarChart data={chartData} layout="vertical" margin={{ left: 80 }} role="img" aria-label={`Top entity types: ${chartData.map((d) => `${d.name} ${d.count}`).join(', ')}`}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis type="number" stroke="var(--muted-foreground)" />
              <YAxis type="category" dataKey="name" width={80} tick={{ fontSize: 12 }} stroke="var(--muted-foreground)" />
              <Tooltip />
              <Bar dataKey="count" fill="var(--color-primary-500)" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
