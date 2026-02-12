import { cn } from '@/lib/utils.ts';
import { STATUS_COLORS, type ScanStatus } from '@/lib/constants.ts';

interface StatusBadgeProps {
  status: ScanStatus;
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold',
      STATUS_COLORS[status],
      status === 'running' && 'animate-pulse',
      className,
    )}>
      {status === 'running' && <span className="h-1.5 w-1.5 rounded-full bg-blue-500" aria-hidden="true" />}
      {status}
    </span>
  );
}
