import { cn } from '@/lib/utils.ts';

interface EntityTagProps {
  type: string;
  count?: number;
  className?: string;
}

export function EntityTag({ type, count, className }: EntityTagProps) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1 rounded-md bg-[var(--muted)] px-2 py-0.5 text-xs font-medium text-[var(--muted-foreground)]',
      className,
    )}>
      {type}
      {count !== undefined && (
        <span className="rounded-full bg-[var(--accent)] px-1.5 text-[var(--accent-foreground)]">
          {count}
        </span>
      )}
    </span>
  );
}
