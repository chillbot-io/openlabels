import { cn } from '@/lib/utils.ts';

/**
 * The OpenLabels tag icon — a red label tag with a string loop.
 * Renders inline as an SVG so it inherits color/size from parent context.
 */
export function LogoIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 64 80"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn('h-6 w-auto', className)}
      aria-hidden="true"
    >
      {/* String / loop */}
      <path
        d="M28 18 Q28 5, 36 5 Q44 5, 44 14"
        stroke="currentColor"
        strokeWidth={2.5}
        strokeLinecap="round"
        fill="none"
        opacity={0.5}
      />
      {/* Tag body */}
      <rect x="14" y="16" width="28" height="42" rx="4" fill="#E03E3E" />
      {/* Pointed bottom */}
      <polygon points="14,50 42,50 28,68" fill="#E03E3E" />
      {/* Hole */}
      <circle cx="28" cy="25" r="4" fill="white" />
    </svg>
  );
}

/**
 * Full logo: tag icon + "openlabels" wordmark.
 * Use in the sidebar header (expanded) and login page.
 */
export function Logo({ className, iconOnly }: { className?: string; iconOnly?: boolean }) {
  return (
    <span className={cn('inline-flex items-center gap-2', className)}>
      <LogoIcon className="h-7 w-auto shrink-0" />
      {!iconOnly && (
        <span className="text-lg font-bold tracking-tight">openlabels</span>
      )}
    </span>
  );
}
