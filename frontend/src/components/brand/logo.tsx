import { cn } from '@/lib/utils.ts';

/**
 * The OpenLabels tag icon — renders the /logo-icon.svg from public/.
 */
export function LogoIcon({ className }: { className?: string }) {
  return (
    <img
      src="/logo-icon.svg"
      alt=""
      aria-hidden="true"
      className={cn('h-6 w-auto', className)}
    />
  );
}

/**
 * Full logo: "openlabels" wordmark + tag icon.
 * Renders /logo.svg (full) or /logo-icon.svg (icon-only) from public/.
 */
export function Logo({ className, iconOnly }: { className?: string; iconOnly?: boolean }) {
  return iconOnly ? (
    <LogoIcon className={className} />
  ) : (
    <img
      src="/logo.svg"
      alt="OpenLabels"
      className={cn('h-8 w-auto', className)}
    />
  );
}
